# Field report — migrating Garden LMS onto Alfiz 0.1.2

Garden LMS is a Next.js 15 / Prisma LMS with a hand-rolled RBAC layer: a
97-key catalog across 8 product areas, ~400 enforcement call sites, its own
wildcard matcher, checkbox tree, role/user-grant/API-token tables, and a
course-scoping layer built from `CourseStaff` rows. The whole thing was
replaced with `@alfiz-auth/{core,application,prisma,verify}`.

**It worked.** The migration landed with the catalog's 97 keys unchanged, one
database migration per engine, a clean typecheck and build, and
`alfiz-verify` reporting 0 errors over 263 files. Course access became real
scoped grants, and cohorts became grantable subjects — a capability Garden did
not previously have and did not have to build.

What follows is the friction, ordered by how much it cost. Each item is what
happened, why it hurt, and a concrete proposal.

---

## 1. The sync/async boundary is the single biggest adoption cost

**Severity: high — this is the one that decides whether an SSR app can adopt
Alfiz incrementally.**

`can()` is async because closures come from the provider. A server-rendered
app performs hundreds of conditional-UI checks per page render — every button,
every panel, every nav item. Garden had 167 synchronous `can(actor, key)` call
sites, many inside pure render helpers and `.map()` callbacks. Making them all
`await` would have meant touching essentially every page and turning
non-async helpers into async ones, which in React Server Components cascades.

The way out is available but undocumented: fetch `SubjectAccessData` once per
request, build a `CheckContext` with `toCheckContext`, and evaluate with the
pure `checkKey`. That is exactly what the core is designed for — and it is
better than the async path for a request-scoped app, because every check in a
request then sees one consistent snapshot instead of a cache that may tick over
mid-render. But finding it required reading `client.ts` and `access.ts`;
nothing in the README or CONVENTIONS points at it.

```ts
// what Garden ended up doing, per request
const access = await app.getSubjectAccess(principal);
const ctx = toCheckContext(access, Date.now(), (k, s) => catalog.appliesAt(k, s));
const can = (key, scope) => checkKey(ctx, key, scope ? [scope, "*"] : ["*"]);
```

**Proposal.** Make this a first-class shape:

```ts
const snap = await client.snapshot(principal);   // one provider round-trip
snap.can(key, scope?);        // synchronous
snap.canAny(pattern);         // synchronous
snap.heldKeys;                // Set<PermissionKey>
```

Everything needed already exists. Documenting the snapshot as *the* pattern
for server-rendered frameworks — and saying plainly that a per-request
snapshot is a stronger consistency guarantee than the TTL cache, not a weaker
one — would remove the largest single obstacle to adoption.

A related note: **object closures for top-level scope types are computable
without I/O.** Garden's `garden.course` has `parent: null`, so its chain is
always `[scope, "*"]`. That fact is what let scoped checks stay synchronous
too. Worth stating explicitly, because it means "scoped checks force you
async" is not true for the flat-scope case, which is probably most first
adoptions.

## 2. The Prisma driver does not typecheck against a generated Prisma 7 client

**Severity: high — it contradicts the package's own headline promise.**

`packages/prisma/README` and the module docblock both say the generated client
"satisfies `AlfizPrismaDelegates` structurally — pass the `PrismaClient`
instance straight to `prismaDriver`". It does not:

```
Type 'AlfizGrantCreateData' is not assignable to type 'AlfizGrantCreateInput'.
  Types of property 'provenance' are incompatible.
    Type 'JsonValue' is not assignable to type 'JsonNullClass | InputJsonValue'.
      Type 'null' is not assignable to type 'JsonNullClass | InputJsonValue'.
```

`JsonValue` admits bare `null`; Prisma requires its `Prisma.JsonNull` sentinel
to write SQL NULL into a Json column. The irony is that `delegates.ts` already
documents this exact rule — "Optional Json columns are OMITTED from create
data when absent (Prisma requires a sentinel, not plain `null`)" — and the
driver honours it: required Json columns always receive an object, optional
ones are omitted. So the runtime behaviour is correct and only the type is
too wide.

Garden had to write `prismaDriver(db as unknown as AlfizPrismaDelegates)` —
precisely the cast the package advertises as unnecessary.

**Proposal.** Narrow the *create-data* Json fields to `Exclude<JsonValue,
null>` (four type aliases: grant, revoke, role/patterns, audit/detail,
request/justification…). Reads can stay `unknown`. Add a compile-only fixture
that assigns a real generated `PrismaClient` to `AlfizPrismaDelegates`, so
this regression cannot recur silently.

## 3. Deleting a principal or a scope instance strands its grants

**Severity: high — this is security-shaped, not ergonomic.**

Grants key on subject and scope *strings*, not foreign keys. Deleting a user,
an API token, or a scoped resource leaves every grant that referenced it in
place. Nothing in the API surface or the docs flags this, and the failure mode
is silent: if an id is ever reused, the new principal inherits the old one's
access.

Garden had to write both cleanups by hand and remember to call them from four
places (`deleteUser` ×2, course delete ×2):

```ts
dropAllAccessFor(subject)      // list grants by subject, delete; plus revokes
dropCourseScope(scopeId)       // list grants by scope, delete
```

**Proposal.** Ship `deleteSubject(subject, provenance)` and
`deleteScope(scope, provenance)` on the Application — everyone hits this, the
implementation is six lines, and getting it wrong is a vulnerability. At
minimum, say so loudly in CONVENTIONS.md next to the resource-moves section,
which already teaches "call `notifyScopeMoved` in the same code path": the
same discipline applies to deletion.

## 4. Missing write APIs force the wrong tool

Three gaps each pushed a routine admin operation onto machinery meant for
something else:

**No caller-supplied ids.** `createRole` and `createGroup` call `this.newId()`
unconditionally. Garden needs two well-known roles ("Course instructor",
"Course assistant") that a SQL data migration must also reference by id.
Because the API cannot accept an id, migration SQL hardcodes `gdnrole_*` while
`createRole` generates UUIDs, and runtime has to resolve "canonical id, else
name" with a per-process cache. *Proposal: optional `id` on `RoleInput` and
the group input, or `upsertRole`.*

**No `updateGroup`.** Groups can be created, re-parented, deleted, and have
membership set — but renaming one has no API. Garden routes renames through
`importDirectory`, which audits as `directory.import_groups` (wrong story for
"an admin renamed a cohort") and clears `parents` unless you read them back
and re-pass them. *Proposal: `updateGroup(groupId, {name, description},
provenance)`.*

**No user provisioning.** `StoredUser` exists in the storage seam, but the
Application exposes no way to set a user's `active` flag. "Deactivate this
account" — a core admin action, and the thing that makes Alfiz evaluate a
principal to no access — has to go through `importDirectory({users: [...]})`.
*Proposal: `setUserActive(userId, active, provenance)`.*

## 5. `alfiz-verify`'s CLI cannot describe a real project

**Severity: medium-high — the CLI was unusable; `verifyProject` was fine.**

`verifyProject` accepts `gateNames`, `visibilityNames`, and
`serverFilePatterns`. `CliConfig` exposes none of them. Every project with its
own guard wrappers gets false errors — and the conventions *encourage*
wrappers; `gateAction` is itself one. Out of the box against Garden the CLI
reported 21 errors, of which 19 were false:

- `gateDestructiveAction`, `assertTeaches`, `requireTeachesApi` — Garden's own
  gates, invisible to the fixed name list, so every action using them read as
  "exported server action contains no gate".
- Consequently `unreferenced-leaf` warned about keys that *are* enforced,
  just through a wrapper.
- Every `/system` route flagged, though the trust domain that must survive a
  database outage is explicitly endorsed by SPECIFICATION.md §2.7 and cannot
  gate on catalog keys by construction.

Garden abandoned the CLI and wrote ~100 lines around `verifyProject`. The two
real findings were worth having (`canAny` used as a gate in two route
handlers — genuinely the documented anti-pattern, now fixed with the any-of
`can` form), which is exactly why the noise matters: at 21 errors nobody reads
the list.

**Proposals.**
1. Pass `gateNames` / `visibilityNames` / `serverFilePatterns` through
   `CliConfig`. One-line change, removes most of the noise.
2. Add an out-of-domain concept: a config list, or an in-file
   `// alfiz-verify-ignore-file <reason>` pragma. The spec already blesses
   surfaces that authenticate outside the catalog; the tooling should have a
   vocabulary for them rather than forcing a path-substring hack.
3. Improve one message: `requireDomainAccess("admin")` reports *"admin is not
   in the catalog (typo, or an undeclared key)"*. `admin` is a declared
   namespace and a valid pattern, so it trips `isOurs` and then fails. The
   right answer is `"admin.*"` — say so: *did you mean `admin.*`?* This is the
   project-root visibility idiom and a newcomer will hit it immediately.

## 6. Ergonomic papercuts

**`effectiveKeys` is the only "holds it anywhere" probe, and it is
O(catalog).** Conditional UI legitimately needs it: under scoped grants, an
instructor holds `publish_course` only at the courses they teach, so an
unscoped "should this button exist" question is the *right* question. The doc
comment says "not a gate", which reads as "don't use this". Garden calls it
once per request and caches the Set. *Proposal: `holdsAnywhere(principal,
key)`, and phrasing that distinguishes "never a gate" from "not useful".*

**Typed keys fight generic wrappers.** `grantedScopes(principal, key)` is
typed to the catalog's `K`. Garden's `assertTeaches(actor, course, permission:
string)` is a runtime wrapper over many keys and had to pass `permission as
never`. *Proposal: accept `K | (string & {})` on the runtime-string paths, or
document a blessed escape hatch.*

**Scope declaration is per-leaf.** 44 of Garden's 97 leaves carry an identical
`scopes: ["garden.course"]`. *Proposal: allow `scopes` on a group, inherited
by its leaves and overridable.*

**One description field.** Pickers want a short label *and* longer help text.
Garden put the label in `description` and keeps a side `DETAILS` map — which
will drift. *Proposal: add `label?` to `PermissionLeafInput` and `GroupInput`.*

**No bulk grant write.** Migrating existing assignments is N sequential
`createGrant` calls, each with its own validation, audit row, and invalidation
event. Garden's seed does ~18; a real tenant migration does thousands.
*Proposal: `createGrants(inputs[], provenance)` with one audit entry and one
event.*

## 7. Two semantics that deserve a much louder callout

Both are correct, both are load-bearing, and getting either wrong silently
produces a system where scoping does nothing.

**A global grant satisfies every scoped check.** The global scope is in every
object closure, so `can(u, k, "docs.doc:1")` passes for anyone holding `k` at
`*`. Obvious once stated. Its consequence is not: if your existing roles grant
resource-level permissions globally — which every pre-Alfiz RBAC system does,
because that is the only thing it *can* do — then adding scopes changes
nothing until you **split those roles**. Garden's teaching roles had to be cut
into a global half and a per-course half; that split *is* the migration, and
it is the step a reader will not anticipate.

**A role's meaning depends on where it is granted.** `appliesAt` restricts a
scoped grant to the leaves declaring that scope type, so granting role R at
`*` and at `docs.folder:9` confers different sets from the same definition.
This is genuinely powerful — it is what let one "Course instructor" role be
safe to hand out per course — but "the same role means different things
depending on where you attach it" is surprising enough to need a worked
example, not one sentence in a method docblock.

**Proposal.** A short `docs/MIGRATING.md`: how to move an existing
role/assignment schema onto grant rows, why global-vs-scoped role splitting is
the crux, and the `appliesAt` worked example. Combined with `createGrants` and
the subject/scope deletion helpers, this is the difference between "Alfiz is
for greenfield" and "Alfiz is adoptable".

---

## What worked well, and should not change

- **The grant row really does absorb everything.** API tokens became
  `service:<id>` subjects, cohorts became `group:<id>` subjects, course
  staffing became a scoped role grant — three features, zero new mechanisms.
  Granting a cohort a permission at one course is now one row in a system that
  never had group permissions at all.
- **`defineCatalog`'s derived types.** Every key at every call site
  compile-checked, with no codegen step.
- **The namespace-per-project escape hatch.** `additionalNamespaces` let 97
  keys keep their exact three-level shape, so no stored pattern and no call
  site had to change. That single feature is why this migration was tractable.
- **The verifier's two real findings.** `canAny` used as a gate in two route
  handlers — the documented anti-pattern, caught by tooling rather than
  review. That is the pitch working exactly as advertised.
- **`explain` / `grantedScopes` as an error-message primitive.** Garden's
  `assertTeaches` distinguishes "you cannot do this at all" from "not here" by
  asking whether the principal holds the key at *any* scope. Better errors than
  the code it replaced, for free.
- **Refusing to delete a role that grants still reference.** Caught a real
  ordering bug in Garden's admin flow immediately.
