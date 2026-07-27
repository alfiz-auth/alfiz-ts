# Migrating an existing RBAC system onto Alfiz

This guide is for the brownfield case: you already have a permission
catalog (a constants file of key strings), roles, assignment tables, maybe
an ad-hoc resource-scoping layer, and hundreds of enforcement call sites.
The goal is to land the migration **without renaming keys, without touching
call sites beyond mechanical substitution, and without changing who can do
what** — and then to turn on the capabilities your old system didn't have.

It is ordered the way a real migration proceeds. Steps 3 and 4 are the two
semantics that decide whether your scoping works at all; read them even if
you skim the rest.

## 1. Keep your keys

You already have a constants file of dotted key strings. `defineCatalog`
takes exactly that — permissions are declared by their full dotted key — so
step one is usually a paste and a reformat, with no key renamed:

```ts
defineCatalog({
  namespaces: ["admin", "billing", "lms"],
  permissions: {
    "admin.access.read": { kind: "read" },
    "admin.access.manage_roles": true,
    "billing.invoices.read": { kind: "read" },
    // …your existing keys, verbatim
  },
});
```

Two things that stop a brownfield catalog from needing renames:

- **`namespaces`** — if your keys span several top-level prefixes
  (`admin.*`, `billing.*`, `lms.*`), declare each one. Your keys keep their
  exact spelling. Group levels are inferred from the keys themselves;
  nothing needs declaring per tab.
- **`conventions: { depth }`** — if your keys are two or four levels deep,
  declare the depth you actually use (or `"any"` for a mixed catalog)
  instead of renaming. This is a linter setting, not a structural gate: a
  catalog that deviates still builds, and `alfiz-verify` reports the
  deviation at build time. New keys can still follow the blessed shape.

Three catalog conveniences worth using from day one:

- `group("<path>", { … }, { … })` bundles one tab's keys into a named,
  foldable block carrying its label and scope defaults. Past ~30 keys,
  blocks are what keep the catalog readable — and because keys are
  absolute, each block can live in its own file next to the feature it
  gates. Small catalogs don't need them at all.
- A group-level `scopes: [...]` (on a block, or via the `groups` map)
  declares the default scope types for every leaf under it — declare it
  once per tab instead of on forty sibling leaves. A leaf's own `scopes`
  (including an explicit `[]` for global-only) overrides it.
- `label` on leaves and groups is the short picker text; `description` is
  the longer help text. Keeping both in the catalog is what stops UI copy
  drifting into side tables.

<details>
<summary>Upgrading a 0.3.x catalog</summary>

The nested `projects` → `groups` → `permissions` shape still builds and is
deprecated, not removed. To convert, flatten each leaf to its full key:

```ts
// 0.3.x
projects: { docs: { groups: { files: {
  scopes: ["docs.folder"],
  permissions: { read: true, delete: { destructive: true } },
} } } }

// 0.4.0
permissions: [
  group("docs.files", { scopes: ["docs.folder"] }, {
    "docs.files.read": true,
    "docs.files.delete": { destructive: true },
  }),
]
```

`namespace` + `additionalNamespaces` become `namespaces` (first is
primary), and `allowArbitraryDepth: true` becomes
`conventions: { depth: "any" }`. Every key, pattern, grant row, and
published document is unchanged — this is a source-level change only.

One behavior change to know about: a key at the wrong depth used to throw
from `defineCatalog`. It is now a lint error reported by `lintCatalog` and
failed by `alfiz-verify`, so a catalog that deviates boots and CI catches
it. If you relied on the boot throw, keep `alfiz-verify` in CI.

</details>

## 2. Everything you are migrating becomes one table

Alfiz has one atomic unit: the grant row
`(subject, role-or-pattern, scope, expiry?)` with provenance. Map your
existing concepts onto it before writing any code:

| You have | It becomes |
| --- | --- |
| role assignment table | grant rows with `roleId`, subject `user:<id>` |
| group/cohort permissions | grant rows with subject `group:<id>` |
| API tokens with permission lists | grant rows with subject `service:<id>` |
| public/anonymous access flags | grant rows with subject `everyone` |
| per-resource ACL rows (`CourseStaff`, …) | grant rows with a `scope` |
| temporary elevations | grant rows with `expiresAt` |

If a concept doesn't fit this table, stop and reread — in every migration
so far the row absorbed it.

## 3. The crux: a global grant satisfies every scoped check

The global scope `*` is in **every** object closure. So
`can(user, "lms.courses.publish_course", "lms.course:9")` passes for anyone
holding `publish_course` at `*` — a global grant is authority *everywhere*,
including every scope you will ever create.

Obvious once stated. Its consequence is the step every migration
underestimates: **your existing roles grant resource-level permissions
globally**, because a scopeless RBAC system has no other place to put them.
If you import "Instructor = may publish courses" as a global role and then
start writing scoped grants, *scoping changes nothing* — every instructor
still passes every scoped check through the global grant.

**Splitting those roles is the migration.** Cut each role that mixes
org-wide authority with per-resource authority into two:

```ts
// BEFORE (the imported shape): one role, granted globally to all teachers.
//   "Instructor": may browse the catalog, AND may publish/grade/etc.
// Granted at *, the publish/grade half is effective at EVERY course.

// AFTER: the global half stays global…
await app.createRole(
  {
    id: "role_teacher_base",
    name: "Teacher (base)",
    patterns: ["lms.catalog.read", "lms.reports.read"],
  },
  provenance,
);
// …and the per-course half becomes a role you grant AT a course.
await app.createRole(
  {
    id: "role_course_instructor",
    name: "Course instructor",
    patterns: ["lms.courses.*"], // publish_course, grade_student, …
  },
  provenance,
);

await app.createGrant({ subject: "user:jane", roleId: "role_teacher_base", provenance });
await app.createGrant({
  subject: "user:jane",
  roleId: "role_course_instructor",
  scope: "lms.course:9", // Jane's authority exists only where she teaches
  provenance,
});
```

Rule of thumb while cutting: for each pattern in an old role ask *"should a
holder be able to do this at a resource they have no relationship with?"*
Yes → the global half. No → the scoped half.

## 4. A role's meaning depends on where it is granted

The same role definition confers **different key sets at different grant
sites**. `appliesAt` restricts a scoped grant to the leaves that declare
that scope type; a global grant confers everything the patterns match.

Worked example, using this tab:

```ts
courses: {
  scopes: ["lms.course"],              // inherited default for the tab
  permissions: {
    read: true,                        // scopes: ["lms.course"] (inherited)
    publish_course: true,              //           "
    manage_catalog: { scopes: [] },    // global-only: no scoped grant confers it
  },
},
```

One role, two grant sites:

```ts
await app.createRole(
  { id: "role_instructor", name: "Instructor", patterns: ["lms.courses.*"] },
  provenance,
);
```

| Check | granted at `*` | granted at `lms.course:9` |
| --- | --- | --- |
| `can(u, "lms.courses.read", "lms.course:9")` | ✅ | ✅ |
| `can(u, "lms.courses.read", "lms.course:10")` | ✅ | ❌ |
| `can(u, "lms.courses.manage_catalog")` | ✅ | ❌ — `manage_catalog` declares no `lms.course` scope, so a course-site grant cannot confer it |

This is what makes one "Course instructor" role safe to hand out per
course: the catalog — not the role author's restraint — bounds what a
scoped grant site can confer. But it also means "grant role R" is an
incomplete sentence during a migration; always say *where*.

## 5. Import assignments in bulk, with your own ids

Migrating N existing assignments is one `createGrants` call, not N
`createGrant` calls: every input is validated **before** any row is written
(one bad assignment rejects the whole batch instead of half-importing a
tenant), then one audit entry records the batch and one invalidation event
fires per distinct subject.

```ts
await app.createGrants(
  assignments.map((a) => ({
    subject: `user:${a.userId}`,
    roleId: a.roleId,
    scope: a.courseId ? `lms.course:${a.courseId}` : undefined,
  })),
  { kind: "import", source: "legacy-rbac-2026-07" },
);
```

Where a SQL data migration must reference a role or cohort by id, pass the
id yourself — `createRole({ id: "role_course_instructor", ... })`,
`createGroup({ id: "cohort_2026", ... })` — so migration SQL and runtime
agree on identity with no name-resolution cache. A taken id is a conflict,
never an overwrite.

## 6. Wire the lifecycle paths, not just the checks

Grants key on subject and scope **strings**, not foreign keys. Alfiz cannot
see your `users` or `courses` tables, so deleting a row there strands the
grant rows here — silently, and if an id is ever reused the new principal
inherits the old one's access. Three pairings, same discipline as
`notifyScopeMoved`:

| In the code path that… | call |
| --- | --- |
| deletes a user / API token / service account | `app.deleteSubject("user:<id>", provenance)` |
| deletes a scoped resource (a course, a folder) | `app.deleteScope("lms.course:<id>", provenance)` |
| moves a resource (parent pointer changes) | `app.notifyScopeMoved("<type>:<id>")` |

`deleteSubject` on a `user:` also removes their revokes, their stored
record, grants held by their implicit-group subjects
(`directs:`/`orgof:`), and cancels their pending requests. `deleteScope`
sweeps one scope id — descendants are separate rows, so call it per deleted
resource when removing a subtree.

For offboarding that must be **reversible**, deactivate instead:
`app.setUserActive(userId, false, provenance)` — an inactive principal
evaluates to no access on every check shape. Delete when the id itself is
being retired.

## 7. Server-rendered apps: one snapshot per request

A server-rendered page performs hundreds of conditional-UI checks inside
pure render helpers and `.map()` callbacks that cannot become async. Do not
make them async. Fetch once per request and check synchronously:

```ts
const snap = await alfiz.snapshot({ userId }); // one provider round-trip

snap.can("lms.courses.read");                    // sync
snap.can("lms.courses.publish_course", courseScope); // sync, scoped
snap.canAny("admin.*");                          // sync visibility
snap.heldKeys;                                   // Set of every key held anywhere
snap.holds("lms.courses.publish_course");        // "should this button exist at all"
```

A per-request snapshot is a **stronger** consistency guarantee than calling
`can` repeatedly — every check in the request sees one data instant and one
clock, instead of a cache that may tick over mid-render. Staleness across
requests stays bounded exactly as documented for the client.

Scoped checks stay synchronous too, in the cases that matter:

- Scope types declared `parent: null` are **flat by contract** — their
  chains are `[scope, "*"]`, computable without I/O. Most first adoptions
  (courses, projects, workspaces) are flat.
- Every scope the principal holds a grant or revoke at is resolved at
  snapshot time.
- A *hierarchical* scope you intend to check must be pre-resolved:
  `alfiz.snapshot(principal, { scopes: [docScope] })`. Checking an
  unresolved hierarchical scope throws rather than guessing a chain —
  guessing would miss ancestor revokes, which fails open.

Actions and route handlers keep gating with `can` / `can.fresh` — the
snapshot is the read/render surface.

### Hierarchical list pages

A list page inverts the order: it cannot know its row ids until after it
queries, so it cannot name them when it builds the snapshot it wanted to
guard with. Two shapes, and which you want depends on the size of the list.

**Tens of rows — resolve after querying.** `resolve` extends an existing
snapshot in place, with no second closure fetch, so every check still sees
one data instant:

```ts
const snap = await alfiz.snapshot(principal);
snap.require("docs.files.read");                       // guard the page
const rows = await db.doc.findMany({ where: { folderId } });
await snap.resolve(rows.map((r) => `docs.doc:${r.id}`)); // ids exist now
const editable = rows.filter((r) => snap.can("docs.files.update_file", `docs.doc:${r.id}`));
```

**Thousands of rows — don't check per row at all.** That is the N+1 the
listing helpers exist to avoid: compute the granted scope set once and push
the filter into your database, so the query returns only visible rows.

```ts
const { granted, revoked } = snap.grantedScopes("docs.files.read");
const plan = planListing({ granted, revoked });
if (plan.mode === "none") return [];                    // never an unfiltered query
const rows = await db.doc.findMany({
  where: plan.mode === "all" ? {} : prismaMatPathWhere(plan.include, { pathField: "path" }),
});
```

Flat scope types (`parent: null`) need neither: their chains are known by
declaration, so `snap.can(key, scope)` works on any row id immediately.

## 8. Turn the verifier on last, and configure it for your wrappers

Your codebase gates through its own wrappers (`assertTeaches`,
`gateDestructiveAction`, …) — the conventions encourage exactly that. Tell
the verifier, or every wrapped action reads as ungated:

```jsonc
// alfiz-verify.config.json — names are ADDED to the built-in defaults
{
  "catalog": "alfiz-catalog.json",
  "include": ["src", "app"],
  "gateNames": ["assertTeaches", "gateDestructiveAction"],
  "serverFilePatterns": ["app/actions/"]
}
```

Surfaces that authenticate outside the catalog *by design* (system trust
domains that must survive a database outage) opt out in-file, with a
reason the next reviewer will see. It belongs in the file header —
anywhere in the leading comments, above or below a `"use server"` /
`"use client"` directive, exactly as JavaScript itself allows:

```ts
"use server";
// alfiz-verify-ignore-file system trust domain: authenticates by deploy key
```

A pragma placed *after* the first real statement does nothing; the verifier
warns and names the line rather than leaving you to infer it from an
unchanged error count.

One thing the upgrade will surface: checks are now verified against the
catalog at runtime too, so a key or pattern the catalog does not declare
raises `UnknownPermissionError` instead of being evaluated. If a nav table
or a generic wrapper carries a bare group path (`"admin"` where `"admin.*"`
was meant), that is where you will hear about it — see §9.

## 9. Runtime strings are checked against the catalog

Typed keys and the verifier cover every literal call site. The paths they
cannot see — nav tables, config, generic wrappers taking `permission:
string` — are checked at runtime instead: a key or pattern the catalog does
not declare raises `UnknownPermissionError`, a **programming error** your
framework should map to 500, never 403.

This is not strictness for its own sake. Both silent behaviours it replaces
were wrong in ways that were nearly impossible to notice:

| Call | Before | Now |
| --- | --- | --- |
| `can(u, "docs.files.raed")` | **`true`** for anyone holding `*` or `docs.*` — the typo admitted exactly the privileged users who review and test it, and denied everyone else | throws, naming the key |
| `canAny(u, "admin")` | `false` — a whole nav section vanishes, no error to search for | throws: *did you mean `"admin.*"`?* |

Two consequences worth planning for:

- **A bare group path is never a valid check.** For visibility, the subtree
  pattern is `"admin.*"`. For a gate, groups are folders — gate on a leaf.
- **Keys must exist in the compiled-in catalog.** That is always true for a
  correct deployment (the catalog ships with the code that checks it), but
  a shared component checking a key from a namespace this app does not
  declare will now say so instead of quietly denying.

Provenance is validated the same way, at the write path: a missing
`actorUserId` is rejected as `ProviderWriteRejectedError("provenance.
actorUserId is required for kind \"admin\"", "validation")` before any row
is written, instead of failing later inside the audit writer as a
driver-level error naming a column you never wrote.

## 10. The checklist

1. Catalog: keys unchanged (`namespaces` / `conventions: { depth }`),
   scope types declared (`parent: null` only if instances are truly flat),
   group-level `scopes` for scoped tabs.
2. Roles imported **split**: global halves and scoped halves (§3).
3. Assignments imported with `createGrants` under an `import` provenance;
   well-known ids supplied by you.
4. Every delete path paired with `deleteSubject` / `deleteScope`; every
   move path with `notifyScopeMoved`; offboarding with `setUserActive`.
5. Render path on `snapshot` (hierarchical list pages: `resolve` after the
   query, or push the filter down); actions on `can` / `can.fresh`.
6. Runtime-string check paths audited for bare group paths, and
   `UnknownPermissionError` mapped to 500 rather than 403.
7. `alfiz-verify` in CI with your wrappers configured, out-of-domain files
   pragma'd (in the header), and the remaining error count at zero.

After that, the capabilities your old system lacked — cohort grants,
time-bound elevation, access requests, per-resource roles — are single
grant rows away, not features to build.

## 11. Adopting the caching upgrades (0.3)

Everything is opt-in; defaults reproduce the previous behavior. The only
observable default changes are strictly improving: the object-chain cache
is now bounded (10 000 entries) and both caches evict least-recently-used
instead of oldest-inserted.

To tighten cross-process staleness from the TTLs to a revalidation window:

1. Merge the `AlfizEpoch` / `AlfizEvent` models from the Prisma fragment
   and migrate (additive — no backfill, no seed).
2. Turn on persistence: `createApplication({ ..., events: { persist: true } })`.
   Multi-node deployments must already be passing a database advisory lock
   to `prismaDriver` — event appends serialize under it too.
3. Give clients a window: `createAlfizClient({ ..., revalidateAfterMs: 5_000 })`.
   Quiet systems stop refetching entirely (validated TTL renewal); a write
   anywhere propagates within one window.
4. Serverless / large fleets, optionally: pass `cacheStore` (any
   `CacheStore`; `respCacheStore(redisClient)` covers the RESP family) so
   cold processes skip the closure fan-out. Private, authenticated cache
   infrastructure only.
5. Long-lived multi-node fleets, optionally: `startEventPoller(app)` for
   push-like invalidation between revalidations.

`notifyScopeMoved` now returns a promise (durability of the move event);
fire-and-forget callers need no change. Custom `StorageDriver`
implementations keep compiling — the new methods (`getRoles`, the four
event methods) are optional, and the Application falls back or fails
loudly (never silently) when they are absent.
