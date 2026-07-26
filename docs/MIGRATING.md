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

`defineCatalog` wants `<project>.<tab>.<permission>`, and your existing keys
already have *some* shape. Two escape hatches exist so that stored patterns
and call sites never have to change:

- **`additionalNamespaces`** — if your keys span several top-level prefixes
  (`admin.*`, `billing.*`, `lms.*`), declare each one and give each a
  top-level project. Your keys keep their exact spelling.
- **`allowArbitraryDepth`** — if your keys are two or four levels deep,
  opt out of the three-level convention instead of renaming. New keys can
  still follow the blessed shape.

Two catalog conveniences worth using from day one:

- A group-level `scopes: [...]` declares the default scope types for every
  leaf under it — declare it once per tab instead of on forty sibling
  leaves. A leaf's own `scopes` (including an explicit `[]` for
  global-only) overrides it.
- `label` on leaves and groups is the short picker text; `description` is
  the longer help text. Keeping both in the catalog is what stops UI copy
  drifting into side tables.

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
reason the next reviewer will see:

```ts
// alfiz-verify-ignore-file system trust domain: authenticates by deploy key
```

## 9. The checklist

1. Catalog: keys unchanged (`additionalNamespaces` / `allowArbitraryDepth`),
   scope types declared (`parent: null` only if instances are truly flat),
   group-level `scopes` for scoped tabs.
2. Roles imported **split**: global halves and scoped halves (§3).
3. Assignments imported with `createGrants` under an `import` provenance;
   well-known ids supplied by you.
4. Every delete path paired with `deleteSubject` / `deleteScope`; every
   move path with `notifyScopeMoved`; offboarding with `setUserActive`.
5. Render path on `snapshot`; actions on `can` / `can.fresh`.
6. `alfiz-verify` in CI with your wrappers configured, out-of-domain files
   pragma'd, and the remaining error count at zero.

After that, the capabilities your old system lacked — cohort grants,
time-bound elevation, access requests, per-resource roles — are single
grant rows away, not features to build.
