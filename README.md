# Alfiz

Alfiz is an authorization layer for TypeScript applications. It is not in the
business of authentication — identity (users, sessions, organizations) stays
with your identity provider, and resource data stays in your database. Alfiz
owns everything in between: **who may do what, where, and why**.

## The three layers

| Layer | Package | What it is |
| --- | --- | --- |
| **Client** | `@alfiz-auth/core` | The evaluator: grammar, catalog, closures, check shapes, caches, graph integrity, request evaluation, headless tree logic, and the provider contract. Every capability is a pure function over provider-supplied data. No storage, no I/O. |
| **Application** | `@alfiz-auth/application` (+ `@alfiz-auth/prisma`) | The local provider: the same contract implemented against **your** database through a storage seam. Standalone, it is the **org root** — the complete system for one organization, with the full feature set and no external dependency. |
| **Service** | (future) | A managed provider speaking the *same contract*: hosted administration by relay, and federation (catalog registry, cross-application composition, the centralized org root). Nothing in this repo depends on it, by design. |

Runtime checks never leave your application in any topology: every `can()`
runs in-process against your catalog, your rows, and your resolver.

## Quickstart

```ts
import { defineCatalog, createAlfizClient, parentPointerResolver } from "@alfiz-auth/core";
import { createApplication, memoryDriver } from "@alfiz-auth/application";

// 1. The catalog: the single source of truth, in code.
export const catalog = defineCatalog({
  namespace: "docs",
  projects: {
    docs: {
      groups: {
        files: {
          permissions: {
            read: { scopes: ["docs.folder", "docs.doc"] },
            update_file: { scopes: ["docs.folder", "docs.doc"] },
            delete: { scopes: ["docs.folder"] }, // destructive: stands alone
          },
        },
      },
    },
  },
  scopeTypes: {
    "docs.folder": { parent: null },
    "docs.doc": { parent: "docs.folder" },
  },
});

// 2. The application: your database (swap memoryDriver for @alfiz-auth/prisma),
//    your hierarchy, resolved by your code.
const app = createApplication({
  catalog,
  storage: memoryDriver(),
  ancestry: parentPointerResolver((scope) => myDb.parentOf(scope)),
});

// 3. The client: typed checks. Keys are compile-time verified.
const alfiz = createAlfizClient({ catalog, provider: app });

await alfiz.can({ userId }, "docs.files.read", "docs.doc:123");
await alfiz.requirePermission({ userId }, "docs.files.update_file", "docs.doc:123");
await alfiz.canAny({ userId }, "docs.*");            // visibility only, never a gate
await alfiz.can.fresh({ userId }, "docs.files.delete", "docs.folder:9"); // destructive: bypass caches
```

Server-rendered pages don't sprinkle `await` through render helpers — they
take **one snapshot per request** and check synchronously. A snapshot is
one consistent instant of the caches (a *stronger* per-request guarantee
than repeated `can` calls), and scope types declared `parent: null` are
flat by contract, so scoped checks stay synchronous too:

```ts
const snap = await alfiz.snapshot({ userId });   // one provider round-trip
snap.can("docs.files.read");                     // sync — safe inside .map()
snap.canAny("docs.*");                           // sync visibility
snap.heldKeys;                                   // every key held at ANY scope
snap.holds("docs.files.update_file");            // "should this button exist at all"
await snap.resolve(rowScopes);                   // list pages: extend after querying
```

Every check is verified against the catalog first: a key or pattern it does
not declare raises `UnknownPermissionError` rather than being evaluated.
Typed keys and `alfiz-verify` cover literal call sites; this covers the
runtime-string paths they cannot see — and closes the hole where a
misspelled gate key would pass for anyone holding a covering wildcard.

Granting is one row, however the access came to be — an admin, a role, a
group, an approved request, `everyone`:

```ts
await app.createGrant({
  subject: "group:teachers",        // or user:…, org:…, everyone, service:…, directs:…, orgof:…
  pattern: "docs.files.*",          // forward-inclusive: includes future keys
  scope: "docs.folder:9",           // or omit for global
  expiresAt: Date.now() + 86_400_000, // optional: time-bound access
  provenance: { kind: "admin", actorUserId: "root" },
});
```

Bulk imports use `createGrants(inputs, provenance)` — validate-everything-
first, one audit entry, one invalidation per subject. And because grants
key on subject and scope *strings*, deletion is a discipline, not an
accident: call `deleteSubject(...)` / `deleteScope(...)` from the same code
paths that delete the principal or the resource (exactly as
`notifyScopeMoved` pairs with moves), or a reused id inherits the stranded
access. `setUserActive(userId, false, ...)` is the reversible offboarding
switch.

## The semantic opinions (fixed, not pluggable)

Alfiz is unopinionated about storage, transport, and deployment — and
*maximally* opinionated about semantics:

- **Union-only inheritance.** Groups, roles, and object hierarchies only
  widen access. The single negative layer is the personal revoke.
- **Negative always wins, scope-inclusively.** A revoke at any scope
  suppresses matching access at that scope and every descendant — including
  a direct grant on a deeper object. Not configurable.
- **Forward-inclusive wildcards.** A stored `docs.*` grants keys added under
  `docs` in the future. Deliberate, documented, owned.
- **Everything reduces to the grant row** `(subject, role-or-pattern, scope,
  expiry?)` with provenance. Requests, public access, machine scopes, and
  time-bound elevation are all this row.
- **Hierarchy is data, resolved at check time.** Grants are stored once at
  the node where they are made; checks walk *up* ancestor chains (O(depth)),
  never down subtrees.
- **A global grant satisfies every scoped check.** `*` is in every object
  closure, so authority granted globally is authority everywhere. The
  consequence for existing systems — whose roles can only grant globally —
  is that adopting scopes means *splitting those roles*; that split is the
  migration, and [`docs/MIGRATING.md`](docs/MIGRATING.md) walks it.
- **The naming floor.** `<project>.<tab>.<permission>`; every tab has a
  `read`; actions are `<verb>_<noun>`; destructive actions stand alone.

## Staleness, honestly

Closures are cached; decisions are not. Subject-side caches default to a
30-second TTL (configurable) plus event-driven invalidation — that TTL is
the bound on over-access after a revocation. Object ancestor chains bust
immediately when a move is reported: your application owns the hierarchy,
so call `app.notifyScopeMoved(scope)` from the code path that changes a
parent pointer; a 60-second chain TTL (configurable) bounds staleness for
moves that were never reported. `can.fresh()` bypasses all caches — pair it
with destructive actions and just-in-time elevations. Nothing on your
request path is ever metered, priced, or throttled: checks are unmeterable
by construction.

## Packages

- [`@alfiz-auth/core`](packages/core) — the Client.
- [`@alfiz-auth/application`](packages/application) — the local provider + storage seam.
- [`@alfiz-auth/prisma`](packages/prisma) — the Prisma storage driver + schema fragment.
- [`@alfiz-auth/verify`](packages/verify) — static verification (`alfiz-verify`).

`docs/CONVENTIONS.md` is the machine-legible convention document — drop it
into your agent context; `@alfiz-auth/verify` checks what the conventions
assume. Moving an existing RBAC system over? Start with
[`docs/MIGRATING.md`](docs/MIGRATING.md) — it covers the role-splitting
crux, bulk import, deletion wiring, and the per-request snapshot pattern.

## Development

```
npm install
npm test          # vitest, all packages
npx tsc -b packages/core packages/application packages/prisma packages/verify
```

Alfiz's own administration permissions live under `alfiz_internal.*` — a
reserved namespace that can never collide with yours.
