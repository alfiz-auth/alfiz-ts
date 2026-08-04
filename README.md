# Alfiz

Alfiz is an authorization layer for TypeScript applications. It is not in the
business of authentication — identity (users, sessions, organizations) stays
with your identity provider, and resource data stays in your database. Alfiz
owns everything in between: **who may do what, where, and why**.

## The three layers

| Layer | Package | What it is |
| --- | --- | --- |
| **Client** | `@alfiz/core` | The evaluator: grammar, catalog, closures, check shapes, caches, graph integrity, request evaluation, headless tree logic, and the provider contract. Every capability is a pure function over provider-supplied data. No storage, no I/O. |
| **Application** | `@alfiz/application` (+ `@alfiz/prisma`) | The local provider: the same contract implemented against **your** database through a storage seam. Standalone, it is the **org root** — the complete system for one organization, with the full feature set and no external dependency. |
| **Alfiz Cloud** | `alfiz.dev` | The managed provider speaking the *same contract*: the hosted Dashboard (administration by relay) and Federation (catalog registry, cross-application composition, the centralized org root). Nothing in this repo depends on it, by design. |

The Client/Provider split is enforced in code, not convention. The provider
contract has three normative artifacts, held in exact correspondence by the
type system and the test suite: the `AlfizProvider` interface, the
`AlfizProviderBase` abstract class every provider extends, and the **Alfiz
Provider API** — an [OpenAPI document](packages/core/openapi/alfiz-provider.v1.yaml)
fixing the contract's wire form. Exactly two kinds of implementation exist,
both in `@alfiz/application`: the **local** provider (`AlfizApplication`,
your database) and the **hosted** provider (`HostedProvider`, an API
connection to the same contract served elsewhere — the seam the Dashboard
and Federation ride on). Because the wire form is a language-agnostic
document rather than a TypeScript export, a provider can be implemented —
and consumed — from any language.

Runtime checks never leave your application in any topology: every `can()`
runs in-process against your catalog, your rows, and your resolver.

## Quickstart

```ts
import { defineCatalog, createAlfizClient, parentPointerResolver } from "@alfiz/core";
import { createApplication, memoryDriver } from "@alfiz/application";

// 1. The catalog: the single source of truth, in code. Permissions are
//    declared by their full dotted key — the same notation every check,
//    grant, and nav entry uses, so a key greps straight to its declaration.
export const catalog = defineCatalog({
  namespaces: ["docs"],
  permissions: {
    "docs.files.read": { scopes: ["docs.folder", "docs.doc"] },
    "docs.files.update_file": { scopes: ["docs.folder", "docs.doc"] },
    "docs.files.delete": { scopes: ["docs.folder"] }, // destructive: stands alone
  },
  scopeTypes: {
    "docs.folder": { parent: null },
    "docs.doc": { parent: "docs.folder" },
  },
});

// 2. The application: your database (swap memoryDriver for @alfiz/prisma),
//    your hierarchy, resolved by your code.
const app = createApplication({
  catalog,
  storage: memoryDriver(),
  ancestry: parentPointerResolver((scope) => myDb.parentOf(scope)),
});

// 3. The client: typed checks. Keys are compile-time verified.
const alfiz = createAlfizClient({ catalog, provider: app });

await alfiz.can({ userId }, "docs.files.read", "docs.doc:123");
await alfiz.require({ userId }, "docs.files.update_file", "docs.doc:123");
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
not declare raises `UnknownPermissionError` rather than being evaluated —
and the error names the closest declared keys, so the typo carries its own
fix.

### Typed end to end

The catalog literal derives three unions, and everything downstream carries
them: **keys** and **patterns** gate at compile time (a typo'd `can()` is a
build error), and **scope ids** hint — literal scopes autocomplete every
declared `<scopeType>:` prefix while ids from variables flow through,
because the instance half of a scope id is runtime data.

```ts
type Key = KeyOf<typeof catalog>;      // "docs.files.read" | "docs.files.update_file" | …
type Scope = ScopeOf<typeof catalog>;  // "*" | `docs.folder:${string}` | `docs.doc:${string}`

// Context objects need no hand-written type parameters:
const ctx: { alfiz: ClientOf<typeof catalog>; snap: SnapshotOf<typeof catalog> } = …;

// Write paths are typed too — createApplication infers from the catalog,
// so seeding scripts and migrations autocomplete grants:
await app.createGrant({ subject: "group:teachers", pattern: "docs.files.*", … });
```

Code that consumes the *published* document instead of the source module
(federated apps, other repos) gets the same treatment via codegen:
`alfiz-verify codegen --catalog alfiz-catalog.json --out alfiz.gen.ts`
emits the literal unions, and
`catalogFromDocument<AlfizKey, AlfizPattern, AlfizScopeId>(doc)` pins them
back on.
Typed keys and `alfiz-verify` cover literal call sites; this covers the
runtime-string paths they cannot see — and closes the hole where a
misspelled gate key would pass for anyone holding a covering wildcard.

### Permissions you reference but don't own

Every application announces its own catalog. Some also *interface* with
another's — the hosted dashboard, or a federated sibling. `namespaces` is
what you own; `imports` is what you reference:

```ts
import zoomDoc from "./zoom.catalog.json" with { type: "json" };

export const catalog = defineCatalog({
  namespaces: ["docs"],
  permissions: { "docs.files.read": { scopes: ["docs.folder"] } },
  imports: {
    zoom: {
      from: "registry:zoom@^3",
      document: zoomDoc,           // fetched in CI, committed
      scopes: ["docs.folder"],     // YOUR scope types — zoom's are unresolvable here
      permissions: { "zoom.host": true, "zoom.meetings.*": true },
    },
  },
});

await app.createRole({ name: "Teacher", patterns: ["docs.files.*", "zoom.host"] });
```

From there the catalog works normally: typed keys, verified call sites,
grants, role bundles, pickers. Attaching the owner's `document` is the
recommended shape and the difference is concrete — with it, wildcards
expand, `canAny` answers exactly, and `zoom.hostt` fails the build; without
it a wildcard is an *opaque region*, still grantable and checkable but
approximated wherever an answer needs expanding a pattern into keys. What
you publish never includes imports (that would be defining keys in someone
else's namespace); what you *consume* publishes separately, so a provider
can tell you that you still import a tombstoned key.

Checking a permission you neither own nor import is an **implicit** import:
an `alfiz-verify` error by default, a warning where an import source is
configured, and either is suppressible. At runtime it raises
`UnknownPermissionError` unless you relax
`createAlfizClient({ externalPermissions: "warn" })` — which never softens a
typo in your own namespace, or one outside an import that knows its keys,
and never performs I/O to decide.

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
- **The global `*` confers only declared vocabulary.** A permission admitted
  by `externalPermissions` — declared in no catalog, owned or imported —
  needs a grant that names its namespace. `zoom.*` confers it; a bare `*`
  does not. Otherwise a typo in a foreign namespace would pass for exactly
  the broadly-privileged users who review and test the gate.
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
  Depth is a *convention* the linter enforces, not a structural law: a
  two-level integration catalog (`zoom.host`) declares
  `conventions: { depth: 2 }` and builds. Group levels are folders, inferred
  from the keys — `group()` blocks exist to organize a large catalog, never
  as a requirement for a small one.

## Staleness, honestly

Closures are cached; decisions are not. Subject-side caches default to a
30-second TTL (configurable) plus event-driven invalidation — that TTL is
the bound on over-access after a revocation. Object ancestor chains bust
immediately when a move is reported: your application owns the hierarchy,
so call `app.notifyScopeMoved(scope)` from the code path that changes a
parent pointer; a 60-second chain TTL (configurable) bounds staleness for
moves that were never reported. `can.fresh()` bypasses all caches — pair it
with destructive actions and just-in-time elevations. Nothing on your
request path is ever metered, priced, or throttled by Alfiz Cloud: it is
never in the path of a check, so it cannot see one, bill for one, or slow
one down.

Those TTL bounds are per process. To tighten them across processes — other
nodes, serverless invocations — turn on the **event log**: the Application
persists its invalidation events (`events: { persist: true }`, two extra
tables), and clients revalidate against it (`revalidateAfterMs`) with one
constant-cost read per window that renews caches while writes are quiet and
replays exactly the missed events when they are not. An optional shared
cache (`cacheStore`, with a first-party adapter for any RESP-compatible
service) gives cold processes warm closures under the same freshness rules.

| Mode | Cross-process staleness bound | Steady-state cost per check |
| --- | --- | --- |
| TTL only (default) | subject/object TTL (30s / 60s) | 0 queries warm; full closure fetch per TTL expiry |
| + event log & `revalidateAfterMs` | revalidation window (e.g. 5s) + one request | 0 queries warm; ONE single-row read per window, amortized over all principals |
| + `cacheStore` (L2) | same as above | cold starts read one cache entry + one head read instead of the closure fan-out |
| epoch unreachable (failure) | falls back to the TTL bounds | fail-closed to the database — stale data is never served past its window |

## Metrics

Every check can emit a structured observation — shape, decision,
permission, scope type, principal, and the rows that decided it. It is off
by default, synchronous, guarded, and fire-and-forget: a sink that throws,
hangs, or falls over loses counts and never a decision.

Point it at OpenTelemetry and you are done:

```ts
import { metrics } from "@opentelemetry/api";

const alfiz = createAlfizClient({
  catalog,
  provider: app,
  metrics: {
    observer: otelMetricsObserver({ meter: metrics.getMeter("alfiz") }),
    // Gates are user actions; visibility checks are hundreds per render.
    // Sample them separately — one Math.random() inside the call, no I/O.
    sampleRate: { gate: 1, visibility: 0.02 },
  },
});
```

Or read them directly, with no external system at all — the aggregator is a
pure, bounded, windowed fold you can serve from your own process:

```ts
const local = createMetricsAggregator();
// metrics: { observer: local.observer }
app.get("/internal/permission-metrics", () => Response.json(local.snapshot()));
```

Or store them, and get the question worth having: **what breaks if I revoke
this?** Turn on `metrics: {}` on the Application (one extra table) and point
the client at it:

```ts
const sink = createProviderMetricsSink(app);         // aggregate → batch → store
const usage = await app.getGrantUsage({ ids: [grantId] });
revocationSafeguard(usage[0]);
// → "This grant was the only thing allowing 1200 checks in the last 7 days."
```

That warning keys on `soleMatch` — checks where the row was the *sole*
matcher — not on raw participation, because a grant fully shadowed by a
broader one loses nothing when revoked, and a warning that cries wolf gets
clicked through. And when a grant shows no recent use, Alfiz says exactly
that and no more: absence of use is not evidence that revoking is safe.

Metrics stay where they are produced: there is no uplink and no central
metrics store. The hosted dashboard can read them back for your own
administrators, over the same relay as every other admin surface, and keeps
no copy. They are not a billing dimension, and nothing about the feature
puts anything new on your request path. Counts are sampled and lossy by
design; they are numbers, not audit.

## Packages

- [`@alfiz/core`](packages/core) — the Client, the provider contract
  (interface + abstract class), and the contract's wire form (the
  [Alfiz Provider API OpenAPI document](packages/core/openapi/alfiz-provider.v1.yaml)).
- [`@alfiz/application`](packages/application) — the local provider + storage
  seam, plus both halves of the Provider API wire: the handler that serves it
  from an Application, and the hosted provider that consumes it.
- [`@alfiz/prisma`](packages/prisma) — the Prisma storage driver + schema fragment.
- [`@alfiz/verify`](packages/verify) — static verification (`alfiz-verify`).

`docs/CONVENTIONS.md` is the machine-legible convention document — drop it
into your agent context; `@alfiz/verify` checks what the conventions
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
