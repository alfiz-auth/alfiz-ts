# Changelog

## 0.7.0 — the enterprise release: safe by default, reviewable by construction

> **Breaking.** Two defaults flip to their safe settings (event persistence
> on the Application, epoch revalidation on the Client), and a failing
> final `auto` approval stage now DENIES instead of stranding the request.
> Read the Breaking section — each change has a one-line opt-out restoring
> the old behavior.

This release answers an external enterprise-readiness review. The theme
throughout: things that were possible are now *declared*, things that were
the integrator's silent obligation are now *detected*, and the safe
configuration is now the *default* one.

**Licensing, finally coherent.** Every package now ships `"license": "MIT"`
and a `LICENSE` file. The previous `UNLICENSED` marker in published
packages contradicted the pricing page's "MIT, forever" — the marker was
the error, not the pricing page. A `SECURITY.md` with a disclosure contact
and a support-window statement ships in the repository root.

**Safe caching by default.** With a storage driver that can persist events
(both bundled drivers can), the Application now persists them by default,
and a Client attached to an epoch-bearing provider now revalidates by
default (5s window). The effective cross-process revocation bound drops
from the blind 30s TTL to the revalidation window, on the default path,
with no configuration. Opt-outs: `events: { persist: false }`,
`revalidateAfterMs: false`. And there is now an incident switch —
`strict: true` on the client makes EVERY check bypass both cache tiers,
exactly as if each call were `can.fresh`; wire it to an environment
variable and flip it when revocations must land immediately.

**Separation of duties, detective by design.** The catalog declares
mutual-exclusion constraints (`constraints.sod`): two or more pattern sets
no principal may hold across. `listSodViolations()` reports every user
whose effective access crosses a constraint — closure walked, roles
resolved, revokes respected — with the concrete keys that put them there.
`sod: { enforce: "reject" }` upgrades user-subject grant writes to
preventive rejection. Evaluation stays union-only: `can()` never consults
a constraint, nothing enters the hot path, and constraint declarations are
validated at boot (including the pattern-in-two-sets bug, and patterns
reaching into open import regions, both of which are declaration errors).

**The condition seam.** A permission may declare
`requiresCondition: true`: holding it is necessary but no longer
sufficient — every gate must pass `{ condition: () => … }` evaluating the
application's own predicate ("under $10k", "still Draft"). A gate without
one throws `MissingConditionError` (a programming error, mapped like
`UnknownPermissionError`), and `alfiz-verify` gains `missing-condition`,
which fails CI on literal call sites missing the predicate. Alfiz still
evaluates no attributes — the seam enforces that YOUR evaluation is
present, which is what keeps `if (amount < limit)` from quietly living
beside the gate where no tool can see it. Conditions are in-process by
construction; visibility shapes ignore them.

**Reviewability.** Three new surfaces answer the questions an access
review asks:

- `exportEntitlements()` — the per-user effective-access rollup: every
  conferred key with `held` (revokes applied) and the conferring rows,
  closure attached. The export an external IGA ingests; write-back is the
  ordinary API.
- `listWildcardDrift({ sinceVersion })` — forward-inclusive wildcards
  absorb keys published later; this names every gained key and every live
  wildcard grant or assigned role that absorbed one. Catalog publishes now
  retain history per version (`AlfizCatalogVersion` model — optional; a
  schema without it answers `unsupported` rather than wrongly).
- `reconcileRows()` — the orphan report behind the
  `deleteSubject`/`deleteScope` discipline: rows referencing users, orgs,
  or scopes the host deleted (existence supplied by host predicates),
  group rows with no group, role grants with no role. `sweep: true`
  deletes through the audited paths; dangling role grants are reported,
  never swept.

**Audit, specified.** `listAuditEvents` grows the export surface: `actor`,
`action`, `from`/`to` time range, and (`at`, `id`) cursor paging. Optional
tamper-evidence: `audit: { hashChain: true }` chains every entry with
SHA-256 over a canonical serialization (stable across JSON column key
reordering); `verifyAuditChain` verifies a full log or an export window
against a carried hash. The chain is evidence, not proof — anchor the head
hash externally — and enabling it serializes appends through
`runExclusive("audit", …)`.

**Directory sync can now deprovision.** `importDirectory` was an additive
upsert: a user who vanished from the directory kept `active: true`, their
memberships, and their reporting edge, forever. With
`{ authoritative: true }` each dataset the snapshot carries becomes
authoritative: absent users are DEACTIVATED (never deleted), memberships
in directory-managed groups are swept for users the map no longer lists
(locally-authored groups untouched), and unasserted reporting edges are
cleared. Every deprovisioning action is audited and counted in the result.

**The non-JS check path.** The Provider API gains `POST /v1/check`: a Go,
Python, or Java service posts a principal, key (any-of array supported),
and scope, and the serving APPLICATION evaluates in-process — same
catalog, same rows, same resolver, same closure caches. "Runtime checks
never leave the application" survives intact: the serving side is the
application, in your infrastructure; the caller pays a network hop, which
is the honest cost of not being in the process. `requiresCondition` keys
answer with an error, not a half-checked yes.

**A published performance envelope.** `npm run bench` seeds synthetic
organizations against the memory driver and prints cold-miss and
warm-check quantiles; representative numbers are published in the docs
with the methodology and its caveats stated.

**Driver conformance, published.** The storage contract suite is now
`@alfiz/application/driver-suite` — the same cases the bundled drivers
pass, including the `runExclusive` serialization case that keeps cycle
detection sound under concurrency, plus new cases for audit filters and
catalog history. A custom driver's test file is three lines.

### Breaking

- **A failing FINAL `auto` approval stage now auto-DENIES** the request
  (decision recorded, `decidedBy: "auto"`) instead of leaving it pending
  at a stage no human can decide. The review called such requests
  "permanently undecidable except by admin override"; a recorded denial
  the requester can re-raise beats an undecidable limbo. Non-final auto
  stages still abstain and fall through — they accelerate, they never
  gate. If you relied on the stranded-pending state as an ersatz admin
  queue, add an explicit `named_approvers` stage last.
- **`events.persist` defaults on** when the driver implements the event
  methods. Opt out with `events: { persist: false }`. An explicit
  `persist: true` against an incapable driver still throws; the auto
  default degrades honestly instead.
- **`revalidateAfterMs` defaults to 5 000** against a provider exposing
  `epoch`, and its type widens to `number | false` — `false` restores
  TTL-only caching. Deployments that pinned staleness tests to the blind
  TTL need the explicit `false`.
- **Log order is now (`at`, `id`)** for audit reads, in every driver.
  Same-millisecond events previously kept memory-driver insertion order;
  they now order by id, identically everywhere, which is what makes cursor
  paging stable. (`AlfizAudit` gains `prevHash`/`hash` columns and an
  `@@index([at, id])`; `AlfizCatalogVersion` is a new optional model —
  merge the updated schema fragment and migrate.)
- `putCatalog` on the storage seam takes an optional third `publishedAt`
  parameter, and two optional history methods join the driver interface.
  Existing drivers compile unchanged; without the history methods the
  drift report answers `unsupported`.
- `AuditEvent` gains optional `prevHash`/`hash`; `listAuditEvents` takes
  the widened `AuditQuery`. Additive on the wire.

## 0.6.0 — the provider seam, made explicit

> **Breaking.** The relay module is replaced by the Alfiz Provider API.
> If you mounted `createRelayHandler` or called `createRelayProvider`,
> read the Breaking section — the rename is mechanical, but the wire
> format underneath changed shape.

The provider contract has always been the system's single load-bearing
interface, implemented identically by the Application and the Service. What
it lacked was enforcement: the contract lived only as a TypeScript
interface, and its wire form lived only as an implementation detail — a
single `{ op, args }` RPC endpoint with positional arguments, describable
to another language by reading the source. This release makes the
Client/Provider split explicit, in code, in three artifacts that cannot
drift:

**The abstract class.** `AlfizProviderBase` (`@alfiz/core`) is the
contract as an implementation root. Exactly two kinds of provider extend
it, by design:

- `AlfizApplication` (`@alfiz/application`) — the **local** provider,
  against your own database. Standalone, the org root; unchanged in what
  it does.
- `HostedProvider` (also `@alfiz/application`) — the **hosted** provider:
  an API connection wrapped in the abstract class, the seam the hosted
  Dashboard, data-plane-less consumers, and Federation attach through.
  Fetch-only; it lives next to the handler that serves its far side, so
  both halves of the wire ship together.

The base class carries only what is invariant across every implementation:
the abstract statement of the contract (checked against the `AlfizProvider`
interface by its `implements` clause), the invalidation-listener plumbing
both implementations shared verbatim, `ingestEvents` for epoch replay, and
the uniform rejection helper. A Client still attaches to the interface and
still cannot observe which implementation it got.

**The operation manifest.** `PROVIDER_OPERATIONS` (`@alfiz/core`,
protocol.ts) names every wire-crossing operation with its read/write kind
and capability gate. A compile-time assertion holds it in exact
correspondence with the interface: add a contract method without a manifest
entry — or a manifest entry naming nothing — and the build fails, naming
the drifted method.

**The OpenAPI document.** The Alfiz Provider API
(`packages/core/openapi/alfiz-provider.v1.yaml`, shipped in the
`@alfiz/core` package) fixes the contract's wire form, and the test suite
holds it to the manifest: one `POST {base}/v1/{op}` per operation,
named-field JSON bodies, object results, and a typed-error envelope under
correct HTTP statuses. The document is normative and language-agnostic —
the reason it exists. A provider (or consumer) in Go, Python, or anything
else is "the abstract class's surface, served over this API"; nothing about
the wire is discoverable only by reading TypeScript.

The wire conventions the document encodes, stated once: every operation is
a POST with a JSON object body of named parameters (`{}` when there are
none); every success is a 200 with a JSON *object* — never a bare array,
primitive, or null — so any response can grow a field without a wire
break; every failure carries the typed envelope, with the status as a
transport hint (403 `not_org_root`, 409 `conflict`/`graph_cycle`, 422
`validation`, 404 `not_found`, 501 `unsupported`). `ProviderWriteRejectedError`
codes and `GraphCycleError` paths survive the wire and re-throw intact, so
a dashboard renders "cycle: a → b → a" identically for local and remote
writes. The live `onInvalidate` stream still never crosses: the epoch
operations remain the cross-process invalidation transport.

### Breaking

- `createRelayHandler` → `createProviderHandler` (`@alfiz/application`).
  Mount it under a catch-all so `POST {base}/v1/{op}` reaches it; the old
  single-endpoint mount no longer matches anything.
- `createRelayProvider` / `RelayProvider` → `createHostedProvider` /
  `HostedProvider` (still `@alfiz/application`). The constructor target is
  unchanged (`url`, `secret`, `timeoutMs`, `fetchImpl`) — `url` is now the
  base URL below which `/v1/{op}` paths are appended.
- The wire format changed from `{ op, args }` positional RPC at one URL to
  per-operation paths with named-field bodies, per the OpenAPI document.
  Both ends of a link must upgrade together.
- `RelayTransportError` → `ProviderTransportError`; protocol-level
  rejections (bad credentials, unknown op, malformed body) surface as
  `ProviderTransportError` with the status, while provider-domain errors
  re-throw typed exactly as before. `RelayWireError` → `ProviderWireError`;
  `toWireError` → `toProviderWireError`; `RELAY_PROTOCOL_VERSION` →
  `PROVIDER_API_VERSION` (now `1`, carried in the path prefix and the
  `ping` result's `api` field). `RelayPingResult` → `ProviderPingResult`.
- `OrgSnapshot` and `ApplyOrgSnapshotInput` moved to `@alfiz/core` — they
  are wire-contract types now, alongside `ProviderWireError` and the
  operation manifest. `@alfiz/application` still re-exports them, so
  existing imports keep compiling.
- Capability-gated absences (epoch off, no metrics store, no storage for
  snapshot ops) now answer with `ProviderWriteRejectedError` code
  `unsupported` under a 501, where the relay answered with a
  `RelayProtocolError` inside a 200.

## 0.5.2 — imported permissions

> **A patch number carrying two breaking changes.** Read the Breaking
> section at the end of this entry before upgrading — `alfiz-verify` will
> report call sites it previously passed in silence, and a hand-written
> provider needs one new field. The version number is deliberately small;
> the changes under it are not.

Every application announces its own catalog. Some also *interface* with
another's — the hosted dashboard, or a federated sibling — and until now the
library handled that case inconsistently in the worst possible direction:
`alfiz-verify` silently dropped any literal outside your namespaces, while
`can()` threw for the same string. CI green, production 500. The
cross-namespace role composition the registry exists to enable could not be
expressed in a catalog at all.

The cause was one field doing two jobs. `namespaces` answered both "which
keys may I declare" and "which keys may I check", so referencing another
application's permission meant claiming its namespace. Those are now split:

```ts
defineCatalog({
  namespaces: ["docs"],                       // what you OWN
  permissions: { "docs.files.read": true },
  imports: {                                  // what you REFERENCE
    zoom: {
      from: "registry:zoom@^3",
      document: zoomDoc,                      // fetched in CI, committed
      scopes: ["docs.folder"],                // YOUR scope types, never zoom's
      permissions: { "zoom.host": true, "zoom.meetings.*": true },
    },
  },
});
```

From there the catalog machinery works normally. Attaching the owner's
`document` is the recommended shape and the difference is concrete: with it
wildcards expand, `canAny` answers exactly, and `zoom.hostt` fails the
build. Without it a wildcard is an **opaque region** — declared, grantable,
and checkable, but approximated wherever an answer would need expanding a
pattern into keys, and those approximations are fail-closed.

Scope wiring is deliberately the importer's: the owner publishes
vocabulary, and only you can resolve your own resources' ancestry. A foreign
scope type is a build error. So is a pattern broader than what you imported
— importing `zoom.meetings.*` does not make `zoom.*` storable, because that
is a widening claim over a namespace you do not own.

Checking a permission you neither own nor import is an **implicit** import.
`alfiz-verify` reports it: an error where no import source is configured
(an application that has never imported has no plausible source for a
foreign key, so it is a typo), a warning where one is, naming the
declaration to paste. At runtime it still throws unless you opt in:

```ts
createAlfizClient({ catalog, provider, externalPermissions: "warn" });
```

Two cases never soften, whatever the setting: a permission under a
namespace you own (enumerable, so unambiguously a typo) and one outside an
import that knows its own keys. And the policy performs no I/O — no
provider lookup, no lazy fetch, no boot-time registry call. Runtime checks
never leave your application, and `snapshot.can()` being synchronous is the
structural proof, not just the promise.

One new semantic, in the fixed-not-pluggable list: **a bare global `*` does
not confer a permission no catalog declares.** `*` means everything in the
declared vocabulary; any narrower pattern names its namespace by
construction and confers normally. Without this, admitting foreign keys
would restore the exact failure `UnknownPermissionError` exists to
prevent — a misspelled gate passing for the broadly-privileged reviewers
who would never notice, and denying everyone it was written for.

What you publish is unchanged: `toDocument()` carries owned vocabulary
only, because publishing imported leaves would define keys in a namespace
you do not own. What you *consume* publishes separately, as its own
artifact and its own provider operation:

```ts
await app.publishImports(catalog.toImportManifest(), provenance);
```

That is what extends drift the one direction it could never reach. The
registry names roles and grants referencing tombstoned keys; it has never
been able to name the code that still imports one.

### Also

- `alfiz-verify` gains per-line suppression:
  `// alfiz-verify-ignore-next-line <rule> <reason>` and its trailing
  `-line` form, for the case the file pragma is far too blunt for. The rule
  name is required, not optional — an unqualified per-line ignore is how a
  `client-reachable-secret` error gets silenced by somebody reaching for the
  nearest way to quiet an unrelated warning. A pragma with no reason, no
  rule, or nothing left to suppress is itself a warning.
- `catalogFromDocument(document, { imports, documents })` rebuilds a catalog
  that knows its imports. A published document carries owned vocabulary by
  design, so tooling reading one alone would have called every imported key
  foreign.
- `alfiz-verify.config.json` gains `importManifest`, `imports`,
  `importSource`, `implicitImports`, and `implicitImportAllow`.
- The permission tree gains a `region` node kind. Regions have no leaves
  under them, and a node with nothing to satisfy can never read as fully
  selected — so an imported subtree would otherwise have been permanently
  untickable in every role editor built on the kit.
- `lintCatalog` skips imported entries. Another application's keys answer to
  its depth convention and its naming floor, not yours, and a finding your
  codebase cannot act on is the wrong kind of finding.
- Optional provider surface: `publishImports` / `getPublishedImports`,
  gated by `capabilities().imports`, with an optional `AlfizImports` Prisma
  model and two new relay ops. A driver without them still satisfies the
  contract.

### Breaking

`alfiz-verify` previously **skipped** foreign-namespace literals in silence,
so a project already referencing them will see new findings. This is the
correct direction — those call sites throw at runtime today — but it will
move your error count. Declare the import, or set
`"implicitImports": "off"`.

`ProviderCapabilities` gains a required `imports` field; a hand-written
provider implementation needs one line.

## 0.5.1 — usage over time

`getPermissionUsage` and `getScopeTypeUsage` now return a `buckets` array
alongside their totals, the same per-bucket shape `RowUsage` has carried
since 0.5.0:

```ts
const [usage] = await app.getPermissionUsage({ ids: ["docs.files.delete"] });
usage.gateAllow;                        // 1_284 — the total, unchanged
usage.buckets.map((b) => b.gateAllow);  // [201, 173, 244, …] — day by day
```

The store has always bucketed by day; only the read collapsed it, which
left a usage-over-time chart with no source for the one dimension that
carries denials. The totals are exactly the series summed, so this costs one
pass over rows already fetched and saves callers a round trip per bucket.

Buckets with no traffic are absent rather than zero-filled — a caller that
wants a dense axis knows the window and the granularity and can fill the
gaps, and a sparse window should not pay for its empty days.

Purely additive: a new field on a returned type, no contract method added,
no storage change, nothing to migrate.

## 0.5.0 — permission metrics

Two questions had no good answer from access data alone. *Which permissions
are actually exercised?* — the one a product owner asks before deprecating a
surface. And *if I revoke this grant, what breaks?* — the one an
administrator asks with the delete button already under the cursor. Both are
answerable at the only place that sees every check: the Client, in your own
process.

### The observation stream

Every evaluated check can emit a structured `CheckObservation` — shape,
decision, permission, scope type, principal, and the rows that decided it —
to an observer you configure. It is off by default, synchronous, guarded,
and fire-and-forget: an observer that throws, hangs, or falls over loses
counts and never a decision, and nothing in the feature can add latency to a
check.

The observer is the product, not an implementation detail, and the shipped
OpenTelemetry adapter is the proof — a few dozen lines against the same
interface any sink of yours would use:

```ts
const alfiz = createAlfizClient({
  catalog,
  provider: app,
  metrics: {
    observer: otelMetricsObserver({ meter: metrics.getMeter("alfiz") }),
    sampleRate: { gate: 1, visibility: 0.02 },
  },
});
```

Your dashboards, your alerting, your retention, joined to your application
metrics. Alfiz does not host any of that and is not going to.

### Sampling, for the request paths that need it

`sampleRate` is evaluated with one random draw *inside the call*, before any
observation is built — an unsampled check costs a comparison and allocates
nothing. No storage read, no coordination: not pure, and fast, which is the
trade a high-traffic path wants.

Gates and visibility traffic sample separately, because they differ by
orders of magnitude: one server render fires hundreds of `canAny` and
`holds` checks, while gates correspond one-to-one with user actions and are
usually worth keeping whole. Every observation carries the rate that kept
it, so counts extrapolate honestly — and both figures survive, `observed`
next to `estimated`, rather than one quietly standing in for the other.

Sampling decides only whether a check is **counted**. It can never change an
answer.

### Reading them directly

`createMetricsAggregator()` is a pure, windowed, bounded fold over the
stream with a live `snapshot()` — a complete metrics API with no external
system and no storage:

```ts
const local = createMetricsAggregator();
app.get("/internal/permission-metrics", () => Response.json(local.snapshot()));
```

Memory is fixed regardless of traffic: scope instances aggregate to scope
**type** unless a type opts in, principals live in a bounded map with an
overflow flag, every counter map is capped, and each batch reports what it
dropped. Windows are tagged with an instance id, so many app servers merge.

### Storing them, and the revocation safeguard

`metrics: {}` on the Application adds one table of rolling daily counters,
keyed by grant, revoke, role, permission, and scope type, with retention
compaction. `createProviderMetricsSink(app)` wires the client to it.
Delivery is batched, pre-aggregated, unawaited, and back-pressured — under
load it drops batches rather than growing a queue, because the right failure
mode for a counter is losing counts, not adding latency.

What that buys is the warning:

```ts
revocationSafeguard((await app.getGrantUsage({ ids: [grantId] }))[0]);
// → "This grant was the only thing allowing 1200 checks in the last 7 days."
```

It keys on **`soleMatch`** — checks where the row was the *sole* matcher —
not on raw participation. A check satisfied by two grants loses nothing when
one is revoked, so warning about a grant fully shadowed by a broader one
just teaches administrators to click through warnings; that case reads
"matched 40 000 checks, but was never the only thing allowing them" instead.
Revokes get the mirrored treatment, pointing the other way: deleting a
revoke *widens* access.

And when a grant shows no recent use, the copy says exactly that and stops.
Absence of use is not evidence that revoking is safe — break-glass access is
precisely the kind that sits unused for months.

### Also in this release

- **`capabilities().metrics`** joins the provider contract, gating the new
  optional `reportMetrics` / `get*Usage` methods exactly as `audit` gates the
  audit log. A deployment that has not opted in advertises `false`, stores
  nothing, and renders nothing.
- **`StorageDriver.recordMetrics` / `readMetrics` / `pruneMetrics`** are
  optional, implemented by the memory and Prisma drivers. The Prisma schema
  fragment gains one model, `AlfizMetric`; a client generated without it
  still satisfies the delegate bundle, and enabling `metrics` against a
  driver that cannot store them throws at construction rather than accepting
  batches that go nowhere.
- **`explain()` gains `impliedBy`** — the grants at a descendant scope behind
  a §7.5 ancestor implication. `matchedGrants` keeps its exact meaning (rows
  matching *at this scope*), so an implied allow still reports none there.
- **Check shapes take an optional `CheckOptions`** (`{ observe }`), and
  `snapshot()` an `observe` flag. View-as previews set it: an administrator
  looking through someone's eyes did not use that person's grants, and
  attribution never follows the preview.
- **`require` and `requireAny` no longer delegate** to `can` / `canAny`
  internally. One call now produces one observation, named for the shape
  actually called.

### The guarantee, restated precisely

The old sentence — "checks are unmeterable by construction" — was the
stronger claim and, with this release, the false one. The durable one is
about dependency, and it is unchanged: **Alfiz Cloud is never in the path of
a check**, so it cannot see one, bill for one, or slow one down. Permission
metrics are your counts of your checks, in your database. There is no
uplink, no central metrics store, and no cross-application metrics
dashboard — that would make checks observable to the Service, and would be a
deliberate amendment to the specification rather than a side effect of a
feature. See §18 of `docs/SPECIFICATION.md`.

## 0.4.0 — the catalog says what it means

The catalog input was overcommitted to a shape the data model never had.
`projects` → `groups` → `permissions` spelled out a three-level hierarchy in
three different keywords while the built catalog, the published document, and
every consumer of both were already flat lists of leaves and groups — and
reading `mathaniyy.approvals.decide_student` out of that nesting meant
traversing four levels of indentation and mentally deleting two of them. The
key you check with was never the key you could grep for.

Permissions are now declared by their **full dotted key** — the notation
every check, grant, role pattern, and nav entry already used.

```ts
defineCatalog({
  namespaces: ["docs"],
  permissions: {
    "docs.files.read": { kind: "read" },
    "docs.files.delete": { destructive: true, scopes: ["docs.folder"] },
  },
});
```

Nothing about the permission grammar, the wire format, or evaluation changed.
This is a source-level change to how a catalog is *written*.

### Groups are inferred, and optional

Every dotted prefix of a declared key is a group. Nothing declares them into
existence, so depth costs nothing and a small catalog needs no grouping
construct at all — ten keys in one flat map is a complete, idiomatic catalog.

For catalogs big enough that a flat map becomes a wall, `group()` bundles one
group's keys into a named, foldable unit carrying its label and scope
defaults, and `permissions` accepts an array of blocks mixed freely with bare
maps:

```ts
export const courses = group("lms.courses", { label: "Courses", scopes: ["lms.course"] }, {
  "lms.courses.read": { kind: "read" },
  "lms.courses.publish": true,
});

defineCatalog({ namespaces: ["lms"], permissions: [courses, enrollments] });
```

A key that does not start with its block's path is a **compile error** naming
the fix, so a block's prefix cannot drift from its contents. And because keys
are absolute, blocks compose by concatenation — a large catalog splits into
one file per feature, declared next to the code it gates, with no deep merge
to reason about. That composition is the reason for absolute keys, not a
side effect of them.

- **`namespaces: [...]`** replaces `namespace` + `additionalNamespaces` (first
  is primary). Two lists that had to mirror the project keys by hand become
  one.
- **`groups: { … }`** is an optional metadata map for paths you did not write
  a block for — typically the project level.
- Group children keep **declaration order** in pickers and role editors, as
  before; only the top-level maps are sorted.

### Depth is a convention, not a boot error (behavior change)

`defineCatalog` used to throw when a key was not exactly three levels deep,
escapable by one global `allowArbitraryDepth` boolean. But a two-level
integration catalog (`zoom.host`) is a house-style decision, not a structural
error — and the module's own contract already said structural invalidity
throws while convention violations lint. It now follows it:

```ts
conventions: { depth: 3 }      // the default
conventions: { depth: 2 }      // an integration catalog
conventions: { depth: "any" }  // opt out
```

A deviation is a `lintCatalog` error, failed by `alfiz-verify` in CI. If you
relied on the boot throw, keep the verifier in CI. Structural invalidity
still fails at boot — and gains a check flat keys make possible that nesting
made unreachable: a key that is also a group path (`docs.files` declared
alongside `docs.files.read`) would be both a folder and a leaf, and is
rejected.

### Breaking: the nested shape is gone

Alfiz is pre-1.0 and this ships no compatibility shim. `projects`,
`namespace`, `additionalNamespaces`, and `allowArbitraryDepth` are **removed**
— `namespaces` and `permissions` are now required, and everything else about
`CatalogInput` is optional.

Every key, pattern, stored grant row, and published document is unchanged, so
this is a source edit with no data migration. `docs/MIGRATING.md` has the
conversion, which is mechanical: flatten each leaf to its full key.

`CatalogDocument` gains an optional `conventions` field at the same
`formatVersion: 1`; documents written before 0.4.0 read back at the default
depth.

### Types

Deriving keys from absolute strings is materially cheaper than walking two
sibling records per level: `CatalogKeys` is now a union of the entries' own
key sets, and group wildcards come from a prefix-splitting template type. The
anti-widening suite (`derived-types.test-d.ts`) covers the new surface,
including the compile error for an out-of-block key.

## 0.3.0 — the relay seam, and caching that survives more than one process

The staleness bound stops being "a TTL per process" and becomes "one
revalidation window, any number of processes" — opt-in, with defaults
byte-identical to 0.2.2 (except two strict improvements: the object-chain
cache is now bounded, and both client caches evict LRU).

### The relay seam (Alfiz Cloud)

- **Relay** — `@alfiz/application` ships the Application side of the
  Alfiz Cloud relay protocol (`relay.ts`): `createRelayHandler` mounts one
  bearer-authenticated POST endpoint (timing-safe secret check) whose ops
  mirror the provider contract one-to-one, plus the epoch reads, the
  org-snapshot ops that promotion/demotion/sync ride on, and a health
  probe. Every relayed write lands in the same provider methods local code
  calls, so org-root gating, validation, graph integrity, and audit apply
  unchanged; typed errors survive the wire (`ProviderWriteRejectedError`
  codes, `GraphCycleError` paths re-thrown intact). `createRelayProvider`
  is the calling side: an `AlfizProvider` over fetch exposing the linked
  Application's epoch, with `ping` / `exportOrgSnapshot` /
  `applyOrgSnapshot` extras and `RelayTransportError` for transport
  failures. `onAuthorityChanged` tells the host to reconstruct its
  Application when an authority transfer flips the `orgRoot` flag. Runtime
  checks never traverse the relay; nothing here is on any request path.

### The event log (cross-process invalidation)

- `events: { persist: true }` on the Application appends every
  invalidation event to a sequenced log (`AlfizEpoch` + `AlfizEvent`,
  additive Prisma fragment) before the write returns, exposed as
  `provider.epoch { head, since }`. Retention defaults to 7d / 100k rows.
- `revalidateAfterMs` on the client: past the window, ONE constant-cost
  head read (coalesced across concurrent checks) validates both caches
  for every principal — unchanged head renews TTLs, changed head replays
  only the missed events, gaps bust everything. Generation-guarded
  renewal keeps fetch/replay races TTL-bounded. Fail-closed: an
  unreachable epoch degrades to exactly the old TTL contract.
- `ingestEvents` + `startEventPoller` — push-like invalidation for
  long-lived nodes, optional sugar over the same log.

### The shared cache tier (serverless cold starts)

- `CacheStore` (three string-valued methods, zero dependencies) as an L2:
  read order L1 → L2 → provider; entries served only under exactly the
  current log head (or within the TTL, epoch-less); every error is a
  miss. `respCacheStore` adapts node-redis/ioredis call shapes
  structurally — first-party support for the whole RESP family.

### The miss path, fixed

- `getSubjectAccess` no longer scans the entire group table per miss (the
  topology map is cached with `groupTopologyTtlMs`, busted synchronously
  by group writes), fetches each referenced role once — batched via the
  optional `StorageDriver.getRoles` — instead of twice serially, and
  overlaps independent queries.

### Client cache hygiene

- Object-chain cache bounded (`maxObjectCacheEntries`, 10k); LRU
  eviction on both caches; O(affected) event busting via secondary
  indexes; in-flight coalescing for chain resolution; bust-during-fetch
  state now self-pruning instead of growing per busted key.
- `notifyScopeMoved` returns a promise (resolves when the move event is
  durable). All other new surface is optional; custom drivers compile
  unchanged.

## 0.2.2 — typed end to end, errors that carry their fix
## Unreleased — one name per question, on every surface

The check surface is the same set of questions it was; what changed is that
each question now has exactly one name, spelled identically wherever it is
asked. If you know the question, you know the method name — on the client,
the snapshot, the session, and the new session snapshot.

### Renames (breaking)

- **`client.requirePermission` → `client.require`** — matching
  `snapshot.require` and `session.require`. (The verifier's
  `DEFAULT_GATE_NAMES` still recognizes `requirePermission`, so host-app
  wrappers by that name keep counting as gates.)
- **`client.holdsAnywhere` → `client.holds`** — matching `snapshot.holds`.
  Same semantics: held at ANY scope, never a gate.
- **`client.effectiveKeys` → `client.heldKeys`** — matching
  `snapshot.heldKeys`. Same semantics: every catalog key held somewhere.

### Session snapshots: view-as joins the one-snapshot-per-request pattern

- **`session.snapshot(options?)`** — one fetch per identity, then
  synchronous, preview-narrowed checks: `can` / `canAny` / `require` /
  `requireAny` / `holds` / `heldKeys`, each the actor ∩ preview
  intersection, plus `resolve(scopes)` extending both identities at once.
  Render paths under view-as no longer fall back to per-button `await` —
  the gap where the prescribed render pattern was impossible is closed.
  Role previews evaluate synchronously with no extra resolution (role
  patterns are global-scope by construction); unknown role ids fail
  closed. `SessionSnapshotOf<Cat>` completes the derived-type family.
- Denials thrown from a session snapshot name the ACTOR, exactly as on the
  async session methods — attribution never follows the preview.

### Sharper edges, stated where you hit them

- **`holds` is now verifier-enforced as never-a-gate**: it joins
  `canAny`/`requireAny` in `DEFAULT_VISIBILITY_NAMES`, so a `holds` call
  inside a server action or route handler is a build error, not a
  convention.
- **`requireAny`'s one sanctioned use is now stated on the method**: the
  page-top visibility guard on a page that still gates its own read.
  Never an action gate.
- **`can` with no scope means the GLOBAL scope** — "may they do this
  everywhere?", not "anywhere?" — now documented on the gate itself, with
  the pointer to `holds` for the anywhere question.

No package versions were bumped; these land with the next release.

No semantic changes: this release is developer experience — the derived
types now cover every surface a human types a permission or scope into,
and every error explains itself. Nothing breaks: new type parameters
default to the old `string` behavior, and scope typing is a *hint*, not a
gate.

### The derived-type family grows a third member: scopes

- **`ScopeOf<typeof catalog>`** — `"*" | "docs.folder:${string}" | …`,
  derived from the declared `scopeTypes` exactly as `KeyOf` / `PatternOf`
  derive from the tree. Carried by the client, snapshot, and session as a
  third type parameter (defaulting to `string`).
- Scope parameters (`can`, `require*`, `explain`, `snapshot({ scopes })`,
  `resolve`) are **hints, not gates** (`LooseScopeId`): literal call sites
  autocomplete `*` and every declared `<scopeType>:` prefix, while ids
  from variables and databases flow through unchanged. Keys and patterns
  remain strictly gated — a scope id's instance half is runtime data; a
  permission key never is.
- **`scopeId(type, id)` narrows**: it now returns `` `${T}:${string}` ``,
  so ids built through the helper satisfy the derived scope union.

### The write paths are typed

- `GrantInput` / `RevokeInput` / `RequestInput` / `RoleInput` are generic
  over the catalog's pattern and scope unions (defaulting to `string` — the
  `AlfizProvider` wire contract is unchanged).
- **`createApplication` now infers from the catalog** exactly as
  `createAlfizClient` does, so seeding scripts, data migrations, and admin
  actions autocomplete `pattern:` and `scope:` at the call site. Loose
  (`LoosePattern`), deliberately: role editors legitimately pass runtime
  strings, and the write path validates every one against the catalog
  regardless.

### Autocomplete crosses the wire: codegen

- **`alfiz-verify codegen --catalog <doc.json> [--out <file>] [--prefix
  <Name>]`** emits a dependency-free module of literal unions
  (`AlfizKey` / `AlfizPattern` / `AlfizScopeType` / `AlfizScopeId`) from a
  published `CatalogDocument`. Deterministic (sorted), so regeneration
  diffs are exactly the catalog change. Programmatic form:
  `generateCatalogTypes(document, options)`.
- **`catalogFromDocument<K, P, S>(doc)`** pins the emitted unions back
  onto a document-built catalog (`TypedCatalog<K, P, S>`), and
  `createAlfizClient` picks them up — federated consumers of a published
  catalog get the same typed `can` as the team that owns the source
  module. Untyped calls still return `string`-typed catalogs, honestly.
- `KeyOf` / `PatternOf` / `ScopeOf` now read the phantom members, so they
  work uniformly for literal-built and document-typed catalogs.

### Errors carry their fix

- **Edit-distance "did you mean"** on every unknown-permission surface:
  check paths (`UnknownPermissionError.didYouMean`), Application write
  rejections, and `alfiz-verify` findings. `can(u, "docs.files.raed")` now
  says *did you mean "docs.files.read"?* — and a right-leaf-wrong-group
  string (`docs.approvals.decide_student`) names the key under the project
  that actually declares it.
- **Undeclared namespaces are called out**: `"stripe.charges.create"`
  reports that `stripe` is not a namespace of this catalog, and lists the
  declared ones — the "wrong catalog entirely" mistake stops reading like
  a typo. (`unknownPermissionContext` / `closestPatterns` are exported for
  wrappers that build their own messages.)
- **`validateGrantableAt` says where the grant WOULD be valid**: unknown
  scope types list the declared ones; non-grantable patterns list the
  scope types their matched leaves declare (or say "global-only, add
  `scopes`"); no-match patterns get a near-miss.
- **`UnresolvedScopeError`** (new, typed) replaces the bare `Error` a
  snapshot threw for an unresolvable scope — carrying the scope, its
  type, whether it is declared, and the scopes the snapshot CAN evaluate,
  with the pre-resolve recipes in the message.
- **`AccessDeniedError` names the principal** (`for user:u1`) when the
  throw site knew it — `requirePermission`, `snapshot.require`, session
  gates — and points at `explain()` for the why. New `principal` field
  for structured handling.

### Regression-proofing the types themselves

The silent failure mode of derived types is *widening*: one annotation of
`Record<string, GroupInput>` in the wrong place and every call site still
compiles — autocomplete just disappears. `vitest` now runs a typecheck
suite (`packages/core/test/derived-types.test-d.ts`) asserting the unions
stay **exactly** their literal members, that typos are compile errors, and
that document-typed catalogs thread through `createAlfizClient`.

## 0.2.1 — second field report

From upgrading the same LMS to 0.2.0 and adopting the surface it added.
Every 0.1.2 finding stayed fixed; this release is the friction the upgrade
itself exposed — plus a soundness hole found while investigating one of it.

### Checks are verified against the catalog (behavior change)

Investigating the reported "`canAny("admin")` silently answers `false`"
turned up its sibling on the **gate** path, in the dangerous direction:
`*` matches any string, so `can(user, "docs.files.raed")` returned **true**
for anyone holding a covering wildcard and `false` for everyone else. A
misspelled gate key admitted exactly the broadly-privileged users who
review and test it, while denying the users it was written for.

Both are the same missing rule, now enforced at every check boundary:

- An undeclared key or pattern raises **`UnknownPermissionError`** instead
  of being evaluated — a programming error; map it to 500, never 403.
  `isUnknownPermission(err)` narrows it.
- Enforced on `can`, `canAny`, `require*`, `explain`, `grantedScopes`,
  `holdsAnywhere` and every snapshot equivalent. Typed keys and
  `alfiz-verify` already covered literal call sites; this covers the
  runtime-string paths they cannot see (nav tables, config, generic
  wrappers) — the ones the report's nav regression came from.
- Messages carry the fix: a group path where a pattern belongs says *did
  you mean `"admin.*"`?*; a group path where a **gate key** belongs says to
  gate on a leaf, since `admin.*` is not a gate either.
- `assertCanViewAs` now denies (rather than raising) when a catalog is
  built with `includeAlfizInternal: false` — previews fail closed.

**Upgrading:** a bare group path or a stale key in a runtime-string check
path now throws where it previously returned a quiet boolean. That is the
bug becoming visible; fix the string or declare the key.

### The ignore pragma follows JavaScript's own rule

`// alfiz-verify-ignore-file <reason>` is now recognized anywhere in the
file **header** — the leading comments, above *or below* a `"use server"` /
`"use client"` directive, exactly as the language permits comments before
and between directive-prologue statements. Every RSC file puts that
directive on line 1, so requiring the pragma above it made the natural
placement the broken one.

And a misplaced pragma is no longer a silent no-op: it is reported as a
warning naming its line. A security tool that quietly drops its own escape
hatch teaches the adopter that the escape hatch doesn't work.

Also recognized inside a JSDoc header; prose that merely mentions the
pragma mid-sentence is not one. `ignoreFilePragma` is replaced by
`findIgnorePragma`, which returns `{ reason, line, effective }`.

### Provenance validated at the write path

A provenance missing its `actorUserId` used to pass through every write and
fail inside the audit writer, as a driver-level error naming a Prisma
argument the developer never wrote. `validateProvenance` (exported from
core) now checks the required fields per kind, and the Application asserts
it at the **top of every public write** — not merely in `actorOf`, which
runs after the row is inserted and would leave a written row with no audit
entry. `actorOf` keeps the assertion as a backstop.

### Grant queries that don't scan

- `listGrants({ roleId })` on the provider contract (the storage seam
  already supported it) — "who holds this role" without reading every
  grant in the organization.
- **`countGrants(filter)`** through the contract, the storage seam, and
  both drivers (`SELECT count(*)`), for the role-holder count an admin page
  renders per row. `deleteRole` uses it for its blocking-holder check.
  *Breaking for third-party storage drivers:* implement `countGrants`.

### Derived types and hierarchical list pages

- **`SnapshotOf<Cat>`**, **`ClientOf<Cat>`**, **`SessionOf<Cat>`** round out
  `KeyOf` / `PatternOf`, so a snapshot on a request-context object stops
  needing hand-written type parameters.
- **`snapshot.resolve(scopes)`** extends an existing snapshot's chains
  without a second closure fetch — the shape a hierarchical list page
  needs, since it cannot know its row ids until after it queries. The data
  instant and clock are unchanged, so the consistency guarantee holds.
  Documented, with the push-the-filter-down alternative for large result
  sets, in the snapshot docblock, CONVENTIONS, and `docs/MIGRATING.md` §7.

## 0.2.0 — the alpha-feedback release

Shaped by the first real migration (a Next.js LMS with a 97-key catalog,
~400 call sites, and a hand-rolled scoping layer). The theme: the semantics
were right; the surface around adopting them needed to grow.

### The request-scoped snapshot (`@alfiz/core`)

- `client.snapshot(principal, { scopes?, fresh? })` → `AlfizSnapshot`: one
  provider round-trip, then **synchronous** `can` / `canAny` / `require` /
  `requireAny` / `explain` / `grantedScopes` / `holds` / `heldKeys`. The
  first-class pattern for server-rendered frameworks, where conditional-UI
  checks live in render helpers and `.map()` callbacks that cannot become
  async. A snapshot is one consistent instant — a stronger per-request
  guarantee than repeated `can` calls, with the same cross-request
  staleness bounds.
- Every scope in the principal's own grant/revoke rows is chain-resolved at
  snapshot time, so revoke suppression, `canAny`, and §7.5 ancestor
  implication agree exactly with `client.can`. Hierarchical check targets
  are pre-resolved via `{ scopes: [...] }`; checking an unresolved
  hierarchical scope throws instead of evaluating a truncated chain (which
  would fail open on ancestor revokes).
- **Semantic tightening:** a scope type declared `parent: null` now commits
  to flat instances — chains are `[scope, "*"]` by declaration, which is
  what keeps scoped checks on top-level types synchronous. Types whose
  instances nest under the same type declare themselves as their own parent
  (`"docs.folder": { parent: "docs.folder" }`).
- `client.holdsAnywhere(principal, key)` — the single-key "held at any
  scope" probe; `effectiveKeys` reframed: legitimate for unscoped
  conditional UI, still never a gate.
- `LooseKey<K>` (`K | (string & {})`) on the introspection paths —
  `explain`, `grantedScopes`, `holdsAnywhere`, and the snapshot
  equivalents — so generic wrappers over many keys stop needing
  `as never`. Gates stay strictly typed.

### Referential cleanup and the missing write APIs (`@alfiz/application`)

- **`deleteSubject(subject, provenance)`** — grants key on subject strings,
  so deleting a principal in the host's tables silently stranded its rows,
  and a reused id inherited them. Sweeps every grant held by the subject;
  for users also revokes, the stored record, implicit-group
  (`directs:`/`orgof:`) grants, and cancels pending requests.
- **`deleteScope(scope, provenance)`** — the resource-deletion half: grants
  and revokes at the scope, plus cancellation of pending requests targeting
  it. Paired with the host's delete paths exactly as `notifyScopeMoved`
  pairs with moves (see the new CONVENTIONS section).
- **`createGrants(inputs, provenance)`** — the bulk write migrations need:
  every input validated before any row is written, one audit entry
  (`grant.create_bulk`), one invalidation event per distinct subject.
- **Caller-supplied ids** on `createRole` / `createGroup` — migration SQL
  and runtime agree on well-known ids; collisions are conflicts, never
  overwrites.
- **`updateGroup(groupId, { name, description }, provenance)`** — renames
  no longer detour through `importDirectory` (which audited as a directory
  sync and clobbered parents).
- **`setUserActive(userId, active, provenance)`** — the reversible
  offboarding switch; creates the record when absent so deactivating a
  never-provisioned principal sticks.
- Unknown-pattern rejections on every write path now name the group-path
  near-miss: `"docs"` → *the subtree pattern is `"docs.*"`*.
- Storage seam (breaking for driver implementors): `deleteUser(userId)`
  added; `listRevokes` filter gains `scope`.

### The generated-client promise, pinned (`@alfiz/prisma`)

- Create-data Json fields narrowed from `JsonValue` to
  `InputJsonValue = Exclude<JsonValue, null>` — Prisma rejects bare `null`
  in Json inputs (SQL NULL needs the `Prisma.JsonNull` sentinel), so the
  old width made every generated client fail the structural match and
  forced the exact cast the README calls unnecessary.
- Optional properties are now declared Prisma-style (`prop?: T`, no
  explicit `| undefined`), so the match also holds for adopters compiling
  with `exactOptionalPropertyTypes`.
- `src/prisma-client-shape.ts`: a compile-only replica of the types
  `prisma generate` emits for the Alfiz models, with per-model
  assignability assertions. A delegate change that would break generated
  clients now fails this package's build, not the adopter's.
- Driver: `deleteUser`, revoke `scope` filtering; schema fragment adds an
  `AlfizRevoke.scope` index.

### A verifier that can describe a real project (`@alfiz/verify`)

- CLI config gains `gateNames`, `visibilityNames`, `serverFilePatterns` —
  a project's own guard wrappers are the encouraged pattern, and without
  declaring them every wrapped action read as ungated. CLI lists are
  additive to the defaults; the programmatic options still replace
  (spread the newly exported `DEFAULT_GATE_NAMES` /
  `DEFAULT_VISIBILITY_NAMES` / `DEFAULT_SERVER_FILE_PATTERNS`).
- `// alfiz-verify-ignore-file <reason>` — the out-of-domain vocabulary for
  surfaces that authenticate outside the catalog by design. Skips the file,
  records it in the report's `skippedFiles`, and warns when no reason is
  given.
- The group-path near-miss gets a real message: `requireAny("admin")` now
  says *did you mean `"admin.*"`?* instead of "not in the catalog".

### Catalog ergonomics (`@alfiz/core`)

- Group-level `scopes` — declared once on a tab, inherited by every leaf
  under it (nearest declaration wins; a leaf's own `scopes`, including
  explicit `[]`, overrides). Ends the 40-identical-`scopes`-lines catalog.
- `label` on leaves and groups — the short picker name alongside the longer
  `description`, carried through `LeafMeta`/`GroupMeta`, the catalog
  document, and the headless tree — so UI copy stops drifting into side
  tables.

### Docs

- **`docs/MIGRATING.md`** — the brownfield guide: keeping existing keys,
  the role-splitting crux ("a global grant satisfies every scoped check"),
  the `appliesAt` worked example ("a role's meaning depends on where it is
  granted"), bulk import, deletion wiring, the snapshot pattern, and
  verifier configuration.
- CONVENTIONS: new snapshot and deletion sections; verifier wrapper/pragma
  guidance. README: snapshot in the quickstart, the global-grant semantics
  called out as a top-level opinion.
