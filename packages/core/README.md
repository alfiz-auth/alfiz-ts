# @alfiz/core

The Alfiz **Client**: the evaluator. Everything here is a pure function over
data a provider supplies — no storage, no I/O.

- **Grammar** (`grammar.ts`) — key/pattern validation, forward-inclusive
  subtree wildcard matching, pattern intersection.
- **Catalog** (`catalog.ts`) — `defineCatalog` (permissions declared by their
  full dotted key; `group()` blocks to organize a large one), derived
  template-literal key and pattern types (`KeyOf`, `PatternOf`, plus
  `ClientOf` / `SnapshotOf` for context objects), scope types, navigation
  wiring, requestability, `lintCatalog`, the reserved `alfiz_internal.*`
  project, `toDocument()`/`catalogFromDocument()` (the publish wire shape).
- **Subjects & scopes** (`subjects.ts`, `scopes.ts`) — subject ids and
  closure computation (groups, ancestors, implicit `directs:`/`orgof:`
  groups from reporting edges, orgs, `everyone`); scope ids, the
  `resolveAncestors` seam, object closures.
- **Access algebra** (`access.ts`) — the grant tuple with provenance and
  expiry, personal-only revokes, `checkKey`/`explainKey` (negative always
  wins, scope-inclusive), `checkAny`, granted/revoked scope sets, virtual
  parent dissolution planning.
- **Graph integrity** (`graph.ts`) — cycle detection with named paths,
  whole-graph validation, SCC auto-condensation for directory imports.
- **Requests** (`requests.ts`) — the request object (a proposed grant
  tuple), approval policies (auto predicates, named approvers, management
  layers), pure stage evaluation.
- **Client** (`client.ts`) — `createAlfizClient`: `can` / `canAny` /
  `require*` / `can.fresh`, closure caches parameterized by provider
  invalidation events, `explain`, `grantedScopes`, `holds` / `heldKeys`.
  One name per question, on every surface — the client, the snapshot, and
  the session spell each check shape identically.
  Every check is verified against the catalog first —
  an undeclared key or pattern raises `UnknownPermissionError` (a
  programming error: map it to 500, never 403) instead of being evaluated,
  which is what keeps a misspelled gate from passing for wildcard holders.
  Both caches are LRU-bounded; `subject`/`role`/`scope` events bust in
  O(affected entries) via secondary indexes, and in-flight fetches
  coalesce and honor busts that land mid-flight.
- **Cache tiers** (`cache.ts` + client options) — `revalidateAfterMs`
  turns on epoch revalidation against a provider that persists its
  invalidation events (`provider.epoch`): one constant-cost head read per
  window validates both caches for every principal, renews TTLs while
  writes are quiet, and replays only the missed events when they are not.
  `cacheStore` plugs in a shared L2 (`CacheStore` — three string-valued
  methods, zero dependencies) so cold processes find warm closures;
  `respCacheStore(client)` adapts any RESP-family client (node-redis or
  ioredis call shape — Redis, Valkey, KeyDB, Dragonfly, ElastiCache,
  Upstash) structurally, no dependency added.
- **Snapshot** (`snapshot.ts`) — `client.snapshot(principal)`: one provider
  round-trip, then SYNCHRONOUS `can`/`canAny`/`require*`/`holds`/`heldKeys`
  over one consistent instant — the pattern for server-rendered frameworks,
  where render helpers cannot be async. Flat (`parent: null`) scope types
  check synchronously with no pre-resolution; `resolve(scopes)` extends a
  snapshot after a query without a second fetch (hierarchical list pages).
- **Listing** (`listing.ts`) — `planListing` plus materialized-path and
  closure-table query helpers.
- **Headless tree** (`tree.ts`) — the wildcard-aware permission-tree
  selection logic behind role editors and grant pickers.
- **Metrics** (`metrics.ts`, `otel.ts`) — the optional `CheckObservation`
  stream off every check path, with the shape, decision, permission, scope
  type, principal, and the rows that decided it. Sync, guarded, and
  fire-and-forget: an observer that throws or hangs loses counts, never a
  decision. `sampleRate` is one random draw inside the call before anything
  is built (gates and visibility traffic sampled separately, each
  observation carrying the rate that kept it, so counts extrapolate);
  `createMetricsAggregator` is a pure bounded windowed fold with a live
  `snapshot()` — a complete direct-read API needing no external system;
  `otelMetricsObserver` writes into an OpenTelemetry `Meter` (structurally
  typed, so `@opentelemetry/api` is not a dependency);
  `createProviderMetricsSink` batches to a provider that stores usage; and
  `revocationSafeguard` turns stored usage into the "what breaks if I revoke
  this" warning — keyed on `soleMatch`, the counterfactual, never on raw
  participation, and never claiming an unused grant is safe to remove.
- **Provider contract** (`provider.ts`) — the single interface every
  provider implements; capability discovery for progressive disclosure.

See the repo root README and `docs/CONVENTIONS.md`.
