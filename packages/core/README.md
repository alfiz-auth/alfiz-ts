# @alfiz-auth/core

The Alfiz **Client**: the evaluator. Everything here is a pure function over
data a provider supplies — no storage, no I/O.

- **Grammar** (`grammar.ts`) — key/pattern validation, forward-inclusive
  subtree wildcard matching, pattern intersection.
- **Catalog** (`catalog.ts`) — `defineCatalog`, derived template-literal key
  and pattern types (`KeyOf`, `PatternOf`, plus `ClientOf` / `SnapshotOf`
  for context objects), scope types, navigation wiring,
  requestability, `lintCatalog`, the reserved `alfiz_internal.*` project,
  `toDocument()`/`catalogFromDocument()` (the publish wire shape).
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
  invalidation events, `explain`, `grantedScopes`, `effectiveKeys`,
  `holdsAnywhere`. Every check is verified against the catalog first —
  an undeclared key or pattern raises `UnknownPermissionError` (a
  programming error: map it to 500, never 403) instead of being evaluated,
  which is what keeps a misspelled gate from passing for wildcard holders.
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
- **Provider contract** (`provider.ts`) — the single interface every
  provider implements; capability discovery for progressive disclosure.

See the repo root README and `docs/CONVENTIONS.md`.
