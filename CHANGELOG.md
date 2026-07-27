# Changelog

## Unreleased — caching that survives more than one process

The staleness bound stops being "a TTL per process" and becomes "one
revalidation window, any number of processes" — opt-in, with defaults
byte-identical to 0.2.2 (except two strict improvements: the object-chain
cache is now bounded, and both client caches evict LRU).

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

### The request-scoped snapshot (`@alfiz-auth/core`)

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

### Referential cleanup and the missing write APIs (`@alfiz-auth/application`)

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

### The generated-client promise, pinned (`@alfiz-auth/prisma`)

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

### A verifier that can describe a real project (`@alfiz-auth/verify`)

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

### Catalog ergonomics (`@alfiz-auth/core`)

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
