# Changelog

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
