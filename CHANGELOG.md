# Changelog

## 0.3.0 — second field report

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
