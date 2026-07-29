# Alfiz conventions — machine-legible

This document is written to be loaded into an AI agent's context when working
on a codebase that uses Alfiz. Everything here is checked by `@alfiz/verify`;
follow the conventions and the verifier will confirm, skip a step and it will
fail the build.

## Permission keys

- Shape: `<project>.<tab>.<permission>` — three dot-separated levels. This is
  a CONVENTION checked by the linter, not a structural law: a catalog with a
  different house style declares `conventions: { depth: 2 }` (or `"any"`) and
  builds. Structural errors — bad segments, an undeclared namespace, a key
  that is also a group path — still throw at boot.
- `<project>` and `<tab>` are folders, never permissions. Only the leaf is
  grantable or checkable. Group levels are INFERRED from the keys: every
  dotted prefix of a declared key is a group. A key that another key extends
  (`docs.files` alongside `docs.files.read`) would be both, and is an error.
- Reads are `read`, or `read_<thing>` when a tab exposes distinct readable
  surfaces (`read` alongside `read_pii`).
- Actions are `<verb>_<noun>`: `decide_student`, `advance_stage`, `issue_code`.
- Destructive actions stand alone as their own leaf (`delete`) and are never
  bundled into a broader permission.
- Every tab declares AT MINIMUM one read permission and one action permission
  per distinct action. More granularity is encouraged; less is a lint error.
- Wildcards are subtree-only and forward-inclusive: `*`, `docs.*`,
  `docs.files.*`. `docs.*` matches keys added under `docs` in the future and
  never matches the bare group `docs` itself. Wildcards never appear mid-key.
- The namespace `alfiz_internal` is reserved for Alfiz itself.

## The catalog

- One catalog module per application, built with `defineCatalog` from
  `@alfiz/core`. It is the single source of truth: types, verification, and
  admin UI all derive from it. Never infer permissions from call sites; never
  configure them in a dashboard.
- Permissions are declared by their FULL DOTTED KEY, so a key at a call site
  greps straight to its declaration:

  ```ts
  defineCatalog({
    namespaces: ["docs"],
    permissions: {
      "docs.files.read": { kind: "read" },
      "docs.files.delete": { destructive: true, scopes: ["docs.folder"] },
    },
  });
  ```

- Past a handful of keys, organize with `group()` blocks — each is a named,
  foldable unit carrying its own label and scope defaults, and `permissions`
  takes an array of them mixed freely with bare maps:

  ```ts
  export const files = group("docs.files", { label: "Files", scopes: ["docs.folder"] }, {
    "docs.files.read": { kind: "read" },
    "docs.files.delete": { destructive: true },
  });

  defineCatalog({ namespaces: ["docs"], permissions: [files, folders] });
  ```

  Every key in a block must start with the block's path — a compile error
  otherwise. Because keys are absolute, blocks compose by concatenation, so a
  large catalog splits into one file per feature (`export const files = …`
  next to the code it gates) with no deep merge to reason about.
- Blocks are OPTIONAL. A ten-permission app writing one flat map is a
  complete, idiomatic catalog. Reach for `group()` when a catalog gets big
  enough that folding and labels earn their keep — not before.
- Adding a surface means adding its keys to the catalog FIRST. The derived
  types (`KeyOf<typeof catalog>`) then make every call site compile-checked.
- Scope types (`docs.folder`, `docs.doc`) are declared in the catalog with
  their parent types. A permission grantable at a scope lists it in `scopes`.
- Requestability is catalog data (scope types) or role data (`requestable`).
  Nothing is requestable by default.

## Imported permissions

Permissions this application REFERENCES but does not own — from a hosted
dashboard, or from a federated sibling application — go in `imports`, never
in `permissions`. `namespaces` means "namespaces I own"; importing one you
own is an error.

```ts
import zoomDoc from "./zoom.catalog.json" with { type: "json" };

defineCatalog({
  namespaces: ["docs"],
  permissions: { "docs.files.read": { kind: "read" } },
  imports: {
    zoom: {
      from: "registry:zoom@^3",
      document: zoomDoc,              // ← attach it; see below
      scopes: ["docs.folder"],        // YOUR scope types, never zoom's
      permissions: { "zoom.host": true, "zoom.meetings.*": true },
    },
  },
});
```

- **Attach the `document`.** Fetch the namespace owner's published catalog in
  CI and commit it, exactly as you already commit `alfiz-catalog.json`. With
  it, an import behaves like owned vocabulary: wildcards expand, `canAny`
  answers exactly, and a typo is a build error. Without it, wildcards become
  opaque *regions* — still grantable and checkable, but approximated
  everywhere an answer needs expanding a pattern into keys, and an
  unenumerated key under one is admitted sight unseen.
- **`scopes` names scope types THIS catalog declares.** The owning
  application publishes vocabulary; only you know which of your resources it
  applies to, and only you can resolve their ancestry. A foreign scope type
  is a build error. The default is `[]` — grantable globally only.
- **Import the narrowest thing that works.** A pattern broader than what you
  imported is rejected: importing `zoom.meetings.*` does not make `zoom.*`
  storable, because that is a widening claim over a namespace you do not own.
- **Close the key union with codegen.** `alfiz-verify codegen --catalog
  zoom.catalog.json --prefix Zoom`, then
  `importedKeys<ZoomKey>({ … })` — a wildcard import otherwise widens
  `KeyOf` by one template member, since a subtree you cannot enumerate has
  no closed key set.
- **What you publish never includes imports.** `toDocument()` carries owned
  vocabulary only; what you consume publishes separately via
  `toImportManifest()` and `app.publishImports(...)`. Point
  `alfiz-verify.config.json` at both.

A check for a permission in a namespace you neither own nor import is an
*implicit* import: an `alfiz-verify` error by default, a warning where a
registry or dashboard is configured, and at runtime an
`UnknownPermissionError` unless `externalPermissions` is relaxed. Declaring
the import is the fix, and it is one line.

## The four-point wiring checklist

An action or surface is NOT done until all four hold:

1. **Page**: `require(<read key>)` at the top; project roots also
   guard visibility with `requireAny("<project>.*")`, but still gate their
   own read.
2. **Navigation**: the nav item's `permission` field in the catalog — a
   concrete key, an any-of array of keys, or a pattern.
3. **Server action / route handler**: `gateAction(<key>)` /
   `require(<key>)` before any work. Bundled actions touching
   several surfaces gate EACH field path on its own permission.
4. **Conditional UI**: `can(<key>)` around every button and panel.

All four accept scoped forms taking a scope instance id (`docs.doc:123`).

## Check shapes — which to use where

One name per question, on every surface: the client, the snapshot, the
session, and the session snapshot all spell each check shape identically.
If you know the question, you know the method name.

- `can(subject, key, scope?)` — the ONLY shape usable as a gate. Accepts an
  any-of array of keys where a surface is legitimately reachable under
  multiple permissions. NO SCOPE MEANS THE GLOBAL SCOPE — "may they do this
  everywhere?", the strictest check, NOT "may they do this anywhere?"; the
  anywhere question is `holds`.
- `require(subject, key, scope?)` — the throwing form of `can`, for page
  tops, actions, and route handlers.
- `canAny(subject, pattern)` — visibility affordance ONLY: whether to show a
  nav entry, a project root, a settings icon. NEVER a gate. The verifier
  errors on `canAny`/`requireAny` in a server action or route handler.
- `requireAny(subject, pattern)` — the throwing form of `canAny`, and
  exactly as narrow: it exists for ONE pattern — the page-top visibility
  guard (`requireAny("<project>.*")` → your 404/redirect) on a page that
  still gates its own read with `require`. Never an action gate.
- `can.fresh(...)` — bypasses all caches. REQUIRED pairing for destructive
  actions (`delete` leaves) and time-bound elevations.
- `holds(subject, key)` — "does this key exist for them at ANY scope": the
  right question for unscoped conditional UI under scoped grants (the
  button exists; the action still gates at its concrete scope). Never a
  gate — the verifier errors on `holds` in a server action or route
  handler. `heldKeys` is its many-key form (the whole held set at once).

Every check is verified against the catalog before it is evaluated. A key
or pattern the catalog does not declare raises `UnknownPermissionError` —
a PROGRAMMING error; map it to 500, never 403. This is what the typed keys
and the verifier do for literal call sites, extended to the runtime-string
paths they cannot see (nav tables, config, generic wrappers):

- Gates take a concrete key. A group path (`"admin"`) or a wildcard
  (`"docs.*"`) is not a key — gate on a leaf.
- `canAny`/`requireAny` take a key, a `<group>.*` pattern, or `*`. A bare
  group path matches nothing, so it is rejected with the correction.
- Never "probe" with a key that might not exist: an undeclared key used to
  pass for anyone holding a covering wildcard, which is why this is
  enforced rather than warned.

## Server-rendered pages: one snapshot per request

Render paths perform many checks inside helpers and `.map()` callbacks that
must stay synchronous. Do NOT make render helpers async, and do NOT call
`can()` per button. Fetch once, check synchronously:

```ts
const snap = await alfiz.snapshot({ userId });      // once per request
snap.can("docs.files.read");                        // sync gate-shaped check
snap.can("docs.files.update_file", "docs.doc:1");   // sync, scoped
snap.canAny("docs.*");                              // sync visibility
snap.heldKeys / snap.holds(key)                     // "held anywhere" probes
```

- A per-request snapshot is a STRONGER consistency guarantee than repeated
  `can` calls: one data instant, one clock, for every check in the render.
- Scope types declared `parent: null` are flat BY CONTRACT (chains are
  `[scope, "*"]`), so scoped checks on them are synchronous with no
  pre-resolution. Hierarchical scopes you intend to check must be listed:
  `alfiz.snapshot(principal, { scopes: [docScope] })` — an unresolved
  hierarchical scope throws rather than guessing (a guessed chain would
  miss ancestor revokes: fail-open).
- Hierarchical LIST pages cannot know row ids before querying: guard the
  page, query, then `await snap.resolve(rowScopes)` — it extends the same
  snapshot with no second fetch, so the data instant is unchanged. Past a
  few dozen rows, stop checking per row and push the filter into the
  database (`grantedScopes` + `planListing`) instead.
- Server actions and route handlers still gate with `can`/`can.fresh` —
  the snapshot is the read/render surface.

## Grants and revokes

- Grant rows are `(subject, role-or-pattern, scope, expiry?)` with
  provenance. Subjects: `user:<id>`, `group:<id>`, `org:<id>`, `everyone`,
  `service:<id>`, implicit `directs:<uid>` / `orgof:<uid>`.
- Public access is an ordinary grant to `everyone` — never special-case it.
- Time-bound access is an ordinary grant with `expiresAt` — never build a
  parallel mechanism.
- Revokes are personal-only (individual users) and always win,
  scope-inclusively. Groups and roles can never revoke.
- "Broad vs narrow authority" is modeled with ONE permission key granted at
  different scopes — never with parallel blanket-and-variant key families.
- A GLOBAL grant satisfies EVERY scoped check (`*` is in every object
  closure). Roles that mix org-wide and per-resource authority must be
  split before scoped grants change anything — see `docs/MIGRATING.md`.
- Bulk writes (migrations, imports) use `createGrants(inputs, provenance)`:
  all inputs validated before any row is written, one audit entry, one
  invalidation per distinct subject. Never loop `createGrant` for an import.
- Every write carries a valid provenance — `{kind:"admin", actorUserId}`,
  `{kind:"import", source}`, and so on. It is validated up front and
  rejected as a `ProviderWriteRejectedError` naming the missing field.
- Counting role holders is `countGrants({ roleId })`, never `listGrants()`
  filtered in memory — the latter reads every grant in the organization.
- Migration SQL and runtime agree on identity by passing YOUR ids:
  `createRole({ id: "role_x", ... })`, `createGroup({ id: "cohort_y", ... })`.
  A taken id is a conflict, never an overwrite.

## Sessions and view-as

- A session carries the actor (real user) and subject (previewed identity)
  separately. Checks intersect both: previews only narrow.
- Audit attribution always uses the actor, never the previewed subject.
- Starting a preview requires `alfiz_internal.access.view_as`; stopping one
  is never gated.
- Render paths under view-as follow the SAME one-snapshot-per-request rule:
  `const snap = await session.snapshot()`, then synchronous `can` /
  `canAny` / `require*` / `holds` / `heldKeys` — every answer is the
  actor ∩ preview intersection. `snapshot({ scopes })` and
  `snap.resolve(rowScopes)` pre-resolve hierarchical targets for both
  identities at once.

## Service-to-service

- Machine subjects are `service:<id>`, verified by the timing-safe env-key
  shim (`createServiceKeyShim`), with rotation lists ("current,previous").
- Key material must never be reachable from client bundles — list the env
  identifier in `forbidClientIdentifiers` and the verifier fails the build
  if it appears in a `"use client"` module.

## Resource moves

- Your application owns the object hierarchy. Whenever a resource's parent
  pointer changes (a document moves folders), call
  `app.notifyScopeMoved("<scopeType>:<id>")` in the same code path — this
  busts cached ancestor chains immediately, which is what makes "moving a
  sensitive document into a restricted folder takes effect at once" true.
  The client's object-chain TTL only bounds the damage if you forget.

## Deletions — the same discipline as moves

Grants key on subject and scope STRINGS, not foreign keys: Alfiz cannot see
your tables, so deleting a principal or a resource there strands its rows
here, and a reused id silently inherits the stranded access. Pair every
delete path:

- Deleting a user / API token / service account →
  `app.deleteSubject("user:<id>" | "service:<id>", provenance)` in the same
  code path. For users this also removes revokes, the stored record,
  implicit-group (`directs:`/`orgof:`) grants, and cancels their pending
  requests. For groups use `deleteGroup` (it also repairs parentage and
  membership).
- Deleting a scoped resource → `app.deleteScope("<scopeType>:<id>",
  provenance)`. Descendant scopes are separate rows: call it per deleted
  resource when removing a subtree.
- Reversible offboarding → `app.setUserActive(userId, false, provenance)`;
  an inactive principal evaluates to no access everywhere. Deactivate on
  offboarding; delete when the id itself is retired.

## Listing pages

- Never per-row `can()` (N+1). Compute the granted scope set
  (`client.grantedScopes`), build a plan (`planListing`), and push the
  filter into the database (`matPathCondition` / `closureTableCondition` /
  `prismaMatPathWhere`). Scoped listing requires the resource table to carry
  a materialized path column or a closure table.

## Metrics (optional)

- Off unless configured. `metrics: { observer }` on `createAlfizClient` emits
  one `CheckObservation` per evaluated check. The observer is called
  SYNCHRONOUSLY on the check path: do cheap work (increment, buffer) and
  nothing else. Throwing is contained — it costs the observation, never the
  decision — but a slow observer is your latency, so never do I/O in one.
- Pipe to whatever you already run. `otelMetricsObserver({ meter })` is the
  shipped OpenTelemetry adapter; an array of observers fans out.
  `createMetricsAggregator()` folds the stream into fixed memory with a live
  `snapshot()` if you want to serve the numbers yourself.
- **Sample high-traffic paths.** `sampleRate: { gate: 1, visibility: 0.02 }`
  — gates map to user actions and are worth keeping whole; `canAny`,
  `holds`, and `heldKeys` fire hundreds of times per render. The draw is one
  `Math.random()` inside the call, before anything is allocated. Counts
  carry their rate, so `estimated` is the extrapolation and `observed` is
  what was seen. Sampling NEVER changes an answer.
- Keep cardinality bounded. Scope instances aggregate to scope TYPE unless
  you opt a type in (`scopeInstances: ["docs.folder"]`); do not opt in a
  per-document type. Principals are PII-adjacent — off by default in the
  OTel adapter, and leave them off unless you know your backend can take it.
- To store usage locally (and get revocation safeguards), turn on
  `metrics: {}` on the Application and wire
  `createProviderMetricsSink(app)`. Render warnings with
  `revocationSafeguard(usage)`: it keys on `soleMatch` — the checks a row
  was the ONLY thing allowing — and never claims an unused grant is safe to
  revoke. Do not write copy that does.
- Metrics are counts, not audit: sampled, lossy, and dropped under
  back-pressure. Never derive an authorization decision, a compliance
  record, or a billing figure from them.

## Verification

Run `alfiz-verify` (or `verifyProject` programmatically) in CI. It checks:
unknown keys at call sites, `canAny` used as a gate, exported server actions
with no gate, catalog leaves referenced nowhere, catalog convention
violations, and client-reachable secrets. Typos compile — the verifier is
what catches the rest.

- Your own gate wrappers (`assertTeaches`, `gateDestructiveAction`, …) are
  the encouraged pattern — DECLARE them, or every wrapped action reads as
  ungated: `gateNames` / `visibilityNames` / `serverFilePatterns` in
  `alfiz-verify.config.json` (added to the built-in defaults), or the same
  options on `verifyProject` (replacing them; spread `DEFAULT_GATE_NAMES`).
- Surfaces that authenticate OUTSIDE the catalog by design (system trust
  domains that must survive a database outage) opt out per file, with a
  reason: `// alfiz-verify-ignore-file <reason>` in the file HEADER —
  the leading comments, above or below a `"use server"`/`"use client"`
  directive, exactly as JavaScript allows. A pragma without a reason is a
  warning (unexplained exemptions rot); a pragma past the first statement
  is inert and is reported as such rather than silently doing nothing.
