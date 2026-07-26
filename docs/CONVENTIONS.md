# Alfiz conventions — machine-legible

This document is written to be loaded into an AI agent's context when working
on a codebase that uses Alfiz. Everything here is checked by `@alfiz-auth/verify`;
follow the conventions and the verifier will confirm, skip a step and it will
fail the build.

## Permission keys

- Shape: `<project>.<tab>.<permission>` — exactly three dot-separated levels.
- `<project>` and `<tab>` are folders, never permissions. Only the leaf is
  grantable or checkable.
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
  `@alfiz-auth/core`. It is the single source of truth: types, verification, and
  admin UI all derive from it. Never infer permissions from call sites; never
  configure them in a dashboard.
- Adding a surface means adding its keys to the catalog FIRST. The derived
  types (`KeyOf<typeof catalog>`) then make every call site compile-checked.
- Scope types (`docs.folder`, `docs.doc`) are declared in the catalog with
  their parent types. A permission grantable at a scope lists it in `scopes`.
- Requestability is catalog data (scope types) or role data (`requestable`).
  Nothing is requestable by default.

## The four-point wiring checklist

An action or surface is NOT done until all four hold:

1. **Page**: `requirePermission(<read key>)` at the top; project roots also
   guard visibility with `requireAny("<project>.*")`, but still gate their
   own read.
2. **Navigation**: the nav item's `permission` field in the catalog — a
   concrete key, an any-of array of keys, or a pattern.
3. **Server action / route handler**: `gateAction(<key>)` /
   `requirePermission(<key>)` before any work. Bundled actions touching
   several surfaces gate EACH field path on its own permission.
4. **Conditional UI**: `can(<key>)` around every button and panel.

All four accept scoped forms taking a scope instance id (`docs.doc:123`).

## Check shapes — which to use where

- `can(subject, key, scope?)` — the ONLY shape usable as a gate. Accepts an
  any-of array of keys where a surface is legitimately reachable under
  multiple permissions.
- `canAny(subject, pattern)` — visibility affordance ONLY: whether to show a
  nav entry, a project root, a settings icon. NEVER a gate. The verifier
  errors on `canAny`/`requireAny` in a server action or route handler.
- `require*` — the throwing forms of both.
- `can.fresh(...)` — bypasses all caches. REQUIRED pairing for destructive
  actions (`delete` leaves) and time-bound elevations.

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

## Sessions and view-as

- A session carries the actor (real user) and subject (previewed identity)
  separately. Checks intersect both: previews only narrow.
- Audit attribution always uses the actor, never the previewed subject.
- Starting a preview requires `alfiz_internal.access.view_as`; stopping one
  is never gated.

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

## Listing pages

- Never per-row `can()` (N+1). Compute the granted scope set
  (`client.grantedScopes`), build a plan (`planListing`), and push the
  filter into the database (`matPathCondition` / `closureTableCondition` /
  `prismaMatPathWhere`). Scoped listing requires the resource table to carry
  a materialized path column or a closure table.

## Verification

Run `alfiz-verify` (or `verifyProject` programmatically) in CI. It checks:
unknown keys at call sites, `canAny` used as a gate, exported server actions
with no gate, catalog leaves referenced nowhere, catalog convention
violations, and client-reachable secrets. Typos compile — the verifier is
what catches the rest.
