# @alfiz-auth/application

The Alfiz **Application**: the local provider. Implements the provider
contract against your own database through the storage seam
(`StorageDriver`) — one database is the sole hard requirement. A complete
in-memory driver ships as the reference; `@alfiz-auth/prisma` provides the
Prisma-backed one; implement `StorageDriver` yourself for anything else.

Standalone (the default), the Application is the **org root**: it owns
groups, roles, global grants/revokes, and the reporting tree locally, with
the full feature set — including management-layer approvals against its own
hierarchy — and no external dependency. With `orgRoot: false` it serves the
same data as a synced read model and rejects org-domain writes.

What lives here:

- `createApplication` — the provider: closure supply, row operations with
  validation + provenance + audit, graph writes with transactional DAG
  enforcement (cycle paths named in errors), request workflows (auto
  predicates run at submit; human decisions unlock consecutive autos;
  `alfiz_internal.requests.decide_request` is the administrative override),
  the approver queue, catalog publishing, virtual-parent dissolution
  snapshots, invalidation events.
- `memoryDriver` — the reference storage driver.
- `notifyScopeMoved(scope)` — the move hook: the host application owns the
  hierarchy behind `resolveAncestors`, so it must report parent-pointer
  changes; this emits the `scope` invalidation that busts cached ancestor
  chains immediately.
- Sessions (`session.ts`) — actor/subject split with view-as narrowing:
  every check intersects the previewed subject with the actor's REAL
  access, so previews can only narrow. `serializeViewAs`/`parseViewAs` for
  cookie plumbing.
- Service principals (`service-principal.ts`) — the timing-safe env-key
  shim with rotation lists; pair with `@alfiz-auth/verify`'s client-reach guard.
- Directory ingestion (`importDirectory`) — groups/memberships/reporting
  edges from Entra/Okta/LDAP-shaped snapshots; cyclic group nesting is
  auto-condensed into virtual parents, cyclic reporting edges are skipped
  with warnings, never silently combined.

Every driver must pass the contract suite in `test/driver-suite.ts`.
