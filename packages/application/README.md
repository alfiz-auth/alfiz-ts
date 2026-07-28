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
- The admin lifecycle surface — `createGrants` (bulk: validate-all-first,
  one audit entry, one invalidation per subject), caller-supplied ids on
  `createRole`/`createGroup` (migration SQL and runtime agree on identity),
  `updateGroup` (rename without touching parentage or membership),
  `setUserActive` (the reversible offboarding switch: inactive principals
  evaluate to no access), and `listGrants`/`countGrants` filtered by
  `roleId` (role-holder counts without reading every grant).
- Provenance is validated on every write, before any row is touched:
  a missing `actorUserId` is a `ProviderWriteRejectedError` naming the
  field, not a driver-level error inside the audit writer.
- `notifyScopeMoved(scope)` — the move hook: the host application owns the
  hierarchy behind `resolveAncestors`, so it must report parent-pointer
  changes; this emits the `scope` invalidation that busts cached ancestor
  chains immediately. (Now async: with event persistence on, it resolves
  once the move event is durable to other processes.)
- **Event persistence** (`events: { persist: true }`) — every invalidation
  event is appended to a sequenced log in your database before the write
  returns, and exposed as `provider.epoch` — the signal clients use
  (`revalidateAfterMs`) to revalidate their caches across processes with
  one single-row read. Requires a driver implementing the optional event
  methods (the memory and Prisma drivers do; construction fails loudly
  otherwise). Retention defaults to 7 days / 100 000 rows, pruned
  opportunistically; a client whose cursor predates retention busts
  everything and resumes. `ingestEvents(events)` re-emits foreign events
  into local listeners; `startEventPoller(app)` (from `events.ts`) tails
  the log on an interval for push-like invalidation on long-lived nodes —
  optional sugar, correctness never depends on it.
- **Metrics** (`metrics: {}`) — rolling permission-usage buckets (daily by
  default) keyed by grant, revoke, role, permission, and scope type, fed by
  `reportMetrics` and read back with `getGrantUsage` / `getRevokeUsage` /
  `getRoleUsage` / `getPermissionUsage` / `getScopeTypeUsage`. Off by
  default and advertised through `capabilities().metrics`, so a deployment
  that has not opted in stores and renders nothing. Requires a driver
  implementing the optional metric methods (memory and Prisma do;
  construction fails loudly otherwise). Retention defaults to 90 days,
  compacted opportunistically. Writes are pre-aggregated batches delivered
  off the request path and never awaited by it: `createProviderMetricsSink`
  (core) is the wiring, and it drops batches under back-pressure rather
  than queueing — losing counts is the right failure mode for a counter,
  adding latency is not. Per-grant `soleMatch` is what
  `revocationSafeguard` (core) keys on.
- **Closure-supply performance** — the group-parent topology is cached
  per Application (`groupTopologyTtlMs`, default 30s, `0` disables),
  busted synchronously by local group writes and by ingested events, so a
  cache miss no longer re-reads every group in the organization; roles
  referenced by a grant set are batch-read once (`StorageDriver.getRoles`,
  optional, with a parallel per-id fallback); independent queries run
  concurrently.
- `deleteSubject(subject, provenance)` / `deleteScope(scope, provenance)` —
  the deletion hooks, same discipline as moves: grants key on subject and
  scope STRINGS, so the code path that deletes a principal or a resource
  must sweep its rows here, or a reused id inherits the stranded access.
  User deletion also removes revokes, the stored record, implicit-group
  grants, and cancels pending requests.
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

## Relay

The Application side of the Alfiz Cloud relay: `createRelayHandler` serves
the provider contract over one bearer-authenticated POST endpoint, so a
linked Application is reachable by the hosted dashboard while remaining
the org root and the sole writer. Every relayed operation lands in the
same provider methods local code calls — org-root gating, validation,
graph integrity, and audit apply to relayed writes exactly as to local
ones. Mount it at an internal route:

```ts
import { createRelayHandler } from "@alfiz-auth/application";
import { app, storage } from "@/lib/alfiz";

export const POST = createRelayHandler({
  application: app,
  storage,
  secret: process.env.ALFIZ_RELAY_SECRET!,
  applicationId: "docs",
});
```

The secret is minted at the Alfiz Cloud link step; keep it in an
environment variable. The `storage` option enables the org-snapshot ops
(promotion, demotion, read-model sync); `onAuthorityChanged` is called
after an authority-transfer snapshot applies, so the host can reconstruct
its Application with the new `orgRoot` flag — a constructor commitment the
library cannot flip at runtime. Typed errors survive the wire
(`ProviderWriteRejectedError` codes, `GraphCycleError` paths), and
`createRelayProvider(target)` is the calling side: an `AlfizProvider` over
fetch that exposes the linked Application's epoch. Runtime checks never
traverse the relay — every `can()` runs in-process, and nothing in the
protocol is on any request path.

Every driver must pass the contract suite in `test/driver-suite.ts`.
