/**
 * The Alfiz Application: the local provider. A library-embedded
 * implementation of the provider contract against the application's own
 * database (through the storage seam), with no external dependency.
 *
 * Standalone, the Application is the org root: it owns organizational-domain
 * data — groups, roles, global grants and revokes, the reporting tree — with
 * the full feature set, locally. Configured as a non-root (federated read
 * model), it serves the same data read-only and rejects org-domain writes.
 */

import type {
  AccessRequest,
  AlfizProvider,
  AnyCatalog,
  ApprovalStage,
  AuditEvent,
  AuditQuery,
  CatalogDocument,
  CheckContext,
  EpochSource,
  GrantInput,
  GrantQuery,
  GrantRow,
  ImportManifest,
  InvalidationEvent,
  InvalidationListener,
  MetricBucket,
  MetricBucketDelta,
  MetricDimension,
  MetricsBatch,
  PermissionPattern,
  PermissionUsage,
  PrincipalRef,
  Provenance,
  RowUsage,
  UsageQuery,
  RequestFilter,
  RequestInput,
  RevokeInput,
  RevokeRow,
  RoleInput,
  RoleRecord,
  ScopeId,
  SubjectAccessData,
  SubjectId,
  UserGroup,
} from "@alfiz/core";
import {
  ALFIZ_INTERNAL_NAMESPACE,
  AlfizProviderBase,
  patternContains,
  GLOBAL_SCOPE,
  METRIC_GATE_ALLOW,
  METRIC_GATE_DENY,
  METRIC_MATCHED,
  METRIC_SOLE_MATCH,
  METRIC_VISIBILITY_ALLOW,
  METRIC_VISIBILITY_DENY,
  ProviderWriteRejectedError,
  applyDecision,
  canDecideStage,
  checkKey,
  computeServiceClosure,
  computeSubjectClosure,
  findCycle,
  formatAlternatives,
  isGlobalScope,
  isValidSubject,
  namespaceOf,
  parseSubject,
  planVirtualParentDissolution,
  runAutoStages,
  unknownPermissionContext,
  normalizeProvenance,
  validateProvenance,
  validateGrantRow,
  validateJustification,
  validatePattern,
  validateScopeId,
} from "@alfiz/core";
import type {
  AncestryResolver,
  LooseScopeId,
  PrincipalEntitlements,
  SodViolation,
} from "@alfiz/core";
import {
  checkSodConstraints,
  entitlementsOf,
  isExpired,
  principalKind,
  wildcardDrift,
} from "@alfiz/core";
import { randomUUID } from "node:crypto";
import { computeAuditHash } from "./audit-chain.js";
import type { StorageDriver, StoredUser } from "./storage.js";

export interface ApplicationOptions {
  catalog: AnyCatalog;
  storage: StorageDriver;
  /**
   * The ancestry seam: resolves a scope instance's ancestor chain against
   * the application's own tables — the reason checks are local forever.
   * Omit for fully-global deployments (every scope is `*`).
   */
  ancestry?: AncestryResolver | undefined;
  /**
   * Standalone (default): this Application is the org root and the single
   * writer of organizational-domain data. `false`: the org root lives
   * elsewhere; org-domain data is a synced read model and local writes to it
   * are rejected.
   */
  orgRoot?: boolean | undefined;
  /**
   * TTL (ms) for the group-parent topology map used to build subject
   * closures. Without it, every closure supply re-reads EVERY group in the
   * organization just to walk parent edges — the single most expensive part
   * of a cache miss. Local group writes bust it synchronously, so the TTL
   * only bounds staleness for group writes made by ANOTHER process against
   * the same database (worst case it adds to the client's subject TTL);
   * event-log replay (`ingestEvents`, the poller) busts it too. Default
   * 30s; `0` disables the cache and restores the per-miss scan.
   */
  groupTopologyTtlMs?: number | undefined;
  /**
   * Persist invalidation events to storage with a monotonic sequence,
   * exposing them as `provider.epoch` — the cross-process cache-freshness
   * signal. In-process listeners get every event either way; persistence is
   * what lets OTHER processes (other nodes, serverless invocations)
   * revalidate their caches with one tiny read instead of waiting out a
   * TTL. Requires a driver implementing the optional event methods
   * (`appendEvents`/`headSeq`/`eventsSince`/`pruneEvents`); construction
   * throws when they are missing, because silently degrading a freshness
   * guarantee is worse than failing loudly. Default off.
   */
  events?:
    | {
        /**
         * Since 0.7.0, persistence defaults to ON whenever the storage
         * driver implements the event methods — the safe configuration is
         * the default one. Pass `false` to opt out, or `true` to demand it
         * (construction then throws if the driver cannot, rather than
         * silently degrading the freshness guarantee).
         */
        persist?: boolean | undefined;
        /**
         * Event retention: entries older than `maxAgeMs` (default 7 days)
         * or beyond the newest `maxRows` (default 100 000) are pruned
         * opportunistically. A client whose cursor predates retention gets
         * a gap and does a full bust — retention only needs to cover the
         * longest interval between one client's revalidations.
         */
        retention?:
          | { maxAgeMs?: number | undefined; maxRows?: number | undefined }
          | undefined;
      }
    | undefined;
  /**
   * Store permission-usage metrics: rolling counter buckets keyed by grant
   * id, revoke id, role id, permission key, and scope type, fed by
   * `reportMetrics` and read back by the usage methods and the revocation
   * safeguards. Off by default — a deployment that only wants numbers in its
   * own metrics stack points the client's observer at OpenTelemetry and
   * never enables this.
   *
   * Requires a storage driver implementing `recordMetrics`, `readMetrics`,
   * and `pruneMetrics`; construction throws when they are missing, on the
   * same reasoning as `events.persist` — silently accepting metrics that go
   * nowhere would make every safeguard read a confident zero.
   */
  metrics?:
    | {
        /**
         * Bucket granularity (ms). Default one day. Storage is bounded by
         * attributed rows × retention ÷ granularity, so this is the knob
         * that trades resolution for rows.
         */
        bucketMs?: number | undefined;
        /**
         * How long buckets are kept (ms). Default 90 days. Pruning is
         * opportunistic and off the write path — a failed prune costs disk,
         * not correctness.
         */
        retentionMs?: number | undefined;
      }
    | undefined;
  /**
   * Separation-of-duty posture. Constraints come from the CATALOG
   * (`constraints.sod`); this option only chooses what a violating write
   * does. `"off"` (default): constraints are detective only — read the
   * report with `listSodViolations`. `"reject"`: a `createGrant` /
   * `createGrants` whose USER-subject row would create a NEW violation is
   * rejected with code `conflict`. Group- and role-shaped writes are never
   * rejected — every member would need evaluating on a write path — and
   * remain the report's job; that boundary is documented, not hidden.
   */
  sod?: { enforce?: "off" | "reject" | undefined } | undefined;
  /**
   * Audit-log posture. `hashChain: true` makes every audit entry carry a
   * SHA-256 hash over its canonical serialization plus the previous entry's
   * hash, so edits, deletions, and reordering are detectable
   * (`verifyAuditChain`). Appends are serialized through
   * `runExclusive("audit", …)` while chaining — an ordering cost paid only
   * by deployments that opt in; multi-node deployments need a real
   * cross-process lock on the driver (the Prisma driver's `options.lock`)
   * for the chain to stay linear. Off by default.
   */
  audit?: { hashChain?: boolean | undefined } | undefined;
  clock?: (() => number) | undefined;
  ids?: (() => string) | undefined;
}

const actorOf = (p: Provenance): string => {
  // Backstop: every public write asserts provenance up front (before any
  // storage is touched), but this is the last gate before a row is
  // attributed, so an internally-constructed provenance cannot slip past.
  const issue = validateProvenance(p);
  if (issue) throw new ProviderWriteRejectedError(issue, "validation");
  switch (p.kind) {
    case "admin":
      return p.actorUserId;
    case "request":
      return p.approvedBy ?? "auto";
    case "import":
      return `import:${p.source}`;
    case "merge":
      return `merge:${p.source}`;
    case "reconciler":
      return `reconciler:${p.integrationId}`;
    case "dissolution":
      return "system";
    case "system":
      return "system";
  }
};

export interface DirectorySnapshot {
  /** External directory groups with their (possibly cyclic) nesting. */
  groups?: Array<{
    id: string;
    name: string;
    description?: string | undefined;
    parents?: readonly string[] | undefined;
  }>;
  /** userId → group ids. */
  memberships?: Record<string, readonly string[]>;
  /** userId → manager userId. */
  reportingEdges?: Record<string, string>;
  /** userId → org ids. */
  orgs?: Record<string, readonly string[]>;
  /** Users to ensure exist (unlisted users are untouched). */
  users?: Array<{ userId: string; active?: boolean | undefined }>;
}

export interface DirectoryImportResult {
  warnings: string[];
  virtualParents: Array<{ id: string; members: string[] }>;
  /** Populated by authoritative imports: what deprovisioning did. */
  deactivatedUsers?: string[];
  removedMemberships?: number;
  clearedReportingEdges?: number;
}

export interface DirectoryImportOptions {
  /**
   * Treat the snapshot as the AUTHORITATIVE state of every dataset it
   * carries, not an additive overlay. The default (false) is upsert-only —
   * and upsert-only means OFFBOARDING NEVER PROPAGATES: a user who
   * disappears from the directory keeps `active: true`, their memberships,
   * and their reporting edge until someone notices. Authoritative mode
   * closes that, per dataset, touching only datasets the snapshot carries:
   *
   * - `users` present → users known to this store but absent from the
   *   snapshot are DEACTIVATED (never deleted — grants stay for audit,
   *   `deleteSubject` remains the id-retirement path);
   * - `memberships` present → stored memberships in imported (virtual
   *   included) groups absent from the snapshot are removed; memberships in
   *   locally-authored groups are never touched;
   * - `reportingEdges` present → stored edges absent from the snapshot are
   *   cleared.
   *
   * Groups themselves are never deleted here: a directory group that
   * disappears may still be referenced by grants, and deleting it silently
   * would strand them — that is `reconcileRows`' finding to surface.
   */
  authoritative?: boolean | undefined;
}

/**
 * Generic over the catalog's derived pattern and scope-id unions, so the
 * write paths (grants, revokes, roles, requests) autocomplete at literal
 * call sites — seeding scripts, data migrations, admin actions. Construct
 * with `createAlfizApplication(options)` to infer both; the parameters are
 * hints (`LoosePattern` / `LooseScopeId`), so runtime strings from role
 * editors flow through unchanged and are validated against the catalog as
 * always.
 */
export class AlfizApplication<
    P extends string = string,
    S extends string = string,
  >
  extends AlfizProviderBase
  implements AlfizProvider
{
  readonly catalog: AnyCatalog;
  override readonly resolveAncestors: AncestryResolver;
  /** Present when `events.persist` is on — see {@link EpochSource}. */
  override readonly epoch: EpochSource | undefined;

  private readonly storage: StorageDriver;
  private readonly orgRoot: boolean;
  private readonly now: () => number;
  private readonly newId: () => string;
  private readonly groupTopologyTtl: number;
  private groupTopology: {
    parents: Map<string, readonly string[]>;
    expiresAt: number;
    /** Event-log head when this snapshot was taken; null when not persisting. */
    seq: number | null;
  } | null = null;
  private groupTopologyFetch: Promise<Map<string, readonly string[]>> | null =
    null;
  /** Bust-during-fetch protection for the topology cache. */
  private groupTopologyGen = 0;
  /** Scope types already warned about for a flat-declaration contradiction. */
  private readonly warnedFlatTypes = new Set<string>();
  private readonly persistEvents: boolean;
  private readonly eventRetention: { maxAgeMs: number; maxRows: number };
  /**
   * Events emitted by the write in progress, awaiting persistence. Writes
   * flush (append + clear) before returning, so "the write returned"
   * implies "other processes can learn about it" — matching the audit
   * log's position in the write path.
   */
  private readonly pendingEvents: InvalidationEvent[] = [];
  private appendsSincePrune = 0;
  private readonly metricsEnabled: boolean;
  private readonly metricsBucketMs: number;
  private readonly metricsRetentionMs: number;
  private reportsSinceMetricPrune = 0;
  private readonly sodEnforce: "off" | "reject";
  private readonly auditHashChain: boolean;
  /**
   * The newest chained entry's hash. `undefined` before the first chained
   * append seeds it from storage; `null` when the chain is empty. Guarded by
   * `runExclusive("audit", …)` — reads and writes happen only inside it.
   */
  private auditHead: string | null | undefined;

  constructor(options: ApplicationOptions) {
    super();
    this.catalog = options.catalog;
    this.storage = options.storage;
    this.orgRoot = options.orgRoot ?? true;
    this.now = options.clock ?? Date.now;
    this.newId = options.ids ?? randomUUID;
    // A catalog with a hierarchical scope type and no resolver is the one
    // brown-field shape that fails OPEN: `() => []` truncates every chain,
    // so an ancestor revoke — which the README says wins "at that scope and
    // every descendant", not configurable — silently stops applying to the
    // descendants it was written for. Nothing said so before; a missing
    // resolver looked exactly like a flat deployment.
    //
    // A warning rather than a throw, because refusing construction would
    // break running deployments on a patch upgrade — including ones whose
    // hierarchical types are declared but never checked against. It becomes
    // an error in the next minor; the changelog says so.
    if (options.ancestry === undefined) {
      const hierarchical = [...this.catalog.scopeTypes.entries()]
        .filter(([, meta]) => meta.parent !== null || meta.multiParent)
        .map(([type]) => type);
      if (hierarchical.length > 0) {
        console.warn(
          `alfiz: this catalog declares hierarchical scope types (${hierarchical.join(", ")}) but createApplication got no \`ancestry\` resolver. ` +
            "Every ancestor chain will be empty, so a revoke made at a parent scope will NOT suppress access on its descendants — " +
            "the one rule Alfiz states as non-configurable. Pass `ancestry: parentPointerResolver(...)` (or your own resolver); " +
            "a resolver that cannot answer must THROW rather than return a partial chain, so the check fails closed. " +
            "This becomes an error in the next minor.",
        );
      }
    }
    this.resolveAncestors = this.guardedAncestry(options.ancestry);
    this.groupTopologyTtl = options.groupTopologyTtlMs ?? 30_000;
    this.sodEnforce = options.sod?.enforce ?? "off";
    this.auditHashChain = options.audit?.hashChain ?? false;
    const driverPersists =
      this.storage.appendEvents !== undefined &&
      this.storage.headSeq !== undefined &&
      this.storage.eventsSince !== undefined &&
      this.storage.pruneEvents !== undefined;
    // Safe-by-default: a driver that CAN persist events does, making the
    // epoch available to every process; `events: { persist: false }` is the
    // explicit opt-out. Only an explicit `true` against an incapable driver
    // is an error — the auto default degrades honestly to the pre-epoch
    // contract instead.
    this.persistEvents = options.events?.persist ?? driverPersists;
    this.eventRetention = {
      maxAgeMs: options.events?.retention?.maxAgeMs ?? 7 * 24 * 3600_000,
      maxRows: options.events?.retention?.maxRows ?? 100_000,
    };
    if (this.persistEvents) {
      const { storage } = this;
      if (
        !storage.appendEvents ||
        !storage.headSeq ||
        !storage.eventsSince ||
        !storage.pruneEvents
      ) {
        // Fail loudly: silently running without persistence would let every
        // OTHER process serve stale access it believes it can revalidate.
        throw new ProviderWriteRejectedError(
          "events.persist requires a storage driver implementing appendEvents, headSeq, eventsSince, and pruneEvents",
          "unsupported",
        );
      }
      this.epoch = {
        head: () => storage.headSeq!.call(storage),
        since: (seq, limit) =>
          storage.eventsSince!.call(storage, seq, limit ?? 500),
      };
    } else {
      this.epoch = undefined;
    }

    this.metricsEnabled = options.metrics !== undefined;
    this.metricsBucketMs = options.metrics?.bucketMs ?? 86_400_000;
    this.metricsRetentionMs = options.metrics?.retentionMs ?? 90 * 86_400_000;
    if (this.metricsEnabled) {
      const { storage } = this;
      if (!storage.recordMetrics || !storage.readMetrics || !storage.pruneMetrics) {
        // Same reasoning as `events.persist`: accepting batches that go
        // nowhere would make every safeguard read a confident zero, which is
        // worse than no safeguard at all.
        throw new ProviderWriteRejectedError(
          "metrics requires a storage driver implementing recordMetrics, readMetrics, and pruneMetrics",
          "unsupported",
        );
      }
    }
  }

  // -- events ---------------------------------------------------------------
  // Listener registry and `ingestEvents` come from `AlfizProviderBase`.
  // Coupling the topology cache to `emitInvalidation` (rather than to
  // `emit`) keeps it honest on EVERY arrival path — local writes, epoch
  // replay through `ingestEvents`, and snapshot applies alike.

  protected override emitInvalidation(event: InvalidationEvent): void {
    // Every write that can change group parentage emits a `group:` subject
    // event (or `all`), so busting here keeps the topology cache honest at
    // every emission site — including replayed events from other processes.
    if (
      event.type === "all" ||
      (event.type === "subject" && event.subject.startsWith("group:"))
    ) {
      this.groupTopology = null;
      this.groupTopologyGen++;
    }
    super.emitInvalidation(event);
  }

  private emit(event: InvalidationEvent): void {
    if (this.persistEvents) this.pendingEvents.push(event);
    this.emitInvalidation(event);
  }

  /**
   * Persist events buffered by the write in progress. Called at the end of
   * every emitting public write — after the rows, like the audit entry, and
   * awaited for the same reason: a durable row whose invalidation was lost
   * would stay live in every other process's cache until an unrelated event
   * busts it. On append failure the batch is restored for the next flush to
   * retry, and the error surfaces to the caller.
   */
  private async flushEvents(): Promise<void> {
    if (!this.persistEvents || this.pendingEvents.length === 0) return;
    const batch = this.pendingEvents.splice(0);
    try {
      await this.storage.appendEvents!(batch, this.now());
    } catch (error) {
      this.pendingEvents.unshift(...batch);
      throw error;
    }
    // Opportunistic retention pruning, off the write path's critical
    // guarantees: a failed prune costs disk, not correctness.
    if (++this.appendsSincePrune >= 32) {
      this.appendsSincePrune = 0;
      void this.storage
        .pruneEvents!({
          at: this.now() - this.eventRetention.maxAgeMs,
          keepRows: this.eventRetention.maxRows,
        })
        .catch(() => undefined);
    }
  }

  private emitSubject(subject: SubjectId): void {
    this.emit({ type: "subject", subject });
    if (subject.startsWith("user:")) {
      this.emit({ type: "user", userId: subject.slice("user:".length) });
    }
  }

  /**
   * The host application owns the object hierarchy behind
   * `resolveAncestors`, so only it knows when a resource moved. Call this
   * from the code path that changes a parent pointer: it emits the `scope`
   * invalidation event that busts cached ancestor chains immediately —
   * "moving a sensitive document into a restricted folder must take effect
   * at once". Without it, staleness is bounded only by the client's
   * object-chain TTL. With event persistence on, the returned promise
   * resolves once the event is durable (other processes can see it);
   * fire-and-forget callers keep the local-bust behavior either way.
   */
  async notifyScopeMoved(scope: LooseScopeId<S>): Promise<void> {
    this.emit({ type: "scope", scope });
    await this.flushEvents();
  }

  private async audit(
    provenance: Provenance,
    action: string,
    target: string,
    detail?: unknown,
  ): Promise<void> {
    const event: AuditEvent = {
      id: this.newId(),
      at: this.now(),
      actor: actorOf(provenance),
      action,
      target,
      ...(detail === undefined ? {} : { detail }),
    };
    if (!this.auditHashChain) {
      await this.storage.appendAudit(event);
      return;
    }
    // Chained appends serialize: the hash covers the predecessor, so two
    // concurrent appends reading the same head would fork the chain. The
    // head seeds lazily from the newest stored entry — enabling the chain
    // on an existing log starts it there, leaving earlier entries unhashed
    // before the chain rather than invalidated by it.
    await this.storage.runExclusive("audit", async () => {
      if (this.auditHead === undefined) {
        const [newest] = await this.storage.listAudit({ limit: 1 });
        this.auditHead = newest?.hash ?? null;
      }
      const prevHash = this.auditHead;
      const hash = computeAuditHash(event, prevHash);
      await this.storage.appendAudit({
        ...event,
        ...(prevHash !== null ? { prevHash } : {}),
        hash,
      });
      this.auditHead = hash;
    });
  }

  private requireOrgRoot(what: string): void {
    if (!this.orgRoot) {
      throw new ProviderWriteRejectedError(
        `${what} is organizational-domain data: this Application is not the org root and holds it as a read model`,
        "not_org_root",
      );
    }
  }

  /**
   * Provenance is validated at the TOP of every public write, not merely
   * where it is consumed: `audit()` runs after the row is inserted, so a
   * late rejection would leave a written row with no audit entry — the
   * partial-write failure the bulk path is explicitly designed against.
   */
  private assertProvenance(provenance: Provenance): void {
    const issue = validateProvenance(provenance);
    if (issue) throw new ProviderWriteRejectedError(issue, "validation");
  }

  /** Validate, then keep only the fields the kind declares. */
  private cleanProvenance(provenance: Provenance): Provenance {
    this.assertProvenance(provenance);
    return normalizeProvenance(provenance);
  }

  /**
   * The unknown-pattern rejection, with the group-path near-miss named,
   * edit-distance typos suggested, and undeclared namespaces called out —
   * the same context the check-path `UnknownPermissionError` carries.
   */
  private unknownPattern(pattern: string): ProviderWriteRejectedError {
    const { suggestion, didYouMean, hint } = unknownPermissionContext(
      this.catalog,
      pattern,
      "pattern",
    );
    let message = `pattern ${JSON.stringify(pattern)} references nothing in the catalog`;
    if (suggestion) {
      message += ` — it is a group, and groups are folders, never keys; the subtree pattern is ${JSON.stringify(suggestion)}`;
    } else {
      if (didYouMean.length > 0) {
        message += ` — did you mean ${formatAlternatives(didYouMean)}?`;
      }
      if (hint) message += ` (${hint})`;
    }
    return new ProviderWriteRejectedError(message, "validation");
  }

  // -- capabilities ---------------------------------------------------------

  async capabilities() {
    const users = await this.storage.listUsers();
    let multiParent = false;
    for (const st of this.catalog.scopeTypes.values()) {
      if (st.multiParent) multiParent = true;
    }
    return {
      orgRoot: this.orgRoot,
      requests: true,
      reporting: users.some((u) => u.managerUserId !== null),
      audit: true,
      multiParent,
      metrics: this.metricsEnabled,
      // The storage seam's import methods are optional, exactly as the
      // event-log ones are: a driver written before manifests existed still
      // satisfies the contract, and its clients simply render nothing.
      imports:
        this.storage.putImports !== undefined &&
        this.storage.getImports !== undefined,
    };
  }

  // -- closure supply -------------------------------------------------------

  /**
   * The reporting chain, walked from an already-loaded starting edge so the
   * caller's `getUser` read is not repeated. Chains are short in practice;
   * each level is one indexed read.
   */
  private async managerChain(userId: string): Promise<string[]> {
    const user = await this.storage.getUser(userId);
    return this.managerChainFrom(userId, user?.managerUserId ?? null);
  }

  private async managerChainFrom(
    userId: string,
    firstManager: string | null,
  ): Promise<string[]> {
    const chain: string[] = [];
    const seen = new Set<string>([userId]);
    let current = firstManager;
    while (current !== null && !seen.has(current)) {
      chain.push(current);
      seen.add(current);
      current = (await this.storage.getUser(current))?.managerUserId ?? null;
    }
    return chain;
  }

  /**
   * The group-parent topology, cached application-side: closure math needs
   * every parent edge, and re-reading the whole group table per subject miss
   * is the dominant cost of `getSubjectAccess`. Local group writes bust this
   * synchronously (see `emit`); the TTL bounds cross-process staleness.
   *
   * When events are persisted the TTL is NOT the only check. A client that
   * replays an invalidation busts its own entry and immediately refetches —
   * from here. If this cache is warm and stale, the client stores the stale
   * closure as freshly validated and then *renews* it on every quiet
   * revalidation, so the entry never lapses and no further event ever
   * targets it: a reparented group could stay live indefinitely, worse than
   * the blind TTL it replaced. Comparing the event-log head costs one
   * single-row read on a path that already issues several, and makes the
   * refetch that follows an invalidation actually see the write.
   */
  /**
   * Wrap the host's ancestry resolver so a chain the CATALOG says cannot be
   * empty is never accepted as empty.
   *
   * A truncated chain fails open: `can` walks up from the target scope, so a
   * missing ancestor is a revoke that silently stops applying to the
   * descendants it was written for. The shape that produces one is the shape
   * every host eventually writes — `try { ...db } catch { return [] }`, so
   * "auth doesn't break on a blip" — and it is indistinguishable from a
   * legitimately-rootless scope unless the catalog says otherwise.
   *
   * The catalog often does say otherwise. A scope type whose declared parent
   * is a DIFFERENT type (`docs.doc: { parent: "docs.folder" }`) asserts that
   * every instance has a parent, so `[]` contradicts the declaration and is
   * refused. A self-nesting type (`docs.folder: { parent: "docs.folder" }`)
   * has genuine roots, and a `parent: null` type is flat, so neither is
   * constrained here — those keep answering exactly as before.
   *
   * A resolver that cannot answer must THROW; a throw already fails closed
   * on every check shape.
   */
  private guardedAncestry(
    resolver: AncestryResolver | undefined,
  ): AncestryResolver {
    const base: AncestryResolver = resolver ?? (() => []);
    return async (scope: ScopeId) => {
      const ancestors = await base(scope);
      const type = typeof scope === "string" ? scope.slice(0, scope.indexOf(":")) : "";
      const meta = this.catalog.scopeTypes.get(type);
      const parent = meta?.parent ?? null;
      if (ancestors.length > 0) {
        // The converse contradiction, and the more dangerous one: the
        // catalog declares this type FLAT, and `parent: null` is not a hint
        // — the snapshot treats it as a promise and answers scoped checks
        // synchronously by synthesizing `[scope, "*"]`, consulting no
        // resolver at all. If the host's tables nest the type anyway, that
        // synthesis silently drops every ancestor revoke, and the sync and
        // async surfaces disagree in the permissive direction. Caught here,
        // on the path that CAN see it.
        if (
          parent === null &&
          meta !== undefined &&
          !meta.multiParent &&
          ancestors.some((a) => a !== GLOBAL_SCOPE) &&
          !this.warnedFlatTypes.has(type)
        ) {
          // Warned, not thrown — once per scope type. A blanket resolver
          // that answers the same chain for everything is a common shape in
          // development and in migrations, and refusing it outright would
          // break running deployments on a patch upgrade. The warning names
          // the contradiction; the async path keeps answering correctly (it
          // resolves the chain), and it is only the snapshot that cannot.
          this.warnedFlatTypes.add(type);
          console.warn(
            `alfiz: the ancestry resolver returned ancestors for ${JSON.stringify(scope)}, but the catalog ` +
              `declares ${JSON.stringify(type)} with \`parent: null\` — a flat scope type. That declaration is ` +
              "load-bearing: snapshots answer scoped checks for flat types synchronously, without consulting the " +
              "resolver, so a nested instance loses its ancestor revokes THERE while `client.can` still applies " +
              "them — the two surfaces disagree, permissively. Declare the parent, or stop nesting the type.",
          );
        }
        return ancestors;
      }
      if (parent !== null && parent !== type) {
        throw new ProviderWriteRejectedError(
          `the ancestry resolver returned no ancestors for ${JSON.stringify(scope)}, but the catalog ` +
            `declares ${JSON.stringify(type)} nested under ${JSON.stringify(parent)}, so every instance has one. ` +
            "An empty chain would silently drop ancestor revokes on this scope — a resolver that cannot " +
            "answer must throw rather than return a partial chain.",
          "unsupported",
        );
      }
      return ancestors;
    };
  }

  /**
   * The event-log head, or `null` when this Application does not persist
   * events (nothing to compare against — the TTL is the whole bound, as
   * documented). An unreadable log answers `NaN`, which equals no recorded
   * seq, so a cache built under a readable log is dropped rather than
   * trusted while the log is down.
   */
  private async currentEpochSeq(): Promise<number | null> {
    if (!this.epoch) return null;
    try {
      return await this.epoch.head();
    } catch {
      return Number.NaN;
    }
  }

  private async groupParentMap(): Promise<Map<string, readonly string[]>> {
    if (this.groupTopologyTtl <= 0) {
      const groups = await this.storage.listGroups();
      return new Map(groups.map((g) => [g.id, g.parents]));
    }
    const cached = this.groupTopology;
    if (cached && cached.expiresAt > this.now()) {
      const seq = await this.currentEpochSeq();
      if (seq === cached.seq) return cached.parents;
      // The log moved (or became unreadable) since this snapshot: drop it
      // rather than build a closure on it.
      this.groupTopology = null;
      this.groupTopologyGen++;
    }
    if (this.groupTopologyFetch) return this.groupTopologyFetch;
    const generation = this.groupTopologyGen;
    // Both reads start inside ONE promise that is registered synchronously
    // below — awaiting the seq out here would let concurrent misses slip past
    // the in-flight check and each issue their own `listGroups`, which is the
    // fan-out this cache exists to prevent.
    const fetching = (async () => {
      const [seqAtFetch, groups] = await Promise.all([
        this.currentEpochSeq(),
        this.storage.listGroups(),
      ]);
      const parents = new Map<string, readonly string[]>(
        groups.map((g) => [g.id, g.parents]),
      );
      if (this.groupTopologyGen === generation) {
        this.groupTopology = {
          parents,
          expiresAt: this.now() + this.groupTopologyTtl,
          seq: seqAtFetch,
        };
      }
      return parents;
    })();
    this.groupTopologyFetch = fetching;
    try {
      return await fetching;
    } finally {
      this.groupTopologyFetch = null;
    }
  }

  async getSubjectAccess(principal: PrincipalRef): Promise<SubjectAccessData> {
    // The same discriminant the Client keys its cache by — see
    // `principalKind`. Reading the halves in a different order here is how a
    // principal naming both got a service's closure stored under a user's key.
    const who = principalKind(principal);
    if (who.kind === "service") {
      const closure = [...computeServiceClosure(who.id)];
      const grants = (
        await this.storage.listGrants({ subjects: closure })
      ).filter((row) => !isExpired(row, this.now()));
      const { roles, unresolvedRoleIds } = await this.resolveRoles(grants);
      return {
        userId: null,
        closure,
        grants,
        revokes: [],
        roles,
        managerChain: [],
        unresolvedRoleIds,
        active: true,
      };
    }

    const [stored, groupParents] = await Promise.all([
      this.storage.getUser(who.id),
      this.groupParentMap(),
    ]);
    // A principal the identity provider authenticated but Alfiz never
    // provisioned is still a member of `everyone` — public access is an
    // ordinary grant row, and it must reach them. Deny-by-default still
    // holds: without matching rows they can do nothing. Inactive means an
    // EXPLICIT active:false — offboarding, not absence.
    const user: StoredUser = stored ?? {
      userId: who.id,
      active: true,
      groupIds: [],
      orgIds: [],
      managerUserId: null,
    };
    const managerChain = await this.managerChainFrom(
      user.userId,
      user.managerUserId,
    );
    const closure = [
      ...computeSubjectClosure({
        userId: user.userId,
        groupIds: user.groupIds,
        groupParents,
        orgIds: user.orgIds,
        managerChain,
      }),
    ];
    const [allGrants, revokes] = await Promise.all([
      this.storage.listGrants({ subjects: closure }),
      this.storage.listRevokes({ userId: user.userId }),
    ]);
    // Expired grants are dropped on the WRITER's clock as well as the
    // checker's. The evaluator filters them too — that is what makes expiry
    // exact for an in-process check — but the checking process may be a
    // different machine whose clock lags this one, and a lagging checker
    // would honour a grant this Application already considers dead. Only
    // grants are filtered: a revoke is the negative layer, and dropping one
    // early could only ever widen access.
    const grants = allGrants.filter((row) => !isExpired(row, this.now()));
    const { roles, unresolvedRoleIds } = await this.resolveRoles(grants);
    return {
      userId: user.userId,
      closure,
      grants,
      revokes,
      roles,
      managerChain,
      unresolvedRoleIds,
      active: user.active,
    };
  }

  /**
   * One pass over the distinct role ids a grant set references — batched
   * through `StorageDriver.getRoles` when the driver provides it, parallel
   * per-id reads otherwise. Found and missing ids come from the same reads,
   * so the two can never disagree (the previous shape fetched every role
   * twice, serially, once per question).
   */
  private async resolveRoles(grants: readonly GrantRow[]): Promise<{
    roles: RoleRecord[];
    unresolvedRoleIds: string[];
  }> {
    const ids = [...new Set(grants.flatMap((g) => (g.roleId ? [g.roleId] : [])))];
    if (ids.length === 0) return { roles: [], unresolvedRoleIds: [] };
    const found = this.storage.getRoles
      ? await this.storage.getRoles(ids)
      : (await Promise.all(ids.map((id) => this.storage.getRole(id)))).filter(
          (role): role is RoleRecord => role !== null,
        );
    const byId = new Map(found.map((role) => [role.id, role]));
    const roles: RoleRecord[] = [];
    const unresolvedRoleIds: string[] = [];
    for (const id of ids) {
      const role = byId.get(id);
      if (role) roles.push(role);
      else unresolvedRoleIds.push(id);
    }
    return { roles, unresolvedRoleIds };
  }

  private async contextFor(principal: PrincipalRef): Promise<{
    data: SubjectAccessData;
    ctx: CheckContext;
  }> {
    const data = await this.getSubjectAccess(principal);
    return {
      data,
      ctx: {
        subjectClosure: new Set(data.closure),
        userId: data.userId,
        rows: {
          grants: data.grants,
          revokes: data.revokes,
          roles: new Map(data.roles.map((r) => [r.id, r])),
        },
        now: this.now(),
        grantApplies: (key, grantScope) => this.catalog.appliesAt(key, grantScope),
      },
    };
  }

  // -- row operations -------------------------------------------------------

  private validateGrantInput(input: Omit<GrantInput, "provenance">): void {
    const scope = input.scope ?? GLOBAL_SCOPE;
    const scopeIssue = validateScopeId(scope);
    if (scopeIssue) {
      throw new ProviderWriteRejectedError(scopeIssue.reason, "validation");
    }
    if ((input.roleId === undefined) === (input.pattern === undefined)) {
      throw new ProviderWriteRejectedError(
        "a grant carries exactly one of roleId / pattern",
        "validation",
      );
    }
    if (input.pattern !== undefined) {
      const issue = validatePattern(input.pattern);
      if (issue) {
        throw new ProviderWriteRejectedError(issue.reason, "validation");
      }
      if (!this.catalog.isKnownPattern(input.pattern)) {
        throw this.unknownPattern(input.pattern);
      }
      if (!isGlobalScope(scope)) {
        const grantable = this.catalog.validateGrantableAt(input.pattern, scope);
        if (grantable) {
          throw new ProviderWriteRejectedError(grantable.message, "validation");
        }
      }
    }
    if (input.expiresAt !== undefined && input.expiresAt !== null) {
      // Shape before value: the past-expiry guard below is a comparison, and
      // a comparison against `NaN` — which is what an arithmetic slip or an
      // ISO string arriving over the wire produces — is `false` in both
      // directions, so a malformed bound slipped past the write path AND
      // read as "never expires" at every check. The evaluator now fails
      // closed on such a row; this stops it being stored at all.
      if (
        typeof input.expiresAt !== "number" ||
        !Number.isFinite(input.expiresAt)
      ) {
        throw new ProviderWriteRejectedError(
          `expiresAt must be a finite epoch-millisecond number — received ${JSON.stringify(input.expiresAt)}`,
          "validation",
        );
      }
      if (input.expiresAt <= this.now()) {
        throw new ProviderWriteRejectedError(
          "expiresAt is already in the past",
          "validation",
        );
      }
    }
  }

  /** Everything createGrant checks before touching storage — shared by the bulk form. */
  private async assertGrantWritable(
    input: Omit<GrantInput, "provenance">,
  ): Promise<void> {
    this.validateGrantInput(input);
    const scope = input.scope ?? GLOBAL_SCOPE;
    if (isGlobalScope(scope)) this.requireOrgRoot("a global-scope grant");
    if (input.roleId !== undefined) {
      const role = await this.storage.getRole(input.roleId);
      if (!role) {
        throw new ProviderWriteRejectedError(
          `role ${JSON.stringify(input.roleId)} does not exist`,
          "not_found",
        );
      }
      if (!isGlobalScope(scope)) {
        const grantable = role.patterns.some(
          (p) => this.catalog.validateGrantableAt(p, scope) === null,
        );
        if (!grantable) {
          throw new ProviderWriteRejectedError(
            `role ${JSON.stringify(input.roleId)} has no pattern grantable at ${scope}`,
            "validation",
          );
        }
      }
    }
  }

  private buildGrantRow(
    input: Omit<GrantInput, "provenance">,
    provenance: Provenance,
  ): GrantRow {
    const row: GrantRow = {
      id: this.newId(),
      subject: input.subject,
      roleId: input.roleId,
      pattern: input.pattern,
      scope: input.scope ?? GLOBAL_SCOPE,
      expiresAt: input.expiresAt,
      provenance: this.cleanProvenance(provenance),
      createdAt: this.now(),
    };
    const invalid = validateGrantRow(row);
    if (invalid) {
      throw new ProviderWriteRejectedError(invalid.reason, "validation");
    }
    return row;
  }

  /**
   * The preventive half of separation-of-duty, when opted into: would this
   * row give a USER a violation they do not already have? Pre-existing
   * violations never block unrelated writes — the report owns those — and
   * non-user subjects pass through (see `ApplicationOptions.sod`).
   */
  private async assertSodAllows(
    row: GrantRow,
    /**
     * Rows written earlier in the same batch. `contextFor` reads storage,
     * and nothing in a batch is in storage yet, so without this each row was
     * judged against a world containing none of its siblings — and the two
     * halves of a constraint, submitted together, both passed. A batch is
     * one write as far as the constraint is concerned.
     */
    pending: readonly GrantRow[] = [],
  ): Promise<void> {
    if (this.sodEnforce !== "reject") return;
    const constraints = this.catalog.sodConstraints;
    if (constraints.length === 0) return;
    const parsed = parseSubject(row.subject);
    if (parsed?.kind !== "user") return;
    const { ctx } = await this.contextFor({ userId: parsed.id });
    const siblings = pending.filter((r) => r.subject === row.subject);
    const baseGrants = [...ctx.rows.grants, ...siblings];
    const before = checkSodConstraints(
      { ...ctx, rows: { ...ctx.rows, grants: baseGrants } },
      this.catalog,
      constraints,
    );
    const after = checkSodConstraints(
      { ...ctx, rows: { ...ctx.rows, grants: [...baseGrants, row] } },
      this.catalog,
      constraints,
    );
    const had = new Set(before.map((v) => v.constraintId));
    const created = after.find((v) => !had.has(v.constraintId));
    if (created) {
      throw new ProviderWriteRejectedError(
        `grant violates separation-of-duty constraint ${JSON.stringify(created.constraintId)}: the subject would hold ${created.sets
          .map((s) => `[${s.keys.join(", ")}]`)
          .join(" and ")}`,
        "conflict",
      );
    }
  }

  /**
   * The detective separation-of-duty report: every user whose effective
   * access crosses a constraint's sets, with the concrete keys that put
   * them there. Evaluation is `checkSodConstraints` over the same closure
   * supply every check uses — revokes suppress, expiry filters, and a
   * violation names only access the user genuinely holds right now.
   */
  async listSodViolations(options?: {
    userIds?: readonly string[] | undefined;
  }): Promise<Array<{ userId: string; violations: SodViolation[] }>> {
    const constraints = this.catalog.sodConstraints;
    if (constraints.length === 0) return [];
    let userIds = options?.userIds;
    if (userIds === undefined) {
      // Candidates are every user the system can NAME: stored user records
      // plus user-subject grant rows (a grant to `user:x` does not create a
      // record). Access arriving purely through `everyone` or an org
      // subject reaches users this store never heard of; those are the
      // host's to enumerate via `options.userIds`.
      const named = new Set(
        (await this.storage.listUsers()).map((u) => u.userId),
      );
      for (const grant of await this.storage.listGrants()) {
        const parsed = parseSubject(grant.subject);
        if (parsed?.kind === "user") named.add(parsed.id);
      }
      userIds = [...named].sort();
    }
    const report: Array<{ userId: string; violations: SodViolation[] }> = [];
    for (const userId of userIds) {
      const { ctx } = await this.contextFor({ userId });
      const violations = checkSodConstraints(ctx, this.catalog, constraints);
      if (violations.length > 0) report.push({ userId, violations });
    }
    return report;
  }

  /**
   * The entitlement export: the per-user effective-access rollup an access
   * review signs and an external IGA ingests. Answers arrive computed —
   * closure walked, roles resolved, expiry filtered, revokes applied — so
   * a reviewer reads capability, not raw rows; each entitlement still
   * names its conferring rows, which is the write-back path (revoke the
   * grant, end-date it, or write a personal revoke, all ordinary API).
   * Same candidate rule as `listSodViolations`: stored users plus
   * user-subject grant rows, with `userIds` for hosts whose users this
   * store cannot enumerate.
   */
  async exportEntitlements(options?: {
    userIds?: readonly string[] | undefined;
  }): Promise<PrincipalEntitlements[]> {
    let userIds = options?.userIds;
    if (userIds === undefined) {
      const named = new Set(
        (await this.storage.listUsers()).map((u) => u.userId),
      );
      for (const grant of await this.storage.listGrants()) {
        const parsed = parseSubject(grant.subject);
        if (parsed?.kind === "user") named.add(parsed.id);
      }
      userIds = [...named].sort();
    }
    const out: PrincipalEntitlements[] = [];
    for (const userId of userIds) {
      const { data, ctx } = await this.contextFor({ userId });
      const { entitlements, revokes } = entitlementsOf(ctx, this.catalog);
      out.push({
        userId,
        active: data.active,
        closure: data.closure,
        entitlements,
        revokes,
      });
    }
    return out;
  }

  async createGrant(input: GrantInput<P, S>): Promise<GrantRow> {
    this.assertProvenance(input.provenance);
    await this.assertGrantWritable(input);
    const row = this.buildGrantRow(input, input.provenance);
    await this.assertSodAllows(row);
    // Audit BEFORE the row, not after. The seam has no transaction, so one
    // of the two can fail alone, and the orders are not equivalent: audit
    // last means a failed append leaves a live, unaudited grant — the exact
    // state an attacker who can break audit writes would want. Audit first
    // means a failed insert leaves an entry for a grant that never existed,
    // which over-reports rather than under-reports, and which the invariant
    // this class already states ("no row without its audit entry") permits.
    await this.audit(input.provenance, "grant.create", row.id, {
      subject: row.subject,
      roleId: row.roleId,
      pattern: row.pattern,
      scope: row.scope,
      expiresAt: row.expiresAt,
    });
    await this.storage.insertGrant(row);
    this.emitSubject(row.subject);
    await this.flushEvents();
    return row;
  }

  /**
   * The bulk write for migrations and imports. Every input is validated
   * BEFORE any row is written, so one bad assignment rejects the whole
   * batch instead of leaving a half-imported tenant; then one audit entry
   * records the batch and one invalidation event fires per distinct
   * subject. N sequential `createGrant` calls would cost N validations, N
   * audit rows, and N cache busts — this is the shape a real tenant
   * migration wants.
   */
  async createGrants(
    inputs: readonly Omit<GrantInput<P, S>, "provenance">[],
    provenance: Provenance,
  ): Promise<GrantRow[]> {
    this.assertProvenance(provenance);
    if (inputs.length === 0) return [];
    for (const input of inputs) {
      await this.assertGrantWritable(input);
    }
    const rows = inputs.map((input) => this.buildGrantRow(input, provenance));
    for (const [index, row] of rows.entries()) {
      await this.assertSodAllows(row, rows.slice(0, index));
    }
    // Audited first, for the reason `createGrant` states, and recording what
    // the batch CONFERS rather than only how many rows it wrote — a bulk
    // write later deleted otherwise left a log that never said what was
    // granted to whom.
    await this.audit(provenance, "grant.create_bulk", this.newId(), {
      count: rows.length,
      grantIds: rows.map((r) => r.id),
      grants: rows.map((r) => ({
        id: r.id,
        subject: r.subject,
        roleId: r.roleId,
        pattern: r.pattern,
        scope: r.scope,
        expiresAt: r.expiresAt,
      })),
    });
    // "One bad assignment rejects the whole batch instead of leaving a
    // half-imported tenant" covered VALIDATION only: a driver error on row N
    // left rows 1..N-1 live while the caller saw a rejection and, reasonably,
    // retried — duplicating access under fresh ids. Without a transaction on
    // the seam, compensation is the honest approximation: undo what landed,
    // then report the original failure.
    const written: GrantRow[] = [];
    try {
      for (const row of rows) {
        await this.storage.insertGrant(row);
        written.push(row);
      }
    } catch (error) {
      for (const row of written.reverse()) {
        try {
          await this.storage.deleteGrant(row.id);
        } catch {
          // Best effort: the original failure is the one worth reporting,
          // and `reconcileRows()` is the sweep for whatever survives.
        }
      }
      await this.audit(provenance, "grant.create_bulk_rolled_back", this.newId(), {
        attempted: rows.length,
        undone: written.length,
        reason: error instanceof Error ? error.message : String(error),
      });
      await this.flushEvents();
      throw error;
    }
    for (const subject of new Set(rows.map((r) => r.subject))) {
      this.emitSubject(subject);
    }
    await this.flushEvents();
    return rows;
  }

  async deleteGrant(grantId: string, provenance: Provenance): Promise<void> {
    this.assertProvenance(provenance);
    if (!this.orgRoot) {
      // Inspect before touching: org-domain rows are not ours to delete, and
      // a delete-then-undo would leave a window where the row is missing.
      const target = (await this.storage.listGrants()).find(
        (r) => r.id === grantId,
      );
      if (!target) {
        throw new ProviderWriteRejectedError("grant not found", "not_found");
      }
      if (isGlobalScope(target.scope)) {
        this.requireOrgRoot("a global-scope grant");
      }
    }
    const row = await this.storage.deleteGrant(grantId);
    if (!row) {
      throw new ProviderWriteRejectedError("grant not found", "not_found");
    }
    await this.audit(provenance, "grant.delete", grantId, {
      subject: row.subject,
    });
    this.emitSubject(row.subject);
    await this.flushEvents();
  }

  async listGrants(filter?: GrantQuery): Promise<GrantRow[]> {
    return this.storage.listGrants({
      subject: filter?.subject,
      scope: filter?.scope,
      roleId: filter?.roleId,
    });
  }

  /**
   * Matching grants, counted in the database. The role-holder count an
   * admin page renders per row is the case this exists for — `listGrants()`
   * and grouping in memory reads every grant in the organization to
   * produce a number.
   */
  async countGrants(filter?: GrantQuery): Promise<number> {
    return this.storage.countGrants({
      subject: filter?.subject,
      scope: filter?.scope,
      roleId: filter?.roleId,
    });
  }

  async createRevoke(input: RevokeInput<P, S>): Promise<RevokeRow> {
    this.assertProvenance(input.provenance);
    const scope = input.scope ?? GLOBAL_SCOPE;
    if (isGlobalScope(scope)) this.requireOrgRoot("a global-scope revoke");
    const issue = validatePattern(input.pattern);
    if (issue) throw new ProviderWriteRejectedError(issue.reason, "validation");
    if (!this.catalog.isKnownPattern(input.pattern)) {
      // A typo'd revoke would silently fail OPEN — the one direction a
      // mistake here must never take.
      throw this.unknownPattern(input.pattern);
    }
    const scopeIssue = validateScopeId(scope);
    if (scopeIssue) {
      throw new ProviderWriteRejectedError(scopeIssue.reason, "validation");
    }
    const row: RevokeRow = {
      id: this.newId(),
      userId: input.userId,
      pattern: input.pattern,
      scope,
      provenance: this.cleanProvenance(input.provenance),
      createdAt: this.now(),
    };
    await this.storage.insertRevoke(row);
    await this.audit(input.provenance, "revoke.create", row.id, {
      userId: row.userId,
      pattern: row.pattern,
      scope: row.scope,
    });
    this.emit({ type: "user", userId: row.userId });
    await this.flushEvents();
    return row;
  }

  async deleteRevoke(revokeId: string, provenance: Provenance): Promise<void> {
    this.assertProvenance(provenance);
    if (!this.orgRoot) {
      const target = (await this.storage.listRevokes()).find(
        (r) => r.id === revokeId,
      );
      if (!target) {
        throw new ProviderWriteRejectedError("revoke not found", "not_found");
      }
      if (isGlobalScope(target.scope)) {
        this.requireOrgRoot("a global-scope revoke");
      }
    }
    const row = await this.storage.deleteRevoke(revokeId);
    if (!row) {
      throw new ProviderWriteRejectedError("revoke not found", "not_found");
    }
    await this.audit(provenance, "revoke.delete", revokeId, {
      userId: row.userId,
    });
    this.emit({ type: "user", userId: row.userId });
    await this.flushEvents();
  }

  async listRevokes(filter?: {
    userId?: string | undefined;
    scope?: ScopeId | undefined;
  }): Promise<RevokeRow[]> {
    return this.storage.listRevokes(filter);
  }

  // -- referential cleanup ----------------------------------------------------
  // Grants key on subject and scope STRINGS, not foreign keys. Deleting a
  // principal or a resource in the host application's own tables therefore
  // strands the rows here — silently, and a reused id would inherit the
  // stranded access. These two are the deletion discipline, paired with the
  // host's own delete paths exactly as `notifyScopeMoved` pairs with moves.

  /**
   * Remove a principal from the authorization system: every grant held by
   * `subject`; and for `user:<id>` subjects also their personal revokes,
   * their stored record (memberships, org links, reporting edge), grants
   * held by their implicit-group subjects (`directs:<id>` / `orgof:<id>`,
   * which are keyed to the user id and would resurrect on id reuse), and
   * their pending access requests (cancelled — a departed requester must
   * not haunt approver queues).
   *
   * Call this from the same code path that deletes the user, revokes the
   * API token, or removes the service account. For groups prefer
   * `deleteGroup`, which additionally repairs parentage and memberships.
   * Reporting edges POINTING AT a deleted user are left in place: who
   * inherits the orphaned team is an organizational decision for the host
   * (reassign via `setReportingEdge` / `importDirectory`), not a cleanup.
   */
  async deleteSubject(
    subject: SubjectId,
    provenance: Provenance,
  ): Promise<{ deletedGrants: number; deletedRevokes: number }> {
    this.assertProvenance(provenance);
    if (!isValidSubject(subject)) {
      throw new ProviderWriteRejectedError(
        `${JSON.stringify(subject)} is not a valid subject id`,
        "validation",
      );
    }
    const parsed = parseSubject(subject)!;
    if (parsed.kind === "user") {
      // Offboarding touches the user record and memberships: org-domain.
      this.requireOrgRoot("offboarding a user");
    }
    const sweep: SubjectId[] =
      parsed.kind === "user"
        ? [subject, `directs:${parsed.id}`, `orgof:${parsed.id}`]
        : [subject];
    const grants: GrantRow[] = [];
    for (const member of sweep) {
      grants.push(...(await this.storage.listGrants({ subject: member })));
    }
    const revokes =
      parsed.kind === "user"
        ? await this.storage.listRevokes({ userId: parsed.id })
        : [];
    if (
      !this.orgRoot &&
      (grants.some((g) => isGlobalScope(g.scope)) ||
        revokes.some((r) => isGlobalScope(r.scope)))
    ) {
      // Checked before ANY row is touched: no partial sweep on rejection.
      this.requireOrgRoot("deleting a subject's global-scope rows");
    }
    for (const grant of grants) {
      await this.storage.deleteGrant(grant.id);
      await this.audit(provenance, "grant.delete", grant.id, {
        subject: grant.subject,
        reason: "subject deleted",
      });
    }
    for (const revoke of revokes) {
      await this.storage.deleteRevoke(revoke.id);
      await this.audit(provenance, "revoke.delete", revoke.id, {
        userId: revoke.userId,
        reason: "subject deleted",
      });
    }
    let cancelledRequests = 0;
    if (parsed.kind === "user") {
      const pending = await this.storage.listRequests({
        state: "pending",
        requesterUserId: parsed.id,
      });
      for (const request of pending) {
        await this.storage.updateRequest({
          ...request,
          state: "cancelled",
          decidedAt: this.now(),
        });
        await this.audit(provenance, "request.cancel", request.id, {
          reason: "subject deleted",
        });
      }
      cancelledRequests = pending.length;
      await this.storage.deleteUser(parsed.id);
    }
    await this.audit(provenance, "subject.delete", subject, {
      grants: grants.length,
      revokes: revokes.length,
      ...(cancelledRequests > 0 ? { cancelledRequests } : {}),
    });
    for (const member of sweep) this.emitSubject(member);
    await this.flushEvents();
    return { deletedGrants: grants.length, deletedRevokes: revokes.length };
  }

  /**
   * Remove a deleted resource's access data: every grant and every personal
   * revoke AT `scope`, plus cancellation of pending requests targeting it.
   * Call this from the same code path that deletes the resource row.
   *
   * Rows at DESCENDANT scopes are separate rows — hierarchy is your data,
   * so Alfiz cannot enumerate a subtree. When you delete a subtree of
   * resources, call this once per deleted resource id.
   */
  async deleteScope(
    scope: LooseScopeId<S>,
    provenance: Provenance,
  ): Promise<{ deletedGrants: number; deletedRevokes: number }> {
    this.assertProvenance(provenance);
    if (isGlobalScope(scope)) {
      throw new ProviderWriteRejectedError(
        "the global scope is not a deletable resource",
        "validation",
      );
    }
    const scopeIssue = validateScopeId(scope);
    if (scopeIssue) {
      throw new ProviderWriteRejectedError(scopeIssue.reason, "validation");
    }
    const grants = await this.storage.listGrants({ scope });
    const revokes = await this.storage.listRevokes({ scope });
    for (const grant of grants) {
      await this.storage.deleteGrant(grant.id);
      await this.audit(provenance, "grant.delete", grant.id, {
        subject: grant.subject,
        reason: "scope deleted",
      });
    }
    for (const revoke of revokes) {
      await this.storage.deleteRevoke(revoke.id);
      await this.audit(provenance, "revoke.delete", revoke.id, {
        userId: revoke.userId,
        reason: "scope deleted",
      });
    }
    const pending = (
      await this.storage.listRequests({ state: "pending" })
    ).filter((r) => r.scope === scope);
    for (const request of pending) {
      await this.storage.updateRequest({
        ...request,
        state: "cancelled",
        decidedAt: this.now(),
      });
      await this.audit(provenance, "request.cancel", request.id, {
        reason: "scope deleted",
      });
    }
    await this.audit(provenance, "scope.delete", scope, {
      grants: grants.length,
      revokes: revokes.length,
      ...(pending.length > 0 ? { cancelledRequests: pending.length } : {}),
    });
    this.emit({ type: "scope", scope });
    for (const subject of new Set(grants.map((g) => g.subject))) {
      this.emitSubject(subject);
    }
    for (const userId of new Set(revokes.map((r) => r.userId))) {
      this.emit({ type: "user", userId });
    }
    await this.flushEvents();
    return { deletedGrants: grants.length, deletedRevokes: revokes.length };
  }

  /**
   * The reconciliation job behind `deleteSubject`/`deleteScope` discipline:
   * grants and revokes reference subjects and scopes as opaque strings, so
   * a host that missed a cleanup call strands rows silently — and a reused
   * identifier RESURRECTS them as live access. This report finds them.
   *
   * The host supplies existence predicates over ITS tables (`userExists`,
   * `scopeExists`); group- and role-referencing rows are checked against
   * this store's own tables with no callback needed. Run it on a schedule;
   * with `sweep: true` (and provenance) the orphans are deleted through the
   * same audited paths as any other removal. Detection without a sweep is
   * free of write risk and is the recommended first deployment.
   */
  async reconcileRows(input: {
    /** Does this user id exist in the host's user store? */
    userExists?: ((userId: string) => boolean | Promise<boolean>) | undefined;
    /** Does this org id still exist? Unchecked when omitted. */
    orgExists?: ((orgId: string) => boolean | Promise<boolean>) | undefined;
    /** Does this scope instance still resolve to a resource? Unchecked when omitted. */
    scopeExists?: ((scope: string) => boolean | Promise<boolean>) | undefined;
    /** Delete what was found, through the audited delete paths. */
    sweep?: boolean | undefined;
    /** Required with `sweep` — the audit actor of the deletions. */
    provenance?: Provenance | undefined;
  }): Promise<{
    orphanedGrants: GrantRow[];
    orphanedRevokes: RevokeRow[];
    /** Grants naming a role this store no longer defines. */
    danglingRoleGrants: GrantRow[];
    swept: boolean;
  }> {
    if (input.sweep) {
      if (!input.provenance) {
        throw new ProviderWriteRejectedError(
          "reconcileRows with sweep: true requires provenance for the audited deletions",
          "validation",
        );
      }
      this.assertProvenance(input.provenance);
    }
    const knownGroups = new Set(
      (await this.storage.listGroups()).map((g) => g.id),
    );
    const knownRoles = new Set(
      (await this.storage.listRoles()).map((r) => r.id),
    );
    const userExists = async (userId: string): Promise<boolean> =>
      input.userExists === undefined ? true : await input.userExists(userId);
    const subjectOrphaned = async (subject: SubjectId): Promise<boolean> => {
      const parsed = parseSubject(subject);
      if (parsed === null) return false; // malformed is a different finding
      switch (parsed.kind) {
        case "user":
          return !(await userExists(parsed.id));
        case "group":
          return !knownGroups.has(parsed.id);
        case "directs":
        case "orgof":
          return !(await userExists(parsed.id));
        case "org":
          return input.orgExists === undefined
            ? false
            : !(await input.orgExists(parsed.id));
        default:
          return false; // everyone / service subjects have no host table
      }
    };
    const scopeOrphaned = async (scope: string): Promise<boolean> =>
      input.scopeExists !== undefined &&
      !isGlobalScope(scope) &&
      !(await input.scopeExists(scope));

    const orphanedGrants: GrantRow[] = [];
    const danglingRoleGrants: GrantRow[] = [];
    for (const grant of await this.storage.listGrants()) {
      if (
        (await subjectOrphaned(grant.subject)) ||
        (await scopeOrphaned(grant.scope))
      ) {
        orphanedGrants.push(grant);
      } else if (grant.roleId !== undefined && !knownRoles.has(grant.roleId)) {
        danglingRoleGrants.push(grant);
      }
    }
    const orphanedRevokes: RevokeRow[] = [];
    for (const revoke of await this.storage.listRevokes()) {
      if (
        !(await userExists(revoke.userId)) ||
        (await scopeOrphaned(revoke.scope))
      ) {
        orphanedRevokes.push(revoke);
      }
    }

    if (input.sweep && input.provenance) {
      const provenance = input.provenance;
      for (const grant of orphanedGrants) {
        await this.storage.deleteGrant(grant.id);
        await this.audit(provenance, "grant.delete", grant.id, {
          subject: grant.subject,
          scope: grant.scope,
          reason: "reconciliation: orphaned",
        });
        this.emitSubject(grant.subject);
      }
      for (const revoke of orphanedRevokes) {
        await this.storage.deleteRevoke(revoke.id);
        await this.audit(provenance, "revoke.delete", revoke.id, {
          userId: revoke.userId,
          reason: "reconciliation: orphaned",
        });
        this.emit({ type: "user", userId: revoke.userId });
      }
      // Dangling role grants are NOT swept: the row's subject and scope are
      // real, and deleting the row on a missing role definition could mask a
      // role-sync bug. They stay a finding for a human.
      await this.audit(provenance, "reconcile.sweep", "rows", {
        grants: orphanedGrants.length,
        revokes: orphanedRevokes.length,
      });
      await this.flushEvents();
    }

    return {
      orphanedGrants,
      orphanedRevokes,
      danglingRoleGrants,
      swept: input.sweep === true,
    };
  }

  // -- requests -------------------------------------------------------------

  /**
   * §9.3: a policy referencing management layers where no reporting
   * hierarchy is populated is a configuration error — surfaced at policy
   * creation for roles, at submission for catalog scope-type policies —
   * never silently skipped. Empty stage lists and layers < 1 are equally
   * unresolvable.
   */
  private async assertPolicyResolvable(
    stages: readonly ApprovalStage[],
  ): Promise<void> {
    if (stages.length === 0) {
      throw new ProviderWriteRejectedError(
        "requestable without a resolvable policy: declare at least one approval stage",
        "validation",
      );
    }
    for (const stage of stages) {
      if (stage.kind !== "management") continue;
      if ((stage.layers ?? 1) < 1) {
        throw new ProviderWriteRejectedError(
          "management layers must be at least 1 (the direct manager)",
          "validation",
        );
      }
      const users = await this.storage.listUsers();
      if (!users.some((u) => u.managerUserId !== null)) {
        throw new ProviderWriteRejectedError(
          "policy references management layers but no reporting hierarchy is populated",
          "validation",
        );
      }
    }
  }

  private async requestability(input: RequestInput): Promise<{
    prompts: readonly import("@alfiz/core").RequestPromptInput[];
    maxDurationMs: number | undefined;
    requireExpiry: boolean;
    stages: readonly ApprovalStage[];
    /** Undefined for a role-shaped request — the role is its own ceiling. */
    patterns?: readonly PermissionPattern[] | undefined;
  }> {
    if (input.roleId !== undefined) {
      const role = await this.storage.getRole(input.roleId);
      if (!role) {
        throw new ProviderWriteRejectedError("role not found", "not_found");
      }
      if (!role.requestable) {
        throw new ProviderWriteRejectedError(
          `role ${JSON.stringify(role.name)} is not requestable`,
          "validation",
        );
      }
      const scope = input.scope ?? GLOBAL_SCOPE;
      if (!isGlobalScope(scope)) {
        // Approval writes the row without re-validation, so the same
        // grantability rule as createGrant must hold at submission.
        const grantable = role.patterns.some(
          (p) => this.catalog.validateGrantableAt(p, scope) === null,
        );
        if (!grantable) {
          throw new ProviderWriteRejectedError(
            `role ${JSON.stringify(role.name)} has no pattern grantable at ${scope}`,
            "validation",
          );
        }
      }
      return {
        prompts: role.requestable.prompts ?? [],
        maxDurationMs: role.requestable.maxDurationMs,
        requireExpiry: role.requestable.requireExpiry ?? false,
        stages: role.requestable.stages,
      };
    }
    const scope = input.scope ?? GLOBAL_SCOPE;
    if (isGlobalScope(scope)) {
      throw new ProviderWriteRejectedError(
        "pattern requests need a scope whose type declares requestability; global access is requested through requestable roles",
        "validation",
      );
    }
    const type = scope.slice(0, scope.indexOf(":"));
    const scopeType = this.catalog.scopeTypes.get(type);
    if (!scopeType?.requestable) {
      throw new ProviderWriteRejectedError(
        `scope type ${JSON.stringify(type)} is not requestable`,
        "validation",
      );
    }
    return {
      prompts: scopeType.requestable.prompts ?? [],
      maxDurationMs: scopeType.requestable.maxDurationMs,
      requireExpiry: scopeType.requestable.requireExpiry ?? false,
      stages: scopeType.requestable.policy.stages,
      patterns: scopeType.requestable.patterns,
    };
  }

  /**
   * The ceiling on what a pattern-shaped request may ask for.
   *
   * Two rules. The bare global `*` is never requestable — it confers every
   * key grantable at the scope, destructive ones included, and "give me
   * everything" is not a reviewable ask however good the approver. Beyond
   * that, a scope type may declare `requestable.patterns`, and a proposal
   * must be covered by one of them; a type that declares none accepts any
   * other declared pattern, exactly as before.
   *
   * This is what stops an `auto` stage — "my team may self-serve folder
   * access" — from handing over a pattern nobody reviewed.
   */
  private assertRequestablePattern(
    pattern: PermissionPattern,
    allowed: readonly PermissionPattern[] | undefined,
  ): void {
    if (pattern === "*") {
      throw new ProviderWriteRejectedError(
        'a request cannot propose the unbounded global pattern "*" — it confers every key ' +
          "grantable at the scope. Request the concrete patterns you need, or a role that names them.",
        "validation",
      );
    }
    if (allowed === undefined) return;
    // Containment, not intersection: a proposal must fit INSIDE a permitted
    // pattern. `docs.*` intersects `docs.files.read` in both directions, so
    // an intersection test would admit a proposal strictly broader than the
    // ceiling — the exact thing the ceiling exists to refuse.
    const covered = allowed.some((permitted) =>
      patternContains(permitted, pattern),
    );
    if (!covered) {
      throw new ProviderWriteRejectedError(
        `pattern ${JSON.stringify(pattern)} is outside what this scope type makes requestable ` +
          `(${allowed.map((p) => JSON.stringify(p)).join(", ")})`,
        "validation",
      );
    }
  }

  async submitRequest(input: RequestInput<P, S>): Promise<AccessRequest> {
    const scope = input.scope ?? GLOBAL_SCOPE;
    if (isGlobalScope(scope)) {
      // Requests are homed where their proposed row would live.
      this.requireOrgRoot("a global-scope access request");
    }
    if ((input.roleId === undefined) === (input.pattern === undefined)) {
      throw new ProviderWriteRejectedError(
        "a request proposes exactly one of roleId / pattern",
        "validation",
      );
    }
    if (input.pattern !== undefined) {
      const issue = validatePattern(input.pattern);
      if (issue) throw new ProviderWriteRejectedError(issue.reason, "validation");
      if (!this.catalog.isKnownPattern(input.pattern)) {
        throw this.unknownPattern(input.pattern);
      }
      if (!isGlobalScope(scope)) {
        const grantable = this.catalog.validateGrantableAt(input.pattern, scope);
        if (grantable) {
          throw new ProviderWriteRejectedError(grantable.message, "validation");
        }
      }
    }
    const requestability = await this.requestability(input);
    if (input.pattern !== undefined) {
      this.assertRequestablePattern(input.pattern, requestability.patterns);
    }
    await this.assertPolicyResolvable(requestability.stages);
    const problems = validateJustification(
      requestability.prompts,
      input.justification ?? {},
    );
    if (problems.length > 0) {
      throw new ProviderWriteRejectedError(problems.join("; "), "validation");
    }
    const now = this.now();
    let proposedExpiresAt = input.proposedExpiresAt;
    if (proposedExpiresAt !== undefined && proposedExpiresAt <= now) {
      throw new ProviderWriteRejectedError(
        "proposed expiry is already in the past",
        "validation",
      );
    }
    if (requestability.requireExpiry && proposedExpiresAt === undefined) {
      throw new ProviderWriteRejectedError(
        "this access must be time-bound: propose an expiry",
        "validation",
      );
    }
    if (requestability.maxDurationMs !== undefined) {
      if (proposedExpiresAt === undefined) {
        // A maximum-duration policy caps open-ended requests too: omitting
        // the expiry must not evade the cap, so the cap becomes the expiry.
        proposedExpiresAt = now + requestability.maxDurationMs;
      } else if (proposedExpiresAt - now > requestability.maxDurationMs) {
        throw new ProviderWriteRejectedError(
          `proposed duration exceeds the maximum (${requestability.maxDurationMs} ms)`,
          "validation",
        );
      }
    }
    let request: AccessRequest = {
      id: this.newId(),
      requesterUserId: input.requesterUserId,
      roleId: input.roleId,
      pattern: input.pattern,
      scope,
      proposedExpiresAt,
      justification: input.justification ?? {},
      state: "pending",
      stageIndex: 0,
      stages: requestability.stages,
      decisions: [],
      createdAt: now,
    };
    const requester = await this.contextFor({ userId: input.requesterUserId });
    // Every open region, not a pattern-filtered slice: the stages carry their
    // own patterns and `checkAny` intersects per pattern anyway.
    const result = runAutoStages(
      request,
      requester.ctx,
      now,
      this.catalog.keys,
      [...this.catalog.openRegions.values()],
    );
    request = result.request;
    await this.storage.insertRequest(request);
    await this.audit(
      // Attributed to the requester, not to "system". `actorOf` maps a
      // `system` provenance to the literal actor `"system"` and drops the
      // note, so `listAuditEvents({ actor: userId })` returned nothing for
      // the one action in the request lifecycle a person actually initiated
      // — approve, deny, and cancel all name someone.
      { kind: "admin", actorUserId: input.requesterUserId },
      "request.submit",
      request.id,
      {
        roleId: input.roleId,
        pattern: input.pattern,
        scope,
        requesterUserId: input.requesterUserId,
      },
    );
    if (result.grantPlan) {
      await this.writeGrantFromPlan(result.grantPlan);
    }
    return request;
  }

  private async writeGrantFromPlan(
    plan: Omit<GrantRow, "id">,
  ): Promise<GrantRow> {
    const row: GrantRow = { ...plan, id: this.newId() };
    await this.storage.insertGrant(row);
    await this.audit(row.provenance, "grant.create", row.id, {
      subject: row.subject,
      roleId: row.roleId,
      pattern: row.pattern,
      scope: row.scope,
      expiresAt: row.expiresAt,
    });
    this.emitSubject(row.subject);
    await this.flushEvents();
    return row;
  }

  private async canDecide(
    request: AccessRequest,
    deciderUserId: string,
  ): Promise<boolean> {
    // Maker is never checker. A request is an escalation the requester is
    // asking someone else to vouch for, so approving your own defeats the
    // whole mechanism — and both routes into this method were open to it:
    // a requester who happens to hold the named approver role, and one
    // holding the administrative override, which exists for stages nobody
    // can fill, not for self-service. The override is deliberately included:
    // an approver pool of one is a directory problem, and answering it by
    // approving yourself is exactly what an access review will flag.
    if (deciderUserId === request.requesterUserId) return false;
    const stage = request.stages[request.stageIndex];
    const decider = await this.contextFor({ userId: deciderUserId });
    if (!decider.data.active) return false;
    const requesterChain = await this.managerChain(request.requesterUserId);
    if (
      stage &&
      canDecideStage(
        stage,
        { userId: deciderUserId, ctx: decider.ctx },
        requesterChain,
      )
    ) {
      return true;
    }
    // Administrative override: holders of the Alfiz approvals permission may
    // decide any stage — the escape hatch for stages nobody can fill.
    return checkKey(
      decider.ctx,
      `${ALFIZ_INTERNAL_NAMESPACE}.requests.decide_request`,
      [GLOBAL_SCOPE],
    );
  }

  async decideRequest(
    requestId: string,
    decision: {
      deciderUserId: string;
      decision: "approved" | "denied";
      note?: string | undefined;
    },
  ): Promise<AccessRequest> {
    // Decisions are serialized per request: two concurrent deciders must not
    // both apply (a denial overwritten by an approval, duplicate grants).
    return this.storage.runExclusive(`request:${requestId}`, async () => {
      const request = await this.storage.getRequest(requestId);
      if (!request) {
        throw new ProviderWriteRejectedError("request not found", "not_found");
      }
      if (request.state !== "pending") {
        throw new ProviderWriteRejectedError(
          `request is ${request.state}`,
          "conflict",
        );
      }
      // Requests are homed where their proposed row would live: deciding a
      // global-scope request is an org-domain write.
      if (isGlobalScope(request.scope)) {
        this.requireOrgRoot("deciding a global-scope access request");
      }
      if (!(await this.canDecide(request, decision.deciderUserId))) {
        throw new ProviderWriteRejectedError(
          "not an approver for the current stage",
          "validation",
        );
      }
      const now = this.now();
      let result = applyDecision(request, {
        decidedBy: decision.deciderUserId,
        decision: decision.decision,
        at: now,
        note: decision.note,
      });
      if (result.request.state === "pending") {
        // A human approval may unlock consecutive auto stages.
        const requester = await this.contextFor({
          userId: request.requesterUserId,
        });
        const advanced = runAutoStages(
          result.request,
          requester.ctx,
          now,
          this.catalog.keys,
          [...this.catalog.openRegions.values()],
        );
        result = {
          request: advanced.request,
          grantPlan: advanced.grantPlan ?? result.grantPlan,
        };
      }
      if (
        result.grantPlan?.roleId !== undefined &&
        (await this.storage.getRole(result.grantPlan.roleId)) === null
      ) {
        // The role was deleted while the request was pending: approving now
        // would write a dangling-role grant that confers nothing.
        throw new ProviderWriteRejectedError(
          "the requested role no longer exists",
          "conflict",
        );
      }
      await this.storage.updateRequest(result.request);
      await this.audit(
        { kind: "admin", actorUserId: decision.deciderUserId },
        `request.${decision.decision}`,
        requestId,
        { note: decision.note },
      );
      if (result.grantPlan) {
        await this.writeGrantFromPlan(result.grantPlan);
      }
      return result.request;
    });
  }

  async cancelRequest(
    requestId: string,
    byUserId: string,
  ): Promise<AccessRequest> {
    return this.storage.runExclusive(`request:${requestId}`, async () => {
      const request = await this.storage.getRequest(requestId);
      if (!request) {
        throw new ProviderWriteRejectedError("request not found", "not_found");
      }
      if (request.requesterUserId !== byUserId) {
        throw new ProviderWriteRejectedError(
          "only the requester may cancel",
          "validation",
        );
      }
      if (request.state !== "pending") {
        throw new ProviderWriteRejectedError(
          `request is ${request.state}`,
          "conflict",
        );
      }
      const cancelled: AccessRequest = {
        ...request,
        state: "cancelled",
        decidedAt: this.now(),
      };
      await this.storage.updateRequest(cancelled);
      await this.audit(
        { kind: "admin", actorUserId: byUserId },
        "request.cancel",
        requestId,
      );
      return cancelled;
    });
  }

  async listRequests(filter?: RequestFilter): Promise<AccessRequest[]> {
    return this.storage.listRequests(filter);
  }

  async listApproverQueue(approverUserId: string): Promise<AccessRequest[]> {
    const pending = await this.storage.listRequests({ state: "pending" });
    const queue: AccessRequest[] = [];
    for (const request of pending) {
      if (await this.canDecide(request, approverUserId)) queue.push(request);
    }
    return queue;
  }

  // -- catalog registration -------------------------------------------------

  async publishCatalog(
    document: CatalogDocument,
    provenance: Provenance,
  ): Promise<{ version: number }> {
    this.assertProvenance(provenance);
    if (document.formatVersion !== 1) {
      throw new ProviderWriteRejectedError(
        `unknown catalog format ${String(document.formatVersion)}`,
        "validation",
      );
    }
    // Namespace ownership, enforced locally as well as at the registry: a
    // publish carries what this application OWNS. `Catalog.toDocument()`
    // already filters imported leaves out, so a document arriving here with
    // foreign keys was hand-assembled, and shadowing another application's
    // namespace is the one thing a publish must never be able to do.
    const published = new Set(document.namespaces);
    for (const leaf of document.leaves) {
      const ns = namespaceOf(leaf.key);
      if (ns !== null && !published.has(ns)) {
        throw new ProviderWriteRejectedError(
          `catalog document publishes ${JSON.stringify(leaf.key)}, which is outside its own namespaces ` +
            `[${document.namespaces.join(", ")}] — an application never defines keys in a namespace it does not own`,
          "validation",
        );
      }
    }
    const current = await this.storage.getCatalog();
    const version = (current?.version ?? 0) + 1;
    await this.storage.putCatalog(version, document, this.now());
    await this.audit(provenance, "catalog.publish", document.namespace, {
      version,
    });
    this.emit({ type: "catalog" });
    await this.flushEvents();
    return { version };
  }

  async getPublishedCatalog() {
    return this.storage.getCatalog();
  }

  /** Published versions with their publish instants, oldest first. */
  async listCatalogVersions(): Promise<
    Array<{ version: number; publishedAt: number }>
  > {
    if (!this.storage.listCatalogVersions) {
      throw new ProviderWriteRejectedError(
        "this storage driver retains no catalog history (implement listCatalogVersions/getCatalogVersion)",
        "unsupported",
      );
    }
    return this.storage.listCatalogVersions();
  }

  /**
   * The wildcard-drift report: which keys the catalog gained since a
   * published version, and which live wildcard grants and assigned roles
   * silently absorbed them (forward inclusion working exactly as
   * documented — this report is what makes it reviewable). An access
   * review that certified version N runs this against N before signing the
   * next cycle; a finding means a grant now confers more than what was
   * certified.
   */
  async listWildcardDrift(input: { sinceVersion: number }): Promise<
    import("@alfiz/core").WildcardDriftReport & {
      fromVersion: number;
      toVersion: number;
    }
  > {
    if (!this.storage.getCatalogVersion) {
      throw new ProviderWriteRejectedError(
        "this storage driver retains no catalog history (implement listCatalogVersions/getCatalogVersion)",
        "unsupported",
      );
    }
    const from = await this.storage.getCatalogVersion(input.sinceVersion);
    if (!from) {
      throw new ProviderWriteRejectedError(
        `catalog version ${input.sinceVersion} is not retained`,
        "not_found",
      );
    }
    const head = await this.storage.getCatalog();
    if (!head) {
      throw new ProviderWriteRejectedError(
        "no catalog has been published",
        "not_found",
      );
    }
    const report = wildcardDrift({
      from: from.document,
      to: head.document,
      grants: await this.storage.listGrants(),
      roles: await this.storage.listRoles(),
      now: this.now(),
    });
    return {
      ...report,
      fromVersion: from.version,
      toVersion: head.version,
    };
  }

  /**
   * Registers what this application CONSUMES. Separate from the catalog
   * publish on purpose — see `AlfizProvider.publishImports`. Emits no
   * invalidation: a manifest changes nothing any client evaluates, it only
   * tells the provider what to warn about.
   */
  override async publishImports(
    manifest: ImportManifest,
    provenance: Provenance,
  ): Promise<{ version: number }> {
    this.assertProvenance(provenance);
    const put = this.storage.putImports;
    const get = this.storage.getImports;
    if (put === undefined || get === undefined) {
      throw new ProviderWriteRejectedError(
        "this storage driver does not store import manifests (capabilities().imports is false)",
        "unsupported",
      );
    }
    if (manifest.formatVersion !== 1) {
      throw new ProviderWriteRejectedError(
        `unknown import manifest format ${String(manifest.formatVersion)}`,
        "validation",
      );
    }
    for (const entry of manifest.imports) {
      if (entry.namespace === manifest.namespace) {
        throw new ProviderWriteRejectedError(
          `manifest declares an import of ${JSON.stringify(entry.namespace)}, which is the publishing application's own namespace`,
          "validation",
        );
      }
    }
    const current = await get.call(this.storage);
    const version = (current?.version ?? 0) + 1;
    await put.call(this.storage, version, manifest);
    await this.audit(provenance, "imports.publish", manifest.namespace, {
      version,
      namespaces: manifest.imports.map((i) => i.namespace),
    });
    return { version };
  }

  override async getPublishedImports() {
    return this.storage.getImports?.call(this.storage) ?? null;
  }

  // -- organizational data --------------------------------------------------

  async listRoles(): Promise<RoleRecord[]> {
    return this.storage.listRoles();
  }

  private validateRolePatterns(patterns: readonly string[]): void {
    for (const pattern of patterns) {
      const issue = validatePattern(pattern);
      if (issue) throw new ProviderWriteRejectedError(issue.reason, "validation");
      if (!this.catalog.isKnownPattern(pattern)) {
        throw this.unknownPattern(pattern);
      }
    }
  }

  /** A caller-supplied id must be usable and free — never an overwrite. */
  private validateSuppliedId(id: string): void {
    if (id === "") {
      throw new ProviderWriteRejectedError(
        "a caller-supplied id must be a non-empty string",
        "validation",
      );
    }
  }

  async createRole(
    input: RoleInput<P>,
    provenance: Provenance,
  ): Promise<RoleRecord> {
    this.assertProvenance(provenance);
    this.requireOrgRoot("a role definition");
    this.validateRolePatterns(input.patterns);
    if (input.requestable) {
      await this.assertPolicyResolvable(input.requestable.stages);
    }
    if (input.id !== undefined) {
      this.validateSuppliedId(input.id);
      if ((await this.storage.getRole(input.id)) !== null) {
        throw new ProviderWriteRejectedError(
          `role id ${JSON.stringify(input.id)} already exists`,
          "conflict",
        );
      }
    }
    const role: RoleRecord = {
      id: input.id ?? this.newId(),
      name: input.name,
      description: input.description,
      patterns: [...input.patterns],
      requestable: input.requestable,
    };
    await this.storage.upsertRole(role);
    await this.audit(provenance, "role.create", role.id, { name: role.name });
    this.emit({ type: "role", roleId: role.id });
    await this.flushEvents();
    return role;
  }

  async updateRole(
    roleId: string,
    input: Partial<RoleInput<P>>,
    provenance: Provenance,
  ): Promise<RoleRecord> {
    this.assertProvenance(provenance);
    this.requireOrgRoot("a role definition");
    const existing = await this.storage.getRole(roleId);
    if (!existing) {
      throw new ProviderWriteRejectedError("role not found", "not_found");
    }
    if (input.patterns) this.validateRolePatterns(input.patterns);
    if (input.requestable) {
      await this.assertPolicyResolvable(input.requestable.stages);
    }
    // A role's PATTERNS are frozen while a request references it. `deleteRole`
    // already refuses here; rewriting the patterns is the same TOCTOU with a
    // worse outcome, because the request survives it: the approver reviews
    // "Reader" and the requester receives whatever the role says at approval
    // time. Renaming or re-describing stays allowed — neither changes what
    // approving the request would confer.
    if (input.patterns !== undefined) {
      const changed =
        input.patterns.length !== existing.patterns.length ||
        input.patterns.some((p, i) => p !== existing.patterns[i]);
      if (changed) {
        const pending = (
          await this.storage.listRequests({ state: "pending" })
        ).filter((r) => r.roleId === roleId);
        if (pending.length > 0) {
          throw new ProviderWriteRejectedError(
            `role is referenced by ${pending.length} pending request(s); its patterns are frozen ` +
              "until they are decided or cancelled — otherwise an approver reviews one thing and grants another",
            "conflict",
          );
        }
      }
    }
    const updated: RoleRecord = {
      ...existing,
      ...(input.name !== undefined ? { name: input.name } : {}),
      ...(input.description !== undefined
        ? { description: input.description }
        : {}),
      ...(input.patterns !== undefined ? { patterns: [...input.patterns] } : {}),
      ...(input.requestable !== undefined
        ? { requestable: input.requestable }
        : {}),
    };
    await this.storage.upsertRole(updated);
    await this.audit(provenance, "role.update", roleId, { name: updated.name });
    this.emit({ type: "role", roleId });
    await this.flushEvents();
    return updated;
  }

  async deleteRole(roleId: string, provenance: Provenance): Promise<void> {
    this.assertProvenance(provenance);
    this.requireOrgRoot("a role definition");
    const holders = await this.storage.countGrants({ roleId });
    if (holders > 0) {
      throw new ProviderWriteRejectedError(
        `role is assigned by ${holders} grant(s); remove them first`,
        "conflict",
      );
    }
    const pending = (await this.storage.listRequests({ state: "pending" })).filter(
      (r) =>
        r.roleId === roleId ||
        r.stages.some((s) => s.kind === "named_approvers" && s.roleId === roleId),
    );
    if (pending.length > 0) {
      throw new ProviderWriteRejectedError(
        `role is referenced by ${pending.length} pending request(s); decide or cancel them first`,
        "conflict",
      );
    }
    await this.storage.deleteRole(roleId);
    await this.audit(provenance, "role.delete", roleId);
    this.emit({ type: "role", roleId });
    await this.flushEvents();
  }

  async listGroups(): Promise<UserGroup[]> {
    return this.storage.listGroups();
  }

  async createGroup(
    input: {
      id?: string | undefined;
      name: string;
      description?: string | undefined;
      parents?: string[] | undefined;
    },
    provenance: Provenance,
  ): Promise<UserGroup> {
    this.assertProvenance(provenance);
    this.requireOrgRoot("a user group");
    return this.storage.runExclusive("groups", async () => {
      if (input.id !== undefined) {
        this.validateSuppliedId(input.id);
        if ((await this.storage.getGroup(input.id)) !== null) {
          throw new ProviderWriteRejectedError(
            `group id ${JSON.stringify(input.id)} already exists`,
            "conflict",
          );
        }
      }
      for (const parent of input.parents ?? []) {
        if ((await this.storage.getGroup(parent)) === null) {
          throw new ProviderWriteRejectedError(
            `parent group ${JSON.stringify(parent)} does not exist`,
            "not_found",
          );
        }
      }
      const group: UserGroup = {
        id: input.id ?? this.newId(),
        name: input.name,
        description: input.description,
        parents: [...(input.parents ?? [])],
      };
      await this.storage.upsertGroup(group);
      await this.audit(provenance, "group.create", group.id, {
        name: group.name,
      });
      this.emitSubject(`group:${group.id}`);
      await this.flushEvents();
      return group;
    });
  }

  async updateGroup(
    groupId: string,
    input: { name?: string | undefined; description?: string | undefined },
    provenance: Provenance,
  ): Promise<UserGroup> {
    this.assertProvenance(provenance);
    this.requireOrgRoot("a user group");
    // Serialized with the graph writes: upsertGroup stores the full record,
    // so an unserialized rename could clobber a concurrent parent edit.
    return this.storage.runExclusive("groups", async () => {
      const group = await this.storage.getGroup(groupId);
      if (!group) {
        throw new ProviderWriteRejectedError("group not found", "not_found");
      }
      const updated: UserGroup = {
        ...group,
        ...(input.name !== undefined ? { name: input.name } : {}),
        ...(input.description !== undefined
          ? { description: input.description }
          : {}),
      };
      await this.storage.upsertGroup(updated);
      await this.audit(provenance, "group.update", groupId, {
        name: updated.name,
      });
      // No invalidation event: identity is the id — names and descriptions
      // never enter evaluation, so renaming busts nothing.
      return updated;
    });
  }

  async setGroupParents(
    groupId: string,
    parents: string[],
    provenance: Provenance,
  ): Promise<UserGroup> {
    this.assertProvenance(provenance);
    this.requireOrgRoot("group parentage");
    return this.storage.runExclusive("groups", async () => {
      const group = await this.storage.getGroup(groupId);
      if (!group) {
        throw new ProviderWriteRejectedError("group not found", "not_found");
      }
      for (const parent of parents) {
        if ((await this.storage.getGroup(parent)) === null) {
          throw new ProviderWriteRejectedError(
            `parent group ${JSON.stringify(parent)} does not exist`,
            "not_found",
          );
        }
      }
      const all = await this.storage.listGroups();
      const candidate = new Map<string, readonly string[]>(
        all.map((g) => [g.id, g.id === groupId ? parents : g.parents]),
      );
      const cycle = findCycle(candidate);
      if (cycle) {
        throw new ProviderWriteRejectedError(
          `cycle: ${cycle.join(" → ")}`,
          "graph_cycle",
        );
      }
      const updated: UserGroup = { ...group, parents: [...parents] };
      await this.storage.upsertGroup(updated);
      await this.audit(provenance, "group.set_parents", groupId, { parents });
      this.emitSubject(`group:${groupId}`);
      await this.flushEvents();
      return updated;
    });
  }

  async deleteGroup(groupId: string, provenance: Provenance): Promise<void> {
    this.assertProvenance(provenance);
    this.requireOrgRoot("a user group");
    await this.storage.runExclusive("groups", async () => {
      const group = await this.storage.getGroup(groupId);
      if (!group) {
        throw new ProviderWriteRejectedError("group not found", "not_found");
      }
      // Referential integrity, symmetrically: membership, parent references,
      // and subject rows all follow the group out.
      const members = await this.storage.listUsersInGroup(groupId);
      for (const userId of members) {
        const user = await this.storage.getUser(userId);
        if (user) {
          await this.storage.upsertUser({
            ...user,
            groupIds: user.groupIds.filter((g) => g !== groupId),
          });
        }
      }
      for (const other of await this.storage.listGroups()) {
        if (other.id !== groupId && other.parents.includes(groupId)) {
          await this.storage.upsertGroup({
            ...other,
            parents: other.parents.filter((p) => p !== groupId),
          });
          this.emitSubject(`group:${other.id}`);
        }
      }
      const subject: SubjectId = `group:${groupId}`;
      for (const grant of await this.storage.listGrants({ subject })) {
        await this.storage.deleteGrant(grant.id);
        await this.audit(provenance, "grant.delete", grant.id, {
          reason: "group deleted",
        });
      }
      await this.storage.deleteGroup(groupId);
      await this.audit(provenance, "group.delete", groupId, {
        name: group.name,
        members: members.length,
      });
      this.emitSubject(subject);
      for (const userId of members) this.emit({ type: "user", userId });
      await this.flushEvents();
    });
  }

  async setGroupMembership(
    userId: string,
    groupIds: string[],
    provenance: Provenance,
  ): Promise<void> {
    this.assertProvenance(provenance);
    this.requireOrgRoot("group membership");
    for (const groupId of groupIds) {
      if ((await this.storage.getGroup(groupId)) === null) {
        throw new ProviderWriteRejectedError(
          `group ${JSON.stringify(groupId)} does not exist`,
          "not_found",
        );
      }
    }
    const user = (await this.storage.getUser(userId)) ?? {
      userId,
      active: true,
      groupIds: [],
      orgIds: [],
      managerUserId: null,
    };
    await this.storage.upsertUser({ ...user, groupIds: [...new Set(groupIds)] });
    await this.audit(provenance, "user.set_groups", userId, { groupIds });
    this.emit({ type: "user", userId });
    await this.flushEvents();
  }

  async getGroupMembers(groupId: string): Promise<string[]> {
    return this.storage.listUsersInGroup(groupId);
  }

  /**
   * The offboarding switch: an inactive principal evaluates to NO access —
   * every check shape, every scope — from the next closure supply
   * (immediately, via the emitted invalidation; bounded by the subject TTL
   * otherwise). Creates the record when absent, because deactivating a
   * principal Alfiz never stored must still stick: absence means "member of
   * `everyone`", not "gone". Reversible, unlike `deleteSubject` —
   * deactivate on offboarding, delete when the id itself is being retired.
   */
  async setUserActive(
    userId: string,
    active: boolean,
    provenance: Provenance,
  ): Promise<void> {
    this.assertProvenance(provenance);
    this.requireOrgRoot("user provisioning");
    const user = (await this.storage.getUser(userId)) ?? {
      userId,
      active: true,
      groupIds: [],
      orgIds: [],
      managerUserId: null,
    };
    await this.storage.upsertUser({ ...user, active });
    await this.audit(provenance, "user.set_active", userId, { active });
    this.emit({ type: "user", userId });
    await this.flushEvents();
  }

  async setReportingEdge(
    userId: string,
    managerUserId: string | null,
    provenance: Provenance,
  ): Promise<void> {
    this.assertProvenance(provenance);
    this.requireOrgRoot("a reporting edge");
    await this.storage.runExclusive("reporting", async () => {
      const user = (await this.storage.getUser(userId)) ?? {
        userId,
        active: true,
        groupIds: [],
        orgIds: [],
        managerUserId: null,
      };
      const oldChain = await this.managerChain(userId);
      if (managerUserId !== null) {
        if (managerUserId === userId) {
          throw new ProviderWriteRejectedError(
            `cycle: ${userId} → ${userId}`,
            "graph_cycle",
          );
        }
        // Walking up from the proposed manager must not reach the user.
        const path: string[] = [managerUserId];
        let current = (await this.storage.getUser(managerUserId))
          ?.managerUserId;
        const seen = new Set<string>([managerUserId]);
        while (current != null && !seen.has(current)) {
          path.push(current);
          if (current === userId) {
            throw new ProviderWriteRejectedError(
              `cycle: ${[userId, ...path].join(" → ")}`,
              "graph_cycle",
            );
          }
          seen.add(current);
          current = (await this.storage.getUser(current))?.managerUserId;
        }
        if (path.includes(userId)) {
          throw new ProviderWriteRejectedError(
            `cycle: ${[userId, ...path].join(" → ")}`,
            "graph_cycle",
          );
        }
        // A manager referenced by an edge is a principal: ensure the record
        // exists so chains walk through them and they can approve.
        if ((await this.storage.getUser(managerUserId)) === null) {
          await this.storage.upsertUser({
            userId: managerUserId,
            active: true,
            groupIds: [],
            orgIds: [],
            managerUserId: null,
          });
        }
      }
      await this.storage.upsertUser({ ...user, managerUserId });
      await this.audit(provenance, "user.set_manager", userId, {
        managerUserId,
      });
      const newChain = await this.managerChain(userId);
      this.emit({ type: "user", userId });
      // The edited user's own implicit groups too: their reports' closures
      // contain orgof:<userId>, and those closures just gained or lost the
      // new ancestors above them.
      for (const m of new Set([userId, ...oldChain, ...newChain])) {
        this.emit({ type: "subject", subject: `directs:${m}` });
        this.emit({ type: "subject", subject: `orgof:${m}` });
      }
      await this.flushEvents();
    });
  }

  async getReportingEdges(): Promise<Map<string, string>> {
    const edges = new Map<string, string>();
    for (const user of await this.storage.listUsers()) {
      if (user.managerUserId !== null) {
        edges.set(user.userId, user.managerUserId);
      }
    }
    return edges;
  }

  async dissolveVirtualParent(
    groupId: string,
    provenance: Provenance,
  ): Promise<void> {
    this.assertProvenance(provenance);
    this.requireOrgRoot("a virtual parent");
    await this.storage.runExclusive("groups", async () => {
      const parent = await this.storage.getGroup(groupId);
      if (!parent) {
        throw new ProviderWriteRejectedError("group not found", "not_found");
      }
      const all = await this.storage.listGroups();
      const children = all.filter((g) => g.parents.includes(groupId));
      const parentSubject: SubjectId = `group:${groupId}`;
      const now = this.now();
      const parentGrants = await this.storage.listGrants({
        subject: parentSubject,
      });
      const copies = planVirtualParentDissolution({
        parentSubject,
        childSubjects: children.map((c) => `group:${c.id}`),
        grants: parentGrants,
        virtualParentId: groupId,
        now,
      });
      for (const copy of copies) {
        const row: GrantRow = { ...copy, id: this.newId() };
        await this.storage.insertGrant(row);
        await this.audit(row.provenance, "grant.create", row.id, {
          subject: row.subject,
          copiedFrom: groupId,
        });
      }
      for (const grant of parentGrants) {
        await this.storage.deleteGrant(grant.id);
        await this.audit(provenance, "grant.delete", grant.id, {
          reason: "virtual parent dissolved",
          copiedTo: children.map((c) => `group:${c.id}`),
        });
      }
      // Children keep inheriting the parent's own parents, then drift freely.
      for (const child of children) {
        await this.storage.upsertGroup({
          ...child,
          parents: [
            ...new Set([
              ...child.parents.filter((p) => p !== groupId),
              ...parent.parents,
            ]),
          ],
        });
        this.emitSubject(`group:${child.id}`);
      }
      // Direct members (rare for virtual parents, possible after imports)
      // must not keep a dangling membership.
      const members = await this.storage.listUsersInGroup(groupId);
      for (const userId of members) {
        const user = await this.storage.getUser(userId);
        if (user) {
          await this.storage.upsertUser({
            ...user,
            groupIds: user.groupIds.filter((g) => g !== groupId),
          });
          this.emit({ type: "user", userId });
        }
      }
      await this.storage.deleteGroup(groupId);
      await this.audit(provenance, "group.dissolve_virtual_parent", groupId, {
        children: children.map((c) => c.id),
        copiedGrants: copies.length,
      });
      this.emitSubject(parentSubject);
      await this.flushEvents();
    });
  }

  // -- audit ----------------------------------------------------------------

  async listAuditEvents(filter?: AuditQuery): Promise<AuditEvent[]> {
    return this.storage.listAudit(filter);
  }

  // -- metrics ---------------------------------------------------------------
  // Aggregated windows in, rolling usage out. Everything here sits off the
  // request path by construction: the client aggregates in memory and hands
  // over batches on its own schedule, and nothing in a check, a render, or a
  // row write ever waits on this store.

  private requireMetrics(): void {
    if (!this.metricsEnabled) {
      throw new ProviderWriteRejectedError(
        "metrics are not enabled on this Application (pass `metrics: {}` to createAlfizApplication)",
        "unsupported",
      );
    }
  }

  /** Floors an instant to its bucket start — daily by default. */
  private bucketOf(at: number): number {
    return Math.floor(at / this.metricsBucketMs) * this.metricsBucketMs;
  }

  /**
   * Ingest one aggregated window. Counters accumulate, so batches from many
   * app servers — each with its own client and its own instance id — sum
   * into the same buckets, which is what makes the numbers deployment-wide.
   *
   * Nothing is validated against the catalog here: a metrics row is a
   * counter, not access data, and rejecting a batch because one permission
   * key was tombstoned mid-deploy would lose the whole window.
   */
  override async reportMetrics(batch: MetricsBatch): Promise<void> {
    this.requireMetrics();
    const bucket = this.bucketOf(batch.windowStart);
    // Merged before writing: two check counters differing only by shape fold
    // into one gate-allow increment, so the batch costs as few statements as
    // its distinct buckets, not as many as its counters.
    const deltas = new Map<string, MetricBucketDelta>();
    const add = (
      dimension: MetricDimension,
      subject: string,
      metric: string,
      count: number,
    ): void => {
      if (count <= 0) return;
      const key = `${dimension}|${subject}|${metric}`;
      const existing = deltas.get(key);
      if (existing) existing.count += count;
      else deltas.set(key, { bucket, dimension, subject, metric, count });
    };

    for (const row of batch.grants) {
      add("grant", row.rowId, METRIC_MATCHED, row.estimatedMatched);
      add("grant", row.rowId, METRIC_SOLE_MATCH, row.estimatedSoleMatch);
    }
    for (const row of batch.revokes) {
      add("revoke", row.rowId, METRIC_MATCHED, row.estimatedMatched);
      add("revoke", row.rowId, METRIC_SOLE_MATCH, row.estimatedSoleMatch);
    }
    for (const row of batch.roles) {
      add("role", row.rowId, METRIC_MATCHED, row.estimatedMatched);
      add("role", row.rowId, METRIC_SOLE_MATCH, row.estimatedSoleMatch);
    }
    for (const counter of batch.checks) {
      const metric = counter.gate
        ? counter.decision === "allow"
          ? METRIC_GATE_ALLOW
          : METRIC_GATE_DENY
        : counter.decision === "allow"
          ? METRIC_VISIBILITY_ALLOW
          : METRIC_VISIBILITY_DENY;
      add("permission", counter.permission, metric, counter.estimated);
      // Two flat rollups rather than their cross product: bounded by
      // catalog size and by scope-type count, and enough for every question
      // the shipped surfaces ask.
      add("scopeType", counter.scopeType, metric, counter.estimated);
    }
    if (deltas.size === 0) return;
    await this.storage.recordMetrics!([...deltas.values()]);

    // Retention compaction, opportunistic and unawaited — a failed prune
    // costs disk, not correctness. Same posture as event-log pruning.
    if (++this.reportsSinceMetricPrune >= 32) {
      this.reportsSinceMetricPrune = 0;
      void this.storage
        .pruneMetrics!(this.bucketOf(this.now() - this.metricsRetentionMs))
        .catch(() => undefined);
    }
  }

  /** Bucket reads shared by every usage method. */
  private async usageBuckets(
    dimension: MetricDimension,
    query: UsageQuery | undefined,
  ): Promise<{
    rows: MetricBucket[];
    windowStart: number;
    windowEnd: number;
  }> {
    this.requireMetrics();
    const until = query?.until ?? this.now();
    const since = query?.since ?? until - this.metricsRetentionMs;
    const rows = await this.storage.readMetrics!({
      dimension,
      ...(query?.ids === undefined ? {} : { subjects: query.ids }),
      since: this.bucketOf(since),
      until,
    });
    return { rows, windowStart: since, windowEnd: until };
  }

  private async rowUsage(
    dimension: MetricDimension,
    query: UsageQuery | undefined,
  ): Promise<RowUsage[]> {
    const { rows, windowStart, windowEnd } = await this.usageBuckets(
      dimension,
      query,
    );
    const bySubject = new Map<string, RowUsage>();
    for (const row of rows) {
      let usage = bySubject.get(row.subject);
      if (usage === undefined) {
        usage = {
          rowId: row.subject,
          matched: 0,
          soleMatch: 0,
          windowStart,
          windowEnd,
          buckets: [],
        };
        bySubject.set(row.subject, usage);
      }
      let bucket = usage.buckets.find((b) => b.bucket === row.bucket);
      if (bucket === undefined) {
        bucket = { bucket: row.bucket, matched: 0, soleMatch: 0 };
        usage.buckets.push(bucket);
      }
      if (row.metric === METRIC_MATCHED) {
        usage.matched += row.count;
        bucket.matched += row.count;
      } else if (row.metric === METRIC_SOLE_MATCH) {
        usage.soleMatch += row.count;
        bucket.soleMatch += row.count;
      }
    }
    for (const usage of bySubject.values()) {
      usage.buckets.sort((a, b) => a.bucket - b.bucket);
    }
    return [...bySubject.values()];
  }

  /**
   * Per-grant usage. `soleMatch` is the counterfactual one — the checks this
   * row was the ONLY thing allowing, which is exactly the number that would
   * have flipped to deny had it not existed. Feed it to
   * `revocationSafeguard` for the warning copy.
   */
  override async getGrantUsage(query?: UsageQuery): Promise<RowUsage[]> {
    return this.rowUsage("grant", query);
  }

  /** Per-revoke usage: checks each revoke suppressed. Deleting one widens access. */
  override async getRevokeUsage(query?: UsageQuery): Promise<RowUsage[]> {
    return this.rowUsage("revoke", query);
  }

  /** Per-role usage, for role-edit and role-delete safeguards. */
  override async getRoleUsage(query?: UsageQuery): Promise<RowUsage[]> {
    return this.rowUsage("role", query);
  }

  /**
   * Per-permission counts — the per-action metric. Gate and visibility
   * traffic are reported separately and never summed: a project that renders
   * a nav item on every page would otherwise drown out every action in the
   * catalog.
   */
  override async getPermissionUsage(query?: UsageQuery): Promise<PermissionUsage[]> {
    return this.keyedUsage("permission", query);
  }

  /**
   * Per-scope-type counts — the same rollup keyed by scope type. "Which
   * parts of the hierarchy are actually checked" is a capacity question,
   * not an access one, and it is the reading that tells you whether a scope
   * type earns its complexity.
   */
  override async getScopeTypeUsage(query?: UsageQuery): Promise<PermissionUsage[]> {
    return this.keyedUsage("scopeType", query);
  }

  private async keyedUsage(
    dimension: MetricDimension,
    query: UsageQuery | undefined,
  ): Promise<PermissionUsage[]> {
    const { rows, windowStart, windowEnd } = await this.usageBuckets(
      dimension,
      query,
    );
    const byKey = new Map<string, PermissionUsage>();
    for (const row of rows) {
      let usage = byKey.get(row.subject);
      if (usage === undefined) {
        usage = {
          permission: row.subject,
          gateAllow: 0,
          gateDeny: 0,
          visibilityAllow: 0,
          visibilityDeny: 0,
          windowStart,
          windowEnd,
          buckets: [],
        };
        byKey.set(row.subject, usage);
      }
      // The stored granularity is already the series resolution — the totals
      // below are just this list summed, so returning both costs one pass and
      // saves every caller a second round trip to draw usage over time.
      let bucket = usage.buckets.find((b) => b.bucket === row.bucket);
      if (bucket === undefined) {
        bucket = {
          bucket: row.bucket,
          gateAllow: 0,
          gateDeny: 0,
          visibilityAllow: 0,
          visibilityDeny: 0,
        };
        usage.buckets.push(bucket);
      }
      switch (row.metric) {
        case METRIC_GATE_ALLOW:
          usage.gateAllow += row.count;
          bucket.gateAllow += row.count;
          break;
        case METRIC_GATE_DENY:
          usage.gateDeny += row.count;
          bucket.gateDeny += row.count;
          break;
        case METRIC_VISIBILITY_ALLOW:
          usage.visibilityAllow += row.count;
          bucket.visibilityAllow += row.count;
          break;
        case METRIC_VISIBILITY_DENY:
          usage.visibilityDeny += row.count;
          bucket.visibilityDeny += row.count;
          break;
      }
    }
    for (const usage of byKey.values()) {
      usage.buckets.sort((a, b) => a.bucket - b.bucket);
    }
    return [...byKey.values()];
  }

  // -- directory ingestion (org-root only) ----------------------------------

  /**
   * Directory ingestion: sync groups, memberships, reporting edges, and org
   * memberships from the identity provider or directory. Cyclic group
   * nesting — which no provider controls — is auto-condensed into virtual
   * parents with a warning. Cycle-forming reporting edges are skipped and
   * reported, never silently combined.
   */
  async importDirectory(
    snapshot: DirectorySnapshot,
    source: string,
    options?: DirectoryImportOptions,
  ): Promise<DirectoryImportResult> {
    this.requireOrgRoot("directory ingestion");
    const authoritative = options?.authoritative ?? false;
    const provenance: Provenance = { kind: "import", source };
    const warnings: string[] = [];
    const virtualParents: Array<{ id: string; members: string[] }> = [];
    const deactivatedUsers: string[] = [];
    let removedMemberships = 0;
    let clearedReportingEdges = 0;

    await this.storage.runExclusive("groups", async () => {
      if (snapshot.groups) {
        // Condense the MERGED graph — pre-existing groups plus the snapshot
        // (snapshot wins per group) — a snapshot that is individually
        // acyclic can still close a cycle through stored parentage, and a
        // stored cycle would brick every later group-parent edit.
        const existing = await this.storage.listGroups();
        const parentsOf = new Map<string, readonly string[]>(
          existing.map((g) => [g.id, g.parents]),
        );
        for (const g of snapshot.groups) parentsOf.set(g.id, g.parents ?? []);
        const { condenseImportedGraph } = await import("@alfiz/core");
        const condensed = condenseImportedGraph(parentsOf);
        warnings.push(...condensed.warnings);
        virtualParents.push(...condensed.virtualParents);
        const names = new Map(snapshot.groups.map((g) => [g.id, g]));
        const existingById = new Map(existing.map((g) => [g.id, g]));
        for (const [id, parents] of condensed.parentsOf) {
          const known = names.get(id);
          const prior = existingById.get(id);
          const priorParents = prior?.parents ?? null;
          const changed =
            known !== undefined ||
            prior === undefined ||
            priorParents === null ||
            priorParents.length !== parents.length ||
            priorParents.some((p, i) => parents[i] !== p);
          if (!changed) continue;
          await this.storage.upsertGroup({
            id,
            name: known?.name ?? prior?.name ?? id,
            description: known?.description ?? prior?.description,
            parents: [...parents],
            virtual: condensed.virtualParents.some((vp) => vp.id === id)
              ? true
              : prior?.virtual,
          });
        }
        await this.audit(provenance, "directory.import_groups", source, {
          groups: condensed.parentsOf.size,
          condensed: condensed.virtualParents.length,
        });
      }
    });

    for (const spec of snapshot.users ?? []) {
      const user = (await this.storage.getUser(spec.userId)) ?? {
        userId: spec.userId,
        active: true,
        groupIds: [],
        orgIds: [],
        managerUserId: null,
      };
      await this.storage.upsertUser({
        ...user,
        active: spec.active ?? user.active,
      });
    }
    if (authoritative && snapshot.users) {
      // The half upsert-only cannot do: a user the directory no longer
      // lists is deactivated — every check answers no within the staleness
      // bound — never deleted; rows stay for audit and `deleteSubject`
      // remains the deliberate id-retirement path.
      const listed = new Set(snapshot.users.map((u) => u.userId));
      for (const user of await this.storage.listUsers()) {
        if (listed.has(user.userId) || !user.active) continue;
        await this.storage.upsertUser({ ...user, active: false });
        deactivatedUsers.push(user.userId);
        await this.audit(provenance, "user.deactivate", user.userId, {
          reason: "authoritative directory import: absent from snapshot",
        });
      }
    }

    for (const [userId, groupIds] of Object.entries(
      snapshot.memberships ?? {},
    )) {
      const user = (await this.storage.getUser(userId)) ?? {
        userId,
        active: true,
        groupIds: [],
        orgIds: [],
        managerUserId: null,
      };
      await this.storage.upsertUser({
        ...user,
        groupIds: [...new Set(groupIds)],
      });
    }
    if (authoritative && snapshot.memberships) {
      // Sweep memberships in DIRECTORY-MANAGED groups (the snapshot's own
      // `groups` section, plus parents condensation minted) for users the
      // membership map no longer lists. Locally-authored groups are never
      // touched: the directory is authoritative only over what it owns.
      const directoryGroups = new Set([
        ...(snapshot.groups ?? []).map((g) => g.id),
        ...virtualParents.map((vp) => vp.id),
      ]);
      if (directoryGroups.size === 0) {
        warnings.push(
          "authoritative memberships skipped: the snapshot carries no `groups` section, so directory-managed groups cannot be told apart from locally-authored ones",
        );
      } else {
        const listed = snapshot.memberships;
        for (const user of await this.storage.listUsers()) {
          const keep = new Set(listed[user.userId] ?? []);
          const next = user.groupIds.filter(
            (g) => !directoryGroups.has(g) || keep.has(g),
          );
          if (next.length !== user.groupIds.length) {
            removedMemberships += user.groupIds.length - next.length;
            await this.storage.upsertUser({ ...user, groupIds: next });
          }
        }
      }
    }

    for (const [userId, orgIds] of Object.entries(snapshot.orgs ?? {})) {
      const user = (await this.storage.getUser(userId)) ?? {
        userId,
        active: true,
        groupIds: [],
        orgIds: [],
        managerUserId: null,
      };
      await this.storage.upsertUser({ ...user, orgIds: [...new Set(orgIds)] });
    }

    if (snapshot.reportingEdges) {
      await this.storage.runExclusive("reporting", async () => {
        // Cycle detection must see the MERGED edge set: snapshot edges
        // overlaid on stored ones — a partial import composed with stored
        // edges can close a loop the snapshot alone does not contain.
        const merged = new Map<string, string>();
        for (const user of await this.storage.listUsers()) {
          if (user.managerUserId !== null) {
            merged.set(user.userId, user.managerUserId);
          }
        }
        for (const [userId, managerUserId] of Object.entries(
          snapshot.reportingEdges!,
        )) {
          // Walk upward through the merged view as it would look with this
          // edge applied; a loop back to userId is a cycle — skipped with a
          // warning, never written.
          const path = [userId];
          let current: string | undefined = managerUserId;
          let cyclic = false;
          const seen = new Set<string>([userId]);
          while (current !== undefined) {
            path.push(current);
            if (seen.has(current)) {
              cyclic = current === userId;
              break;
            }
            seen.add(current);
            current = merged.get(current);
          }
          if (cyclic) {
            warnings.push(
              `reporting cycle skipped: ${path.join(" → ")} — resolve in the directory`,
            );
            continue;
          }
          merged.set(userId, managerUserId);
          const user = (await this.storage.getUser(userId)) ?? {
            userId,
            active: true,
            groupIds: [],
            orgIds: [],
            managerUserId: null,
          };
          await this.storage.upsertUser({ ...user, managerUserId });
        }
        if (authoritative) {
          // An edge the directory no longer asserts is cleared: a stale
          // edge silently routes approvals to someone who left, which is
          // worse than an unpopulated one (that at least fails loudly at
          // policy creation).
          const asserted = new Set(Object.keys(snapshot.reportingEdges!));
          for (const user of await this.storage.listUsers()) {
            if (user.managerUserId === null || asserted.has(user.userId)) {
              continue;
            }
            await this.storage.upsertUser({ ...user, managerUserId: null });
            clearedReportingEdges++;
          }
        }
      });
    }

    await this.audit(provenance, "directory.import", source, {
      warnings: warnings.length,
      ...(authoritative
        ? {
            authoritative: true,
            deactivatedUsers: deactivatedUsers.length,
            removedMemberships,
            clearedReportingEdges,
          }
        : {}),
    });
    this.emit({ type: "all" });
    await this.flushEvents();
    return {
      warnings,
      virtualParents,
      ...(authoritative
        ? { deactivatedUsers, removedMemberships, clearedReportingEdges }
        : {}),
    };
  }
}

/**
 * Constructs an Application whose write paths are typed by the catalog's
 * derived pattern and scope-id unions — the write-side counterpart of
 * `createAlfizClient`. Pass the catalog literal (or a `TypedCatalog` from
 * a published document) and seeding scripts autocomplete grants.
 */
export function createApplication<Cat extends AnyCatalog>(
  options: Omit<ApplicationOptions, "catalog"> & { catalog: Cat },
): AlfizApplication<Cat["$pattern"], Cat["$scope"]> {
  return new AlfizApplication(options);
}
