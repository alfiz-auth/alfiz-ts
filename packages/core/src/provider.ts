/**
 * The provider contract — the single load-bearing interface of the system,
 * implemented identically by the Application (local, one database) and the
 * Service (managed). A Client cannot observe which provider it is attached
 * to except through capability discovery.
 *
 * The contract comprises: closure supply, row operations (grant, revoke,
 * request CRUD, with provenance and expiry), catalog registration, graph
 * writes (with integrity semantics enforced provider-side), organizational
 * data management, and invalidation events.
 */

import type { GrantRow, Provenance, RevokeRow, RoleDef } from "./access.js";
import type { CatalogDocument, ImportManifest } from "./catalog.js";
import type { LoosePattern, PermissionPattern } from "./grammar.js";
import type {
  MetricsBatch,
  PermissionUsage,
  RowUsage,
  UsageQuery,
} from "./metrics.js";
import type { AccessRequest, ApprovalStage } from "./requests.js";
import type { AncestryResolver, LooseScopeId, ScopeId } from "./scopes.js";
import type { SubjectId } from "./subjects.js";

// ---------------------------------------------------------------------------
// Capability discovery — progressive disclosure over the wire. Machinery a
// deployment has not opted into is invisible; components render accordingly.
// ---------------------------------------------------------------------------

export interface ProviderCapabilities {
  /**
   * Whether this provider is currently the org root — the single
   * authoritative writer of organizational-domain data (groups, roles,
   * global grants/revokes, reporting edges). Non-root providers serve the
   * same data as a synced read model and reject writes to it.
   */
  orgRoot: boolean;
  /** Request workflows (submit/decide/queues) are served. */
  requests: boolean;
  /** Reporting hierarchy (and so implicit groups, management approvals) is populated. */
  reporting: boolean;
  /** An audit log is kept and readable. */
  audit: boolean;
  /** Multi-parent object graphs are enabled for at least one scope type. */
  multiParent: boolean;
  /**
   * Permission-usage metrics are accepted (`reportMetrics`) and readable
   * (`getGrantUsage` and friends). Off unless the deployment opted in, and
   * components render usage and revocation warnings only when it is on —
   * progressive disclosure, exactly like `audit`.
   */
  metrics: boolean;
  /**
   * Import manifests are accepted (`publishImports`) and readable
   * (`getPublishedImports`). Off unless the provider stores them; components
   * and drift reports render the consumption side only when it is on —
   * progressive disclosure, exactly like `audit` and `metrics`.
   */
  imports: boolean;
}

// ---------------------------------------------------------------------------
// Closure supply
// ---------------------------------------------------------------------------

/** Who is being evaluated: a person or a machine subject. */
export type PrincipalRef = { userId: string } | { serviceId: string };

/**
 * The one discriminant for {@link PrincipalRef}, so no two readers of a
 * principal can disagree about who it names.
 *
 * The union admits exactly one of the two keys, but that is a *compile-time*
 * guarantee and it only binds literal call sites: a claims object widened
 * through `as`, a spread of two sources, or a JSON body straight off the
 * wire can all carry both. When they do, "pick whichever key I test first"
 * is the worst possible answer — the Client keyed its cache by one half
 * while the provider answered for the other, so a user's entry held a
 * service's authority and the user's own revokes were skipped as
 * inapplicable. Reading the same field in both places would only hide the
 * ambiguity behind whichever half won; there is no correct interpretation of
 * a principal that names two principals, so this refuses it.
 *
 * A programming error, on the footing of `UnknownPermissionError`: map it to
 * 500, never 403. Nobody was denied — the question was malformed.
 */
export function principalKind(
  principal: PrincipalRef,
): { kind: "user"; id: string } | { kind: "service"; id: string } {
  const hasUser =
    "userId" in principal && (principal as { userId?: unknown }).userId != null;
  const hasService =
    "serviceId" in principal &&
    (principal as { serviceId?: unknown }).serviceId != null;
  if (hasUser && hasService) {
    throw new TypeError(
      "alfiz: a principal names both a userId and a serviceId — it must name exactly one. " +
        "A check cannot be evaluated for two principals, and answering for either one " +
        "would cache one principal's authority under the other's key.",
    );
  }
  if (hasUser) return { kind: "user", id: (principal as { userId: string }).userId };
  if (hasService) {
    return { kind: "service", id: (principal as { serviceId: string }).serviceId };
  }
  throw new TypeError(
    "alfiz: a principal names neither a userId nor a serviceId — it must name exactly one.",
  );
}

/**
 * Everything the Client needs to evaluate a principal: their subject closure
 * and the access rows visible to it. Diagnostics are surfaced, never
 * silently dropped.
 */
export interface SubjectAccessData {
  /** `null` for machine subjects. */
  userId: string | null;
  closure: SubjectId[];
  /** Unfiltered rows for closure members, at every scope. */
  grants: GrantRow[];
  revokes: RevokeRow[];
  /** Definitions for every role referenced by `grants`. */
  roles: RoleDef[];
  /** The principal's manager chain, nearest-first (empty when unpopulated). */
  managerChain: string[];
  /** Role ids referenced by grants but not found — a data-integrity signal. */
  unresolvedRoleIds: string[];
  /** Whether the principal exists and is active. Inactive principals evaluate to no access. */
  active: boolean;
}

// ---------------------------------------------------------------------------
// Invalidation events — cache policy is a Client behavior parameterized by
// provider events, identical in every topology.
// ---------------------------------------------------------------------------

export type InvalidationEvent =
  /** A user's memberships, edges, or rows changed: bust their subject-side cache. */
  | { type: "user"; userId: string }
  /** A group's parentage or access changed: bust every cached closure containing it. */
  | { type: "subject"; subject: SubjectId }
  /** An object (or an ancestor) moved: bust that chain immediately. */
  | { type: "scope"; scope: ScopeId }
  /** A role definition changed. */
  | { type: "role"; roleId: string }
  /** The registered catalog changed. */
  | { type: "catalog" }
  /** Bust everything (promotion, merge, import). */
  | { type: "all" };

export type InvalidationListener = (event: InvalidationEvent) => void;
export type Unsubscribe = () => void;

/**
 * The persisted-event freshness signal: a monotonic sequence over the same
 * invalidation events the live stream carries, durable in the provider's
 * store. `onInvalidate` only reaches listeners in the writing process; the
 * epoch reaches every process that can reach the database — it is the
 * cross-process (and serverless) invalidation transport.
 *
 * `head()` is a single tiny read whose cost is independent of organization
 * size: unchanged head means NOTHING changed anywhere, so every cached
 * closure is still exact. A client that saw sequence `n` catches up with
 * `since(n)` and replays the returned events through the same busting logic
 * the live stream feeds — identical semantics, different arrival path.
 */
export interface EpochSource {
  /** The sequence number of the most recently persisted event (0 when none). */
  head(): Promise<number>;
  /**
   * Events after `seq`, oldest first, at most `limit` (provider-chosen
   * default). `{ gap: true }` when `seq` predates the provider's event
   * retention — the caller can no longer catch up selectively and must
   * treat everything it holds as suspect (bust all, resume from `head()`).
   */
  since(
    seq: number,
    limit?: number,
  ): Promise<{ upTo: number; events: InvalidationEvent[] } | { gap: true }>;
}

// ---------------------------------------------------------------------------
// Row operations
// ---------------------------------------------------------------------------

/**
 * Write-path inputs are generic over the catalog's derived pattern and
 * scope unions, defaulting to plain strings — the wire contract
 * (`AlfizProvider`) stays string-typed, while `AlfizApplication`
 * (constructed via `createAlfizApplication`) instantiates them so seeding
 * scripts and admin code autocomplete patterns and scope prefixes. Loose
 * (`LoosePattern` / `LooseScopeId`), not strict: role editors and admin
 * UIs legitimately pass runtime strings, and the write path validates
 * every one against the catalog regardless.
 */
export interface GrantInput<
  P extends string = PermissionPattern,
  S extends string = ScopeId,
> {
  subject: SubjectId;
  roleId?: string | undefined;
  pattern?: LoosePattern<P> | undefined;
  scope?: LooseScopeId<S> | undefined;
  expiresAt?: number | undefined;
  provenance: Provenance;
}

/** The filter shared by `listGrants` and `countGrants`. */
export interface GrantQuery {
  subject?: SubjectId | undefined;
  scope?: ScopeId | undefined;
  /** Grants conferring a given role — role-holder queries without a scan. */
  roleId?: string | undefined;
}

export interface RevokeInput<
  P extends string = PermissionPattern,
  S extends string = ScopeId,
> {
  userId: string;
  pattern: LoosePattern<P>;
  scope?: LooseScopeId<S> | undefined;
  provenance: Provenance;
}

export interface RequestInput<
  P extends string = PermissionPattern,
  S extends string = ScopeId,
> {
  requesterUserId: string;
  roleId?: string | undefined;
  pattern?: LoosePattern<P> | undefined;
  scope?: LooseScopeId<S> | undefined;
  proposedExpiresAt?: number | undefined;
  justification?: Record<string, string> | undefined;
}

export interface RequestFilter {
  state?: AccessRequest["state"] | undefined;
  requesterUserId?: string | undefined;
}

// ---------------------------------------------------------------------------
// Organizational data (org-root owned; read model elsewhere)
// ---------------------------------------------------------------------------

export interface UserGroup {
  id: string;
  name: string;
  description?: string | undefined;
  /** Parent group ids (the DAG; enforced provider-side). */
  parents: string[];
  /** True for virtual parents created by condensation or sync. */
  virtual?: boolean | undefined;
}

export interface RoleInput<P extends string = PermissionPattern> {
  /**
   * Caller-supplied id. Omit for a generated one. Supply it when something
   * OUTSIDE the runtime must reference the role by id — a SQL data
   * migration seeding well-known roles, an infra-as-code definition — so
   * migration SQL and `createRole` agree on identity instead of the caller
   * maintaining a name-resolution cache. Creating an id that already
   * exists is a conflict, never an overwrite.
   */
  id?: string | undefined;
  name: string;
  description?: string | undefined;
  patterns: LoosePattern<P>[];
  /** Nothing is requestable by default. */
  requestable?:
    | {
        prompts?: readonly import("./requests.js").RequestPromptInput[];
        maxDurationMs?: number | undefined;
        requireExpiry?: boolean | undefined;
        stages: readonly ApprovalStage[];
      }
    | undefined;
}

export interface RoleRecord extends RoleDef {
  requestable?: RoleInput["requestable"] | undefined;
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

export interface AuditEvent {
  id: string;
  at: number;
  /** Who performed the write (a user id, `service:<id>`, or `system`). */
  actor: string;
  action: string;
  /** The entity acted on (row id, group id, request id, …). */
  target: string;
  detail?: unknown;
  /**
   * Tamper-evidence, present when the writing Application has
   * `audit: { hashChain: true }`: `hash` covers this event's canonical
   * serialization plus `prevHash`, so any edited, deleted, or reordered
   * entry breaks every hash after it. Verify with `verifyAuditChain`
   * (`@alfiz/application`).
   */
  prevHash?: string | undefined;
  hash?: string | undefined;
}

/**
 * The audit read filter, shared by the storage seam, the provider contract,
 * and the wire. Two paging modes, chosen by `cursor`:
 *
 * - **Without `cursor`** — the LAST `limit` matching events, in log order
 *   (ascending `at`): the shape an admin page's "recent activity" wants.
 * - **With `cursor`** — the first `limit` matching events strictly AFTER the
 *   cursor position, ascending: the shape an exporter wants. Events are
 *   ordered by (`at`, `id`); pass the last event you received as the next
 *   cursor and repeat until fewer than `limit` rows come back.
 */
export interface AuditQuery {
  target?: string | undefined;
  actor?: string | undefined;
  action?: string | undefined;
  /** Inclusive lower bound on `at` (epoch ms). */
  from?: number | undefined;
  /** Exclusive upper bound on `at` (epoch ms). */
  to?: number | undefined;
  /** Resume after this position (exclusive). Ordering is (`at`, then `id`). */
  cursor?: { at: number; id: string } | undefined;
  limit?: number | undefined;
}

// ---------------------------------------------------------------------------
// The contract
// ---------------------------------------------------------------------------

export class ProviderWriteRejectedError extends Error {
  override name = "ProviderWriteRejectedError";
  constructor(
    message: string,
    readonly code:
      | "not_org_root"
      | "graph_cycle"
      | "validation"
      | "not_found"
      | "conflict"
      | "unsupported",
  ) {
    super(message);
  }
}

export interface AlfizProvider {
  capabilities(): Promise<ProviderCapabilities>;

  // -- Closure supply -------------------------------------------------------
  getSubjectAccess(principal: PrincipalRef): Promise<SubjectAccessData>;
  /** The ancestry seam: only the owning application can resolve this. */
  resolveAncestors: AncestryResolver;

  // -- Invalidation ---------------------------------------------------------
  onInvalidate(listener: InvalidationListener): Unsubscribe;
  /**
   * Present when the provider persists its invalidation events (the
   * Application's `events.persist` option; always present on the managed
   * Service). Capability discovery, same as everything else: a client that
   * finds it can revalidate caches across processes; one that doesn't falls
   * back to TTL-bounded staleness.
   */
  epoch?: EpochSource | undefined;

  // -- Row operations -------------------------------------------------------
  createGrant(input: GrantInput): Promise<GrantRow>;
  /**
   * The bulk write for migrations and imports: every input validated BEFORE
   * any row is written (one bad input rejects the whole batch), then one
   * audit entry for the batch and one invalidation event per distinct
   * subject — not one of each per row.
   */
  createGrants(
    inputs: readonly Omit<GrantInput, "provenance">[],
    provenance: Provenance,
  ): Promise<GrantRow[]>;
  deleteGrant(grantId: string, provenance: Provenance): Promise<void>;
  listGrants(filter?: GrantQuery): Promise<GrantRow[]>;
  /**
   * How many grants match — without materializing them. "How many people
   * hold this role", rendered per row on a roles admin page, is the case
   * this exists for: the alternative is reading every grant in the
   * organization to produce a number.
   */
  countGrants(filter?: GrantQuery): Promise<number>;
  createRevoke(input: RevokeInput): Promise<RevokeRow>;
  deleteRevoke(revokeId: string, provenance: Provenance): Promise<void>;
  listRevokes(filter?: {
    userId?: string | undefined;
    scope?: ScopeId | undefined;
  }): Promise<RevokeRow[]>;

  // -- Referential cleanup ----------------------------------------------------
  // Grants key on subject and scope STRINGS, not foreign keys: deleting a
  // principal or a resource in the host application's own tables strands the
  // rows here, and a reused id silently inherits the stranded access. These
  // two are the cleanup half of the contract — call them from the same code
  // paths that delete the principal / the resource, exactly as
  // `notifyScopeMoved` pairs with moves.

  /**
   * Removes every grant held by `subject`. For `user:<id>` subjects, also
   * removes the user's personal revokes, their stored record (memberships,
   * org links, reporting edge), grants held by their implicit-group
   * subjects (`directs:<id>`, `orgof:<id>` — keyed to the user id), and
   * cancels their pending access requests. Reporting edges POINTING AT the
   * deleted user are left for the host to reassign — who manages the
   * orphaned team is an organizational decision, not a cleanup.
   */
  deleteSubject(
    subject: SubjectId,
    provenance: Provenance,
  ): Promise<{ deletedGrants: number; deletedRevokes: number }>;

  /**
   * Removes every grant and personal revoke AT `scope`, and cancels pending
   * requests targeting it. Rows at DESCENDANT scopes are separate rows:
   * when a subtree of resources is deleted, call this per deleted resource
   * id. The global scope is not deletable.
   */
  deleteScope(
    scope: ScopeId,
    provenance: Provenance,
  ): Promise<{ deletedGrants: number; deletedRevokes: number }>;

  // -- Requests -------------------------------------------------------------
  submitRequest(input: RequestInput): Promise<AccessRequest>;
  decideRequest(
    requestId: string,
    decision: {
      deciderUserId: string;
      decision: "approved" | "denied";
      note?: string | undefined;
    },
  ): Promise<AccessRequest>;
  cancelRequest(requestId: string, byUserId: string): Promise<AccessRequest>;
  listRequests(filter?: RequestFilter): Promise<AccessRequest[]>;
  /** The requests `approverUserId` may currently decide — the approver queue. */
  listApproverQueue(approverUserId: string): Promise<AccessRequest[]>;

  // -- Catalog registration -------------------------------------------------
  publishCatalog(
    document: CatalogDocument,
    provenance: Provenance,
  ): Promise<{ version: number }>;
  getPublishedCatalog(): Promise<{
    version: number;
    document: CatalogDocument;
  } | null>;

  // -- Import registration (OPTIONAL — gated by `capabilities().imports`) ----
  // The consumption side, deliberately separate from `publishCatalog`. What
  // an application ANNOUNCES is owned vocabulary others may grant against;
  // what it CONSUMES is a dependency others can only warn it about. Folding
  // the second into the first would let an application appear to define keys
  // in a namespace it does not own — the shadowing namespace ownership
  // exists to prevent.
  //
  // What it buys: the drift report today names roles and grants that
  // reference unpublished keys, but never CODE. With manifests, a provider
  // can say "application `docs` imports `zoom.breakout.manage`, tombstoned
  // 30 days ago" — before the next deploy discovers it.

  /** Versioned monotonically per application, exactly like `publishCatalog`. */
  publishImports?(
    manifest: ImportManifest,
    provenance: Provenance,
  ): Promise<{ version: number }>;
  getPublishedImports?(): Promise<{
    version: number;
    manifest: ImportManifest;
  } | null>;

  // -- Organizational data (rejected when not org root) ---------------------
  listRoles(): Promise<RoleRecord[]>;
  createRole(input: RoleInput, provenance: Provenance): Promise<RoleRecord>;
  updateRole(
    roleId: string,
    input: Partial<RoleInput>,
    provenance: Provenance,
  ): Promise<RoleRecord>;
  deleteRole(roleId: string, provenance: Provenance): Promise<void>;

  listGroups(): Promise<UserGroup[]>;
  createGroup(
    input: {
      /** Caller-supplied id (migrations, well-known cohorts). Conflict when taken. */
      id?: string | undefined;
      name: string;
      description?: string | undefined;
      parents?: string[] | undefined;
    },
    provenance: Provenance,
  ): Promise<UserGroup>;
  /**
   * Rename / re-describe a group. Identity is the opaque id, so renaming
   * never breaks grants or memberships — same rule as roles. Parentage is a
   * graph write and stays on `setGroupParents`; membership on
   * `setGroupMembership`.
   */
  updateGroup(
    groupId: string,
    input: { name?: string | undefined; description?: string | undefined },
    provenance: Provenance,
  ): Promise<UserGroup>;
  /** Graph write: transactional DAG enforcement, cycle paths named in errors. */
  setGroupParents(
    groupId: string,
    parents: string[],
    provenance: Provenance,
  ): Promise<UserGroup>;
  deleteGroup(groupId: string, provenance: Provenance): Promise<void>;
  setGroupMembership(
    userId: string,
    groupIds: string[],
    provenance: Provenance,
  ): Promise<void>;
  getGroupMembers(groupId: string): Promise<string[]>;

  /**
   * User provisioning: set the `active` flag, creating the record when
   * absent (deactivating a never-provisioned principal must stick). This is
   * the offboarding switch — an inactive principal evaluates to NO access,
   * every check shape, immediately on the next closure supply. Reversible,
   * unlike `deleteSubject`.
   */
  setUserActive(
    userId: string,
    active: boolean,
    provenance: Provenance,
  ): Promise<void>;

  /** Graph write: the reporting tree. `managerUserId: null` clears the edge. */
  setReportingEdge(
    userId: string,
    managerUserId: string | null,
    provenance: Provenance,
  ): Promise<void>;
  getReportingEdges(): Promise<Map<string, string>>;

  /**
   * Dissolve a virtual parent: snapshot its grants down to each child with
   * provenance, then remove it — after which the children drift freely.
   */
  dissolveVirtualParent(groupId: string, provenance: Provenance): Promise<void>;

  // -- Audit ----------------------------------------------------------------
  listAuditEvents(filter?: AuditQuery): Promise<AuditEvent[]>;

  // -- Metrics (OPTIONAL — gated by `capabilities().metrics`) ----------------
  // The delivery half of the metrics pipeline and the reads the safeguards
  // and per-action numbers are built from. Optional on the contract, so a
  // provider that stores no metrics still satisfies it and its clients
  // simply render nothing.
  //
  // Direction matters here and is deliberate: the Client hands batches to
  // its OWN provider — the local Application — and nothing carries them
  // further. Metrics are local data with a local reader; an application that
  // wants them elsewhere sends them there itself, through the observer.

  /**
   * Ingest one aggregated window. Never individual checks: the client
   * aggregates first, so what crosses this boundary is windowed counts
   * tagged with an instance id, and many app servers' batches merge wherever
   * they land. Called off the request path, fire-and-forget — a failed batch
   * is a lost count, never a failed check.
   */
  reportMetrics?(batch: MetricsBatch): Promise<void>;

  /**
   * Per-grant usage over a window: `matched` (participated in an allow) and
   * `soleMatch` (was the ONLY row allowing — revoking it would have denied).
   * The revocation safeguard keys on the second; see `revocationSafeguard`.
   */
  getGrantUsage?(query?: UsageQuery): Promise<RowUsage[]>;

  /**
   * Per-revoke usage: how many checks each revoke suppressed. Deleting a
   * revoke WIDENS access, so this reading points the opposite direction from
   * the grant one.
   */
  getRevokeUsage?(query?: UsageQuery): Promise<RowUsage[]>;

  /** Per-role usage, for role-edit and role-delete safeguards. */
  getRoleUsage?(query?: UsageQuery): Promise<RowUsage[]>;

  /**
   * Per-permission counts, split by gate versus visibility traffic — the
   * per-action metric. `ids` filters to specific keys; omit for the catalog.
   */
  getPermissionUsage?(query?: UsageQuery): Promise<PermissionUsage[]>;

  /** The same rollup keyed by scope type — which parts of the hierarchy are checked. */
  getScopeTypeUsage?(query?: UsageQuery): Promise<PermissionUsage[]>;
}
