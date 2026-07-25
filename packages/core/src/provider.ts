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
import type { CatalogDocument } from "./catalog.js";
import type { PermissionPattern } from "./grammar.js";
import type { AccessRequest, ApprovalStage } from "./requests.js";
import type { AncestryResolver, ScopeId } from "./scopes.js";
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
}

// ---------------------------------------------------------------------------
// Closure supply
// ---------------------------------------------------------------------------

/** Who is being evaluated: a person or a machine subject. */
export type PrincipalRef = { userId: string } | { serviceId: string };

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

// ---------------------------------------------------------------------------
// Row operations
// ---------------------------------------------------------------------------

export interface GrantInput {
  subject: SubjectId;
  roleId?: string | undefined;
  pattern?: PermissionPattern | undefined;
  scope?: ScopeId | undefined;
  expiresAt?: number | undefined;
  provenance: Provenance;
}

export interface RevokeInput {
  userId: string;
  pattern: PermissionPattern;
  scope?: ScopeId | undefined;
  provenance: Provenance;
}

export interface RequestInput {
  requesterUserId: string;
  roleId?: string | undefined;
  pattern?: PermissionPattern | undefined;
  scope?: ScopeId | undefined;
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

export interface RoleInput {
  name: string;
  description?: string | undefined;
  patterns: PermissionPattern[];
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

  // -- Row operations -------------------------------------------------------
  createGrant(input: GrantInput): Promise<GrantRow>;
  deleteGrant(grantId: string, provenance: Provenance): Promise<void>;
  listGrants(filter?: {
    subject?: SubjectId | undefined;
    scope?: ScopeId | undefined;
  }): Promise<GrantRow[]>;
  createRevoke(input: RevokeInput): Promise<RevokeRow>;
  deleteRevoke(revokeId: string, provenance: Provenance): Promise<void>;
  listRevokes(filter?: { userId?: string | undefined }): Promise<RevokeRow[]>;

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
    input: { name: string; description?: string | undefined; parents?: string[] | undefined },
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
  listAuditEvents(filter?: {
    target?: string | undefined;
    limit?: number | undefined;
  }): Promise<AuditEvent[]>;
}
