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
  listGrants(filter?: {
    subject?: SubjectId | undefined;
    scope?: ScopeId | undefined;
  }): Promise<GrantRow[]>;
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
  listAuditEvents(filter?: {
    target?: string | undefined;
    limit?: number | undefined;
  }): Promise<AuditEvent[]>;
}
