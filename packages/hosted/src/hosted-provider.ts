/**
 * The hosted provider: the provider contract with its far side reached
 * over the Alfiz Provider API — an API connection wrapped in the
 * contract's abstract class, and the second of the system's two provider
 * implementations (the first being `AlfizApplication`, the local one).
 *
 * A `HostedProvider` never stores or decides anything itself: every read
 * and write is forwarded to the serving side — a linked Application's
 * `createProviderHandler` mount, or a managed service speaking the same
 * API — which enforces its provider-side integrity rules on remote
 * operations exactly as on local ones. Delegation, never a second writer.
 *
 * The wire form is fixed by the OpenAPI document in `@alfiz/core`
 * (`openapi/alfiz-provider.v1.yaml`): `POST {base}/v1/{op}`, named-field
 * JSON bodies, object results, typed-error envelopes. This class is
 * deliberately nothing more than that document, executed — a port of the
 * provider side to another language starts from the same document and
 * ends in the same class shape.
 *
 * Freshness: the hosted provider exposes the far side's epoch, so an
 * `AlfizClient` attached to it revalidates with one tiny read per window —
 * the same cross-process mechanism the library uses over a shared
 * database, carried over HTTP instead. The live `onInvalidate` stream
 * never crosses processes; a poller may feed epoch events back through
 * `ingestEvents` (inherited from the base class) for push-like latency.
 */

import type {
  AccessRequest,
  AlfizProvider,
  ApplyOrgSnapshotInput,
  AuditEvent,
  CatalogDocument,
  EpochSource,
  GrantInput,
  GrantQuery,
  GrantRow,
  ImportManifest,
  InvalidationEvent,
  MetricsBatch,
  OrgSnapshot,
  PermissionUsage,
  PrincipalRef,
  Provenance,
  ProviderCapabilities,
  ProviderOp,
  ProviderPingResult,
  ProviderWireError,
  RequestFilter,
  RequestInput,
  RevokeInput,
  RevokeRow,
  RoleInput,
  RoleRecord,
  RowUsage,
  ScopeId,
  SubjectAccessData,
  SubjectId,
  UsageQuery,
  UserGroup,
} from "@alfiz/core";
import {
  AlfizProviderBase,
  providerOpPath,
  rethrowProviderWireError,
} from "@alfiz/core";

export interface HostedProviderTarget {
  /** Base URL of the serving side; operations POST to `{url}/v1/{op}`. */
  url: string;
  /** The bearer token minted at link time. */
  secret: string;
  /** Timeout per call; administrative traffic, so generous. Default 15s. */
  timeoutMs?: number | undefined;
  /** Test seam: swap the transport. Defaults to global fetch. */
  fetchImpl?: typeof fetch | undefined;
}

/** The transport failed — as opposed to the far side answering with an error. */
export class ProviderTransportError extends Error {
  override name = "ProviderTransportError";
  constructor(
    message: string,
    readonly status?: number | undefined,
  ) {
    super(message);
  }
}

export class HostedProvider extends AlfizProviderBase {
  override readonly epoch: EpochSource;
  override readonly resolveAncestors: (scope: ScopeId) => Promise<ScopeId[]>;

  constructor(private readonly target: HostedProviderTarget) {
    super();
    this.epoch = {
      head: async () => (await this.call<{ seq: number }>("epoch.head", {})).seq,
      since: (seq, limit) =>
        this.call("epoch.since", limit === undefined ? { seq } : { seq, limit }),
    };
    this.resolveAncestors = async (scope) =>
      (await this.call<{ ancestors: ScopeId[] }>("resolveAncestors", { scope }))
        .ancestors;
  }

  /**
   * One wire exchange, per the conventions in `@alfiz/core`'s protocol
   * module: POST the operation's named parameters, take the object result,
   * re-throw error envelopes typed.
   */
  async call<T>(op: ProviderOp, params: Record<string, unknown>): Promise<T> {
    const { url, secret, timeoutMs = 15_000, fetchImpl = fetch } = this.target;
    const endpoint = url.replace(/\/$/, "") + providerOpPath(op);
    let response: Response;
    try {
      response = await fetchImpl(endpoint, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${secret}`,
        },
        body: JSON.stringify(params),
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (error) {
      throw new ProviderTransportError(
        `provider call to ${endpoint} failed: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
    let payload: unknown;
    try {
      payload = await response.json();
    } catch {
      throw new ProviderTransportError(
        `provider call to ${endpoint} answered ${response.status} with a non-JSON body`,
        response.status,
      );
    }
    const envelope = payload as { error?: ProviderWireError };
    if (envelope !== null && typeof envelope === "object" && envelope.error) {
      // Protocol-level failures (bad credentials, unknown op, malformed
      // body) are the CALLER's transport problem; provider-domain errors
      // re-throw typed, identical to the serving side throwing locally.
      if (envelope.error.name === "ProviderApiError") {
        throw new ProviderTransportError(
          `provider call to ${endpoint} was rejected by the API: ${envelope.error.message}`,
          response.status,
        );
      }
      rethrowProviderWireError(envelope.error);
    }
    if (!response.ok) {
      throw new ProviderTransportError(
        `provider call to ${endpoint} answered ${response.status}`,
        response.status,
      );
    }
    return payload as T;
  }

  // -- health / link ---------------------------------------------------------
  ping(): Promise<ProviderPingResult> {
    return this.call("ping", {});
  }

  // -- org snapshot ops (promotion, demotion, read-model sync) ---------------
  async exportOrgSnapshot(): Promise<OrgSnapshot> {
    return (await this.call<{ snapshot: OrgSnapshot }>("org.exportSnapshot", {}))
      .snapshot;
  }
  applyOrgSnapshot(input: ApplyOrgSnapshotInput): Promise<{ applied: true }> {
    return this.call("org.applySnapshot", { ...input });
  }

  // -- capability discovery --------------------------------------------------
  capabilities(): Promise<ProviderCapabilities> {
    return this.call("capabilities", {});
  }

  // -- closure supply --------------------------------------------------------
  getSubjectAccess(principal: PrincipalRef): Promise<SubjectAccessData> {
    return this.call("getSubjectAccess", { principal });
  }

  // -- row operations --------------------------------------------------------
  async createGrant(input: GrantInput): Promise<GrantRow> {
    return (await this.call<{ grant: GrantRow }>("createGrant", { input })).grant;
  }
  async createGrants(
    inputs: readonly Omit<GrantInput, "provenance">[],
    provenance: Provenance,
  ): Promise<GrantRow[]> {
    return (
      await this.call<{ grants: GrantRow[] }>("createGrants", {
        inputs,
        provenance,
      })
    ).grants;
  }
  async deleteGrant(grantId: string, provenance: Provenance): Promise<void> {
    await this.call("deleteGrant", { grantId, provenance });
  }
  async listGrants(filter?: GrantQuery): Promise<GrantRow[]> {
    return (await this.call<{ grants: GrantRow[] }>("listGrants", { filter }))
      .grants;
  }
  async countGrants(filter?: GrantQuery): Promise<number> {
    return (await this.call<{ count: number }>("countGrants", { filter })).count;
  }
  async createRevoke(input: RevokeInput): Promise<RevokeRow> {
    return (await this.call<{ revoke: RevokeRow }>("createRevoke", { input }))
      .revoke;
  }
  async deleteRevoke(revokeId: string, provenance: Provenance): Promise<void> {
    await this.call("deleteRevoke", { revokeId, provenance });
  }
  async listRevokes(filter?: {
    userId?: string | undefined;
    scope?: ScopeId | undefined;
  }): Promise<RevokeRow[]> {
    return (await this.call<{ revokes: RevokeRow[] }>("listRevokes", { filter }))
      .revokes;
  }

  // -- referential cleanup ---------------------------------------------------
  deleteSubject(
    subject: SubjectId,
    provenance: Provenance,
  ): Promise<{ deletedGrants: number; deletedRevokes: number }> {
    return this.call("deleteSubject", { subject, provenance });
  }
  deleteScope(
    scope: ScopeId,
    provenance: Provenance,
  ): Promise<{ deletedGrants: number; deletedRevokes: number }> {
    return this.call("deleteScope", { scope, provenance });
  }

  // -- requests --------------------------------------------------------------
  async submitRequest(input: RequestInput): Promise<AccessRequest> {
    return (await this.call<{ request: AccessRequest }>("submitRequest", { input }))
      .request;
  }
  async decideRequest(
    requestId: string,
    decision: {
      deciderUserId: string;
      decision: "approved" | "denied";
      note?: string | undefined;
    },
  ): Promise<AccessRequest> {
    return (
      await this.call<{ request: AccessRequest }>("decideRequest", {
        requestId,
        decision,
      })
    ).request;
  }
  async cancelRequest(requestId: string, byUserId: string): Promise<AccessRequest> {
    return (
      await this.call<{ request: AccessRequest }>("cancelRequest", {
        requestId,
        byUserId,
      })
    ).request;
  }
  async listRequests(filter?: RequestFilter): Promise<AccessRequest[]> {
    return (
      await this.call<{ requests: AccessRequest[] }>("listRequests", { filter })
    ).requests;
  }
  async listApproverQueue(approverUserId: string): Promise<AccessRequest[]> {
    return (
      await this.call<{ requests: AccessRequest[] }>("listApproverQueue", {
        approverUserId,
      })
    ).requests;
  }

  // -- catalog registration --------------------------------------------------
  publishCatalog(
    document: CatalogDocument,
    provenance: Provenance,
  ): Promise<{ version: number }> {
    return this.call("publishCatalog", { document, provenance });
  }
  async getPublishedCatalog(): Promise<{
    version: number;
    document: CatalogDocument;
  } | null> {
    return (
      await this.call<{
        published: { version: number; document: CatalogDocument } | null;
      }>("getPublishedCatalog", {})
    ).published;
  }

  // -- import registration ---------------------------------------------------
  // Present unconditionally on the transport; the far side answers
  // `unsupported` when it stores none, which is what `capabilities().imports`
  // tells a caller in advance. The same posture as metrics below.

  override publishImports(
    manifest: ImportManifest,
    provenance: Provenance,
  ): Promise<{ version: number }> {
    return this.call("publishImports", { manifest, provenance });
  }
  override async getPublishedImports(): Promise<{
    version: number;
    manifest: ImportManifest;
  } | null> {
    return (
      await this.call<{
        published: { version: number; manifest: ImportManifest } | null;
      }>("getPublishedImports", {})
    ).published;
  }

  // -- organizational data ---------------------------------------------------
  async listRoles(): Promise<RoleRecord[]> {
    return (await this.call<{ roles: RoleRecord[] }>("listRoles", {})).roles;
  }
  async createRole(input: RoleInput, provenance: Provenance): Promise<RoleRecord> {
    return (
      await this.call<{ role: RoleRecord }>("createRole", { input, provenance })
    ).role;
  }
  async updateRole(
    roleId: string,
    input: Partial<RoleInput>,
    provenance: Provenance,
  ): Promise<RoleRecord> {
    return (
      await this.call<{ role: RoleRecord }>("updateRole", {
        roleId,
        input,
        provenance,
      })
    ).role;
  }
  async deleteRole(roleId: string, provenance: Provenance): Promise<void> {
    await this.call("deleteRole", { roleId, provenance });
  }

  async listGroups(): Promise<UserGroup[]> {
    return (await this.call<{ groups: UserGroup[] }>("listGroups", {})).groups;
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
    return (
      await this.call<{ group: UserGroup }>("createGroup", { input, provenance })
    ).group;
  }
  async updateGroup(
    groupId: string,
    input: { name?: string | undefined; description?: string | undefined },
    provenance: Provenance,
  ): Promise<UserGroup> {
    return (
      await this.call<{ group: UserGroup }>("updateGroup", {
        groupId,
        input,
        provenance,
      })
    ).group;
  }
  async setGroupParents(
    groupId: string,
    parents: string[],
    provenance: Provenance,
  ): Promise<UserGroup> {
    return (
      await this.call<{ group: UserGroup }>("setGroupParents", {
        groupId,
        parents,
        provenance,
      })
    ).group;
  }
  async deleteGroup(groupId: string, provenance: Provenance): Promise<void> {
    await this.call("deleteGroup", { groupId, provenance });
  }
  async setGroupMembership(
    userId: string,
    groupIds: string[],
    provenance: Provenance,
  ): Promise<void> {
    await this.call("setGroupMembership", { userId, groupIds, provenance });
  }
  async getGroupMembers(groupId: string): Promise<string[]> {
    return (await this.call<{ userIds: string[] }>("getGroupMembers", { groupId }))
      .userIds;
  }

  async setUserActive(
    userId: string,
    active: boolean,
    provenance: Provenance,
  ): Promise<void> {
    await this.call("setUserActive", { userId, active, provenance });
  }

  async setReportingEdge(
    userId: string,
    managerUserId: string | null,
    provenance: Provenance,
  ): Promise<void> {
    await this.call("setReportingEdge", { userId, managerUserId, provenance });
  }
  async getReportingEdges(): Promise<Map<string, string>> {
    const { edges } = await this.call<{ edges: Record<string, string> }>(
      "getReportingEdges",
      {},
    );
    return new Map(Object.entries(edges));
  }

  async dissolveVirtualParent(
    groupId: string,
    provenance: Provenance,
  ): Promise<void> {
    await this.call("dissolveVirtualParent", { groupId, provenance });
  }

  // -- audit -----------------------------------------------------------------
  async listAuditEvents(filter?: {
    target?: string | undefined;
    limit?: number | undefined;
  }): Promise<AuditEvent[]> {
    return (
      await this.call<{ events: AuditEvent[] }>("listAuditEvents", { filter })
    ).events;
  }

  // -- metrics ---------------------------------------------------------------
  // The far side reads usage out of the store that kept it; nothing is
  // retained on this end.

  override async reportMetrics(batch: MetricsBatch): Promise<void> {
    await this.call("reportMetrics", { batch });
  }
  override async getGrantUsage(query?: UsageQuery): Promise<RowUsage[]> {
    return (await this.call<{ usage: RowUsage[] }>("getGrantUsage", { query }))
      .usage;
  }
  override async getRevokeUsage(query?: UsageQuery): Promise<RowUsage[]> {
    return (await this.call<{ usage: RowUsage[] }>("getRevokeUsage", { query }))
      .usage;
  }
  override async getRoleUsage(query?: UsageQuery): Promise<RowUsage[]> {
    return (await this.call<{ usage: RowUsage[] }>("getRoleUsage", { query }))
      .usage;
  }
  override async getPermissionUsage(query?: UsageQuery): Promise<PermissionUsage[]> {
    return (
      await this.call<{ usage: PermissionUsage[] }>("getPermissionUsage", {
        query,
      })
    ).usage;
  }
  override async getScopeTypeUsage(query?: UsageQuery): Promise<PermissionUsage[]> {
    return (
      await this.call<{ usage: PermissionUsage[] }>("getScopeTypeUsage", {
        query,
      })
    ).usage;
  }
}

// Assignability check: the hosted provider satisfies the contract with the
// optional members PRESENT — the transport carries them unconditionally and
// the far side is the one that gates.
const _hostedImplementsContract: AlfizProvider = null as unknown as HostedProvider;
void _hostedImplementsContract;

export function createHostedProvider(target: HostedProviderTarget): HostedProvider {
  return new HostedProvider(target);
}

export type { InvalidationEvent };
