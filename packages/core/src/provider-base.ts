/**
 * The provider contract as an abstract class — the single implementation
 * root every Alfiz provider extends, and the enforcement of the
 * Client/Provider split in code rather than convention.
 *
 * Exactly two kinds of implementation exist, by design:
 *
 * - the **local provider** (`AlfizApplication`, `@alfiz/application`):
 *   the contract against the application's own database, standalone the
 *   org root — the complete system with no external dependency; and
 * - the **hosted provider** (`HostedProvider`, also `@alfiz/application`): the same
 *   contract with its far side reached over the Alfiz Provider API — the
 *   Dashboard/Federation seam, an API connection wrapped in this class.
 *
 * A Client attaches to `AlfizProvider` and cannot observe which one it got
 * except through capability discovery; the wire form of the hosted seam is
 * fixed by the OpenAPI document (see protocol.ts), which is what makes the
 * provider side portable to other implementation languages: a conforming
 * provider in any language is "this class's surface, served over that API".
 *
 * What lives here is only what is invariant across every implementation:
 * the abstract statement of the contract (checked against the
 * `AlfizProvider` interface by the `implements` clause), the
 * invalidation-listener plumbing shared by both, and the uniform rejection
 * helper. Everything with an opinion about storage or transport belongs in
 * a subclass.
 */

import type { GrantRow, Provenance, RevokeRow } from "./access.js";
import type { CatalogDocument, ImportManifest } from "./catalog.js";
import type {
  MetricsBatch,
  PermissionUsage,
  RowUsage,
  UsageQuery,
} from "./metrics.js";
import type {
  AlfizProvider,
  AuditEvent,
  AuditQuery,
  EpochSource,
  GrantInput,
  GrantQuery,
  InvalidationEvent,
  InvalidationListener,
  PrincipalRef,
  ProviderCapabilities,
  RequestFilter,
  RequestInput,
  RevokeInput,
  RoleInput,
  RoleRecord,
  SubjectAccessData,
  Unsubscribe,
  UserGroup,
} from "./provider.js";
import { ProviderWriteRejectedError } from "./provider.js";
import type { AccessRequest } from "./requests.js";
import type { AncestryResolver, ScopeId } from "./scopes.js";
import type { SubjectId } from "./subjects.js";

export abstract class AlfizProviderBase implements AlfizProvider {
  // -- Capability discovery -------------------------------------------------
  abstract capabilities(): Promise<ProviderCapabilities>;

  // -- Closure supply -------------------------------------------------------
  abstract getSubjectAccess(principal: PrincipalRef): Promise<SubjectAccessData>;
  /** The ancestry seam: only the owning application can resolve this. */
  abstract resolveAncestors: AncestryResolver;

  // -- Invalidation ---------------------------------------------------------
  // The listener registry is the one piece of behavior every provider
  // shares verbatim, so it lives here. What EMITS differs by nature: the
  // local provider emits from its own writes; the hosted provider emits
  // nothing on its own — its epoch is the cross-process transport, and a
  // poller may feed foreign events back through `ingestEvents`.

  /**
   * Present when the provider persists its invalidation events; capability
   * discovery, same as everything else. A client that finds it can
   * revalidate caches across processes; one that doesn't falls back to
   * TTL-bounded staleness.
   */
  epoch?: EpochSource | undefined;

  private readonly invalidationListeners = new Set<InvalidationListener>();

  onInvalidate(listener: InvalidationListener): Unsubscribe {
    this.invalidationListeners.add(listener);
    return () => this.invalidationListeners.delete(listener);
  }

  /**
   * Notify local listeners of one event. Subclasses override to couple
   * provider-internal caches to the stream (and call `super`), so every
   * arrival path — local write, epoch replay, snapshot apply — busts the
   * same state.
   */
  protected emitInvalidation(event: InvalidationEvent): void {
    for (const listener of this.invalidationListeners) listener(event);
  }

  /**
   * Re-emit events that originated in ANOTHER process (read via
   * `epoch.since`, typically by an event poller) into this provider's local
   * listener stream, so attached clients bust as if the write were local.
   * Ingested events are never re-persisted — they are already in the log.
   */
  ingestEvents(events: readonly InvalidationEvent[]): void {
    for (const event of events) this.emitInvalidation(event);
  }

  /** Uniform rejection: the one error taxonomy every implementation speaks. */
  protected reject(
    message: string,
    code: ConstructorParameters<typeof ProviderWriteRejectedError>[1],
  ): never {
    throw new ProviderWriteRejectedError(message, code);
  }

  // -- Row operations -------------------------------------------------------
  abstract createGrant(input: GrantInput): Promise<GrantRow>;
  abstract createGrants(
    inputs: readonly Omit<GrantInput, "provenance">[],
    provenance: Provenance,
  ): Promise<GrantRow[]>;
  abstract deleteGrant(grantId: string, provenance: Provenance): Promise<void>;
  abstract listGrants(filter?: GrantQuery): Promise<GrantRow[]>;
  abstract countGrants(filter?: GrantQuery): Promise<number>;
  abstract createRevoke(input: RevokeInput): Promise<RevokeRow>;
  abstract deleteRevoke(revokeId: string, provenance: Provenance): Promise<void>;
  abstract listRevokes(filter?: {
    userId?: string | undefined;
    scope?: ScopeId | undefined;
  }): Promise<RevokeRow[]>;

  // -- Referential cleanup --------------------------------------------------
  abstract deleteSubject(
    subject: SubjectId,
    provenance: Provenance,
  ): Promise<{ deletedGrants: number; deletedRevokes: number }>;
  abstract deleteScope(
    scope: ScopeId,
    provenance: Provenance,
  ): Promise<{ deletedGrants: number; deletedRevokes: number }>;

  // -- Requests -------------------------------------------------------------
  abstract submitRequest(input: RequestInput): Promise<AccessRequest>;
  abstract decideRequest(
    requestId: string,
    decision: {
      deciderUserId: string;
      decision: "approved" | "denied";
      note?: string | undefined;
    },
  ): Promise<AccessRequest>;
  abstract cancelRequest(
    requestId: string,
    byUserId: string,
  ): Promise<AccessRequest>;
  abstract listRequests(filter?: RequestFilter): Promise<AccessRequest[]>;
  abstract listApproverQueue(approverUserId: string): Promise<AccessRequest[]>;

  // -- Catalog registration -------------------------------------------------
  abstract publishCatalog(
    document: CatalogDocument,
    provenance: Provenance,
  ): Promise<{ version: number }>;
  abstract getPublishedCatalog(): Promise<{
    version: number;
    document: CatalogDocument;
  } | null>;

  // -- Import registration (OPTIONAL — gated by `capabilities().imports`) ---
  publishImports?(
    manifest: ImportManifest,
    provenance: Provenance,
  ): Promise<{ version: number }>;
  getPublishedImports?(): Promise<{
    version: number;
    manifest: ImportManifest;
  } | null>;

  // -- Organizational data (rejected when not org root) ---------------------
  abstract listRoles(): Promise<RoleRecord[]>;
  abstract createRole(
    input: RoleInput,
    provenance: Provenance,
  ): Promise<RoleRecord>;
  abstract updateRole(
    roleId: string,
    input: Partial<RoleInput>,
    provenance: Provenance,
  ): Promise<RoleRecord>;
  abstract deleteRole(roleId: string, provenance: Provenance): Promise<void>;

  abstract listGroups(): Promise<UserGroup[]>;
  abstract createGroup(
    input: {
      id?: string | undefined;
      name: string;
      description?: string | undefined;
      parents?: string[] | undefined;
    },
    provenance: Provenance,
  ): Promise<UserGroup>;
  abstract updateGroup(
    groupId: string,
    input: { name?: string | undefined; description?: string | undefined },
    provenance: Provenance,
  ): Promise<UserGroup>;
  abstract setGroupParents(
    groupId: string,
    parents: string[],
    provenance: Provenance,
  ): Promise<UserGroup>;
  abstract deleteGroup(groupId: string, provenance: Provenance): Promise<void>;
  abstract setGroupMembership(
    userId: string,
    groupIds: string[],
    provenance: Provenance,
  ): Promise<void>;
  abstract getGroupMembers(groupId: string): Promise<string[]>;

  abstract setUserActive(
    userId: string,
    active: boolean,
    provenance: Provenance,
  ): Promise<void>;

  abstract setReportingEdge(
    userId: string,
    managerUserId: string | null,
    provenance: Provenance,
  ): Promise<void>;
  abstract getReportingEdges(): Promise<Map<string, string>>;

  abstract dissolveVirtualParent(
    groupId: string,
    provenance: Provenance,
  ): Promise<void>;

  // -- Audit ----------------------------------------------------------------
  abstract listAuditEvents(filter?: AuditQuery): Promise<AuditEvent[]>;

  // -- Metrics (OPTIONAL — gated by `capabilities().metrics`) ---------------
  reportMetrics?(batch: MetricsBatch): Promise<void>;
  getGrantUsage?(query?: UsageQuery): Promise<RowUsage[]>;
  getRevokeUsage?(query?: UsageQuery): Promise<RowUsage[]>;
  getRoleUsage?(query?: UsageQuery): Promise<RowUsage[]>;
  getPermissionUsage?(query?: UsageQuery): Promise<PermissionUsage[]>;
  getScopeTypeUsage?(query?: UsageQuery): Promise<PermissionUsage[]>;
}
