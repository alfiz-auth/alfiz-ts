/**
 * The storage seam: the one interface a database must satisfy to host an
 * Alfiz Application. Implement it over Prisma (@alfiz-auth/prisma), raw SQL,
 * Mongo, or anything else — the Application's semantics (graph integrity,
 * request workflows, org-root gating, audit) live above this line and are
 * identical over every driver.
 *
 * Drivers store and retrieve; they never interpret. All ids are assigned by
 * the Application.
 */

import type {
  AccessRequest,
  AuditEvent,
  CatalogDocument,
  GrantRow,
  RevokeRow,
  RoleRecord,
  ScopeId,
  SubjectId,
  UserGroup,
} from "@alfiz-auth/core";

/**
 * The authorization-relevant user record. Identity (profile, sessions,
 * invitations) deliberately stays in the identity provider; Alfiz stores
 * only provider ids and the organizational links keyed to them.
 */
export interface StoredUser {
  userId: string;
  active: boolean;
  /** Explicit group memberships, stored on the user record. */
  groupIds: string[];
  /** Identity-provider organization memberships. */
  orgIds: string[];
  /** The reports-to edge; `null` at the top of a chain. */
  managerUserId: string | null;
}

export interface GrantFilter {
  subjects?: readonly SubjectId[] | undefined;
  subject?: SubjectId | undefined;
  scope?: ScopeId | undefined;
  roleId?: string | undefined;
}

export interface RevokeFilter {
  userId?: string | undefined;
  scope?: ScopeId | undefined;
}

export interface RequestStorageFilter {
  state?: AccessRequest["state"] | undefined;
  requesterUserId?: string | undefined;
}

export interface AuditFilter {
  target?: string | undefined;
  limit?: number | undefined;
}

export interface StorageDriver {
  // -- grants ---------------------------------------------------------------
  insertGrant(row: GrantRow): Promise<void>;
  /** Returns the deleted row, or null when absent. */
  deleteGrant(id: string): Promise<GrantRow | null>;
  listGrants(filter?: GrantFilter): Promise<GrantRow[]>;

  // -- revokes --------------------------------------------------------------
  insertRevoke(row: RevokeRow): Promise<void>;
  deleteRevoke(id: string): Promise<RevokeRow | null>;
  listRevokes(filter?: RevokeFilter): Promise<RevokeRow[]>;

  // -- roles ----------------------------------------------------------------
  upsertRole(role: RoleRecord): Promise<void>;
  getRole(id: string): Promise<RoleRecord | null>;
  listRoles(): Promise<RoleRecord[]>;
  deleteRole(id: string): Promise<void>;

  // -- groups ---------------------------------------------------------------
  upsertGroup(group: UserGroup): Promise<void>;
  getGroup(id: string): Promise<UserGroup | null>;
  listGroups(): Promise<UserGroup[]>;
  deleteGroup(id: string): Promise<void>;

  // -- users ----------------------------------------------------------------
  getUser(userId: string): Promise<StoredUser | null>;
  upsertUser(user: StoredUser): Promise<void>;
  /** Removes the user record and its membership edges. A no-op when absent. */
  deleteUser(userId: string): Promise<void>;
  listUsers(): Promise<StoredUser[]>;
  listUsersInGroup(groupId: string): Promise<string[]>;

  // -- requests -------------------------------------------------------------
  insertRequest(request: AccessRequest): Promise<void>;
  updateRequest(request: AccessRequest): Promise<void>;
  getRequest(id: string): Promise<AccessRequest | null>;
  listRequests(filter?: RequestStorageFilter): Promise<AccessRequest[]>;

  // -- catalog --------------------------------------------------------------
  putCatalog(version: number, document: CatalogDocument): Promise<void>;
  getCatalog(): Promise<{ version: number; document: CatalogDocument } | null>;

  // -- audit ----------------------------------------------------------------
  appendAudit(event: AuditEvent): Promise<void>;
  listAudit(filter?: AuditFilter): Promise<AuditEvent[]>;

  /**
   * Serialize graph writes: two concurrent edge insertions can each be
   * individually cycle-free while jointly forming a cycle, so edge writes
   * are serialized per graph key (`"groups"`, `"reporting"`, …). Implement
   * with an advisory lock (SQL) or a mutex (in-process).
   */
  runExclusive<T>(key: string, fn: () => Promise<T>): Promise<T>;
}
