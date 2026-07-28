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
  InvalidationEvent,
  MetricBucket,
  MetricBucketDelta,
  MetricBucketQuery,
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
  /**
   * Matching rows, counted in the database rather than in memory — push
   * `SELECT count(*)` down instead of materializing every grant to size a
   * set (role-holder counts on an admin page).
   */
  countGrants(filter?: GrantFilter): Promise<number>;

  // -- revokes --------------------------------------------------------------
  insertRevoke(row: RevokeRow): Promise<void>;
  deleteRevoke(id: string): Promise<RevokeRow | null>;
  listRevokes(filter?: RevokeFilter): Promise<RevokeRow[]>;

  // -- roles ----------------------------------------------------------------
  upsertRole(role: RoleRecord): Promise<void>;
  getRole(id: string): Promise<RoleRecord | null>;
  /**
   * OPTIONAL batch read: the roles matching `ids`, in any order, absent ids
   * simply missing from the result. Closure supply resolves every role a
   * grant set references; a driver that implements this turns that into one
   * `WHERE id IN (...)` query instead of a read per id. Omit it and the
   * Application falls back to parallel `getRole` calls.
   */
  getRoles?(ids: readonly string[]): Promise<RoleRecord[]>;
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

  // -- invalidation events (OPTIONAL — the persisted-event log) -------------
  // Implementing all four enables `events.persist` on the Application: the
  // same invalidation events the in-process stream carries, durable with a
  // monotonic sequence, so OTHER processes can revalidate their caches with
  // one tiny read (`headSeq`) instead of trusting a TTL. Sequence numbers
  // are contiguous and assigned by the driver under `runExclusive`.

  /**
   * Appends `events` (in order) at the head of the log, atomically advancing
   * the sequence. Returns the sequence of the last appended event.
   */
  appendEvents?(
    events: readonly InvalidationEvent[],
    at: number,
  ): Promise<{ upTo: number }>;
  /** The sequence of the newest persisted event; 0 when the log is empty. */
  headSeq?(): Promise<number>;
  /**
   * Events with sequence greater than `seq`, oldest first, at most `limit`.
   * `{ gap: true }` when `seq` predates retention (pruned away) — the
   * caller must fall back to a full bust.
   */
  eventsSince?(
    seq: number,
    limit: number,
  ): Promise<{ upTo: number; events: InvalidationEvent[] } | { gap: true }>;
  /**
   * Deletes events older than `cutoff.at` (epoch ms) and/or beyond the
   * newest `cutoff.keepRows`, recording the pruned-through sequence so
   * `eventsSince` can report gaps. Returns the number deleted.
   */
  pruneEvents?(cutoff: {
    at?: number | undefined;
    keepRows?: number | undefined;
  }): Promise<number>;

  // -- metrics (OPTIONAL — the rolling usage buckets) -----------------------
  // Implementing all three enables `metrics` on the Application: aggregated
  // check counts, bucketed by time and keyed by grant id, revoke id, role
  // id, permission key, or scope type. Storage is bounded by
  // (attributed rows × retention buckets), writes arrive pre-aggregated and
  // batched off the request path, and retention compaction is a delete.
  //
  // Counters ACCUMULATE: `recordMetrics` increments, it does not replace.
  // Many app servers report into the same buckets and their counts sum,
  // which is what makes the numbers whole-deployment numbers.

  /**
   * Applies a batch of counter increments, creating rows that do not exist.
   * One statement per bucket at worst; an upsert-with-increment where the
   * database has one.
   */
  recordMetrics?(deltas: readonly MetricBucketDelta[]): Promise<void>;
  /** Buckets matching the query, in any order. */
  readMetrics?(query: MetricBucketQuery): Promise<MetricBucket[]>;
  /** Deletes buckets starting before `before` (epoch ms). Returns the count. */
  pruneMetrics?(before: number): Promise<number>;

  /**
   * Serialize graph writes: two concurrent edge insertions can each be
   * individually cycle-free while jointly forming a cycle, so edge writes
   * are serialized per graph key (`"groups"`, `"reporting"`, …). Implement
   * with an advisory lock (SQL) or a mutex (in-process).
   */
  runExclusive<T>(key: string, fn: () => Promise<T>): Promise<T>;
}
