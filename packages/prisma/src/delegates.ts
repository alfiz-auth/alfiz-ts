/**
 * The structural Prisma surface: the exact subset of a generated Prisma
 * client the driver calls, written out as plain interfaces so `@prisma/client`
 * is NOT a dependency of this package. Any client generated from the schema
 * fragment in `prisma/schema.prisma` satisfies `AlfizPrismaDelegates`
 * structurally — pass the `PrismaClient` instance straight to `prismaDriver`.
 * So does the in-memory mock the test suite uses.
 *
 * Deliberately narrow:
 *   - Where-clauses are equality and `{ in: [...] }` only, so every query
 *     shape stays portable across databases (and trivially mockable).
 *   - Json columns read back as `unknown` — the driver casts at the boundary
 *     with dedicated helpers; no `any` anywhere.
 *   - BigInt columns are `bigint` on both sides; nullable columns are
 *     `T | null`, never `undefined` (Prisma's convention). Optional Json
 *     columns are OMITTED from create data when absent (Prisma requires a
 *     sentinel, not plain `null`, to write SQL NULL into a Json column).
 *   - Optional properties are declared Prisma-style (`prop?: T`, no explicit
 *     `| undefined`), so the structural match also holds for adopters
 *     compiling with `exactOptionalPropertyTypes`.
 */

/** A JSON value as read back from a Json column. */
export type JsonValue =
  | string
  | number
  | boolean
  | null
  | JsonValue[]
  | { [key: string]: JsonValue };

/**
 * A JSON value as WRITTEN to a Json column: everything except bare `null`.
 * Prisma's create/update inputs reject top-level `null` — writing SQL NULL
 * requires the `Prisma.JsonNull` sentinel, so the driver OMITS optional Json
 * fields instead (nested nulls are fine). Keeping the create-data fields
 * this narrow is what makes a generated `PrismaClient` satisfy
 * `AlfizPrismaDelegates` structurally, with no cast — the package's headline
 * promise, pinned by `prisma-client-shape.ts`.
 */
export type InputJsonValue = Exclude<JsonValue, null>;

/** The only string conditions the driver uses: equality or membership. */
export type StringWhere = string | { in: string[] };

// ---------------------------------------------------------------------------
// AlfizGrant
// ---------------------------------------------------------------------------

export interface AlfizGrantRecord {
  id: string;
  subject: string;
  roleId: string | null;
  pattern: string | null;
  scope: string;
  expiresAt: bigint | null;
  provenance: unknown;
  createdAt: bigint;
}

export interface AlfizGrantCreateData {
  id: string;
  subject: string;
  roleId: string | null;
  pattern: string | null;
  scope: string;
  expiresAt: bigint | null;
  provenance: InputJsonValue;
  createdAt: bigint;
}

export interface AlfizGrantWhere {
  subject?: StringWhere;
  scope?: string;
  roleId?: string;
}

export interface AlfizGrantDelegate {
  create(args: { data: AlfizGrantCreateData }): Promise<unknown>;
  findUnique(args: { where: { id: string } }): Promise<AlfizGrantRecord | null>;
  findMany(args?: { where?: AlfizGrantWhere }): Promise<AlfizGrantRecord[]>;
  /** `SELECT count(*)`: sizing a grant set without materializing it. */
  count(args?: { where?: AlfizGrantWhere }): Promise<number>;
  deleteMany(args: { where: { id: string } }): Promise<unknown>;
}

// ---------------------------------------------------------------------------
// AlfizRevoke
// ---------------------------------------------------------------------------

export interface AlfizRevokeRecord {
  id: string;
  userId: string;
  pattern: string;
  scope: string;
  provenance: unknown;
  createdAt: bigint;
}

export interface AlfizRevokeCreateData {
  id: string;
  userId: string;
  pattern: string;
  scope: string;
  provenance: InputJsonValue;
  createdAt: bigint;
}

export interface AlfizRevokeWhere {
  userId?: string;
  scope?: string;
}

export interface AlfizRevokeDelegate {
  create(args: { data: AlfizRevokeCreateData }): Promise<unknown>;
  findUnique(args: { where: { id: string } }): Promise<AlfizRevokeRecord | null>;
  findMany(args?: { where?: AlfizRevokeWhere }): Promise<AlfizRevokeRecord[]>;
  deleteMany(args: { where: { id: string } }): Promise<unknown>;
}

// ---------------------------------------------------------------------------
// AlfizRole
// ---------------------------------------------------------------------------

export interface AlfizRoleRecord {
  id: string;
  name: string;
  description: string | null;
  patterns: unknown;
  /** `null` when the role is not requestable. */
  requestable: unknown;
}

export interface AlfizRoleCreateData {
  id: string;
  name: string;
  description: string | null;
  patterns: InputJsonValue;
  /** Omitted (not `null`) when absent — the column defaults to NULL. */
  requestable?: InputJsonValue;
}

export interface AlfizRoleDelegate {
  create(args: { data: AlfizRoleCreateData }): Promise<unknown>;
  findUnique(args: { where: { id: string } }): Promise<AlfizRoleRecord | null>;
  /** The batch read behind `getRoles`: `WHERE id IN (...)` when filtered. */
  findMany(args?: { where?: { id?: StringWhere } }): Promise<AlfizRoleRecord[]>;
  deleteMany(args: { where: { id: string } }): Promise<unknown>;
}

// ---------------------------------------------------------------------------
// AlfizGroup + AlfizGroupParent
// ---------------------------------------------------------------------------

export interface AlfizGroupRecord {
  id: string;
  name: string;
  description: string | null;
  virtual: boolean;
}

export interface AlfizGroupData {
  name: string;
  description: string | null;
  virtual: boolean;
}

export interface AlfizGroupDelegate {
  upsert(args: {
    where: { id: string };
    create: AlfizGroupData & { id: string };
    update: AlfizGroupData;
  }): Promise<unknown>;
  findUnique(args: { where: { id: string } }): Promise<AlfizGroupRecord | null>;
  findMany(): Promise<AlfizGroupRecord[]>;
  deleteMany(args: { where: { id: string } }): Promise<unknown>;
}

export interface AlfizGroupParentRecord {
  childId: string;
  parentId: string;
}

export interface AlfizGroupParentWhere {
  childId?: StringWhere;
  parentId?: StringWhere;
}

export interface AlfizGroupParentDelegate {
  findMany(args?: { where?: AlfizGroupParentWhere }): Promise<AlfizGroupParentRecord[]>;
  createMany(args: { data: AlfizGroupParentRecord[] }): Promise<unknown>;
  deleteMany(args: { where: AlfizGroupParentWhere }): Promise<unknown>;
}

// ---------------------------------------------------------------------------
// AlfizUser + AlfizMembership
// ---------------------------------------------------------------------------

export interface AlfizUserRecord {
  userId: string;
  active: boolean;
  orgIds: unknown;
  managerUserId: string | null;
}

export interface AlfizUserData {
  active: boolean;
  orgIds: InputJsonValue;
  managerUserId: string | null;
}

export interface AlfizUserDelegate {
  upsert(args: {
    where: { userId: string };
    create: AlfizUserData & { userId: string };
    update: AlfizUserData;
  }): Promise<unknown>;
  findUnique(args: { where: { userId: string } }): Promise<AlfizUserRecord | null>;
  findMany(): Promise<AlfizUserRecord[]>;
  /** deleteMany, not delete: Prisma's `delete` throws on absent rows and the seam wants a no-op. */
  deleteMany(args: { where: { userId: string } }): Promise<unknown>;
}

export interface AlfizMembershipRecord {
  userId: string;
  groupId: string;
}

export interface AlfizMembershipWhere {
  userId?: StringWhere;
  groupId?: StringWhere;
}

export interface AlfizMembershipDelegate {
  findMany(args?: { where?: AlfizMembershipWhere }): Promise<AlfizMembershipRecord[]>;
  createMany(args: { data: AlfizMembershipRecord[] }): Promise<unknown>;
  deleteMany(args: { where: AlfizMembershipWhere }): Promise<unknown>;
}

// ---------------------------------------------------------------------------
// AlfizRequest
// ---------------------------------------------------------------------------

export interface AlfizRequestRecord {
  id: string;
  requesterUserId: string;
  roleId: string | null;
  pattern: string | null;
  scope: string;
  proposedExpiresAt: bigint | null;
  justification: unknown;
  state: string;
  stageIndex: number;
  stages: unknown;
  decisions: unknown;
  createdAt: bigint;
  decidedAt: bigint | null;
}

export interface AlfizRequestData {
  requesterUserId: string;
  roleId: string | null;
  pattern: string | null;
  scope: string;
  proposedExpiresAt: bigint | null;
  justification: InputJsonValue;
  state: string;
  stageIndex: number;
  stages: InputJsonValue;
  decisions: InputJsonValue;
  createdAt: bigint;
  decidedAt: bigint | null;
}

export interface AlfizRequestWhere {
  state?: string;
  requesterUserId?: string;
}

export interface AlfizRequestDelegate {
  create(args: { data: AlfizRequestData & { id: string } }): Promise<unknown>;
  upsert(args: {
    where: { id: string };
    create: AlfizRequestData & { id: string };
    update: AlfizRequestData;
  }): Promise<unknown>;
  findUnique(args: { where: { id: string } }): Promise<AlfizRequestRecord | null>;
  findMany(args?: { where?: AlfizRequestWhere }): Promise<AlfizRequestRecord[]>;
}

// ---------------------------------------------------------------------------
// AlfizCatalog (versioned singleton, id = 1)
// ---------------------------------------------------------------------------

export interface AlfizCatalogRecord {
  id: number;
  version: number;
  document: unknown;
}

export interface AlfizCatalogDelegate {
  upsert(args: {
    where: { id: number };
    create: { id: number; version: number; document: InputJsonValue };
    update: { version: number; document: InputJsonValue };
  }): Promise<unknown>;
  findUnique(args: { where: { id: number } }): Promise<AlfizCatalogRecord | null>;
}

// ---------------------------------------------------------------------------
// AlfizImports (versioned singleton, id = 1) — what the application CONSUMES
// ---------------------------------------------------------------------------

export interface AlfizImportsRecord {
  id: number;
  version: number;
  manifest: unknown;
}

export interface AlfizImportsDelegate {
  upsert(args: {
    where: { id: number };
    create: { id: number; version: number; manifest: InputJsonValue };
    update: { version: number; manifest: InputJsonValue };
  }): Promise<unknown>;
  findUnique(args: { where: { id: number } }): Promise<AlfizImportsRecord | null>;
}

// ---------------------------------------------------------------------------
// AlfizAudit
// ---------------------------------------------------------------------------

export interface AlfizAuditRecord {
  id: string;
  at: bigint;
  actor: string;
  action: string;
  target: string;
  /** `null` when the event carries no detail. */
  detail: unknown;
}

export interface AlfizAuditCreateData {
  id: string;
  at: bigint;
  actor: string;
  action: string;
  target: string;
  /** Omitted (not `null`) when absent — the column defaults to NULL. */
  detail?: InputJsonValue;
}

export interface AlfizAuditDelegate {
  create(args: { data: AlfizAuditCreateData }): Promise<unknown>;
  /**
   * The one ordered query: ascending by `at`, with Prisma's negative-`take`
   * convention ("last N of the ordered result") for audit tail reads.
   */
  findMany(args?: {
    where?: { target?: string };
    orderBy?: { at: "asc" };
    take?: number;
  }): Promise<AlfizAuditRecord[]>;
}

// ---------------------------------------------------------------------------
// AlfizEpoch + AlfizEvent (the persisted invalidation log)
// ---------------------------------------------------------------------------

export interface AlfizEpochRecord {
  id: number;
  seq: bigint;
  prunedThrough: bigint;
}

export interface AlfizEpochDelegate {
  upsert(args: {
    where: { id: number };
    create: { id: number; seq: bigint; prunedThrough: bigint };
    update: Record<string, never>;
  }): Promise<unknown>;
  /** Atomic head advance: increment and read back in one statement. */
  update(args: {
    where: { id: number };
    data:
      | { seq: { increment: bigint } }
      | { prunedThrough: bigint };
  }): Promise<AlfizEpochRecord>;
  findUnique(args: { where: { id: number } }): Promise<AlfizEpochRecord | null>;
}

export interface AlfizEventRecord {
  seq: bigint;
  type: string;
  payload: unknown;
  at: bigint;
}

export interface AlfizEventCreateData {
  seq: bigint;
  type: string;
  payload: InputJsonValue;
  at: bigint;
}

export interface AlfizEventDelegate {
  createMany(args: { data: AlfizEventCreateData[] }): Promise<unknown>;
  findMany(args: {
    where: { seq: { gt: bigint } };
    orderBy: { seq: "asc" };
    take?: number;
  }): Promise<AlfizEventRecord[]>;
  /** Newest event older than a cutoff — sizing a prune without a scan. */
  findFirst(args: {
    where: { at: { lt: bigint } };
    orderBy: { seq: "desc" };
  }): Promise<AlfizEventRecord | null>;
  deleteMany(args: { where: { seq: { lte: bigint } } }): Promise<{
    count: number;
  }>;
}

// ---------------------------------------------------------------------------
// AlfizMetric (rolling permission-usage buckets)
// ---------------------------------------------------------------------------

export interface AlfizMetricRecord {
  bucket: bigint;
  dimension: string;
  subject: string;
  metric: string;
  count: bigint;
}

/** The composite identity of a bucket — Prisma's generated `@@id` input. */
export interface AlfizMetricWhereUnique {
  bucket_dimension_subject_metric: {
    bucket: bigint;
    dimension: string;
    subject: string;
    metric: string;
  };
}

export interface AlfizMetricWhere {
  dimension?: string;
  subject?: { in: string[] };
  bucket?: { gte?: bigint; lt?: bigint };
}

export interface AlfizMetricDelegate {
  /**
   * Increment-or-create. Counters ACCUMULATE across every app server
   * reporting into the same bucket, which is what makes the numbers
   * deployment-wide rather than per-process.
   */
  upsert(args: {
    where: AlfizMetricWhereUnique;
    create: AlfizMetricRecord;
    update: { count: { increment: bigint } };
  }): Promise<unknown>;
  findMany(args: { where: AlfizMetricWhere }): Promise<AlfizMetricRecord[]>;
  deleteMany(args: { where: { bucket: { lt: bigint } } }): Promise<{
    count: number;
  }>;
}

// ---------------------------------------------------------------------------
// The full delegate bundle
// ---------------------------------------------------------------------------

/**
 * Everything `prismaDriver` needs from a Prisma client. A generated
 * `PrismaClient` for a schema containing the Alfiz models satisfies this
 * structurally; no `@prisma/client` import required.
 */
export interface AlfizPrismaDelegates {
  alfizGrant: AlfizGrantDelegate;
  alfizRevoke: AlfizRevokeDelegate;
  alfizRole: AlfizRoleDelegate;
  alfizGroup: AlfizGroupDelegate;
  alfizGroupParent: AlfizGroupParentDelegate;
  alfizUser: AlfizUserDelegate;
  alfizMembership: AlfizMembershipDelegate;
  alfizRequest: AlfizRequestDelegate;
  alfizCatalog: AlfizCatalogDelegate;
  alfizAudit: AlfizAuditDelegate;
  /**
   * OPTIONAL — present when the schema includes the AlfizImports model. A
   * client generated without it still satisfies this interface; the driver
   * then omits the import methods and `capabilities().imports` is false.
   */
  alfizImports?: AlfizImportsDelegate;
  /**
   * OPTIONAL — present when the schema includes the AlfizEpoch/AlfizEvent
   * models (the persisted invalidation log). A client generated without
   * them still satisfies this interface; the driver then simply omits the
   * event methods, and `events.persist` on the Application refuses loudly.
   */
  alfizEpoch?: AlfizEpochDelegate;
  alfizEvent?: AlfizEventDelegate;
  /**
   * OPTIONAL — present when the schema includes the AlfizMetric model
   * (rolling permission-usage buckets). Absent, the driver omits the metric
   * methods and the Application refuses `metrics` loudly rather than
   * accepting batches that go nowhere.
   */
  alfizMetric?: AlfizMetricDelegate;
}
