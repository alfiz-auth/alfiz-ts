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
  /** Returns the affected-row count: the caller distinguishes a delete it
   * performed from one a concurrent actor already did. */
  deleteMany(args: { where: { id: string } }): Promise<{ count: number }>;
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
  /** Returns the affected-row count: the caller distinguishes a delete it
   * performed from one a concurrent actor already did. */
  deleteMany(args: { where: { id: string } }): Promise<{ count: number }>;
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

/**
 * The update half of `upsertRole`. Fields are optional, mirroring Prisma's
 * generated update inputs.
 *
 * Unlike the create form, `requestable` is written on EVERY update — a role
 * that lost its requestable policy must have the column cleared, and
 * omitting the field would silently keep the old policy alive, so a
 * de-privileging edit would not de-privilege. Clearing a nullable `Json`
 * column is the one place a client needs its own sentinel
 * (`Prisma.DbNull`), which this package cannot name without taking
 * `@prisma/client` as a dependency; `PrismaDriverOptions.jsonNull` supplies
 * it and the driver casts it at the boundary, alongside its other casts.
 */
export interface AlfizRoleUpdateData {
  name?: string;
  description?: string | null;
  patterns?: InputJsonValue;
  requestable?: InputJsonValue;
}

export interface AlfizRoleDelegate {
  create(args: { data: AlfizRoleCreateData }): Promise<unknown>;
  findUnique(args: { where: { id: string } }): Promise<AlfizRoleRecord | null>;
  /** The batch read behind `getRoles`: `WHERE id IN (...)` when filtered. */
  findMany(args?: { where?: { id?: StringWhere } }): Promise<AlfizRoleRecord[]>;
  /**
   * One atomic statement, so `upsertRole` never has to delete first — the
   * same shape `AlfizGroupDelegate` already uses.
   *
   * Every grant conferring a role denies while that role is unreadable
   * ("unknown roles confer nothing"), so a delete-then-create window was a
   * live authorization outage; a failure between the two halves lost the
   * role outright; and two concurrent writers collided on the primary key.
   */
  upsert(args: {
    where: { id: string };
    create: AlfizRoleCreateData;
    update: AlfizRoleUpdateData;
  }): Promise<unknown>;
  /** Returns the affected-row count: the caller distinguishes a delete it
   * performed from one a concurrent actor already did. */
  deleteMany(args: { where: { id: string } }): Promise<{ count: number }>;
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
  /** Returns the affected-row count: the caller distinguishes a delete it
   * performed from one a concurrent actor already did. */
  deleteMany(args: { where: { id: string } }): Promise<{ count: number }>;
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
// AlfizCatalogVersion (OPTIONAL) — catalog history, one row per publish
// ---------------------------------------------------------------------------

export interface AlfizCatalogVersionRecord {
  version: number;
  document: unknown;
  publishedAt: bigint;
}

export interface AlfizCatalogVersionDelegate {
  upsert(args: {
    where: { version: number };
    create: { version: number; document: InputJsonValue; publishedAt: bigint };
    update: { document: InputJsonValue; publishedAt: bigint };
  }): Promise<unknown>;
  findUnique(args: {
    where: { version: number };
  }): Promise<AlfizCatalogVersionRecord | null>;
  findMany(args?: {
    orderBy?: { version: "asc" };
  }): Promise<AlfizCatalogVersionRecord[]>;
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
  /** `null` unless the writing Application chains audit hashes. */
  prevHash?: string | null;
  hash?: string | null;
}

export interface AlfizAuditCreateData {
  id: string;
  at: bigint;
  actor: string;
  action: string;
  target: string;
  /** Omitted (not `null`) when absent — the column defaults to NULL. */
  detail?: InputJsonValue;
  prevHash?: string;
  hash?: string;
}

/**
 * Exactly the `where` shapes `listAudit` emits: equality filters, an `at`
 * range, and the compound (`at`, `id`) cursor condition expressed through
 * `OR` — each disjunct itself one of these shapes.
 */
export interface AlfizAuditWhere {
  target?: string;
  actor?: string;
  action?: string;
  at?: bigint | { gte?: bigint; lt?: bigint; gt?: bigint };
  id?: { gt?: string };
  OR?: AlfizAuditWhere[];
}

export interface AlfizAuditDelegate {
  create(args: { data: AlfizAuditCreateData }): Promise<unknown>;
  /**
   * Ordered reads: ascending by (`at`, `id`), with Prisma's negative-`take`
   * convention ("last N of the ordered result") for audit tail reads and a
   * compound (`at`, `id`) cursor condition for export paging.
   */
  findMany(args?: {
    where?: AlfizAuditWhere;
    orderBy?: { at: "asc"; id?: "asc" } | Array<{ at?: "asc"; id?: "asc" }>;
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
   * OPTIONAL — present when the schema includes the AlfizCatalogVersion
   * model. A client generated without it still satisfies this interface;
   * the driver then keeps only the catalog head, and the wildcard-drift
   * report answers `unsupported` instead of wrongly.
   */
  alfizCatalogVersion?: AlfizCatalogVersionDelegate;
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
