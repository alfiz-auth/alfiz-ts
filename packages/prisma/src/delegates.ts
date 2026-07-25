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
 */

/** A JSON value as stored in (and written to) a Json column. */
export type JsonValue =
  | string
  | number
  | boolean
  | null
  | JsonValue[]
  | { [key: string]: JsonValue };

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
  provenance: JsonValue;
  createdAt: bigint;
}

export interface AlfizGrantWhere {
  subject?: StringWhere | undefined;
  scope?: string | undefined;
  roleId?: string | undefined;
}

export interface AlfizGrantDelegate {
  create(args: { data: AlfizGrantCreateData }): Promise<unknown>;
  findUnique(args: { where: { id: string } }): Promise<AlfizGrantRecord | null>;
  findMany(args?: { where?: AlfizGrantWhere | undefined }): Promise<AlfizGrantRecord[]>;
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
  provenance: JsonValue;
  createdAt: bigint;
}

export interface AlfizRevokeDelegate {
  create(args: { data: AlfizRevokeCreateData }): Promise<unknown>;
  findUnique(args: { where: { id: string } }): Promise<AlfizRevokeRecord | null>;
  findMany(args?: {
    where?: { userId?: string | undefined } | undefined;
  }): Promise<AlfizRevokeRecord[]>;
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
  patterns: JsonValue;
  /** Omitted (not `null`) when absent — the column defaults to NULL. */
  requestable?: JsonValue | undefined;
}

export interface AlfizRoleDelegate {
  create(args: { data: AlfizRoleCreateData }): Promise<unknown>;
  findUnique(args: { where: { id: string } }): Promise<AlfizRoleRecord | null>;
  findMany(): Promise<AlfizRoleRecord[]>;
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
  childId?: StringWhere | undefined;
  parentId?: StringWhere | undefined;
}

export interface AlfizGroupParentDelegate {
  findMany(args?: {
    where?: AlfizGroupParentWhere | undefined;
  }): Promise<AlfizGroupParentRecord[]>;
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
  orgIds: JsonValue;
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
}

export interface AlfizMembershipRecord {
  userId: string;
  groupId: string;
}

export interface AlfizMembershipWhere {
  userId?: StringWhere | undefined;
  groupId?: StringWhere | undefined;
}

export interface AlfizMembershipDelegate {
  findMany(args?: {
    where?: AlfizMembershipWhere | undefined;
  }): Promise<AlfizMembershipRecord[]>;
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
  justification: JsonValue;
  state: string;
  stageIndex: number;
  stages: JsonValue;
  decisions: JsonValue;
  createdAt: bigint;
  decidedAt: bigint | null;
}

export interface AlfizRequestWhere {
  state?: string | undefined;
  requesterUserId?: string | undefined;
}

export interface AlfizRequestDelegate {
  create(args: { data: AlfizRequestData & { id: string } }): Promise<unknown>;
  upsert(args: {
    where: { id: string };
    create: AlfizRequestData & { id: string };
    update: AlfizRequestData;
  }): Promise<unknown>;
  findUnique(args: { where: { id: string } }): Promise<AlfizRequestRecord | null>;
  findMany(args?: {
    where?: AlfizRequestWhere | undefined;
  }): Promise<AlfizRequestRecord[]>;
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
    create: { id: number; version: number; document: JsonValue };
    update: { version: number; document: JsonValue };
  }): Promise<unknown>;
  findUnique(args: { where: { id: number } }): Promise<AlfizCatalogRecord | null>;
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
  detail?: JsonValue | undefined;
}

export interface AlfizAuditDelegate {
  create(args: { data: AlfizAuditCreateData }): Promise<unknown>;
  /**
   * The one ordered query: ascending by `at`, with Prisma's negative-`take`
   * convention ("last N of the ordered result") for audit tail reads.
   */
  findMany(args?: {
    where?: { target?: string | undefined } | undefined;
    orderBy?: { at: "asc" } | undefined;
    take?: number | undefined;
  }): Promise<AlfizAuditRecord[]>;
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
}
