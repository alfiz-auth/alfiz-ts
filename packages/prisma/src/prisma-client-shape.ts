/**
 * COMPILE-ONLY fixture — no runtime exports, nothing to import.
 *
 * The package's headline promise is that a client generated from
 * `prisma/schema.prisma` satisfies {@link AlfizPrismaDelegates}
 * structurally, with no cast. That promise once broke silently: our create
 * data used a Json type admitting bare `null`, which Prisma's generated
 * inputs reject (SQL NULL needs the `Prisma.JsonNull` sentinel), and every
 * adopter got `prismaDriver(db as unknown as AlfizPrismaDelegates)` — the
 * exact cast the README calls unnecessary.
 *
 * This file replicates the input/output types Prisma 7 generates for the
 * Alfiz models — the Json input plumbing verbatim (`JsonNullClass`,
 * `InputJsonValue` with nested nulls and `toJSON`), scalar unions
 * (`bigint | number`), create-input optionality, filter objects — and
 * asserts assignability at the type level. If a delegate-surface change
 * breaks compatibility with what `prisma generate` emits, `tsc` fails here,
 * naming the model. Deliberately simplified: `select`/`include`/`omit`
 * plumbing and extension generics are elided, because compatibility breaks
 * live in the input types, not the selection machinery.
 */

import type {
  AlfizGrantCreateData,
  AlfizPrismaDelegates,
  AlfizRequestData,
  AlfizRevokeCreateData,
  AlfizRoleCreateData,
  InputJsonValue,
  JsonValue,
} from "./delegates.js";

// ---------------------------------------------------------------------------
// Prisma 7's Json input plumbing, replicated
// ---------------------------------------------------------------------------

declare class P7JsonNullClass {
  private readonly _brand_JsonNull: "JsonNull";
}
declare class P7DbNullClass {
  private readonly _brand_DbNull: "DbNull";
}

/** Required Json columns: value or the JSON-null sentinel — never bare null. */
type P7JsonNullValueInput = P7JsonNullClass;
/** Optional Json columns: value, JSON-null, or SQL-NULL sentinel. */
type P7NullableJsonNullValueInput = P7JsonNullClass | P7DbNullClass;

interface P7InputJsonObject {
  readonly [key: string]: P7InputJsonValue | null;
}
interface P7InputJsonArray extends ReadonlyArray<P7InputJsonValue | null> {}
type P7InputJsonValue =
  | string
  | number
  | boolean
  | P7InputJsonObject
  | P7InputJsonArray
  | { toJSON(): unknown };

type P7JsonObject = { [key in string]?: P7JsonValue };
interface P7JsonArray extends Array<P7JsonValue> {}
type P7JsonValue = string | number | boolean | P7JsonObject | P7JsonArray | null;

// ---------------------------------------------------------------------------
// Filter objects (the subset relevant to the driver's where-clauses)
// ---------------------------------------------------------------------------

interface P7StringFilter {
  equals?: string;
  in?: string[];
  notIn?: string[];
  lt?: string;
  lte?: string;
  gt?: string;
  gte?: string;
  contains?: string;
  startsWith?: string;
  endsWith?: string;
  not?: P7StringFilter | string;
}

interface P7StringNullableFilter {
  equals?: string | null;
  in?: string[] | null;
  notIn?: string[] | null;
  not?: P7StringNullableFilter | string | null;
}

interface P7IntFilter {
  equals?: number;
  in?: number[];
  lt?: number;
  lte?: number;
  gt?: number;
  gte?: number;
}

interface P7BigIntFilter {
  equals?: bigint | number;
  in?: bigint[] | number[];
  lt?: bigint | number;
  lte?: bigint | number;
  gt?: bigint | number;
  gte?: bigint | number;
}

type P7SortOrder = "asc" | "desc";

/** Prisma's WhereUniqueInput acceptance shape: the unique key, rest optional. */
type P7AtLeast<O, K extends keyof O> = Partial<O> & Required<Pick<O, K>>;

type P7Where<Fields> = Fields & {
  AND?: P7Where<Fields> | P7Where<Fields>[];
  OR?: P7Where<Fields>[];
  NOT?: P7Where<Fields> | P7Where<Fields>[];
};

interface P7BatchPayload {
  count: number;
}

// ---------------------------------------------------------------------------
// AlfizGrant, as generated
// ---------------------------------------------------------------------------

interface P7GrantPayload {
  id: string;
  subject: string;
  roleId: string | null;
  pattern: string | null;
  scope: string;
  expiresAt: bigint | null;
  provenance: P7JsonValue;
  createdAt: bigint;
}

interface P7GrantCreateInput {
  id: string;
  subject: string;
  roleId?: string | null;
  pattern?: string | null;
  scope: string;
  expiresAt?: bigint | number | null;
  provenance: P7JsonNullValueInput | P7InputJsonValue;
  createdAt: bigint | number;
}

type P7GrantWhereInput = P7Where<{
  id?: P7StringFilter | string;
  subject?: P7StringFilter | string;
  roleId?: P7StringNullableFilter | string | null;
  pattern?: P7StringNullableFilter | string | null;
  scope?: P7StringFilter | string;
}>;

type P7GrantWhereUniqueInput = P7AtLeast<{ id: string }, "id">;

interface P7GrantDelegate {
  create(args: {
    data: P7GrantCreateInput;
    select?: unknown;
    omit?: unknown;
  }): Promise<P7GrantPayload>;
  findUnique(args: {
    where: P7GrantWhereUniqueInput;
    select?: unknown;
    omit?: unknown;
  }): Promise<P7GrantPayload | null>;
  findMany(args?: {
    where?: P7GrantWhereInput;
    orderBy?: unknown;
    take?: number;
    skip?: number;
    select?: unknown;
  }): Promise<P7GrantPayload[]>;
  deleteMany(args?: { where?: P7GrantWhereInput }): Promise<P7BatchPayload>;
  update(args: unknown): Promise<P7GrantPayload>;
  count(args?: unknown): Promise<number>;
}

// ---------------------------------------------------------------------------
// AlfizRevoke
// ---------------------------------------------------------------------------

interface P7RevokePayload {
  id: string;
  userId: string;
  pattern: string;
  scope: string;
  provenance: P7JsonValue;
  createdAt: bigint;
}

interface P7RevokeCreateInput {
  id: string;
  userId: string;
  pattern: string;
  scope: string;
  provenance: P7JsonNullValueInput | P7InputJsonValue;
  createdAt: bigint | number;
}

type P7RevokeWhereInput = P7Where<{
  id?: P7StringFilter | string;
  userId?: P7StringFilter | string;
  pattern?: P7StringFilter | string;
  scope?: P7StringFilter | string;
}>;

interface P7RevokeDelegate {
  create(args: {
    data: P7RevokeCreateInput;
    select?: unknown;
  }): Promise<P7RevokePayload>;
  findUnique(args: {
    where: P7AtLeast<{ id: string }, "id">;
    select?: unknown;
  }): Promise<P7RevokePayload | null>;
  findMany(args?: {
    where?: P7RevokeWhereInput;
    orderBy?: unknown;
    take?: number;
  }): Promise<P7RevokePayload[]>;
  deleteMany(args?: { where?: P7RevokeWhereInput }): Promise<P7BatchPayload>;
  count(args?: unknown): Promise<number>;
}

// ---------------------------------------------------------------------------
// AlfizRole
// ---------------------------------------------------------------------------

interface P7RolePayload {
  id: string;
  name: string;
  description: string | null;
  patterns: P7JsonValue;
  requestable: P7JsonValue | null;
}

interface P7RoleCreateInput {
  id: string;
  name: string;
  description?: string | null;
  patterns: P7JsonNullValueInput | P7InputJsonValue;
  requestable?: P7NullableJsonNullValueInput | P7InputJsonValue;
}

type P7RoleWhereInput = P7Where<{
  id?: P7StringFilter | string;
  name?: P7StringFilter | string;
}>;

interface P7RoleDelegate {
  create(args: {
    data: P7RoleCreateInput;
    select?: unknown;
  }): Promise<P7RolePayload>;
  findUnique(args: {
    where: P7AtLeast<{ id: string }, "id">;
    select?: unknown;
  }): Promise<P7RolePayload | null>;
  findMany(args?: {
    where?: P7RoleWhereInput;
    orderBy?: unknown;
  }): Promise<P7RolePayload[]>;
  deleteMany(args?: { where?: P7RoleWhereInput }): Promise<P7BatchPayload>;
}

// ---------------------------------------------------------------------------
// AlfizGroup + AlfizGroupParent
// ---------------------------------------------------------------------------

interface P7GroupPayload {
  id: string;
  name: string;
  description: string | null;
  virtual: boolean;
}

interface P7GroupCreateInput {
  id: string;
  name: string;
  description?: string | null;
  virtual?: boolean;
}

interface P7GroupUpdateInput {
  name?: string;
  description?: string | null;
  virtual?: boolean;
}

interface P7GroupDelegate {
  upsert(args: {
    where: P7AtLeast<{ id: string }, "id">;
    create: P7GroupCreateInput;
    update: P7GroupUpdateInput;
    select?: unknown;
  }): Promise<P7GroupPayload>;
  findUnique(args: {
    where: P7AtLeast<{ id: string }, "id">;
    select?: unknown;
  }): Promise<P7GroupPayload | null>;
  findMany(args?: { where?: unknown }): Promise<P7GroupPayload[]>;
  deleteMany(args?: { where?: unknown }): Promise<P7BatchPayload>;
}

interface P7GroupParentPayload {
  childId: string;
  parentId: string;
}

type P7GroupParentWhereInput = P7Where<{
  childId?: P7StringFilter | string;
  parentId?: P7StringFilter | string;
}>;

interface P7GroupParentDelegate {
  findMany(args?: {
    where?: P7GroupParentWhereInput;
  }): Promise<P7GroupParentPayload[]>;
  createMany(args: {
    data: P7GroupParentPayload[];
    skipDuplicates?: boolean;
  }): Promise<P7BatchPayload>;
  deleteMany(args?: {
    where?: P7GroupParentWhereInput;
  }): Promise<P7BatchPayload>;
}

// ---------------------------------------------------------------------------
// AlfizUser + AlfizMembership
// ---------------------------------------------------------------------------

interface P7UserPayload {
  userId: string;
  active: boolean;
  orgIds: P7JsonValue;
  managerUserId: string | null;
}

interface P7UserCreateInput {
  userId: string;
  active: boolean;
  orgIds: P7JsonNullValueInput | P7InputJsonValue;
  managerUserId?: string | null;
}

interface P7UserUpdateInput {
  active?: boolean;
  orgIds?: P7JsonNullValueInput | P7InputJsonValue;
  managerUserId?: string | null;
}

type P7UserWhereInput = P7Where<{
  userId?: P7StringFilter | string;
  managerUserId?: P7StringNullableFilter | string | null;
}>;

interface P7UserDelegate {
  upsert(args: {
    where: P7AtLeast<{ userId: string }, "userId">;
    create: P7UserCreateInput;
    update: P7UserUpdateInput;
    select?: unknown;
  }): Promise<P7UserPayload>;
  findUnique(args: {
    where: P7AtLeast<{ userId: string }, "userId">;
    select?: unknown;
  }): Promise<P7UserPayload | null>;
  findMany(args?: { where?: P7UserWhereInput }): Promise<P7UserPayload[]>;
  deleteMany(args?: { where?: P7UserWhereInput }): Promise<P7BatchPayload>;
}

interface P7MembershipPayload {
  userId: string;
  groupId: string;
}

type P7MembershipWhereInput = P7Where<{
  userId?: P7StringFilter | string;
  groupId?: P7StringFilter | string;
}>;

interface P7MembershipDelegate {
  findMany(args?: {
    where?: P7MembershipWhereInput;
  }): Promise<P7MembershipPayload[]>;
  createMany(args: {
    data: P7MembershipPayload[];
    skipDuplicates?: boolean;
  }): Promise<P7BatchPayload>;
  deleteMany(args?: {
    where?: P7MembershipWhereInput;
  }): Promise<P7BatchPayload>;
}

// ---------------------------------------------------------------------------
// AlfizRequest
// ---------------------------------------------------------------------------

interface P7RequestPayload {
  id: string;
  requesterUserId: string;
  roleId: string | null;
  pattern: string | null;
  scope: string;
  proposedExpiresAt: bigint | null;
  justification: P7JsonValue;
  state: string;
  stageIndex: number;
  stages: P7JsonValue;
  decisions: P7JsonValue;
  createdAt: bigint;
  decidedAt: bigint | null;
}

interface P7RequestCreateInput {
  id: string;
  requesterUserId: string;
  roleId?: string | null;
  pattern?: string | null;
  scope: string;
  proposedExpiresAt?: bigint | number | null;
  justification: P7JsonNullValueInput | P7InputJsonValue;
  state: string;
  stageIndex: number;
  stages: P7JsonNullValueInput | P7InputJsonValue;
  decisions: P7JsonNullValueInput | P7InputJsonValue;
  createdAt: bigint | number;
  decidedAt?: bigint | number | null;
}

interface P7RequestUpdateInput extends Partial<Omit<P7RequestCreateInput, "id">> {}

type P7RequestWhereInput = P7Where<{
  id?: P7StringFilter | string;
  requesterUserId?: P7StringFilter | string;
  state?: P7StringFilter | string;
  stageIndex?: P7IntFilter | number;
  createdAt?: P7BigIntFilter | bigint | number;
}>;

interface P7RequestDelegate {
  create(args: {
    data: P7RequestCreateInput;
    select?: unknown;
  }): Promise<P7RequestPayload>;
  upsert(args: {
    where: P7AtLeast<{ id: string }, "id">;
    create: P7RequestCreateInput;
    update: P7RequestUpdateInput;
    select?: unknown;
  }): Promise<P7RequestPayload>;
  findUnique(args: {
    where: P7AtLeast<{ id: string }, "id">;
    select?: unknown;
  }): Promise<P7RequestPayload | null>;
  findMany(args?: {
    where?: P7RequestWhereInput;
    orderBy?: unknown;
  }): Promise<P7RequestPayload[]>;
}

// ---------------------------------------------------------------------------
// AlfizCatalog + AlfizAudit
// ---------------------------------------------------------------------------

interface P7CatalogPayload {
  id: number;
  version: number;
  document: P7JsonValue;
}

interface P7CatalogCreateInput {
  id?: number;
  version: number;
  document: P7JsonNullValueInput | P7InputJsonValue;
}

interface P7CatalogDelegate {
  upsert(args: {
    where: P7AtLeast<{ id: number }, "id">;
    create: P7CatalogCreateInput;
    update: Partial<P7CatalogCreateInput>;
    select?: unknown;
  }): Promise<P7CatalogPayload>;
  findUnique(args: {
    where: P7AtLeast<{ id: number }, "id">;
    select?: unknown;
  }): Promise<P7CatalogPayload | null>;
}

interface P7CatalogVersionPayload {
  version: number;
  document: P7JsonValue;
  publishedAt: bigint;
}

interface P7CatalogVersionDelegate {
  upsert(args: {
    where: { version: number };
    create: { version: number; document: P7InputJsonValue; publishedAt: bigint | number };
    update: { document?: P7InputJsonValue; publishedAt?: bigint | number };
    select?: unknown;
  }): Promise<P7CatalogVersionPayload>;
  findUnique(args: {
    where: { version: number };
    select?: unknown;
  }): Promise<P7CatalogVersionPayload | null>;
  findMany(args?: {
    orderBy?: { version?: P7SortOrder };
    take?: number;
  }): Promise<P7CatalogVersionPayload[]>;
}

interface P7AuditPayload {
  id: string;
  at: bigint;
  actor: string;
  action: string;
  target: string;
  detail: P7JsonValue | null;
  prevHash: string | null;
  hash: string | null;
}

interface P7AuditCreateInput {
  id: string;
  at: bigint | number;
  actor: string;
  action: string;
  target: string;
  detail?: P7NullableJsonNullValueInput | P7InputJsonValue;
  prevHash?: string | null;
  hash?: string | null;
}

type P7AuditWhereInput = P7Where<{
  id?: P7StringFilter | string;
  target?: P7StringFilter | string;
  actor?: P7StringFilter | string;
  action?: P7StringFilter | string;
  at?: P7BigIntFilter | bigint | number;
}>;

interface P7AuditDelegate {
  create(args: {
    data: P7AuditCreateInput;
    select?: unknown;
  }): Promise<P7AuditPayload>;
  findMany(args?: {
    where?: P7AuditWhereInput;
    orderBy?:
      | { at?: P7SortOrder; id?: P7SortOrder }
      | { at?: P7SortOrder; id?: P7SortOrder }[];
    take?: number;
    skip?: number;
  }): Promise<P7AuditPayload[]>;
}

// ---------------------------------------------------------------------------
// AlfizEpoch + AlfizEvent (the persisted invalidation log)
// ---------------------------------------------------------------------------

interface P7BigIntFieldUpdateOperationsInput {
  set?: bigint | number;
  increment?: bigint | number;
  decrement?: bigint | number;
  multiply?: bigint | number;
  divide?: bigint | number;
}

interface P7EpochPayload {
  id: number;
  seq: bigint;
  prunedThrough: bigint;
}

interface P7EpochCreateInput {
  id?: number;
  seq: bigint | number;
  prunedThrough?: bigint | number;
}

interface P7EpochUpdateInput {
  seq?: bigint | number | P7BigIntFieldUpdateOperationsInput;
  prunedThrough?: bigint | number | P7BigIntFieldUpdateOperationsInput;
}

interface P7EpochDelegate {
  upsert(args: {
    where: P7AtLeast<{ id: number }, "id">;
    create: P7EpochCreateInput;
    update: P7EpochUpdateInput;
    select?: unknown;
  }): Promise<P7EpochPayload>;
  update(args: {
    where: P7AtLeast<{ id: number }, "id">;
    data: P7EpochUpdateInput;
    select?: unknown;
  }): Promise<P7EpochPayload>;
  findUnique(args: {
    where: P7AtLeast<{ id: number }, "id">;
    select?: unknown;
  }): Promise<P7EpochPayload | null>;
}

interface P7EventPayload {
  seq: bigint;
  type: string;
  payload: P7JsonValue;
  at: bigint;
}

interface P7EventCreateManyInput {
  seq: bigint | number;
  type: string;
  payload: P7JsonNullValueInput | P7InputJsonValue;
  at: bigint | number;
}

type P7EventWhereInput = P7Where<{
  seq?: P7BigIntFilter | bigint | number;
  type?: P7StringFilter | string;
  at?: P7BigIntFilter | bigint | number;
}>;

interface P7EventDelegate {
  createMany(args: {
    data: P7EventCreateManyInput[];
    skipDuplicates?: boolean;
  }): Promise<P7BatchPayload>;
  findMany(args?: {
    where?: P7EventWhereInput;
    orderBy?: { seq?: P7SortOrder } | { seq?: P7SortOrder }[];
    take?: number;
    skip?: number;
  }): Promise<P7EventPayload[]>;
  findFirst(args?: {
    where?: P7EventWhereInput;
    orderBy?: { seq?: P7SortOrder } | { seq?: P7SortOrder }[];
  }): Promise<P7EventPayload | null>;
  deleteMany(args?: { where?: P7EventWhereInput }): Promise<P7BatchPayload>;
}

// ---------------------------------------------------------------------------
// AlfizMetric (rolling permission-usage buckets)
// ---------------------------------------------------------------------------

interface P7MetricPayload {
  bucket: bigint;
  dimension: string;
  subject: string;
  metric: string;
  count: bigint;
}

interface P7MetricCreateInput {
  bucket: bigint | number;
  dimension: string;
  subject: string;
  metric: string;
  count: bigint | number;
}

interface P7MetricUpdateInput {
  bucket?: bigint | number | P7BigIntFieldUpdateOperationsInput;
  dimension?: string;
  subject?: string;
  metric?: string;
  count?: bigint | number | P7BigIntFieldUpdateOperationsInput;
}

/** The compound-`@@id` where-unique input Prisma generates for this model. */
type P7MetricWhereUniqueInput = P7AtLeast<
  {
    bucket_dimension_subject_metric: {
      bucket: bigint | number;
      dimension: string;
      subject: string;
      metric: string;
    };
  },
  "bucket_dimension_subject_metric"
>;

type P7MetricWhereInput = P7Where<{
  bucket?: P7BigIntFilter | bigint | number;
  dimension?: P7StringFilter | string;
  subject?: P7StringFilter | string;
  metric?: P7StringFilter | string;
}>;

interface P7MetricDelegate {
  upsert(args: {
    where: P7MetricWhereUniqueInput;
    create: P7MetricCreateInput;
    update: P7MetricUpdateInput;
    select?: unknown;
  }): Promise<P7MetricPayload>;
  findMany(args?: {
    where?: P7MetricWhereInput;
    take?: number;
    skip?: number;
  }): Promise<P7MetricPayload[]>;
  deleteMany(args?: { where?: P7MetricWhereInput }): Promise<P7BatchPayload>;
}

// ---------------------------------------------------------------------------
// The generated client, and the assertions
// ---------------------------------------------------------------------------

/** The shape `prisma generate` emits for a schema containing the Alfiz models. */
interface P7GeneratedClient {
  alfizGrant: P7GrantDelegate;
  alfizRevoke: P7RevokeDelegate;
  alfizRole: P7RoleDelegate;
  alfizGroup: P7GroupDelegate;
  alfizGroupParent: P7GroupParentDelegate;
  alfizUser: P7UserDelegate;
  alfizMembership: P7MembershipDelegate;
  alfizRequest: P7RequestDelegate;
  alfizCatalog: P7CatalogDelegate;
  alfizCatalogVersion: P7CatalogVersionDelegate;
  alfizAudit: P7AuditDelegate;
  alfizEpoch: P7EpochDelegate;
  alfizEvent: P7EventDelegate;
  alfizMetric: P7MetricDelegate;
  // The client carries far more; extra members never break structural matching.
  $connect(): Promise<void>;
  $disconnect(): Promise<void>;
  $transaction(arg: unknown): Promise<unknown>;
  $extends(arg: unknown): unknown;
}

type Assert<T extends true> = T;
type IsAssignable<A, B> = [A] extends [B] ? true : false;

/**
 * THE promise: the generated client is an `AlfizPrismaDelegates`, no cast.
 * If an assertion here errors, a delegate-surface change broke
 * compatibility with generated clients — fix the delegate types, not the
 * adopters. Per-delegate pins first, so a break names the exact model.
 */
type _GrantDelegateOk = Assert<IsAssignable<P7GrantDelegate, AlfizPrismaDelegates["alfizGrant"]>>;
type _RevokeDelegateOk = Assert<IsAssignable<P7RevokeDelegate, AlfizPrismaDelegates["alfizRevoke"]>>;
type _RoleDelegateOk = Assert<IsAssignable<P7RoleDelegate, AlfizPrismaDelegates["alfizRole"]>>;
type _GroupDelegateOk = Assert<IsAssignable<P7GroupDelegate, AlfizPrismaDelegates["alfizGroup"]>>;
type _GroupParentDelegateOk = Assert<
  IsAssignable<P7GroupParentDelegate, AlfizPrismaDelegates["alfizGroupParent"]>
>;
type _UserDelegateOk = Assert<IsAssignable<P7UserDelegate, AlfizPrismaDelegates["alfizUser"]>>;
type _MembershipDelegateOk = Assert<
  IsAssignable<P7MembershipDelegate, AlfizPrismaDelegates["alfizMembership"]>
>;
type _RequestDelegateOk = Assert<IsAssignable<P7RequestDelegate, AlfizPrismaDelegates["alfizRequest"]>>;
type _CatalogDelegateOk = Assert<IsAssignable<P7CatalogDelegate, AlfizPrismaDelegates["alfizCatalog"]>>;
type _CatalogVersionDelegateOk = Assert<
  IsAssignable<
    P7CatalogVersionDelegate,
    NonNullable<AlfizPrismaDelegates["alfizCatalogVersion"]>
  >
>;
type _AuditDelegateOk = Assert<IsAssignable<P7AuditDelegate, AlfizPrismaDelegates["alfizAudit"]>>;
type _EpochDelegateOk = Assert<
  IsAssignable<P7EpochDelegate, NonNullable<AlfizPrismaDelegates["alfizEpoch"]>>
>;
type _EventDelegateOk = Assert<
  IsAssignable<P7EventDelegate, NonNullable<AlfizPrismaDelegates["alfizEvent"]>>
>;
type _MetricDelegateOk = Assert<
  IsAssignable<P7MetricDelegate, NonNullable<AlfizPrismaDelegates["alfizMetric"]>>
>;
/** A client generated WITHOUT the optional models must keep satisfying the bundle. */
type _PreLogClientStillOk = Assert<
  IsAssignable<
    Omit<
      P7GeneratedClient,
      "alfizEpoch" | "alfizEvent" | "alfizMetric" | "alfizCatalogVersion"
    >,
    AlfizPrismaDelegates
  >
>;
type _ClientSatisfiesDelegates = Assert<
  IsAssignable<P7GeneratedClient, AlfizPrismaDelegates>
>;

/** Per-model create-data pins: what the driver writes, Prisma must accept. */
type _GrantDataAccepted = Assert<
  IsAssignable<AlfizGrantCreateData, P7GrantCreateInput>
>;
type _RevokeDataAccepted = Assert<
  IsAssignable<AlfizRevokeCreateData, P7RevokeCreateInput>
>;
type _RoleDataAccepted = Assert<
  IsAssignable<AlfizRoleCreateData, P7RoleCreateInput>
>;
type _RequestDataAccepted = Assert<
  IsAssignable<AlfizRequestData & { id: string }, P7RequestCreateInput>
>;

/**
 * The original regression, kept failing on purpose: a Json type admitting
 * bare `null` must NOT be accepted by a required Json input. If this
 * @ts-expect-error stops erroring, the replica itself has drifted wide.
 */
// @ts-expect-error — bare null is not a valid Prisma Json input
type _BareNullStillRejected = Assert<IsAssignable<JsonValue, P7GrantCreateInput["provenance"]>>;

/** And our own input type must keep excluding it. */
type _OurInputExcludesNull = Assert<
  IsAssignable<null, InputJsonValue> extends false ? true : false
>;

export {};
