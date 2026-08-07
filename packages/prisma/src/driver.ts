/**
 * The Prisma storage driver: implements the storage seam over the structural
 * delegate surface in delegates.ts, so it runs against any generated Prisma
 * client (Postgres, MySQL, SQLite, …) without depending on `@prisma/client`.
 *
 * Mapping rules, applied uniformly at this boundary:
 *   - Optional core fields (`field?: T | undefined`) ↔ nullable columns:
 *     `null` becomes `undefined` on read, `undefined` becomes `null` (or an
 *     omitted Json field) on write.
 *   - Epoch-ms `number` fields ↔ BigInt columns, converted losslessly with
 *     `BigInt()` / `Number()` (epoch ms sit well inside 2^53).
 *   - Json columns round-trip the core payloads (provenance, patterns,
 *     stages, …) through two typed helpers; no `any` reaches the surface.
 *   - Edge tables (AlfizMembership, AlfizGroupParent) are reconciled on
 *     upsert: rows no longer present are deleted, new ones inserted.
 *
 * Like every driver, this one stores and retrieves; it never interprets.
 * Ids and semantics are the Application's.
 */

import type {
  AccessRequest,
  ApprovalStage,
  AuditEvent,
  CatalogDocument,
  ImportManifest,
  GrantRow,
  InvalidationEvent,
  MetricDimension,
  Provenance,
  RequestDecision,
  RevokeRow,
  RoleRecord,
  UserGroup,
} from "@alfiz/core";
import type {
  AuditFilter,
  GrantFilter,
  RequestStorageFilter,
  RevokeFilter,
  StorageDriver,
  StoredUser,
} from "@alfiz/application";
import type {
  AlfizAuditCreateData,
  AlfizAuditRecord,
  AlfizAuditWhere,
  AlfizEpochDelegate,
  AlfizEventDelegate,
  AlfizGrantCreateData,
  AlfizGrantRecord,
  AlfizGrantWhere,
  AlfizGroupRecord,
  AlfizImportsDelegate,
  AlfizMetricDelegate,
  AlfizPrismaDelegates,
  AlfizRequestData,
  AlfizRequestRecord,
  AlfizRevokeWhere,
  AlfizRoleCreateData,
  AlfizRoleRecord,
  AlfizUserRecord,
  InputJsonValue,
} from "./delegates.js";

export interface PrismaDriverOptions {
  /**
   * Cross-node serialization for graph writes. In-process, the default
   * promise-chain mutex is enough; a MULTI-NODE deployment must pass a
   * database advisory lock here (e.g. Postgres:
   * `SELECT pg_advisory_xact_lock(hashtext($key))` inside a transaction
   * wrapping `fn`), or two nodes can jointly write a graph cycle that each
   * would have rejected alone.
   */
  lock?: (<T>(key: string, fn: () => Promise<T>) => Promise<T>) | undefined;
  /**
   * The sentinel your Prisma client uses to write SQL NULL into a nullable
   * `Json` column — `Prisma.DbNull`. Needed only to CLEAR a role's
   * `requestable` policy; every other write passes a real value.
   *
   * It is an option rather than an import because this package deliberately
   * keeps `@prisma/client` out of its dependency graph (see the module
   * header). Defaults to `null`, which is correct for the bundled memory
   * driver and for any client that accepts it; pass `Prisma.DbNull` if your
   * client rejects a bare `null` on a Json column.
   */
  jsonNull?: unknown;
}

// ---------------------------------------------------------------------------
// Boundary helpers — the only casts in the package, kept in one place.
// ---------------------------------------------------------------------------

/** Core payloads (provenance, stages, …) are JSON-shaped by contract, and never bare null. */
const toJson = (value: unknown): InputJsonValue => value as InputJsonValue;
const fromJson = <T>(value: unknown): T => value as T;

/**
 * Epoch-millisecond values cross into `BigInt` columns here, and `BigInt`
 * throws a bare `RangeError` on anything non-integral — `0.5`, `NaN`, a
 * numeric string. Those reach this driver from the wire (`{"filter":{"from":
 * 0.5}}`, `{"op":"epoch.since","seq":0.5}`), where the answer should be a
 * typed error rather than an untyped 500 out of the storage layer; the
 * memory driver, comparing numbers, filtered them without complaint.
 *
 * Refused rather than rounded, and refused identically in `memoryDriver`.
 * Rounding cannot make the two drivers agree — a `from` bound would have to
 * round up and a `to` bound down to match numeric comparison — and a filter
 * that means a different span on two drivers is a wrong answer on one of
 * them. There is no sensible epoch-millisecond value with a fraction.
 */
const toBig = (value: number): bigint => {
  if (typeof value !== "number" || !Number.isSafeInteger(value)) {
    throw new TypeError(
      `alfiz: expected an integer epoch-millisecond value, received ${JSON.stringify(value)}`,
    );
  }
  return BigInt(value);
};
const optToBig = (value: number | undefined): bigint | null =>
  value === undefined ? null : toBig(value);
const optFromBig = (value: bigint | null): number | undefined =>
  value === null ? undefined : Number(value);
const optFromStr = (value: string | null): string | undefined =>
  value === null ? undefined : value;

// ---------------------------------------------------------------------------
// Row mappings
// ---------------------------------------------------------------------------

const grantToDb = (row: GrantRow): AlfizGrantCreateData => ({
  id: row.id,
  subject: row.subject,
  roleId: row.roleId ?? null,
  pattern: row.pattern ?? null,
  scope: row.scope,
  expiresAt: optToBig(row.expiresAt),
  provenance: toJson(row.provenance),
  createdAt: toBig(row.createdAt),
});

const grantFromDb = (row: AlfizGrantRecord): GrantRow => ({
  id: row.id,
  subject: row.subject,
  roleId: optFromStr(row.roleId),
  pattern: optFromStr(row.pattern),
  scope: row.scope,
  expiresAt: optFromBig(row.expiresAt),
  provenance: fromJson<Provenance>(row.provenance),
  createdAt: Number(row.createdAt),
});

const revokeFromDb = (row: {
  id: string;
  userId: string;
  pattern: string;
  scope: string;
  provenance: unknown;
  createdAt: bigint;
}): RevokeRow => ({
  id: row.id,
  userId: row.userId,
  pattern: row.pattern,
  scope: row.scope,
  provenance: fromJson<Provenance>(row.provenance),
  createdAt: Number(row.createdAt),
});

const roleToDb = (role: RoleRecord): AlfizRoleCreateData => ({
  id: role.id,
  name: role.name,
  description: role.description ?? null,
  patterns: toJson(role.patterns),
  ...(role.requestable === undefined
    ? {}
    : { requestable: toJson(role.requestable) }),
});

const roleFromDb = (row: AlfizRoleRecord): RoleRecord => ({
  id: row.id,
  name: row.name,
  description: optFromStr(row.description),
  patterns: fromJson<string[]>(row.patterns),
  requestable:
    row.requestable === null
      ? undefined
      : fromJson<RoleRecord["requestable"]>(row.requestable),
});

const groupFromDb = (row: AlfizGroupRecord, parents: string[]): UserGroup => ({
  id: row.id,
  name: row.name,
  description: optFromStr(row.description),
  parents,
  virtual: row.virtual ? true : undefined,
});

const userFromDb = (row: AlfizUserRecord, groupIds: string[]): StoredUser => ({
  userId: row.userId,
  active: row.active,
  groupIds,
  orgIds: fromJson<string[]>(row.orgIds),
  managerUserId: row.managerUserId,
});

const requestToDb = (r: AccessRequest): AlfizRequestData & { id: string } => ({
  id: r.id,
  requesterUserId: r.requesterUserId,
  roleId: r.roleId ?? null,
  pattern: r.pattern ?? null,
  scope: r.scope,
  proposedExpiresAt: optToBig(r.proposedExpiresAt),
  justification: toJson(r.justification),
  state: r.state,
  stageIndex: r.stageIndex,
  stages: toJson(r.stages),
  decisions: toJson(r.decisions),
  createdAt: toBig(r.createdAt),
  decidedAt: optToBig(r.decidedAt),
});

const requestFromDb = (row: AlfizRequestRecord): AccessRequest => ({
  id: row.id,
  requesterUserId: row.requesterUserId,
  roleId: optFromStr(row.roleId),
  pattern: optFromStr(row.pattern),
  scope: row.scope,
  proposedExpiresAt: optFromBig(row.proposedExpiresAt),
  justification: fromJson<Record<string, string>>(row.justification),
  state: fromJson<AccessRequest["state"]>(row.state),
  stageIndex: row.stageIndex,
  stages: fromJson<readonly ApprovalStage[]>(row.stages),
  decisions: fromJson<readonly RequestDecision[]>(row.decisions),
  createdAt: Number(row.createdAt),
  decidedAt: optFromBig(row.decidedAt),
});

const auditToDb = (event: AuditEvent): AlfizAuditCreateData => ({
  id: event.id,
  at: toBig(event.at),
  actor: event.actor,
  action: event.action,
  target: event.target,
  // `undefined` and `null` detail both map to SQL NULL (Prisma writes NULL
  // into a Json column via a sentinel, not a plain null — so we omit).
  ...(event.detail === undefined || event.detail === null
    ? {}
    : { detail: toJson(event.detail) }),
  ...(event.prevHash !== undefined ? { prevHash: event.prevHash } : {}),
  ...(event.hash !== undefined ? { hash: event.hash } : {}),
});

const auditFromDb = (row: AlfizAuditRecord): AuditEvent => ({
  id: row.id,
  at: Number(row.at),
  actor: row.actor,
  action: row.action,
  target: row.target,
  ...(row.detail === null || row.detail === undefined
    ? {}
    : { detail: row.detail }),
  ...(row.prevHash === null || row.prevHash === undefined
    ? {}
    : { prevHash: row.prevHash }),
  ...(row.hash === null || row.hash === undefined ? {} : { hash: row.hash }),
});

// ---------------------------------------------------------------------------
// The driver
// ---------------------------------------------------------------------------

/**
 * Build a StorageDriver over a Prisma client (or anything satisfying
 * {@link AlfizPrismaDelegates} structurally):
 *
 * ```ts
 * const prisma = new PrismaClient();
 * const storage = prismaDriver(prisma);
 * const app = createApplication({ storage, ... });
 * ```
 *
 * `runExclusive` uses `options.lock` when provided, else an in-process
 * promise-chain mutex per key (the memory driver's approach). That mutex
 * only serializes within one process: multi-node deployments MUST supply a
 * database advisory lock (e.g. Postgres `pg_advisory_xact_lock`) via
 * `options.lock` so concurrent graph writes on different nodes cannot
 * jointly form a cycle.
 */
export function prismaDriver(
  db: AlfizPrismaDelegates,
  options?: PrismaDriverOptions,
): StorageDriver {
  const externalLock = options?.lock;
  const jsonNull = options?.jsonNull ?? null;
  const locks = new Map<string, Promise<unknown>>();

  const exclusive = <T>(key: string, fn: () => Promise<T>): Promise<T> => {
    if (externalLock !== undefined) return externalLock(key, fn);
    const previous = locks.get(key) ?? Promise.resolve();
    const next = previous.then(fn, fn);
    locks.set(
      key,
      next.catch(() => undefined),
    );
    return next;
  };

  /**
   * The grant where-clause, shared by list and count so the two can never
   * disagree about what "matching" means. `null` means "provably empty"
   * (contradictory subject filters), which the caller short-circuits rather
   * than sending an impossible query.
   */
  const grantWhere = (filter?: GrantFilter): AlfizGrantWhere | null => {
    const where: AlfizGrantWhere = {};
    if (filter?.subject !== undefined && filter.subjects !== undefined) {
      // Both filters present: their conjunction is the intersection.
      if (!filter.subjects.includes(filter.subject)) return null;
      where.subject = filter.subject;
    } else if (filter?.subject !== undefined) {
      where.subject = filter.subject;
    } else if (filter?.subjects !== undefined) {
      where.subject = { in: [...filter.subjects] };
    }
    if (filter?.scope !== undefined) where.scope = filter.scope;
    if (filter?.roleId !== undefined) {
      // `roleId` is a nullable column, and Prisma reads `{ roleId: null }` as
      // `IS NULL` — so a JSON body carrying an explicit `null` (which the
      // wire layer forwards verbatim) turned "grants of this role" into
      // "every pattern grant in the organization". Dropping the clause would
      // be no better: that is the same widening by another route. A filter
      // naming a role that cannot exist matches nothing, which is what the
      // memory driver already answers.
      if (typeof filter.roleId !== "string") return null;
      where.roleId = filter.roleId;
    }
    return where;
  };

  /** Diff an edge set keyed on `userId`/`childId` into deletes + inserts. */
  const diff = (
    current: readonly string[],
    desired: readonly string[],
  ): { toRemove: string[]; toAdd: string[] } => {
    const have = new Set(current);
    const want = new Set(desired);
    return {
      toRemove: [...have].filter((x) => !want.has(x)),
      toAdd: [...want].filter((x) => !have.has(x)),
    };
  };

  return {
    durable: true,
    driverName: "prisma",

    // -- grants ---------------------------------------------------------------
    async insertGrant(row) {
      await db.alfizGrant.create({ data: grantToDb(row) });
    },
    async deleteGrant(id) {
      // Read first, then deleteMany: Prisma's `delete` throws when the row is
      // absent, and the contract wants `null` back instead. The affected-row
      // count decides the answer — discarding it made a concurrent deleter
      // look like our own success, and the Application audits a second
      // `grant.delete` for a row it did not remove.
      const existing = await db.alfizGrant.findUnique({ where: { id } });
      if (existing === null) return null;
      const { count } = await db.alfizGrant.deleteMany({ where: { id } });
      return count === 0 ? null : grantFromDb(existing);
    },
    async listGrants(filter?: GrantFilter) {
      const where = grantWhere(filter);
      if (where === null) return [];
      const rows = await db.alfizGrant.findMany({ where });
      return rows.map(grantFromDb);
    },
    async countGrants(filter?: GrantFilter) {
      const where = grantWhere(filter);
      if (where === null) return 0;
      return db.alfizGrant.count({ where });
    },

    // -- revokes --------------------------------------------------------------
    async insertRevoke(row) {
      await db.alfizRevoke.create({
        data: {
          id: row.id,
          userId: row.userId,
          pattern: row.pattern,
          scope: row.scope,
          provenance: toJson(row.provenance),
          createdAt: toBig(row.createdAt),
        },
      });
    },
    async deleteRevoke(id) {
      const existing = await db.alfizRevoke.findUnique({ where: { id } });
      if (existing === null) return null;
      const { count } = await db.alfizRevoke.deleteMany({ where: { id } });
      return count === 0 ? null : revokeFromDb(existing);
    },
    async listRevokes(filter?: RevokeFilter) {
      const where: AlfizRevokeWhere = {};
      if (filter?.userId !== undefined) where.userId = filter.userId;
      if (filter?.scope !== undefined) where.scope = filter.scope;
      const rows = await db.alfizRevoke.findMany({ where });
      return rows.map(revokeFromDb);
    },

    // -- roles ----------------------------------------------------------------
    async upsertRole(role) {
      // Update-then-create, never delete-then-create. The old comment
      // claimed the delete/create window was benign because "the Application
      // serializes organizational writes" — it does not: only `groups`,
      // `reporting`, `request:*` and `audit` take the lock, and role writes
      // never did. So the window was real, and while it was open every grant
      // conferring the role denied ("unknown roles confer nothing"), a
      // failure in the create half destroyed the role outright, and two
      // concurrent updates collided on the primary key.
      //
      await db.alfizRole.upsert({
        where: { id: role.id },
        create: roleToDb(role),
        update: {
          name: role.name,
          description: role.description ?? null,
          patterns: toJson(role.patterns),
          // Explicit on every update, unlike the create half: a role that
          // LOST its requestable policy must have the column cleared, and
          // omitting the field would silently keep the old policy alive —
          // a de-privileging edit that did not de-privilege.
          requestable:
            role.requestable === undefined
              ? toJson(jsonNull)
              : toJson(role.requestable),
        },
      });
    },
    async getRole(id) {
      const row = await db.alfizRole.findUnique({ where: { id } });
      return row === null ? null : roleFromDb(row);
    },
    async getRoles(ids) {
      if (ids.length === 0) return [];
      const rows = await db.alfizRole.findMany({
        where: { id: { in: [...ids] } },
      });
      return rows.map(roleFromDb);
    },
    async listRoles() {
      return (await db.alfizRole.findMany()).map(roleFromDb);
    },
    async deleteRole(id) {
      await db.alfizRole.deleteMany({ where: { id } });
    },

    // -- groups ---------------------------------------------------------------
    async upsertGroup(group) {
      const data = {
        name: group.name,
        description: group.description ?? null,
        virtual: group.virtual ?? false,
      };
      await db.alfizGroup.upsert({
        where: { id: group.id },
        create: { id: group.id, ...data },
        update: data,
      });
      const existing = await db.alfizGroupParent.findMany({
        where: { childId: group.id },
      });
      const { toRemove, toAdd } = diff(
        existing.map((e) => e.parentId),
        group.parents,
      );
      if (toRemove.length > 0) {
        await db.alfizGroupParent.deleteMany({
          where: { childId: group.id, parentId: { in: toRemove } },
        });
      }
      if (toAdd.length > 0) {
        await db.alfizGroupParent.createMany({
          data: toAdd.map((parentId) => ({ childId: group.id, parentId })),
        });
      }
    },
    async getGroup(id) {
      const row = await db.alfizGroup.findUnique({ where: { id } });
      if (row === null) return null;
      const edges = await db.alfizGroupParent.findMany({
        where: { childId: id },
      });
      return groupFromDb(
        row,
        edges.map((e) => e.parentId),
      );
    },
    async listGroups() {
      const [rows, edges] = await Promise.all([
        db.alfizGroup.findMany(),
        db.alfizGroupParent.findMany(),
      ]);
      const parentsByChild = new Map<string, string[]>();
      for (const edge of edges) {
        const list = parentsByChild.get(edge.childId);
        if (list === undefined) parentsByChild.set(edge.childId, [edge.parentId]);
        else list.push(edge.parentId);
      }
      return rows.map((row) => groupFromDb(row, parentsByChild.get(row.id) ?? []));
    },
    async deleteGroup(id) {
      // The parent edges compose the group's own record; edges where other
      // groups name this one as parent are their records, left untouched
      // (matching the memory driver's semantics).
      await db.alfizGroupParent.deleteMany({ where: { childId: id } });
      await db.alfizGroup.deleteMany({ where: { id } });
    },

    // -- users ----------------------------------------------------------------
    async getUser(userId) {
      const row = await db.alfizUser.findUnique({ where: { userId } });
      if (row === null) return null;
      const memberships = await db.alfizMembership.findMany({
        where: { userId },
      });
      return userFromDb(
        row,
        memberships.map((m) => m.groupId),
      );
    },
    async upsertUser(user) {
      const data = {
        active: user.active,
        orgIds: toJson(user.orgIds),
        managerUserId: user.managerUserId,
      };
      await db.alfizUser.upsert({
        where: { userId: user.userId },
        create: { userId: user.userId, ...data },
        update: data,
      });
      const existing = await db.alfizMembership.findMany({
        where: { userId: user.userId },
      });
      const { toRemove, toAdd } = diff(
        existing.map((m) => m.groupId),
        user.groupIds,
      );
      if (toRemove.length > 0) {
        await db.alfizMembership.deleteMany({
          where: { userId: user.userId, groupId: { in: toRemove } },
        });
      }
      if (toAdd.length > 0) {
        await db.alfizMembership.createMany({
          data: toAdd.map((groupId) => ({ userId: user.userId, groupId })),
        });
      }
    },
    async deleteUser(userId) {
      // Membership edges compose the user's record, exactly as group-parent
      // edges compose a group's — they follow the record out.
      await db.alfizMembership.deleteMany({ where: { userId } });
      await db.alfizUser.deleteMany({ where: { userId } });
    },
    async listUsers() {
      const [rows, memberships] = await Promise.all([
        db.alfizUser.findMany(),
        db.alfizMembership.findMany(),
      ]);
      const groupsByUser = new Map<string, string[]>();
      for (const m of memberships) {
        const list = groupsByUser.get(m.userId);
        if (list === undefined) groupsByUser.set(m.userId, [m.groupId]);
        else list.push(m.groupId);
      }
      return rows.map((row) => userFromDb(row, groupsByUser.get(row.userId) ?? []));
    },
    async listUsersInGroup(groupId) {
      const memberships = await db.alfizMembership.findMany({
        where: { groupId },
      });
      return memberships.map((m) => m.userId);
    },

    // -- requests -------------------------------------------------------------
    async insertRequest(request) {
      await db.alfizRequest.create({ data: requestToDb(request) });
    },
    async updateRequest(request) {
      const data = requestToDb(request);
      await db.alfizRequest.upsert({
        where: { id: request.id },
        create: data,
        update: data,
      });
    },
    async getRequest(id) {
      const row = await db.alfizRequest.findUnique({ where: { id } });
      return row === null ? null : requestFromDb(row);
    },
    async listRequests(filter?: RequestStorageFilter) {
      const rows = await db.alfizRequest.findMany({
        where: {
          ...(filter?.state !== undefined ? { state: filter.state } : {}),
          ...(filter?.requesterUserId !== undefined
            ? { requesterUserId: filter.requesterUserId }
            : {}),
        },
      });
      return rows.map(requestFromDb);
    },

    // -- catalog --------------------------------------------------------------
    async putCatalog(version, document, publishedAt) {
      await db.alfizCatalog.upsert({
        where: { id: 1 },
        create: { id: 1, version, document: toJson(document) },
        update: { version, document: toJson(document) },
      });
      // History rides along when the schema carries the model; the head
      // stays a cheap singleton read either way.
      if (db.alfizCatalogVersion !== undefined) {
        await db.alfizCatalogVersion.upsert({
          where: { version },
          create: {
            version,
            document: toJson(document),
            publishedAt: toBig(publishedAt ?? 0),
          },
          update: {
            document: toJson(document),
            publishedAt: toBig(publishedAt ?? 0),
          },
        });
      }
    },
    async getCatalog() {
      const row = await db.alfizCatalog.findUnique({ where: { id: 1 } });
      if (row === null) return null;
      return {
        version: row.version,
        document: fromJson<CatalogDocument>(row.document),
      };
    },
    ...(db.alfizCatalogVersion !== undefined
      ? {
          async getCatalogVersion(version: number) {
            const row = await db.alfizCatalogVersion!.findUnique({
              where: { version },
            });
            if (row === null) return null;
            return {
              version: row.version,
              document: fromJson<CatalogDocument>(row.document),
              publishedAt: Number(row.publishedAt),
            };
          },
          async listCatalogVersions() {
            const rows = await db.alfizCatalogVersion!.findMany({
              orderBy: { version: "asc" },
            });
            return rows.map((r) => ({
              version: r.version,
              publishedAt: Number(r.publishedAt),
            }));
          },
        }
      : {}),

    // -- audit ----------------------------------------------------------------
    async appendAudit(event) {
      await db.alfizAudit.create({ data: auditToDb(event) });
    },
    async listAudit(filter?: AuditFilter) {
      const limit = filter?.limit;
      if (limit !== undefined && limit <= 0) return [];
      const where: AlfizAuditWhere = {};
      if (filter?.target !== undefined) where.target = filter.target;
      if (filter?.actor !== undefined) where.actor = filter.actor;
      if (filter?.action !== undefined) where.action = filter.action;
      if (filter?.from !== undefined || filter?.to !== undefined) {
        where.at = {
          ...(filter.from !== undefined ? { gte: toBig(filter.from) } : {}),
          ...(filter.to !== undefined ? { lt: toBig(filter.to) } : {}),
        };
      }
      const cursor = filter?.cursor;
      if (cursor !== undefined) {
        // Export paging: strictly after (at, id), ascending, first `limit`.
        where.OR = [
          { at: { gt: toBig(cursor.at) } },
          { at: toBig(cursor.at), id: { gt: cursor.id } },
        ];
        const rows = await db.alfizAudit.findMany({
          where,
          orderBy: [{ at: "asc" }, { id: "asc" }],
          ...(limit !== undefined ? { take: limit } : {}),
        });
        return rows.map(auditFromDb);
      }
      // Without a cursor: the LAST `limit` events in log order — ascending by
      // (`at`, `id`), taking from the end (Prisma's negative-take convention).
      const rows = await db.alfizAudit.findMany({
        ...(Object.keys(where).length > 0 ? { where } : {}),
        orderBy: [{ at: "asc" }, { id: "asc" }],
        ...(limit !== undefined ? { take: -limit } : {}),
      });
      return rows.map(auditFromDb);
    },

    // -- imports --------------------------------------------------------------
    // Included only when the schema carries the AlfizImports model, on the
    // same reasoning as the event log and metrics below.
    ...(db.alfizImports !== undefined ? importMethods(db.alfizImports) : {}),

    // -- invalidation events --------------------------------------------------
    // Included only when the schema carries the AlfizEpoch/AlfizEvent models
    // (both delegates present), so clients generated from the pre-log
    // fragment keep working and `events.persist` fails loudly instead of
    // silently. Sequence allocation is an atomic increment on the singleton
    // epoch row, serialized under the events lock — which, like graph
    // writes, must be a DATABASE advisory lock in multi-node deployments.
    ...(db.alfizEpoch !== undefined && db.alfizEvent !== undefined
      ? eventMethods(db.alfizEpoch, db.alfizEvent, exclusive)
      : {}),

    // -- metrics --------------------------------------------------------------
    // Included only when the schema carries the AlfizMetric model, on the
    // same reasoning as the event log above.
    ...(db.alfizMetric !== undefined ? metricMethods(db.alfizMetric) : {}),

    // -- serialization --------------------------------------------------------
    async runExclusive<T>(key: string, fn: () => Promise<T>): Promise<T> {
      return exclusive(key, fn);
    },
  };
}

// ---------------------------------------------------------------------------
// Rolling permission-usage buckets
// ---------------------------------------------------------------------------

/**
 * Counters, not rows: every write is an increment-or-create against a
 * composite key, so concurrent reporters from many app servers sum instead
 * of racing, and nothing here needs a lock. Batches arrive pre-aggregated
 * and off the request path, so the statement count is the number of distinct
 * buckets in a window — small, and bounded by attributed rows.
 */
/**
 * The import manifest: a versioned singleton, exactly like the catalog, and
 * stored beside it rather than inside it — what an application consumes is a
 * different contract from what it announces.
 */
function importMethods(
  imports: AlfizImportsDelegate,
): Pick<Required<StorageDriver>, "putImports" | "getImports"> {
  return {
    async putImports(version, manifest) {
      await imports.upsert({
        where: { id: 1 },
        create: { id: 1, version, manifest: toJson(manifest) },
        update: { version, manifest: toJson(manifest) },
      });
    },
    async getImports() {
      const row = await imports.findUnique({ where: { id: 1 } });
      if (row === null) return null;
      return {
        version: row.version,
        manifest: fromJson<ImportManifest>(row.manifest),
      };
    },
  };
}

function metricMethods(
  metric: AlfizMetricDelegate,
): Pick<
  Required<StorageDriver>,
  "recordMetrics" | "readMetrics" | "pruneMetrics"
> {
  return {
    async recordMetrics(deltas) {
      for (const delta of deltas) {
        const identity = {
          bucket: toBig(delta.bucket),
          dimension: delta.dimension,
          subject: delta.subject,
          metric: delta.metric,
        };
        await metric.upsert({
          where: { bucket_dimension_subject_metric: identity },
          create: { ...identity, count: toBig(Math.round(delta.count)) },
          update: { count: { increment: toBig(Math.round(delta.count)) } },
        });
      }
    },
    async readMetrics(query) {
      const rows = await metric.findMany({
        where: {
          dimension: query.dimension,
          ...(query.subjects === undefined
            ? {}
            : { subject: { in: [...query.subjects] } }),
          ...(query.since === undefined && query.until === undefined
            ? {}
            : {
                bucket: {
                  ...(query.since === undefined
                    ? {}
                    : { gte: toBig(query.since) }),
                  ...(query.until === undefined
                    ? {}
                    : { lt: toBig(query.until) }),
                },
              }),
        },
      });
      return rows.map((row) => ({
        bucket: Number(row.bucket),
        dimension: row.dimension as MetricDimension,
        subject: row.subject,
        metric: row.metric,
        count: Number(row.count),
      }));
    },
    async pruneMetrics(before) {
      const { count } = await metric.deleteMany({
        where: { bucket: { lt: toBig(before) } },
      });
      return count;
    },
  };
}

// ---------------------------------------------------------------------------
// The persisted invalidation log
// ---------------------------------------------------------------------------

const EVENTS_LOCK = "alfiz:events";

function eventMethods(
  epoch: AlfizEpochDelegate,
  event: AlfizEventDelegate,
  exclusive: <T>(key: string, fn: () => Promise<T>) => Promise<T>,
): Pick<
  Required<StorageDriver>,
  "appendEvents" | "headSeq" | "eventsSince" | "pruneEvents"
> {
  const ensureHead = async (): Promise<void> => {
    await epoch.upsert({
      where: { id: 1 },
      create: { id: 1, seq: 0n, prunedThrough: 0n },
      update: {},
    });
  };

  return {
    async appendEvents(events, at) {
      return exclusive(EVENTS_LOCK, async () => {
        await ensureHead();
        const advanced = await epoch.update({
          where: { id: 1 },
          data: { seq: { increment: BigInt(events.length) } },
        });
        const base = advanced.seq - BigInt(events.length);
        await event.createMany({
          data: events.map((e, index) => ({
            seq: base + BigInt(index + 1),
            type: e.type,
            payload: toJson(e),
            at: toBig(at),
          })),
        });
        return { upTo: Number(advanced.seq) };
      });
    },
    async headSeq() {
      const row = await epoch.findUnique({ where: { id: 1 } });
      return row === null ? 0 : Number(row.seq);
    },
    async eventsSince(seq, limit) {
      const head = await epoch.findUnique({ where: { id: 1 } });
      if (head === null) return { upTo: seq, events: [] };
      if (BigInt(seq) < head.prunedThrough) return { gap: true };
      // A NEGATIVE `take` means "the last N rows" to Prisma, which would
      // hand back the newest event and an `upTo` at head — retiring every
      // invalidation in between. The caller's limit is wire-supplied
      // (`epoch.since`), so it is clamped here rather than trusted.
      const take = Math.max(0, Math.trunc(limit ?? 0)) || undefined;
      const rows = await event.findMany({
        where: { seq: { gt: BigInt(seq) } },
        orderBy: { seq: "asc" },
        ...(take === undefined ? {} : { take }),
      });
      // `seq` is allocated by an atomic increment and the row is inserted
      // afterwards, so there is always a window where N+1 is committed and N
      // is not. Returning [N+1] with `upTo: N+1` retires N forever — the
      // poller advances its cursor past an invalidation it never saw, and
      // that node serves the revoked grant until its blind TTL. Stop at the
      // first discontinuity instead; the caller comes back for the rest.
      const contiguous: typeof rows = [];
      let expected = BigInt(seq) + 1n;
      for (const row of rows) {
        if (row.seq !== expected) break;
        contiguous.push(row);
        expected += 1n;
      }
      return {
        upTo:
          contiguous.length > 0
            ? Number(contiguous[contiguous.length - 1]!.seq)
            : seq,
        events: contiguous.map((row) => fromJson<InvalidationEvent>(row.payload)),
      };
    },
    async pruneEvents(cutoff) {
      return exclusive(EVENTS_LOCK, async () => {
        const head = await epoch.findUnique({ where: { id: 1 } });
        if (head === null) return 0;
        let pruneUpTo = head.prunedThrough;
        if (cutoff.at !== undefined) {
          const newest = await event.findFirst({
            where: { at: { lt: toBig(cutoff.at) } },
            orderBy: { seq: "desc" },
          });
          if (newest !== null && newest.seq > pruneUpTo) pruneUpTo = newest.seq;
        }
        if (cutoff.keepRows !== undefined) {
          const bySize = head.seq - BigInt(cutoff.keepRows);
          if (bySize > pruneUpTo) pruneUpTo = bySize;
        }
        if (pruneUpTo <= head.prunedThrough) return 0;
        const { count } = await event.deleteMany({
          where: { seq: { lte: pruneUpTo } },
        });
        await epoch.update({
          where: { id: 1 },
          data: { prunedThrough: pruneUpTo },
        });
        return count;
      });
    },
  };
}
