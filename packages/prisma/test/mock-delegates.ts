/**
 * An in-memory AlfizPrismaDelegates, faithful to a real Prisma client's
 * observable behavior for the query shapes the driver uses:
 *
 *   - nullable columns store `null`, never `undefined` — optional Json
 *     fields omitted from create data are normalized to `null`;
 *   - BigInt columns store `bigint` values;
 *   - rows are detached on write AND read (structuredClone), like a database
 *     serialization boundary;
 *   - where-clauses support equality and `{ in: [...] }`;
 *   - `create`/`createMany` throw on primary-key violations;
 *   - a negative `take` returns the last N rows of the ordered result
 *     (Prisma's convention).
 *
 * This validates the driver's mapping logic without running prisma codegen.
 */

import type {
  AlfizAuditRecord,
  AlfizAuditWhere,
  AlfizCatalogVersionRecord,
  AlfizCatalogRecord,
  AlfizGrantRecord,
  AlfizGrantWhere,
  AlfizEpochRecord,
  AlfizEventRecord,
  AlfizGroupParentRecord,
  AlfizGroupRecord,
  AlfizMetricRecord,
  AlfizMembershipRecord,
  AlfizPrismaDelegates,
  AlfizRequestRecord,
  AlfizRevokeRecord,
  AlfizRoleRecord,
  AlfizUserRecord,
  StringWhere,
} from "../src/delegates.js";

const clone = <T>(value: T): T => structuredClone(value);

const matchString = (value: string, cond: StringWhere): boolean =>
  typeof cond === "string" ? value === cond : cond.in.includes(value);

const duplicate = (model: string, key: string): Error =>
  new Error(`${model}: unique constraint violation on ${key}`);

export function mockDelegates(): AlfizPrismaDelegates {
  const grants = new Map<string, AlfizGrantRecord>();
  const revokes = new Map<string, AlfizRevokeRecord>();
  const roles = new Map<string, AlfizRoleRecord>();
  const groups = new Map<string, AlfizGroupRecord>();
  const groupParents: AlfizGroupParentRecord[] = [];
  const users = new Map<string, AlfizUserRecord>();
  const memberships: AlfizMembershipRecord[] = [];
  const requests = new Map<string, AlfizRequestRecord>();
  const catalogs = new Map<number, AlfizCatalogRecord>();
  const epochs = new Map<number, AlfizEpochRecord>();
  const events: AlfizEventRecord[] = [];
  const audits: AlfizAuditRecord[] = [];
  const catalogVersions = new Map<number, AlfizCatalogVersionRecord>();
  const metrics = new Map<string, AlfizMetricRecord>();

  const matchingGrants = (where?: AlfizGrantWhere): AlfizGrantRecord[] =>
    [...grants.values()].filter((r) => {
      if (where?.subject !== undefined && !matchString(r.subject, where.subject)) {
        return false;
      }
      if (where?.scope !== undefined && r.scope !== where.scope) return false;
      if (where?.roleId !== undefined && r.roleId !== where.roleId) return false;
      return true;
    });

  return {
    alfizGrant: {
      async create({ data }) {
        if (grants.has(data.id)) throw duplicate("AlfizGrant", data.id);
        const row: AlfizGrantRecord = clone({ ...data });
        grants.set(row.id, row);
        return clone(row);
      },
      async findUnique({ where }) {
        const row = grants.get(where.id);
        return row === undefined ? null : clone(row);
      },
      async findMany(args) {
        return matchingGrants(args?.where).map(clone);
      },
      async count(args) {
        return matchingGrants(args?.where).length;
      },
      async deleteMany({ where }) {
        const existed = grants.delete(where.id);
        return { count: existed ? 1 : 0 };
      },
    },

    alfizRevoke: {
      async create({ data }) {
        if (revokes.has(data.id)) throw duplicate("AlfizRevoke", data.id);
        const row: AlfizRevokeRecord = clone({ ...data });
        revokes.set(row.id, row);
        return clone(row);
      },
      async findUnique({ where }) {
        const row = revokes.get(where.id);
        return row === undefined ? null : clone(row);
      },
      async findMany(args) {
        let rows = [...revokes.values()];
        const userId = args?.where?.userId;
        if (userId !== undefined) rows = rows.filter((r) => r.userId === userId);
        const scope = args?.where?.scope;
        if (scope !== undefined) rows = rows.filter((r) => r.scope === scope);
        return rows.map(clone);
      },
      async deleteMany({ where }) {
        const existed = revokes.delete(where.id);
        return { count: existed ? 1 : 0 };
      },
    },

    alfizRole: {
      async create({ data }) {
        if (roles.has(data.id)) throw duplicate("AlfizRole", data.id);
        const row: AlfizRoleRecord = clone({
          id: data.id,
          name: data.name,
          description: data.description,
          patterns: data.patterns,
          // Omitted optional Json column → SQL NULL.
          requestable: data.requestable ?? null,
        });
        roles.set(row.id, row);
        return clone(row);
      },
      async findUnique({ where }) {
        const row = roles.get(where.id);
        return row === undefined ? null : clone(row);
      },
      async findMany(args) {
        let rows = [...roles.values()];
        const id = args?.where?.id;
        if (id !== undefined) rows = rows.filter((r) => matchString(r.id, id));
        return rows.map(clone);
      },
      async upsert({ where, create, update }) {
        const existing = roles.get(where.id);
        if (existing === undefined) {
          const row: AlfizRoleRecord = clone({
            id: create.id,
            name: create.name,
            description: create.description,
            patterns: create.patterns,
            requestable: create.requestable ?? null,
          });
          roles.set(row.id, row);
          return clone(row);
        }
        const row: AlfizRoleRecord = clone({
          id: existing.id,
          name: update.name,
          description: update.description,
          patterns: update.patterns,
          // The update half is explicit about clearing, so `null` here is a
          // real "no requestable policy" rather than "leave it alone".
          requestable: update.requestable ?? null,
        });
        roles.set(row.id, row);
        return clone(row);
      },
      async deleteMany({ where }) {
        const existed = roles.delete(where.id);
        return { count: existed ? 1 : 0 };
      },
    },

    alfizGroup: {
      async upsert({ where, create, update }) {
        const existing = groups.get(where.id);
        const row: AlfizGroupRecord =
          existing === undefined
            ? clone({ ...create })
            : clone({ ...existing, ...update });
        groups.set(where.id, row);
        return clone(row);
      },
      async findUnique({ where }) {
        const row = groups.get(where.id);
        return row === undefined ? null : clone(row);
      },
      async findMany() {
        return [...groups.values()].map(clone);
      },
      async deleteMany({ where }) {
        const existed = groups.delete(where.id);
        return { count: existed ? 1 : 0 };
      },
    },

    alfizGroupParent: {
      async findMany(args) {
        let rows = [...groupParents];
        const where = args?.where;
        if (where?.childId !== undefined) {
          const cond = where.childId;
          rows = rows.filter((r) => matchString(r.childId, cond));
        }
        if (where?.parentId !== undefined) {
          const cond = where.parentId;
          rows = rows.filter((r) => matchString(r.parentId, cond));
        }
        return rows.map(clone);
      },
      async createMany({ data }) {
        for (const edge of data) {
          if (
            groupParents.some(
              (e) => e.childId === edge.childId && e.parentId === edge.parentId,
            )
          ) {
            throw duplicate("AlfizGroupParent", `${edge.childId}+${edge.parentId}`);
          }
        }
        for (const edge of data) groupParents.push(clone(edge));
        return { count: data.length };
      },
      async deleteMany({ where }) {
        let count = 0;
        for (let i = groupParents.length - 1; i >= 0; i--) {
          const edge = groupParents[i]!;
          if (where.childId !== undefined && !matchString(edge.childId, where.childId)) continue;
          if (where.parentId !== undefined && !matchString(edge.parentId, where.parentId)) continue;
          groupParents.splice(i, 1);
          count++;
        }
        return { count };
      },
    },

    alfizUser: {
      async upsert({ where, create, update }) {
        const existing = users.get(where.userId);
        const row: AlfizUserRecord =
          existing === undefined
            ? clone({ ...create })
            : clone({ ...existing, ...update });
        users.set(where.userId, row);
        return clone(row);
      },
      async findUnique({ where }) {
        const row = users.get(where.userId);
        return row === undefined ? null : clone(row);
      },
      async findMany() {
        return [...users.values()].map(clone);
      },
      async deleteMany({ where }) {
        const existed = users.delete(where.userId);
        return { count: existed ? 1 : 0 };
      },
    },

    alfizMembership: {
      async findMany(args) {
        let rows = [...memberships];
        const where = args?.where;
        if (where?.userId !== undefined) {
          const cond = where.userId;
          rows = rows.filter((r) => matchString(r.userId, cond));
        }
        if (where?.groupId !== undefined) {
          const cond = where.groupId;
          rows = rows.filter((r) => matchString(r.groupId, cond));
        }
        return rows.map(clone);
      },
      async createMany({ data }) {
        for (const m of data) {
          if (
            memberships.some(
              (e) => e.userId === m.userId && e.groupId === m.groupId,
            )
          ) {
            throw duplicate("AlfizMembership", `${m.userId}+${m.groupId}`);
          }
        }
        for (const m of data) memberships.push(clone(m));
        return { count: data.length };
      },
      async deleteMany({ where }) {
        let count = 0;
        for (let i = memberships.length - 1; i >= 0; i--) {
          const m = memberships[i]!;
          if (where.userId !== undefined && !matchString(m.userId, where.userId)) continue;
          if (where.groupId !== undefined && !matchString(m.groupId, where.groupId)) continue;
          memberships.splice(i, 1);
          count++;
        }
        return { count };
      },
    },

    alfizRequest: {
      async create({ data }) {
        if (requests.has(data.id)) throw duplicate("AlfizRequest", data.id);
        const row: AlfizRequestRecord = clone({ ...data });
        requests.set(row.id, row);
        return clone(row);
      },
      async upsert({ where, create, update }) {
        const existing = requests.get(where.id);
        const row: AlfizRequestRecord =
          existing === undefined
            ? clone({ ...create })
            : clone({ ...existing, ...update });
        requests.set(where.id, row);
        return clone(row);
      },
      async findUnique({ where }) {
        const row = requests.get(where.id);
        return row === undefined ? null : clone(row);
      },
      async findMany(args) {
        let rows = [...requests.values()];
        const where = args?.where;
        if (where?.state !== undefined) {
          const cond = where.state;
          rows = rows.filter((r) => r.state === cond);
        }
        if (where?.requesterUserId !== undefined) {
          const cond = where.requesterUserId;
          rows = rows.filter((r) => r.requesterUserId === cond);
        }
        return rows.map(clone);
      },
    },

    alfizCatalog: {
      async upsert({ where, create, update }) {
        const existing = catalogs.get(where.id);
        const row: AlfizCatalogRecord =
          existing === undefined
            ? clone({ ...create })
            : clone({ ...existing, ...update });
        catalogs.set(where.id, row);
        return clone(row);
      },
      async findUnique({ where }) {
        const row = catalogs.get(where.id);
        return row === undefined ? null : clone(row);
      },
    },

    alfizCatalogVersion: {
      async upsert({ where, create, update }) {
        const existing = catalogVersions.get(where.version);
        const row: AlfizCatalogVersionRecord =
          existing === undefined
            ? clone({
                version: create.version,
                document: create.document,
                publishedAt: BigInt(create.publishedAt),
              })
            : clone({
                ...existing,
                ...(update.document !== undefined
                  ? { document: update.document }
                  : {}),
                ...(update.publishedAt !== undefined
                  ? { publishedAt: BigInt(update.publishedAt) }
                  : {}),
              });
        catalogVersions.set(where.version, row);
        return clone(row);
      },
      async findUnique({ where }) {
        const row = catalogVersions.get(where.version);
        return row === undefined ? null : clone(row);
      },
      async findMany(args) {
        const rows = [...catalogVersions.values()];
        if (args?.orderBy !== undefined) {
          rows.sort((a, b) => a.version - b.version);
        }
        return rows.map(clone);
      },
    },

    alfizAudit: {
      async create({ data }) {
        if (audits.some((a) => a.id === data.id)) {
          throw duplicate("AlfizAudit", data.id);
        }
        const row: AlfizAuditRecord = clone({
          id: data.id,
          at: data.at,
          actor: data.actor,
          action: data.action,
          target: data.target,
          // Omitted optional Json column → SQL NULL.
          detail: data.detail ?? null,
          prevHash: data.prevHash ?? null,
          hash: data.hash ?? null,
        });
        audits.push(row);
        return clone(row);
      },
      async findMany(args) {
        const matches = (row: AlfizAuditRecord, where: AlfizAuditWhere): boolean => {
          if (where.target !== undefined && row.target !== where.target) return false;
          if (where.actor !== undefined && row.actor !== where.actor) return false;
          if (where.action !== undefined && row.action !== where.action) return false;
          if (where.at !== undefined) {
            if (typeof where.at === "bigint") {
              if (row.at !== where.at) return false;
            } else {
              if (where.at.gte !== undefined && row.at < where.at.gte) return false;
              if (where.at.lt !== undefined && row.at >= where.at.lt) return false;
              if (where.at.gt !== undefined && row.at <= where.at.gt) return false;
            }
          }
          if (where.id?.gt !== undefined && row.id <= where.id.gt) return false;
          if (where.OR !== undefined && !where.OR.some((w) => matches(row, w))) {
            return false;
          }
          return true;
        };
        let rows = [...audits];
        if (args?.where !== undefined) {
          rows = rows.filter((r) => matches(r, args.where!));
        }
        if (args?.orderBy !== undefined) {
          // (at, id) — as the compound index would order.
          rows.sort((a, b) =>
            a.at !== b.at
              ? a.at < b.at
                ? -1
                : 1
              : a.id < b.id
                ? -1
                : a.id > b.id
                  ? 1
                  : 0,
          );
        }
        const take = args?.take;
        if (take !== undefined) {
          rows = take < 0 ? rows.slice(take) : rows.slice(0, take);
        }
        return rows.map(clone);
      },
    },

    alfizEpoch: {
      async upsert({ where, create }) {
        if (!epochs.has(where.id)) epochs.set(where.id, clone({ ...create }));
        return clone(epochs.get(where.id)!);
      },
      async update({ where, data }) {
        const row = epochs.get(where.id);
        if (row === undefined) {
          throw new Error("AlfizEpoch: record to update not found");
        }
        if ("seq" in data) row.seq += data.seq.increment;
        else row.prunedThrough = data.prunedThrough;
        return clone(row);
      },
      async findUnique({ where }) {
        const row = epochs.get(where.id);
        return row === undefined ? null : clone(row);
      },
    },

    alfizEvent: {
      async createMany({ data }) {
        for (const row of data) {
          if (events.some((e) => e.seq === row.seq)) {
            throw duplicate("AlfizEvent", String(row.seq));
          }
          events.push(clone({ ...row }));
        }
        return { count: data.length };
      },
      async findMany(args) {
        return events
          .filter((e) => e.seq > args.where.seq.gt)
          .sort((a, b) => (a.seq < b.seq ? -1 : 1))
          .slice(0, args.take)
          .map(clone);
      },
      async findFirst(args) {
        const matched = events
          .filter((e) => e.at < args.where.at.lt)
          .sort((a, b) => (a.seq < b.seq ? 1 : -1));
        return matched.length > 0 ? clone(matched[0]!) : null;
      },
      async deleteMany({ where }) {
        const before = events.length;
        for (let i = events.length - 1; i >= 0; i--) {
          if (events[i]!.seq <= where.seq.lte) events.splice(i, 1);
        }
        return { count: before - events.length };
      },
    },

    alfizMetric: {
      async upsert({ where, create, update }) {
        const id = where.bucket_dimension_subject_metric;
        const key = `${id.bucket}|${id.dimension}|${id.subject}|${id.metric}`;
        const row = metrics.get(key);
        if (row === undefined) {
          metrics.set(key, clone({ ...create }));
        } else {
          row.count += update.count.increment;
        }
        return clone(metrics.get(key)!);
      },
      async findMany({ where }) {
        return [...metrics.values()]
          .filter((row) => {
            if (where.dimension !== undefined && row.dimension !== where.dimension) {
              return false;
            }
            if (where.subject !== undefined && !where.subject.in.includes(row.subject)) {
              return false;
            }
            if (where.bucket?.gte !== undefined && row.bucket < where.bucket.gte) {
              return false;
            }
            if (where.bucket?.lt !== undefined && row.bucket >= where.bucket.lt) {
              return false;
            }
            return true;
          })
          .map(clone);
      },
      async deleteMany({ where }) {
        let count = 0;
        for (const [key, row] of metrics) {
          if (row.bucket < where.bucket.lt) {
            metrics.delete(key);
            count++;
          }
        }
        return { count };
      },
    },
  };
}
