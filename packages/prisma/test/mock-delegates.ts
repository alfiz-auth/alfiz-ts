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
  AlfizCatalogRecord,
  AlfizGrantRecord,
  AlfizGrantWhere,
  AlfizGroupParentRecord,
  AlfizGroupRecord,
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
  const audits: AlfizAuditRecord[] = [];

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
      async findMany() {
        return [...roles.values()].map(clone);
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
        });
        audits.push(row);
        return clone(row);
      },
      async findMany(args) {
        let rows = [...audits];
        const target = args?.where?.target;
        if (target !== undefined) rows = rows.filter((r) => r.target === target);
        if (args?.orderBy !== undefined) {
          // Stable sort: ties keep insertion order, as a DB with a secondary
          // key would.
          rows.sort((a, b) => (a.at < b.at ? -1 : a.at > b.at ? 1 : 0));
        }
        const take = args?.take;
        if (take !== undefined) {
          rows = take < 0 ? rows.slice(take) : rows.slice(0, take);
        }
        return rows.map(clone);
      },
    },
  };
}
