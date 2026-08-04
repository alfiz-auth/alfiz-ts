/**
 * The in-memory storage driver: the reference implementation of the storage
 * seam. Complete and correct — suitable for tests, demos, and ephemeral
 * deployments; everything durable should sit on a database driver.
 */

import type {
  AccessRequest,
  AuditEvent,
  CatalogDocument,
  ImportManifest,
  GrantRow,
  InvalidationEvent,
  MetricBucket,
  MetricBucketKey,
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
} from "./storage.js";

const clone = <T>(value: T): T => structuredClone(value);

const matchesGrant = (row: GrantRow, filter?: GrantFilter): boolean => {
  if (filter?.subject !== undefined && row.subject !== filter.subject) return false;
  if (filter?.subjects !== undefined && !filter.subjects.includes(row.subject)) {
    return false;
  }
  if (filter?.scope !== undefined && row.scope !== filter.scope) return false;
  if (filter?.roleId !== undefined && row.roleId !== filter.roleId) return false;
  return true;
};

/** Metric buckets are keyed by their full composite identity. */
const metricKey = (key: MetricBucketKey): string =>
  `${key.bucket}|${key.dimension}|${key.subject}|${key.metric}`;

export function memoryDriver(): StorageDriver {
  const grants = new Map<string, GrantRow>();
  const revokes = new Map<string, RevokeRow>();
  const roles = new Map<string, RoleRecord>();
  const groups = new Map<string, UserGroup>();
  const users = new Map<string, StoredUser>();
  const requests = new Map<string, AccessRequest>();
  const audit: AuditEvent[] = [];
  const metrics = new Map<string, MetricBucket>();
  let catalog: { version: number; document: CatalogDocument } | null = null;
  const catalogVersions = new Map<
    number,
    { version: number; document: CatalogDocument; publishedAt: number }
  >();
  let imports: { version: number; manifest: ImportManifest } | null = null;
  const locks = new Map<string, Promise<unknown>>();
  const events: Array<{ seq: number; event: InvalidationEvent; at: number }> =
    [];
  let eventSeq = 0;
  let prunedThrough = 0;

  return {
    async insertGrant(row) {
      grants.set(row.id, clone(row));
    },
    async deleteGrant(id) {
      const row = grants.get(id) ?? null;
      grants.delete(id);
      return row ? clone(row) : null;
    },
    async listGrants(filter?: GrantFilter) {
      return [...grants.values()]
        .filter((row) => matchesGrant(row, filter))
        .map(clone);
    },
    async countGrants(filter?: GrantFilter) {
      let count = 0;
      for (const row of grants.values()) {
        if (matchesGrant(row, filter)) count++;
      }
      return count;
    },

    async insertRevoke(row) {
      revokes.set(row.id, clone(row));
    },
    async deleteRevoke(id) {
      const row = revokes.get(id) ?? null;
      revokes.delete(id);
      return row ? clone(row) : null;
    },
    async listRevokes(filter?: RevokeFilter) {
      let rows = [...revokes.values()];
      if (filter?.userId !== undefined) {
        rows = rows.filter((r) => r.userId === filter.userId);
      }
      if (filter?.scope !== undefined) {
        rows = rows.filter((r) => r.scope === filter.scope);
      }
      return rows.map(clone);
    },

    async upsertRole(role) {
      roles.set(role.id, clone(role));
    },
    async getRole(id) {
      const role = roles.get(id);
      return role ? clone(role) : null;
    },
    async getRoles(ids) {
      return ids.flatMap((id) => {
        const role = roles.get(id);
        return role ? [clone(role)] : [];
      });
    },
    async listRoles() {
      return [...roles.values()].map(clone);
    },
    async deleteRole(id) {
      roles.delete(id);
    },

    async upsertGroup(group) {
      groups.set(group.id, clone(group));
    },
    async getGroup(id) {
      const group = groups.get(id);
      return group ? clone(group) : null;
    },
    async listGroups() {
      return [...groups.values()].map(clone);
    },
    async deleteGroup(id) {
      groups.delete(id);
    },

    async getUser(userId) {
      const user = users.get(userId);
      return user ? clone(user) : null;
    },
    async upsertUser(user) {
      users.set(user.userId, clone(user));
    },
    async deleteUser(userId) {
      users.delete(userId);
    },
    async listUsers() {
      return [...users.values()].map(clone);
    },
    async listUsersInGroup(groupId) {
      return [...users.values()]
        .filter((u) => u.groupIds.includes(groupId))
        .map((u) => u.userId);
    },

    async insertRequest(request) {
      requests.set(request.id, clone(request));
    },
    async updateRequest(request) {
      requests.set(request.id, clone(request));
    },
    async getRequest(id) {
      const request = requests.get(id);
      return request ? clone(request) : null;
    },
    async listRequests(filter?: RequestStorageFilter) {
      let rows = [...requests.values()];
      if (filter?.state !== undefined) {
        rows = rows.filter((r) => r.state === filter.state);
      }
      if (filter?.requesterUserId !== undefined) {
        rows = rows.filter((r) => r.requesterUserId === filter.requesterUserId);
      }
      return rows.map(clone);
    },

    async putCatalog(version, document, publishedAt) {
      catalog = { version, document: clone(document) };
      catalogVersions.set(version, {
        version,
        document: clone(document),
        publishedAt: publishedAt ?? 0,
      });
    },
    async getCatalog() {
      return catalog ? clone(catalog) : null;
    },
    async getCatalogVersion(version) {
      const row = catalogVersions.get(version);
      return row ? clone(row) : null;
    },
    async listCatalogVersions() {
      return [...catalogVersions.values()]
        .map(({ version, publishedAt }) => ({ version, publishedAt }))
        .sort((a, b) => a.version - b.version);
    },

    async putImports(version, manifest) {
      imports = { version, manifest: clone(manifest) };
    },
    async getImports() {
      return imports ? clone(imports) : null;
    },

    async appendAudit(event) {
      audit.push(clone(event));
    },
    async listAudit(filter?: AuditFilter) {
      let rows = [...audit].sort((a, b) =>
        a.at !== b.at ? a.at - b.at : a.id < b.id ? -1 : a.id > b.id ? 1 : 0,
      );
      if (filter?.target !== undefined) {
        rows = rows.filter((e) => e.target === filter.target);
      }
      if (filter?.actor !== undefined) {
        rows = rows.filter((e) => e.actor === filter.actor);
      }
      if (filter?.action !== undefined) {
        rows = rows.filter((e) => e.action === filter.action);
      }
      if (filter?.from !== undefined) {
        rows = rows.filter((e) => e.at >= filter.from!);
      }
      if (filter?.to !== undefined) {
        rows = rows.filter((e) => e.at < filter.to!);
      }
      const cursor = filter?.cursor;
      if (cursor !== undefined) {
        // Export paging: ascending from the cursor (exclusive), first `limit`.
        rows = rows.filter(
          (e) => e.at > cursor.at || (e.at === cursor.at && e.id > cursor.id),
        );
        const limit = filter?.limit ?? rows.length;
        return rows.slice(0, limit).map(clone);
      }
      const limit = filter?.limit ?? rows.length;
      return rows.slice(-limit).map(clone);
    },

    async appendEvents(toAppend, at) {
      for (const event of toAppend) {
        events.push({ seq: ++eventSeq, event: clone(event), at });
      }
      return { upTo: eventSeq };
    },
    async headSeq() {
      return eventSeq;
    },
    async eventsSince(seq, limit) {
      if (seq < prunedThrough) return { gap: true };
      const matched = events.filter((e) => e.seq > seq).slice(0, limit);
      return {
        upTo: matched.length > 0 ? matched[matched.length - 1]!.seq : seq,
        events: matched.map((e) => clone(e.event)),
      };
    },
    async pruneEvents(cutoff) {
      let pruneUpTo = 0;
      if (cutoff.at !== undefined) {
        for (const e of events) {
          if (e.at < cutoff.at && e.seq > pruneUpTo) pruneUpTo = e.seq;
        }
      }
      if (cutoff.keepRows !== undefined) {
        pruneUpTo = Math.max(pruneUpTo, eventSeq - cutoff.keepRows);
      }
      if (pruneUpTo <= prunedThrough) return 0;
      const before = events.length;
      let index = 0;
      while (index < events.length && events[index]!.seq <= pruneUpTo) index++;
      events.splice(0, index);
      prunedThrough = pruneUpTo;
      return before - events.length;
    },

    async recordMetrics(deltas) {
      for (const delta of deltas) {
        const key = metricKey(delta);
        const existing = metrics.get(key);
        if (existing) {
          existing.count += delta.count;
        } else {
          metrics.set(key, { ...delta });
        }
      }
    },
    async readMetrics(query) {
      const wanted =
        query.subjects === undefined ? null : new Set(query.subjects);
      const rows: MetricBucket[] = [];
      for (const row of metrics.values()) {
        if (row.dimension !== query.dimension) continue;
        if (wanted !== null && !wanted.has(row.subject)) continue;
        if (query.since !== undefined && row.bucket < query.since) continue;
        if (query.until !== undefined && row.bucket >= query.until) continue;
        rows.push({ ...row });
      }
      return rows;
    },
    async pruneMetrics(before) {
      let deleted = 0;
      for (const [key, row] of metrics) {
        if (row.bucket < before) {
          metrics.delete(key);
          deleted++;
        }
      }
      return deleted;
    },

    async runExclusive<T>(key: string, fn: () => Promise<T>): Promise<T> {
      const previous = locks.get(key) ?? Promise.resolve();
      const next = previous.then(fn, fn);
      locks.set(
        key,
        next.catch(() => undefined),
      );
      return next;
    },
  };
}
