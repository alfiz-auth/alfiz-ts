/**
 * The storage-driver contract suite: every driver — memory, Prisma, or
 * yours — must pass these cases unchanged. Framework-free: cases are
 * (name, run) pairs using node:assert, so any test runner can host them.
 *
 * Published as `@alfiz/application/driver-suite` so a custom driver is held
 * to the same contract the bundled drivers are — including the
 * `runExclusive` serialization case that keeps graph-cycle detection sound
 * under concurrency. A driver package's test file is three lines:
 *
 * ```ts
 * import { driverContractCases, eventLogContractCases, metricsContractCases }
 *   from "@alfiz/application/driver-suite";
 * for (const c of driverContractCases) test(c.name, () => c.run(makeDriver()));
 * ```
 */

import assert from "node:assert/strict";
import type { StorageDriver } from "./storage.js";
import type { AccessRequest, GrantRow, RevokeRow } from "@alfiz/core";

export interface DriverCase {
  name: string;
  run(driver: StorageDriver): Promise<void>;
}

const grant = (id: string, subject: string, scope = "*"): GrantRow => ({
  id,
  subject,
  pattern: "docs.files.read",
  scope,
  provenance: { kind: "admin", actorUserId: "root" },
  createdAt: 1,
});

const revoke = (id: string, userId: string): RevokeRow => ({
  id,
  userId,
  pattern: "docs.*",
  scope: "*",
  provenance: { kind: "admin", actorUserId: "root" },
  createdAt: 1,
});

export const driverContractCases: DriverCase[] = [
  {
    name: "grants: insert, filter by subject/subjects/scope/roleId, delete returns the row",
    async run(driver) {
      await driver.insertGrant(grant("g1", "user:u1"));
      await driver.insertGrant(grant("g2", "group:team", "docs.folder:9"));
      await driver.insertGrant({ ...grant("g3", "user:u1"), pattern: undefined, roleId: "r1" });
      assert.equal((await driver.listGrants()).length, 3);
      assert.deepEqual(
        (await driver.listGrants({ subject: "user:u1" })).map((g) => g.id).sort(),
        ["g1", "g3"],
      );
      assert.deepEqual(
        (await driver.listGrants({ subjects: ["group:team", "user:none"] })).map((g) => g.id),
        ["g2"],
      );
      assert.deepEqual(
        (await driver.listGrants({ scope: "docs.folder:9" })).map((g) => g.id),
        ["g2"],
      );
      assert.deepEqual(
        (await driver.listGrants({ roleId: "r1" })).map((g) => g.id),
        ["g3"],
      );
      const deleted = await driver.deleteGrant("g1");
      assert.equal(deleted?.id, "g1");
      assert.equal(await driver.deleteGrant("g1"), null);
      assert.equal((await driver.listGrants()).length, 2);
    },
  },
  {
    name: "grants: countGrants agrees with listGrants for every filter shape",
    async run(driver) {
      await driver.insertGrant(grant("c1", "user:u1"));
      await driver.insertGrant(grant("c2", "user:u1", "docs.folder:9"));
      await driver.insertGrant({ ...grant("c3", "group:team"), pattern: undefined, roleId: "r1" });
      await driver.insertGrant({ ...grant("c4", "user:u2"), pattern: undefined, roleId: "r1" });
      const filters = [
        undefined,
        { subject: "user:u1" },
        { subjects: ["group:team", "user:u2"] },
        { scope: "docs.folder:9" },
        { roleId: "r1" },
        { roleId: "r1", subject: "group:team" },
        { roleId: "nobody-holds-this" },
        // Contradictory subject filters: provably empty, not a scan.
        { subject: "user:u1", subjects: ["user:u2"] },
      ];
      for (const filter of filters) {
        assert.equal(
          await driver.countGrants(filter),
          (await driver.listGrants(filter)).length,
          `countGrants disagreed with listGrants for ${JSON.stringify(filter)}`,
        );
      }
      assert.equal(await driver.countGrants({ roleId: "r1" }), 2);
      assert.equal(await driver.countGrants(), 4);
    },
  },
  {
    name: "grants: rows round-trip losslessly (expiry, provenance)",
    async run(driver) {
      const row: GrantRow = {
        ...grant("g-full", "user:u9", "docs.doc:1"),
        expiresAt: 12345,
        provenance: { kind: "request", requestId: "req1", approvedBy: "boss" },
      };
      await driver.insertGrant(row);
      const [read] = await driver.listGrants({ subject: "user:u9" });
      // Drivers may return unset optionals as absent, undefined, or null.
      const normalize = (g: GrantRow) => ({
        id: g.id,
        subject: g.subject,
        roleId: g.roleId ?? undefined,
        pattern: g.pattern ?? undefined,
        scope: g.scope,
        expiresAt: g.expiresAt ?? undefined,
        provenance: g.provenance,
        createdAt: g.createdAt,
      });
      assert.deepEqual(normalize(read!), normalize(row));
    },
  },
  {
    name: "revokes: insert, filter by user and scope, delete",
    async run(driver) {
      await driver.insertRevoke(revoke("r1", "u1"));
      await driver.insertRevoke(revoke("r2", "u2"));
      await driver.insertRevoke({ ...revoke("r3", "u1"), scope: "docs.folder:9" });
      assert.deepEqual(
        (await driver.listRevokes({ userId: "u1" })).map((r) => r.id).sort(),
        ["r1", "r3"],
      );
      assert.deepEqual(
        (await driver.listRevokes({ scope: "docs.folder:9" })).map((r) => r.id),
        ["r3"],
      );
      assert.deepEqual(
        (await driver.listRevokes({ userId: "u1", scope: "*" })).map((r) => r.id),
        ["r1"],
      );
      assert.equal((await driver.deleteRevoke("r1"))?.id, "r1");
      assert.equal(await driver.deleteRevoke("r1"), null);
    },
  },
  {
    name: "roles: upsert (create + replace), get, list, delete",
    async run(driver) {
      await driver.upsertRole({ id: "role1", name: "Reader", patterns: ["docs.files.read"] });
      await driver.upsertRole({
        id: "role1",
        name: "Reader v2",
        patterns: ["docs.*"],
        requestable: { stages: [{ kind: "management" }] },
      });
      const read = await driver.getRole("role1");
      assert.equal(read?.name, "Reader v2");
      assert.deepEqual(read?.patterns, ["docs.*"]);
      assert.equal(read?.requestable?.stages.length, 1);
      assert.equal((await driver.listRoles()).length, 1);
      await driver.deleteRole("role1");
      assert.equal(await driver.getRole("role1"), null);
    },
  },
  {
    name: "groups: upsert with parents and virtual flag, list, delete",
    async run(driver) {
      await driver.upsertGroup({ id: "g1", name: "A", parents: [] });
      await driver.upsertGroup({ id: "g2", name: "B", parents: ["g1"], virtual: true });
      const g2 = await driver.getGroup("g2");
      assert.deepEqual(g2?.parents, ["g1"]);
      assert.equal(g2?.virtual, true);
      assert.equal((await driver.listGroups()).length, 2);
      await driver.deleteGroup("g2");
      assert.equal(await driver.getGroup("g2"), null);
    },
  },
  {
    name: "users: upsert, membership queries",
    async run(driver) {
      await driver.upsertUser({ userId: "u1", active: true, groupIds: ["g1"], orgIds: ["o1"], managerUserId: "boss" });
      await driver.upsertUser({ userId: "u2", active: false, groupIds: ["g1", "g2"], orgIds: [], managerUserId: null });
      const u1 = await driver.getUser("u1");
      assert.equal(u1?.managerUserId, "boss");
      assert.deepEqual(u1?.orgIds, ["o1"]);
      assert.deepEqual((await driver.listUsersInGroup("g1")).sort(), ["u1", "u2"]);
      assert.deepEqual(await driver.listUsersInGroup("none"), []);
      assert.equal((await driver.listUsers()).length, 2);
      assert.equal(await driver.getUser("ghost"), null);
    },
  },
  {
    name: "users: delete removes the record and its membership edges; absent is a no-op",
    async run(driver) {
      await driver.upsertUser({ userId: "gone", active: true, groupIds: ["g1"], orgIds: [], managerUserId: null });
      await driver.deleteUser("gone");
      assert.equal(await driver.getUser("gone"), null);
      assert.deepEqual(await driver.listUsersInGroup("g1"), []);
      await driver.deleteUser("never-existed"); // must not throw
    },
  },
  {
    name: "requests: insert, update, filters",
    async run(driver) {
      const base: AccessRequest = {
        id: "req1",
        requesterUserId: "u1",
        pattern: "docs.files.read",
        scope: "docs.folder:9",
        justification: { why: "because" },
        state: "pending",
        stageIndex: 0,
        stages: [{ kind: "management", layers: 2 }],
        decisions: [],
        createdAt: 10,
      };
      await driver.insertRequest(base);
      await driver.updateRequest({
        ...base,
        state: "approved",
        decisions: [{ stageIndex: 0, decidedBy: "boss", decision: "approved", at: 20 }],
        decidedAt: 20,
      });
      const read = await driver.getRequest("req1");
      assert.equal(read?.state, "approved");
      assert.equal(read?.decisions.length, 1);
      assert.deepEqual(read?.stages, [{ kind: "management", layers: 2 }]);
      assert.equal((await driver.listRequests({ state: "pending" })).length, 0);
      assert.equal(
        (await driver.listRequests({ requesterUserId: "u1" })).length,
        1,
      );
    },
  },
  {
    name: "catalog: versioned put/get",
    async run(driver) {
      assert.equal(await driver.getCatalog(), null);
      const doc = {
        formatVersion: 1 as const,
        namespace: "docs",
        namespaces: ["docs"],
        leaves: [],
        groups: [],
        scopeTypes: [],
        navigation: [],
      };
      await driver.putCatalog(1, doc);
      await driver.putCatalog(2, doc);
      assert.equal((await driver.getCatalog())?.version, 2);
    },
  },
  {
    name: "catalog: history retained per version when supported",
    async run(driver) {
      const doc = (marker: string) =>
        ({
          formatVersion: 1,
          namespace: "docs",
          namespaces: ["docs"],
          leaves: [],
          groups: [],
          scopeTypes: [],
          navigation: [],
          conventions: { depth: 3 },
          // Distinguish versions through an ignored-but-stored field shape.
          ...(marker ? {} : {}),
        }) as Parameters<StorageDriver["putCatalog"]>[1];
      if (!driver.getCatalogVersion || !driver.listCatalogVersions) return;
      await driver.putCatalog(1, doc("a"), 100);
      await driver.putCatalog(2, doc("b"), 200);
      const head = await driver.getCatalog();
      assert.equal(head!.version, 2);
      const v1 = await driver.getCatalogVersion(1);
      assert.equal(v1!.publishedAt, 100);
      assert.deepEqual(
        (await driver.listCatalogVersions()).map((v) => v.version),
        [1, 2],
      );
      assert.equal(await driver.getCatalogVersion(99), null);
    },
  },
  {
    name: "audit: append-only with target filter and limit",
    async run(driver) {
      for (let i = 0; i < 5; i++) {
        await driver.appendAudit({
          id: `a${i}`,
          at: i,
          actor: "root",
          action: "grant.create",
          target: i % 2 === 0 ? "even" : "odd",
        });
      }
      assert.equal((await driver.listAudit()).length, 5);
      assert.equal((await driver.listAudit({ target: "even" })).length, 3);
      const limited = await driver.listAudit({ limit: 2 });
      assert.deepEqual(
        limited.map((e) => e.id),
        ["a3", "a4"],
      );
    },
  },
  {
    name: "audit: actor/action/time-range filters and (at, id) cursor paging",
    async run(driver) {
      for (let i = 0; i < 6; i++) {
        await driver.appendAudit({
          id: `a${i}`,
          at: Math.floor(i / 2), // two events per millisecond: a0/a1 at 0, …
          actor: i < 3 ? "root" : "ops",
          action: i % 2 === 0 ? "grant.create" : "grant.delete",
          target: "t",
        });
      }
      assert.equal((await driver.listAudit({ actor: "ops" })).length, 3);
      assert.equal(
        (await driver.listAudit({ action: "grant.create" })).length,
        3,
      );
      // from is inclusive, to exclusive.
      assert.deepEqual(
        (await driver.listAudit({ from: 1, to: 2 })).map((e) => e.id),
        ["a2", "a3"],
      );
      // Cursor paging: ascending (at, id), exclusive, stable across ties.
      const page1 = await driver.listAudit({
        cursor: { at: 0, id: "a0" },
        limit: 2,
      });
      assert.deepEqual(
        page1.map((e) => e.id),
        ["a1", "a2"],
      );
      const last1 = page1[page1.length - 1]!;
      const page2 = await driver.listAudit({
        cursor: { at: last1.at, id: last1.id },
        limit: 10,
      });
      assert.deepEqual(
        page2.map((e) => e.id),
        ["a3", "a4", "a5"],
      );
    },
  },
  {
    name: "audit: hash fields round-trip when present",
    async run(driver) {
      await driver.appendAudit({
        id: "h1",
        at: 1,
        actor: "root",
        action: "grant.create",
        target: "t",
        hash: "abc",
      });
      await driver.appendAudit({
        id: "h2",
        at: 2,
        actor: "root",
        action: "grant.create",
        target: "t",
        prevHash: "abc",
        hash: "def",
      });
      const [e1, e2] = await driver.listAudit();
      assert.equal(e1!.hash, "abc");
      assert.equal(e1!.prevHash, undefined);
      assert.equal(e2!.prevHash, "abc");
      assert.equal(e2!.hash, "def");
    },
  },
  {
    name: "runExclusive: serializes work per key",
    async run(driver) {
      const order: number[] = [];
      await Promise.all([
        driver.runExclusive("k", async () => {
          await new Promise((r) => setTimeout(r, 20));
          order.push(1);
        }),
        driver.runExclusive("k", async () => {
          order.push(2);
        }),
      ]);
      assert.deepEqual(order, [1, 2]);
    },
  },
];

/**
 * The event-log contract: for drivers implementing the OPTIONAL persisted
 * invalidation log (`appendEvents`/`headSeq`/`eventsSince`/`pruneEvents`).
 * Register these only for drivers that carry the log — the base contract
 * above never requires it.
 */
export const eventLogContractCases: DriverCase[] = [
  {
    name: "events: contiguous sequences from 1, headSeq tracks the newest",
    async run(driver) {
      assert.equal(await driver.headSeq!(), 0);
      const first = await driver.appendEvents!(
        [{ type: "user", userId: "u1" }],
        1_000,
      );
      assert.equal(first.upTo, 1);
      const second = await driver.appendEvents!(
        [
          { type: "subject", subject: "group:eng" },
          { type: "role", roleId: "r1" },
        ],
        2_000,
      );
      assert.equal(second.upTo, 3);
      assert.equal(await driver.headSeq!(), 3);
    },
  },
  {
    name: "events: eventsSince replays oldest-first past the cursor, honors limit",
    async run(driver) {
      await driver.appendEvents!(
        [
          { type: "user", userId: "u1" },
          { type: "user", userId: "u2" },
          { type: "user", userId: "u3" },
        ],
        1_000,
      );
      const all = await driver.eventsSince!(0, 100);
      assert.ok(!("gap" in all));
      assert.equal(all.upTo, 3);
      assert.deepEqual(
        all.events.map((e) => (e.type === "user" ? e.userId : "?")),
        ["u1", "u2", "u3"],
      );
      const tail = await driver.eventsSince!(1, 100);
      assert.ok(!("gap" in tail));
      assert.deepEqual(
        tail.events.map((e) => (e.type === "user" ? e.userId : "?")),
        ["u2", "u3"],
      );
      // Limit bounds a page; upTo names the cursor for the next loop.
      const page = await driver.eventsSince!(0, 2);
      assert.ok(!("gap" in page));
      assert.equal(page.events.length, 2);
      assert.equal(page.upTo, 2);
      const caughtUp = await driver.eventsSince!(3, 100);
      assert.ok(!("gap" in caughtUp));
      assert.equal(caughtUp.events.length, 0);
      assert.equal(caughtUp.upTo, 3);
    },
  },
  {
    name: "events: pruning reports gaps to stale cursors, newer cursors still catch up",
    async run(driver) {
      for (let i = 1; i <= 6; i++) {
        await driver.appendEvents!([{ type: "user", userId: `u${i}` }], i * 1_000);
      }
      // Prune by age: events at < 4000 (u1..u3) go.
      const pruned = await driver.pruneEvents!({ at: 4_000 });
      assert.equal(pruned, 3);
      const stale = await driver.eventsSince!(2, 100);
      assert.ok("gap" in stale && stale.gap);
      const exact = await driver.eventsSince!(3, 100);
      assert.ok(!("gap" in exact));
      assert.deepEqual(
        exact.events.map((e) => (e.type === "user" ? e.userId : "?")),
        ["u4", "u5", "u6"],
      );
      // Prune by size: keep the newest 1 row (u5 goes too).
      const bySize = await driver.pruneEvents!({ keepRows: 1 });
      assert.equal(bySize, 2);
      assert.equal(await driver.headSeq!(), 6);
      const afterSize = await driver.eventsSince!(5, 100);
      assert.ok(!("gap" in afterSize));
      assert.deepEqual(
        afterSize.events.map((e) => (e.type === "user" ? e.userId : "?")),
        ["u6"],
      );
      // A no-op prune deletes nothing.
      assert.equal(await driver.pruneEvents!({ at: 1_000 }), 0);
    },
  },
];

/**
 * The rolling metric buckets. Optional on the contract — a driver that
 * implements none of these simply cannot host `metrics` — but a driver that
 * implements them must behave exactly like this, because the safeguard
 * numbers are only as honest as the accumulation underneath them.
 */
export const metricsContractCases: DriverCase[] = [
  {
    name: "metrics: increments accumulate on the composite key",
    async run(driver) {
      const key = {
        bucket: 86_400_000,
        dimension: "grant" as const,
        subject: "g1",
        metric: "matched",
      };
      await driver.recordMetrics!([{ ...key, count: 3 }]);
      await driver.recordMetrics!([{ ...key, count: 4 }]);
      // A different metric on the same row is a different counter.
      await driver.recordMetrics!([{ ...key, metric: "soleMatch", count: 2 }]);

      const rows = await driver.readMetrics!({ dimension: "grant" });
      assert.equal(rows.length, 2);
      assert.equal(rows.find((r) => r.metric === "matched")!.count, 7);
      assert.equal(rows.find((r) => r.metric === "soleMatch")!.count, 2);
    },
  },
  {
    name: "metrics: reads filter by dimension, subject, and bucket window",
    async run(driver) {
      const base = { dimension: "grant" as const, metric: "matched", count: 1 };
      await driver.recordMetrics!([
        { ...base, bucket: 0, subject: "g1" },
        { ...base, bucket: 86_400_000, subject: "g1" },
        { ...base, bucket: 86_400_000, subject: "g2" },
        { ...base, bucket: 86_400_000, subject: "p1", dimension: "permission" },
      ]);

      assert.equal((await driver.readMetrics!({ dimension: "grant" })).length, 3);
      assert.equal(
        (await driver.readMetrics!({ dimension: "permission" })).length,
        1,
      );
      assert.deepEqual(
        (
          await driver.readMetrics!({ dimension: "grant", subjects: ["g2"] })
        ).map((r) => r.subject),
        ["g2"],
      );
      // `since` is inclusive, `until` exclusive.
      assert.equal(
        (await driver.readMetrics!({ dimension: "grant", since: 86_400_000 }))
          .length,
        2,
      );
      assert.equal(
        (await driver.readMetrics!({ dimension: "grant", until: 86_400_000 }))
          .length,
        1,
      );
    },
  },
  {
    name: "metrics: pruning drops buckets before the cutoff only",
    async run(driver) {
      const base = {
        dimension: "grant" as const,
        subject: "g1",
        metric: "matched",
        count: 1,
      };
      await driver.recordMetrics!([
        { ...base, bucket: 0 },
        { ...base, bucket: 86_400_000 },
        { ...base, bucket: 2 * 86_400_000 },
      ]);
      assert.equal(await driver.pruneMetrics!(2 * 86_400_000), 2);
      const rows = await driver.readMetrics!({ dimension: "grant" });
      assert.deepEqual(
        rows.map((r) => r.bucket),
        [2 * 86_400_000],
      );
      assert.equal(await driver.pruneMetrics!(0), 0);
    },
  },
];
