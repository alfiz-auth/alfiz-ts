/**
 * The storage-driver contract suite: every driver — memory, Prisma, or
 * yours — must pass these cases unchanged. Framework-free: cases are
 * (name, run) pairs using node:assert, so any test runner can host them.
 */

import assert from "node:assert/strict";
import type { StorageDriver } from "@alfiz-auth/application";
import type { AccessRequest, GrantRow, RevokeRow } from "@alfiz-auth/core";

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
    name: "revokes: insert, filter by user, delete",
    async run(driver) {
      await driver.insertRevoke(revoke("r1", "u1"));
      await driver.insertRevoke(revoke("r2", "u2"));
      assert.deepEqual(
        (await driver.listRevokes({ userId: "u1" })).map((r) => r.id),
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
