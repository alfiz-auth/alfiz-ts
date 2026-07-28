import { describe, expect, it } from "vitest";
import {
  driverContractCases,
  eventLogContractCases,
  metricsContractCases,
} from "../../application/test/driver-suite.js";
import { prismaDriver } from "../src/index.js";
import { mockDelegates } from "./mock-delegates.js";

describe("prismaDriver passes the storage contract", () => {
  for (const testCase of [
    ...driverContractCases,
    ...eventLogContractCases,
    ...metricsContractCases,
  ]) {
    it(testCase.name, async () => {
      await testCase.run(prismaDriver(mockDelegates()));
    });
  }
});

describe("prismaDriver without the optional models", () => {
  it("omits the event methods when alfizEpoch/alfizEvent are absent", () => {
    const db = mockDelegates() as Partial<
      ReturnType<typeof mockDelegates>
    > & { alfizEpoch?: unknown; alfizEvent?: unknown };
    delete db.alfizEpoch;
    delete db.alfizEvent;
    const driver = prismaDriver(db as never);
    expect(driver.appendEvents).toBeUndefined();
    expect(driver.headSeq).toBeUndefined();
    expect(driver.eventsSince).toBeUndefined();
    expect(driver.pruneEvents).toBeUndefined();
  });

  it("omits the metric methods when alfizMetric is absent", () => {
    const db = mockDelegates() as Partial<ReturnType<typeof mockDelegates>> & {
      alfizMetric?: unknown;
    };
    delete db.alfizMetric;
    const driver = prismaDriver(db as never);
    expect(driver.recordMetrics).toBeUndefined();
    expect(driver.readMetrics).toBeUndefined();
    expect(driver.pruneMetrics).toBeUndefined();
  });
});

describe("prismaDriver mapping specifics", () => {
  it("round-trips absent optionals as SQL NULL and back to undefined", async () => {
    const db = mockDelegates();
    const driver = prismaDriver(db);

    await driver.insertGrant({
      id: "g1",
      subject: "user:u1",
      pattern: "docs.files.read",
      scope: "*",
      provenance: { kind: "admin", actorUserId: "root" },
      createdAt: 1,
    });
    // Stored as null, per Prisma's nullable-column convention...
    const rawGrant = await db.alfizGrant.findUnique({ where: { id: "g1" } });
    expect(rawGrant?.roleId).toBeNull();
    expect(rawGrant?.expiresAt).toBeNull();
    // ...and read back as undefined, per the core types' convention.
    const [grant] = await driver.listGrants({ subject: "user:u1" });
    expect(grant?.roleId).toBeUndefined();
    expect(grant?.pattern).toBe("docs.files.read");
    expect(grant?.expiresAt).toBeUndefined();

    await driver.insertRequest({
      id: "req1",
      requesterUserId: "u1",
      pattern: "docs.files.read",
      scope: "*",
      justification: {},
      state: "pending",
      stageIndex: 0,
      stages: [],
      decisions: [],
      createdAt: 5,
    });
    const rawRequest = await db.alfizRequest.findUnique({ where: { id: "req1" } });
    expect(rawRequest?.roleId).toBeNull();
    expect(rawRequest?.decidedAt).toBeNull();
    const request = await driver.getRequest("req1");
    expect(request?.roleId).toBeUndefined();
    expect(request?.decidedAt).toBeUndefined();

    // The populated direction: decidedAt number ↔ BigInt column.
    await driver.updateRequest({
      ...(await driver.getRequest("req1"))!,
      state: "approved",
      decidedAt: 42,
    });
    expect((await db.alfizRequest.findUnique({ where: { id: "req1" } }))?.decidedAt).toBe(42n);
    expect((await driver.getRequest("req1"))?.decidedAt).toBe(42);
  });

  it("preserves large epoch-ms values through BigInt columns", async () => {
    const db = mockDelegates();
    const driver = prismaDriver(db);
    const expiresAt = 8_640_000_000_000_000; // the maximum JS Date epoch ms
    const createdAt = 1_753_436_400_123;

    await driver.insertGrant({
      id: "g-big",
      subject: "user:u1",
      pattern: "docs.files.read",
      scope: "*",
      expiresAt,
      provenance: { kind: "system" },
      createdAt,
    });
    const raw = await db.alfizGrant.findUnique({ where: { id: "g-big" } });
    expect(raw?.expiresAt).toBe(8_640_000_000_000_000n);
    expect(raw?.createdAt).toBe(1_753_436_400_123n);

    const [read] = await driver.listGrants();
    expect(read?.expiresAt).toBe(expiresAt);
    expect(read?.createdAt).toBe(createdAt);
  });

  it("reconciles membership rows on upsertUser (adds and removes)", async () => {
    const db = mockDelegates();
    const driver = prismaDriver(db);
    const base = { userId: "u1", active: true, orgIds: [], managerUserId: null };

    await driver.upsertUser({ ...base, groupIds: ["g1", "g2"] });
    expect((await driver.getUser("u1"))?.groupIds.sort()).toEqual(["g1", "g2"]);

    await driver.upsertUser({ ...base, groupIds: ["g2", "g3"] });
    expect(await driver.listUsersInGroup("g1")).toEqual([]);
    expect(await driver.listUsersInGroup("g2")).toEqual(["u1"]);
    expect(await driver.listUsersInGroup("g3")).toEqual(["u1"]);
    expect((await driver.getUser("u1"))?.groupIds.sort()).toEqual(["g2", "g3"]);

    // Exactly the surviving edge rows remain — nothing orphaned, no duplicates.
    expect(await db.alfizMembership.findMany()).toHaveLength(2);
  });
});
