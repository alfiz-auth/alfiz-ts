/**
 * Event persistence (`events.persist`): the invalidation log is the
 * cross-process freshness signal, so its core invariant is that the DURABLE
 * stream equals the LIVE stream — any write another process must learn
 * about is exactly the set the local listeners were told about.
 */
import { describe, expect, it } from "vitest";
import type { InvalidationEvent } from "@alfiz-auth/core";
import { createApplication, memoryDriver } from "@alfiz-auth/application";
import { admin, makeApp, testCatalog } from "./fixtures.js";

function makePersistingApp() {
  return makeApp({ events: { persist: true } });
}

async function readLog(
  app: ReturnType<typeof makeApp>["app"],
): Promise<InvalidationEvent[]> {
  const result = await app.epoch!.since(0, 10_000);
  if ("gap" in result) throw new Error("unexpected gap");
  return result.events;
}

describe("events.persist", () => {
  it("refuses a driver without the event methods, loudly", () => {
    const storage = memoryDriver();
    delete (storage as { appendEvents?: unknown }).appendEvents;
    expect(() =>
      createApplication({
        catalog: testCatalog(),
        storage,
        events: { persist: true },
      }),
    ).toThrow(/appendEvents/);
  });

  it("exposes epoch only when persistence is on", () => {
    expect(makeApp().app.epoch).toBeUndefined();
    expect(makePersistingApp().app.epoch).toBeDefined();
  });

  it("the durable stream equals the live stream, across every write kind", async () => {
    const { app } = makePersistingApp();
    const live: InvalidationEvent[] = [];
    app.onInvalidate((event) => live.push(event));

    // A battery covering every emitting write path.
    const role = await app.createRole(
      { name: "Reader", patterns: ["docs.files.read"] },
      admin,
    );
    await app.updateRole(role.id, { name: "Readers" }, admin);
    await app.createGroup({ id: "eng", name: "Engineering" }, admin);
    await app.createGroup({ id: "web", name: "Web" }, admin);
    await app.setGroupParents("web", ["eng"], admin);
    await app.setGroupMembership("u1", ["web"], admin);
    await app.setUserActive("u2", false, admin);
    await app.setReportingEdge("u1", "boss", admin);
    const grant = await app.createGrant({
      subject: "group:eng",
      roleId: role.id,
      provenance: admin,
    });
    const bulk = await app.createGrants(
      [
        { subject: "user:u1", pattern: "docs.files.read" },
        { subject: "user:u1", pattern: "docs.admin.read" },
        { subject: "user:u3", pattern: "docs.files.read" },
      ],
      admin,
    );
    const revoke = await app.createRevoke({
      userId: "u1",
      pattern: "docs.files.read",
      scope: "docs.folder:9",
      provenance: admin,
    });
    await app.deleteRevoke(revoke.id, admin);
    await app.deleteGrant(bulk[2]!.id, admin);
    await app.notifyScopeMoved("docs.doc:1");
    await app.publishCatalog(testCatalog().toDocument(), admin);
    await app.deleteScope("docs.folder:9", admin);
    await app.deleteSubject("user:u3", admin);
    await app.deleteGrant(grant.id, admin);
    await app.deleteGroup("web", admin);
    await app.deleteRole(role.id, admin);
    await app.importDirectory({ users: [{ userId: "u9" }] }, "test-directory");

    expect(live.length).toBeGreaterThan(10);
    expect(await readLog(app)).toEqual(live);
    expect(await app.epoch!.head()).toBe(live.length);
  });

  it("a write returns only after its events are durable", async () => {
    const { app } = makePersistingApp();
    await app.createGrant({
      subject: "user:u1",
      pattern: "docs.files.read",
      provenance: admin,
    });
    // No settling, no timers: the awaited write IS the durability point.
    expect(await app.epoch!.head()).toBeGreaterThan(0);
  });

  it("append failure surfaces to the writer and retries on the next flush", async () => {
    const storage = memoryDriver();
    const realAppend = storage.appendEvents!.bind(storage);
    let failNext = true;
    storage.appendEvents = async (events, at) => {
      if (failNext) {
        failNext = false;
        throw new Error("event store down");
      }
      return realAppend(events, at);
    };
    const app = createApplication({
      catalog: testCatalog(),
      storage,
      events: { persist: true },
    });
    await expect(
      app.createGrant({
        subject: "user:u1",
        pattern: "docs.files.read",
        provenance: admin,
      }),
    ).rejects.toThrow("event store down");
    // The failed batch was restored: the next write persists both.
    await app.createGrant({
      subject: "user:u2",
      pattern: "docs.files.read",
      provenance: admin,
    });
    const log = await app.epoch!.since(0, 100);
    if ("gap" in log) throw new Error("unexpected gap");
    expect(log.events).toEqual([
      { type: "subject", subject: "user:u1" },
      { type: "user", userId: "u1" },
      { type: "subject", subject: "user:u2" },
      { type: "user", userId: "u2" },
    ]);
  });

  it("ingestEvents re-emits to local listeners without re-persisting", async () => {
    const { app } = makePersistingApp();
    const live: InvalidationEvent[] = [];
    app.onInvalidate((event) => live.push(event));
    app.ingestEvents([
      { type: "user", userId: "remote-user" },
      { type: "subject", subject: "group:remote" },
    ]);
    expect(live).toHaveLength(2);
    expect(await app.epoch!.head()).toBe(0);
  });

  it("ingested group events bust the topology cache", async () => {
    const { app, storage } = makePersistingApp();
    await app.createGroup({ id: "eng", name: "Engineering" }, admin);
    await app.setGroupMembership("u1", ["eng"], admin);
    const before = await app.getSubjectAccess({ userId: "u1" });
    expect(before.closure).toContain("group:eng");
    // Another process reparents eng under root — simulated at the seam.
    await storage.upsertGroup({
      id: "root",
      name: "Root",
      parents: [],
    });
    await storage.upsertGroup({
      id: "eng",
      name: "Engineering",
      parents: ["root"],
    });
    // Without ingestion the topology cache still holds the old edges…
    const stale = await app.getSubjectAccess({ userId: "u1" });
    expect(stale.closure).not.toContain("group:root");
    // …ingesting the remote event busts it.
    app.ingestEvents([{ type: "subject", subject: "group:eng" }]);
    const fresh = await app.getSubjectAccess({ userId: "u1" });
    expect(fresh.closure).toContain("group:root");
  });

  it("retention pruning kicks in after enough appends", async () => {
    const { app, storage } = makeApp({
      events: { persist: true, retention: { maxRows: 10 } },
    });
    // 33 single-event appends: the 32nd flush triggers an opportunistic
    // prune down to the newest 10 rows.
    for (let i = 0; i < 33; i++) {
      await app.setUserActive(`u${i}`, true, admin);
    }
    // The prune is fire-and-forget; give it a microtask turn.
    await new Promise((resolve) => setImmediate(resolve));
    const head = await storage.headSeq!();
    const stale = await storage.eventsSince!(0, 1000);
    expect(head).toBe(33);
    expect("gap" in stale && stale.gap).toBe(true);
    const recent = await storage.eventsSince!(head - 5, 1000);
    if ("gap" in recent) throw new Error("recent cursor should not gap");
    expect(recent.events).toHaveLength(5);
  });
});
