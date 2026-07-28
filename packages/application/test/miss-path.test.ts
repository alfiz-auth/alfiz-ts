/**
 * The closure-supply miss path: query counts and topology-cache behavior.
 * getSubjectAccess is what every client cache miss pays for, so these tests
 * pin its round-trip budget — the group table is read once per topology TTL
 * (not per miss), roles are resolved once (batched when the driver can),
 * and independent queries overlap.
 */
import { describe, expect, it } from "vitest";
import type { StorageDriver } from "@alfiz/application";
import { createApplication, memoryDriver } from "@alfiz/application";
import { admin, testAncestry, testCatalog } from "./fixtures.js";

/** Wraps a driver, counting calls per method. */
function instrument(driver: StorageDriver): {
  driver: StorageDriver;
  calls: Record<string, number>;
} {
  const calls: Record<string, number> = {};
  const wrapped = new Proxy(driver, {
    get(target, prop, receiver) {
      const value = Reflect.get(target, prop, receiver);
      if (typeof value !== "function") return value;
      return (...args: unknown[]) => {
        const key = String(prop);
        calls[key] = (calls[key] ?? 0) + 1;
        return (value as (...a: unknown[]) => unknown).apply(target, args);
      };
    },
  });
  return { driver: wrapped, calls };
}

function makeInstrumentedApp(options?: {
  groupTopologyTtlMs?: number;
  withoutGetRoles?: boolean;
}) {
  const base = memoryDriver();
  if (options?.withoutGetRoles) {
    // Simulate a custom driver predating the optional batch read.
    delete (base as { getRoles?: unknown }).getRoles;
  }
  const { driver, calls } = instrument(base);
  let tick = 1_000_000;
  const app = createApplication({
    catalog: testCatalog(),
    storage: driver,
    ancestry: testAncestry,
    clock: () => tick,
    ...(options?.groupTopologyTtlMs !== undefined
      ? { groupTopologyTtlMs: options.groupTopologyTtlMs }
      : {}),
  });
  return { app, calls, storage: driver, advance: (ms: number) => (tick += ms) };
}

async function seed(app: ReturnType<typeof makeInstrumentedApp>["app"]) {
  await app.createGroup({ id: "eng", name: "Engineering" }, admin);
  await app.createGroup({ id: "web", name: "Web", parents: ["eng"] }, admin);
  await app.setGroupMembership("u1", ["web"], admin);
  const role = await app.createRole(
    { id: "reader", name: "Reader", patterns: ["docs.files.read"] },
    admin,
  );
  await app.createGrant({
    subject: "group:eng",
    roleId: role.id,
    provenance: admin,
  });
  await app.createGrant({
    subject: "user:u1",
    pattern: "docs.admin.read",
    provenance: admin,
  });
}

describe("getSubjectAccess miss path", () => {
  it("reads the group table once per topology TTL, not once per miss", async () => {
    const { app, calls, advance } = makeInstrumentedApp();
    await seed(app);
    calls.listGroups = 0;

    await app.getSubjectAccess({ userId: "u1" });
    await app.getSubjectAccess({ userId: "u1" });
    await app.getSubjectAccess({ userId: "u2" });
    expect(calls.listGroups).toBe(1);

    // Past the TTL, the next miss re-reads once.
    advance(31_000);
    await app.getSubjectAccess({ userId: "u1" });
    await app.getSubjectAccess({ userId: "u1" });
    expect(calls.listGroups).toBe(2);
  });

  it("a local group write busts the topology cache synchronously", async () => {
    const { app, calls } = makeInstrumentedApp();
    await seed(app);

    const before = await app.getSubjectAccess({ userId: "u1" });
    expect(before.closure).toContain("group:eng");

    // Detach web from eng: u1's closure must lose group:eng immediately,
    // within the same topology-TTL window. (The write itself reads the
    // group table for its cycle check — count only reads after it.)
    await app.setGroupParents("web", [], admin);
    calls.listGroups = 0;
    const after = await app.getSubjectAccess({ userId: "u1" });
    expect(calls.listGroups).toBe(1);
    expect(after.closure).not.toContain("group:eng");
  });

  it("groupTopologyTtlMs: 0 restores the per-miss scan", async () => {
    const { app, calls } = makeInstrumentedApp({ groupTopologyTtlMs: 0 });
    await seed(app);
    calls.listGroups = 0;
    await app.getSubjectAccess({ userId: "u1" });
    await app.getSubjectAccess({ userId: "u1" });
    expect(calls.listGroups).toBe(2);
  });

  it("concurrent misses share one topology read", async () => {
    const { app, calls } = makeInstrumentedApp();
    await seed(app);
    calls.listGroups = 0;
    await Promise.all([
      app.getSubjectAccess({ userId: "u1" }),
      app.getSubjectAccess({ userId: "u2" }),
      app.getSubjectAccess({ userId: "u3" }),
    ]);
    expect(calls.listGroups).toBe(1);
  });

  it("resolves roles once via the batch read when the driver has one", async () => {
    const { app, calls } = makeInstrumentedApp();
    await seed(app);
    calls.getRole = 0;
    calls.getRoles = 0;
    const data = await app.getSubjectAccess({ userId: "u1" });
    expect(data.roles.map((r) => r.id)).toEqual(["reader"]);
    expect(calls.getRoles).toBe(1);
    expect(calls.getRole).toBe(0);
  });

  it("falls back to one parallel getRole per distinct id without the batch read", async () => {
    const { app, calls } = makeInstrumentedApp({ withoutGetRoles: true });
    await seed(app);
    calls.getRole = 0;
    const data = await app.getSubjectAccess({ userId: "u1" });
    expect(data.roles.map((r) => r.id)).toEqual(["reader"]);
    expect(calls.getRole).toBe(1); // one distinct roleId → one read, not two
  });

  it("reports unresolved role ids from the same read as resolved ones", async () => {
    const { app, storage } = makeInstrumentedApp();
    await seed(app);
    // A stranded row referencing a role that no longer exists — the
    // data-integrity signal unresolvedRoleIds exists for. Written at the
    // storage seam because the Application's own write path (correctly)
    // refuses to create it.
    await storage.insertGrant({
      id: "stranded",
      subject: "user:u1",
      roleId: "ghost",
      scope: "*",
      provenance: admin,
      createdAt: 0,
    });
    const data = await app.getSubjectAccess({ userId: "u1" });
    expect(data.roles.map((r) => r.id)).toEqual(["reader"]);
    expect(data.unresolvedRoleIds).toEqual(["ghost"]);
  });

  it("produces identical SubjectAccessData with and without the topology cache", async () => {
    const cached = makeInstrumentedApp();
    const uncached = makeInstrumentedApp({ groupTopologyTtlMs: 0 });
    await seed(cached.app);
    await seed(uncached.app);
    await cached.app.setReportingEdge("u1", "boss", admin);
    await uncached.app.setReportingEdge("u1", "boss", admin);

    const a = await cached.app.getSubjectAccess({ userId: "u1" });
    const b = await uncached.app.getSubjectAccess({ userId: "u1" });
    // Ids differ (random per instance); compare everything shape-relevant.
    expect(a.closure).toEqual(b.closure);
    expect(a.managerChain).toEqual(b.managerChain);
    expect(a.roles.map((r) => r.id)).toEqual(b.roles.map((r) => r.id));
    expect(a.unresolvedRoleIds).toEqual(b.unresolvedRoleIds);
    expect(a.grants.length).toBe(b.grants.length);
    expect(a.active).toBe(b.active);
  });
});
