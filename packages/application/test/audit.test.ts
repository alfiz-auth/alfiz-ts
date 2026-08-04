import { describe, expect, it } from "vitest";
import { defineCatalog } from "@alfiz/core";
import type { Provenance } from "@alfiz/core";
import {
  computeAuditHash,
  createApplication,
  memoryDriver,
  verifyAuditChain,
} from "@alfiz/application";

const catalog = defineCatalog({
  application: "docs",
  namespaces: ["docs"],
  permissions: {
    "docs.files.read": {},
    "docs.files.edit": {},
  },
});

const admin: Provenance = { kind: "admin", actorUserId: "root" };

function makeApp(options?: { hashChain?: boolean }) {
  let tick = 1_000;
  return createApplication({
    catalog,
    storage: memoryDriver(),
    ...(options?.hashChain ? { audit: { hashChain: true } } : {}),
    clock: () => ++tick,
  });
}

describe("audit filters", () => {
  it("filters by actor, action, and time range through listAuditEvents", async () => {
    const app = makeApp();
    await app.createGrant({ subject: "user:u1", pattern: "docs.files.read", provenance: admin });
    await app.createGrant({
      subject: "user:u2",
      pattern: "docs.files.edit",
      provenance: { kind: "admin", actorUserId: "other" },
    });
    expect(await app.listAuditEvents({ actor: "root" })).toHaveLength(1);
    expect(await app.listAuditEvents({ action: "grant.create" })).toHaveLength(2);
    const all = await app.listAuditEvents();
    expect(await app.listAuditEvents({ to: all[1]!.at })).toHaveLength(1);
  });

  it("pages an export with the (at, id) cursor", async () => {
    const app = makeApp();
    for (let i = 0; i < 5; i++) {
      await app.createGrant({
        subject: `user:u${i}`,
        pattern: "docs.files.read",
        provenance: admin,
      });
    }
    const exported = [];
    let cursor: { at: number; id: string } | undefined;
    for (;;) {
      const page = await app.listAuditEvents({
        ...(cursor ? { cursor } : { cursor: { at: 0, id: "" } }),
        limit: 2,
      });
      exported.push(...page);
      if (page.length < 2) break;
      const last = page[page.length - 1]!;
      cursor = { at: last.at, id: last.id };
    }
    expect(exported).toHaveLength(5);
    expect(new Set(exported.map((e) => e.id)).size).toBe(5);
  });
});

describe("audit hash chain", () => {
  it("is off by default", async () => {
    const app = makeApp();
    await app.createGrant({ subject: "user:u1", pattern: "docs.files.read", provenance: admin });
    const [event] = await app.listAuditEvents();
    expect(event!.hash).toBeUndefined();
  });

  it("chains every entry and verifies end to end", async () => {
    const app = makeApp({ hashChain: true });
    await app.createGrant({ subject: "user:u1", pattern: "docs.files.read", provenance: admin });
    const grants = await app.listGrants();
    await app.deleteGrant(grants[0]!.id, admin);
    await app.createRevoke({ userId: "u1", pattern: "docs.*", provenance: admin });

    const events = await app.listAuditEvents();
    expect(events.length).toBeGreaterThanOrEqual(3);
    for (const event of events) expect(event.hash).toBeDefined();
    const result = verifyAuditChain(events);
    expect(result).toEqual({ ok: true, hashed: events.length });
  });

  it("detects a tampered entry and a broken link", async () => {
    const app = makeApp({ hashChain: true });
    await app.createGrant({ subject: "user:u1", pattern: "docs.files.read", provenance: admin });
    await app.createRevoke({ userId: "u1", pattern: "docs.*", provenance: admin });
    const events = await app.listAuditEvents();

    const tampered = events.map((e, i) => (i === 0 ? { ...e, actor: "evil" } : e));
    expect(verifyAuditChain(tampered)).toMatchObject({ ok: false, reason: "hash_mismatch" });

    const dropped = events.slice(1); // deleting the first entry breaks the next link
    expect(verifyAuditChain(dropped)).toMatchObject({ ok: false });
  });

  it("starts mid-log when enabled later, leaving earlier entries unhashed", async () => {
    const storage = memoryDriver();
    let tick = 0;
    const before = createApplication({ catalog, storage, clock: () => ++tick });
    await before.createGrant({ subject: "user:u1", pattern: "docs.files.read", provenance: admin });

    const after = createApplication({
      catalog,
      storage,
      audit: { hashChain: true },
      clock: () => ++tick,
    });
    await after.createRevoke({ userId: "u1", pattern: "docs.*", provenance: admin });

    const events = await after.listAuditEvents();
    expect(events[0]!.hash).toBeUndefined();
    expect(events.at(-1)!.hash).toBeDefined();
    expect(verifyAuditChain(events)).toEqual({ ok: true, hashed: 1 });
  });

  it("computeAuditHash is stable across detail key order", () => {
    const base = { id: "x", at: 1, actor: "a", action: "b", target: "c" };
    const h1 = computeAuditHash({ ...base, detail: { b: 1, a: 2 } }, null);
    const h2 = computeAuditHash({ ...base, detail: { a: 2, b: 1 } }, null);
    expect(h1).toBe(h2);
  });
});
