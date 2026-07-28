import { describe, expect, it } from "vitest";
import type { MetricsBatch, StorageDriver } from "@alfiz-auth/core";
import {
  ProviderWriteRejectedError,
  createAlfizClient,
  createMetricsAggregator,
  createProviderMetricsSink,
  revocationSafeguard,
} from "@alfiz-auth/core";
import { createApplication, memoryDriver } from "@alfiz-auth/application";
import { admin, makeApp, testCatalog } from "./fixtures.js";

const DAY = 86_400_000;

/** A window's worth of counters, shaped as the client would report them. */
const batch = (over: Partial<MetricsBatch> = {}): MetricsBatch => ({
  instanceId: "web-1",
  windowStart: 1_000_000,
  windowEnd: 1_060_000,
  checks: [],
  grants: [],
  revokes: [],
  roles: [],
  principals: { distinct: 1, overflowed: false },
  dropped: 0,
  ...over,
});

const rowCounter = (rowId: string, matched: number, soleMatch: number) => ({
  rowId,
  matched,
  soleMatch,
  estimatedMatched: matched,
  estimatedSoleMatch: soleMatch,
  recentPrincipals: ["user:u1"],
});

describe("the metrics capability", () => {
  it("is off by default and advertised when on", async () => {
    expect((await makeApp().app.capabilities()).metrics).toBe(false);
    expect((await makeApp({ metrics: {} }).app.capabilities()).metrics).toBe(true);
  });

  it("refuses to enable against a driver that cannot store buckets", () => {
    const partial = memoryDriver();
    delete (partial as Partial<StorageDriver>).recordMetrics;
    expect(() =>
      createApplication({ catalog: testCatalog(), storage: partial, metrics: {} }),
    ).toThrow(ProviderWriteRejectedError);
  });

  it("rejects reports and reads when metrics are off", async () => {
    const { app } = makeApp();
    await expect(app.reportMetrics(batch())).rejects.toThrow(
      ProviderWriteRejectedError,
    );
    await expect(app.getGrantUsage()).rejects.toThrow(ProviderWriteRejectedError);
  });
});

describe("reportMetrics", () => {
  it("accumulates counters across batches and app servers", async () => {
    const { app } = makeApp({ metrics: {} });
    await app.reportMetrics(
      batch({ instanceId: "web-1", grants: [rowCounter("grant-a", 10, 4)] }),
    );
    await app.reportMetrics(
      batch({ instanceId: "web-2", grants: [rowCounter("grant-a", 5, 1)] }),
    );

    const [usage] = await app.getGrantUsage({ ids: ["grant-a"] });
    expect(usage).toMatchObject({ rowId: "grant-a", matched: 15, soleMatch: 5 });
  });

  it("keys usage by row, and separates grants from revokes and roles", async () => {
    const { app } = makeApp({ metrics: {} });
    await app.reportMetrics(
      batch({
        grants: [rowCounter("grant-a", 3, 3), rowCounter("grant-b", 9, 0)],
        revokes: [rowCounter("revoke-a", 7, 7)],
        roles: [rowCounter("role-lead", 3, 3)],
      }),
    );

    const grants = await app.getGrantUsage();
    expect(grants.map((u) => u.rowId).sort()).toEqual(["grant-a", "grant-b"]);
    expect((await app.getRevokeUsage())[0]).toMatchObject({
      rowId: "revoke-a",
      matched: 7,
    });
    expect((await app.getRoleUsage())[0]).toMatchObject({ rowId: "role-lead" });
  });

  it("splits per-permission counts by gate versus visibility", async () => {
    const { app } = makeApp({ metrics: {} });
    await app.reportMetrics(
      batch({
        checks: [
          {
            permission: "docs.files.delete",
            decision: "allow",
            shape: "can",
            gate: true,
            scopeType: "docs.folder",
            observed: 12,
            estimated: 12,
          },
          {
            permission: "docs.files.delete",
            decision: "deny",
            shape: "require",
            gate: true,
            scopeType: "docs.folder",
            observed: 3,
            estimated: 3,
          },
          {
            permission: "docs.files.delete",
            decision: "allow",
            shape: "holds",
            gate: false,
            scopeType: "*",
            observed: 4_000,
            estimated: 4_000,
          },
        ],
      }),
    );

    const [usage] = await app.getPermissionUsage({ ids: ["docs.files.delete"] });
    // 40 000 renders and 12 actions are different numbers and stay that way.
    expect(usage).toMatchObject({
      permission: "docs.files.delete",
      gateAllow: 12,
      gateDeny: 3,
      visibilityAllow: 4_000,
      visibilityDeny: 0,
    });

    const [byScope] = await app.getScopeTypeUsage({ ids: ["docs.folder"] });
    expect(byScope).toMatchObject({ gateAllow: 12, gateDeny: 3 });
  });

  it("returns per-bucket series alongside the totals", async () => {
    const { app, advance } = makeApp({ metrics: {} });
    const start = 1_000_000;
    const counter = (estimated: number) => ({
      permission: "docs.files.read",
      decision: "allow" as const,
      shape: "can" as const,
      gate: true,
      scopeType: "docs.folder",
      observed: estimated,
      estimated,
    });
    await app.reportMetrics(batch({ windowStart: start, checks: [counter(10)] }));
    advance(2 * DAY);
    await app.reportMetrics(
      batch({ windowStart: start + 2 * DAY, checks: [counter(4)] }),
    );

    const [usage] = await app.getPermissionUsage({ ids: ["docs.files.read"] });
    // Totals are exactly the series summed — one read answers both questions.
    expect(usage!.gateAllow).toBe(14);
    expect(usage!.buckets.map((b) => b.gateAllow)).toEqual([10, 4]);
    expect(usage!.buckets[0]!.bucket).toBeLessThan(usage!.buckets[1]!.bucket);
    // Empty days are absent rather than zero-filled.
    expect(usage!.buckets).toHaveLength(2);
  });

  it("buckets by day and reports per-bucket detail", async () => {
    const { app, advance } = makeApp({ metrics: {} });
    const start = 1_000_000;
    await app.reportMetrics(
      batch({ windowStart: start, grants: [rowCounter("grant-a", 2, 2)] }),
    );
    advance(2 * DAY);
    await app.reportMetrics(
      batch({
        windowStart: start + 2 * DAY,
        grants: [rowCounter("grant-a", 5, 1)],
      }),
    );

    const [usage] = await app.getGrantUsage({ ids: ["grant-a"] });
    expect(usage!.matched).toBe(7);
    expect(usage!.buckets).toHaveLength(2);
    expect(usage!.buckets[0]!.bucket).toBeLessThan(usage!.buckets[1]!.bucket);
    expect(usage!.buckets.map((b) => b.matched)).toEqual([2, 5]);
  });

  it("honours the query window", async () => {
    const { app, advance } = makeApp({ metrics: {} });
    await app.reportMetrics(
      batch({ windowStart: 1_000_000, grants: [rowCounter("grant-a", 2, 2)] }),
    );
    advance(5 * DAY);
    await app.reportMetrics(
      batch({
        windowStart: 1_000_000 + 5 * DAY,
        grants: [rowCounter("grant-a", 8, 8)],
      }),
    );

    const recent = await app.getGrantUsage({ since: 1_000_000 + 4 * DAY });
    expect(recent[0]!.matched).toBe(8);
  });

  it("prunes buckets past retention", async () => {
    const { app, storage, advance } = makeApp({
      metrics: { retentionMs: DAY },
    });
    await app.reportMetrics(
      batch({ windowStart: 1_000_000, grants: [rowCounter("grant-a", 1, 1)] }),
    );
    advance(30 * DAY);
    // Pruning is opportunistic — 32 reports, then a sweep.
    for (let i = 0; i < 32; i++) {
      await app.reportMetrics(
        batch({
          windowStart: 1_000_000 + 30 * DAY,
          grants: [rowCounter("grant-b", 1, 0)],
        }),
      );
    }
    await new Promise((resolve) => setTimeout(resolve, 0));
    const remaining = await storage.readMetrics!({ dimension: "grant" });
    expect(remaining.every((row) => row.subject === "grant-b")).toBe(true);
  });
});

describe("end to end: checks in, safeguards out", () => {
  it("counts real checks and warns about the grant that carries them", async () => {
    const { app, now } = makeApp({ metrics: {} });
    const grant = await app.createGrant({
      subject: "user:u1",
      pattern: "docs.files.delete",
      scope: "docs.folder:9",
      provenance: admin,
    });
    // The sink's clock is the Application's: batches are stamped with the
    // window they cover, and the store buckets by that stamp.
    const sink = createProviderMetricsSink(app, { windowMs: 60_000, clock: now });
    const client = createAlfizClient({
      catalog: testCatalog(),
      provider: app,
      metrics: { observer: sink.observer },
    });

    for (let i = 0; i < 5; i++) {
      expect(
        await client.can({ userId: "u1" }, "docs.files.delete", "docs.folder:9"),
      ).toBe(true);
    }
    // A denied check for good measure — it must not be attributed anywhere.
    await client.can({ userId: "u2" }, "docs.files.delete", "docs.folder:9");
    await sink.stop();

    const [usage] = await app.getGrantUsage({ ids: [grant.id] });
    expect(usage).toMatchObject({ matched: 5, soleMatch: 5 });

    const safeguard = revocationSafeguard(usage!);
    expect(safeguard.level).toBe("warning");
    expect(safeguard.headline).toContain("only thing allowing 5 checks");

    const [permission] = await app.getPermissionUsage({
      ids: ["docs.files.delete"],
    });
    expect(permission).toMatchObject({ gateAllow: 5, gateDeny: 1 });
  });

  it("a second, broader grant turns the warning into context", async () => {
    const { app, now } = makeApp({ metrics: {} });
    const narrow = await app.createGrant({
      subject: "user:u1",
      pattern: "docs.files.delete",
      scope: "docs.folder:9",
      provenance: admin,
    });
    await app.createGrant({
      subject: "everyone",
      pattern: "docs.files.*",
      scope: "docs.folder:9",
      provenance: admin,
    });
    const sink = createProviderMetricsSink(app, { windowMs: 60_000, clock: now });
    const client = createAlfizClient({
      catalog: testCatalog(),
      provider: app,
      metrics: { observer: sink.observer },
    });

    await client.can({ userId: "u1" }, "docs.files.delete", "docs.folder:9");
    await sink.stop();

    const [usage] = await app.getGrantUsage({ ids: [narrow.id] });
    expect(usage).toMatchObject({ matched: 1, soleMatch: 0 });
    expect(revocationSafeguard(usage!).level).toBe("context");
  });

  it("sampling scales the stored estimate back up", async () => {
    const { app, now } = makeApp({ metrics: {} });
    const grant = await app.createGrant({
      subject: "user:u1",
      pattern: "docs.files.read",
      scope: "docs.folder:9",
      provenance: admin,
    });
    const sink = createProviderMetricsSink(app, { windowMs: 60_000, clock: now });
    const client = createAlfizClient({
      catalog: testCatalog(),
      provider: app,
      metrics: { observer: sink.observer, sampleRate: 0.1, random: () => 0.05 },
    });

    for (let i = 0; i < 10; i++) {
      await client.can({ userId: "u1" }, "docs.files.read", "docs.folder:9");
    }
    await sink.stop();

    // Ten checks, all kept by the stubbed random, each standing for ten.
    const [usage] = await app.getGrantUsage({ ids: [grant.id] });
    expect(usage!.matched).toBe(100);
  });

  it("a local aggregator is a complete direct-read API with no store at all", async () => {
    const { app } = makeApp();
    await app.createGrant({
      subject: "user:u1",
      pattern: "docs.files.read",
      provenance: admin,
    });
    const metrics = createMetricsAggregator({ clock: () => 1_000_000 });
    const client = createAlfizClient({
      catalog: testCatalog(),
      provider: app,
      metrics: { observer: metrics.observer },
    });

    await client.can({ userId: "u1" }, "docs.files.read");
    await client.canAny({ userId: "u1" }, "docs.*");

    const snapshot = metrics.snapshot();
    expect(snapshot.checks).toHaveLength(2);
    expect(snapshot.principals.distinct).toBe(1);
    expect((await app.capabilities()).metrics).toBe(false);
  });
});

describe("view-as", () => {
  it("does not attribute the previewed subject's grants to the preview", async () => {
    const { app, now } = makeApp({ metrics: {} });
    const actorGrant = await app.createGrant({
      subject: "user:admin1",
      pattern: "docs.*",
      provenance: admin,
    });
    const previewedGrant = await app.createGrant({
      subject: "user:u1",
      pattern: "docs.files.read",
      provenance: admin,
    });
    const sink = createProviderMetricsSink(app, { windowMs: 60_000, clock: now });
    const client = createAlfizClient({
      catalog: testCatalog(),
      provider: app,
      metrics: { observer: sink.observer },
    });
    const { AlfizSession } = await import("@alfiz-auth/application");
    const session = new AlfizSession(client, {
      actorUserId: "admin1",
      viewAs: { kind: "user", userId: "u1" },
    });

    expect(await session.can("docs.files.read")).toBe(true);
    const snap = await session.snapshot();
    expect(snap.can("docs.files.read")).toBe(true);
    await sink.stop();

    // The administrator's own grant carries the check; the previewed
    // person's does not. Attribution never follows the preview.
    const usage = await app.getGrantUsage();
    const byId = new Map(usage.map((u) => [u.rowId, u]));
    expect(byId.get(actorGrant.id)!.matched).toBe(2);
    expect(byId.has(previewedGrant.id)).toBe(false);
  });
});
