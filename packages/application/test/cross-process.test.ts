/**
 * The end-to-end story this whole design exists for: two processes on one
 * database (simulated as two Applications over one storage driver), a
 * client on each, and a revocation on process A becoming effective on
 * process B within the revalidation window — not the cache TTL — while
 * quiet periods cost B zero closure refetches. Plus the round-trip budget
 * per scenario, pinned with an instrumented driver.
 */
import { describe, expect, it } from "vitest";
import { createAlfizClient } from "@alfiz-auth/core";
import type { StorageDriver } from "@alfiz-auth/application";
import { createApplication, memoryDriver } from "@alfiz-auth/application";
import { admin, testAncestry, testCatalog } from "./fixtures.js";

function instrument(driver: StorageDriver): {
  driver: StorageDriver;
  calls: Record<string, number>;
  total: () => number;
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
  return {
    driver: wrapped,
    calls,
    total: () => Object.values(calls).reduce((a, b) => a + b, 0),
  };
}

function twoProcesses() {
  let tick = 1_000_000;
  const clock = () => tick;
  const advance = (ms: number) => {
    tick += ms;
  };
  const base = memoryDriver();
  const seeded = instrument(base);
  const appA = createApplication({
    catalog: testCatalog(),
    storage: base,
    ancestry: testAncestry,
    clock,
    events: { persist: true },
  });
  const appB = createApplication({
    catalog: testCatalog(),
    storage: seeded.driver,
    ancestry: testAncestry,
    clock,
    events: { persist: true },
  });
  return { appA, appB, clock, advance, calls: seeded.calls, total: seeded.total };
}

describe("cross-process revocation", () => {
  it("a revoke on process A denies on process B within the revalidation window, not the TTL", async () => {
    const { appA, appB, clock, advance } = twoProcesses();
    const grant = await appA.createGrant({
      subject: "user:u1",
      pattern: "docs.files.read",
      provenance: admin,
    });
    // B's client: an ENORMOUS TTL, so any propagation observed here is the
    // epoch's doing, not expiry.
    const clientB = createAlfizClient({
      catalog: testCatalog(),
      provider: appB,
      clock,
      subjectCacheTtlMs: 3_600_000,
      revalidateAfterMs: 5_000,
    });
    expect(await clientB.can({ userId: "u1" }, "docs.files.read")).toBe(true);

    await appA.deleteGrant(grant.id, admin);
    // Still within B's validation window: the cached answer serves.
    expect(await clientB.can({ userId: "u1" }, "docs.files.read")).toBe(true);
    // One window later B revalidates, replays A's events, and denies.
    advance(6_000);
    expect(await clientB.can({ userId: "u1" }, "docs.files.read")).toBe(false);
  });

  it("offboarding on process A (setUserActive false) sticks on process B one window later", async () => {
    const { appA, appB, clock, advance } = twoProcesses();
    await appA.createGrant({
      subject: "everyone",
      pattern: "docs.files.read",
      provenance: admin,
    });
    const clientB = createAlfizClient({
      catalog: testCatalog(),
      provider: appB,
      clock,
      subjectCacheTtlMs: 3_600_000,
      revalidateAfterMs: 5_000,
    });
    expect(await clientB.can({ userId: "mallory" }, "docs.files.read")).toBe(true);
    await appA.setUserActive("mallory", false, admin);
    advance(6_000);
    expect(await clientB.can({ userId: "mallory" }, "docs.files.read")).toBe(false);
  });
});

describe("round-trip budget per scenario", () => {
  it("warm hit: zero storage reads; quiet window boundary: exactly one head read", async () => {
    const { appA, appB, clock, advance, calls, total } = twoProcesses();
    await appA.createGrant({
      subject: "user:u1",
      pattern: "docs.files.read",
      provenance: admin,
    });
    const clientB = createAlfizClient({
      catalog: testCatalog(),
      provider: appB,
      clock,
      revalidateAfterMs: 5_000,
    });
    await clientB.can({ userId: "u1" }, "docs.files.read"); // cold miss, paid once
    const afterMiss = total();

    // Warm hits inside the window: pure memory.
    await clientB.can({ userId: "u1" }, "docs.files.read");
    await clientB.can({ userId: "u1" }, "docs.files.read");
    expect(total()).toBe(afterMiss);

    // Past the window with a quiet log: ONE headSeq read revalidates
    // everything — no closure refetch, no group scan, nothing else.
    advance(6_000);
    const headBefore = calls.headSeq ?? 0;
    await clientB.can({ userId: "u1" }, "docs.files.read");
    await clientB.can({ userId: "u1" }, "docs.files.read");
    expect((calls.headSeq ?? 0) - headBefore).toBe(1);
    expect(total()).toBe(afterMiss + 1);

    // And far past the old TTL, still nothing but one head read per window.
    advance(120_000);
    await clientB.can({ userId: "u1" }, "docs.files.read");
    expect(total()).toBe(afterMiss + 2);
  });

  it("the epoch costs at most one extra read per window and wins outright past the TTL", async () => {
    // Same battery against both modes. The epoch client may issue at most
    // ONE more storage call per phase — the constant-cost head read — and
    // must be strictly cheaper once the TTL would have expired, at small
    // scale (this fixture IS small scale) as at large.
    async function run(revalidate: boolean) {
      const { appA, appB, clock, advance, total } = twoProcesses();
      await appA.createGrant({
        subject: "user:u1",
        pattern: "docs.files.read",
        provenance: admin,
      });
      const client = createAlfizClient({
        catalog: testCatalog(),
        provider: appB,
        clock,
        subjectCacheTtlMs: 30_000,
        ...(revalidate ? { revalidateAfterMs: 5_000 } : {}),
      });
      const perPhase: number[] = [];
      const phase = async (advanceMs: number, checks: number) => {
        advance(advanceMs);
        const before = total();
        for (let i = 0; i < checks; i++) {
          await client.can({ userId: "u1" }, "docs.files.read");
        }
        perPhase.push(total() - before);
      };
      await phase(0, 3); // cold miss + warm hits
      await phase(6_000, 3); // one window later
      await phase(31_000, 3); // past the TTL
      await phase(31_000, 3); // and again
      return perPhase;
    }
    const withEpoch = await run(true);
    const ttlOnly = await run(false);
    for (let i = 0; i < ttlOnly.length; i++) {
      expect(withEpoch[i]!).toBeLessThanOrEqual(ttlOnly[i]! + 1);
    }
    // Past the TTL the epoch mode does ONE head read where TTL-only pays
    // the whole closure fan-out again.
    expect(withEpoch[2]!).toBeLessThan(ttlOnly[2]!);
    expect(withEpoch[3]!).toBeLessThan(ttlOnly[3]!);
  });
});
