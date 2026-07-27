/**
 * The event poller: cross-process invalidation for long-lived nodes,
 * exercised with two Applications over one shared storage driver — the
 * closest in-process approximation of two nodes on one database.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { InvalidationEvent } from "@alfiz-auth/core";
import {
  createApplication,
  memoryDriver,
  startEventPoller,
} from "@alfiz-auth/application";
import { admin, testCatalog } from "./fixtures.js";

describe("startEventPoller", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  function twoNodes() {
    const storage = memoryDriver();
    const nodeA = createApplication({
      catalog: testCatalog(),
      storage,
      events: { persist: true },
    });
    const nodeB = createApplication({
      catalog: testCatalog(),
      storage,
      events: { persist: true },
    });
    return { storage, nodeA, nodeB };
  }

  it("refuses an Application without event persistence", () => {
    const app = createApplication({
      catalog: testCatalog(),
      storage: memoryDriver(),
    });
    expect(() => startEventPoller(app)).toThrow(/events\.persist/);
  });

  it("delivers another node's events into local listeners within one poll", async () => {
    const { nodeA, nodeB } = twoNodes();
    const seenOnB: InvalidationEvent[] = [];
    nodeB.onInvalidate((event) => seenOnB.push(event));
    const poller = startEventPoller(nodeB, { intervalMs: 1_000 });
    await vi.advanceTimersByTimeAsync(0); // first tick pins the cursor

    await nodeA.createGrant({
      subject: "user:u1",
      pattern: "docs.files.read",
      provenance: admin,
    });
    expect(seenOnB).toHaveLength(0); // nothing until the next poll
    await vi.advanceTimersByTimeAsync(1_000);
    expect(seenOnB).toEqual([
      { type: "subject", subject: "user:u1" },
      { type: "user", userId: "u1" },
    ]);
    poller.stop();
  });

  it("starts from the current head: history is not replayed", async () => {
    const { nodeA, nodeB } = twoNodes();
    await nodeA.createGrant({
      subject: "user:old",
      pattern: "docs.files.read",
      provenance: admin,
    });
    const seenOnB: InvalidationEvent[] = [];
    nodeB.onInvalidate((event) => seenOnB.push(event));
    const poller = startEventPoller(nodeB, { intervalMs: 1_000 });
    await vi.advanceTimersByTimeAsync(2_500);
    expect(seenOnB).toHaveLength(0);
    poller.stop();
  });

  it("a gap ingests a full bust and resumes from the head", async () => {
    const { storage, nodeA, nodeB } = twoNodes();
    const seenOnB: InvalidationEvent[] = [];
    nodeB.onInvalidate((event) => seenOnB.push(event));
    const poller = startEventPoller(nodeB, { intervalMs: 1_000 });
    await vi.advanceTimersByTimeAsync(0);

    await nodeA.setUserActive("u1", false, admin);
    // Retention passed the poller by: its cursor now predates the log.
    await storage.pruneEvents!({ keepRows: 0 });
    await vi.advanceTimersByTimeAsync(1_000);
    expect(seenOnB).toEqual([{ type: "all" }]);
    // Later events flow normally again.
    await nodeA.setUserActive("u2", false, admin);
    await vi.advanceTimersByTimeAsync(1_000);
    expect(seenOnB).toEqual([{ type: "all" }, { type: "user", userId: "u2" }]);
    poller.stop();
  });

  it("polling errors are reported and retried, and stop() stops", async () => {
    const { nodeA, nodeB } = twoNodes();
    const errors: unknown[] = [];
    const realSince = nodeB.epoch!.since.bind(nodeB.epoch!);
    let failNext = false;
    (nodeB.epoch as { since: typeof realSince }).since = async (seq, limit) => {
      if (failNext) {
        failNext = false;
        throw new Error("log unreachable");
      }
      return realSince(seq, limit);
    };
    const seenOnB: InvalidationEvent[] = [];
    nodeB.onInvalidate((event) => seenOnB.push(event));
    const poller = startEventPoller(nodeB, {
      intervalMs: 1_000,
      onError: (error) => errors.push(error),
    });
    await vi.advanceTimersByTimeAsync(0);
    await nodeA.setUserActive("u1", false, admin);
    failNext = true;
    await vi.advanceTimersByTimeAsync(1_000);
    expect(errors).toHaveLength(1);
    expect(seenOnB).toHaveLength(0);
    await vi.advanceTimersByTimeAsync(1_000); // retried on the next tick
    expect(seenOnB).toEqual([{ type: "user", userId: "u1" }]);
    poller.stop();
    await nodeA.setUserActive("u2", false, admin);
    await vi.advanceTimersByTimeAsync(5_000);
    expect(seenOnB).toEqual([{ type: "user", userId: "u1" }]);
  });
});
