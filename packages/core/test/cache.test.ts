/**
 * The shared cache tier (L2): serverless cold starts find warm closures,
 * and every failure or freshness doubt is a miss — never an answer.
 */
import { describe, expect, it } from "vitest";
import type { CacheStore } from "../src/cache.js";
import { respCacheStore } from "../src/cache.js";
import type {
  IoRedisLikeClient,
  NodeRedisLikeClient,
} from "../src/cache.js";
import type { GrantRow } from "../src/access.js";
import { defineCatalog } from "../src/catalog.js";
import { createAlfizClient } from "../src/client.js";
import type {
  AlfizProvider,
  InvalidationEvent,
  InvalidationListener,
  SubjectAccessData,
} from "../src/provider.js";

const catalog = defineCatalog({
  namespaces: ["docs"],
  includeAlfizInternal: false,
  permissions: {
    "docs.files.read": { scopes: ["docs.folder", "docs.doc"] },
  },
  scopeTypes: {
    "docs.folder": { parent: "docs.folder" },
    "docs.doc": { parent: "docs.folder" },
  },
});

const grant = (): GrantRow => ({
  id: "g1",
  subject: "user:u1",
  pattern: "docs.files.read",
  scope: "*",
  provenance: { kind: "admin", actorUserId: "root" },
  createdAt: 0,
});

/** A provider with a scriptable log, counting fetches. */
function makeProvider() {
  const listeners = new Set<InvalidationListener>();
  const log: InvalidationEvent[] = [];
  let fetches = 0;
  return {
    getSubjectAccess: async (): Promise<SubjectAccessData> => {
      fetches++;
      return {
        userId: "u1",
        closure: ["user:u1", "everyone"],
        grants: [grant()],
        revokes: [],
        roles: [],
        managerChain: [],
        unresolvedRoleIds: [],
        active: true,
      };
    },
    resolveAncestors: () => ["*"],
    onInvalidate: (listener: InvalidationListener) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    epoch: {
      head: async () => log.length,
      since: async (seq: number, limit = 500) => ({
        upTo: seq + log.slice(seq, seq + limit).length,
        events: log.slice(seq, seq + limit),
      }),
    },
    append: (event: InvalidationEvent) => log.push(event),
    stats: () => ({ fetches }),
  };
}

/** An in-memory CacheStore with error injection and call counters. */
function makeStore() {
  const backing = new Map<string, string>();
  let failGets = false;
  let gets = 0;
  let sets = 0;
  const store: CacheStore = {
    async get(key) {
      gets++;
      if (failGets) throw new Error("cache down");
      return backing.get(key) ?? null;
    },
    async set(key, value) {
      sets++;
      backing.set(key, value);
    },
    async delete(key) {
      backing.delete(key);
    },
  };
  return {
    store,
    backing,
    stats: () => ({ gets, sets }),
    failGets: (value: boolean) => {
      failGets = value;
    },
  };
}

const flushWrites = () => new Promise((resolve) => setImmediate(resolve));

describe("CacheStore (L2)", () => {
  it("a cold client with a warm L2 and a quiet epoch pays zero provider fetches", async () => {
    const provider = makeProvider();
    const { store } = makeStore();
    const clientOptions = {
      catalog,
      provider: provider as unknown as AlfizProvider,
      cacheStore: store,
      revalidateAfterMs: 5_000,
    };
    // Process A warms the L2…
    const a = createAlfizClient(clientOptions);
    expect(await a.can({ userId: "u1" }, "docs.files.read")).toBe(true);
    await flushWrites();
    expect(provider.stats().fetches).toBe(1);
    a.close();
    // …process B (a cold serverless invocation) starts empty.
    const b = createAlfizClient(clientOptions);
    expect(await b.can({ userId: "u1" }, "docs.files.read")).toBe(true);
    expect(provider.stats().fetches).toBe(1); // L2 hit, no fan-out
  });

  it("an entry written under an older head is discarded", async () => {
    const provider = makeProvider();
    const { store } = makeStore();
    const clientOptions = {
      catalog,
      provider: provider as unknown as AlfizProvider,
      cacheStore: store,
      revalidateAfterMs: 5_000,
    };
    const a = createAlfizClient(clientOptions);
    await a.can({ userId: "u1" }, "docs.files.read");
    await flushWrites();
    a.close();
    // A write lands anywhere in the system: the head advances.
    provider.append({ type: "user", userId: "someone-else" });
    const b = createAlfizClient(clientOptions);
    await b.can({ userId: "u1" }, "docs.files.read");
    expect(provider.stats().fetches).toBe(2); // stale seq: refetched
  });

  it("without an epoch, L2 entries are honored only within their TTL", async () => {
    const provider = makeProvider();
    const { epoch, ...epochless } = provider;
    const { store } = makeStore();
    let now = 1_000;
    const clientOptions = {
      catalog,
      provider: epochless as unknown as AlfizProvider,
      cacheStore: store,
      subjectCacheTtlMs: 30_000,
      clock: () => now,
    };
    const a = createAlfizClient(clientOptions);
    await a.can({ userId: "u1" }, "docs.files.read");
    await flushWrites();
    a.close();
    const b = createAlfizClient(clientOptions);
    await b.can({ userId: "u1" }, "docs.files.read");
    expect(provider.stats().fetches).toBe(1); // fresh: served from L2
    b.close();
    now += 31_000;
    const c = createAlfizClient(clientOptions);
    await c.can({ userId: "u1" }, "docs.files.read");
    expect(provider.stats().fetches).toBe(2); // past freshUntil: refetched
  });

  it("L2 errors and garbage envelopes are misses, reported but never served", async () => {
    const provider = makeProvider();
    const { store, backing, failGets } = makeStore();
    const errors: unknown[] = [];
    const client = createAlfizClient({
      catalog,
      provider: provider as unknown as AlfizProvider,
      cacheStore: store,
      revalidateAfterMs: 5_000,
      subjectCacheTtlMs: 0, // force every check through the L2 path
      onCacheStoreError: (error) => errors.push(error),
    });
    failGets(true);
    expect(await client.can({ userId: "u1" }, "docs.files.read")).toBe(true);
    expect(provider.stats().fetches).toBe(1);
    expect(errors).toHaveLength(1);
    failGets(false);
    // Unparseable and version-mismatched envelopes: misses, not answers.
    backing.set("alfiz:v1:sub:u:u1", "not json at all");
    await client.can({ userId: "u1" }, "docs.files.read");
    expect(provider.stats().fetches).toBe(2);
    backing.set(
      "alfiz:v1:sub:u:u1",
      JSON.stringify({ v: 99, seq: 0, data: {} }),
    );
    await client.can({ userId: "u1" }, "docs.files.read");
    expect(provider.stats().fetches).toBe(3);
  });
});

describe("respCacheStore", () => {
  it("adapts the node-redis call shape (options object)", async () => {
    const calls: unknown[][] = [];
    const backing = new Map<string, string>();
    const client: NodeRedisLikeClient = {
      async get(key) {
        return backing.get(key) ?? null;
      },
      async set(key, value, options) {
        calls.push([key, value, options]);
        backing.set(key, value);
      },
      async del(key) {
        backing.delete(key);
      },
    };
    const store = respCacheStore(client);
    await store.set("k", "v", 60_000);
    expect(calls).toEqual([["k", "v", { PX: 60_000 }]]);
    expect(await store.get("k")).toBe("v");
    await store.delete("k");
    expect(await store.get("k")).toBeNull();
  });

  it("falls back to the ioredis call shape (positional) and remembers it", async () => {
    const calls: unknown[][] = [];
    const backing = new Map<string, string>();
    const client: IoRedisLikeClient = {
      async get(key) {
        return backing.get(key) ?? null;
      },
      async set(key, value, mode, ttlMs) {
        // A real RESP server rejects the whole command on a bad argument —
        // nothing is written.
        if (typeof mode !== "string" || typeof ttlMs !== "number") {
          throw new Error("ERR syntax error");
        }
        calls.push([key, value, mode, ttlMs]);
        backing.set(key, value);
      },
      async del(key) {
        backing.delete(key);
      },
    };
    const store = respCacheStore(client);
    await store.set("k", "v", 60_000);
    await store.set("k2", "v2", 30_000);
    expect(calls).toEqual([
      ["k", "v", "PX", 60_000],
      ["k2", "v2", "PX", 30_000],
    ]);
    expect(await store.get("k2")).toBe("v2");
  });
});
