import { describe, expect, it } from "vitest";
import type { GrantRow, RevokeRow, RoleDef } from "../src/access.js";
import { defineCatalog } from "../src/catalog.js";
import { createAlfizClient } from "../src/client.js";
import { AccessDeniedError } from "../src/errors.js";
import type {
  AlfizProvider,
  InvalidationEvent,
  InvalidationListener,
  SubjectAccessData,
} from "../src/provider.js";

const catalog = defineCatalog({
  namespace: "docs",
  includeAlfizInternal: false,
  projects: {
    docs: {
      groups: {
        files: {
          permissions: {
            read: { scopes: ["docs.folder", "docs.doc"] },
            read_listing: { scopes: ["docs.folder"], impliedOnAncestors: true },
            update_file: { scopes: ["docs.folder", "docs.doc"] },
            delete: { scopes: ["docs.folder"] },
          },
        },
      },
    },
  },
  scopeTypes: {
    // Folders nest in folders: a self-referencing parent, not `null` —
    // `parent: null` would commit folder chains to `[scope, "*"]`.
    "docs.folder": { parent: "docs.folder" },
    "docs.doc": { parent: "docs.folder" },
  },
});

/** A scriptable fake provider: subject data + parent pointers + events. */
function fakeProvider(state: {
  grants: GrantRow[];
  revokes?: RevokeRow[];
  roles?: RoleDef[];
  closure?: string[];
  active?: boolean;
  parents?: Record<string, string>;
}) {
  const listeners = new Set<InvalidationListener>();
  let fetches = 0;
  let resolves = 0;
  const provider = {
    getSubjectAccess: async (): Promise<SubjectAccessData> => {
      fetches++;
      return {
        userId: "u1",
        closure: state.closure ?? ["user:u1", "everyone"],
        grants: state.grants,
        revokes: state.revokes ?? [],
        roles: state.roles ?? [],
        managerChain: [],
        unresolvedRoleIds: [],
        active: state.active ?? true,
      };
    },
    resolveAncestors: (scope: string) => {
      resolves++;
      const chain: string[] = [];
      let current: string | undefined = state.parents?.[scope];
      while (current !== undefined) {
        chain.push(current);
        current = state.parents?.[current];
      }
      chain.push("*");
      return chain;
    },
    onInvalidate: (listener: InvalidationListener) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    emit: (event: Parameters<InvalidationListener>[0]) => {
      for (const l of listeners) l(event);
    },
    stats: () => ({ fetches, resolves }),
  };
  return provider as typeof provider & AlfizProvider;
}

const g = (
  subject: string,
  what: { pattern?: string; roleId?: string },
  scope = "*",
  expiresAt?: number,
): GrantRow => ({
  id: Math.random().toString(36).slice(2),
  subject,
  pattern: what.pattern,
  roleId: what.roleId,
  scope,
  expiresAt,
  provenance: { kind: "admin", actorUserId: "root" },
  createdAt: 0,
});

describe("AlfizClient.can", () => {
  it("global and scoped checks against the object closure", async () => {
    const provider = fakeProvider({
      grants: [g("user:u1", { pattern: "docs.files.read" }, "docs.folder:9")],
      parents: { "docs.doc:1": "docs.folder:9" },
    });
    const client = createAlfizClient({ catalog, provider });
    expect(await client.can({ userId: "u1" }, "docs.files.read", "docs.doc:1")).toBe(true);
    expect(await client.can({ userId: "u1" }, "docs.files.read", "docs.doc:2")).toBe(false);
    expect(await client.can({ userId: "u1" }, "docs.files.read")).toBe(false);
    expect(await client.can({ userId: "u1" }, "docs.files.delete", "docs.doc:1")).toBe(false);
  });

  it("any-of arrays gate on any key", async () => {
    const provider = fakeProvider({ grants: [g("user:u1", { pattern: "docs.files.read" })] });
    const client = createAlfizClient({ catalog, provider });
    expect(await client.can({ userId: "u1" }, ["docs.files.delete", "docs.files.read"])).toBe(true);
    expect(await client.can({ userId: "u1" }, ["docs.files.delete", "docs.files.update_file"])).toBe(false);
  });

  it("inactive principals evaluate to no access", async () => {
    const provider = fakeProvider({
      grants: [g("user:u1", { pattern: "*" })],
      active: false,
    });
    const client = createAlfizClient({ catalog, provider });
    expect(await client.can({ userId: "u1" }, "docs.files.read")).toBe(false);
  });

  it("caches subject data within TTL and re-fetches after invalidation", async () => {
    const provider = fakeProvider({ grants: [g("user:u1", { pattern: "docs.files.read" })] });
    let now = 1000;
    const client = createAlfizClient({ catalog, provider, clock: () => now, subjectCacheTtlMs: 30_000 });
    await client.can({ userId: "u1" }, "docs.files.read");
    await client.can({ userId: "u1" }, "docs.files.read");
    expect(provider.stats().fetches).toBe(1);

    provider.emit({ type: "user", userId: "u1" });
    await client.can({ userId: "u1" }, "docs.files.read");
    expect(provider.stats().fetches).toBe(2);

    now += 31_000; // TTL expiry
    await client.can({ userId: "u1" }, "docs.files.read");
    expect(provider.stats().fetches).toBe(3);
  });

  it("busts subject caches on closure-member events", async () => {
    const provider = fakeProvider({
      grants: [g("group:team", { pattern: "docs.files.read" })],
      closure: ["user:u1", "group:team", "everyone"],
    });
    const client = createAlfizClient({ catalog, provider });
    await client.can({ userId: "u1" }, "docs.files.read");
    provider.emit({ type: "subject", subject: "group:team" });
    await client.can({ userId: "u1" }, "docs.files.read");
    expect(provider.stats().fetches).toBe(2);
  });

  it("caches object chains until a scope event busts chains through the moved node", async () => {
    const provider = fakeProvider({
      grants: [g("user:u1", { pattern: "docs.files.read" }, "docs.folder:9")],
      parents: { "docs.doc:1": "docs.folder:9" },
    });
    const client = createAlfizClient({ catalog, provider });
    await client.can({ userId: "u1" }, "docs.files.read", "docs.doc:1");
    await client.can({ userId: "u1" }, "docs.files.read", "docs.doc:1");
    expect(provider.stats().resolves).toBe(1);
    provider.emit({ type: "scope", scope: "docs.folder:9" });
    await client.can({ userId: "u1" }, "docs.files.read", "docs.doc:1");
    expect(provider.stats().resolves).toBe(2);
  });

  it("can.fresh bypasses both caches", async () => {
    const provider = fakeProvider({
      grants: [g("user:u1", { pattern: "docs.files.read" }, "docs.folder:9")],
      parents: { "docs.doc:1": "docs.folder:9" },
    });
    const client = createAlfizClient({ catalog, provider });
    await client.can({ userId: "u1" }, "docs.files.read", "docs.doc:1");
    await client.can.fresh({ userId: "u1" }, "docs.files.read", "docs.doc:1");
    expect(provider.stats().fetches).toBe(2);
    expect(provider.stats().resolves).toBe(2);
  });

  it("expired grants deny (time-bound lapse)", async () => {
    const provider = fakeProvider({
      grants: [g("user:u1", { pattern: "docs.files.read" }, "*", 500)],
    });
    const client = createAlfizClient({ catalog, provider, clock: () => 1000 });
    expect(await client.can({ userId: "u1" }, "docs.files.read")).toBe(false);
  });
});

describe("review regressions", () => {
  it("can(u, key, '*') agrees with can(u, key) for impliedOnAncestors leaves", async () => {
    const provider = fakeProvider({
      grants: [g("user:u1", { pattern: "docs.files.read_listing" }, "docs.folder:9")],
      parents: { "docs.folder:9": "docs.folder:2" },
    });
    const client = createAlfizClient({ catalog, provider });
    // One narrow share must not pass the broadest possible check.
    expect(await client.can({ userId: "u1" }, "docs.files.read_listing")).toBe(false);
    expect(await client.can({ userId: "u1" }, "docs.files.read_listing", "*")).toBe(false);
    // Proper ancestors still get the implication.
    expect(await client.can({ userId: "u1" }, "docs.files.read_listing", "docs.folder:2")).toBe(true);
  });

  it("explain agrees with can and reports the implication", async () => {
    const provider = fakeProvider({
      grants: [g("user:u1", { pattern: "docs.files.read_listing" }, "docs.folder:9")],
      parents: { "docs.folder:9": "docs.folder:2" },
    });
    const client = createAlfizClient({ catalog, provider });
    const atAncestor = await client.explain({ userId: "u1" }, "docs.files.read_listing", "docs.folder:2");
    expect(atAncestor.allowed).toBe(true);
    expect(atAncestor.implied).toBe(true);
    expect(atAncestor.matchedGrants).toEqual([]); // no direct match — implication only
    const atGlobal = await client.explain({ userId: "u1" }, "docs.files.read_listing");
    expect(atGlobal.allowed).toBe(false);
    expect(atGlobal.implied).toBe(false);
  });

  it("an invalidation landing during an in-flight fetch is not lost", async () => {
    let release: (() => void) | undefined;
    let fetches = 0;
    const base = fakeProvider({ grants: [g("user:u1", { pattern: "docs.files.read" })] });
    const provider = {
      ...base,
      getSubjectAccess: async (p: Parameters<typeof base.getSubjectAccess>[0]) => {
        fetches++;
        if (fetches === 1) {
          await new Promise<void>((r) => {
            release = r;
          });
        }
        return base.getSubjectAccess(p);
      },
    };
    const client = createAlfizClient({ catalog, provider });
    const first = client.can({ userId: "u1" }, "docs.files.read");
    // The bust arrives while the fetch is still in flight…
    provider.emit({ type: "user", userId: "u1" });
    release!();
    await first;
    // …so the stale result must NOT have been cached: the next check refetches.
    await client.can({ userId: "u1" }, "docs.files.read");
    expect(fetches).toBe(2);
    client.close();
  });

  it("a wildcard grant at a scope confers only keys grantable at that scope type", async () => {
    const provider = fakeProvider({
      grants: [g("user:u1", { pattern: "docs.files.*" }, "docs.doc:1")],
    });
    const client = createAlfizClient({ catalog, provider });
    expect(await client.can({ userId: "u1" }, "docs.files.read", "docs.doc:1")).toBe(true);
    // delete is folder-only: it does not escape through the wildcard.
    expect(await client.can({ userId: "u1" }, "docs.files.delete", "docs.doc:1")).toBe(false);
  });

  it("effectiveKeys ignores scoped revokes (they narrow one subtree, not the held set)", async () => {
    const provider = fakeProvider({
      grants: [g("user:u1", { pattern: "docs.files.read" })],
      revokes: [
        {
          id: "r1",
          userId: "u1",
          pattern: "docs.files.read",
          scope: "docs.folder:9",
          provenance: { kind: "admin", actorUserId: "root" },
          createdAt: 0,
        },
      ],
    });
    const client = createAlfizClient({ catalog, provider });
    expect(await client.effectiveKeys({ userId: "u1" })).toContain("docs.files.read");
  });
});

describe("cache hygiene", () => {
  it("objectCache is bounded: least-recently-used chains evict first", async () => {
    const provider = fakeProvider({
      grants: [g("user:u1", { pattern: "docs.files.read" }, "docs.folder:root")],
      parents: {
        "docs.doc:1": "docs.folder:root",
        "docs.doc:2": "docs.folder:root",
        "docs.doc:3": "docs.folder:root",
      },
    });
    const client = createAlfizClient({
      catalog,
      provider,
      maxObjectCacheEntries: 2,
    });
    await client.can({ userId: "u1" }, "docs.files.read", "docs.doc:1");
    await client.can({ userId: "u1" }, "docs.files.read", "docs.doc:2");
    // Hit doc:1 so doc:2 becomes the least recently used…
    await client.can({ userId: "u1" }, "docs.files.read", "docs.doc:1");
    expect(provider.stats().resolves).toBe(2);
    // …then doc:3 evicts doc:2, not doc:1.
    await client.can({ userId: "u1" }, "docs.files.read", "docs.doc:3");
    await client.can({ userId: "u1" }, "docs.files.read", "docs.doc:1");
    expect(provider.stats().resolves).toBe(3); // doc:1 still cached
    await client.can({ userId: "u1" }, "docs.files.read", "docs.doc:2");
    expect(provider.stats().resolves).toBe(4); // doc:2 was evicted
  });

  it("subjectCache eviction is LRU: a hit entry survives", async () => {
    let fetches = 0;
    const listeners = new Set<InvalidationListener>();
    const provider: AlfizProvider = {
      getSubjectAccess: async (p) => {
        fetches++;
        return {
          userId: "userId" in p ? p.userId : null,
          closure: ["userId" in p ? `user:${p.userId}` : `service:x`, "everyone"],
          grants: [],
          revokes: [],
          roles: [],
          managerChain: [],
          unresolvedRoleIds: [],
          active: true,
        };
      },
      resolveAncestors: () => ["*"],
      onInvalidate: (l) => {
        listeners.add(l);
        return () => listeners.delete(l);
      },
    } as unknown as AlfizProvider;
    const client = createAlfizClient({
      catalog,
      provider,
      maxSubjectCacheEntries: 2,
    });
    await client.can({ userId: "a" }, "docs.files.read");
    await client.can({ userId: "b" }, "docs.files.read");
    await client.can({ userId: "a" }, "docs.files.read"); // refresh a's recency
    await client.can({ userId: "c" }, "docs.files.read"); // evicts b, not a
    expect(fetches).toBe(3);
    await client.can({ userId: "a" }, "docs.files.read"); // still cached
    expect(fetches).toBe(3);
    await client.can({ userId: "b" }, "docs.files.read"); // was evicted
    expect(fetches).toBe(4);
  });

  it("concurrent object-chain misses for the same scope resolve once", async () => {
    let release: (() => void) | undefined;
    const gate = new Promise<void>((r) => {
      release = r;
    });
    let resolves = 0;
    const base = fakeProvider({
      grants: [g("user:u1", { pattern: "docs.files.read" }, "docs.folder:9")],
      parents: { "docs.doc:1": "docs.folder:9" },
    });
    const provider = {
      ...base,
      resolveAncestors: async (scope: string) => {
        resolves++;
        await gate;
        return base.resolveAncestors(scope);
      },
    };
    const client = createAlfizClient({ catalog, provider });
    const first = client.can({ userId: "u1" }, "docs.files.read", "docs.doc:1");
    const second = client.can({ userId: "u1" }, "docs.files.read", "docs.doc:1");
    release!();
    expect(await first).toBe(true);
    expect(await second).toBe(true);
    expect(resolves).toBe(1);
  });

  it("a scope bust landing during an in-flight chain resolution is not lost", async () => {
    let release: (() => void) | undefined;
    let resolves = 0;
    const base = fakeProvider({
      grants: [g("user:u1", { pattern: "docs.files.read" }, "docs.folder:9")],
      parents: { "docs.doc:1": "docs.folder:9" },
    });
    const provider = {
      ...base,
      resolveAncestors: async (scope: string) => {
        resolves++;
        if (resolves === 1) {
          await new Promise<void>((r) => {
            release = r;
          });
        }
        return base.resolveAncestors(scope);
      },
    };
    const client = createAlfizClient({ catalog, provider });
    const first = client.can({ userId: "u1" }, "docs.files.read", "docs.doc:1");
    provider.emit({ type: "scope", scope: "docs.doc:1" });
    release!();
    await first;
    // The stale chain must not have been cached: the next check re-resolves.
    await client.can({ userId: "u1" }, "docs.files.read", "docs.doc:1");
    expect(resolves).toBe(2);
  });

  it("internal maps drain once fetches settle and caches are busted", async () => {
    const provider = fakeProvider({
      grants: [g("user:u1", { pattern: "docs.files.read" }, "docs.folder:9")],
      parents: { "docs.doc:1": "docs.folder:9" },
    });
    const client = createAlfizClient({ catalog, provider });
    await client.can({ userId: "u1" }, "docs.files.read", "docs.doc:1");
    // Repeated bust/refetch cycles must not accumulate per-key state (the
    // generation maps this design replaced grew one entry per busted key).
    for (let i = 0; i < 5; i++) {
      provider.emit({ type: "user", userId: "u1" });
      provider.emit({ type: "scope", scope: "docs.doc:1" });
      await client.can({ userId: "u1" }, "docs.files.read", "docs.doc:1");
    }
    const internals = client as unknown as {
      subjectFetchStates: Map<string, unknown>;
      objectFetchStates: Map<string, unknown>;
      subjectInFlight: Map<string, unknown>;
      objectInFlight: Map<string, unknown>;
      closureIndex: Map<string, Set<string>>;
      roleIndex: Map<string, Set<string>>;
      chainIndex: Map<string, Set<string>>;
    };
    expect(internals.subjectFetchStates.size).toBe(0);
    expect(internals.objectFetchStates.size).toBe(0);
    expect(internals.subjectInFlight.size).toBe(0);
    expect(internals.objectInFlight.size).toBe(0);
    provider.emit({ type: "all" });
    expect(internals.closureIndex.size).toBe(0);
    expect(internals.roleIndex.size).toBe(0);
    expect(internals.chainIndex.size).toBe(0);
  });

  it("role events bust exactly the entries referencing the role", async () => {
    const provider = fakeProvider({
      grants: [g("user:u1", { roleId: "editor" })],
      roles: [{ id: "editor", name: "Editor", patterns: ["docs.files.*"] }],
    });
    const client = createAlfizClient({ catalog, provider });
    expect(await client.can({ userId: "u1" }, "docs.files.read")).toBe(true);
    provider.emit({ type: "role", roleId: "unrelated" });
    await client.can({ userId: "u1" }, "docs.files.read");
    expect(provider.stats().fetches).toBe(1); // untouched by an unrelated role
    provider.emit({ type: "role", roleId: "editor" });
    await client.can({ userId: "u1" }, "docs.files.read");
    expect(provider.stats().fetches).toBe(2);
  });
});

describe("epoch revalidation", () => {
  /** fakeProvider plus a scriptable persisted-event log. */
  function epochProvider(state: Parameters<typeof fakeProvider>[0]) {
    const base = fakeProvider(state);
    const log: InvalidationEvent[] = [];
    let prunedThrough = 0;
    let headReads = 0;
    let failing = false;
    const provider = {
      ...base,
      epoch: {
        head: async () => {
          if (failing) throw new Error("epoch unreachable");
          headReads++;
          return log.length;
        },
        since: async (seq: number, limit = 500) => {
          if (failing) throw new Error("epoch unreachable");
          if (seq < prunedThrough) return { gap: true as const };
          const events = log.slice(seq, seq + limit);
          return { upTo: seq + events.length, events };
        },
      },
      append: (event: InvalidationEvent) => {
        // A write on ANOTHER process: reaches the log, not the live stream.
        log.push(event);
      },
      prune: () => {
        prunedThrough = log.length;
      },
      fail: (value: boolean) => {
        failing = value;
      },
      epochStats: () => ({ headReads }),
    };
    return provider;
  }

  const grants = () => [g("user:u1", { pattern: "docs.files.read" })];

  it("an unchanged head renews TTLs: zero refetches, ever, while writes are quiet", async () => {
    const provider = epochProvider({ grants: grants() });
    let now = 1_000;
    const client = createAlfizClient({
      catalog,
      provider,
      clock: () => now,
      subjectCacheTtlMs: 30_000,
      revalidateAfterMs: 5_000,
    });
    await client.can({ userId: "u1" }, "docs.files.read");
    expect(provider.stats().fetches).toBe(1);
    // Far past the subject TTL — the pre-epoch design would refetch here.
    for (let i = 0; i < 20; i++) {
      now += 31_000;
      expect(await client.can({ userId: "u1" }, "docs.files.read")).toBe(true);
    }
    expect(provider.stats().fetches).toBe(1);
  });

  it("within the window not even the head is read; past it, one read amortizes", async () => {
    const provider = epochProvider({ grants: grants() });
    let now = 1_000;
    const client = createAlfizClient({
      catalog,
      provider,
      clock: () => now,
      revalidateAfterMs: 5_000,
    });
    await client.can({ userId: "u1" }, "docs.files.read");
    const initial = provider.epochStats().headReads;
    await client.can({ userId: "u1" }, "docs.files.read");
    await client.can({ userId: "u1" }, "docs.files.read");
    expect(provider.epochStats().headReads).toBe(initial);
    now += 6_000;
    await client.can({ userId: "u1" }, "docs.files.read");
    await client.can({ userId: "u1" }, "docs.files.read");
    expect(provider.epochStats().headReads).toBe(initial + 1);
  });

  it("a head bump replays only the missed events: the affected principal refetches, others serve", async () => {
    const provider = epochProvider({
      grants: [
        g("user:u1", { pattern: "docs.files.read" }),
        g("user:u2", { pattern: "docs.files.read" }),
      ],
    });
    let now = 1_000;
    const client = createAlfizClient({
      catalog,
      provider,
      clock: () => now,
      revalidateAfterMs: 5_000,
    });
    await client.can({ userId: "u1" }, "docs.files.read");
    await client.can({ userId: "u2" }, "docs.files.read");
    expect(provider.stats().fetches).toBe(2);
    // Another process revokes u1's access: only the log knows.
    provider.append({ type: "user", userId: "u1" });
    now += 6_000;
    await client.can({ userId: "u2" }, "docs.files.read");
    expect(provider.stats().fetches).toBe(2); // u2 untouched by the event
    await client.can({ userId: "u1" }, "docs.files.read");
    expect(provider.stats().fetches).toBe(3); // u1 busted by replay
  });

  it("a gap busts everything and resumes from the current head", async () => {
    const provider = epochProvider({ grants: grants() });
    let now = 1_000;
    const client = createAlfizClient({
      catalog,
      provider,
      clock: () => now,
      revalidateAfterMs: 5_000,
    });
    await client.can({ userId: "u1" }, "docs.files.read");
    provider.append({ type: "role", roleId: "unrelated" });
    provider.prune(); // the cursor now predates retention
    now += 6_000;
    await client.can({ userId: "u1" }, "docs.files.read");
    expect(provider.stats().fetches).toBe(2);
    // After resuming from head, quiet revalidation renews again.
    now += 6_000;
    await client.can({ userId: "u1" }, "docs.files.read");
    expect(provider.stats().fetches).toBe(2);
  });

  it("fails closed: an unreachable epoch stops renewing, so the TTL bound takes over", async () => {
    const provider = epochProvider({ grants: grants() });
    let now = 1_000;
    const client = createAlfizClient({
      catalog,
      provider,
      clock: () => now,
      subjectCacheTtlMs: 30_000,
      revalidateAfterMs: 5_000,
    });
    await client.can({ userId: "u1" }, "docs.files.read");
    provider.fail(true);
    // Within the TTL a cached entry still serves (today's contract)…
    now += 6_000;
    await client.can({ userId: "u1" }, "docs.files.read");
    expect(provider.stats().fetches).toBe(1);
    // …but past it nothing was renewed: the check refetches from the DB.
    now += 31_000;
    await client.can({ userId: "u1" }, "docs.files.read");
    expect(provider.stats().fetches).toBe(2);
  });

  it("concurrent checks past the window share one head read", async () => {
    const provider = epochProvider({
      grants: [
        g("user:u1", { pattern: "docs.files.read" }),
        g("user:u2", { pattern: "docs.files.read" }),
        g("user:u3", { pattern: "docs.files.read" }),
      ],
    });
    let now = 1_000;
    const client = createAlfizClient({
      catalog,
      provider,
      clock: () => now,
      revalidateAfterMs: 5_000,
    });
    await client.can({ userId: "u1" }, "docs.files.read");
    const before = provider.epochStats().headReads;
    now += 6_000;
    await Promise.all([
      client.can({ userId: "u1" }, "docs.files.read"),
      client.can({ userId: "u2" }, "docs.files.read"),
      client.can({ userId: "u3" }, "docs.files.read"),
    ]);
    expect(provider.epochStats().headReads).toBe(before + 1);
  });

  it("a fetch that overlapped a replay is never renewed (generation guard)", async () => {
    let release: (() => void) | undefined;
    let blockNext = false;
    const base = epochProvider({ grants: grants() });
    const provider = {
      ...base,
      getSubjectAccess: async (p: Parameters<typeof base.getSubjectAccess>[0]) => {
        if (blockNext) {
          blockNext = false;
          await new Promise<void>((r) => {
            release = r;
          });
        }
        return base.getSubjectAccess(p);
      },
    };
    let now = 1_000;
    const client = createAlfizClient({
      catalog,
      provider,
      clock: () => now,
      subjectCacheTtlMs: 30_000,
      revalidateAfterMs: 5_000,
    });
    // First contact pins the epoch cursor.
    await client.can({ userId: "u2" }, "docs.files.read");
    // u1's fetch starts… and stalls.
    blockNext = true;
    const stalled = client.can({ userId: "u1" }, "docs.files.read");
    await new Promise((r) => setTimeout(r, 0));
    // While it is in flight, a replay lands (event for an uncached subject —
    // nothing to bust, but the generation advances).
    base.append({ type: "subject", subject: "group:elsewhere" });
    now += 6_000;
    await client.can({ userId: "u2" }, "docs.files.read"); // triggers the replay
    release!();
    await stalled; // u1 stored under the OLD generation
    // u2 refetches once past its TTL, picking up the current generation…
    now += 26_000;
    await client.can({ userId: "u2" }, "docs.files.read");
    const afterU2 = base.stats().fetches;
    // …after which quiet revalidations renew u2's entry but never u1's:
    // the overlapped fetch stays bounded by its original TTL.
    now += 31_000;
    await client.can({ userId: "u2" }, "docs.files.read");
    expect(base.stats().fetches).toBe(afterU2); // renewed, no refetch
    await client.can({ userId: "u1" }, "docs.files.read");
    expect(base.stats().fetches).toBe(afterU2 + 1); // stale generation: refetch
  });
});

describe("ancestor visibility (impliedOnAncestors)", () => {
  it("a granted scope implies the marked leaf on its ancestors only", async () => {
    const provider = fakeProvider({
      grants: [g("user:u1", { pattern: "docs.files.read_listing" }, "docs.folder:9")],
      parents: { "docs.folder:9": "docs.folder:2", "docs.doc:1": "docs.folder:9" },
    });
    const client = createAlfizClient({ catalog, provider });
    // Direct + descendants: normal semantics.
    expect(await client.can({ userId: "u1" }, "docs.files.read_listing", "docs.folder:9")).toBe(true);
    // Ancestor of the granted scope: implied.
    expect(await client.can({ userId: "u1" }, "docs.files.read_listing", "docs.folder:2")).toBe(true);
    // Unrelated scope: not implied.
    expect(await client.can({ userId: "u1" }, "docs.files.read_listing", "docs.folder:77")).toBe(false);
    // Unmarked leaves never imply upward.
    expect(await client.can({ userId: "u1" }, "docs.files.read", "docs.folder:2")).toBe(false);
  });
});

describe("AlfizClient.canAny and require*", () => {
  it("canAny is a visibility affordance over the catalog", async () => {
    const provider = fakeProvider({
      grants: [g("user:u1", { pattern: "docs.files.update_file" }, "docs.folder:9")],
    });
    const client = createAlfizClient({ catalog, provider });
    expect(await client.canAny({ userId: "u1" }, "docs.*")).toBe(true);
    expect(await client.canAny({ userId: "u1" }, "docs.files.*")).toBe(true);
  });

  it("requirePermission throws typed denials", async () => {
    const provider = fakeProvider({ grants: [] });
    const client = createAlfizClient({ catalog, provider });
    await expect(
      client.requirePermission({ userId: "u1" }, "docs.files.read"),
    ).rejects.toThrow(AccessDeniedError);
    await expect(
      client.requirePermission({ userId: "u1" }, "docs.files.read"),
    ).rejects.toMatchObject({ reason: "forbidden" });
  });

  it("requirePermission distinguishes inactive principals", async () => {
    const provider = fakeProvider({ grants: [g("user:u1", { pattern: "*" })], active: false });
    const client = createAlfizClient({ catalog, provider });
    await expect(
      client.requirePermission({ userId: "u1" }, "docs.files.read"),
    ).rejects.toMatchObject({ reason: "inactive" });
  });
});

describe("explain / effectiveKeys / grantedScopes", () => {
  it("explain shows the winning rows", async () => {
    const grant = g("user:u1", { pattern: "docs.*" });
    const revoke: RevokeRow = {
      id: "r1",
      userId: "u1",
      pattern: "docs.files.delete",
      scope: "*",
      provenance: { kind: "admin", actorUserId: "root" },
      createdAt: 0,
    };
    const provider = fakeProvider({ grants: [grant], revokes: [revoke] });
    const client = createAlfizClient({ catalog, provider });
    const explained = await client.explain({ userId: "u1" }, "docs.files.delete");
    expect(explained.allowed).toBe(false);
    expect(explained.matchedGrants.map((m) => m.id)).toEqual([grant.id]);
    expect(explained.matchedRevokes.map((m) => m.id)).toEqual(["r1"]);
  });

  it("effectiveKeys lists held catalog keys minus revokes", async () => {
    const provider = fakeProvider({
      grants: [g("user:u1", { pattern: "docs.files.*" })],
      revokes: [
        {
          id: "r1",
          userId: "u1",
          pattern: "docs.files.delete",
          scope: "*",
          provenance: { kind: "admin", actorUserId: "root" },
          createdAt: 0,
        },
      ],
    });
    const client = createAlfizClient({ catalog, provider });
    expect(await client.effectiveKeys({ userId: "u1" })).toEqual([
      "docs.files.read",
      "docs.files.read_listing",
      "docs.files.update_file",
    ]);
  });

  it("grantedScopes feeds the listing plan", async () => {
    const provider = fakeProvider({
      grants: [
        g("user:u1", { pattern: "docs.files.read" }, "docs.folder:9"),
        g("everyone", { pattern: "docs.files.read" }, "docs.folder:2"),
      ],
    });
    const client = createAlfizClient({ catalog, provider });
    const { granted } = await client.grantedScopes({ userId: "u1" }, "docs.files.read");
    expect(granted).toEqual(new Set(["docs.folder:9", "docs.folder:2"]));
  });
});
