/**
 * Adversarial review of the stale-authority surface: cache keys, the shared
 * L2 tier, snapshots, epoch replay, expiry, clock handling, and invalidation
 * completeness (including transitively affected principals).
 *
 * Every assertion here states the SECURE behavior. A failing test is a
 * decision served past a bound the README's "Staleness, honestly" section
 * states, or a cache answering with authority that is not the principal's.
 */
/**
 * KNOWN-OPEN MARKER — `it.fails(...)` in this file.
 *
 * A test written as `it.fails` asserts the SECURE behavior and records that
 * Alfiz does not have it yet: it passes while the finding is open, and turns
 * RED the moment someone fixes the underlying issue. That is the point — the
 * failure is the signal to delete the `.fails` and promote the test, so a
 * fix can never land silently and a finding can never quietly rot.
 *
 * Every one of them is listed in the 0.7.1 changelog entry with its
 * severity. They are open findings, not accepted behavior.
 */
import { describe, expect, it } from "vitest";
import type { GrantRow, RevokeRow, RoleDef } from "../src/access.js";
import type { CacheStore } from "../src/cache.js";
import { defineCatalog } from "../src/catalog.js";
import { createAlfizClient } from "../src/client.js";
import type {
  AlfizProvider,
  InvalidationEvent,
  InvalidationListener,
  PrincipalRef,
  SubjectAccessData,
} from "../src/provider.js";
import { createApplication, memoryDriver } from "@alfiz/application";

const catalog = defineCatalog({
  namespaces: ["docs"],
  includeAlfizInternal: false,
  permissions: {
    "docs.files.read": { scopes: ["docs.folder", "docs.doc"] },
    "docs.files.delete": { scopes: ["docs.folder"] },
  },
  scopeTypes: {
    "docs.folder": { parent: "docs.folder" },
    "docs.doc": { parent: "docs.folder" },
  },
});

/** A second, unrelated application's catalog — a different Alfiz deployment. */
const otherCatalog = defineCatalog({
  namespaces: ["hr"],
  includeAlfizInternal: false,
  permissions: {
    "hr.people.read": true,
    "hr.people.terminate": true,
  },
  scopeTypes: {},
});

const admin = { kind: "admin", actorUserId: "root" } as const;

const g = (
  subject: string,
  pattern: string,
  scope = "*",
  expiresAt?: number,
): GrantRow => ({
  id: `${subject}|${pattern}|${scope}`,
  subject,
  pattern,
  scope,
  expiresAt,
  provenance: admin,
  createdAt: 0,
});

const data = (over: Partial<SubjectAccessData> = {}): SubjectAccessData => ({
  userId: "u1",
  closure: ["user:u1", "everyone"],
  grants: [],
  revokes: [],
  roles: [],
  managerChain: [],
  unresolvedRoleIds: [],
  active: true,
  ...over,
});

/** A scriptable provider with mutable state, a persisted log, and counters. */
function fakeProvider(state: {
  grants: GrantRow[];
  revokes?: RevokeRow[];
  roles?: RoleDef[];
  closure?: string[];
  active?: boolean;
  userId?: string;
  parents?: Record<string, string>;
  /** Provider page size for `epoch.since`. */
  pageSize?: number;
}) {
  const listeners = new Set<InvalidationListener>();
  const log: InvalidationEvent[] = [];
  let prunedThrough = 0;
  let fetches = 0;
  let resolves = 0;
  let failing = false;
  const provider = {
    getSubjectAccess: async (): Promise<SubjectAccessData> => {
      fetches++;
      return data({
        userId: state.userId ?? "u1",
        closure: state.closure ?? ["user:u1", "everyone"],
        grants: [...state.grants],
        revokes: state.revokes ?? [],
        roles: state.roles ?? [],
        active: state.active ?? true,
      });
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
    epoch: {
      head: async () => {
        if (failing) throw new Error("epoch unreachable");
        return log.length;
      },
      since: async (seq: number, limit = state.pageSize ?? 500) => {
        if (failing) throw new Error("epoch unreachable");
        if (seq < prunedThrough) return { gap: true as const };
        const events = log.slice(seq, seq + limit);
        return { upTo: seq + events.length, events };
      },
    },
    /** A write on ANOTHER process: reaches the log, not the live stream. */
    append: (event: InvalidationEvent) => log.push(event),
    prune: () => {
      prunedThrough = log.length;
    },
    /** Simulate a truncated / restored event table: the head goes backwards. */
    truncate: () => {
      log.length = 0;
      prunedThrough = 0;
    },
    fail: (value: boolean) => {
      failing = value;
    },
    emit: (event: InvalidationEvent) => {
      for (const listener of listeners) listener(event);
    },
    stats: () => ({ fetches, resolves }),
  };
  return provider as typeof provider & AlfizProvider;
}

/** An in-memory CacheStore that also lets a test plant raw entries. */
function makeStore() {
  const backing = new Map<string, string>();
  const store: CacheStore = {
    async get(key) {
      return backing.get(key) ?? null;
    },
    async set(key, value) {
      backing.set(key, value);
    },
    async delete(key) {
      backing.delete(key);
    },
  };
  return { store, backing };
}

/** L2 writes are fire-and-forget; let the microtask queue drain. */
const flushWrites = () => new Promise((resolve) => setImmediate(resolve));

// ---------------------------------------------------------------------------

describe("cache keys: one principal, one entry", () => {
  it("a principal naming both a user and a service never answers with the service's authority", async () => {
    // The client keys on `userId` first (`"userId" in p`); the Application
    // resolves `serviceId` first. A principal object carrying both — a
    // session/claims object widened through a cast, the common shape — is
    // therefore CACHED under the user's key but FILLED with the service's
    // closure.
    let now = 1_000_000;
    const app = createApplication({
      catalog,
      storage: memoryDriver(),
      clock: () => now,
    });
    await app.createGrant({
      subject: "service:importer",
      pattern: "docs.files.read",
      provenance: admin,
    });
    const client = createAlfizClient({
      catalog,
      provider: app,
      clock: () => now,
      revalidateAfterMs: false,
    });

    const ambiguous = { userId: "alice", serviceId: "importer" } as PrincipalRef;
    // A principal naming two principals has no correct interpretation, so
    // the call is refused outright rather than resolved in favour of
    // whichever half the reader happens to test first — which is how the
    // Client and the provider came to disagree, and how a service closure
    // ended up cached under a user key.
    await expect(client.can(ambiguous, "docs.files.read")).rejects.toThrow(
      /names both a userId and a serviceId/,
    );

    // alice holds nothing. Whatever the ambiguous call did, it must not be
    // able to answer for the plain user principal.
    expect(await client.can({ userId: "alice" }, "docs.files.read")).toBe(false);
    client.close();
  });

  it("a user and a service sharing an id never share a cache entry", async () => {
    let fetches = 0;
    const provider = {
      getSubjectAccess: async (p: PrincipalRef): Promise<SubjectAccessData> => {
        fetches++;
        return "serviceId" in p
          ? data({
              userId: null,
              closure: ["service:x", "everyone"],
              grants: [g("service:x", "docs.files.read")],
            })
          : data({ userId: "x", closure: ["user:x"], grants: [] });
      },
      resolveAncestors: () => ["*"],
      onInvalidate: () => () => undefined,
    } as unknown as AlfizProvider;
    const client = createAlfizClient({ catalog, provider });

    expect(await client.can({ serviceId: "x" }, "docs.files.read")).toBe(true);
    expect(await client.can({ userId: "x" }, "docs.files.read")).toBe(false);
    expect(fetches).toBe(2);
    client.close();
  });
});

describe("the shared L2 tier", () => {
  it("two deployments sharing one cache store never read each other's closures", async () => {
    // One RESP service, two Alfiz deployments, stock configuration. Alice is
    // a global admin in the `docs` application and a nobody in `hr`.
    const { store } = makeStore();
    let now = 1_000_000;
    const docsProvider = fakeProvider({
      grants: [g("user:alice", "*")],
      userId: "alice",
      closure: ["user:alice", "everyone"],
    });
    const hrProvider = fakeProvider({
      grants: [],
      userId: "alice",
      closure: ["user:alice", "everyone"],
    });
    const docsClient = createAlfizClient({
      catalog,
      provider: docsProvider,
      cacheStore: store,
      clock: () => now,
      revalidateAfterMs: false,
    });
    const hrClient = createAlfizClient({
      catalog: otherCatalog,
      provider: hrProvider,
      cacheStore: store,
      clock: () => now,
      revalidateAfterMs: false,
    });

    expect(await docsClient.can({ userId: "alice" }, "docs.files.delete")).toBe(
      true,
    );
    await flushWrites();

    // The `hr` deployment has never granted alice anything.
    expect(await hrClient.can({ userId: "alice" }, "hr.people.terminate")).toBe(
      false,
    );
    expect(hrProvider.stats().fetches).toBe(1);
    docsClient.close();
    hrClient.close();
  });

  it("an L2 envelope whose payload names a different principal is a miss, never an answer", async () => {
    const { store, backing } = makeStore();
    let now = 1_000_000;
    const provider = fakeProvider({
      grants: [],
      userId: "victim",
      closure: ["user:victim", "everyone"],
    });
    const client = createAlfizClient({
      catalog,
      provider,
      cacheStore: store,
      clock: () => now,
      revalidateAfterMs: false,
      subjectCacheTtlMs: 30_000,
    });
    // A stale/foreign entry sitting at the victim's key with somebody else's
    // closure inside it. The envelope is well-formed and in-window; only its
    // PAYLOAD disagrees with the key.
    backing.set(
      "alfiz:v1:sub:u:victim",
      JSON.stringify({
        v: 1,
        freshUntil: now + 30_000,
        data: data({
          userId: "attacker",
          closure: ["user:attacker"],
          grants: [g("user:attacker", "*")],
        }),
      }),
    );

    expect(await client.can({ userId: "victim" }, "docs.files.delete")).toBe(
      false,
    );
    client.close();
  });

  it("an unreachable epoch does not turn a warm L2 entry into unbounded stale authority", async () => {
    // README: "epoch unreachable (failure) | falls back to the TTL bounds |
    // fail-closed to the database — stale data is never served past its
    // window." That must hold with an L2 configured, not only without one.
    const { store } = makeStore();
    let now = 1_000_000;
    const state = { grants: [g("user:u1", "docs.files.read")] };
    const provider = fakeProvider(state);
    const client = createAlfizClient({
      catalog,
      provider,
      cacheStore: store,
      clock: () => now,
      subjectCacheTtlMs: 30_000,
      revalidateAfterMs: 5_000,
    });
    expect(await client.can({ userId: "u1" }, "docs.files.read")).toBe(true);
    await flushWrites();

    // The grant is deleted on another process (the event reaches the log) and
    // the epoch becomes unreadable before this process can replay it.
    state.grants.length = 0;
    provider.append({ type: "user", userId: "u1" });
    provider.fail(true);

    // Past the subject TTL the entry has lapsed: the check must go to the
    // database, exactly as it does without an L2.
    now += 31_000;
    expect(await client.can({ userId: "u1" }, "docs.files.read")).toBe(false);
    // …and it must stay denied however long the epoch stays down.
    now += 600_000;
    expect(await client.can({ userId: "u1" }, "docs.files.read")).toBe(false);
    client.close();
  });

  it("can.fresh bypasses L1, the L2, and the in-flight dedupe", async () => {
    const { store } = makeStore();
    let now = 1_000_000;
    const state = {
      grants: [g("user:u1", "docs.files.read", "docs.folder:9")],
      parents: { "docs.doc:1": "docs.folder:9" } as Record<string, string>,
    };
    const provider = fakeProvider(state);
    const client = createAlfizClient({
      catalog,
      provider,
      cacheStore: store,
      clock: () => now,
      subjectCacheTtlMs: 3_600_000,
      objectCacheTtlMs: 3_600_000,
      revalidateAfterMs: false,
    });
    expect(
      await client.can({ userId: "u1" }, "docs.files.read", "docs.doc:1"),
    ).toBe(true);
    await flushWrites();
    const warm = provider.stats();

    // The database changes with no event at all: the cached answer is allowed
    // to be stale, `can.fresh` is not.
    state.grants.length = 0;
    state.parents["docs.doc:1"] = "docs.folder:77";
    expect(
      await client.can({ userId: "u1" }, "docs.files.read", "docs.doc:1"),
    ).toBe(true);
    expect(provider.stats().fetches).toBe(warm.fetches);

    expect(
      await client.can.fresh({ userId: "u1" }, "docs.files.read", "docs.doc:1"),
    ).toBe(false);
    // Both tiers were re-supplied, not just the subject side.
    expect(provider.stats().fetches).toBe(warm.fetches + 1);
    expect(provider.stats().resolves).toBeGreaterThan(warm.resolves);
    client.close();
  });

  it("strict: true bypasses the L2 on every check", async () => {
    const { store, backing } = makeStore();
    let now = 1_000_000;
    const state = { grants: [g("user:u1", "docs.files.read")] };
    const provider = fakeProvider(state);
    const warmer = createAlfizClient({
      catalog,
      provider,
      cacheStore: store,
      clock: () => now,
      revalidateAfterMs: false,
    });
    await warmer.can({ userId: "u1" }, "docs.files.read");
    await flushWrites();
    warmer.close();
    expect(backing.size).toBeGreaterThan(0);

    state.grants.length = 0;
    const strict = createAlfizClient({
      catalog,
      provider,
      cacheStore: store,
      clock: () => now,
      strict: true,
      revalidateAfterMs: false,
    });
    expect(await strict.can({ userId: "u1" }, "docs.files.read")).toBe(false);
    strict.close();
  });
});

describe("epoch replay", () => {
  it("a burst larger than the provider's page size is replayed to the tail", async () => {
    // The invalidation that matters is LAST in the burst: a client that reads
    // one page and stops would miss it permanently.
    const state = {
      grants: [g("user:u1", "docs.files.read")],
      pageSize: 1,
    };
    const provider = fakeProvider(state);
    let now = 1_000_000;
    const client = createAlfizClient({
      catalog,
      provider,
      clock: () => now,
      subjectCacheTtlMs: 3_600_000,
      revalidateAfterMs: 5_000,
    });
    expect(await client.can({ userId: "u1" }, "docs.files.read")).toBe(true);

    for (let i = 0; i < 8; i++) {
      provider.append({ type: "user", userId: `noise-${i}` });
    }
    state.grants.length = 0;
    provider.append({ type: "user", userId: "u1" }); // the tail event

    now += 6_000;
    expect(await client.can({ userId: "u1" }, "docs.files.read")).toBe(false);
    client.close();
  });

  it("a head behind the cursor (a restored or truncated log) busts everything", async () => {
    const state = { grants: [g("user:u1", "docs.files.read")] };
    const provider = fakeProvider(state);
    let now = 1_000_000;
    const client = createAlfizClient({
      catalog,
      provider,
      clock: () => now,
      subjectCacheTtlMs: 3_600_000,
      revalidateAfterMs: 5_000,
    });
    provider.append({ type: "user", userId: "someone" });
    provider.append({ type: "user", userId: "someone-else" });
    expect(await client.can({ userId: "u1" }, "docs.files.read")).toBe(true);

    // The events table is restored from an older backup: the head rewinds and
    // this client's cursor is now from the future.
    provider.truncate();
    state.grants.length = 0;
    now += 6_000;
    expect(await client.can({ userId: "u1" }, "docs.files.read")).toBe(false);
    client.close();
  });
});

describe("expiry versus the cache", () => {
  it("a grant that expires inside the cache TTL denies at the next check", async () => {
    let now = 1_000_000;
    const provider = fakeProvider({
      grants: [g("user:u1", "docs.files.read", "*", now + 10_000)],
    });
    const client = createAlfizClient({
      catalog,
      provider,
      clock: () => now,
      subjectCacheTtlMs: 3_600_000,
      revalidateAfterMs: false,
    });
    expect(await client.can({ userId: "u1" }, "docs.files.read")).toBe(true);
    now += 11_000; // expired, but deep inside the cached closure's TTL
    expect(await client.can({ userId: "u1" }, "docs.files.read")).toBe(false);
    expect(provider.stats().fetches).toBe(1); // no refetch needed to be right
    client.close();
  });

  it("an expired grant inside a warm L2 entry is still expired", async () => {
    const { store, backing } = makeStore();
    let now = 1_000_000;
    const provider = fakeProvider({ grants: [] });
    const client = createAlfizClient({
      catalog,
      provider,
      cacheStore: store,
      clock: () => now,
      subjectCacheTtlMs: 30_000,
      revalidateAfterMs: false,
    });
    backing.set(
      "alfiz:v1:sub:u:u1",
      JSON.stringify({
        v: 1,
        freshUntil: now + 30_000,
        data: data({ grants: [g("user:u1", "docs.files.read", "*", now - 1)] }),
      }),
    );
    expect(await client.can({ userId: "u1" }, "docs.files.read")).toBe(false);
    client.close();
  });
});

describe("clock handling", () => {
  it.fails("a backwards clock step does not extend the subject cache TTL", async () => {
    // NTP steps the wall clock back (or a container resumes). The 30s bound
    // is a bound on elapsed time, not on a monotonically increasing clock
    // Alfiz merely hopes for.
    let now = 1_000_000;
    const state = { grants: [g("user:u1", "docs.files.read")] };
    const provider = fakeProvider(state);
    const client = createAlfizClient({
      catalog,
      provider,
      clock: () => now,
      subjectCacheTtlMs: 30_000,
      revalidateAfterMs: false,
    });
    expect(await client.can({ userId: "u1" }, "docs.files.read")).toBe(true);

    now -= 3_600_000; // the step back
    state.grants.length = 0;
    now += 60_000; // …and a full minute of real time passes

    expect(await client.can({ userId: "u1" }, "docs.files.read")).toBe(false);
    client.close();
  });

  it.fails("a backwards clock step does not suspend epoch revalidation", async () => {
    let now = 1_000_000;
    const state = { grants: [g("user:u1", "docs.files.read")] };
    const provider = fakeProvider(state);
    const client = createAlfizClient({
      catalog,
      provider,
      clock: () => now,
      subjectCacheTtlMs: 3_600_000,
      revalidateAfterMs: 5_000,
    });
    expect(await client.can({ userId: "u1" }, "docs.files.read")).toBe(true);

    state.grants.length = 0;
    provider.append({ type: "user", userId: "u1" });
    now -= 3_600_000;
    now += 60_000; // twelve revalidation windows of real time

    expect(await client.can({ userId: "u1" }, "docs.files.read")).toBe(false);
    client.close();
  });
});

describe("snapshots", () => {
  it("a snapshot answers only for the principal it captured", async () => {
    const provider = {
      getSubjectAccess: async (p: PrincipalRef): Promise<SubjectAccessData> =>
        "userId" in p && p.userId === "admin"
          ? data({
              userId: "admin",
              closure: ["user:admin"],
              grants: [g("user:admin", "*")],
            })
          : data({ userId: "nobody", closure: ["user:nobody"], grants: [] }),
      resolveAncestors: () => ["*"],
      onInvalidate: () => () => undefined,
    } as unknown as AlfizProvider;
    const client = createAlfizClient({ catalog, provider });

    const adminSnap = await client.snapshot({ userId: "admin" });
    const nobodySnap = await client.snapshot({ userId: "nobody" });
    expect(adminSnap.principal).toEqual({ userId: "admin" });
    expect(nobodySnap.principal).toEqual({ userId: "nobody" });
    expect(adminSnap.can("docs.files.delete")).toBe(true);
    expect(nobodySnap.can("docs.files.delete")).toBe(false);
    expect(nobodySnap.holds("docs.files.delete")).toBe(false);
    expect([...nobodySnap.heldKeys]).toEqual([]);
    client.close();
  });

  it("resolve() with caller-supplied scope ids never widens a snapshot past client.can", async () => {
    const provider = fakeProvider({
      grants: [
        g("user:u1", "docs.files.read", "docs.folder:9"),
        g("user:u1", "docs.files.delete", "docs.folder:9"),
      ],
      revokes: [
        {
          id: "r1",
          userId: "u1",
          pattern: "docs.files.delete",
          scope: "docs.folder:9",
          provenance: admin,
          createdAt: 0,
        },
      ],
      parents: {
        "docs.doc:1": "docs.folder:9",
        "docs.doc:evil": "docs.folder:9",
        "docs.folder:9": "docs.folder:2",
      },
    });
    const client = createAlfizClient({ catalog, provider });
    const snap = await client.snapshot({ userId: "u1" });

    // Row ids the request handler learned only after querying — including one
    // an attacker chose.
    await snap.resolve(["docs.doc:1", "docs.doc:evil"]);
    for (const scope of ["docs.doc:1", "docs.doc:evil"] as const) {
      expect(snap.can("docs.files.read", scope)).toBe(
        await client.can({ userId: "u1" }, "docs.files.read", scope),
      );
      // The ancestor revoke still wins at every resolved descendant.
      expect(snap.can("docs.files.delete", scope)).toBe(false);
    }
    // And a hierarchical scope nobody resolved still fails closed rather than
    // evaluating a truncated chain that would miss ancestor revokes.
    expect(() => snap.can("docs.files.read", "docs.folder:2")).toThrow(
      /resolve/i,
    );
    client.close();
  });
});

describe("invalidation completeness", () => {
  /** One Application, one client, TTLs long enough that only events can save us. */
  function local(overrides: Record<string, unknown> = {}) {
    let now = 1_000_000;
    const storage = memoryDriver();
    const app = createApplication({
      catalog,
      storage,
      clock: () => now,
      ...overrides,
    });
    const client = createAlfizClient({
      catalog,
      provider: app,
      clock: () => now,
      subjectCacheTtlMs: 3_600_000,
      objectCacheTtlMs: 3_600_000,
      revalidateAfterMs: false,
    });
    return {
      app,
      client,
      advance: (ms: number) => {
        now += ms;
      },
    };
  }

  it("a role edit busts users who hold the role only through a group", async () => {
    const { app, client } = local();
    const role = await app.createRole(
      { name: "Editor", patterns: ["docs.files.delete"] },
      admin,
    );
    await app.createGroup({ id: "team", name: "Team" }, admin);
    await app.setGroupMembership("u1", ["team"], admin);
    await app.createGrant({
      subject: "group:team",
      roleId: role.id,
      provenance: admin,
    });
    expect(await client.can({ userId: "u1" }, "docs.files.delete")).toBe(true);

    await app.updateRole(role.id, { patterns: ["docs.files.read"] }, admin);
    expect(await client.can({ userId: "u1" }, "docs.files.delete")).toBe(false);
    client.close();
  });

  it("removing a group's parent busts the transitively affected member", async () => {
    const { app, client } = local();
    await app.createGroup({ id: "admins", name: "Admins" }, admin);
    await app.createGroup(
      { id: "team", name: "Team", parents: ["admins"] },
      admin,
    );
    await app.setGroupMembership("u1", ["team"], admin);
    await app.createGrant({
      subject: "group:admins",
      pattern: "docs.files.delete",
      provenance: admin,
    });
    expect(await client.can({ userId: "u1" }, "docs.files.delete")).toBe(true);

    await app.setGroupParents("team", [], admin);
    expect(await client.can({ userId: "u1" }, "docs.files.delete")).toBe(false);
    client.close();
  });

  it("deleting the group that held the grant busts its members", async () => {
    const { app, client } = local();
    await app.createGroup({ id: "admins", name: "Admins" }, admin);
    await app.setGroupMembership("u1", ["admins"], admin);
    await app.createGrant({
      subject: "group:admins",
      pattern: "docs.files.delete",
      provenance: admin,
    });
    expect(await client.can({ userId: "u1" }, "docs.files.delete")).toBe(true);

    await app.deleteSubject("group:admins", admin);
    expect(await client.can({ userId: "u1" }, "docs.files.delete")).toBe(false);
    client.close();
  });

  it("setUserActive(false) denies on the very next check", async () => {
    const { app, client } = local();
    await app.createGrant({
      subject: "everyone",
      pattern: "docs.files.read",
      provenance: admin,
    });
    expect(await client.can({ userId: "u1" }, "docs.files.read")).toBe(true);
    await app.setUserActive("u1", false, admin);
    expect(await client.can({ userId: "u1" }, "docs.files.read")).toBe(false);
    client.close();
  });

  it("a group-parentage change on another process lands within the revalidation window", async () => {
    // README: with the event log on, the cross-process staleness bound is the
    // revalidation window — for every write that changes authority, not only
    // for grant rows. Stock configuration on both sides.
    let now = 1_000_000;
    const storage = memoryDriver();
    const appA = createApplication({ catalog, storage, clock: () => now });
    const appB = createApplication({ catalog, storage, clock: () => now });
    await appA.createGroup({ id: "admins", name: "Admins" }, admin);
    await appA.createGroup(
      { id: "team", name: "Team", parents: ["admins"] },
      admin,
    );
    await appA.setGroupMembership("u1", ["team"], admin);
    await appA.createGrant({
      subject: "group:admins",
      pattern: "docs.files.delete",
      provenance: admin,
    });
    const clientB = createAlfizClient({
      catalog,
      provider: appB,
      clock: () => now,
      subjectCacheTtlMs: 3_600_000,
      revalidateAfterMs: 5_000,
    });
    expect(await clientB.can({ userId: "u1" }, "docs.files.delete")).toBe(true);

    await appA.setGroupParents("team", [], admin);
    now += 6_000; // one revalidation window
    expect(await clientB.can({ userId: "u1" }, "docs.files.delete")).toBe(false);
    // …and it must not simply be slow: no TTL anywhere may leave it allowed.
    now += 86_400_000;
    expect(await clientB.can({ userId: "u1" }, "docs.files.delete")).toBe(false);
    clientB.close();
  });
});
