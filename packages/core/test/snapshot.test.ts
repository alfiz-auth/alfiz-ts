import { describe, expect, it } from "vitest";
import type { GrantRow, RevokeRow, RoleDef } from "../src/access.js";
import { defineCatalog } from "../src/catalog.js";
import { createAlfizClient } from "../src/client.js";
import { AccessDeniedError } from "../src/errors.js";
import type {
  AlfizProvider,
  InvalidationListener,
  SubjectAccessData,
} from "../src/provider.js";

const catalog = defineCatalog({
  namespace: "docs",
  additionalNamespaces: ["lms"],
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
    lms: {
      groups: {
        courses: {
          permissions: {
            read: { scopes: ["lms.course"] },
            publish_course: { scopes: ["lms.course"] },
          },
        },
      },
    },
  },
  scopeTypes: {
    "docs.folder": { parent: "docs.folder" }, // hierarchical: folders nest
    "docs.doc": { parent: "docs.folder" },
    "lms.course": { parent: null }, // flat: chains are [scope, *] by declaration
  },
});

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

const revoke = (pattern: string, scope = "*"): RevokeRow => ({
  id: Math.random().toString(36).slice(2),
  userId: "u1",
  pattern,
  scope,
  provenance: { kind: "admin", actorUserId: "root" },
  createdAt: 0,
});

describe("snapshot: one round-trip, synchronous checks", () => {
  it("global, flat-scoped, and any-of checks are sync and agree with client.can", async () => {
    const provider = fakeProvider({
      grants: [
        g("user:u1", { pattern: "lms.courses.publish_course" }, "lms.course:9"),
        g("everyone", { pattern: "docs.files.read" }),
      ],
    });
    const client = createAlfizClient({ catalog, provider });
    const snap = await client.snapshot({ userId: "u1" });

    // Flat scope type: no pre-resolution, no resolver I/O for the target.
    expect(snap.can("lms.courses.publish_course", "lms.course:9")).toBe(true);
    expect(snap.can("lms.courses.publish_course", "lms.course:10")).toBe(false);
    expect(snap.can("lms.courses.publish_course")).toBe(false);
    expect(snap.can("docs.files.read")).toBe(true);
    expect(snap.can(["docs.files.delete", "docs.files.read"])).toBe(true);
    expect(snap.can(["docs.files.delete", "docs.files.update_file"])).toBe(false);

    expect(await client.can({ userId: "u1" }, "lms.courses.publish_course", "lms.course:9")).toBe(true);
    expect(await client.can({ userId: "u1" }, "lms.courses.publish_course", "lms.course:10")).toBe(false);
  });

  it("a global grant satisfies every scoped check — the migration crux, sync too", async () => {
    const provider = fakeProvider({
      grants: [g("user:u1", { pattern: "lms.courses.publish_course" })],
    });
    const client = createAlfizClient({ catalog, provider });
    const snap = await client.snapshot({ userId: "u1" });
    expect(snap.can("lms.courses.publish_course", "lms.course:9")).toBe(true);
  });

  it("one provider fetch serves every check in the request", async () => {
    const provider = fakeProvider({
      grants: [g("user:u1", { pattern: "docs.*" })],
    });
    const client = createAlfizClient({ catalog, provider, subjectCacheTtlMs: 0 });
    const snap = await client.snapshot({ userId: "u1" });
    for (let i = 0; i < 50; i++) {
      snap.can("docs.files.read");
      snap.canAny("docs.*");
      snap.holds("docs.files.update_file");
    }
    expect(provider.stats().fetches).toBe(1);
  });

  it("hierarchical scopes: granted scopes are pre-resolved, targets need opting in", async () => {
    const provider = fakeProvider({
      grants: [g("user:u1", { pattern: "docs.files.read" }, "docs.folder:9")],
      parents: { "docs.folder:9": "docs.folder:2", "docs.doc:1": "docs.folder:9" },
    });
    const client = createAlfizClient({ catalog, provider });

    // Target pre-resolved: exact ancestor-chain semantics.
    const snap = await client.snapshot({ userId: "u1" }, { scopes: ["docs.doc:1", "docs.doc:77"] });
    expect(snap.can("docs.files.read", "docs.doc:1")).toBe(true); // via folder:9
    expect(snap.can("docs.files.read", "docs.doc:77")).toBe(false);
    expect(snap.can("docs.files.read", "docs.folder:9")).toBe(true); // granted scope: auto-resolved

    // Unresolved hierarchical target: throws rather than guessing a chain.
    expect(() => snap.can("docs.files.read", "docs.doc:2")).toThrow(/pre-resolve/i);
    expect(() => snap.can("docs.files.read", "docs.doc:2")).toThrow(/docs\.doc:2/);
  });

  it("an undeclared scope type names itself in the error", async () => {
    const provider = fakeProvider({ grants: [] });
    const client = createAlfizClient({ catalog, provider });
    const snap = await client.snapshot({ userId: "u1" });
    expect(() => snap.can("docs.files.read", "ghost.type:1")).toThrow(/not declared/);
  });

  it("revokes at ancestors suppress, exactly as client.can", async () => {
    const provider = fakeProvider({
      grants: [g("user:u1", { pattern: "docs.files.read" }, "docs.folder:2")],
      revokes: [revoke("docs.files.read", "docs.folder:9")],
      parents: { "docs.doc:1": "docs.folder:9", "docs.folder:9": "docs.folder:2" },
    });
    const client = createAlfizClient({ catalog, provider });
    const snap = await client.snapshot({ userId: "u1" }, { scopes: ["docs.doc:1", "docs.folder:2"] });
    // The revoke at folder:9 suppresses at folder:9 and below…
    expect(snap.can("docs.files.read", "docs.doc:1")).toBe(false);
    expect(snap.can("docs.files.read", "docs.folder:9")).toBe(false);
    // …but not above it.
    expect(snap.can("docs.files.read", "docs.folder:2")).toBe(true);
    expect(await client.can({ userId: "u1" }, "docs.files.read", "docs.doc:1")).toBe(false);
  });

  it("ancestor implication (§7.5) agrees with client.can", async () => {
    const provider = fakeProvider({
      grants: [g("user:u1", { pattern: "docs.files.read_listing" }, "docs.folder:9")],
      parents: { "docs.folder:9": "docs.folder:2" },
    });
    const client = createAlfizClient({ catalog, provider });
    const snap = await client.snapshot({ userId: "u1" }, { scopes: ["docs.folder:2", "docs.folder:77"] });
    expect(snap.can("docs.files.read_listing", "docs.folder:2")).toBe(true); // implied on ancestor
    expect(snap.can("docs.files.read_listing", "docs.folder:77")).toBe(false);
    expect(snap.can("docs.files.read_listing")).toBe(false); // never at global
    expect(snap.can("docs.files.read_listing", "*")).toBe(false);
    const explained = snap.explain("docs.files.read_listing", "docs.folder:2");
    expect(explained.allowed).toBe(true);
    expect(explained.implied).toBe(true);
    expect(explained.matchedGrants).toEqual([]);
  });

  it("canAny is exact: scoped grants suppressed by ancestor revokes do not over-show", async () => {
    const provider = fakeProvider({
      grants: [g("user:u1", { pattern: "docs.files.update_file" }, "docs.doc:1")],
      revokes: [revoke("docs.files.update_file", "docs.folder:9")],
      parents: { "docs.doc:1": "docs.folder:9" },
    });
    const client = createAlfizClient({ catalog, provider });
    const snap = await client.snapshot({ userId: "u1" });
    // The only grant sits under the revoked subtree: nothing effectively held.
    expect(snap.canAny("docs.files.*")).toBe(false);
    expect(await client.canAny({ userId: "u1" }, "docs.files.*")).toBe(false);
  });

  it("inactive principals evaluate to no access, everywhere", async () => {
    const provider = fakeProvider({
      grants: [g("user:u1", { pattern: "*" })],
      active: false,
    });
    const client = createAlfizClient({ catalog, provider });
    const snap = await client.snapshot({ userId: "u1" });
    expect(snap.active).toBe(false);
    expect(snap.can("docs.files.read")).toBe(false);
    expect(snap.canAny("docs.*")).toBe(false);
    expect(snap.holds("docs.files.read")).toBe(false);
    expect(snap.heldKeys.size).toBe(0);
    expect(snap.grantedScopes("docs.files.read").granted.size).toBe(0);
    expect(() => snap.require("docs.files.read")).toThrow(AccessDeniedError);
    try {
      snap.require("docs.files.read");
    } catch (err) {
      expect((err as AccessDeniedError).reason).toBe("inactive");
    }
  });

  it("expired grants deny at the snapshot's evaluation instant", async () => {
    const provider = fakeProvider({
      grants: [g("user:u1", { pattern: "docs.files.read" }, "*", 500)],
    });
    const client = createAlfizClient({ catalog, provider, clock: () => 1000 });
    const snap = await client.snapshot({ userId: "u1" });
    expect(snap.at).toBe(1000);
    expect(snap.can("docs.files.read")).toBe(false);
  });

  it("heldKeys and holds answer 'anywhere', with only global revokes suppressing", async () => {
    const provider = fakeProvider({
      grants: [
        g("user:u1", { pattern: "lms.courses.publish_course" }, "lms.course:9"),
        g("user:u1", { pattern: "docs.files.*" }),
      ],
      revokes: [
        revoke("docs.files.delete"), // global: erases the key
        revoke("docs.files.read", "docs.folder:9"), // scoped: narrows one subtree only
      ],
      parents: {},
    });
    const client = createAlfizClient({ catalog, provider });
    const snap = await client.snapshot({ userId: "u1" });
    // Scoped grant: held anywhere, even though no global check passes.
    expect(snap.holds("lms.courses.publish_course")).toBe(true);
    expect(snap.can("lms.courses.publish_course")).toBe(false);
    expect(snap.heldKeys.has("lms.courses.publish_course")).toBe(true);
    expect(snap.heldKeys.has("docs.files.read")).toBe(true);
    expect(snap.heldKeys.has("docs.files.delete")).toBe(false);
    expect(snap.heldKeys.has("lms.courses.read")).toBe(false);
    // Agrees with the client-side probes.
    expect(await client.holdsAnywhere({ userId: "u1" }, "lms.courses.publish_course")).toBe(true);
    expect(await client.effectiveKeys({ userId: "u1" })).toContain("docs.files.read");
    // The wrapper escape hatch: plain strings flow through LooseKey paths.
    const permission: string = "lms.courses.publish_course";
    expect(snap.holds(permission)).toBe(true);
    expect(await client.holdsAnywhere({ userId: "u1" }, permission)).toBe(true);
  });

  it("grantedScopes is sync and feeds the listing plan", async () => {
    const provider = fakeProvider({
      grants: [
        g("user:u1", { pattern: "lms.courses.read" }, "lms.course:9"),
        g("everyone", { pattern: "lms.courses.read" }, "lms.course:2"),
      ],
    });
    const client = createAlfizClient({ catalog, provider });
    const snap = await client.snapshot({ userId: "u1" });
    expect(snap.grantedScopes("lms.courses.read").granted).toEqual(
      new Set(["lms.course:9", "lms.course:2"]),
    );
  });

  it("roles resolve inside the snapshot", async () => {
    const provider = fakeProvider({
      grants: [g("user:u1", { roleId: "r-teacher" }, "lms.course:9")],
      roles: [
        { id: "r-teacher", name: "Teacher", patterns: ["lms.courses.*"] },
      ],
    });
    const client = createAlfizClient({ catalog, provider });
    const snap = await client.snapshot({ userId: "u1" });
    expect(snap.can("lms.courses.publish_course", "lms.course:9")).toBe(true);
    expect(snap.can("lms.courses.publish_course", "lms.course:10")).toBe(false);
    // The role's meaning at this grant site: only course-grantable keys apply.
    expect(snap.can("docs.files.read", "lms.course:9")).toBe(false);
  });

  it("snapshot draws from the client caches; fresh bypasses them", async () => {
    const provider = fakeProvider({
      grants: [g("user:u1", { pattern: "docs.files.read" })],
    });
    const client = createAlfizClient({ catalog, provider });
    await client.snapshot({ userId: "u1" });
    await client.snapshot({ userId: "u1" });
    expect(provider.stats().fetches).toBe(1);
    await client.snapshot({ userId: "u1" }, { fresh: true });
    expect(provider.stats().fetches).toBe(2);
  });

  it("require/requireAny throw typed denials", async () => {
    const provider = fakeProvider({ grants: [] });
    const client = createAlfizClient({ catalog, provider });
    const snap = await client.snapshot({ userId: "u1" });
    expect(() => snap.require("docs.files.read")).toThrow(AccessDeniedError);
    expect(() => snap.requireAny("docs.*")).toThrow(AccessDeniedError);
    try {
      snap.require("docs.files.read");
    } catch (err) {
      expect((err as AccessDeniedError).reason).toBe("forbidden");
    }
  });

  it("resolve() extends a snapshot in place — the hierarchical list-page shape", async () => {
    const provider = fakeProvider({
      grants: [g("user:u1", { pattern: "docs.files.read" }, "docs.folder:9")],
      parents: {
        "docs.doc:1": "docs.folder:9",
        "docs.doc:2": "docs.folder:9",
        "docs.doc:99": "docs.folder:77",
      },
    });
    const client = createAlfizClient({ catalog, provider });

    // 1. Guard the page — the row ids do not exist yet.
    const snap = await client.snapshot({ userId: "u1" });
    const fetchesAfterGuard = provider.stats().fetches;
    expect(() => snap.can("docs.files.read", "docs.doc:1")).toThrow(/resolve/);

    // 2. Query, then resolve what the query returned.
    const rows = ["docs.doc:1", "docs.doc:2", "docs.doc:99"];
    const returned = await snap.resolve(rows);
    expect(returned).toBe(snap); // same snapshot, for chaining

    // 3. Check rows synchronously, against the SAME data instant.
    expect(provider.stats().fetches).toBe(fetchesAfterGuard); // no re-fetch
    expect(rows.filter((r) => snap.can("docs.files.read", r))).toEqual([
      "docs.doc:1",
      "docs.doc:2",
    ]);
    expect(snap.resolvedScopes.has("docs.doc:99")).toBe(true);
  });

  it("resolve() skips already-resolved scopes and ignores the global scope", async () => {
    const provider = fakeProvider({
      grants: [g("user:u1", { pattern: "docs.files.read" }, "docs.folder:9")],
      parents: { "docs.doc:1": "docs.folder:9" },
    });
    const client = createAlfizClient({ catalog, provider });
    const snap = await client.snapshot({ userId: "u1" }, { scopes: ["docs.doc:1"] });
    const before = provider.stats().resolves;
    await snap.resolve(["docs.doc:1", "docs.doc:1", "*"]);
    expect(provider.stats().resolves).toBe(before);
  });

  it("service principals snapshot too", async () => {
    const provider = fakeProvider({
      grants: [g("service:cron", { pattern: "docs.files.read" })],
      closure: ["service:cron", "everyone"],
    });
    // Machine subjects have no personal revokes; userId null.
    const base = await provider.getSubjectAccess({ serviceId: "cron" });
    const machine = { ...base, userId: null };
    const patched = {
      ...provider,
      getSubjectAccess: async () => machine,
    } as typeof provider;
    const client = createAlfizClient({ catalog, provider: patched });
    const snap = await client.snapshot({ serviceId: "cron" });
    expect(snap.can("docs.files.read")).toBe(true);
    expect(snap.holds("docs.files.read")).toBe(true);
  });
});
