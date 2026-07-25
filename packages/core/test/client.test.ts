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
    "docs.folder": { parent: null },
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
