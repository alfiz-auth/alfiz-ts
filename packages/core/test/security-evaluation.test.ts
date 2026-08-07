/**
 * Adversarial regression suite for the core evaluation engine.
 *
 * Every test here asserts the SECURE, DESIRED behavior of the semantics the
 * README fixes as non-negotiable — negative-always-wins (scope-inclusively),
 * union-only inheritance, forward-inclusive wildcards with a hard separator
 * boundary, "the global `*` confers only declared vocabulary", and "hierarchy
 * is data, resolved at check time; checks walk UP".
 *
 * A failing test in this file is a wrong-answer bug in the sense SECURITY.md
 * uses the term: a check that allows what the rows deny, or a revoke that
 * fails to suppress. Nothing here is weakened to go green.
 */

import { describe, expect, it } from "vitest";
import type {
  CheckContext,
  GrantRow,
  RevokeRow,
  RoleDef,
} from "../src/access.js";
import { checkKey, explainKey, isExpired, keyHeldAnywhere } from "../src/access.js";
import type { CatalogDocument } from "../src/catalog.js";
import { defineCatalog } from "../src/catalog.js";
import { createAlfizClient } from "../src/client.js";
import { UnknownPermissionError, UnresolvedScopeError } from "../src/errors.js";
import {
  isValidKey,
  patternMatchesKey,
  patternsIntersect,
} from "../src/grammar.js";
import {
  condenseImportedGraph,
  findCycle,
  findCycleForEdge,
} from "../src/graph.js";
import type { AlfizProvider, SubjectAccessData } from "../src/provider.js";
import {
  objectClosureOf,
  parentPointerResolver,
  parseScopeId,
  scopeId,
} from "../src/scopes.js";
import { checkSodConstraints } from "../src/sod.js";
import {
  computeSubjectClosure,
  parseSubject,
  userSubject,
} from "../src/subjects.js";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const NOW = 1_000_000;

const catalog = defineCatalog({
  namespaces: ["docs"],
  includeAlfizInternal: false,
  permissions: {
    "docs.files.read": {
      scopes: ["docs.folder", "docs.doc"],
      impliedOnAncestors: true,
    },
    "docs.files.update_file": { scopes: ["docs.folder", "docs.doc"] },
    "docs.files.delete": { scopes: ["docs.folder"] },
    "docs.vendors.admin_vendor": { scopes: ["docs.folder"] },
    "docs.payments.approve_payment": { scopes: ["docs.folder"] },
  },
  scopeTypes: {
    // Self-parented: folders nest, so folder scopes are hierarchical and
    // must be resolved rather than assumed flat.
    "docs.folder": { parent: "docs.folder" },
    "docs.doc": { parent: "docs.folder", multiParent: true },
  },
  constraints: {
    sod: [
      {
        id: "vendor-vs-payments",
        sets: [["docs.vendors.*"], ["docs.payments.*"]],
      },
    ],
  },
});

/**
 * doc:1 → folder:9 → folder:2 (root)
 * doc:5 → folder:7 (root)
 * doc:m → folder:9 AND folder:7 (multi-parent)
 */
const PARENTS: Record<string, readonly string[]> = {
  "docs.doc:1": ["docs.folder:9"],
  "docs.folder:9": ["docs.folder:2"],
  "docs.folder:2": [],
  "docs.doc:5": ["docs.folder:7"],
  "docs.folder:7": [],
  "docs.doc:m": ["docs.folder:9", "docs.folder:7"],
};
const ALL_SCOPES = Object.keys(PARENTS);

const resolveAncestors = (scope: string): string[] => {
  const out: string[] = [];
  const seen = new Set([scope]);
  let frontier = [scope];
  while (frontier.length > 0) {
    const next: string[] = [];
    for (const node of frontier) {
      for (const parent of PARENTS[node] ?? []) {
        if (seen.has(parent)) continue;
        seen.add(parent);
        out.push(parent);
        next.push(parent);
      }
    }
    frontier = next;
  }
  out.push("*");
  return out;
};

let seq = 0;
const grant = (
  what: { pattern?: string; roleId?: string },
  scope = "*",
  subject = "user:u1",
  expiresAt?: number,
): GrantRow => ({
  id: `g${++seq}`,
  subject,
  pattern: what.pattern,
  roleId: what.roleId,
  scope,
  expiresAt,
  provenance: { kind: "admin", actorUserId: "root" },
  createdAt: NOW - 1000,
});

const revoke = (pattern: string, scope = "*", userId = "u1"): RevokeRow => ({
  id: `r${++seq}`,
  userId,
  pattern,
  scope,
  provenance: { kind: "admin", actorUserId: "root" },
  createdAt: NOW - 1000,
});

interface Rows {
  grants?: GrantRow[];
  revokes?: RevokeRow[];
  roles?: RoleDef[];
  closure?: string[];
  active?: boolean;
  ancestors?: (scope: string) => string[];
}

const providerOf = (rows: Rows): AlfizProvider =>
  ({
    getSubjectAccess: async (): Promise<SubjectAccessData> => ({
      userId: "u1",
      closure: rows.closure ?? ["user:u1", "everyone"],
      grants: rows.grants ?? [],
      revokes: rows.revokes ?? [],
      roles: rows.roles ?? [],
      managerChain: [],
      unresolvedRoleIds: [],
      active: rows.active ?? true,
    }),
    resolveAncestors: rows.ancestors ?? resolveAncestors,
    onInvalidate: () => () => {},
  }) as unknown as AlfizProvider;

const clientOf = (rows: Rows) =>
  createAlfizClient({ catalog, provider: providerOf(rows) });

const ctxOf = (rows: Rows): CheckContext => ({
  subjectClosure: new Set(rows.closure ?? ["user:u1", "everyone"]),
  userId: "u1",
  rows: {
    grants: rows.grants ?? [],
    revokes: rows.revokes ?? [],
    roles: new Map((rows.roles ?? []).map((r) => [r.id, r])),
  },
  now: NOW,
  grantApplies: (key, grantScope) => catalog.appliesAt(key, grantScope),
});

// ---------------------------------------------------------------------------
// 1. Forward-inclusive wildcards: the separator boundary, both directions
// ---------------------------------------------------------------------------

describe("wildcard prefix confusion", () => {
  it("a subtree wildcard never matches a sibling namespace that merely shares a prefix", () => {
    for (const key of [
      "docsx.read",
      "docs2.files.read",
      "docs_private.files.read",
      "docsdocs.read",
      "docs",
      "docs.",
    ]) {
      expect(patternMatchesKey("docs.*", key)).toBe(false);
    }
    expect(patternMatchesKey("docs.*", "docs.files.read")).toBe(true);
  });

  it("a deeper subtree wildcard respects the separator on the last segment too", () => {
    for (const key of [
      "docs.files_secret.read",
      "docs.filesx.read",
      "docs.files2.read",
      "docs.files",
      "docs.files.",
    ]) {
      expect(patternMatchesKey("docs.files.*", key)).toBe(false);
    }
    expect(patternMatchesKey("docs.files.*", "docs.files.read")).toBe(true);
    expect(patternMatchesKey("docs.files.*", "docs.files.a.b.c")).toBe(true);
  });

  it("intersection is segment-aware in both argument orders", () => {
    for (const [a, b] of [
      ["docs.*", "docsx.*"],
      ["docsx.*", "docs.*"],
      ["docs.files.*", "docs.files_secret.*"],
      ["docs.files_secret.*", "docs.files.*"],
      ["docs.*", "docs"],
      ["docs", "docs.*"],
      ["docs.files.read", "docs.files_secret.*"],
    ] as const) {
      expect(patternsIntersect(a, b)).toBe(false);
    }
    expect(patternsIntersect("docs.*", "docs.files.*")).toBe(true);
    expect(patternsIntersect("docs.files.*", "docs.*")).toBe(true);
  });

  it("a key with an empty segment is not a key, and cannot be gated on", async () => {
    // `docs..read` string-prefixes `docs.` — the grammar must refuse it as a
    // key so it can never reach an evaluator through a runtime-string path.
    expect(isValidKey("docs..read")).toBe(false);
    expect(catalog.hasKey("docs..read")).toBe(false);
    const client = clientOf({ grants: [grant({ pattern: "docs.*" })] });
    await expect(
      client.can({ userId: "u1" }, "docs..read" as never),
    ).rejects.toBeInstanceOf(UnknownPermissionError);
    client.close();
  });
});

// ---------------------------------------------------------------------------
// 2. Scope ids: parsing, forging, and the caller-supplied resource id
// ---------------------------------------------------------------------------

describe("scope-id parsing cannot be used to forge a scope", () => {
  it("the type half is everything before the FIRST colon; the rest is opaque", () => {
    expect(parseScopeId("docs.doc:a:b")).toEqual({
      type: "docs.doc",
      instanceId: "a:b",
    });
    expect(scopeId("docs.doc", "a:b")).toBe("docs.doc:a:b");
    // Degenerate shapes parse to nothing at all.
    for (const bad of ["docs.doc:", ":9", "docs.doc", "", ":"]) {
      expect(parseScopeId(bad)).toBe(null);
    }
  });

  it("a grant at a malformed scope confers nothing (fail closed)", () => {
    for (const bad of ["docs.folder:", "docs.folder", ":9", "*:1", " docs.folder:9"]) {
      expect(catalog.appliesAt("docs.files.delete", bad)).toBe(false);
    }
    expect(catalog.appliesAt("docs.files.delete", "docs.folder:9")).toBe(true);
    expect(catalog.appliesAt("docs.files.delete", "*")).toBe(true);
  });

  it("a resource id smuggling `*` cannot widen a check", async () => {
    const client = clientOf({
      grants: [grant({ pattern: "docs.files.read" }, "docs.folder:9")],
    });
    const p = { userId: "u1" };
    // The grant is folder-scoped; `*` is the STRICTEST check, not the loosest.
    expect(await client.can(p, "docs.files.read", "*")).toBe(false);
    expect(await client.can(p, "docs.files.read")).toBe(false);
    // And the instance half being `*` is just an instance id, not the global scope.
    expect(await client.can(p, "docs.files.read", "docs.folder:*")).toBe(false);
    expect(await client.can(p, "docs.files.read", "docs.doc:*")).toBe(false);
    expect(await client.can(p, "docs.files.read", "docs.folder:9")).toBe(true);
    client.close();
  });

  it("scope matching is exact membership, never a string prefix", async () => {
    const client = clientOf({
      grants: [grant({ pattern: "docs.files.read" }, "docs.folder:9")],
    });
    const p = { userId: "u1" };
    for (const impostor of [
      "docs.folder:99",
      "docs.folder:9x",
      "docs.folder:9 ",
      "docs.folder:9\n",
      "docs.folder:9\t",
    ]) {
      expect(await client.can(p, "docs.files.read", impostor)).toBe(false);
    }
    client.close();
  });

  it("a whitespace- or newline-padded scope id never aliases the clean one", async () => {
    const client = clientOf({
      grants: [grant({ pattern: "docs.files.read" }, "docs.folder:9 ")],
    });
    // A grant written at a padded id must not answer for the clean id either.
    expect(
      await client.can({ userId: "u1" }, "docs.files.read", "docs.folder:9"),
    ).toBe(false);
    client.close();
  });

  it("the global scope's closure is only itself, whatever the resolver says", async () => {
    expect(await objectClosureOf("*", () => ["docs.folder:9", "*"])).toEqual([
      "*",
    ]);
  });
});

// ---------------------------------------------------------------------------
// 3. Negative always wins, scope-inclusively
// ---------------------------------------------------------------------------

describe("negative always wins, scope-inclusively", () => {
  const deepGrant = () => [
    grant({ pattern: "docs.files.update_file" }, "docs.doc:1"),
  ];

  it("a revoke at EVERY ancestor level kills a deeper direct grant", async () => {
    for (const at of ["docs.doc:1", "docs.folder:9", "docs.folder:2", "*"]) {
      const client = clientOf({
        grants: deepGrant(),
        revokes: [revoke("docs.files.update_file", at)],
      });
      const p = { userId: "u1" };
      expect(await client.can(p, "docs.files.update_file", "docs.doc:1")).toBe(
        false,
      );
      const explained = await client.explain(
        p,
        "docs.files.update_file",
        "docs.doc:1",
      );
      expect(explained.allowed).toBe(false);
      const snap = await client.snapshot(p, { scopes: ALL_SCOPES });
      expect(snap.can("docs.files.update_file", "docs.doc:1")).toBe(false);
      client.close();
    }
  });

  it("a revoke on an unrelated branch does not suppress", async () => {
    const client = clientOf({
      grants: deepGrant(),
      revokes: [revoke("docs.files.update_file", "docs.folder:7")],
    });
    expect(
      await client.can({ userId: "u1" }, "docs.files.update_file", "docs.doc:1"),
    ).toBe(true);
    client.close();
  });

  it("a wildcard revoke suppresses a concrete grant under it, at any depth", async () => {
    const client = clientOf({
      grants: deepGrant(),
      revokes: [revoke("docs.*", "docs.folder:2")],
    });
    expect(
      await client.can({ userId: "u1" }, "docs.files.update_file", "docs.doc:1"),
    ).toBe(false);
    client.close();
  });

  it("multi-parent: a revoke on EITHER parent branch suppresses the union", async () => {
    for (const at of ["docs.folder:9", "docs.folder:7", "docs.folder:2"]) {
      const client = clientOf({
        grants: [grant({ pattern: "docs.files.update_file" }, "docs.folder:7")],
        revokes: [revoke("docs.files.update_file", at)],
      });
      expect(
        await client.can(
          { userId: "u1" },
          "docs.files.update_file",
          "docs.doc:m",
        ),
      ).toBe(false);
      client.close();
    }
  });

  it("a revoke beats a role grant arriving through a group", async () => {
    const client = clientOf({
      closure: ["user:u1", "group:team", "everyone"],
      roles: [{ id: "editor", name: "Editor", patterns: ["docs.files.*"] }],
      grants: [grant({ roleId: "editor" }, "docs.folder:2", "group:team")],
      revokes: [revoke("docs.files.update_file", "docs.folder:9")],
    });
    const p = { userId: "u1" };
    expect(await client.can(p, "docs.files.update_file", "docs.doc:1")).toBe(
      false,
    );
    // ...and only the revoked key, at only the revoked subtree.
    expect(await client.can(p, "docs.files.read", "docs.doc:1")).toBe(true);
    expect(
      await client.can(p, "docs.files.update_file", "docs.folder:2"),
    ).toBe(true);
    client.close();
  });

  it("a cycle in the ancestry data does not let a revoke fall out of the closure", async () => {
    const cyclic = parentPointerResolver((scope) =>
      scope === "docs.folder:a"
        ? "docs.folder:b"
        : scope === "docs.folder:b"
          ? "docs.folder:a"
          : null,
    );
    const client = clientOf({
      ancestors: cyclic,
      grants: [grant({ pattern: "docs.files.delete" }, "docs.folder:a")],
      revokes: [revoke("docs.files.delete", "docs.folder:b")],
    });
    expect(
      await client.can({ userId: "u1" }, "docs.files.delete", "docs.folder:a"),
    ).toBe(false);
    client.close();
  });

  it("revokes are personal-only: another user's revoke never suppresses", () => {
    const ctx = ctxOf({
      closure: ["user:u1", "group:team", "everyone"],
      grants: [grant({ pattern: "docs.files.read" }, "*", "group:team")],
      revokes: [revoke("docs.files.read", "*", "u2")],
    });
    expect(checkKey(ctx, "docs.files.read", ["*"])).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// 4. §7.5 ancestor implication: it walks DOWN, so it must never outlive a revoke
// ---------------------------------------------------------------------------

describe("ancestor implication (§7.5) stays inside the negative rule", () => {
  const held = () => [grant({ pattern: "docs.files.read" }, "docs.doc:1")];

  it("implies the key on proper ancestors only, never globally", async () => {
    const client = clientOf({ grants: held() });
    const p = { userId: "u1" };
    expect(await client.can(p, "docs.files.read", "docs.folder:9")).toBe(true);
    expect(await client.can(p, "docs.files.read", "docs.folder:2")).toBe(true);
    // `can(u, key, "*")` must agree with `can(u, key)`, and neither may pass.
    expect(await client.can(p, "docs.files.read", "*")).toBe(false);
    expect(await client.can(p, "docs.files.read")).toBe(false);
    // Nor may it leak sideways into an unrelated subtree.
    expect(await client.can(p, "docs.files.read", "docs.folder:7")).toBe(false);
    client.close();
  });

  it("a revoke anywhere over the implying grant kills the implication", async () => {
    for (const at of ["docs.doc:1", "docs.folder:9", "docs.folder:2", "*"]) {
      const client = clientOf({
        grants: held(),
        revokes: [revoke("docs.files.read", at)],
      });
      const p = { userId: "u1" };
      expect(await client.can(p, "docs.files.read", "docs.folder:9")).toBe(
        false,
      );
      const snap = await client.snapshot(p, { scopes: ALL_SCOPES });
      expect(snap.can("docs.files.read", "docs.folder:9")).toBe(false);
      expect(
        (await client.explain(p, "docs.files.read", "docs.folder:9")).allowed,
      ).toBe(false);
      client.close();
    }
  });

  it("implication is opt-in per leaf: an undeclared key is never implied", async () => {
    const client = clientOf({
      grants: [grant({ pattern: "docs.files.update_file" }, "docs.doc:1")],
    });
    expect(
      await client.can(
        { userId: "u1" },
        "docs.files.update_file",
        "docs.folder:9",
      ),
    ).toBe(false);
    client.close();
  });
});

// ---------------------------------------------------------------------------
// 5. Union-only inheritance
// ---------------------------------------------------------------------------

describe("union-only inheritance", () => {
  it("adding a group can only widen: no membership ever removes access", async () => {
    const rows = {
      grants: [
        grant({ pattern: "docs.files.read" }, "*", "user:u1"),
        grant({ pattern: "docs.files.delete" }, "docs.folder:9", "group:team"),
      ],
    };
    const alone = clientOf({ ...rows, closure: ["user:u1", "everyone"] });
    const withGroup = clientOf({
      ...rows,
      closure: ["user:u1", "group:team", "everyone"],
    });
    const p = { userId: "u1" };
    expect(await alone.can(p, "docs.files.read")).toBe(true);
    expect(await withGroup.can(p, "docs.files.read")).toBe(true);
    expect(await alone.can(p, "docs.files.delete", "docs.folder:9")).toBe(false);
    expect(await withGroup.can(p, "docs.files.delete", "docs.folder:9")).toBe(
      true,
    );
    alone.close();
    withGroup.close();
  });

  it("a group closure is a pure superset — group parentage adds, never subtracts", () => {
    const closure = computeSubjectClosure({
      userId: "u1",
      groupIds: ["team"],
      groupParents: new Map([["team", ["staff"]]]),
    });
    for (const subject of ["user:u1", "group:team", "group:staff", "everyone"]) {
      expect(closure.has(subject)).toBe(true);
    }
  });

  it("an unresolvable role confers nothing rather than everything", () => {
    const ctx = ctxOf({ grants: [grant({ roleId: "ghost" })] });
    expect(checkKey(ctx, "docs.files.read", ["*"])).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// 6. The global `*` confers only declared vocabulary
// ---------------------------------------------------------------------------

const zoomDocument: CatalogDocument = defineCatalog({
  namespaces: ["zoom"],
  includeAlfizInternal: false,
  conventions: { depth: "any" },
  permissions: { "zoom.host": true },
}).toDocument();

const permissiveClient = (pattern: string, roleId?: string) =>
  createAlfizClient({
    catalog,
    provider: providerOf({
      grants: [grant(roleId ? { roleId } : { pattern })],
      roles: roleId ? [{ id: roleId, name: "Root", patterns: [pattern] }] : [],
    }),
    externalPermissions: "allow",
  });

describe("the global `*` confers only declared vocabulary", () => {
  it("a bare `*` grant does not confer a permission no catalog declares", async () => {
    const client = permissiveClient("*");
    expect(await client.can({ userId: "u1" }, "zoom.host" as never)).toBe(false);
    expect(await client.holds({ userId: "u1" }, "zoom.host")).toBe(false);
    // ...and still confers everything the catalog DOES declare.
    expect(await client.can({ userId: "u1" }, "docs.files.read")).toBe(true);
    client.close();
  });

  it("a role whose pattern is the bare `*` cannot launder the rule", async () => {
    const client = permissiveClient("*", "root");
    expect(await client.can({ userId: "u1" }, "zoom.host" as never)).toBe(false);
    expect(await client.can({ userId: "u1" }, "docs.files.read")).toBe(true);
    client.close();
  });

  it("a namespace-anchored grant does confer it", async () => {
    const client = permissiveClient("zoom.*");
    expect(await client.can({ userId: "u1" }, "zoom.host" as never)).toBe(true);
    client.close();
  });

  it("the rule is positive-only: a `*` revoke still suppresses an undeclared key", async () => {
    const client = createAlfizClient({
      catalog,
      provider: providerOf({
        grants: [grant({ pattern: "zoom.*" })],
        revokes: [revoke("*")],
      }),
      externalPermissions: "allow",
    });
    expect(await client.can({ userId: "u1" }, "zoom.host" as never)).toBe(false);
    client.close();
  });

  it("an enumerated import still refuses a key it does not cover", async () => {
    const enumerated = defineCatalog({
      namespaces: ["docs"],
      includeAlfizInternal: false,
      permissions: { "docs.files.read": true },
      imports: {
        zoom: { document: zoomDocument, permissions: { "zoom.host": true } },
      },
    });
    const client = createAlfizClient({
      catalog: enumerated,
      provider: providerOf({ grants: [grant({ pattern: "zoom.*" })] }),
      externalPermissions: "allow",
    });
    await expect(
      client.can({ userId: "u1" }, "zoom.hostt" as never),
    ).rejects.toBeInstanceOf(UnknownPermissionError);
    client.close();
  });
});

// ---------------------------------------------------------------------------
// 7. A gate is a question about a KEY. It must never evaluate a pattern.
// ---------------------------------------------------------------------------

describe("gates refuse patterns, not just unknown keys", () => {
  it("the bare `*` and an OWNED wildcard are refused as gate keys", async () => {
    const client = permissiveClient("*");
    const p = { userId: "u1" };
    await expect(client.can(p, "*" as never)).rejects.toBeInstanceOf(
      UnknownPermissionError,
    );
    await expect(client.can(p, "docs.*" as never)).rejects.toBeInstanceOf(
      UnknownPermissionError,
    );
    await expect(client.can(p, "docs.files.*" as never)).rejects.toBeInstanceOf(
      UnknownPermissionError,
    );
    client.close();
  });

  it("a FOREIGN subtree wildcard is refused as a gate key on the async surfaces", async () => {
    // `admittingRegion` refuses a wildcard as a key precisely so a gate can
    // never check one ("the one thing `can` must never do", catalog.ts).
    // The implicit-import admission path has to hold the same line, or a
    // runtime-string gate silently becomes "do you hold a covering
    // wildcard?" — passing for exactly the broadly-privileged users who
    // review and test it, and denying the users it was written for.
    const client = permissiveClient("zoom.*");
    const p = { userId: "u1" };
    await expect(client.can(p, "zoom.*" as never)).rejects.toBeInstanceOf(
      UnknownPermissionError,
    );
    await expect(
      client.can(p, "zoom.meetings.*" as never),
    ).rejects.toBeInstanceOf(UnknownPermissionError);
    await expect(client.require(p, "zoom.*" as never)).rejects.toBeInstanceOf(
      UnknownPermissionError,
    );
    await expect(client.holds(p, "zoom.*")).rejects.toBeInstanceOf(
      UnknownPermissionError,
    );
    await expect(client.explain(p, "zoom.*")).rejects.toBeInstanceOf(
      UnknownPermissionError,
    );
    client.close();
  });

  it("a FOREIGN subtree wildcard is refused as a gate key on the snapshot too", async () => {
    const client = permissiveClient("zoom.*");
    const snap = await client.snapshot({ userId: "u1" });
    expect(() => snap.can("zoom.*" as never)).toThrow(UnknownPermissionError);
    expect(() => snap.holds("zoom.*")).toThrow(UnknownPermissionError);
    client.close();
  });
});

// ---------------------------------------------------------------------------
// 8. Expiry
// ---------------------------------------------------------------------------

describe("expiry is enforced on every path", () => {
  it("boundary: exactly-now, zero, and negative expiries are all expired", () => {
    expect(isExpired({ expiresAt: NOW }, NOW)).toBe(true);
    expect(isExpired({ expiresAt: NOW - 1 }, NOW)).toBe(true);
    expect(isExpired({ expiresAt: 0 }, NOW)).toBe(true);
    expect(isExpired({ expiresAt: -1 }, NOW)).toBe(true);
    expect(isExpired({ expiresAt: NOW + 1 }, NOW)).toBe(false);
    expect(isExpired({ expiresAt: undefined }, NOW)).toBe(false);
  });

  it("an expired grant is invisible to every surface, not just to `can`", async () => {
    const client = clientOf({
      grants: [grant({ pattern: "docs.*" }, "*", "user:u1", Date.now() - 1)],
    });
    const p = { userId: "u1" };
    expect(await client.can(p, "docs.files.read")).toBe(false);
    expect(await client.canAny(p, "docs.*")).toBe(false);
    expect(await client.holds(p, "docs.files.read")).toBe(false);
    expect(await client.heldKeys(p)).toEqual([]);
    expect(
      [...(await client.grantedScopes(p, "docs.files.read")).granted],
    ).toEqual([]);
    const snap = await client.snapshot(p);
    expect([...snap.heldKeys]).toEqual([]);
    expect(snap.canAny("docs.*")).toBe(false);
    expect(snap.can("docs.files.read")).toBe(false);
    client.close();
  });

  it("an expiry the engine cannot honour is treated as EXPIRED, never as immortal", () => {
    // `expiresAt !== undefined && expiresAt <= now` evaluates to false for
    // NaN and for any non-numeric value, so a row whose expiry is
    // meaningless currently outlives every deadline it was written to
    // enforce. A grant that carries an expiry it cannot honour must fail
    // closed — the row says "until", and the engine must never read that as
    // "forever".
    expect(isExpired({ expiresAt: NaN }, NOW)).toBe(true);
    expect(
      isExpired(
        { expiresAt: "2020-01-01T00:00:00Z" as unknown as number },
        NOW,
      ),
    ).toBe(true);
  });

  it("a grant whose stored expiry is a past ISO string does not pass a check", async () => {
    // The write path guards with the same `<= now` comparison, so a runtime
    // string (an admin UI, a JSON body on POST /v1/createGrant) sails past
    // validation and then never expires: the row says 2020, the check says
    // yes. That is the wrong-answer class SECURITY.md names.
    const client = clientOf({
      grants: [
        grant(
          { pattern: "docs.files.delete" },
          "*",
          "user:u1",
          "2020-01-01T00:00:00Z" as unknown as number,
        ),
      ],
    });
    expect(await client.can({ userId: "u1" }, "docs.files.delete")).toBe(false);
    expect(await client.holds({ userId: "u1" }, "docs.files.delete")).toBe(
      false,
    );
    client.close();
  });
});

// ---------------------------------------------------------------------------
// 9. Scope-type applicability: a grant confers only what the catalog wired
// ---------------------------------------------------------------------------

describe("scope types constrain what a grant confers, at check time", () => {
  it("a wildcard grant at a narrow scope cannot confer a key never wired there", async () => {
    const client = clientOf({
      grants: [grant({ pattern: "docs.*" }, "docs.doc:1")],
    });
    const p = { userId: "u1" };
    // `docs.files.delete` is declared on docs.folder only.
    expect(await client.can(p, "docs.files.delete", "docs.doc:1")).toBe(false);
    expect(await client.holds(p, "docs.files.delete")).toBe(false);
    expect(await client.heldKeys(p)).not.toContain("docs.files.delete");
    // The keys that ARE wired there still work.
    expect(await client.can(p, "docs.files.read", "docs.doc:1")).toBe(true);
    client.close();
  });

  it("a role grant at a narrow scope is constrained identically", async () => {
    const client = clientOf({
      roles: [{ id: "editor", name: "Editor", patterns: ["docs.files.*"] }],
      grants: [grant({ roleId: "editor" }, "docs.doc:1")],
    });
    expect(
      await client.can({ userId: "u1" }, "docs.files.delete", "docs.doc:1"),
    ).toBe(false);
    client.close();
  });
});

// ---------------------------------------------------------------------------
// 10. Synchronous snapshot: it must never guess a chain
// ---------------------------------------------------------------------------

describe("the snapshot fails closed rather than evaluating a truncated chain", () => {
  it("an unresolved hierarchical scope throws instead of missing an ancestor revoke", async () => {
    const client = clientOf({
      grants: [grant({ pattern: "docs.files.read" })],
      revokes: [revoke("docs.files.read", "docs.folder:9")],
    });
    const snap = await client.snapshot({ userId: "u1" });
    // doc:1's chain was never resolved; guessing it would silently drop the
    // folder:9 revoke.
    expect(() => snap.can("docs.files.read", "docs.doc:1")).toThrow(
      UnresolvedScopeError,
    );
    await snap.resolve(["docs.doc:1"]);
    expect(snap.can("docs.files.read", "docs.doc:1")).toBe(false);
    client.close();
  });

  it("the sync surface agrees with the async one for every resolved scope", async () => {
    const client = clientOf({
      closure: ["user:u1", "group:team", "everyone"],
      grants: [
        grant({ pattern: "docs.files.read" }, "docs.folder:2", "group:team"),
        grant({ pattern: "docs.files.delete" }, "docs.folder:9"),
      ],
      revokes: [revoke("docs.files.read", "docs.folder:9")],
    });
    const p = { userId: "u1" };
    const snap = await client.snapshot(p, { scopes: ALL_SCOPES });
    for (const scope of [...ALL_SCOPES, "*"]) {
      for (const key of [
        "docs.files.read",
        "docs.files.delete",
        "docs.files.update_file",
      ] as const) {
        expect([scope, key, snap.can(key, scope)]).toEqual([
          scope,
          key,
          await client.can(p, key, scope),
        ]);
      }
    }
    client.close();
  });
});

// ---------------------------------------------------------------------------
// 11. Visibility shapes are never gates — and must not stand in for one
// ---------------------------------------------------------------------------

describe("canAny / holds are visibility only", () => {
  it("a grant somewhere makes the surface visible but gates nothing elsewhere", async () => {
    const client = clientOf({
      grants: [grant({ pattern: "docs.files.delete" }, "docs.folder:9")],
    });
    const p = { userId: "u1" };
    expect(await client.canAny(p, "docs.*")).toBe(true);
    expect(await client.holds(p, "docs.files.delete")).toBe(true);
    // The gate at a scope they were never granted still denies.
    expect(await client.can(p, "docs.files.delete", "docs.folder:7")).toBe(
      false,
    );
    expect(await client.can(p, "docs.files.delete", "*")).toBe(false);
    expect(await client.can(p, "docs.files.delete")).toBe(false);
    client.close();
  });

  it("an inactive principal sees and holds nothing on any surface", async () => {
    const client = clientOf({
      active: false,
      grants: [grant({ pattern: "docs.*" })],
    });
    const p = { userId: "u1" };
    expect(await client.can(p, "docs.files.read")).toBe(false);
    expect(await client.canAny(p, "docs.*")).toBe(false);
    expect(await client.holds(p, "docs.files.read")).toBe(false);
    expect(await client.heldKeys(p)).toEqual([]);
    const snap = await client.snapshot(p);
    expect(snap.can("docs.files.read")).toBe(false);
    expect([...snap.heldKeys]).toEqual([]);
    client.close();
  });

  it("a global revoke suppresses the anywhere-probe (fail closed)", () => {
    const ctx = ctxOf({
      grants: [grant({ pattern: "docs.*" }, "docs.folder:9")],
      revokes: [revoke("docs.*")],
    });
    expect(keyHeldAnywhere(ctx, "docs.files.delete")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// 12. Subject strings cannot be used to impersonate
// ---------------------------------------------------------------------------

describe("subject encodings resist impersonation", () => {
  it("a user id of `everyone` is still a user subject", () => {
    expect(userSubject("everyone")).toBe("user:everyone");
    expect(parseSubject("user:everyone")).toEqual({
      kind: "user",
      id: "everyone",
    });
    const closure = computeSubjectClosure({ userId: "everyone", groupIds: [] });
    expect(closure.has("user:everyone")).toBe(true);
  });

  it("a colon in a user id cannot forge a group or an implicit-group subject", () => {
    expect(userSubject("group:admins")).toBe("user:group:admins");
    const closure = computeSubjectClosure({
      userId: "group:admins",
      groupIds: [],
    });
    expect(closure.has("group:admins")).toBe(false);
    expect(closure.has("directs:root")).toBe(false);
  });

  it("only the declared prefixes parse as subjects", () => {
    for (const bad of [
      "bogus:1",
      "everyone:x",
      "user:",
      "group:",
      "",
      ":x",
      "USER:x",
      " user:u1",
    ]) {
      expect(parseSubject(bad)).toBe(null);
    }
  });

  it("a grant to a subject outside the closure never matches", () => {
    const ctx = ctxOf({
      closure: ["user:u1", "everyone"],
      grants: [
        grant({ pattern: "docs.*" }, "*", "group:admins"),
        grant({ pattern: "docs.*" }, "*", "user:u1x"),
        grant({ pattern: "docs.*" }, "*", "user:u"),
      ],
    });
    expect(checkKey(ctx, "docs.files.read", ["*"])).toBe(false);
  });

  it("a revoke is keyed on the exact user id, with no prefix aliasing", () => {
    const rows = {
      grants: [grant({ pattern: "docs.*" })],
      revokes: [revoke("docs.*", "*", "u1x")],
    };
    expect(checkKey(ctxOf(rows), "docs.files.read", ["*"])).toBe(true);
    expect(
      explainKey(ctxOf(rows), "docs.files.read", ["*"]).matchedRevokes,
    ).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// 13. Graph integrity: cycles terminate, and truncation never drops a revoke
// ---------------------------------------------------------------------------

describe("graph integrity", () => {
  it("self-parents, two-cycles and diamonds are all detected", () => {
    expect(findCycleForEdge(new Map(), "a", "a")).toEqual(["a", "a"]);
    expect(findCycle(new Map([["a", ["a"]]]))).toEqual(["a", "a"]);
    expect(
      findCycleForEdge(
        new Map([
          ["b", ["c", "d"]],
          ["d", ["e"]],
          ["e", ["a"]],
        ]),
        "a",
        "b",
      ),
    ).toEqual(["a", "b", "d", "e", "a"]);
    expect(findCycle(new Map([["a", ["b"]], ["b", ["c"]], ["d", ["c"]]]))).toBe(
      null,
    );
  });

  it("a very deep chain and a very long cycle both terminate", () => {
    const deep = new Map<string, string[]>();
    for (let i = 0; i < 10_000; i++) deep.set(`g${i}`, [`g${i + 1}`]);
    expect(findCycle(deep)).toBe(null);

    const cyclic = new Map<string, string[]>();
    for (let i = 0; i < 5_000; i++) cyclic.set(`n${i}`, [`n${(i + 1) % 5_000}`]);
    expect(findCycle(cyclic)).not.toBe(null);
    const condensed = condenseImportedGraph(cyclic);
    expect(condensed.virtualParents.length).toBe(1);
    expect(findCycle(condensed.parentsOf)).toBe(null);
  });

  it("a group-parent cycle neither hangs nor truncates the closure", () => {
    const closure = computeSubjectClosure({
      userId: "u1",
      groupIds: ["a"],
      groupParents: new Map([
        ["a", ["b"]],
        ["b", ["c"]],
        ["c", ["a"]],
      ]),
    });
    for (const s of ["group:a", "group:b", "group:c"]) {
      expect(closure.has(s)).toBe(true);
    }
  });

  it("pathological ancestry depth raises rather than answering", async () => {
    const chain = new Map<string, string>();
    for (let i = 0; i < 20_000; i++) chain.set(`docs.folder:${i}`, `docs.folder:${i + 1}`);
    const resolve = parentPointerResolver((s) => chain.get(s) ?? null);
    const client = clientOf({
      ancestors: resolve,
      grants: [grant({ pattern: "docs.files.read" })],
    });
    // An unbounded walk would hang; a truncated one would drop ancestor
    // revokes. Throwing is the only fail-closed answer.
    await expect(
      client.can({ userId: "u1" }, "docs.files.read", "docs.folder:0"),
    ).rejects.toThrow(/exceeds 10000 levels/);
    client.close();
  });
});

// ---------------------------------------------------------------------------
// 14. Separation of duties sees every path into a set
// ---------------------------------------------------------------------------

describe("separation of duties", () => {
  const constraints = catalog.sodConstraints;

  it("a role through a group plus a direct grant is still one person holding both", () => {
    const ctx = ctxOf({
      closure: ["user:u1", "group:team", "everyone"],
      roles: [{ id: "vendor", name: "Vendor", patterns: ["docs.vendors.*"] }],
      grants: [
        grant({ roleId: "vendor" }, "*", "group:team"),
        grant({ pattern: "docs.payments.approve_payment" }),
      ],
    });
    const violations = checkSodConstraints(ctx, catalog, constraints);
    expect(violations.map((v) => v.constraintId)).toEqual([
      "vendor-vs-payments",
    ]);
    expect(violations[0]!.sets.map((s) => s.setIndex)).toEqual([0, 1]);
  });

  it("two scopes are still one person: scope is deliberately ignored", () => {
    const ctx = ctxOf({
      grants: [
        grant({ pattern: "docs.vendors.admin_vendor" }, "docs.folder:9"),
        grant({ pattern: "docs.payments.approve_payment" }, "docs.folder:7"),
      ],
    });
    expect(checkSodConstraints(ctx, catalog, constraints).length).toBe(1);
  });

  it("an expired grant is not a holding", () => {
    const ctx = ctxOf({
      grants: [
        grant({ pattern: "docs.vendors.admin_vendor" }, "*", "user:u1", NOW - 1),
        grant({ pattern: "docs.payments.approve_payment" }),
      ],
    });
    expect(checkSodConstraints(ctx, catalog, constraints)).toEqual([]);
  });

  it("a grant conferring nothing at its scope type is not a holding either", () => {
    // Both keys are wired to docs.folder only; a docs.doc grant confers
    // neither, so it must not manufacture a violation.
    const ctx = ctxOf({
      grants: [
        grant({ pattern: "docs.vendors.*" }, "docs.doc:1"),
        grant({ pattern: "docs.payments.approve_payment" }),
      ],
    });
    expect(checkSodConstraints(ctx, catalog, constraints)).toEqual([]);
  });
});
