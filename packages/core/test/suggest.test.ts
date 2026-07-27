/**
 * Informative errors: the suggestion engine (edit-distance near-misses,
 * right-leaf-wrong-group matches, undeclared-namespace hints) and the
 * context that check errors, write rejections, and snapshot failures carry.
 */

import { describe, expect, it } from "vitest";
import type { GrantRow } from "../src/access.js";
import {
  closestPatterns,
  defineCatalog,
  unknownPermissionContext,
} from "../src/catalog.js";
import { createAlfizClient } from "../src/client.js";
import {
  AccessDeniedError,
  UnresolvedScopeError,
  formatAlternatives,
} from "../src/errors.js";
import type { AlfizProvider, SubjectAccessData } from "../src/provider.js";

const catalog = defineCatalog({
  namespaces: ["docs", "mathaniyy"],
  includeAlfizInternal: false,
  permissions: {
    "docs.files.read": true,
    "docs.files.update_file": { scopes: ["docs.folder"] },
    "docs.files.delete": { scopes: ["docs.folder"] },
    "mathaniyy.approvals.read": true,
    "mathaniyy.approvals.decide_student": true,
  },
  scopeTypes: {
    "docs.folder": { parent: "docs.folder" },
    "docs.doc": { parent: "docs.folder" },
  },
});

const providerWith = (grants: GrantRow[]): AlfizProvider =>
  ({
    getSubjectAccess: async (): Promise<SubjectAccessData> => ({
      userId: "u1",
      closure: ["user:u1", "everyone"],
      grants,
      revokes: [],
      roles: [],
      managerChain: [],
      unresolvedRoleIds: [],
      active: true,
    }),
    resolveAncestors: () => ["*"],
    onInvalidate: () => () => {},
  }) as unknown as AlfizProvider;

const globalGrant: GrantRow = {
  id: "g1",
  subject: "user:u1",
  pattern: "*",
  scope: "*",
  provenance: { kind: "admin", actorUserId: "root" },
  createdAt: 0,
};

describe("closestPatterns", () => {
  it("finds the edit-distance near-miss", () => {
    expect(closestPatterns(catalog, "docs.files.raed", "key")[0]).toBe(
      "docs.files.read",
    );
  });

  it("finds the right leaf under the wrong project by its final segment", () => {
    expect(
      closestPatterns(catalog, "docs.approvals.decide_student", "key"),
    ).toContain("mathaniyy.approvals.decide_student");
  });

  it("suggests group wildcards at pattern sites", () => {
    expect(closestPatterns(catalog, "docs.file.*", "pattern")).toContain(
      "docs.files.*",
    );
  });

  it("stays silent for strings near nothing", () => {
    expect(closestPatterns(catalog, "zzzzzz.qqqq.wwww", "key")).toEqual([]);
  });
});

describe("unknownPermissionContext", () => {
  it("flags undeclared namespaces", () => {
    const { hint } = unknownPermissionContext(
      catalog,
      "stripe.charges.create",
      "key",
    );
    expect(hint).toMatch(/"stripe" is not a namespace/);
    expect(hint).toMatch(/docs, mathaniyy/);
  });

  it("suppresses near-miss noise when the group-path suggestion applies", () => {
    const ctx = unknownPermissionContext(catalog, "docs.files", "pattern");
    expect(ctx.suggestion).toBe("docs.files.*");
    expect(ctx.didYouMean).toEqual([]);
  });
});

describe("check errors carry the context", () => {
  it("a typo'd gate key names the closest declared key", async () => {
    const client = createAlfizClient({
      catalog,
      provider: providerWith([globalGrant]),
    });
    await expect(
      client.can({ userId: "u1" }, "docs.files.raed" as never),
    ).rejects.toThrow(/Did you mean "docs.files.read"/);
  });

  it("an undeclared namespace is called out on the pattern path", async () => {
    const client = createAlfizClient({
      catalog,
      provider: providerWith([globalGrant]),
    });
    await expect(
      client.canAny({ userId: "u1" }, "stripe.charges.*" as never),
    ).rejects.toThrow(/"stripe" is not a namespace/);
  });
});

describe("validateGrantableAt says where the grant WOULD be valid", () => {
  it("unknown scope types list the declared ones", () => {
    const issue = catalog.validateGrantableAt("docs.files.read", "ghost.thing:1");
    expect(issue?.message).toMatch(/declared scope types: docs.folder, docs.doc/);
  });

  it("non-grantable patterns list the scope types the leaves declare", () => {
    const issue = catalog.validateGrantableAt("docs.files.delete", "docs.doc:1");
    expect(issue?.message).toMatch(/grantable at: docs.folder/);
  });

  it("global-only leaves say so", () => {
    const issue = catalog.validateGrantableAt("docs.files.read", "docs.doc:1");
    expect(issue?.message).toMatch(/grantable at "\*" only/);
  });

  it("patterns matching nothing get a near-miss", () => {
    const issue = catalog.validateGrantableAt("docs.files.raed", "docs.doc:1");
    expect(issue?.message).toMatch(/did you mean "docs.files.read"/);
  });
});

describe("AccessDeniedError attribution", () => {
  it("names the principal and points at explain()", async () => {
    const client = createAlfizClient({ catalog, provider: providerWith([]) });
    const err = await client
      .require({ userId: "u1" }, "docs.files.read")
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(AccessDeniedError);
    expect((err as AccessDeniedError).principal).toEqual({ userId: "u1" });
    expect((err as AccessDeniedError).message).toMatch(/for user:u1/);
    expect((err as AccessDeniedError).message).toMatch(/explain\(/);
  });
});

describe("UnresolvedScopeError", () => {
  it("is typed, and reports what IS resolved", async () => {
    const client = createAlfizClient({
      catalog,
      provider: providerWith([globalGrant]),
    });
    const snap = await client.snapshot({ userId: "u1" });
    const err = (() => {
      try {
        snap.can("docs.files.delete", "docs.folder:unresolved");
        return null;
      } catch (e) {
        return e;
      }
    })();
    expect(err).toBeInstanceOf(UnresolvedScopeError);
    const typed = err as UnresolvedScopeError;
    expect(typed.scope).toBe("docs.folder:unresolved");
    expect(typed.scopeType).toBe("docs.folder");
    expect(typed.declared).toBe(true);
    expect(typed.message).toMatch(/hierarchical/);
    expect(typed.message).toMatch(/Pre-resolve/);
  });

  it("an undeclared scope type lists the declared ones", async () => {
    const client = createAlfizClient({
      catalog,
      provider: providerWith([globalGrant]),
    });
    const snap = await client.snapshot({ userId: "u1" });
    expect(() => snap.can("docs.files.read", "ghost.thing:1")).toThrow(
      /not declared in the catalog \(declared scope types: docs.folder, docs.doc\)/,
    );
  });
});

describe("formatAlternatives", () => {
  it("renders 1, 2, and 3+ item lists", () => {
    expect(formatAlternatives(["a"])).toBe('"a"');
    expect(formatAlternatives(["a", "b"])).toBe('"a" or "b"');
    expect(formatAlternatives(["a", "b", "c"])).toBe('"a", "b", or "c"');
  });
});
