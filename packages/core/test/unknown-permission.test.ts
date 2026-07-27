/**
 * Checks are verified against the catalog. Two failure modes motivated
 * this, and the first is a soundness hole rather than an ergonomic one:
 *
 *   - GATE path: `*` matches any string, so an undeclared key silently
 *     PASSED for anyone holding a covering wildcard and denied everyone
 *     else — a misspelled gate admits exactly the broadly-privileged users
 *     who review and test it.
 *   - VISIBILITY path: an undeclared pattern matched no catalog key and
 *     silently answered `false`, so a whole nav section could vanish with
 *     no error to search for.
 */

import { describe, expect, it } from "vitest";
import type { GrantRow } from "../src/access.js";
import { defineCatalog } from "../src/catalog.js";
import { createAlfizClient } from "../src/client.js";
import { UnknownPermissionError, isUnknownPermission } from "../src/errors.js";
import type { AlfizProvider, SubjectAccessData } from "../src/provider.js";

const catalog = defineCatalog({
  namespaces: ["docs", "admin"],
  includeAlfizInternal: false,
  permissions: {
    "docs.files.read": { scopes: ["docs.folder"] },
    "docs.files.update_file": { scopes: ["docs.folder"] },
    "admin.access.read": true,
  },
  scopeTypes: { "docs.folder": { parent: null } },
});

/** A principal holding the broadest possible grant — the fail-open case. */
const wildcardHolder = (pattern = "*"): AlfizProvider => {
  const grant: GrantRow = {
    id: "g1",
    subject: "user:u1",
    pattern,
    scope: "*",
    provenance: { kind: "admin", actorUserId: "root" },
    createdAt: 0,
  };
  return {
    getSubjectAccess: async (): Promise<SubjectAccessData> => ({
      userId: "u1",
      closure: ["user:u1", "everyone"],
      grants: [grant],
      revokes: [],
      roles: [],
      managerChain: [],
      unresolvedRoleIds: [],
      active: true,
    }),
    resolveAncestors: () => ["*"],
    onInvalidate: () => () => {},
  } as unknown as AlfizProvider;
};

const client = () =>
  createAlfizClient({ catalog, provider: wildcardHolder() });

describe("the gate-path fail-open, closed", () => {
  it("a typo'd key no longer passes for a wildcard holder", async () => {
    const c = client();
    // Before: `true` — "*" matches any string, including a typo.
    await expect(
      c.can({ userId: "u1" }, "docs.files.raed" as never),
    ).rejects.toBeInstanceOf(UnknownPermissionError);
    await expect(
      c.require({ userId: "u1" }, "docs.files.raed" as never),
    ).rejects.toThrow(/not a permission key/);
    // A key from a namespace the catalog never declared, likewise.
    await expect(
      c.can({ userId: "u1" }, "stripe.charges.create" as never),
    ).rejects.toBeInstanceOf(UnknownPermissionError);
    // The real key still passes.
    expect(await c.can({ userId: "u1" }, "docs.files.read")).toBe(true);
  });

  it("an any-of array is validated element by element", async () => {
    const c = client();
    await expect(
      c.can({ userId: "u1" }, ["docs.files.read", "docs.files.raed"] as never),
    ).rejects.toThrow(/docs.files.raed/);
  });

  it("a group path or wildcard as a GATE key is rejected with the right advice", async () => {
    const c = client();
    // A group: gates check leaves, so the fix is not `admin.*` as a gate.
    await expect(c.can({ userId: "u1" }, "admin" as never)).rejects.toThrow(
      /is a group, not a permission key.*canAny\("admin\.\*"\)/s,
    );
    // A wildcard: a pattern, not a key.
    await expect(
      c.can({ userId: "u1" }, "docs.files.*" as never),
    ).rejects.toThrow(/is a pattern, not a permission key/);
  });

  it("the error is a programming error, distinguishable from a denial", async () => {
    const c = client();
    const err = await c
      .can({ userId: "u1" }, "docs.files.raed" as never)
      .catch((e: unknown) => e);
    expect(isUnknownPermission(err)).toBe(true);
    expect((err as UnknownPermissionError).permission).toBe("docs.files.raed");
    expect((err as UnknownPermissionError).expected).toBe("key");
    expect((err as UnknownPermissionError).name).toBe("UnknownPermissionError");
  });
});

describe("the visibility-path silent false, closed", () => {
  it('canAny("admin") answers with the suggestion instead of false', async () => {
    const c = client();
    // Well-typed, evaluated happily, matched nothing, returned false.
    await expect(
      c.canAny({ userId: "u1" }, "admin" as never),
    ).rejects.toThrow(/is a group, not a pattern.*Did you mean "admin\.\*"\?/s);
    await expect(
      c.requireAny({ userId: "u1" }, "admin" as never),
    ).rejects.toBeInstanceOf(UnknownPermissionError);
    // The corrected form works.
    expect(await c.canAny({ userId: "u1" }, "admin.*")).toBe(true);
    expect(await c.canAny({ userId: "u1" }, "*")).toBe(true);
  });

  it("an undeclared pattern is a typo, reported as one", async () => {
    const c = client();
    await expect(
      c.canAny({ userId: "u1" }, "ghost.thing.*" as never),
    ).rejects.toThrow(/is not in this catalog/);
  });
});

describe("the introspection paths — where runtime strings live", () => {
  it("LooseKey paths validate too: explain, grantedScopes, holds", async () => {
    const c = client();
    const runtimeTypo: string = "docs.files.raed";
    await expect(c.explain({ userId: "u1" }, runtimeTypo)).rejects.toBeInstanceOf(
      UnknownPermissionError,
    );
    await expect(
      c.grantedScopes({ userId: "u1" }, runtimeTypo),
    ).rejects.toBeInstanceOf(UnknownPermissionError);
    await expect(
      c.holds({ userId: "u1" }, runtimeTypo),
    ).rejects.toBeInstanceOf(UnknownPermissionError);
    // A real key still flows through the escape hatch.
    const realKey: string = "docs.files.read";
    expect(await c.holds({ userId: "u1" }, realKey)).toBe(true);
  });
});

describe("the snapshot enforces the same rule", () => {
  it("every synchronous shape validates before evaluating", async () => {
    const snap = await client().snapshot({ userId: "u1" });
    expect(() => snap.can("docs.files.raed" as never)).toThrow(
      UnknownPermissionError,
    );
    expect(() => snap.require("docs.files.raed" as never)).toThrow(
      UnknownPermissionError,
    );
    expect(() => snap.canAny("admin" as never)).toThrow(/Did you mean/);
    expect(() => snap.requireAny("admin" as never)).toThrow(/Did you mean/);
    expect(() => snap.holds("docs.files.raed")).toThrow(UnknownPermissionError);
    expect(() => snap.grantedScopes("docs.files.raed")).toThrow(
      UnknownPermissionError,
    );
    expect(() => snap.explain("docs.files.raed")).toThrow(
      UnknownPermissionError,
    );
    expect(snap.can("docs.files.read")).toBe(true);
  });

  it("validation precedes the active check, so inactive principals report typos too", async () => {
    const provider = wildcardHolder();
    const inactive = {
      ...provider,
      getSubjectAccess: async () => ({
        ...(await provider.getSubjectAccess({ userId: "u1" })),
        active: false,
      }),
    } as AlfizProvider;
    const snap = await createAlfizClient({ catalog, provider: inactive }).snapshot({
      userId: "u1",
    });
    // A silent `false` from inactivity must not mask a malformed check —
    // the typo is the same bug whoever is logged in.
    expect(() => snap.can("docs.files.raed" as never)).toThrow(
      UnknownPermissionError,
    );
    expect(snap.can("docs.files.read")).toBe(false);
  });
});
