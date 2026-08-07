/**
 * Implicit imports: `can()` for a permission in a namespace the catalog
 * neither owns nor imports.
 *
 * The whole feature is a widening of the guard `unknown-permission.test.ts`
 * pins, so the first thing tested here is what does NOT widen. Two closures
 * stay shut whatever the policy says (an owned namespace, and an enumerated
 * import), and one evaluation rule stops the widening from reopening the
 * hole the guard exists for: a bare `*` never confers a permission no
 * catalog declares.
 */

import { describe, expect, it, vi } from "vitest";
import type { GrantRow } from "../src/access.js";
import type { CatalogDocument } from "../src/catalog.js";
import { defineCatalog } from "../src/catalog.js";
import { createAlfizClient } from "../src/client.js";
import { UnknownPermissionError } from "../src/errors.js";
import type { AlfizProvider, SubjectAccessData } from "../src/provider.js";

const zoomDocument: CatalogDocument = defineCatalog({
  namespaces: ["zoom"],
  includeAlfizInternal: false,
  conventions: { depth: "any" },
  permissions: { "zoom.host": true, "zoom.meetings.read": true },
}).toDocument();

const catalog = defineCatalog({
  namespaces: ["docs"],
  includeAlfizInternal: false,
  permissions: { "docs.files.read": true },
});

const enumeratedCatalog = defineCatalog({
  namespaces: ["docs"],
  includeAlfizInternal: false,
  permissions: { "docs.files.read": true },
  imports: {
    zoom: { document: zoomDocument, permissions: { "zoom.host": true } },
  },
});

/** A principal holding one grant — the pattern under test. */
const holder = (pattern: string): AlfizProvider => {
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

describe('externalPermissions: "error" (the default)', () => {
  it("throws for a foreign namespace, exactly as before", async () => {
    const client = createAlfizClient({ catalog, provider: holder("*") });
    await expect(client.can({ userId: "u1" }, "zoom.host")).rejects.toBeInstanceOf(
      UnknownPermissionError,
    );
  });

  it("names the fix in the message", async () => {
    const client = createAlfizClient({ catalog, provider: holder("*") });
    const error = await client
      .can({ userId: "u1" }, "zoom.host")
      .catch((e: unknown) => e as UnknownPermissionError);
    expect(error).toBeInstanceOf(UnknownPermissionError);
    expect((error as UnknownPermissionError).namespaceOrigin).toBe("foreign");
    expect((error as UnknownPermissionError).isForeignNamespace).toBe(true);
    expect((error as UnknownPermissionError).message).toMatch(
      /neither owns nor imports/,
    );
    expect((error as UnknownPermissionError).message).toMatch(/`imports`/);
  });
});

describe('externalPermissions: "allow" / "warn"', () => {
  const permissive = (
    mode: "allow" | "warn",
    pattern: string,
    onExternalPermission?: (info: unknown) => void,
  ) =>
    createAlfizClient({
      catalog,
      provider: holder(pattern),
      externalPermissions: mode,
      ...(onExternalPermission
        ? { onExternalPermission: onExternalPermission as never }
        : {}),
    });

  it("evaluates a foreign key against a namespace-anchored grant", async () => {
    const client = permissive("allow", "zoom.*");
    expect(await client.can({ userId: "u1" }, "zoom.host")).toBe(true);
  });

  it("DENIES the same key to a holder of the bare global wildcard", async () => {
    // The rule that makes this policy safe. `*` means "everything in the
    // declared vocabulary", and a policy-admitted key is outside it — so a
    // typo cannot pass for exactly the broadly-privileged users who review
    // and test the gate.
    const client = permissive("allow", "*");
    expect(await client.can({ userId: "u1" }, "zoom.host")).toBe(false);
  });

  it("keeps the bare wildcard working for everything the catalog declares", async () => {
    const client = permissive("allow", "*");
    expect(await client.can({ userId: "u1" }, "docs.files.read")).toBe(true);
  });

  it("still throws for a typo in an OWNED namespace", async () => {
    // An owned catalog is enumerable, so an unknown key in it is
    // unambiguously a bug this codebase can fix.
    const client = permissive("allow", "*");
    await expect(
      client.can({ userId: "u1" }, "docs.files.raed"),
    ).rejects.toBeInstanceOf(UnknownPermissionError);
  });

  it("still throws for a key outside an ENUMERATED import", async () => {
    // The return on committing the document: the catalog knows zoom's keys,
    // so it can tell you this one is not among them.
    const client = createAlfizClient({
      catalog: enumeratedCatalog,
      provider: holder("*"),
      externalPermissions: "allow",
    });
    const error = await client
      .can({ userId: "u1" }, "zoom.meetings.read")
      .catch((e: unknown) => e as UnknownPermissionError);
    expect(error).toBeInstanceOf(UnknownPermissionError);
    expect((error as UnknownPermissionError).namespaceOrigin).toBe("imported");
    expect((error as UnknownPermissionError).importedPatterns).toEqual([
      "zoom.host",
    ]);
    expect((error as UnknownPermissionError).message).toMatch(
      /not covered by this catalog's import/,
    );
  });

  it("reports once per distinct permission, not once per call", async () => {
    const seen: Array<Record<string, unknown>> = [];
    const client = permissive("warn", "zoom.*", (info) =>
      seen.push(info as Record<string, unknown>),
    );
    await client.can({ userId: "u1" }, "zoom.host");
    await client.can({ userId: "u1" }, "zoom.host");
    await client.can({ userId: "u1" }, "zoom.other");
    expect(seen).toEqual([
      { permission: "zoom.host", expected: "key", namespace: "zoom", shape: "can" },
      { permission: "zoom.other", expected: "key", namespace: "zoom", shape: "can" },
    ]);
  });

  it('says nothing under "allow"', async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const client = permissive("allow", "zoom.*");
    await client.can({ userId: "u1" }, "zoom.host");
    expect(warn).not.toHaveBeenCalled();
    warn.mockRestore();
  });

  it("falls back to console.warn with the declaration to paste", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const client = permissive("warn", "zoom.*");
    await client.can({ userId: "u1" }, "zoom.host");
    expect(warn).toHaveBeenCalledTimes(1);
    // The namespace is quoted like every other echoed runtime string — the
    // snippet stays pasteable, and a namespace carrying a newline or an ANSI
    // escape cannot forge a second log line on its way to a shared sink.
    expect(String(warn.mock.calls[0]?.[0])).toMatch(/imports: \{ "zoom":/);
    warn.mockRestore();
  });
});

describe("the policy holds on every surface", () => {
  it("applies to canAny, require, holds, explain, and grantedScopes", async () => {
    const strict = createAlfizClient({ catalog, provider: holder("*") });
    const principal = { userId: "u1" };
    await expect(strict.canAny({ ...principal }, "zoom.*")).rejects.toBeInstanceOf(
      UnknownPermissionError,
    );
    await expect(strict.require(principal, "zoom.host")).rejects.toBeInstanceOf(
      UnknownPermissionError,
    );
    await expect(strict.holds(principal, "zoom.host")).rejects.toBeInstanceOf(
      UnknownPermissionError,
    );
    await expect(strict.explain(principal, "zoom.host")).rejects.toBeInstanceOf(
      UnknownPermissionError,
    );
    await expect(
      strict.grantedScopes(principal, "zoom.host"),
    ).rejects.toBeInstanceOf(UnknownPermissionError);
  });

  it("is inherited by the synchronous snapshot", async () => {
    // One name per question, same behavior on every surface: if the async
    // `can` admits it, the sync one must too.
    const permissive = createAlfizClient({
      catalog,
      provider: holder("zoom.*"),
      externalPermissions: "allow",
    });
    const snap = await permissive.snapshot({ userId: "u1" });
    expect(snap.can("zoom.host")).toBe(true);
    expect(() => snap.can("docs.files.raed")).toThrow(UnknownPermissionError);

    const strict = createAlfizClient({ catalog, provider: holder("zoom.*") });
    const strictSnap = await strict.snapshot({ userId: "u1" });
    expect(() => strictSnap.can("zoom.host")).toThrow(UnknownPermissionError);
  });

  it("denies a snapshot check for a bare-wildcard holder too", async () => {
    const client = createAlfizClient({
      catalog,
      provider: holder("*"),
      externalPermissions: "allow",
    });
    const snap = await client.snapshot({ userId: "u1" });
    expect(snap.can("zoom.host")).toBe(false);
    expect(snap.holds("zoom.host")).toBe(false);
  });
});

describe("canAny over an OPEN region", () => {
  // The failure this branch exists to prevent: an open region enumerates no
  // concrete keys, so a `canAny` driven purely by key expansion answers a
  // confident `false` — a whole nav section vanishing with no error to
  // search for.
  const regionCatalog = defineCatalog({
    namespaces: ["docs"],
    includeAlfizInternal: false,
    permissions: { "docs.files.read": true },
    imports: { zoom: { permissions: { "zoom.meetings.*": true } } },
  });

  const withRows = (
    grants: readonly { pattern: string; scope?: string }[],
    revokes: readonly { pattern: string; scope?: string }[] = [],
  ): AlfizProvider =>
    ({
      getSubjectAccess: async (): Promise<SubjectAccessData> => ({
        userId: "u1",
        closure: ["user:u1", "everyone"],
        grants: grants.map((g, i) => ({
          id: `g${i}`,
          subject: "user:u1",
          pattern: g.pattern,
          scope: g.scope ?? "*",
          provenance: { kind: "admin", actorUserId: "root" },
          createdAt: 0,
        })) as GrantRow[],
        revokes: revokes.map((r, i) => ({
          id: `r${i}`,
          userId: "u1",
          pattern: r.pattern,
          scope: r.scope ?? "*",
          provenance: { kind: "admin", actorUserId: "root" },
          createdAt: 0,
        })) as never,
        roles: [],
        managerChain: [],
        unresolvedRoleIds: [],
        active: true,
      }),
      resolveAncestors: () => ["*"],
      onInvalidate: () => () => {},
    }) as unknown as AlfizProvider;

  it("is TRUE when a grant reaches the region, despite there being no keys", async () => {
    const client = createAlfizClient({
      catalog: regionCatalog,
      provider: withRows([{ pattern: "zoom.meetings.*" }]),
    });
    expect(await client.canAny({ userId: "u1" }, "zoom.meetings.*")).toBe(true);
    expect(regionCatalog.keysMatching("zoom.meetings.*")).toEqual([]);
  });

  it("is false when no grant reaches it", async () => {
    const client = createAlfizClient({
      catalog: regionCatalog,
      provider: withRows([{ pattern: "docs.files.read" }]),
    });
    expect(await client.canAny({ userId: "u1" }, "zoom.meetings.*")).toBe(false);
  });

  it("suppresses conservatively — a revoke overlapping any part wins", async () => {
    // Fail-closed, and the one behavior difference between an enumerated
    // import and an open one. Documented rather than silently surprising.
    const client = createAlfizClient({
      catalog: regionCatalog,
      provider: withRows(
        [{ pattern: "zoom.meetings.*" }],
        [{ pattern: "zoom.meetings.delete" }],
      ),
    });
    expect(await client.canAny({ userId: "u1" }, "zoom.meetings.*")).toBe(false);
  });

  it("holds on the synchronous snapshot too", async () => {
    const client = createAlfizClient({
      catalog: regionCatalog,
      provider: withRows([{ pattern: "zoom.meetings.*" }]),
    });
    const snap = await client.snapshot({ userId: "u1" });
    expect(snap.canAny("zoom.meetings.*")).toBe(true);
  });
});

describe("observability", () => {
  it("marks an admitted permission so it can be counted and migrated", async () => {
    const observed: Array<Record<string, unknown>> = [];
    const client = createAlfizClient({
      catalog,
      provider: holder("zoom.*"),
      externalPermissions: "allow",
      metrics: {
        observer: (o) => observed.push(o as unknown as Record<string, unknown>),
      },
    });
    await client.can({ userId: "u1" }, "zoom.host");
    await client.can({ userId: "u1" }, "docs.files.read");
    expect(observed.map((o) => o.externalPermission)).toEqual([true, undefined]);
  });

  it("does not mark a legitimate wildcard pattern as external", async () => {
    const observed: Array<Record<string, unknown>> = [];
    const client = createAlfizClient({
      catalog,
      provider: holder("docs.*"),
      metrics: {
        observer: (o) => observed.push(o as unknown as Record<string, unknown>),
      },
    });
    await client.canAny({ userId: "u1" }, "docs.*");
    expect(observed[0]?.externalPermission).toBeUndefined();
  });
});
