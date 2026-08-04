import { describe, expect, it } from "vitest";
import type { GrantRow } from "../src/access.js";
import { defineCatalog } from "../src/catalog.js";
import { createAlfizClient } from "../src/client.js";
import { MissingConditionError } from "../src/errors.js";
import type {
  AlfizProvider,
  InvalidationListener,
  SubjectAccessData,
} from "../src/provider.js";

const catalog = defineCatalog({
  namespaces: ["exp"],
  includeAlfizInternal: false,
  permissions: {
    "exp.claims.read": {},
    "exp.claims.approve_claim": { requiresCondition: true },
  },
});

const grant = (pattern: string): GrantRow => ({
  id: `g:${pattern}`,
  subject: "user:u1",
  pattern,
  scope: "*",
  provenance: { kind: "admin", actorUserId: "root" },
  createdAt: 1,
});

function makeProvider(): AlfizProvider {
  return {
    getSubjectAccess: async (principal: {
      userId?: string;
    }): Promise<SubjectAccessData> => ({
      userId: principal.userId ?? null,
      closure: [`user:${principal.userId}`, "everyone"],
      grants: [grant("exp.claims.read"), grant("exp.claims.approve_claim")],
      revokes: [],
      roles: [],
      managerChain: [],
      unresolvedRoleIds: [],
      active: true,
    }),
    resolveAncestors: () => ["*"],
    onInvalidate: (_listener: InvalidationListener) => () => {},
  } as unknown as AlfizProvider;
}

const makeClient = () =>
  createAlfizClient({ catalog, provider: makeProvider() });

describe("the condition seam (requiresCondition)", () => {
  it("a gate without the declared condition throws a programming error", async () => {
    const client = makeClient();
    await expect(
      client.can({ userId: "u1" }, "exp.claims.approve_claim"),
    ).rejects.toThrow(MissingConditionError);
    await expect(
      client.require({ userId: "u1" }, "exp.claims.approve_claim"),
    ).rejects.toThrow(MissingConditionError);
    client.close();
  });

  it("the condition is the final AND of the decision", async () => {
    const client = makeClient();
    expect(
      await client.can({ userId: "u1" }, "exp.claims.approve_claim", undefined, {
        condition: () => 500 < 10_000,
      }),
    ).toBe(true);
    expect(
      await client.can({ userId: "u1" }, "exp.claims.approve_claim", undefined, {
        condition: () => 50_000 < 10_000,
      }),
    ).toBe(false);
    client.close();
  });

  it("async conditions are awaited on the async surface", async () => {
    const client = makeClient();
    expect(
      await client.can({ userId: "u1" }, "exp.claims.approve_claim", undefined, {
        condition: async () => true,
      }),
    ).toBe(true);
    client.close();
  });

  it("the condition never runs when the rows already deny", async () => {
    const client = makeClient();
    let ran = false;
    expect(
      await client.can({ userId: "nobody" }, "exp.claims.approve_claim", undefined, {
        condition: () => {
          ran = true;
          return true;
        },
      }),
    ).toBe(false);
    expect(ran).toBe(false);
    client.close();
  });

  it("keys without the declaration are unaffected, and may still opt in", async () => {
    const client = makeClient();
    expect(await client.can({ userId: "u1" }, "exp.claims.read")).toBe(true);
    expect(
      await client.can({ userId: "u1" }, "exp.claims.read", undefined, {
        condition: () => false,
      }),
    ).toBe(false);
    client.close();
  });

  it("snapshot: sync condition works; a Promise-returning one throws; a missing one throws", async () => {
    const client = makeClient();
    const snap = await client.snapshot({ userId: "u1" });
    expect(() => snap.can("exp.claims.approve_claim")).toThrow(
      MissingConditionError,
    );
    expect(
      snap.can("exp.claims.approve_claim", undefined, { condition: () => true }),
    ).toBe(true);
    expect(
      snap.can("exp.claims.approve_claim", undefined, { condition: () => false }),
    ).toBe(false);
    expect(() =>
      snap.can("exp.claims.approve_claim", undefined, {
        condition: (() => Promise.resolve(true)) as unknown as () => boolean,
      }),
    ).toThrow(/synchronous/);
    client.close();
  });

  it("visibility shapes ignore the declaration", async () => {
    const client = makeClient();
    expect(await client.canAny({ userId: "u1" }, "exp.claims.*")).toBe(true);
    expect(await client.holds({ userId: "u1" }, "exp.claims.approve_claim")).toBe(
      true,
    );
    client.close();
  });
});
