/**
 * Regressions for the adversarial-review findings: each test pins the fix
 * for one confirmed defect. Titles reference the finding, not the mechanism.
 */

import { describe, expect, it } from "vitest";
import { createAlfizClient, findCycle } from "@alfiz/core";
import { admin, makeApp, testCatalog } from "./fixtures.js";

describe("scope invalidation (critical): moves propagate to cached checks", () => {
  it("notifyScopeMoved busts cached ancestor chains immediately", async () => {
    const parents = new Map<string, string>([
      ["docs.doc:m1", "docs.folder:open"],
    ]);
    const { app } = makeApp({
      ancestry: (scope: string) => {
        const chain: string[] = [];
        let current = parents.get(scope);
        while (current !== undefined) {
          chain.push(current);
          current = parents.get(current);
        }
        return chain;
      },
    });
    const client = createAlfizClient({ catalog: testCatalog(), provider: app });
    await app.createGrant({
      subject: "user:u1",
      pattern: "docs.files.read",
      scope: "docs.folder:open",
      provenance: admin,
    });
    expect(await client.can({ userId: "u1" }, "docs.files.read", "docs.doc:m1")).toBe(true);
    // The HOST app moves the doc into a folder the user cannot see…
    parents.set("docs.doc:m1", "docs.folder:restricted");
    // …and reports the move. The cached chain busts at once.
    app.notifyScopeMoved("docs.doc:m1");
    expect(await client.can({ userId: "u1" }, "docs.files.read", "docs.doc:m1")).toBe(false);
    client.close();
  });

  it("without a move report, the object-chain TTL bounds the staleness", async () => {
    const parents = new Map<string, string>([["docs.doc:t1", "docs.folder:open"]]);
    const { app } = makeApp({
      ancestry: (scope: string) => {
        const chain: string[] = [];
        let current = parents.get(scope);
        while (current !== undefined) {
          chain.push(current);
          current = parents.get(current);
        }
        return chain;
      },
    });
    let now = 1_000_000;
    const client = createAlfizClient({
      catalog: testCatalog(),
      provider: app,
      clock: () => now,
      objectCacheTtlMs: 60_000,
      subjectCacheTtlMs: 0,
    });
    await app.createGrant({
      subject: "user:u1",
      pattern: "docs.files.read",
      scope: "docs.folder:open",
      provenance: admin,
    });
    expect(await client.can({ userId: "u1" }, "docs.files.read", "docs.doc:t1")).toBe(true);
    parents.set("docs.doc:t1", "docs.folder:restricted");
    // Unreported move: still cached within the TTL…
    expect(await client.can({ userId: "u1" }, "docs.files.read", "docs.doc:t1")).toBe(true);
    // …but never beyond it.
    now += 60_001;
    expect(await client.can({ userId: "u1" }, "docs.files.read", "docs.doc:t1")).toBe(false);
    client.close();
  });
});

describe("scope-type system at check time", () => {
  it("a wildcard grant at a scope confers only keys grantable at that scope type", async () => {
    const { app } = makeApp();
    const client = createAlfizClient({
      catalog: testCatalog(),
      provider: app,
      subjectCacheTtlMs: 0,
    });
    // docs.files.* at a doc: read/update declare docs.doc; delete is folder-only.
    await app.createGrant({
      subject: "user:u1",
      pattern: "docs.files.*",
      scope: "docs.doc:1",
      provenance: admin,
    });
    expect(await client.can({ userId: "u1" }, "docs.files.read", "docs.doc:1")).toBe(true);
    expect(await client.can({ userId: "u1" }, "docs.files.update_file", "docs.doc:1")).toBe(true);
    // The folder-only destructive key does NOT escape through the wildcard.
    expect(await client.can({ userId: "u1" }, "docs.files.delete", "docs.doc:1")).toBe(false);
    client.close();
  });
});

describe("request-decision integrity", () => {
  const requestableRole = async (app: ReturnType<typeof makeApp>["app"]) => {
    const owner = await app.createRole({ name: "Owner", patterns: ["docs.*"] }, admin);
    await app.createGrant({ subject: "user:approver", roleId: owner.id, provenance: admin });
    return app.createRole(
      {
        name: "Reader",
        patterns: ["docs.files.read"],
        requestable: { stages: [{ kind: "named_approvers", roleId: owner.id }] },
      },
      admin,
    );
  };

  it("concurrent decisions serialize: a denial is never overwritten, grants never duplicate", async () => {
    const { app } = makeApp();
    const role = await requestableRole(app);
    const request = await app.submitRequest({
      requesterUserId: "requester",
      roleId: role.id,
    });
    const results = await Promise.allSettled([
      app.decideRequest(request.id, { deciderUserId: "approver", decision: "denied" }),
      app.decideRequest(request.id, { deciderUserId: "approver", decision: "approved" }),
    ]);
    const fulfilled = results.filter((r) => r.status === "fulfilled");
    const rejected = results.filter((r) => r.status === "rejected");
    expect(fulfilled.length).toBe(1);
    expect(rejected.length).toBe(1);
    // The first decision (denial) stands; nothing was granted.
    const settled = await app.listRequests();
    expect(settled[0]!.state).toBe("denied");
    expect(await app.listGrants({ subject: "user:requester" })).toEqual([]);
  });

  it("a non-root application refuses to decide a (synced) global-scope request", async () => {
    const { app, storage } = makeApp({ orgRoot: false });
    await storage.insertRequest({
      id: "synced-req",
      requesterUserId: "requester",
      pattern: "docs.files.read",
      scope: "*",
      justification: {},
      state: "pending",
      stageIndex: 0,
      stages: [{ kind: "named_approvers", roleId: "any" }],
      decisions: [],
      createdAt: 0,
    });
    await expect(
      app.decideRequest("synced-req", { deciderUserId: "approver", decision: "approved" }),
    ).rejects.toMatchObject({ code: "not_org_root" });
  });

  it("approving a request whose role was deleted refuses instead of writing a dangling grant", async () => {
    const { app, storage } = makeApp();
    const role = await requestableRole(app);
    const request = await app.submitRequest({
      requesterUserId: "requester",
      roleId: role.id,
    });
    await storage.deleteRole(role.id); // bypass the guarded path deliberately
    await expect(
      app.decideRequest(request.id, { deciderUserId: "approver", decision: "approved" }),
    ).rejects.toMatchObject({ code: "conflict" });
    expect(await app.listGrants({ subject: "user:requester" })).toEqual([]);
  });

  it("deleteRole refuses while pending requests reference the role", async () => {
    const { app } = makeApp();
    const role = await requestableRole(app);
    await app.submitRequest({ requesterUserId: "requester", roleId: role.id });
    await expect(app.deleteRole(role.id, admin)).rejects.toThrow(/pending request/);
  });

  it("a max-duration policy caps open-ended requests: omitting the expiry does not evade it", async () => {
    const { app, now } = makeApp();
    await app.setReportingEdge("requester", "jane", admin);
    const role = await app.createRole(
      {
        name: "Capped",
        patterns: ["docs.files.read"],
        requestable: {
          maxDurationMs: 3600_000,
          stages: [{ kind: "management" }],
        },
      },
      admin,
    );
    const request = await app.submitRequest({
      requesterUserId: "requester",
      roleId: role.id,
    });
    expect(request.proposedExpiresAt).toBe(now() + 3600_000);
    await app.decideRequest(request.id, { deciderUserId: "jane", decision: "approved" });
    const [grant] = await app.listGrants({ subject: "user:requester" });
    expect(grant!.expiresAt).toBe(now() + 3600_000);
  });

  it("past proposed expiries are rejected at submission", async () => {
    const { app, now } = makeApp();
    await app.setReportingEdge("requester", "jane", admin);
    const role = await app.createRole(
      {
        name: "R",
        patterns: ["docs.files.read"],
        requestable: { stages: [{ kind: "management" }] },
      },
      admin,
    );
    await expect(
      app.submitRequest({
        requesterUserId: "requester",
        roleId: role.id,
        proposedExpiresAt: now() - 1,
      }),
    ).rejects.toThrow(/past/);
  });
});

describe("policy resolvability at creation (§9.3)", () => {
  it("management stages without a populated hierarchy are a creation-time error", async () => {
    const { app } = makeApp();
    await expect(
      app.createRole(
        {
          name: "R",
          patterns: ["docs.files.read"],
          requestable: { stages: [{ kind: "management" }] },
        },
        admin,
      ),
    ).rejects.toThrow(/no reporting hierarchy/);
  });

  it("empty stage lists and layers < 1 are rejected", async () => {
    const { app } = makeApp();
    await expect(
      app.createRole(
        { name: "R", patterns: ["docs.files.read"], requestable: { stages: [] } },
        admin,
      ),
    ).rejects.toThrow(/at least one approval stage/);
    await app.setReportingEdge("a", "b", admin);
    await expect(
      app.createRole(
        {
          name: "R",
          patterns: ["docs.files.read"],
          requestable: { stages: [{ kind: "management", layers: 0 }] },
        },
        admin,
      ),
    ).rejects.toThrow(/at least 1/);
  });
});

describe("revoke hygiene", () => {
  it("a typo'd revoke is rejected instead of silently failing open", async () => {
    const { app } = makeApp();
    await expect(
      app.createRevoke({ userId: "u1", pattern: "docs.fles.*", provenance: admin }),
    ).rejects.toThrow(/references nothing/);
    await expect(
      app.createRevoke({ userId: "u1", pattern: "docs.files.raed", provenance: admin }),
    ).rejects.toThrow(/references nothing/);
  });
});

describe("directory import against pre-existing data", () => {
  it("a snapshot closing a cycle THROUGH stored parentage condenses instead of storing a cycle", async () => {
    const { app } = makeApp();
    const a = await app.createGroup({ name: "A" }, admin);
    const b = await app.createGroup({ name: "B", parents: [a.id] }, admin);
    // Snapshot alone is acyclic; merged with stored b→a it closes a loop.
    const result = await app.importDirectory(
      { groups: [{ id: a.id, name: "A", parents: [b.id] }] },
      "entra",
    );
    expect(result.virtualParents.length).toBe(1);
    const stored = new Map(
      (await app.listGroups()).map((g) => [g.id, g.parents as readonly string[]]),
    );
    expect(findCycle(stored)).toBe(null);
    // Group-parent edits still work afterwards (nothing is bricked).
    const c = await app.createGroup({ name: "C" }, admin);
    await app.setGroupParents(c.id, [result.virtualParents[0]!.id], admin);
  });

  it("a snapshot reporting edge closing a loop through stored edges is skipped", async () => {
    const { app } = makeApp();
    await app.setReportingEdge("a", "b", admin);
    const result = await app.importDirectory({ reportingEdges: { b: "a" } }, "okta");
    expect(result.warnings.some((w) => /reporting cycle/.test(w))).toBe(true);
    expect((await app.getReportingEdges()).get("b")).toBeUndefined();
  });
});

describe("holds_pattern end-to-end respects revokes", () => {
  it("a fully revoked requester never auto-approves", async () => {
    const { app } = makeApp();
    await app.setGroupMembership("requester", [], admin);
    await app.createGrant({
      subject: "user:requester",
      pattern: "docs.files.read",
      provenance: admin,
    });
    await app.createRevoke({ userId: "requester", pattern: "*", provenance: admin });
    const role = await app.createRole(
      {
        name: "Elevated",
        patterns: ["docs.admin.manage_settings"],
        requestable: {
          stages: [
            { kind: "auto", predicate: { type: "holds_pattern", pattern: "docs.*" } },
          ],
        },
      },
      admin,
    );
    const request = await app.submitRequest({
      requesterUserId: "requester",
      roleId: role.id,
    });
    expect(request.state).toBe("pending"); // the auto stage abstained
    expect(await app.listGrants({ subject: "user:requester", scope: "*" })).toHaveLength(1); // only the original
  });
});

describe("dissolution and membership hygiene", () => {
  it("dissolving a virtual parent clears direct memberships and audits the removed grants", async () => {
    const { app, storage } = makeApp();
    const vp = await app.createGroup({ name: "Pool" }, admin);
    await app.createGroup({ name: "Child", parents: [vp.id] }, admin);
    await app.setGroupMembership("direct-member", [vp.id], admin);
    await app.createGrant({
      subject: `group:${vp.id}`,
      pattern: "docs.files.read",
      provenance: admin,
    });
    await app.dissolveVirtualParent(vp.id, admin);
    expect((await storage.getUser("direct-member"))!.groupIds).toEqual([]);
    const audit = await app.listAuditEvents();
    expect(
      audit.some(
        (e) =>
          e.action === "grant.delete" &&
          typeof e.detail === "object" &&
          e.detail !== null &&
          (e.detail as { reason?: string }).reason === "virtual parent dissolved",
      ),
    ).toBe(true);
  });
});
