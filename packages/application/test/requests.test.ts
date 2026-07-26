import { describe, expect, it } from "vitest";
import { createAlfizClient } from "@alfiz-auth/core";
import { admin, makeApp, testCatalog } from "./fixtures.js";

const seedUsers = async (app: ReturnType<typeof makeApp>["app"]) => {
  await app.setGroupMembership("requester", [], admin);
  await app.setGroupMembership("approver", [], admin);
};

describe("role-shaped requests", () => {
  it("rejects requests for non-requestable roles (nothing is requestable by default)", async () => {
    const { app } = makeApp();
    await seedUsers(app);
    const role = await app.createRole({ name: "Plain", patterns: ["docs.files.read"] }, admin);
    await expect(
      app.submitRequest({ requesterUserId: "requester", roleId: role.id }),
    ).rejects.toThrow(/not requestable/);
  });

  it("named-approver flow: submit → queue → approve → grant row with request provenance", async () => {
    const { app } = makeApp();
    await seedUsers(app);
    const ownerRole = await app.createRole({ name: "Owner", patterns: ["docs.*"] }, admin);
    await app.createGrant({ subject: "user:approver", roleId: ownerRole.id, provenance: admin });
    const requestable = await app.createRole(
      {
        name: "Reader",
        patterns: ["docs.files.read"],
        requestable: {
          prompts: [{ id: "why", label: "Why?" }],
          stages: [{ kind: "named_approvers", roleId: ownerRole.id }],
        },
      },
      admin,
    );

    await expect(
      app.submitRequest({ requesterUserId: "requester", roleId: requestable.id }),
    ).rejects.toThrow(/missing answer/);

    const request = await app.submitRequest({
      requesterUserId: "requester",
      roleId: requestable.id,
      justification: { why: "onboarding" },
    });
    expect(request.state).toBe("pending");

    // The queue serves whoever can decide the current stage.
    expect((await app.listApproverQueue("approver")).map((r) => r.id)).toEqual([request.id]);
    expect(await app.listApproverQueue("requester")).toEqual([]);

    await expect(
      app.decideRequest(request.id, { deciderUserId: "requester", decision: "approved" }),
    ).rejects.toThrow(/not an approver/);

    const decided = await app.decideRequest(request.id, {
      deciderUserId: "approver",
      decision: "approved",
    });
    expect(decided.state).toBe("approved");

    const grants = await app.listGrants({ subject: "user:requester" });
    expect(grants.length).toBe(1);
    expect(grants[0]!.roleId).toBe(requestable.id);
    expect(grants[0]!.provenance).toEqual({
      kind: "request",
      requestId: request.id,
      approvedBy: "approver",
    });

    // Approval IS the grant: the requester can() now.
    const client = createAlfizClient({ catalog: testCatalog(), provider: app });
    expect(await client.can({ userId: "requester" }, "docs.files.read")).toBe(true);
    client.close();
  });

  it("denial writes nothing", async () => {
    const { app } = makeApp();
    await seedUsers(app);
    const ownerRole = await app.createRole({ name: "Owner", patterns: ["docs.*"] }, admin);
    await app.createGrant({ subject: "user:approver", roleId: ownerRole.id, provenance: admin });
    const requestable = await app.createRole(
      {
        name: "Reader",
        patterns: ["docs.files.read"],
        requestable: { stages: [{ kind: "named_approvers", roleId: ownerRole.id }] },
      },
      admin,
    );
    const request = await app.submitRequest({
      requesterUserId: "requester",
      roleId: requestable.id,
    });
    const denied = await app.decideRequest(request.id, {
      deciderUserId: "approver",
      decision: "denied",
      note: "no",
    });
    expect(denied.state).toBe("denied");
    expect(await app.listGrants({ subject: "user:requester" })).toEqual([]);
  });

  it("auto-approval predicates settle instantly (same machinery as can())", async () => {
    const { app } = makeApp();
    const team = await app.createGroup({ name: "Team" }, admin);
    await app.setGroupMembership("requester", [team.id], admin);
    const requestable = await app.createRole(
      {
        name: "Reader",
        patterns: ["docs.files.read"],
        requestable: {
          stages: [{ kind: "auto", predicate: { type: "in_group", groupId: team.id } }],
        },
      },
      admin,
    );
    const request = await app.submitRequest({
      requesterUserId: "requester",
      roleId: requestable.id,
    });
    expect(request.state).toBe("approved");
    expect(request.decisions[0]!.decidedBy).toBe("auto");
    expect((await app.listGrants({ subject: "user:requester" })).length).toBe(1);
  });

  it("management stages resolve against the reporting tree, standalone and fully local", async () => {
    const { app } = makeApp();
    await app.setReportingEdge("requester", "jane", admin);
    await app.setReportingEdge("jane", "omar", admin);
    const requestable = await app.createRole(
      {
        name: "Elevated",
        patterns: ["docs.admin.manage_settings"],
        requestable: { stages: [{ kind: "management", layers: 2 }] },
      },
      admin,
    );
    const request = await app.submitRequest({
      requesterUserId: "requester",
      roleId: requestable.id,
    });
    // Layer 2 = skip-level manager: omar, not jane.
    expect(await app.listApproverQueue("jane")).toEqual([]);
    expect((await app.listApproverQueue("omar")).length).toBe(1);
    await app.decideRequest(request.id, { deciderUserId: "omar", decision: "approved" });
    expect((await app.listGrants({ subject: "user:requester" })).length).toBe(1);
  });

  it("admin override: alfiz_internal.requests.decide_request may decide any stage", async () => {
    const { app } = makeApp();
    await seedUsers(app);
    // The hierarchy is populated (policy creation demands it), but the
    // REQUESTER has no manager — the stage is unfillable for this request.
    await app.setReportingEdge("someone-else", "their-boss", admin);
    await app.createGrant({
      subject: "user:approver",
      pattern: "alfiz_internal.requests.decide_request",
      provenance: admin,
    });
    const requestable = await app.createRole(
      {
        name: "Reader",
        patterns: ["docs.files.read"],
        requestable: { stages: [{ kind: "management" }] },
      },
      admin,
    );
    const request = await app.submitRequest({
      requesterUserId: "requester",
      roleId: requestable.id,
    });
    expect((await app.listApproverQueue("approver")).length).toBe(1);
    const decided = await app.decideRequest(request.id, {
      deciderUserId: "approver",
      decision: "approved",
    });
    expect(decided.state).toBe("approved");
  });

  it("a human approval unlocks consecutive auto stages", async () => {
    const { app } = makeApp();
    const team = await app.createGroup({ name: "Team" }, admin);
    await app.setGroupMembership("requester", [team.id], admin);
    await app.setReportingEdge("requester", "jane", admin);
    const requestable = await app.createRole(
      {
        name: "Reader",
        patterns: ["docs.files.read"],
        requestable: {
          stages: [
            { kind: "management" },
            { kind: "auto", predicate: { type: "in_group", groupId: team.id } },
          ],
        },
      },
      admin,
    );
    const request = await app.submitRequest({
      requesterUserId: "requester",
      roleId: requestable.id,
    });
    expect(request.state).toBe("pending");
    const decided = await app.decideRequest(request.id, {
      deciderUserId: "jane",
      decision: "approved",
    });
    expect(decided.state).toBe("approved");
    expect((await app.listGrants({ subject: "user:requester" })).length).toBe(1);
  });
});

describe("scope-type (pattern) requests", () => {
  const setup = async () => {
    const made = makeApp();
    const { app } = made;
    await app.setGroupMembership("requester", [], admin);
    const ownerRole = await app.createRole({ name: "Owner", patterns: ["docs.*"] }, admin);
    await app.setGroupMembership("owner", [], admin);
    await app.createGrant({ subject: "user:owner", roleId: ownerRole.id, provenance: admin });
    // The fixture catalog's docs.folder requestability names roleId "" — a
    // placeholder; recreate the app with a catalog wired to the real role id
    // would be heavy, so instead grant the admin override to "owner".
    await app.createGrant({
      subject: "user:owner",
      pattern: "alfiz_internal.requests.decide_request",
      provenance: admin,
    });
    return made;
  };

  it("time-bound requests: expiry rides into the grant and lapses", async () => {
    const { app, advance, now } = await setup();
    const request = await app.submitRequest({
      requesterUserId: "requester",
      pattern: "docs.files.update_file",
      scope: "docs.folder:9",
      proposedExpiresAt: now() + 3600_000,
      justification: { why: "hotfix" },
    });
    await app.decideRequest(request.id, { deciderUserId: "owner", decision: "approved" });
    const client = createAlfizClient({
      catalog: testCatalog(),
      provider: app,
      subjectCacheTtlMs: 0,
      clock: now,
    });
    expect(await client.can({ userId: "requester" }, "docs.files.update_file", "docs.doc:1")).toBe(true);
    advance(3600_001);
    expect(await client.can.fresh({ userId: "requester" }, "docs.files.update_file", "docs.doc:1")).toBe(false);
    client.close();
  });

  it("enforces max duration and justification prompts from the catalog", async () => {
    const { app, now } = await setup();
    await expect(
      app.submitRequest({
        requesterUserId: "requester",
        pattern: "docs.files.read",
        scope: "docs.folder:9",
        proposedExpiresAt: now() + 30 * 24 * 3600_000, // over the 7d max
        justification: { why: "x" },
      }),
    ).rejects.toThrow(/maximum/);
    await expect(
      app.submitRequest({
        requesterUserId: "requester",
        pattern: "docs.files.read",
        scope: "docs.folder:9",
      }),
    ).rejects.toThrow(/missing answer/);
  });

  it("role requests at a scope validate grantability at submission (approval skips re-validation)", async () => {
    const { app } = await setup();
    await app.setReportingEdge("someone", "their-boss", admin);
    // A role whose only pattern is global-only (docs.admin.* declares no scopes).
    const globalOnly = await app.createRole(
      {
        name: "Settings",
        patterns: ["docs.admin.manage_settings"],
        requestable: { stages: [{ kind: "management" }] },
      },
      admin,
    );
    await expect(
      app.submitRequest({
        requesterUserId: "requester",
        roleId: globalOnly.id,
        scope: "docs.folder:9",
        justification: {},
      }),
    ).rejects.toThrow(/no pattern grantable/);
  });

  it("rejects requests at scope types that never declared requestability", async () => {
    const { app } = await setup();
    await expect(
      app.submitRequest({
        requesterUserId: "requester",
        pattern: "docs.files.read",
        scope: "docs.doc:1",
        justification: { why: "x" },
      }),
    ).rejects.toThrow(/not requestable/);
  });
});

describe("request lifecycle", () => {
  it("cancel: requester only, pending only", async () => {
    const { app } = makeApp();
    await app.setGroupMembership("requester", [], admin);
    await app.setReportingEdge("requester", "jane", admin);
    const requestable = await app.createRole(
      {
        name: "Reader",
        patterns: ["docs.files.read"],
        requestable: { stages: [{ kind: "management" }] },
      },
      admin,
    );
    const request = await app.submitRequest({
      requesterUserId: "requester",
      roleId: requestable.id,
    });
    await expect(app.cancelRequest(request.id, "someone-else")).rejects.toThrow(/requester/);
    const cancelled = await app.cancelRequest(request.id, "requester");
    expect(cancelled.state).toBe("cancelled");
    await expect(app.cancelRequest(request.id, "requester")).rejects.toMatchObject({
      code: "conflict",
    });
  });

  it("global-scope requests are org-root homed", async () => {
    const { app } = makeApp({ orgRoot: false });
    await expect(
      app.submitRequest({ requesterUserId: "requester", roleId: "any" }),
    ).rejects.toMatchObject({ code: "not_org_root" });
  });
});
