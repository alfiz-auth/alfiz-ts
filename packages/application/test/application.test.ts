import { describe, expect, it } from "vitest";
import type { InvalidationEvent } from "@alfiz/core";
import { ProviderWriteRejectedError, createAlfizClient } from "@alfiz/core";
import { admin, makeApp, testCatalog } from "./fixtures.js";

describe("getSubjectAccess", () => {
  it("computes the full closure: groups, ancestors, orgs, implicit groups, everyone", async () => {
    const { app } = makeApp();
    await app.createGroup({ name: "Staff" }, admin).then(async (staff) => {
      const teachers = await app.createGroup(
        { name: "Teachers", parents: [staff.id] },
        admin,
      );
      await app.setGroupMembership("u1", [teachers.id], admin);
      await app.setReportingEdge("u1", "jane", admin);
      await app.setReportingEdge("jane", "omar", admin);
      const data = await app.getSubjectAccess({ userId: "u1" });
      expect(data.closure).toContain("user:u1");
      expect(data.closure).toContain(`group:${teachers.id}`);
      expect(data.closure).toContain(`group:${staff.id}`);
      expect(data.closure).toContain("directs:jane");
      expect(data.closure).toContain("orgof:jane");
      expect(data.closure).toContain("orgof:omar");
      expect(data.closure).not.toContain("directs:omar");
      expect(data.closure).toContain("everyone");
      expect(data.managerChain).toEqual(["jane", "omar"]);
      expect(data.active).toBe(true);
    });
  });

  it("unknown principals are active members of `everyone` — public access reaches them", async () => {
    const { app } = makeApp();
    const data = await app.getSubjectAccess({ userId: "ghost" });
    // Deny-by-default still holds (no rows), but absence is not offboarding.
    expect(data.active).toBe(true);
    expect(data.closure).toEqual(["user:ghost", "everyone"]);
    await app.createGrant({
      subject: "everyone",
      pattern: "docs.files.read",
      scope: "docs.doc:1",
      provenance: admin,
    });
    const withPublic = await app.getSubjectAccess({ userId: "ghost" });
    expect(withPublic.grants.length).toBe(1);
  });

  it("explicitly deactivated users evaluate inactive", async () => {
    const { app, storage } = makeApp();
    await storage.upsertUser({
      userId: "gone",
      active: false,
      groupIds: [],
      orgIds: [],
      managerUserId: null,
    });
    expect((await app.getSubjectAccess({ userId: "gone" })).active).toBe(false);
  });

  it("surfaces unresolved role references instead of dropping them silently", async () => {
    const { app, storage } = makeApp();
    await app.setGroupMembership("u1", [], admin);
    await storage.insertGrant({
      id: "g1",
      subject: "user:u1",
      roleId: "ghost-role",
      scope: "*",
      provenance: { kind: "system" },
      createdAt: 0,
    });
    const data = await app.getSubjectAccess({ userId: "u1" });
    expect(data.unresolvedRoleIds).toEqual(["ghost-role"]);
  });

  it("service principals: machine closure, always active", async () => {
    const { app } = makeApp();
    await app.createGrant({
      subject: "service:cron",
      pattern: "docs.files.read",
      provenance: admin,
    });
    const data = await app.getSubjectAccess({ serviceId: "cron" });
    expect(data.userId).toBe(null);
    expect(data.closure).toContain("service:cron");
    expect(data.grants.length).toBe(1);
  });
});

describe("grant validation", () => {
  it("rejects unknown patterns, missing roles, bad scopes, past expiry", async () => {
    const { app } = makeApp();
    await expect(
      app.createGrant({ subject: "user:u1", pattern: "docs.ghost.read", provenance: admin }),
    ).rejects.toThrow(/references nothing/);
    await expect(
      app.createGrant({ subject: "user:u1", roleId: "nope", provenance: admin }),
    ).rejects.toThrow(/does not exist/);
    await expect(
      app.createGrant({
        subject: "user:u1",
        pattern: "docs.files.read",
        scope: "ghost.type:1",
        provenance: admin,
      }),
    ).rejects.toThrow(/unknown scope type/);
    await expect(
      app.createGrant({
        subject: "user:u1",
        pattern: "docs.files.delete",
        scope: "docs.doc:1", // delete is folder-only
        provenance: admin,
      }),
    ).rejects.toThrow(/not grantable/);
    await expect(
      app.createGrant({
        subject: "user:u1",
        pattern: "docs.files.read",
        expiresAt: 1, // long past
        provenance: admin,
      }),
    ).rejects.toThrow(/past/);
    await expect(
      app.createGrant({
        subject: "user:u1",
        pattern: "docs.files.read",
        roleId: "both",
        provenance: admin,
      }),
    ).rejects.toThrow(/exactly one/);
  });

  it("audits creates and deletes with provenance actors", async () => {
    const { app } = makeApp();
    const row = await app.createGrant({
      subject: "user:u1",
      pattern: "docs.files.read",
      provenance: admin,
    });
    await app.deleteGrant(row.id, admin);
    const audit = await app.listAuditEvents();
    expect(audit.map((e) => e.action)).toEqual(["grant.create", "grant.delete"]);
    expect(audit[0]!.actor).toBe("root");
  });
});

describe("org-root gating", () => {
  it("a non-root application rejects org-domain writes but accepts instance-scoped rows", async () => {
    const { app } = makeApp({ orgRoot: false });
    const reject = (p: Promise<unknown>) =>
      expect(p).rejects.toMatchObject({ code: "not_org_root" });
    await reject(app.createGrant({ subject: "user:u1", pattern: "docs.files.read", provenance: admin }));
    await reject(app.createRevoke({ userId: "u1", pattern: "docs.*", provenance: admin }));
    await reject(app.createRole({ name: "R", patterns: [] }, admin));
    await reject(app.createGroup({ name: "G" }, admin));
    await reject(app.setReportingEdge("u1", "jane", admin));
    await reject(app.setGroupMembership("u1", [], admin));

    // Instance-scoped rows are application data and stay writable.
    const scoped = await app.createGrant({
      subject: "user:u1",
      pattern: "docs.files.read",
      scope: "docs.folder:9",
      provenance: admin,
    });
    expect(scoped.scope).toBe("docs.folder:9");
    await app.deleteGrant(scoped.id, admin);
    const revoke = await app.createRevoke({
      userId: "u1",
      pattern: "docs.*",
      scope: "docs.folder:9",
      provenance: admin,
    });
    expect(revoke.scope).toBe("docs.folder:9");
    const caps = await app.capabilities();
    expect(caps.orgRoot).toBe(false);
  });

  it("non-root deletion of a global row is rejected without disturbing the row", async () => {
    const { app, storage } = makeApp({ orgRoot: false });
    // A synced global row (as the read model would hold it).
    await storage.insertGrant({
      id: "synced-1",
      subject: "user:u1",
      pattern: "docs.files.read",
      scope: "*",
      provenance: { kind: "system", note: "synced from org root" },
      createdAt: 0,
    });
    await expect(app.deleteGrant("synced-1", admin)).rejects.toMatchObject({
      code: "not_org_root",
    });
    expect((await app.listGrants({ subject: "user:u1" })).length).toBe(1);
    await storage.insertRevoke({
      id: "synced-r1",
      userId: "u1",
      pattern: "docs.*",
      scope: "*",
      provenance: { kind: "system" },
      createdAt: 0,
    });
    await expect(app.deleteRevoke("synced-r1", admin)).rejects.toMatchObject({
      code: "not_org_root",
    });
    expect((await app.listRevokes({ userId: "u1" })).length).toBe(1);
  });
});

describe("roles", () => {
  it("validates patterns and blocks deletion while assigned", async () => {
    const { app } = makeApp();
    await expect(
      app.createRole({ name: "Bad", patterns: ["docs.ghost.*"] }, admin),
    ).rejects.toThrow(/references nothing/);
    const role = await app.createRole(
      { name: "Reader", patterns: ["docs.files.read"] },
      admin,
    );
    const grant = await app.createGrant({
      subject: "user:u1",
      roleId: role.id,
      provenance: admin,
    });
    await expect(app.deleteRole(role.id, admin)).rejects.toMatchObject({
      code: "conflict",
    });
    await app.deleteGrant(grant.id, admin);
    await app.deleteRole(role.id, admin);
    expect(await app.listRoles()).toEqual([]);
  });
});

describe("group graph integrity", () => {
  it("rejects cycles with the full path named", async () => {
    const { app } = makeApp();
    const a = await app.createGroup({ name: "A" }, admin);
    const b = await app.createGroup({ name: "B", parents: [a.id] }, admin);
    const c = await app.createGroup({ name: "C", parents: [b.id] }, admin);
    try {
      await app.setGroupParents(a.id, [c.id], admin);
      expect.unreachable("cycle should reject");
    } catch (err) {
      expect(err).toBeInstanceOf(ProviderWriteRejectedError);
      expect((err as ProviderWriteRejectedError).code).toBe("graph_cycle");
      expect((err as Error).message).toMatch(/→/);
    }
  });

  it("deleting a group cleans membership, parent refs, and subject rows", async () => {
    const { app, storage } = makeApp();
    const parent = await app.createGroup({ name: "P" }, admin);
    const child = await app.createGroup({ name: "C", parents: [parent.id] }, admin);
    await app.setGroupMembership("u1", [parent.id], admin);
    await app.createGrant({
      subject: `group:${parent.id}`,
      pattern: "docs.files.read",
      provenance: admin,
    });
    await app.deleteGroup(parent.id, admin);
    expect((await storage.getUser("u1"))!.groupIds).toEqual([]);
    expect((await app.listGroups()).find((g) => g.id === child.id)!.parents).toEqual([]);
    expect(await app.listGrants({ subject: `group:${parent.id}` })).toEqual([]);
  });
});

describe("reporting edges", () => {
  it("rejects reporting cycles", async () => {
    const { app } = makeApp();
    await app.setReportingEdge("a", "b", admin);
    await app.setReportingEdge("b", "c", admin);
    await expect(app.setReportingEdge("c", "a", admin)).rejects.toMatchObject({
      code: "graph_cycle",
    });
    await expect(app.setReportingEdge("a", "a", admin)).rejects.toMatchObject({
      code: "graph_cycle",
    });
  });

  it("reporting capability reflects populated edges", async () => {
    const { app } = makeApp();
    expect((await app.capabilities()).reporting).toBe(false);
    await app.setReportingEdge("a", "b", admin);
    expect((await app.capabilities()).reporting).toBe(true);
  });
});

describe("virtual parent dissolution", () => {
  it("copies grants down with provenance, rewires children, removes the parent", async () => {
    const { app } = makeApp();
    const grandparent = await app.createGroup({ name: "GP" }, admin);
    const vp = await app.createGroup({ name: "Pool", parents: [grandparent.id] }, admin);
    const a = await app.createGroup({ name: "A", parents: [vp.id] }, admin);
    const b = await app.createGroup({ name: "B", parents: [vp.id] }, admin);
    const original = await app.createGrant({
      subject: `group:${vp.id}`,
      pattern: "docs.files.read",
      provenance: admin,
    });
    await app.dissolveVirtualParent(vp.id, admin);

    const groups = await app.listGroups();
    expect(groups.find((g) => g.id === vp.id)).toBeUndefined();
    expect(groups.find((g) => g.id === a.id)!.parents).toEqual([grandparent.id]);
    const aGrants = await app.listGrants({ subject: `group:${a.id}` });
    const bGrants = await app.listGrants({ subject: `group:${b.id}` });
    expect(aGrants.length).toBe(1);
    expect(bGrants.length).toBe(1);
    expect(aGrants[0]!.provenance).toEqual({
      kind: "dissolution",
      virtualParentId: vp.id,
      originalGrantId: original.id,
    });
    expect(await app.listGrants({ subject: `group:${vp.id}` })).toEqual([]);
    // The audit trail answers "why do both groups hold docs.files.read?"
    const audit = await app.listAuditEvents();
    expect(audit.some((e) => e.action === "group.dissolve_virtual_parent")).toBe(true);
  });
});

describe("catalog publish", () => {
  it("versions monotonically and audits", async () => {
    const { app } = makeApp();
    const doc = testCatalog().toDocument();
    expect(await app.publishCatalog(doc, admin)).toEqual({ version: 1 });
    expect(await app.publishCatalog(doc, admin)).toEqual({ version: 2 });
    expect((await app.getPublishedCatalog())!.version).toBe(2);
  });
});

describe("application + client end-to-end", () => {
  it("grants flow through the client with event-driven invalidation", async () => {
    const { app } = makeApp();
    const client = createAlfizClient({ catalog: testCatalog(), provider: app });
    await app.setGroupMembership("u1", [], admin);

    expect(await client.can({ userId: "u1" }, "docs.files.read")).toBe(false);
    const teachers = await app.createGroup({ name: "Teachers" }, admin);
    await app.createGrant({
      subject: `group:${teachers.id}`,
      pattern: "docs.files.*",
      provenance: admin,
    });
    // u1 is not a member yet.
    expect(await client.can({ userId: "u1" }, "docs.files.read")).toBe(false);
    // Membership write emits a user event; no TTL wait needed.
    await app.setGroupMembership("u1", [teachers.id], admin);
    expect(await client.can({ userId: "u1" }, "docs.files.read")).toBe(true);
    expect(await client.can({ userId: "u1" }, "docs.files.update_file", "docs.doc:1")).toBe(true);
    // Personal revoke wins over the group wildcard.
    await app.createRevoke({ userId: "u1", pattern: "docs.files.update_file", provenance: admin });
    expect(await client.can({ userId: "u1" }, "docs.files.update_file", "docs.doc:1")).toBe(false);
    expect(await client.can({ userId: "u1" }, "docs.files.read")).toBe(true);
    client.close();
  });

  it("invalidation events observed by the client", async () => {
    const { app } = makeApp();
    const events: InvalidationEvent[] = [];
    const off = app.onInvalidate((e) => events.push(e));
    await app.setGroupMembership("u1", [], admin);
    await app.createGrant({ subject: "user:u1", pattern: "docs.files.read", provenance: admin });
    off();
    expect(events.some((e) => e.type === "user" && e.userId === "u1")).toBe(true);
    expect(events.some((e) => e.type === "subject" && e.subject === "user:u1")).toBe(true);
  });
});
