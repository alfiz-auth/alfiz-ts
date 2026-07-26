/**
 * The write APIs a real migration and a real admin surface need: bulk grant
 * writes, caller-supplied ids, group renames, the active flag, and — the
 * security-shaped pair — subject and scope deletion. Grants key on subject
 * and scope STRINGS: without the deletion discipline, a deleted principal's
 * rows survive and a reused id inherits them.
 */

import { describe, expect, it } from "vitest";
import type { InvalidationEvent } from "@alfiz-auth/core";
import { admin, makeApp } from "./fixtures.js";

const collectEvents = (app: { onInvalidate: (l: (e: InvalidationEvent) => void) => () => void }) => {
  const events: InvalidationEvent[] = [];
  app.onInvalidate((e) => events.push(e));
  return events;
};

describe("createGrants (bulk)", () => {
  it("writes all rows with one audit entry and one event per distinct subject", async () => {
    const { app } = makeApp();
    const events = collectEvents(app);
    const rows = await app.createGrants(
      [
        { subject: "user:u1", pattern: "docs.files.read", scope: "docs.folder:9" },
        { subject: "user:u1", pattern: "docs.files.update_file", scope: "docs.folder:9" },
        { subject: "group:staff", pattern: "docs.admin.read" },
      ],
      { kind: "import", source: "garden-migration" },
    );
    expect(rows.length).toBe(3);
    expect((await app.listGrants({ subject: "user:u1" })).length).toBe(2);

    const audit = await app.listAuditEvents();
    const bulk = audit.filter((e) => e.action === "grant.create_bulk");
    expect(bulk.length).toBe(1);
    expect(bulk[0]!.detail).toMatchObject({ count: 3 });
    expect(audit.filter((e) => e.action === "grant.create").length).toBe(0);

    // One invalidation per distinct subject, not per row.
    expect(events.filter((e) => e.type === "subject").length).toBe(2);
  });

  it("validates every input before writing anything: one bad row rejects the batch", async () => {
    const { app } = makeApp();
    await expect(
      app.createGrants(
        [
          { subject: "user:u1", pattern: "docs.files.read" },
          { subject: "user:u2", pattern: "docs.ghost.read" }, // unknown key
        ],
        admin,
      ),
    ).rejects.toThrow(/references nothing/);
    expect((await app.listGrants()).length).toBe(0);
  });

  it("role grants resolve and scope-grantability holds in bulk too", async () => {
    const { app } = makeApp();
    const role = await app.createRole(
      { name: "Editor", patterns: ["docs.files.update_file"] },
      admin,
    );
    const rows = await app.createGrants(
      [{ subject: "user:u1", roleId: role.id, scope: "docs.folder:9" }],
      admin,
    );
    expect(rows[0]!.roleId).toBe(role.id);
    await expect(
      app.createGrants([{ subject: "user:u1", roleId: "ghost" }], admin),
    ).rejects.toThrow(/does not exist/);
  });

  it("an empty batch is a no-op", async () => {
    const { app } = makeApp();
    expect(await app.createGrants([], admin)).toEqual([]);
    expect((await app.listAuditEvents()).length).toBe(0);
  });
});

describe("unknown-pattern near-miss", () => {
  it("write paths name the group→pattern fix", async () => {
    const { app } = makeApp();
    await expect(
      app.createGrant({ subject: "user:u1", pattern: "docs", provenance: admin }),
    ).rejects.toThrow(/subtree pattern is "docs\.\*"/);
    await expect(
      app.createRole({ name: "R", patterns: ["docs.files"] }, admin),
    ).rejects.toThrow(/subtree pattern is "docs\.files\.\*"/);
  });
});

describe("caller-supplied ids", () => {
  it("createRole and createGroup accept well-known ids; collisions are conflicts", async () => {
    const { app } = makeApp();
    const role = await app.createRole(
      { id: "gdnrole_instructor", name: "Course instructor", patterns: ["docs.files.*"] },
      admin,
    );
    expect(role.id).toBe("gdnrole_instructor");
    await expect(
      app.createRole({ id: "gdnrole_instructor", name: "Dup", patterns: ["docs.files.read"] }, admin),
    ).rejects.toMatchObject({ code: "conflict" });

    const group = await app.createGroup({ id: "cohort_2026", name: "Cohort 2026" }, admin);
    expect(group.id).toBe("cohort_2026");
    await expect(
      app.createGroup({ id: "cohort_2026", name: "Dup" }, admin),
    ).rejects.toMatchObject({ code: "conflict" });

    await expect(
      app.createRole({ id: "", name: "Empty", patterns: [] }, admin),
    ).rejects.toThrow(/non-empty/);
  });

  it("generated ids still work when id is omitted", async () => {
    const { app } = makeApp();
    const role = await app.createRole({ name: "Auto", patterns: ["docs.files.read"] }, admin);
    expect(role.id.length).toBeGreaterThan(0);
  });
});

describe("updateGroup", () => {
  it("renames without touching parents or membership", async () => {
    const { app } = makeApp();
    const parent = await app.createGroup({ name: "Staff" }, admin);
    const group = await app.createGroup(
      { name: "Cohort A", description: "old", parents: [parent.id] },
      admin,
    );
    await app.setGroupMembership("u1", [group.id], admin);

    const updated = await app.updateGroup(
      group.id,
      { name: "Cohort A (renamed)" },
      admin,
    );
    expect(updated.name).toBe("Cohort A (renamed)");
    expect(updated.description).toBe("old"); // untouched when omitted
    expect(updated.parents).toEqual([parent.id]);
    expect(await app.getGroupMembers(group.id)).toEqual(["u1"]);

    const audit = await app.listAuditEvents({ target: group.id });
    expect(audit.some((e) => e.action === "group.update")).toBe(true);
    // NOT audited as a directory import — this is the admin's own rename.
    expect(audit.some((e) => e.action.startsWith("directory."))).toBe(false);
  });

  it("unknown group is not_found; non-root apps reject", async () => {
    const { app } = makeApp();
    await expect(app.updateGroup("ghost", { name: "X" }, admin)).rejects.toMatchObject({
      code: "not_found",
    });
    const nonRoot = makeApp({ orgRoot: false });
    await expect(
      nonRoot.app.updateGroup("any", { name: "X" }, admin),
    ).rejects.toMatchObject({ code: "not_org_root" });
  });
});

describe("setUserActive", () => {
  it("deactivation sticks, evaluates to no access, and is reversible", async () => {
    const { app } = makeApp();
    await app.createGrant({ subject: "user:u1", pattern: "docs.files.read", provenance: admin });
    expect((await app.getSubjectAccess({ userId: "u1" })).active).toBe(true);

    await app.setUserActive("u1", false, admin);
    expect((await app.getSubjectAccess({ userId: "u1" })).active).toBe(false);

    await app.setUserActive("u1", true, admin);
    expect((await app.getSubjectAccess({ userId: "u1" })).active).toBe(true);
  });

  it("deactivating a never-provisioned principal creates the record", async () => {
    const { app } = makeApp();
    const events = collectEvents(app);
    await app.setUserActive("ghost", false, admin);
    expect((await app.getSubjectAccess({ userId: "ghost" })).active).toBe(false);
    expect(events).toContainEqual({ type: "user", userId: "ghost" });
    expect(
      (await app.listAuditEvents({ target: "ghost" })).some(
        (e) => e.action === "user.set_active",
      ),
    ).toBe(true);
  });

  it("is org-domain: non-root apps reject", async () => {
    const { app } = makeApp({ orgRoot: false });
    await expect(app.setUserActive("u1", false, admin)).rejects.toMatchObject({
      code: "not_org_root",
    });
  });
});

describe("deleteSubject", () => {
  it("sweeps a user completely: grants (incl. implicit-group subjects), revokes, record, pending requests", async () => {
    const { app, storage } = makeApp();
    await app.setGroupMembership("u1", [], admin);
    await app.setReportingEdge("r1", "u1", admin); // u1 manages r1
    await app.createGrant({ subject: "user:u1", pattern: "docs.files.read", provenance: admin });
    await app.createGrant({
      subject: "user:u1",
      pattern: "docs.files.update_file",
      scope: "docs.folder:9",
      provenance: admin,
    });
    await app.createGrant({ subject: "directs:u1", pattern: "docs.files.read", provenance: admin });
    await app.createGrant({ subject: "user:other", pattern: "docs.files.read", provenance: admin });
    await app.createRevoke({ userId: "u1", pattern: "docs.files.*", provenance: admin });
    const request = await app.submitRequest({
      requesterUserId: "u1",
      pattern: "docs.files.read",
      scope: "docs.folder:9",
      justification: { why: "need it" },
    });

    const result = await app.deleteSubject("user:u1", admin);
    expect(result).toEqual({ deletedGrants: 3, deletedRevokes: 1 });

    expect(await app.listGrants({ subject: "user:u1" })).toEqual([]);
    expect(await app.listGrants({ subject: "directs:u1" })).toEqual([]);
    expect((await app.listGrants({ subject: "user:other" })).length).toBe(1); // untouched
    expect(await app.listRevokes({ userId: "u1" })).toEqual([]);
    expect(await storage.getUser("u1")).toBe(null);
    expect((await storage.getRequest(request.id))?.state).toBe("cancelled");

    const audit = await app.listAuditEvents({ target: "user:u1" });
    expect(audit.some((e) => e.action === "subject.delete")).toBe(true);
  });

  it("id reuse after deletion inherits nothing", async () => {
    const { app } = makeApp();
    await app.createGrant({ subject: "user:reused", pattern: "docs.admin.*", provenance: admin });
    await app.deleteSubject("user:reused", admin);
    // The "new hire" with the recycled id starts from deny-by-default.
    const data = await app.getSubjectAccess({ userId: "reused" });
    expect(data.grants).toEqual([]);
  });

  it("service principals: rows only, no user machinery", async () => {
    const { app } = makeApp();
    await app.createGrant({ subject: "service:token1", pattern: "docs.files.read", provenance: admin });
    const result = await app.deleteSubject("service:token1", admin);
    expect(result).toEqual({ deletedGrants: 1, deletedRevokes: 0 });
    expect((await app.getSubjectAccess({ serviceId: "token1" })).grants).toEqual([]);
  });

  it("rejects malformed subjects", async () => {
    const { app } = makeApp();
    await expect(app.deleteSubject("banana", admin)).rejects.toMatchObject({
      code: "validation",
    });
  });

  it("non-root: user offboarding rejected; service rows allowed unless global rows exist", async () => {
    const { app } = makeApp({ orgRoot: false });
    await expect(app.deleteSubject("user:u1", admin)).rejects.toMatchObject({
      code: "not_org_root",
    });
    // Instance-scoped service rows are application-domain: allowed.
    await app.createGrant({
      subject: "service:local",
      pattern: "docs.files.read",
      scope: "docs.folder:9",
      provenance: admin,
    });
    expect(await app.deleteSubject("service:local", admin)).toEqual({
      deletedGrants: 1,
      deletedRevokes: 0,
    });
  });
});

describe("deleteScope", () => {
  it("sweeps grants and revokes at the scope, cancels its pending requests, leaves the rest", async () => {
    const { app, storage } = makeApp();
    await app.createGrant({
      subject: "user:u1",
      pattern: "docs.files.read",
      scope: "docs.folder:9",
      provenance: admin,
    });
    await app.createGrant({
      subject: "group:staff",
      pattern: "docs.files.update_file",
      scope: "docs.folder:9",
      provenance: admin,
    });
    await app.createGrant({
      subject: "user:u1",
      pattern: "docs.files.read",
      scope: "docs.folder:2",
      provenance: admin,
    });
    await app.createRevoke({
      userId: "u2",
      pattern: "docs.files.*",
      scope: "docs.folder:9",
      provenance: admin,
    });
    const request = await app.submitRequest({
      requesterUserId: "u3",
      pattern: "docs.files.read",
      scope: "docs.folder:9",
      justification: { why: "need it" },
    });

    const events = collectEvents(app);
    const result = await app.deleteScope("docs.folder:9", admin);
    expect(result).toEqual({ deletedGrants: 2, deletedRevokes: 1 });
    expect(await app.listGrants({ scope: "docs.folder:9" })).toEqual([]);
    expect((await app.listGrants({ scope: "docs.folder:2" })).length).toBe(1);
    expect(await app.listRevokes({ userId: "u2" })).toEqual([]);
    expect((await storage.getRequest(request.id))?.state).toBe("cancelled");

    // The chain through the deleted scope busts, and affected subjects bust.
    expect(events).toContainEqual({ type: "scope", scope: "docs.folder:9" });
    expect(events.filter((e) => e.type === "subject").length).toBe(2);
    expect(events).toContainEqual({ type: "user", userId: "u2" });

    const audit = await app.listAuditEvents({ target: "docs.folder:9" });
    expect(audit.some((e) => e.action === "scope.delete")).toBe(true);
  });

  it("the global scope is not deletable, and scope ids are validated", async () => {
    const { app } = makeApp();
    await expect(app.deleteScope("*", admin)).rejects.toThrow(/not a deletable/);
    await expect(app.deleteScope("no-colon", admin)).rejects.toMatchObject({
      code: "validation",
    });
  });
});
