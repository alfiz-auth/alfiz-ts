import { describe, expect, it } from "vitest";
import { admin, makeApp } from "./fixtures.js";

describe("reconcileRows", () => {
  it("finds grants and revokes referencing users the host deleted", async () => {
    const { app } = makeApp();
    await app.createGrant({ subject: "user:gone", pattern: "docs.files.read", provenance: admin });
    await app.createGrant({ subject: "user:alive", pattern: "docs.files.read", provenance: admin });
    await app.createRevoke({ userId: "gone", pattern: "docs.*", provenance: admin });
    await app.createGrant({ subject: "directs:gone", pattern: "docs.files.read", provenance: admin });

    const report = await app.reconcileRows({
      userExists: (id) => id === "alive",
    });
    expect(report.orphanedGrants.map((g) => g.subject).sort()).toEqual([
      "directs:gone",
      "user:gone",
    ]);
    expect(report.orphanedRevokes).toHaveLength(1);
    expect(report.swept).toBe(false);
    // Detection alone deletes nothing.
    expect(await app.listGrants({ subject: "user:gone" })).toHaveLength(1);
  });

  it("finds grants at scopes the host deleted, and group grants with no group", async () => {
    const { app, storage } = makeApp();
    await app.createGrant({
      subject: "user:u1",
      pattern: "docs.files.read",
      scope: "docs.folder:9",
      provenance: admin,
    });
    // Bypass the guarded path to fabricate a stranded group grant.
    await storage.insertGrant({
      id: "stray",
      subject: "group:never-existed",
      pattern: "docs.files.read",
      scope: "*",
      provenance: admin,
      createdAt: 0,
    });

    const report = await app.reconcileRows({
      userExists: () => true,
      scopeExists: (scope) => scope !== "docs.folder:9",
    });
    expect(report.orphanedGrants.map((g) => g.id).sort()).toEqual(
      expect.arrayContaining(["stray"]),
    );
    expect(report.orphanedGrants.some((g) => g.scope === "docs.folder:9")).toBe(true);
  });

  it("reports dangling role grants without sweeping them", async () => {
    const { app, storage } = makeApp();
    const role = await app.createRole({ name: "R", patterns: ["docs.files.read"] }, admin);
    await app.createGrant({ subject: "user:u1", roleId: role.id, provenance: admin });
    await storage.deleteRole(role.id); // deliberate bypass

    const report = await app.reconcileRows({ userExists: () => true, sweep: true, provenance: admin });
    expect(report.danglingRoleGrants).toHaveLength(1);
    // Not swept: the row survives as a finding.
    expect(await app.listGrants({ subject: "user:u1" })).toHaveLength(1);
  });

  it("sweep deletes orphans through the audited paths", async () => {
    const { app, advance } = makeApp();
    await app.createGrant({ subject: "user:gone", pattern: "docs.files.read", provenance: admin });
    advance(1);
    const report = await app.reconcileRows({
      userExists: () => false,
      sweep: true,
      provenance: admin,
    });
    expect(report.orphanedGrants).toHaveLength(1);
    expect(await app.listGrants()).toHaveLength(0);
    const audit = await app.listAuditEvents({ action: "grant.delete" });
    expect(audit).toHaveLength(1);
    expect((audit[0]!.detail as { reason: string }).reason).toContain("reconciliation");
  });

  it("sweep without provenance is rejected before touching anything", async () => {
    const { app } = makeApp();
    await expect(
      app.reconcileRows({ userExists: () => false, sweep: true }),
    ).rejects.toMatchObject({ code: "validation" });
  });
});

describe("importDirectory({ authoritative: true })", () => {
  it("deactivates users absent from the snapshot, never deletes them", async () => {
    const { app } = makeApp();
    await app.importDirectory(
      { users: [{ userId: "keep" }, { userId: "drop" }] },
      "dir:test",
    );
    const result = await app.importDirectory(
      { users: [{ userId: "keep" }] },
      "dir:test",
      { authoritative: true },
    );
    expect(result.deactivatedUsers).toEqual(["drop"]);
    const access = await app.getSubjectAccess({ userId: "drop" });
    expect(access.active).toBe(false);
  });

  it("upsert-only mode (the default) still never deprovisions", async () => {
    const { app } = makeApp();
    await app.importDirectory({ users: [{ userId: "drop" }] }, "dir:test");
    await app.importDirectory({ users: [{ userId: "other" }] }, "dir:test");
    expect((await app.getSubjectAccess({ userId: "drop" })).active).toBe(true);
  });

  it("sweeps directory-group memberships of users the map no longer lists, keeping local groups", async () => {
    // Users LISTED in the map already get their set replaced (base
    // semantics); the authoritative gap is users who vanish from the map
    // entirely — upsert-only leaves their directory memberships forever.
    const { app } = makeApp();
    const local = await app.createGroup({ id: "local-team", name: "Local" }, admin);
    await app.importDirectory(
      {
        groups: [{ id: "dir-a", name: "A" }, { id: "dir-b", name: "B" }],
        memberships: { u1: ["dir-a", "dir-b"] },
      },
      "dir:test",
    );
    await app.setGroupMembership("u1", ["dir-a", "dir-b", local.id], admin);

    const result = await app.importDirectory(
      {
        groups: [{ id: "dir-a", name: "A" }, { id: "dir-b", name: "B" }],
        memberships: { u2: ["dir-a"] }, // u1 vanished from the directory map
      },
      "dir:test",
      { authoritative: true },
    );
    expect(result.removedMemberships).toBe(2);
    const access = await app.getSubjectAccess({ userId: "u1" });
    expect(access.closure).not.toContain("group:dir-a");
    expect(access.closure).not.toContain("group:dir-b");
    expect(access.closure).toContain(`group:${local.id}`);
  });

  it("warns instead of guessing when memberships come without a groups section", async () => {
    const { app } = makeApp();
    const result = await app.importDirectory(
      { memberships: { u1: [] } },
      "dir:test",
      { authoritative: true },
    );
    expect(result.warnings.some((w) => w.includes("authoritative memberships skipped"))).toBe(true);
  });

  it("clears reporting edges the directory no longer asserts", async () => {
    const { app } = makeApp();
    await app.importDirectory(
      { reportingEdges: { alice: "jane", bob: "jane" } },
      "dir:test",
    );
    const result = await app.importDirectory(
      { reportingEdges: { alice: "jane" } },
      "dir:test",
      { authoritative: true },
    );
    expect(result.clearedReportingEdges).toBe(1);
    expect((await app.getReportingEdges()).get("bob")).toBeUndefined();
    expect((await app.getReportingEdges()).get("alice")).toBe("jane");
  });
});
