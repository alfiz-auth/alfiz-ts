/**
 * The reference scenario: everything AJ-Admin's hand-rolled permission
 * system does, rebuilt on Alfiz — plus what it couldn't do (scoped grants
 * with inheritance, expiry, requests, precise revoke precedence, audit).
 *
 * This test is the parity proof for the "complete standalone app" story:
 * one catalog, one Application on one database, no external dependency.
 */

import { describe, expect, it } from "vitest";
import { createAlfizClient, defineCatalog, parentPointerResolver, planListing } from "@alfiz-auth/core";
import { createApplication, createSession, memoryDriver } from "@alfiz-auth/application";

const catalog = defineCatalog({
  namespace: "mathaniyy",
  additionalNamespaces: ["diploma", "admin", "groups", "payments"],
  projects: {
    mathaniyy: {
      groups: {
        approvals: {
          permissions: {
            read_student: true,
            read_teacher: true,
            decide_student: true,
            decide_teacher: true,
          },
        },
        students: {
          permissions: { read: true, read_pii: true, update_student: true },
        },
      },
    },
    diploma: {
      groups: {
        applicants: {
          permissions: { read: true, advance_stage: true, delete: true },
        },
      },
    },
    admin: {
      groups: {
        access: { permissions: { read: true, manage_roles: true } },
        // AJ-Admin's skip-code blanket-vs-namespaced key family becomes ONE
        // key granted at different scopes.
        skip_codes: {
          permissions: {
            read: true,
            issue_code: { scopes: ["payments.namespace"] },
            revoke_code: { scopes: ["payments.namespace"] },
          },
        },
      },
    },
    groups: {
      groups: {
        attendance: {
          permissions: {
            read: { scopes: ["groups.folder"] },
            manage_folder: { scopes: ["groups.folder"] },
            delete: { scopes: ["groups.folder"] },
          },
        },
      },
    },
  },
  scopeTypes: {
    "groups.folder": { parent: "groups.folder" }, // folders nest in folders
    "payments.namespace": { parent: null }, // genuinely flat: chains are [scope, *]
  },
  navigation: [
    { label: "Mathaniyy", href: "/mathaniyy", permission: "mathaniyy.*" },
    { label: "Diploma", href: "/diploma", permission: "diploma.*" },
    {
      label: "Approvals",
      href: "/mathaniyy/approvals",
      permission: ["mathaniyy.approvals.read_student", "mathaniyy.approvals.read_teacher"],
    },
  ],
});

const folderParents = new Map<string, string | null>([
  ["groups.folder:quran", null],
  ["groups.folder:quran-girls", "groups.folder:quran"],
  ["groups.folder:quran-boys", "groups.folder:quran"],
  ["payments.namespace:application_fees", null],
  ["payments.namespace:tuition", null],
]);

const setup = () => {
  const app = createApplication({
    catalog,
    storage: memoryDriver(),
    ancestry: parentPointerResolver((s) => folderParents.get(s) ?? null),
  });
  const client = createAlfizClient({ catalog, provider: app, subjectCacheTtlMs: 0 });
  const admin = { kind: "admin", actorUserId: "root" } as const;
  return { app, client, admin };
};

describe("the AJ-Admin scenario on Alfiz", () => {
  it("roles + user groups + personal revokes: the effective-access story", async () => {
    const { app, client, admin } = setup();
    // A role: a named bundle of patterns, opaque id, renameable.
    const teacherRole = await app.createRole(
      { name: "Teacher", patterns: ["mathaniyy.students.read", "mathaniyy.approvals.*"] },
      admin,
    );
    // A user group granting a cohort at once: eighty teachers, one edit.
    const teachers = await app.createGroup({ name: "Teachers" }, admin);
    await app.createGrant({ subject: `group:${teachers.id}`, roleId: teacherRole.id, provenance: admin });
    await app.setGroupMembership("t1", [teachers.id], admin);

    expect(await client.can({ userId: "t1" }, "mathaniyy.approvals.decide_student")).toBe(true);
    expect(await client.can({ userId: "t1" }, "mathaniyy.students.read")).toBe(true);
    expect(await client.can({ userId: "t1" }, "mathaniyy.students.read_pii")).toBe(false);

    // Individual revoke wins over everything inherited.
    await app.createRevoke({ userId: "t1", pattern: "mathaniyy.approvals.decide_student", provenance: admin });
    expect(await client.can({ userId: "t1" }, "mathaniyy.approvals.decide_student")).toBe(false);
    expect(await client.can({ userId: "t1" }, "mathaniyy.approvals.read_student")).toBe(true);

    // Renaming the role never breaks assignments (opaque id).
    await app.updateRole(teacherRole.id, { name: "Instructor" }, admin);
    expect(await client.can({ userId: "t1" }, "mathaniyy.students.read")).toBe(true);
  });

  it("project visibility is canAny over the subtree; tabs are any-of arrays", async () => {
    const { app, client, admin } = setup();
    await app.setGroupMembership("t1", [], admin);
    await app.createGrant({
      subject: "user:t1",
      pattern: "mathaniyy.approvals.read_teacher",
      provenance: admin,
    });
    // Project root: show iff the viewer holds anything under it.
    expect(await client.canAny({ userId: "t1" }, "mathaniyy.*")).toBe(true);
    expect(await client.canAny({ userId: "t1" }, "diploma.*")).toBe(false);
    // The Approvals tab is reachable under either read key (any-of).
    expect(
      await client.can({ userId: "t1" }, [
        "mathaniyy.approvals.read_student",
        "mathaniyy.approvals.read_teacher",
      ]),
    ).toBe(true);
  });

  it("attendance folders: scoped group grants with real inheritance and listing", async () => {
    const { app, client, admin } = setup();
    const girlsStaff = await app.createGroup({ name: "Girls program staff" }, admin);
    await app.setGroupMembership("t2", [girlsStaff.id], admin);
    // Grant view on ONE folder subtree — stored once, never fanned out.
    await app.createGrant({
      subject: `group:${girlsStaff.id}`,
      pattern: "groups.attendance.read",
      scope: "groups.folder:quran-girls",
      provenance: admin,
    });
    expect(await client.can({ userId: "t2" }, "groups.attendance.read", "groups.folder:quran-girls")).toBe(true);
    // Sibling and parent folders stay closed.
    expect(await client.can({ userId: "t2" }, "groups.attendance.read", "groups.folder:quran-boys")).toBe(false);
    expect(await client.can({ userId: "t2" }, "groups.attendance.read", "groups.folder:quran")).toBe(false);
    // Manage on the parent covers the whole subtree via the ancestor walk.
    await app.createGrant({
      subject: `group:${girlsStaff.id}`,
      pattern: "groups.attendance.manage_folder",
      scope: "groups.folder:quran",
      provenance: admin,
    });
    expect(await client.can({ userId: "t2" }, "groups.attendance.manage_folder", "groups.folder:quran-boys")).toBe(true);
    // Listing: push the filter into the database, never per-row can().
    const scopes = await client.grantedScopes({ userId: "t2" }, "groups.attendance.read");
    expect(planListing(scopes)).toEqual({
      mode: "scoped",
      include: ["groups.folder:quran-girls"],
      exclude: [],
    });
  });

  it("skip codes: one key, broad or narrow scope — no parallel key family", async () => {
    const { app, client, admin } = setup();
    await app.setGroupMembership("finance", [], admin);
    await app.setGroupMembership("fees-clerk", [], admin);
    // Blanket authority: the key at global scope.
    await app.createGrant({ subject: "user:finance", pattern: "admin.skip_codes.issue_code", provenance: admin });
    // Narrow authority: the SAME key at one payment namespace.
    await app.createGrant({
      subject: "user:fees-clerk",
      pattern: "admin.skip_codes.issue_code",
      scope: "payments.namespace:application_fees",
      provenance: admin,
    });
    expect(await client.can({ userId: "finance" }, "admin.skip_codes.issue_code", "payments.namespace:tuition")).toBe(true);
    expect(await client.can({ userId: "fees-clerk" }, "admin.skip_codes.issue_code", "payments.namespace:application_fees")).toBe(true);
    expect(await client.can({ userId: "fees-clerk" }, "admin.skip_codes.issue_code", "payments.namespace:tuition")).toBe(false);
  });

  it("view-as reproduces AJ-Admin's preview semantics, gated and narrowing-only", async () => {
    const { app, client, admin } = setup();
    await app.setGroupMembership("admin-user", [], admin);
    await app.createGrant({ subject: "user:admin-user", pattern: "*", provenance: admin });
    await app.setGroupMembership("t1", [], admin);
    await app.createGrant({ subject: "user:t1", pattern: "mathaniyy.students.read", provenance: admin });

    const session = await createSession(client, {
      actorUserId: "admin-user",
      viewAs: { kind: "user", userId: "t1" },
    });
    expect(await session.can("mathaniyy.students.read")).toBe(true);
    expect(await session.can("admin.access.manage_roles")).toBe(false); // narrowed
    expect(session.subjectUserId).toBe("t1"); // data-scoped surfaces follow
    expect(session.actorUserId).toBe("admin-user"); // attribution does not
  });

  it("what AJ-Admin could not do: an approved, expiring, audited access request", async () => {
    const { app, client, admin } = setup();
    await app.setReportingEdge("t1", "principal", admin);
    const elevated = await app.createRole(
      {
        name: "Approvals decider",
        patterns: ["mathaniyy.approvals.decide_student"],
        requestable: {
          prompts: [{ id: "why", label: "Why?" }],
          requireExpiry: true,
          maxDurationMs: 24 * 3600_000,
          stages: [{ kind: "management" }],
        },
      },
      admin,
    );
    const request = await app.submitRequest({
      requesterUserId: "t1",
      roleId: elevated.id,
      proposedExpiresAt: Date.now() + 3600_000,
      justification: { why: "covering for Amina today" },
    });
    expect((await app.listApproverQueue("principal")).length).toBe(1);
    await app.decideRequest(request.id, { deciderUserId: "principal", decision: "approved" });
    expect(await client.can({ userId: "t1" }, "mathaniyy.approvals.decide_student")).toBe(true);
    // Provenance answers "why does t1 hold this?" from data.
    const explained = await client.explain({ userId: "t1" }, "mathaniyy.approvals.decide_student");
    expect(explained.matchedGrants[0]!.provenance).toMatchObject({
      kind: "request",
      requestId: request.id,
      approvedBy: "principal",
    });
    const audit = await app.listAuditEvents();
    expect(audit.map((e) => e.action)).toContain("request.approved");
  });
});
