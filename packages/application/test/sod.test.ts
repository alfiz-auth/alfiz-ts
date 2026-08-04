import { describe, expect, it } from "vitest";
import { CatalogError, defineCatalog } from "@alfiz/core";
import type { Provenance } from "@alfiz/core";
import { createApplication, memoryDriver } from "@alfiz/application";

const admin: Provenance = { kind: "admin", actorUserId: "root" };

const sodCatalog = () =>
  defineCatalog({
    namespaces: ["erp"],
    permissions: {
      "erp.vendors.read": {},
      "erp.vendors.manage_vendor": {},
      "erp.payments.read": {},
      "erp.payments.approve_payment": {},
      "erp.reports.read": {},
    },
    constraints: {
      sod: [
        {
          id: "vendor-vs-payments",
          description: "No one may both manage vendors and approve payments",
          sets: [["erp.vendors.manage_vendor"], ["erp.payments.approve_payment"]],
        },
      ],
    },
  });

function makeApp(enforce?: "reject") {
  return createApplication({
    catalog: sodCatalog(),
    storage: memoryDriver(),
    ...(enforce ? { sod: { enforce } } : {}),
  });
}

describe("catalog constraint validation", () => {
  it("rejects a constraint whose sets share a key", () => {
    expect(() =>
      defineCatalog({
        namespaces: ["erp"],
        permissions: { "erp.a.read": {}, "erp.a.write_thing": {} },
        constraints: {
          sod: [{ id: "broken", sets: [["erp.a.*"], ["erp.a.read"]] }],
        },
      }),
    ).toThrow(CatalogError);
  });

  it("rejects a single-set constraint and an unknown pattern", () => {
    expect(() =>
      defineCatalog({
        namespaces: ["erp"],
        permissions: { "erp.a.read": {} },
        constraints: { sod: [{ id: "one", sets: [["erp.a.read"]] }] },
      }),
    ).toThrow(/at least two/);
    expect(() =>
      defineCatalog({
        namespaces: ["erp"],
        permissions: { "erp.a.read": {} },
        constraints: {
          sod: [{ id: "typo", sets: [["erp.a.read"], ["erp.b.write_x"]] }],
        },
      }),
    ).toThrow(/matches no declared permission/);
  });
});

describe("listSodViolations (detective)", () => {
  it("reports a user holding both sets, with the concrete keys", async () => {
    const app = makeApp();
    await app.createGrant({ subject: "user:eve", pattern: "erp.vendors.manage_vendor", provenance: admin });
    await app.createGrant({ subject: "user:eve", pattern: "erp.payments.approve_payment", provenance: admin });
    await app.createGrant({ subject: "user:ok", pattern: "erp.vendors.manage_vendor", provenance: admin });

    const report = await app.listSodViolations();
    expect(report).toHaveLength(1);
    expect(report[0]!.userId).toBe("eve");
    const violation = report[0]!.violations[0]!;
    expect(violation.constraintId).toBe("vendor-vs-payments");
    expect(violation.sets.map((s) => s.keys)).toEqual([
      ["erp.vendors.manage_vendor"],
      ["erp.payments.approve_payment"],
    ]);
  });

  it("sees access inherited through groups and roles", async () => {
    const app = makeApp();
    const approvers = await app.createGroup({ name: "Approvers" }, admin);
    await app.createGrant({
      subject: `group:${approvers.id}`,
      pattern: "erp.payments.approve_payment",
      provenance: admin,
    });
    const vendorAdmin = await app.createRole(
      { name: "Vendor Admin", patterns: ["erp.vendors.*"] },
      admin,
    );
    await app.setGroupMembership("mallory", [approvers.id], admin);
    await app.createGrant({ subject: "user:mallory", roleId: vendorAdmin.id, provenance: admin });

    const report = await app.listSodViolations();
    expect(report.map((r) => r.userId)).toEqual(["mallory"]);
  });

  it("a global revoke suppresses one side and clears the violation", async () => {
    const app = makeApp();
    await app.createGrant({ subject: "user:eve", pattern: "erp.vendors.manage_vendor", provenance: admin });
    await app.createGrant({ subject: "user:eve", pattern: "erp.payments.approve_payment", provenance: admin });
    expect(await app.listSodViolations()).toHaveLength(1);
    await app.createRevoke({ userId: "eve", pattern: "erp.payments.*", provenance: admin });
    expect(await app.listSodViolations()).toHaveLength(0);
  });
});

describe("sod: { enforce: 'reject' } (preventive)", () => {
  it("rejects the user grant that would create a violation", async () => {
    const app = makeApp("reject");
    await app.createGrant({ subject: "user:eve", pattern: "erp.vendors.manage_vendor", provenance: admin });
    await expect(
      app.createGrant({ subject: "user:eve", pattern: "erp.payments.approve_payment", provenance: admin }),
    ).rejects.toMatchObject({ code: "conflict" });
    // Unrelated access is untouched by enforcement.
    await app.createGrant({ subject: "user:eve", pattern: "erp.reports.read", provenance: admin });
  });

  it("group grants pass through enforcement (detective report still catches members)", async () => {
    const app = makeApp("reject");
    const g = await app.createGroup({ name: "Payments" }, admin);
    await app.setGroupMembership("eve", [g.id], admin);
    await app.createGrant({ subject: "user:eve", pattern: "erp.vendors.manage_vendor", provenance: admin });
    // The group-shaped write is not rejected…
    await app.createGrant({
      subject: `group:${g.id}`,
      pattern: "erp.payments.approve_payment",
      provenance: admin,
    });
    // …but the report names the member it violated.
    expect((await app.listSodViolations()).map((r) => r.userId)).toEqual(["eve"]);
  });

  it("default posture is detective-only: the same write succeeds", async () => {
    const app = makeApp();
    await app.createGrant({ subject: "user:eve", pattern: "erp.vendors.manage_vendor", provenance: admin });
    await app.createGrant({ subject: "user:eve", pattern: "erp.payments.approve_payment", provenance: admin });
    expect(await app.listSodViolations()).toHaveLength(1);
  });
});
