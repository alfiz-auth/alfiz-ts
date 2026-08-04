import { describe, expect, it } from "vitest";
import { defineCatalog } from "@alfiz/core";
import type { Provenance } from "@alfiz/core";
import { createApplication, memoryDriver } from "@alfiz/application";

const admin: Provenance = { kind: "admin", actorUserId: "root" };

const catalogV1 = () =>
  defineCatalog({
    namespaces: ["docs"],
    permissions: {
      "docs.files.read": {},
      "docs.files.update_file": {},
    },
  });

const catalogV2 = () =>
  defineCatalog({
    namespaces: ["docs"],
    permissions: {
      "docs.files.read": {},
      "docs.files.update_file": {},
      "docs.files.export_all": {}, // gained
      "docs.admin.manage_settings": {}, // gained, outside files
    },
  });

describe("listWildcardDrift", () => {
  it("names the keys a wildcard grant silently absorbed between publishes", async () => {
    const storage = memoryDriver();
    const app = createApplication({ catalog: catalogV1(), storage });
    await app.publishCatalog(catalogV1().toDocument(), admin);
    await app.createGrant({ subject: "user:u1", pattern: "docs.files.*", provenance: admin });
    await app.createGrant({ subject: "user:u2", pattern: "docs.files.read", provenance: admin });

    const app2 = createApplication({ catalog: catalogV2(), storage });
    await app2.publishCatalog(catalogV2().toDocument(), admin);

    const report = await app2.listWildcardDrift({ sinceVersion: 1 });
    expect(report.fromVersion).toBe(1);
    expect(report.toVersion).toBe(2);
    expect(report.gainedKeys).toEqual([
      "docs.admin.manage_settings",
      "docs.files.export_all",
    ]);
    // The wildcard holder absorbed only the key under its prefix; the
    // concrete-key holder absorbed nothing.
    expect(report.findings).toHaveLength(1);
    const finding = report.findings[0]!;
    expect(finding.pattern).toBe("docs.files.*");
    expect(finding.gainedKeys).toEqual(["docs.files.export_all"]);
    expect(finding.via.kind).toBe("grant");
  });

  it("attributes drift through assigned roles, ignoring unassigned ones", async () => {
    const storage = memoryDriver();
    const app = createApplication({ catalog: catalogV1(), storage });
    await app.publishCatalog(catalogV1().toDocument(), admin);
    const assigned = await app.createRole({ name: "Files", patterns: ["docs.files.*"] }, admin);
    await app.createRole({ name: "Unassigned", patterns: ["docs.*"] }, admin);
    await app.createGrant({ subject: "user:u1", roleId: assigned.id, provenance: admin });

    const app2 = createApplication({ catalog: catalogV2(), storage });
    await app2.publishCatalog(catalogV2().toDocument(), admin);

    const report = await app2.listWildcardDrift({ sinceVersion: 1 });
    const roleFindings = report.findings.filter((f) => f.via.kind === "role");
    expect(roleFindings).toHaveLength(1);
    expect(
      roleFindings[0]!.via.kind === "role" && roleFindings[0]!.via.role.name,
    ).toBe("Files");
  });

  it("rejects an unretained version and reports removals", async () => {
    const storage = memoryDriver();
    const app = createApplication({ catalog: catalogV2(), storage });
    await app.publishCatalog(catalogV2().toDocument(), admin);
    await expect(app.listWildcardDrift({ sinceVersion: 7 })).rejects.toMatchObject({
      code: "not_found",
    });

    const app2 = createApplication({ catalog: catalogV1(), storage });
    await app2.publishCatalog(catalogV1().toDocument(), admin);
    const report = await app2.listWildcardDrift({ sinceVersion: 1 });
    expect(report.removedKeys).toEqual([
      "docs.admin.manage_settings",
      "docs.files.export_all",
    ]);
  });

  it("lists retained versions", async () => {
    const storage = memoryDriver();
    const app = createApplication({ catalog: catalogV1(), storage });
    await app.publishCatalog(catalogV1().toDocument(), admin);
    await app.publishCatalog(catalogV1().toDocument(), admin);
    expect((await app.listCatalogVersions()).map((v) => v.version)).toEqual([1, 2]);
  });
});
