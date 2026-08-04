import { describe, expect, it } from "vitest";
import { admin, makeApp } from "./fixtures.js";

describe("exportEntitlements", () => {
  it("rolls direct, role, and group access into per-user entitlements with sources", async () => {
    const { app } = makeApp();
    const readers = await app.createRole(
      { name: "Reader", patterns: ["docs.files.read"] },
      admin,
    );
    const team = await app.createGroup({ name: "Team" }, admin);
    await app.setGroupMembership("alice", [team.id], admin);
    await app.createGrant({ subject: `group:${team.id}`, roleId: readers.id, provenance: admin });
    await app.createGrant({
      subject: "user:alice",
      pattern: "docs.files.update_file",
      scope: "docs.folder:9",
      provenance: admin,
    });

    const [alice] = await app.exportEntitlements({ userIds: ["alice"] });
    expect(alice!.active).toBe(true);
    const byKey = new Map(alice!.entitlements.map((e) => [e.key, e]));
    const read = byKey.get("docs.files.read")!;
    expect(read.held).toBe(true);
    expect(read.sources[0]!.subject).toBe(`group:${team.id}`);
    expect(read.sources[0]!.roleId).toBe(readers.id);
    const update = byKey.get("docs.files.update_file")!;
    expect(update.sources[0]!.scope).toBe("docs.folder:9");
    // Keys nothing confers are omitted.
    expect(byKey.has("docs.admin.manage_settings")).toBe(false);
  });

  it("a global revoke flips held to false while the conferring source stays visible", async () => {
    const { app } = makeApp();
    await app.createGrant({ subject: "user:bob", pattern: "docs.files.read", provenance: admin });
    await app.createRevoke({ userId: "bob", pattern: "docs.*", provenance: admin });

    const [bob] = await app.exportEntitlements({ userIds: ["bob"] });
    const read = bob!.entitlements.find((e) => e.key === "docs.files.read")!;
    expect(read.held).toBe(false);
    expect(read.sources).toHaveLength(1);
    expect(bob!.revokes).toHaveLength(1);
  });

  it("enumerates users from records and grant rows when none are supplied", async () => {
    const { app } = makeApp();
    await app.createGrant({ subject: "user:only-in-grants", pattern: "docs.files.read", provenance: admin });
    await app.setGroupMembership("only-in-records", [], admin);
    const report = await app.exportEntitlements();
    expect(report.map((r) => r.userId)).toEqual(["only-in-grants", "only-in-records"]);
  });
});
