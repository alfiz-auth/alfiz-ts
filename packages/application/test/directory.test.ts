import { describe, expect, it } from "vitest";
import { admin, makeApp } from "./fixtures.js";

describe("importDirectory", () => {
  it("imports groups, memberships, orgs, and reporting edges", async () => {
    const { app } = makeApp();
    const result = await app.importDirectory(
      {
        groups: [
          { id: "staff", name: "Staff" },
          { id: "teachers", name: "Teachers", parents: ["staff"] },
        ],
        memberships: { u1: ["teachers"] },
        orgs: { u1: ["acme"] },
        reportingEdges: { u1: "jane", jane: "omar" },
        users: [{ userId: "inactive-user", active: false }],
      },
      "entra",
    );
    expect(result.warnings).toEqual([]);
    const data = await app.getSubjectAccess({ userId: "u1" });
    expect(data.closure).toContain("group:teachers");
    expect(data.closure).toContain("group:staff");
    expect(data.closure).toContain("org:acme");
    expect(data.managerChain).toEqual(["jane", "omar"]);
    expect((await app.getSubjectAccess({ userId: "inactive-user" })).active).toBe(false);
  });

  it("auto-condenses cyclic directory nesting into a virtual parent", async () => {
    const { app } = makeApp();
    const result = await app.importDirectory(
      {
        groups: [
          { id: "a", name: "A", parents: ["b"] },
          { id: "b", name: "B", parents: ["a", "ext"] },
          { id: "ext", name: "External" },
        ],
        memberships: { u1: ["a"] },
      },
      "okta",
    );
    expect(result.virtualParents.length).toBe(1);
    expect(result.warnings[0]).toMatch(/condensed/);
    const vp = result.virtualParents[0]!;
    const groups = await app.listGroups();
    const vpGroup = groups.find((g) => g.id === vp.id)!;
    expect(vpGroup.virtual).toBe(true);
    expect(vpGroup.parents).toEqual(["ext"]);
    // Access granted to the pool reaches members of either group.
    await app.createGrant({
      subject: `group:${vp.id}`,
      pattern: "docs.files.read",
      provenance: admin,
    });
    const data = await app.getSubjectAccess({ userId: "u1" });
    expect(data.closure).toContain(`group:${vp.id}`);
    expect(data.closure).toContain("group:ext");
  });

  it("skips reporting cycles with a warning, never silently combining", async () => {
    const { app } = makeApp();
    const result = await app.importDirectory(
      { reportingEdges: { a: "b", b: "a", c: "a" } },
      "ldap",
    );
    expect(result.warnings.some((w) => /reporting cycle/.test(w))).toBe(true);
    // The non-cyclic edge landed.
    const edges = await app.getReportingEdges();
    expect(edges.get("c")).toBe("a");
  });

  it("directory ingestion is org-root only", async () => {
    const { app } = makeApp({ orgRoot: false });
    await expect(app.importDirectory({}, "entra")).rejects.toMatchObject({
      code: "not_org_root",
    });
  });
});
