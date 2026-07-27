import { describe, expect, it } from "vitest";
import { defineCatalog } from "../src/catalog.js";
import {
  buildPermissionTree,
  isNodeChecked,
  isNodeIndeterminate,
  nodePattern,
  toggleNode,
} from "../src/tree.js";
import type { PermTreeNode } from "../src/tree.js";

const catalog = defineCatalog({
  namespaces: ["mathaniyy", "diploma"],
  includeAlfizInternal: false,
  permissions: {
    "mathaniyy.approvals.read_student": true,
    "mathaniyy.approvals.decide_student": true,
    "mathaniyy.schedule.read": true,
    "mathaniyy.schedule.update_slot": true,
    "diploma.applicants.read": true,
    "diploma.applicants.advance_stage": true,
  },
});

const tree = buildPermissionTree(catalog);
const node = (path: string): PermTreeNode => {
  const find = (nodes: readonly PermTreeNode[]): PermTreeNode | undefined => {
    for (const n of nodes) {
      if (n.path === path) return n;
      const found = find(n.children);
      if (found) return found;
    }
    return undefined;
  };
  const found = find(tree);
  if (!found) throw new Error(`no node ${path}`);
  return found;
};

describe("buildPermissionTree", () => {
  it("mirrors the catalog structure", () => {
    expect(tree.map((n) => n.path).sort()).toEqual(["diploma", "mathaniyy"]);
    expect(node("mathaniyy.approvals").children.map((c) => c.path)).toEqual([
      "mathaniyy.approvals.read_student",
      "mathaniyy.approvals.decide_student",
    ]);
    expect(node("mathaniyy.approvals.read_student").kind).toBe("leaf");
  });

  it("nodePattern stores forward-inclusive wildcards for groups", () => {
    expect(nodePattern(node("mathaniyy"))).toBe("mathaniyy.*");
    expect(nodePattern(node("mathaniyy.approvals"))).toBe("mathaniyy.approvals.*");
    expect(nodePattern(node("mathaniyy.approvals.read_student"))).toBe(
      "mathaniyy.approvals.read_student",
    );
  });
});

describe("checked / indeterminate", () => {
  it("wildcard selections check whole subtrees", () => {
    expect(isNodeChecked(["mathaniyy.*"], node("mathaniyy"))).toBe(true);
    expect(isNodeChecked(["mathaniyy.*"], node("mathaniyy.approvals"))).toBe(true);
    expect(isNodeChecked(["mathaniyy.*"], node("mathaniyy.approvals.read_student"))).toBe(true);
    expect(isNodeChecked(["mathaniyy.*"], node("diploma"))).toBe(false);
  });

  it("a group with every leaf individually selected reads checked", () => {
    const selection = ["mathaniyy.approvals.read_student", "mathaniyy.approvals.decide_student"];
    expect(isNodeChecked(selection, node("mathaniyy.approvals"))).toBe(true);
    expect(isNodeIndeterminate(selection, node("mathaniyy.approvals"))).toBe(false);
  });

  it("partial coverage is indeterminate", () => {
    const selection = ["mathaniyy.approvals.read_student"];
    expect(isNodeChecked(selection, node("mathaniyy.approvals"))).toBe(false);
    expect(isNodeIndeterminate(selection, node("mathaniyy.approvals"))).toBe(true);
    expect(isNodeIndeterminate(selection, node("mathaniyy"))).toBe(true);
  });
});

describe("toggleNode", () => {
  it("ticking a group stores its wildcard and subsumes entries under it", () => {
    const result = toggleNode(
      ["mathaniyy.approvals.read_student", "diploma.applicants.read"],
      node("mathaniyy.approvals"),
      tree,
    );
    expect(result).toEqual(["diploma.applicants.read", "mathaniyy.approvals.*"]);
  });

  it("ticking a leaf adds just the key", () => {
    const result = toggleNode([], node("mathaniyy.schedule.read"), tree);
    expect(result).toEqual(["mathaniyy.schedule.read"]);
  });

  it("unticking a leaf under a broad wildcard explodes it into siblings", () => {
    const result = toggleNode(["mathaniyy.*"], node("mathaniyy.approvals.decide_student"), tree);
    expect(result.sort()).toEqual([
      "mathaniyy.approvals.read_student",
      "mathaniyy.schedule.*",
    ]);
    // The unticked leaf is gone; siblings keep forward-inclusion.
    expect(isNodeChecked(result, node("mathaniyy.approvals.decide_student"))).toBe(false);
    expect(isNodeChecked(result, node("mathaniyy.schedule"))).toBe(true);
  });

  it("unticking a group under the bare star keeps other projects wildcarded", () => {
    const result = toggleNode(["*"], node("mathaniyy.approvals"), tree);
    expect(result.sort()).toEqual(["diploma.*", "mathaniyy.schedule.*"]);
  });

  it("unticking a directly stored group removes it", () => {
    const result = toggleNode(["mathaniyy.approvals.*"], node("mathaniyy.approvals"), tree);
    expect(result).toEqual([]);
  });

  it("unticking a leaf that was individually stored removes only it", () => {
    const selection = ["mathaniyy.approvals.read_student", "mathaniyy.approvals.decide_student"];
    const result = toggleNode(selection, node("mathaniyy.approvals.decide_student"), tree);
    expect(result).toEqual(["mathaniyy.approvals.read_student"]);
  });

  it("round-trips: toggle on then off returns to the rest", () => {
    const on = toggleNode(["diploma.*"], node("mathaniyy"), tree);
    expect(on.sort()).toEqual(["diploma.*", "mathaniyy.*"]);
    const off = toggleNode(on, node("mathaniyy"), tree);
    expect(off).toEqual(["diploma.*"]);
  });
});
