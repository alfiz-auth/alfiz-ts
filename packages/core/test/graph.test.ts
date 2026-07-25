import { describe, expect, it } from "vitest";
import {
  GraphCycleError,
  assertEdgeInsertable,
  condenseImportedGraph,
  findCycle,
  findCycleForEdge,
} from "../src/graph.js";

const graph = (edges: Record<string, string[]>) =>
  new Map(Object.entries(edges));

describe("findCycleForEdge", () => {
  it("accepts edges that keep the graph acyclic", () => {
    const g = graph({ b: ["c"] });
    expect(findCycleForEdge(g, "a", "b")).toBe(null);
    expect(findCycleForEdge(g, "c", "d")).toBe(null);
  });

  it("rejects self-edges", () => {
    expect(findCycleForEdge(graph({}), "a", "a")).toEqual(["a", "a"]);
  });

  it("names the full cycle path", () => {
    // b→c and c→a exist; inserting a→b closes a → b → c → a.
    const g = graph({ b: ["c"], c: ["a"] });
    expect(findCycleForEdge(g, "a", "b")).toEqual(["a", "b", "c", "a"]);
  });

  it("finds cycles through diamonds", () => {
    const g = graph({ b: ["c", "d"], d: ["e"], e: ["a"] });
    expect(findCycleForEdge(g, "a", "b")).toEqual(["a", "b", "d", "e", "a"]);
  });

  it("assertEdgeInsertable throws a debuggable error", () => {
    const g = graph({ b: ["a"] });
    try {
      assertEdgeInsertable(g, "a", "b");
      expect.unreachable("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(GraphCycleError);
      expect((err as GraphCycleError).message).toBe("cycle: a → b → a");
      expect((err as GraphCycleError).path).toEqual(["a", "b", "a"]);
    }
  });
});

describe("findCycle (whole graph)", () => {
  it("null on DAGs", () => {
    expect(findCycle(graph({ a: ["b"], b: ["c"], d: ["c"] }))).toBe(null);
    expect(findCycle(graph({}))).toBe(null);
  });

  it("finds an existing cycle", () => {
    const cycle = findCycle(graph({ a: ["b"], b: ["c"], c: ["a"] }));
    expect(cycle).not.toBe(null);
    expect(cycle!.length).toBe(4);
    expect(cycle![0]).toBe(cycle![cycle!.length - 1]);
    const members = new Set(cycle);
    expect(members).toEqual(new Set(["a", "b", "c"]));
  });

  it("finds self-loops", () => {
    expect(findCycle(graph({ a: ["a"] }))).toEqual(["a", "a"]);
  });
});

describe("condenseImportedGraph", () => {
  it("passes DAGs through unchanged, no virtual parents", () => {
    const result = condenseImportedGraph(graph({ a: ["b"], b: ["c"] }));
    expect(result.virtualParents).toEqual([]);
    expect(result.warnings).toEqual([]);
    expect(result.parentsOf.get("a")).toEqual(["b"]);
    expect(result.parentsOf.get("b")).toEqual(["c"]);
  });

  it("collapses a cycle into a virtual parent", () => {
    const result = condenseImportedGraph(
      graph({ a: ["b"], b: ["a"] }),
      (members) => `vp:${members.join("+")}`,
    );
    expect(result.virtualParents).toEqual([{ id: "vp:a+b", members: ["a", "b"] }]);
    expect(result.parentsOf.get("a")).toEqual(["vp:a+b"]);
    expect(result.parentsOf.get("b")).toEqual(["vp:a+b"]);
    expect(result.warnings.length).toBe(1);
    expect(result.warnings[0]).toMatch(/condensed/);
  });

  it("the virtual parent inherits the SCC's external parents", () => {
    // a ↔ b, and b → ext. The pool keeps inheriting from ext via the parent.
    const result = condenseImportedGraph(
      graph({ a: ["b"], b: ["a", "ext"] }),
      (members) => `vp:${members.join("+")}`,
    );
    expect(result.parentsOf.get("vp:a+b")).toEqual(["ext"]);
  });

  it("condenses self-loops", () => {
    const result = condenseImportedGraph(
      graph({ a: ["a", "ext"] }),
      (members) => `vp:${members.join("+")}`,
    );
    expect(result.virtualParents).toEqual([{ id: "vp:a", members: ["a"] }]);
    expect(result.parentsOf.get("a")).toEqual(["vp:a"]);
    expect(result.parentsOf.get("vp:a")).toEqual(["ext"]);
  });

  it("handles multiple independent cycles and keeps the result acyclic", () => {
    const result = condenseImportedGraph(
      graph({
        a: ["b"],
        b: ["a"],
        x: ["y"],
        y: ["x"],
        outsider: ["a", "x"],
      }),
    );
    expect(result.virtualParents.length).toBe(2);
    expect(findCycle(result.parentsOf)).toBe(null);
    const outsiderParents = result.parentsOf.get("outsider")!;
    expect(outsiderParents.length).toBe(2);
  });

  it("nested SCC chains: cycle → cycle becomes vp → vp", () => {
    const result = condenseImportedGraph(
      graph({
        a: ["b"],
        b: ["a", "x"],
        x: ["y"],
        y: ["x"],
      }),
      (members) => `vp:${members.join("+")}`,
    );
    expect(result.parentsOf.get("vp:a+b")).toEqual(["vp:x+y"]);
    expect(findCycle(result.parentsOf)).toBe(null);
  });
});
