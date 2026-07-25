import { describe, expect, it } from "vitest";
import {
  GLOBAL_SCOPE,
  isGlobalScope,
  objectClosureOf,
  parentPointerResolver,
  parseScopeId,
  scopeId,
  scopeTypeOf,
  validateScopeId,
} from "../src/scopes.js";

describe("scope ids", () => {
  it("builds and parses", () => {
    expect(scopeId("docs.doc", "123")).toBe("docs.doc:123");
    expect(parseScopeId("docs.doc:123")).toEqual({
      type: "docs.doc",
      instanceId: "123",
    });
    expect(scopeTypeOf("docs.doc:123")).toBe("docs.doc");
    expect(scopeTypeOf(GLOBAL_SCOPE)).toBe(null);
  });

  it("instance ids may contain colons (opaque)", () => {
    expect(parseScopeId("docs.doc:a:b:c")).toEqual({
      type: "docs.doc",
      instanceId: "a:b:c",
    });
  });

  it("validates", () => {
    expect(validateScopeId("*")).toBe(null);
    expect(validateScopeId("docs.doc:123")).toBe(null);
    expect(validateScopeId("docs.doc")).not.toBe(null); // no instance
    expect(validateScopeId(":123")).not.toBe(null);
    expect(validateScopeId("docs..doc:1")).not.toBe(null); // bad type
    expect(validateScopeId("docs.doc:")).not.toBe(null);
  });

  it("isGlobalScope", () => {
    expect(isGlobalScope("*")).toBe(true);
    expect(isGlobalScope("docs.doc:1")).toBe(false);
  });
});

describe("objectClosureOf", () => {
  it("global scope closure is just itself", async () => {
    expect(await objectClosureOf("*", () => [])).toEqual(["*"]);
  });

  it("self first, ancestors nearest-first, global last", async () => {
    const closure = await objectClosureOf("docs.doc:1", () => [
      "docs.folder:9",
      "docs.folder:2",
      "*",
    ]);
    expect(closure).toEqual(["docs.doc:1", "docs.folder:9", "docs.folder:2", "*"]);
  });

  it("normalizes resolvers that forget the trailing global scope", async () => {
    const closure = await objectClosureOf("docs.doc:1", () => ["docs.folder:9"]);
    expect(closure).toEqual(["docs.doc:1", "docs.folder:9", "*"]);
  });

  it("dedupes and supports async resolvers", async () => {
    const closure = await objectClosureOf("d:1", async () => [
      "f:2",
      "f:2",
      "d:1",
    ]);
    expect(closure).toEqual(["d:1", "f:2", "*"]);
  });
});

describe("parentPointerResolver", () => {
  const parents = new Map<string, string | string[] | null>([
    ["docs.doc:1", "docs.folder:9"],
    ["docs.folder:9", "docs.folder:2"],
    ["docs.folder:2", null],
  ]);
  const resolve = parentPointerResolver((s) => parents.get(s) ?? null);

  it("walks single-parent chains nearest-first", () => {
    expect(resolve("docs.doc:1")).toEqual([
      "docs.folder:9",
      "docs.folder:2",
      "*",
    ]);
    expect(resolve("docs.folder:2")).toEqual(["*"]);
  });

  it("unions multi-parent chains breadth-first, deduplicated", () => {
    const multi = new Map<string, string[] | string | null>([
      ["doc:1", ["folder:a", "folder:b"]],
      ["folder:a", "root:r"],
      ["folder:b", "root:r"],
    ]);
    const resolveMulti = parentPointerResolver((s) => multi.get(s) ?? null);
    expect(resolveMulti("doc:1")).toEqual([
      "folder:a",
      "folder:b",
      "root:r",
      "*",
    ]);
  });

  it("terminates (throws) on a parent cycle rather than hanging", () => {
    const cyclic = new Map<string, string>([
      ["a:1", "b:1"],
      ["b:1", "a:1"],
    ]);
    const resolveCyclic = parentPointerResolver((s) => cyclic.get(s) ?? null);
    // A two-node cycle is fully deduped by the seen-set, so it terminates.
    expect(resolveCyclic("a:1")).toEqual(["b:1", "*"]);
  });
});
