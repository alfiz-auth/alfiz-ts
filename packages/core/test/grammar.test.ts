import { describe, expect, it } from "vitest";
import {
  anyPatternMatchesKey,
  isValidKey,
  isValidPattern,
  isWildcard,
  namespaceOf,
  patternMatchesKey,
  patternsIntersect,
  subtreePattern,
  validateKey,
  validatePattern,
} from "../src/grammar.js";

describe("key validation", () => {
  it("accepts dot-separated snake_case keys", () => {
    expect(isValidKey("mathaniyy.approvals.decide_student")).toBe(true);
    expect(isValidKey("admin.access.read")).toBe(true);
    expect(isValidKey("alfiz_internal.requests.decide_request")).toBe(true);
  });

  it("accepts camelCase segments (lint, not grammar, enforces style)", () => {
    expect(isValidKey("admin.skipCodes.issue")).toBe(true);
  });

  it("accepts arbitrary depth (the 3-level convention is a lint concern)", () => {
    expect(isValidKey("a.b.c.d.e")).toBe(true);
    expect(isValidKey("read")).toBe(true);
  });

  it("rejects malformed keys", () => {
    expect(isValidKey("")).toBe(false);
    expect(isValidKey("a..b")).toBe(false);
    expect(isValidKey(".a")).toBe(false);
    expect(isValidKey("a.")).toBe(false);
    expect(isValidKey("a b.c")).toBe(false);
    expect(isValidKey("1a.b")).toBe(false);
    expect(isValidKey("a.*")).toBe(false); // wildcard is not a key
    expect(isValidKey("*")).toBe(false);
    expect(isValidKey("a.b-c")).toBe(false);
  });

  it("explains what is wrong", () => {
    expect(validateKey("a.*")?.reason).toMatch(/wildcard/i);
    expect(validateKey("a..b")?.reason).toMatch(/segment/i);
  });
});

describe("pattern validation", () => {
  it("accepts keys, subtree wildcards, and the bare star", () => {
    expect(isValidPattern("*")).toBe(true);
    expect(isValidPattern("mathaniyy.*")).toBe(true);
    expect(isValidPattern("mathaniyy.approvals.*")).toBe(true);
    expect(isValidPattern("mathaniyy.approvals.decide_student")).toBe(true);
  });

  it("rejects infix and malformed wildcards", () => {
    expect(isValidPattern("a.*.b")).toBe(false);
    expect(isValidPattern("*.b")).toBe(false);
    expect(isValidPattern("a*")).toBe(false);
    expect(isValidPattern("a.b*")).toBe(false);
    expect(isValidPattern("")).toBe(false);
    expect(isValidPattern("**")).toBe(false);
    expect(validatePattern("a.*.b")?.reason).toMatch(/final/i);
  });

  it("classifies wildcards", () => {
    expect(isWildcard("*")).toBe(true);
    expect(isWildcard("a.*")).toBe(true);
    expect(isWildcard("a.b.c")).toBe(false);
  });
});

describe("patternMatchesKey", () => {
  it("star matches everything", () => {
    expect(patternMatchesKey("*", "a.b.c")).toBe(true);
    expect(patternMatchesKey("*", "read")).toBe(true);
  });

  it("subtree wildcards match strictly-deeper keys at any depth (forward-inclusive)", () => {
    expect(patternMatchesKey("mathaniyy.*", "mathaniyy.approvals.decide_student")).toBe(true);
    expect(patternMatchesKey("mathaniyy.approvals.*", "mathaniyy.approvals.read_student")).toBe(true);
    expect(patternMatchesKey("a.*", "a.b.c.d.e")).toBe(true);
  });

  it("a group wildcard never matches the group itself", () => {
    expect(patternMatchesKey("a.*", "a")).toBe(false);
    expect(patternMatchesKey("a.b.*", "a.b")).toBe(false);
  });

  it("prefix matching is segment-aware, not string-prefix", () => {
    expect(patternMatchesKey("mathaniyy.*", "mathaniyy2.approvals.read")).toBe(false);
    expect(patternMatchesKey("a.b.*", "a.bc.d")).toBe(false);
  });

  it("concrete patterns match only the identical key", () => {
    expect(patternMatchesKey("a.b.c", "a.b.c")).toBe(true);
    expect(patternMatchesKey("a.b.c", "a.b.d")).toBe(false);
    expect(patternMatchesKey("a.b.c", "a.b")).toBe(false);
    expect(patternMatchesKey("a.b", "a.b.c")).toBe(false);
  });

  it("anyPatternMatchesKey unions patterns", () => {
    expect(anyPatternMatchesKey(["x.y.z", "a.*"], "a.b.c")).toBe(true);
    expect(anyPatternMatchesKey(["x.y.z", "a.*"], "b.c.d")).toBe(false);
    expect(anyPatternMatchesKey([], "a.b.c")).toBe(false);
  });
});

describe("patternsIntersect", () => {
  it("star intersects everything", () => {
    expect(patternsIntersect("*", "a.b")).toBe(true);
    expect(patternsIntersect("a.*", "*")).toBe(true);
    expect(patternsIntersect("*", "*")).toBe(true);
  });

  it("wildcard vs concrete follows matching", () => {
    expect(patternsIntersect("a.*", "a.b.c")).toBe(true);
    expect(patternsIntersect("a.b.c", "a.*")).toBe(true);
    expect(patternsIntersect("a.*", "b.c")).toBe(false);
    // `a.*` cannot match the group node `a` itself
    expect(patternsIntersect("a.*", "a")).toBe(false);
  });

  it("nested wildcards intersect; sibling wildcards do not", () => {
    expect(patternsIntersect("a.*", "a.b.*")).toBe(true);
    expect(patternsIntersect("a.b.*", "a.*")).toBe(true);
    expect(patternsIntersect("a.*", "b.*")).toBe(false);
    expect(patternsIntersect("a.b.*", "a.c.*")).toBe(false);
  });

  it("wildcard prefix comparison is segment-aware", () => {
    expect(patternsIntersect("a.*", "ab.*")).toBe(false);
    expect(patternsIntersect("a.b.*", "a.bc.*")).toBe(false);
  });

  it("concrete keys intersect only when equal", () => {
    expect(patternsIntersect("a.b", "a.b")).toBe(true);
    expect(patternsIntersect("a.b", "a.c")).toBe(false);
  });
});

describe("helpers", () => {
  it("namespaceOf", () => {
    expect(namespaceOf("mathaniyy.approvals.read")).toBe("mathaniyy");
    expect(namespaceOf("mathaniyy.*")).toBe("mathaniyy");
    expect(namespaceOf("*")).toBe(null);
  });

  it("subtreePattern", () => {
    expect(subtreePattern("a.b")).toBe("a.b.*");
  });
});
