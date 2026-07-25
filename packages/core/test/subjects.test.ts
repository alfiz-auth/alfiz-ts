import { describe, expect, it } from "vitest";
import {
  EVERYONE,
  computeServiceClosure,
  computeSubjectClosure,
  directsSubject,
  groupSubject,
  implicitGroupMembers,
  isImplicitGroupSubject,
  managerChainOf,
  orgOfSubject,
  orgSubject,
  parseSubject,
  serviceSubject,
  userSubject,
} from "../src/subjects.js";

describe("subject ids", () => {
  it("encodes and parses", () => {
    expect(userSubject("u1")).toBe("user:u1");
    expect(parseSubject("user:u1")).toEqual({ kind: "user", id: "u1" });
    expect(parseSubject("everyone")).toEqual({ kind: "everyone", id: "" });
    expect(parseSubject("directs:jane")).toEqual({ kind: "directs", id: "jane" });
    expect(parseSubject("bogus:1")).toBe(null);
    expect(parseSubject("user:")).toBe(null);
    expect(parseSubject("")).toBe(null);
  });

  it("classifies implicit groups", () => {
    expect(isImplicitGroupSubject(directsSubject("jane"))).toBe(true);
    expect(isImplicitGroupSubject(orgOfSubject("jane"))).toBe(true);
    expect(isImplicitGroupSubject(groupSubject("g1"))).toBe(false);
    expect(isImplicitGroupSubject(EVERYONE)).toBe(false);
  });
});

describe("computeSubjectClosure", () => {
  it("minimal user: self + everyone", () => {
    const closure = computeSubjectClosure({ userId: "u1", groupIds: [] });
    expect(closure).toEqual(new Set(["user:u1", "everyone"]));
  });

  it("includes explicit groups and all their ancestors", () => {
    const closure = computeSubjectClosure({
      userId: "u1",
      groupIds: ["teachers"],
      groupParents: new Map([
        ["teachers", ["staff"]],
        ["staff", ["everyone_group"]],
      ]),
    });
    expect(closure.has(groupSubject("teachers"))).toBe(true);
    expect(closure.has(groupSubject("staff"))).toBe(true);
    expect(closure.has(groupSubject("everyone_group"))).toBe(true);
  });

  it("is cycle-safe on malformed group graphs", () => {
    const closure = computeSubjectClosure({
      userId: "u1",
      groupIds: ["a"],
      groupParents: new Map([
        ["a", ["b"]],
        ["b", ["a"]],
      ]),
    });
    expect(closure.has(groupSubject("a"))).toBe(true);
    expect(closure.has(groupSubject("b"))).toBe(true);
  });

  it("derives implicit groups from the manager chain", () => {
    const closure = computeSubjectClosure({
      userId: "u1",
      groupIds: [],
      managerChain: ["jane", "omar"],
    });
    // Direct manager: member of jane's directs and jane's org.
    expect(closure.has(directsSubject("jane"))).toBe(true);
    expect(closure.has(orgOfSubject("jane"))).toBe(true);
    // Transitive: member of omar's org, but NOT omar's directs.
    expect(closure.has(orgOfSubject("omar"))).toBe(true);
    expect(closure.has(directsSubject("omar"))).toBe(false);
  });

  it("includes organizations", () => {
    const closure = computeSubjectClosure({
      userId: "u1",
      groupIds: [],
      orgIds: ["acme"],
    });
    expect(closure.has(orgSubject("acme"))).toBe(true);
  });
});

describe("managerChainOf", () => {
  const edges = new Map([
    ["u1", "jane"],
    ["jane", "omar"],
    ["omar", "ceo"],
  ]);

  it("walks nearest-first to the root", () => {
    expect(managerChainOf("u1", edges)).toEqual(["jane", "omar", "ceo"]);
    expect(managerChainOf("ceo", edges)).toEqual([]);
  });

  it("is cycle-safe", () => {
    const cyclic = new Map([
      ["a", "b"],
      ["b", "a"],
    ]);
    expect(managerChainOf("a", cyclic)).toEqual(["b"]);
  });
});

describe("implicitGroupMembers", () => {
  const edges = new Map([
    ["u1", "jane"],
    ["u2", "jane"],
    ["u3", "u1"],
    ["jane", "omar"],
  ]);

  it("directs: only direct reports", () => {
    expect(implicitGroupMembers(directsSubject("jane"), edges)).toEqual(
      new Set(["u1", "u2"]),
    );
  });

  it("orgof: transitive reports, excluding the manager", () => {
    expect(implicitGroupMembers(orgOfSubject("jane"), edges)).toEqual(
      new Set(["u1", "u2", "u3"]),
    );
    expect(implicitGroupMembers(orgOfSubject("omar"), edges)).toEqual(
      new Set(["jane", "u1", "u2", "u3"]),
    );
  });

  it("rejects non-implicit subjects", () => {
    expect(() => implicitGroupMembers("group:g1", edges)).toThrow();
  });
});

describe("computeServiceClosure", () => {
  it("service principal: itself + everyone", () => {
    expect(computeServiceClosure("cron")).toEqual(
      new Set([serviceSubject("cron"), "everyone"]),
    );
  });
});
