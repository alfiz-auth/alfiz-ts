import { describe, expect, it } from "vitest";
import type { CheckContext, GrantRow } from "../src/access.js";
import type { AccessRequest, ApprovalStage } from "../src/requests.js";
import {
  applyDecision,
  canDecideStage,
  evaluateAutoPredicate,
  runAutoStages,
  validateJustification,
} from "../src/requests.js";

const NOW = 5_000_000;
let seq = 0;

const grant = (
  subject: string,
  what: { pattern?: string; roleId?: string },
  scope = "*",
): GrantRow => ({
  id: `g${++seq}`,
  subject,
  pattern: what.pattern,
  roleId: what.roleId,
  scope,
  provenance: { kind: "admin", actorUserId: "root" },
  createdAt: NOW - 1,
});

const ctxOf = (
  userId: string,
  closure: string[],
  grants: GrantRow[] = [],
): CheckContext => ({
  subjectClosure: new Set(closure),
  userId,
  rows: { grants, revokes: [], roles: new Map() },
  now: NOW,
});

const request = (stages: ApprovalStage[]): AccessRequest => ({
  id: "req1",
  requesterUserId: "u1",
  pattern: "docs.files.read",
  scope: "docs.folder:9",
  justification: {},
  state: "pending",
  stageIndex: 0,
  stages,
  decisions: [],
  createdAt: NOW - 100,
});

describe("evaluateAutoPredicate", () => {
  it("in_group / in_org / member_of read the closure", () => {
    const ctx = ctxOf("u1", ["user:u1", "group:teachers", "org:acme", "orgof:jane", "everyone"]);
    expect(evaluateAutoPredicate({ type: "in_group", groupId: "teachers" }, ctx)).toBe(true);
    expect(evaluateAutoPredicate({ type: "in_group", groupId: "admins" }, ctx)).toBe(false);
    expect(evaluateAutoPredicate({ type: "in_org", orgId: "acme" }, ctx)).toBe(true);
    expect(evaluateAutoPredicate({ type: "member_of", subject: "orgof:jane" }, ctx)).toBe(true);
    expect(evaluateAutoPredicate({ type: "member_of", subject: "directs:jane" }, ctx)).toBe(false);
  });

  it("holds_pattern intersects effective grants", () => {
    const ctx = ctxOf("u1", ["user:u1", "everyone"], [grant("user:u1", { pattern: "docs.*" })]);
    expect(evaluateAutoPredicate({ type: "holds_pattern", pattern: "docs.files.read" }, ctx)).toBe(true);
    expect(evaluateAutoPredicate({ type: "holds_pattern", pattern: "billing.*" }, ctx)).toBe(false);
  });
});

describe("canDecideStage", () => {
  it("named_approvers requires holding the designated role", () => {
    const stage: ApprovalStage = { kind: "named_approvers", roleId: "owner" };
    const holder = { userId: "boss", ctx: ctxOf("boss", ["user:boss", "everyone"], [grant("user:boss", { roleId: "owner" })]) };
    const bystander = { userId: "u9", ctx: ctxOf("u9", ["user:u9", "everyone"]) };
    expect(canDecideStage(stage, holder, [])).toBe(true);
    expect(canDecideStage(stage, bystander, [])).toBe(false);
  });

  it("role held through a group counts", () => {
    const stage: ApprovalStage = { kind: "named_approvers", roleId: "owner" };
    const viaGroup = {
      userId: "boss",
      ctx: ctxOf("boss", ["user:boss", "group:leads", "everyone"], [grant("group:leads", { roleId: "owner" })]),
    };
    expect(canDecideStage(stage, viaGroup, [])).toBe(true);
  });

  it("management resolves the requester's chain at the stage's layer", () => {
    const chain = ["jane", "omar", "ceo"];
    const decider = (userId: string) => ({ userId, ctx: ctxOf(userId, [`user:${userId}`, "everyone"]) });
    expect(canDecideStage({ kind: "management" }, decider("jane"), chain)).toBe(true);
    expect(canDecideStage({ kind: "management" }, decider("omar"), chain)).toBe(false);
    expect(canDecideStage({ kind: "management", layers: 2 }, decider("omar"), chain)).toBe(true);
    // Clamped to the top when the chain is shorter than the layer.
    expect(canDecideStage({ kind: "management", layers: 9 }, decider("ceo"), chain)).toBe(true);
    // Empty chain: nobody can fill the stage.
    expect(canDecideStage({ kind: "management" }, decider("jane"), [])).toBe(false);
  });

  it("auto stages are never people-decidable", () => {
    expect(
      canDecideStage(
        { kind: "auto", predicate: { type: "in_group", groupId: "g" } },
        { userId: "u", ctx: ctxOf("u", ["user:u"]) },
        [],
      ),
    ).toBe(false);
  });
});

describe("applyDecision", () => {
  it("denial at any stage is final and plans no grant", () => {
    const req = request([{ kind: "management" }, { kind: "named_approvers", roleId: "owner" }]);
    const result = applyDecision(req, { decidedBy: "jane", decision: "denied", at: NOW });
    expect(result.request.state).toBe("denied");
    expect(result.grantPlan).toBeUndefined();
    expect(result.request.decidedAt).toBe(NOW);
  });

  it("approval advances stages; final approval plans the grant with provenance", () => {
    const req = request([{ kind: "management" }, { kind: "named_approvers", roleId: "owner" }]);
    const mid = applyDecision(req, { decidedBy: "jane", decision: "approved", at: NOW });
    expect(mid.request.state).toBe("pending");
    expect(mid.request.stageIndex).toBe(1);
    expect(mid.grantPlan).toBeUndefined();

    const done = applyDecision(mid.request, { decidedBy: "boss", decision: "approved", at: NOW + 1 });
    expect(done.request.state).toBe("approved");
    expect(done.grantPlan).toEqual({
      subject: "user:u1",
      roleId: undefined,
      pattern: "docs.files.read",
      scope: "docs.folder:9",
      expiresAt: undefined,
      provenance: { kind: "request", requestId: "req1", approvedBy: "boss" },
      createdAt: NOW + 1,
    });
    expect(done.request.decisions.length).toBe(2);
  });

  it("a proposed expiry rides into the grant plan (just-in-time access)", () => {
    const req = { ...request([{ kind: "management" } as ApprovalStage]), proposedExpiresAt: NOW + 3_600_000 };
    const done = applyDecision(req, { decidedBy: "jane", decision: "approved", at: NOW });
    expect(done.grantPlan?.expiresAt).toBe(NOW + 3_600_000);
  });

  it("rejects decisions on settled requests", () => {
    const req = { ...request([{ kind: "management" } as ApprovalStage]), state: "denied" as const };
    expect(() => applyDecision(req, { decidedBy: "x", decision: "approved", at: NOW })).toThrow(/not pending/);
  });
});

describe("runAutoStages", () => {
  const teacherCtx = ctxOf("u1", ["user:u1", "group:teachers", "everyone"]);

  it("a passing predicate approves and can settle the whole request", () => {
    const req = request([{ kind: "auto", predicate: { type: "in_group", groupId: "teachers" } }]);
    const result = runAutoStages(req, teacherCtx, NOW);
    expect(result.request.state).toBe("approved");
    expect(result.grantPlan?.provenance).toEqual({ kind: "request", requestId: "req1" });
    expect(result.request.decisions[0]?.decidedBy).toBe("auto");
  });

  it("a failing predicate falls through to the next stage", () => {
    const req = request([
      { kind: "auto", predicate: { type: "in_group", groupId: "admins" } },
      { kind: "management" },
    ]);
    const result = runAutoStages(req, teacherCtx, NOW);
    expect(result.request.state).toBe("pending");
    expect(result.request.stageIndex).toBe(1);
    expect(result.request.decisions).toEqual([]);
  });

  it("consecutive autos chain into human stages", () => {
    const req = request([
      { kind: "auto", predicate: { type: "in_group", groupId: "teachers" } },
      { kind: "named_approvers", roleId: "owner" },
    ]);
    const result = runAutoStages(req, teacherCtx, NOW);
    expect(result.request.state).toBe("pending");
    expect(result.request.stageIndex).toBe(1);
    expect(result.request.decisions.length).toBe(1);
  });

  it("a failing sole auto stage leaves the request pending for admin decision", () => {
    const req = request([{ kind: "auto", predicate: { type: "in_group", groupId: "admins" } }]);
    const result = runAutoStages(req, teacherCtx, NOW);
    expect(result.request.state).toBe("pending");
    expect(result.request.stageIndex).toBe(0);
  });
});

describe("validateJustification", () => {
  it("requires answers and validates select options", () => {
    const prompts = [
      { id: "why", label: "Why?" },
      { id: "env", label: "Environment", kind: "select" as const, options: ["prod", "dev"] },
      { id: "note", label: "Optional", required: false },
    ];
    expect(validateJustification(prompts, { why: "need it", env: "prod" })).toEqual([]);
    expect(validateJustification(prompts, { env: "prod" })).toEqual([
      'missing answer for "why"',
    ]);
    expect(validateJustification(prompts, { why: "x", env: "staging" })).toEqual([
      'answer for "env" is not one of the declared options',
    ]);
  });
});
