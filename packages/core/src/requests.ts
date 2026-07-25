/**
 * Access requests: a request is a proposed grant tuple plus a justification
 * payload and a workflow state. Approval IS the act of writing the grant row,
 * with provenance linking it to the request; denial writes nothing. The
 * request system adds no new access semantics.
 *
 * The request object is part of the provider contract, so its shape is
 * identical against every provider. Policies reference *stages* ("2 layers
 * up"), never resolved approver identities — they resolve against the
 * hierarchy at evaluation time, which is what lets pending requests survive
 * org-root promotion untouched.
 */

import type { PermissionPattern } from "./grammar.js";
import { patternMatchesKey, patternsIntersect } from "./grammar.js";
import type { ScopeId } from "./scopes.js";
import type { SubjectId } from "./subjects.js";
import { groupSubject, orgSubject } from "./subjects.js";
import type { CheckContext, GrantRow, Provenance } from "./access.js";
import { isExpired, patternsOfGrant } from "./access.js";

// ---------------------------------------------------------------------------
// Justification prompts
// ---------------------------------------------------------------------------

export interface RequestPromptInput {
  id: string;
  label: string;
  kind?: "text" | "select";
  /** For `select` prompts. */
  options?: readonly string[];
  required?: boolean;
}

// ---------------------------------------------------------------------------
// Approval policies
// ---------------------------------------------------------------------------

/**
 * A condition on the requester evaluated against their subject closure —
 * the same evaluation machinery as `can()`; no separate rules engine exists.
 */
export type AutoApprovalPredicate =
  | { type: "in_group"; groupId: string }
  | { type: "in_org"; orgId: string }
  /** Membership in any subject — including implicit groups (`directs:<uid>`, `orgof:<uid>`): "auto-approve my team". */
  | { type: "member_of"; subject: SubjectId }
  /** The requester's effective access already intersects this pattern. */
  | { type: "holds_pattern"; pattern: PermissionPattern };

export type ApprovalStage =
  /** Auto-approval predicate: passes or falls through to the next stage. */
  | { kind: "auto"; predicate: AutoApprovalPredicate }
  /** Approval by any subject holding a designated role (canonically the application owner). */
  | { kind: "named_approvers"; roleId: string }
  /**
   * Approval by the requester's manager, or `layers` transitive layers
   * upward (1 = direct manager), resolved by walking the reporting edges at
   * evaluation time. Where the chain is shorter than `layers`, the topmost
   * manager approves.
   */
  | { kind: "management"; layers?: number };

export interface ApprovalPolicyInput {
  /** Ordered stages; every non-auto stage requires an explicit decision. */
  stages: readonly ApprovalStage[];
}

// ---------------------------------------------------------------------------
// The request object (wire shape)
// ---------------------------------------------------------------------------

export type RequestState = "pending" | "approved" | "denied" | "cancelled";

export interface RequestDecision {
  stageIndex: number;
  /** A user id, or `"auto"` for a passed auto-approval stage. */
  decidedBy: string;
  decision: "approved" | "denied";
  at: number;
  note?: string | undefined;
}

/** A proposed grant tuple plus justification and workflow state. */
export interface AccessRequest {
  id: string;
  requesterUserId: string;
  /** Exactly one of roleId / pattern — the same rule as the grant row. */
  roleId?: string | undefined;
  pattern?: PermissionPattern | undefined;
  scope: ScopeId;
  /** Proposed expiry for time-bound / just-in-time access. */
  proposedExpiresAt?: number | undefined;
  /** Prompt id → answer, per the requestability declaration's prompts. */
  justification: Record<string, string>;
  state: RequestState;
  /** Index of the stage currently awaiting a decision (meaningful while pending). */
  stageIndex: number;
  /**
   * The policy stages snapshotted at submission. Stages reference layers and
   * roles, never people, so they survive hierarchy changes and org-root
   * promotion; they resolve at evaluation.
   */
  stages: readonly ApprovalStage[];
  decisions: readonly RequestDecision[];
  createdAt: number;
  decidedAt?: number | undefined;
}

// ---------------------------------------------------------------------------
// Pure evaluation
// ---------------------------------------------------------------------------

/**
 * Evaluates an auto-approval predicate against the requester's closure and
 * rows — deliberately the `can()` machinery, not a rules engine.
 */
export function evaluateAutoPredicate(
  predicate: AutoApprovalPredicate,
  requester: CheckContext,
): boolean {
  switch (predicate.type) {
    case "in_group":
      return requester.subjectClosure.has(groupSubject(predicate.groupId));
    case "in_org":
      return requester.subjectClosure.has(orgSubject(predicate.orgId));
    case "member_of":
      return requester.subjectClosure.has(predicate.subject);
    case "holds_pattern": {
      for (const grant of requester.rows.grants) {
        if (!requester.subjectClosure.has(grant.subject)) continue;
        if (isExpired(grant, requester.now)) continue;
        for (const granted of patternsOfGrant(grant, requester.rows.roles)) {
          if (patternsIntersect(granted, predicate.pattern)) return true;
        }
      }
      return false;
    }
  }
}

/**
 * May `decider` decide the given stage of `request`?
 *
 * - `named_approvers`: the decider holds an unexpired grant of the designated
 *   role (directly or through any closure member).
 * - `management`: the decider is the requester's manager at the stage's layer
 *   (clamped to the top of the chain when the chain is shorter).
 * - `auto` stages are never decided by people.
 */
export function canDecideStage(
  stage: ApprovalStage,
  decider: { userId: string; ctx: CheckContext },
  requesterManagerChain: readonly string[],
): boolean {
  switch (stage.kind) {
    case "auto":
      return false;
    case "named_approvers": {
      for (const grant of decider.ctx.rows.grants) {
        if (!decider.ctx.subjectClosure.has(grant.subject)) continue;
        if (isExpired(grant, decider.ctx.now)) continue;
        if (grant.roleId === stage.roleId) return true;
      }
      return false;
    }
    case "management": {
      const layers = stage.layers ?? 1;
      if (requesterManagerChain.length === 0) return false;
      const idx = Math.min(layers, requesterManagerChain.length) - 1;
      return requesterManagerChain[idx] === decider.userId;
    }
  }
}

export interface StageAdvanceResult {
  request: AccessRequest;
  /** Set when the final stage approved: the row to write, with provenance. */
  grantPlan?: Omit<GrantRow, "id"> | undefined;
}

export class RequestStateError extends Error {
  override name = "RequestStateError";
}

/**
 * Applies a decision to the request's current stage. Approving the final
 * stage yields the grant plan — approval IS row creation; the provider
 * assigns the id, writes the row, and audits, atomically with the state
 * change. Denial at any stage is final and writes nothing.
 */
export function applyDecision(
  request: AccessRequest,
  decision: {
    decidedBy: string;
    decision: "approved" | "denied";
    at: number;
    note?: string | undefined;
  },
): StageAdvanceResult {
  if (request.state !== "pending") {
    throw new RequestStateError(
      `request ${request.id} is ${request.state}, not pending`,
    );
  }
  const record: RequestDecision = {
    stageIndex: request.stageIndex,
    decidedBy: decision.decidedBy,
    decision: decision.decision,
    at: decision.at,
    note: decision.note,
  };
  const decisions = [...request.decisions, record];

  if (decision.decision === "denied") {
    return {
      request: {
        ...request,
        state: "denied",
        decisions,
        decidedAt: decision.at,
      },
    };
  }

  const nextStage = request.stageIndex + 1;
  if (nextStage < request.stages.length) {
    return {
      request: { ...request, stageIndex: nextStage, decisions },
    };
  }
  const provenance: Provenance = {
    kind: "request",
    requestId: request.id,
    ...(decision.decidedBy === "auto" ? {} : { approvedBy: decision.decidedBy }),
  };
  return {
    request: {
      ...request,
      state: "approved",
      decisions,
      decidedAt: decision.at,
    },
    grantPlan: {
      subject: `user:${request.requesterUserId}`,
      roleId: request.roleId,
      pattern: request.pattern,
      scope: request.scope,
      expiresAt: request.proposedExpiresAt,
      provenance,
      createdAt: decision.at,
    },
  };
}

/**
 * Runs consecutive auto stages from the request's current stage: each passing
 * predicate records an `auto` approval and advances; the first failing
 * predicate simply falls through to the next stage (auto stages gate nothing
 * — they accelerate). Returns the settled request (possibly fully approved
 * with a grant plan).
 */
export function runAutoStages(
  request: AccessRequest,
  requester: CheckContext,
  now: number,
): StageAdvanceResult {
  let current: AccessRequest = request;
  let plan: StageAdvanceResult["grantPlan"];
  while (current.state === "pending") {
    const stage = current.stages[current.stageIndex];
    if (!stage || stage.kind !== "auto") break;
    if (evaluateAutoPredicate(stage.predicate, requester)) {
      const advanced = applyDecision(current, {
        decidedBy: "auto",
        decision: "approved",
        at: now,
      });
      current = advanced.request;
      plan = advanced.grantPlan;
    } else {
      // Predicate not met: the auto stage abstains; move to the next stage
      // without recording a decision.
      if (current.stageIndex + 1 >= current.stages.length) {
        // Nothing after the failed auto stage can approve this request; it
        // stays pending at a stage no one can decide unless a later stage
        // exists. Guard: a policy whose stages are exhausted without approval
        // remains pending for explicit administrative decision.
        break;
      }
      current = { ...current, stageIndex: current.stageIndex + 1 };
    }
  }
  return plan !== undefined
    ? { request: current, grantPlan: plan }
    : { request: current };
}

/**
 * Validates a request's justification against the requestability
 * declaration's prompts: required prompts answered, select answers among the
 * declared options.
 */
export function validateJustification(
  prompts: readonly RequestPromptInput[],
  justification: Record<string, string>,
): string[] {
  const problems: string[] = [];
  for (const prompt of prompts) {
    const answer = justification[prompt.id];
    if ((answer === undefined || answer === "") && prompt.required !== false) {
      problems.push(`missing answer for ${JSON.stringify(prompt.id)}`);
      continue;
    }
    if (
      answer !== undefined &&
      prompt.kind === "select" &&
      prompt.options !== undefined &&
      !prompt.options.includes(answer)
    ) {
      problems.push(
        `answer for ${JSON.stringify(prompt.id)} is not one of the declared options`,
      );
    }
  }
  return problems;
}

/** Convenience for surfacing what a pattern-shaped request would confer. */
export function requestMatchesKey(
  request: AccessRequest,
  key: string,
  rolePatterns: readonly PermissionPattern[] | undefined,
): boolean {
  if (request.pattern !== undefined) return patternMatchesKey(request.pattern, key);
  return (rolePatterns ?? []).some((p) => patternMatchesKey(p, key));
}
