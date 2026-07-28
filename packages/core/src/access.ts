/**
 * Everything reduces to the grant row. Roles, groups, public access, machine
 * scopes, approved access requests, and provisioned integrations are all
 * expressed as, or resolve to, the one atomic tuple:
 *
 *   (subject, role-or-permission-pattern, scope, expiry?)
 *
 * The single negative layer is the personal revoke, and it always wins —
 * scope-inclusively: a revoke at any scope suppresses matching access at that
 * scope and every descendant scope, regardless of where the positive grant
 * sits. This is fixed, not configurable.
 */

import type { PermissionKey, PermissionPattern } from "./grammar.js";
import { patternMatchesKey } from "./grammar.js";
import type { ScopeId } from "./scopes.js";
import { GLOBAL_SCOPE } from "./scopes.js";
import type { SubjectId } from "./subjects.js";

/** Who or what created a row. Every grant and revoke carries provenance. */
export type Provenance =
  | { kind: "admin"; actorUserId: string }
  | { kind: "request"; requestId: string; approvedBy?: string }
  | { kind: "dissolution"; virtualParentId: string; originalGrantId: string }
  | { kind: "merge"; source: string }
  | { kind: "import"; source: string }
  | { kind: "reconciler"; integrationId: string }
  | { kind: "system"; note?: string };

/**
 * The atomic grant tuple. Exactly one of `roleId` / `pattern` is set: a grant
 * either names a role (whose patterns it confers) or carries a raw pattern.
 */
export interface GrantRow {
  id: string;
  subject: SubjectId;
  roleId?: string | undefined;
  pattern?: PermissionPattern | undefined;
  /** Scope instance id, or `*`. A grant with no scope is a grant at `*`. */
  scope: ScopeId;
  /** Epoch ms. An expired grant stops matching exactly as a deleted one would, but remains for audit. */
  expiresAt?: number | undefined;
  provenance: Provenance;
  createdAt: number;
}

/** Personal-only: only individual users may hold revokes. */
export interface RevokeRow {
  id: string;
  userId: string;
  pattern: PermissionPattern;
  scope: ScopeId;
  provenance: Provenance;
  createdAt: number;
}

/** A named bundle of positive permission patterns. Identity is the opaque id — renaming never breaks assignments. Roles carry no negative patterns. */
export interface RoleDef {
  id: string;
  name: string;
  description?: string | undefined;
  patterns: PermissionPattern[];
}

/** Every provenance kind, for validation and error messages. */
export const PROVENANCE_KINDS = [
  "admin",
  "request",
  "dissolution",
  "merge",
  "import",
  "reconciler",
  "system",
] as const;

/**
 * Provenance is a required input on every write, and the one that used to
 * go unchecked: a missing `actorUserId` (a JS caller, a wrapper whose
 * argument went missing, an `as any` upstream) sailed through the write
 * path and failed deep inside the audit writer, as a driver-level error
 * naming a column the developer never wrote. Validated here so it is
 * rejected where patterns, scopes, and role references are — with a
 * message naming the field.
 *
 * Returns `null` when valid, else the human-readable reason.
 */
export function validateProvenance(provenance: Provenance): string | null {
  if (provenance === null || typeof provenance !== "object") {
    return `provenance is required: an object with a kind of ${PROVENANCE_KINDS.join(" | ")}`;
  }
  const kind = (provenance as { kind?: unknown }).kind;
  if (typeof kind !== "string") {
    return `provenance.kind is required (${PROVENANCE_KINDS.join(" | ")})`;
  }
  const required = (field: string, value: unknown): string | null =>
    typeof value === "string" && value !== ""
      ? null
      : `provenance.${field} is required for kind ${JSON.stringify(kind)}`;

  switch (kind) {
    case "admin":
      return required("actorUserId", (provenance as { actorUserId?: unknown }).actorUserId);
    case "request": {
      const p = provenance as { requestId?: unknown; approvedBy?: unknown };
      const issue = required("requestId", p.requestId);
      if (issue) return issue;
      return p.approvedBy === undefined || typeof p.approvedBy === "string"
        ? null
        : `provenance.approvedBy must be a user id when present`;
    }
    case "dissolution": {
      const p = provenance as {
        virtualParentId?: unknown;
        originalGrantId?: unknown;
      };
      return (
        required("virtualParentId", p.virtualParentId) ??
        required("originalGrantId", p.originalGrantId)
      );
    }
    case "merge":
    case "import":
      return required("source", (provenance as { source?: unknown }).source);
    case "reconciler":
      return required(
        "integrationId",
        (provenance as { integrationId?: unknown }).integrationId,
      );
    case "system": {
      const note = (provenance as { note?: unknown }).note;
      return note === undefined || typeof note === "string"
        ? null
        : "provenance.note must be a string when present";
    }
    default:
      return `unknown provenance kind ${JSON.stringify(kind)} (expected ${PROVENANCE_KINDS.join(" | ")})`;
  }
}

export interface GrantRowIssue {
  rowId: string;
  reason: string;
}

export function validateGrantRow(row: GrantRow): GrantRowIssue | null {
  const hasRole = row.roleId !== undefined && row.roleId !== "";
  const hasPattern = row.pattern !== undefined && row.pattern !== "";
  if (hasRole === hasPattern) {
    return {
      rowId: row.id,
      reason: "a grant carries exactly one of roleId / pattern",
    };
  }
  return null;
}

export function isExpired(
  row: { expiresAt?: number | undefined },
  now: number,
): boolean {
  return row.expiresAt !== undefined && row.expiresAt <= now;
}

/** The patterns a grant confers: its own, or its role's. Unknown roles confer nothing. */
export function patternsOfGrant(
  row: GrantRow,
  roles: ReadonlyMap<string, RoleDef>,
): readonly PermissionPattern[] {
  // Empty-string pattern is "absent", exactly as validateGrantRow treats it —
  // a role grant with pattern:"" resolves through the role, not to nothing.
  if (row.pattern !== undefined && row.pattern !== "") return [row.pattern];
  if (row.roleId !== undefined && row.roleId !== "") {
    return roles.get(row.roleId)?.patterns ?? [];
  }
  return [];
}

/** The row inputs to an evaluation: provider-supplied, pre-filtered or not. */
export interface AccessRows {
  grants: readonly GrantRow[];
  revokes: readonly RevokeRow[];
  roles: ReadonlyMap<string, RoleDef>;
}

export interface CheckContext {
  /** The subject closure of whoever is being checked. */
  subjectClosure: ReadonlySet<SubjectId>;
  /** The user id, when the subject is a person — personal revokes apply. `null` for machine subjects. */
  userId: string | null;
  rows: AccessRows;
  /** Evaluation instant (epoch ms) for expiry filtering. */
  now: number;
  /**
   * The scope-type system at check time: whether a grant made at
   * `grantScope` may confer `key` there. The Client derives this from the
   * catalog (a leaf applies at a non-global grant scope only when it
   * declares that scope type), which closes the hole where a wildcard or
   * role grant at a narrow scope would otherwise confer keys the catalog
   * never made grantable there. Absent = every matched key applies.
   */
  grantApplies?: ((key: PermissionKey, grantScope: ScopeId) => boolean) | undefined;
}

/**
 * The check: does any unexpired grant row connect a member of the subject
 * closure to a member of the object closure, whose pattern (directly or via
 * the named role's patterns) matches the permission — with no personal revoke
 * at any scope in the object closure suppressing it?
 */
export function checkKey(
  ctx: CheckContext,
  key: PermissionKey,
  objectClosure: readonly ScopeId[],
): boolean {
  return explainKey(ctx, key, objectClosure).allowed;
}

export interface CheckExplanation {
  allowed: boolean;
  /** Unexpired grants that would allow the key at this scope. */
  matchedGrants: GrantRow[];
  /** Revokes that suppress it (non-empty forces `allowed: false`). */
  matchedRevokes: RevokeRow[];
}

/**
 * `checkKey` with its work shown: which rows matched, which revokes won.
 * This is what keeps effective access auditable — "why can (or can't) X do
 * Y here" is answerable from data, not from re-derivation by hand.
 */
export function explainKey(
  ctx: CheckContext,
  key: PermissionKey,
  objectClosure: readonly ScopeId[],
): CheckExplanation {
  const objects = new Set(objectClosure);
  const matchedRevokes: RevokeRow[] = [];
  if (ctx.userId !== null) {
    for (const revoke of ctx.rows.revokes) {
      if (
        revoke.userId === ctx.userId &&
        objects.has(revoke.scope) &&
        patternMatchesKey(revoke.pattern, key)
      ) {
        matchedRevokes.push(revoke);
      }
    }
  }
  const matchedGrants: GrantRow[] = [];
  for (const grant of ctx.rows.grants) {
    if (!ctx.subjectClosure.has(grant.subject)) continue;
    if (!objects.has(grant.scope)) continue;
    if (isExpired(grant, ctx.now)) continue;
    if (ctx.grantApplies && !ctx.grantApplies(key, grant.scope)) continue;
    for (const pattern of patternsOfGrant(grant, ctx.rows.roles)) {
      if (patternMatchesKey(pattern, key)) {
        matchedGrants.push(grant);
        break;
      }
    }
  }
  return {
    allowed: matchedRevokes.length === 0 && matchedGrants.length > 0,
    matchedGrants,
    matchedRevokes,
  };
}

/**
 * The visibility affordance: does the subject's effective access intersect
 * `pattern` at all, at any scope? Never a gate — every page and action still
 * gates on a concrete permission via `checkKey`.
 *
 * Evaluated precisely against the catalog's concrete keys: the intersection
 * is non-empty iff some catalog key matched by `pattern` is granted by some
 * unexpired row and not fully suppressed by a revoke covering that row's
 * scope subtree. `grantScopeClosures` (grant scope → its object closure)
 * makes revoke suppression exact for scoped grants; without it, suppression
 * is checked at the grant's own scope and `*` only, which can only ever
 * over-show — acceptable for a visibility affordance, and documented.
 */
export function checkAny(
  ctx: CheckContext,
  pattern: PermissionPattern,
  catalogKeys: readonly PermissionKey[],
  grantScopeClosures?: ReadonlyMap<ScopeId, readonly ScopeId[]>,
): boolean {
  const keys = catalogKeys.filter((key) => patternMatchesKey(pattern, key));
  if (keys.length === 0) return false;

  const closureOfGrantScope = (scope: ScopeId): readonly ScopeId[] => {
    const provided = grantScopeClosures?.get(scope);
    if (provided) return provided;
    return scope === GLOBAL_SCOPE ? [GLOBAL_SCOPE] : [scope, GLOBAL_SCOPE];
  };

  for (const key of keys) {
    for (const grant of ctx.rows.grants) {
      if (!ctx.subjectClosure.has(grant.subject)) continue;
      if (isExpired(grant, ctx.now)) continue;
      if (ctx.grantApplies && !ctx.grantApplies(key, grant.scope)) continue;
      let matches = false;
      for (const p of patternsOfGrant(grant, ctx.rows.roles)) {
        if (patternMatchesKey(p, key)) {
          matches = true;
          break;
        }
      }
      if (!matches) continue;
      const grantScopeClosure = new Set(closureOfGrantScope(grant.scope));
      let suppressed = false;
      if (ctx.userId !== null) {
        for (const revoke of ctx.rows.revokes) {
          if (
            revoke.userId === ctx.userId &&
            patternMatchesKey(revoke.pattern, key) &&
            grantScopeClosure.has(revoke.scope)
          ) {
            suppressed = true;
            break;
          }
        }
      }
      if (!suppressed) return true;
    }
  }
  return false;
}

/**
 * Every unexpired, applicable grant row conferring `key` on this subject, at
 * any scope. The row-level form of `grantedScopesFor` — and what ancestor
 * implication (§7.5) needs for attribution: an implied allow never passes
 * through `explainKey`'s matched list, so the rows behind it have to come
 * from somewhere if "which grant allowed this" is to stay answerable.
 */
export function grantsMatchingKey(
  ctx: CheckContext,
  key: PermissionKey,
): GrantRow[] {
  const rows: GrantRow[] = [];
  for (const grant of ctx.rows.grants) {
    if (!ctx.subjectClosure.has(grant.subject)) continue;
    if (isExpired(grant, ctx.now)) continue;
    if (ctx.grantApplies && !ctx.grantApplies(key, grant.scope)) continue;
    for (const pattern of patternsOfGrant(grant, ctx.rows.roles)) {
      if (patternMatchesKey(pattern, key)) {
        rows.push(grant);
        break;
      }
    }
  }
  return rows;
}

/**
 * The listing primitive: the scopes appearing in unexpired grant rows for
 * any member of the subject closure whose patterns match `key`. Push-down
 * filtering ("rows whose ancestor set intersects this") is built from this
 * set — see listing.ts.
 */
export function grantedScopesFor(
  ctx: CheckContext,
  key: PermissionKey,
): Set<ScopeId> {
  const scopes = new Set<ScopeId>();
  for (const grant of grantsMatchingKey(ctx, key)) scopes.add(grant.scope);
  return scopes;
}

/**
 * The "holds it anywhere" probe: does any applicable unexpired grant confer
 * `key` at ANY scope, with only global-scope revokes able to suppress it?
 * (A scoped revoke narrows one subtree; it does not erase a key held
 * elsewhere.) This is the right question for unscoped conditional UI under
 * scoped grants — "should this button exist at all" when the concrete scope
 * is not yet known — and the shared engine behind `holds` and `heldKeys`
 * on the client, the snapshot, and the session snapshot. Never a gate:
 * gates use `checkKey` at a concrete scope.
 */
export function keyHeldAnywhere(ctx: CheckContext, key: PermissionKey): boolean {
  let granted = false;
  for (const grant of ctx.rows.grants) {
    if (!ctx.subjectClosure.has(grant.subject)) continue;
    if (isExpired(grant, ctx.now)) continue;
    if (ctx.grantApplies && !ctx.grantApplies(key, grant.scope)) continue;
    if (
      patternsOfGrant(grant, ctx.rows.roles).some((p) =>
        patternMatchesKey(p, key),
      )
    ) {
      granted = true;
      break;
    }
  }
  if (!granted) return false;
  if (ctx.userId === null) return true;
  return !ctx.rows.revokes.some(
    (r) =>
      r.userId === ctx.userId &&
      r.scope === GLOBAL_SCOPE &&
      patternMatchesKey(r.pattern, key),
  );
}

/** The scopes at which the user holds a matching personal revoke — the exclusion set for listing queries. */
export function revokedScopesFor(
  ctx: CheckContext,
  key: PermissionKey,
): Set<ScopeId> {
  const scopes = new Set<ScopeId>();
  if (ctx.userId === null) return scopes;
  for (const revoke of ctx.rows.revokes) {
    if (revoke.userId === ctx.userId && patternMatchesKey(revoke.pattern, key)) {
      scopes.add(revoke.scope);
    }
  }
  return scopes;
}

/**
 * Dissolving a virtual parent is a snapshot: its grants copy down to each
 * child with provenance, after which the children drift freely. Pure — the
 * provider assigns ids, writes rows, deletes the parent's rows, and records
 * the dissolution in the audit log.
 */
export function planVirtualParentDissolution(input: {
  parentSubject: SubjectId;
  childSubjects: readonly SubjectId[];
  grants: readonly GrantRow[];
  virtualParentId: string;
  now: number;
}): Array<Omit<GrantRow, "id">> {
  const copies: Array<Omit<GrantRow, "id">> = [];
  for (const grant of input.grants) {
    if (grant.subject !== input.parentSubject) continue;
    if (isExpired(grant, input.now)) continue;
    for (const child of input.childSubjects) {
      copies.push({
        subject: child,
        roleId: grant.roleId,
        pattern: grant.pattern,
        scope: grant.scope,
        expiresAt: grant.expiresAt,
        provenance: {
          kind: "dissolution",
          virtualParentId: input.virtualParentId,
          originalGrantId: grant.id,
        },
        createdAt: input.now,
      });
    }
  }
  return copies;
}
