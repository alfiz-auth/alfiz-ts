/**
 * One decision core, thin failure adapters: every gate failure carries a
 * typed reason so page redirects, API status codes, and action results are
 * derived from one object instead of four hand-rolled channels.
 */

import type { PermissionKey } from "./grammar.js";
import { isWildcard } from "./grammar.js";
import type { PrincipalRef } from "./provider.js";
import type { ScopeId } from "./scopes.js";

export type DenialReason =
  /** No principal at all — the identity layer produced nobody. */
  | "unauthenticated"
  /** A principal, but the check failed. */
  | "forbidden"
  /** The principal exists but is inactive. */
  | "inactive";

/** `"a"`, `"a" or "b"`, `"a", "b", or "c"` — the did-you-mean list shape. */
export function formatAlternatives(values: readonly string[]): string {
  const quoted = values.map((v) => JSON.stringify(v));
  if (quoted.length <= 1) return quoted.join("");
  if (quoted.length === 2) return `${quoted[0]} or ${quoted[1]}`;
  return `${quoted.slice(0, -1).join(", ")}, or ${quoted.at(-1)}`;
}

const principalLabel = (p: PrincipalRef): string =>
  "userId" in p ? `user:${p.userId}` : `service:${p.serviceId}`;

export class AccessDeniedError extends Error {
  override name = "AccessDeniedError";
  readonly reason: DenialReason;
  readonly permission: PermissionKey | readonly PermissionKey[] | undefined;
  readonly scope: ScopeId | undefined;
  /** Who was denied, when the throw site knew — for log lines and audit trails. */
  readonly principal: PrincipalRef | undefined;

  constructor(options: {
    reason: DenialReason;
    permission?: PermissionKey | readonly PermissionKey[] | undefined;
    scope?: ScopeId | undefined;
    principal?: PrincipalRef | undefined;
    message?: string | undefined;
  }) {
    const what = options.permission
      ? Array.isArray(options.permission)
        ? `any of [${options.permission.join(", ")}]`
        : String(options.permission)
      : "access";
    const who = options.principal
      ? ` for ${principalLabel(options.principal)}`
      : "";
    const how =
      options.reason === "forbidden" && options.permission
        ? ` — explain(principal, key${options.scope ? ", scope" : ""}) shows the rows that matched and the revokes that won`
        : options.reason === "inactive"
          ? ` — the principal is deactivated; every check evaluates to no access until setUserActive(userId, true)`
          : "";
    super(
      options.message ??
        `${options.reason}: ${what}${options.scope ? ` at ${options.scope}` : ""}${who}${how}`,
    );
    this.reason = options.reason;
    this.permission = options.permission;
    this.scope = options.scope;
    this.principal = options.principal;
  }
}

/** True when `err` is a gate failure (for framework adapters to map). */
export function isAccessDenied(err: unknown): err is AccessDeniedError {
  return err instanceof AccessDeniedError;
}

/**
 * A check referenced a key or pattern the catalog does not declare. This is
 * a PROGRAMMING error, not a denial — map it to 500, never to 403.
 *
 * Checks are verified against the catalog because the alternative is worse
 * than useless in both directions:
 *
 *   - On the gate path an undeclared key silently PASSES for anyone holding
 *     a covering wildcard (`*` matches any string, including a typo), and
 *     denies everyone else. So a misspelled gate admits exactly the
 *     broadly-privileged users who review and test it, and blocks the users
 *     it was written for. That is the one direction a mistake here must
 *     never take.
 *   - On the visibility path an undeclared pattern matches no catalog key
 *     and silently answers `false` — an honest-looking answer to a question
 *     that was never asked, which is how a whole nav section disappears
 *     with no error to search for.
 *
 * The static verifier catches every LITERAL call site; this catches the
 * runtime-string paths it cannot see (nav tables, generic wrappers, config)
 * — the same rule, enforced at the other end.
 */
export interface UnknownPermissionDetails {
  permission: string;
  expected: "key" | "pattern";
  /** Pass `suggestPattern(catalog, value)` — non-null means "it is a group". */
  suggestion?: string | null | undefined;
  /** Edit-distance near-misses from `closestPatterns` / `unknownPermissionContext`. */
  didYouMean?: readonly string[] | undefined;
  /** An extra context sentence (e.g. the undeclared-namespace hint). */
  hint?: string | undefined;
}

/**
 * The one composition of the unknown-permission message, shared by
 * `UnknownPermissionError` and the Application's write-path rejections so
 * both report the same idioms — spread `unknownPermissionContext(catalog,
 * value, expected)` into the options to fill the suggestion fields.
 */
export function formatUnknownPermission(
  options: UnknownPermissionDetails,
): string {
  const value = JSON.stringify(options.permission);
  const suggestion = options.suggestion ?? undefined;
  const didYouMean = options.didYouMean ?? [];
  const extras =
    (didYouMean.length > 0
      ? ` Did you mean ${formatAlternatives(didYouMean)}?`
      : "") + (options.hint ? ` Note: ${options.hint}.` : "");
  if (options.expected === "key") {
    if (suggestion !== undefined) {
      // A group path where a gate wanted a leaf. The subtree pattern is
      // NOT the fix here: gates check one concrete key, never a wildcard.
      return (
        `${value} is a group, not a permission key — groups are folders, and only leaves are checkable. ` +
        `Gate on a concrete key under it, or ask the visibility question with canAny(${JSON.stringify(suggestion)}).`
      );
    }
    if (isWildcard(options.permission)) {
      return (
        `${value} is a pattern, not a permission key — a gate checks one concrete key. ` +
        `Use canAny(${value}) for the visibility question (never as a gate).`
      );
    }
    return `${value} is not a permission key in this catalog (typo, or an undeclared key).${extras}`;
  }
  if (suggestion !== undefined) {
    return (
      `${value} is a group, not a pattern — groups are folders, never keys, so it matches nothing. ` +
      `Did you mean ${JSON.stringify(suggestion)}?`
    );
  }
  return `${value} is not in this catalog (typo, or an undeclared key).${extras}`;
}

export class UnknownPermissionError extends Error {
  override name = "UnknownPermissionError";
  /** The offending string. */
  readonly permission: string;
  /** Whether a concrete key or a pattern was expected at this call site. */
  readonly expected: "key" | "pattern";
  /** The corrected pattern when the string named a group, else undefined. */
  readonly suggestion: string | undefined;
  /** Declared keys/patterns near the offending string, closest first. */
  readonly didYouMean: readonly string[];

  constructor(options: UnknownPermissionDetails) {
    super(formatUnknownPermission(options));
    this.permission = options.permission;
    this.expected = options.expected;
    this.suggestion = options.suggestion ?? undefined;
    this.didYouMean = options.didYouMean ?? [];
  }
}

/** True when `err` is a malformed-check error (map to 500, not 403). */
export function isUnknownPermission(
  err: unknown,
): err is UnknownPermissionError {
  return err instanceof UnknownPermissionError;
}

/**
 * A synchronous snapshot check targeted a scope whose ancestor chain the
 * snapshot cannot derive without I/O — a hierarchical scope that was never
 * pre-resolved, or a scope type the catalog never declared. A programming
 * error (map to 500): guessing a truncated chain would miss ancestor
 * grants (fail closed) and ancestor revokes (fail OPEN), and the second is
 * the direction a mistake here must never take.
 */
export class UnresolvedScopeError extends Error {
  override name = "UnresolvedScopeError";
  /** The scope the check targeted. */
  readonly scope: ScopeId;
  /** Its scope type, or `null` when the id has no `<type>:` half. */
  readonly scopeType: string | null;
  /** Whether the scope type is declared in the catalog at all. */
  readonly declared: boolean;
  /** The scopes this snapshot CAN already evaluate. */
  readonly resolvedScopes: readonly ScopeId[];

  constructor(options: {
    scope: ScopeId;
    scopeType: string | null;
    declared: boolean;
    declaredScopeTypes: readonly string[];
    resolvedScopes: readonly ScopeId[];
  }) {
    const resolved = [...options.resolvedScopes].sort();
    const shown = resolved.slice(0, 8);
    const resolvedNote =
      resolved.length === 0
        ? "no scopes are pre-resolved in this snapshot"
        : `scopes already resolved in this snapshot: ${shown.join(", ")}` +
          (resolved.length > shown.length
            ? ` (and ${resolved.length - shown.length} more)`
            : "");
    super(
      `snapshot cannot resolve the ancestor chain of ${JSON.stringify(options.scope)} synchronously: ` +
        (options.declared
          ? `scope type ${JSON.stringify(options.scopeType)} is hierarchical`
          : `scope type ${JSON.stringify(options.scopeType)} is not declared in the catalog` +
            (options.declaredScopeTypes.length > 0
              ? ` (declared scope types: ${options.declaredScopeTypes.join(", ")})`
              : "")) +
        `. Pre-resolve it — client.snapshot(principal, { scopes: [...] }) up front, or ` +
        `await snapshot.resolve([...]) once the ids are known (list pages) — or use the async client.can. ` +
        `(${resolvedNote})`,
    );
    this.scope = options.scope;
    this.scopeType = options.scopeType;
    this.declared = options.declared;
    this.resolvedScopes = options.resolvedScopes;
  }
}

/** Either failure a check can raise: a denial, or a malformed check. */
export type AlfizCheckError = AccessDeniedError | UnknownPermissionError;
