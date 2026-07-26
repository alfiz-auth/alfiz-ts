/**
 * One decision core, thin failure adapters: every gate failure carries a
 * typed reason so page redirects, API status codes, and action results are
 * derived from one object instead of four hand-rolled channels.
 */

import type { PermissionKey } from "./grammar.js";
import { isWildcard } from "./grammar.js";
import type { ScopeId } from "./scopes.js";

export type DenialReason =
  /** No principal at all — the identity layer produced nobody. */
  | "unauthenticated"
  /** A principal, but the check failed. */
  | "forbidden"
  /** The principal exists but is inactive. */
  | "inactive";

export class AccessDeniedError extends Error {
  override name = "AccessDeniedError";
  readonly reason: DenialReason;
  readonly permission: PermissionKey | readonly PermissionKey[] | undefined;
  readonly scope: ScopeId | undefined;

  constructor(options: {
    reason: DenialReason;
    permission?: PermissionKey | readonly PermissionKey[] | undefined;
    scope?: ScopeId | undefined;
    message?: string | undefined;
  }) {
    const what = options.permission
      ? Array.isArray(options.permission)
        ? `any of [${options.permission.join(", ")}]`
        : String(options.permission)
      : "access";
    super(
      options.message ??
        `${options.reason}: ${what}${options.scope ? ` at ${options.scope}` : ""}`,
    );
    this.reason = options.reason;
    this.permission = options.permission;
    this.scope = options.scope;
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
export class UnknownPermissionError extends Error {
  override name = "UnknownPermissionError";
  /** The offending string. */
  readonly permission: string;
  /** Whether a concrete key or a pattern was expected at this call site. */
  readonly expected: "key" | "pattern";
  /** The corrected pattern when the string named a group, else undefined. */
  readonly suggestion: string | undefined;

  constructor(options: {
    permission: string;
    expected: "key" | "pattern";
    /** Pass `suggestPattern(catalog, value)` — non-null means "it is a group". */
    suggestion?: string | null | undefined;
  }) {
    const value = JSON.stringify(options.permission);
    const suggestion = options.suggestion ?? undefined;
    let message: string;
    if (options.expected === "key") {
      if (suggestion !== undefined) {
        // A group path where a gate wanted a leaf. The subtree pattern is
        // NOT the fix here: gates check one concrete key, never a wildcard.
        message =
          `${value} is a group, not a permission key — groups are folders, and only leaves are checkable. ` +
          `Gate on a concrete key under it, or ask the visibility question with canAny(${JSON.stringify(suggestion)}).`;
      } else if (isWildcard(options.permission)) {
        message =
          `${value} is a pattern, not a permission key — a gate checks one concrete key. ` +
          `Use canAny(${value}) for the visibility question (never as a gate).`;
      } else {
        message = `${value} is not a permission key in this catalog (typo, or an undeclared key).`;
      }
    } else if (suggestion !== undefined) {
      message =
        `${value} is a group, not a pattern — groups are folders, never keys, so it matches nothing. ` +
        `Did you mean ${JSON.stringify(suggestion)}?`;
    } else {
      message = `${value} is not in this catalog (typo, or an undeclared key).`;
    }
    super(message);
    this.permission = options.permission;
    this.expected = options.expected;
    this.suggestion = suggestion;
  }
}

/** True when `err` is a malformed-check error (map to 500, not 403). */
export function isUnknownPermission(
  err: unknown,
): err is UnknownPermissionError {
  return err instanceof UnknownPermissionError;
}

/** Either failure a check can raise: a denial, or a malformed check. */
export type AlfizCheckError = AccessDeniedError | UnknownPermissionError;
