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

/**
 * The bound on a runtime-supplied string echoed back in a message. Keys,
 * scope ids, and principal ids are caller data — a scope id is `docs.doc:`
 * plus something that was very likely a URL segment a moment ago — so a
 * message quoting one must not be sizeable by whoever supplied it. Without
 * a bound, a 200 KB permission string becomes a 200 KB message retained by
 * every log line, every `Error` still on the stack, and every wire error
 * body built from it.
 */
const ECHO_LIMIT = 120;

/** Bound an echoed value, naming what was dropped rather than hiding it. */
export function boundEcho(value: string, limit = ECHO_LIMIT): string {
  return value.length <= limit
    ? value
    : `${value.slice(0, limit)}…(+${value.length - limit} more)`;
}

// C0, DEL, C1, and the two Unicode line separators — every character a log
// reader or a terminal treats as a control rather than as text.
// eslint-disable-next-line no-control-regex
const CONTROL_CHARS = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g;

const escapeControl = (c: string): string => {
  const code = c.charCodeAt(0);
  return code <= 0xff
    ? `\\x${code.toString(16).padStart(2, "0")}`
    : `\\u${code.toString(16).padStart(4, "0")}`;
};

/**
 * Bound an echoed value AND neutralize it, for the positions that
 * interpolate it *unquoted* — `forbidden: docs.files.read at docs.doc:123
 * for user:u1`. An id carrying a newline forges a whole extra log line, and
 * one carrying an ANSI escape repaints the terminal of whoever tails that
 * log; both are writable by anyone who can reach a denied route. The quoted
 * positions in this file get the same guarantee free from `JSON.stringify`
 * — this is how the unquoted ones earn it.
 */
export function safeEcho(value: string, limit = ECHO_LIMIT): string {
  return boundEcho(value.replace(CONTROL_CHARS, escapeControl), limit);
}

const principalLabel = (p: PrincipalRef): string =>
  "userId" in p
    ? `user:${safeEcho(p.userId)}`
    : `service:${safeEcho(p.serviceId)}`;

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
        ? `any of [${options.permission.map((k) => safeEcho(k)).join(", ")}]`
        : safeEcho(String(options.permission))
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
        `${options.reason}: ${what}${options.scope ? ` at ${safeEcho(options.scope)}` : ""}${who}${how}`,
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
  /**
   * Whether the permission's namespace is one this catalog owns, imports, or
   * has never heard of. The three are different mistakes with different
   * fixes: a typo, a reach beyond what an import covers, and a missing
   * import declaration. Supplied by `unknownPermissionContext`.
   */
  namespaceOrigin?: "owned" | "imported" | "foreign" | undefined;
  /** What the import for that namespace covers, when there is one. */
  importedPatterns?: readonly string[] | undefined;
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
  // Bounded before quoting: the permission is a runtime string on the paths
  // this error exists to cover, so its length is the caller's to choose.
  const value = JSON.stringify(boundEcho(options.permission));
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
    if (options.namespaceOrigin === "imported") {
      return `${value} is not covered by this catalog's import of that namespace.${extras}`;
    }
    if (options.namespaceOrigin === "foreign") {
      return `${value} is not a permission key in this catalog, and belongs to a namespace it neither owns nor imports.${extras}`;
    }
    return `${value} is not a permission key in this catalog (typo, or an undeclared key).${extras}`;
  }
  if (suggestion !== undefined) {
    return (
      `${value} is a group, not a pattern — groups are folders, never keys, so it matches nothing. ` +
      `Did you mean ${JSON.stringify(suggestion)}?`
    );
  }
  if (options.namespaceOrigin === "imported") {
    return `${value} is not covered by this catalog's import of that namespace.${extras}`;
  }
  if (options.namespaceOrigin === "foreign") {
    return `${value} is not in this catalog, and belongs to a namespace it neither owns nor imports.${extras}`;
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
  /** Whether the namespace is owned, imported, or unknown to this catalog. */
  readonly namespaceOrigin: "owned" | "imported" | "foreign";
  /** What the import for that namespace covers, when there is one. */
  readonly importedPatterns: readonly string[];

  constructor(options: UnknownPermissionDetails) {
    super(formatUnknownPermission(options));
    this.permission = options.permission;
    this.expected = options.expected;
    this.suggestion = options.suggestion ?? undefined;
    this.didYouMean = options.didYouMean ?? [];
    this.namespaceOrigin = options.namespaceOrigin ?? "owned";
    this.importedPatterns = options.importedPatterns ?? [];
  }

  /**
   * The permission belongs to a namespace this catalog does not own — a
   * missing import declaration or a reach beyond one, rather than a typo in
   * this codebase's own vocabulary. Still a programming error, and still
   * mapped to 500, never 403: framework adapters use this to say which fix
   * to suggest, not to change the status code.
   */
  get isForeignNamespace(): boolean {
    return this.namespaceOrigin !== "owned";
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
      `snapshot cannot resolve the ancestor chain of ${JSON.stringify(boundEcho(options.scope))} synchronously: ` +
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

/**
 * A gate for a permission the catalog declares `requiresCondition: true`
 * was called without a `condition` in its options. A PROGRAMMING error, on
 * the same footing as `UnknownPermissionError`: map it to 500, never 403 —
 * the caller forgot the predicate, the principal was not denied. The
 * static verifier (`missing-condition`) catches literal call sites in CI;
 * this closes the runtime-string paths it cannot see.
 */
export class MissingConditionError extends Error {
  override name = "MissingConditionError";
  readonly permission: PermissionKey;

  constructor(permission: PermissionKey, shape: string) {
    super(
      `${JSON.stringify(boundEcho(permission))} is declared \`requiresCondition: true\` — ` +
        `every ${shape} gate for it must pass \`{ condition: () => … }\` ` +
        `evaluating the resource predicate the catalog promises. ` +
        `Holding the permission is necessary but not sufficient by declaration.`,
    );
    this.permission = permission;
  }
}

/** Either failure a check can raise: a denial, or a malformed check. */
export type AlfizCheckError =
  | AccessDeniedError
  | UnknownPermissionError
  | MissingConditionError;
