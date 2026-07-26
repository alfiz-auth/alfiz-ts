/**
 * The permission grammar: dot-separated keys, subtree wildcards, and the
 * matching / intersection algebra everything else is built on.
 *
 * Semantic commitments (fixed, not configurable):
 * - Keys are dot-separated segments. Group levels are folders, never
 *   permissions; only leaves are grantable/checkable.
 * - Wildcards are subtree wildcards and appear only as the final segment:
 *   `*`, `<project>.*`, `<project>.<tab>.*`.
 * - Wildcards are forward-inclusive: a stored `a.b.*` pattern matches keys
 *   added under `a.b` in the future.
 * - `a.*` does NOT match `a` itself: `a` is a group level, not a leaf.
 */

const SEGMENT_RE = /^[a-zA-Z][a-zA-Z0-9_]*$/;

/** A concrete permission key, e.g. `mathaniyy.approvals.decide_student`. */
export type PermissionKey = string;

/** A key or a subtree wildcard: `*`, `a.*`, `a.b.*`, or a concrete key. */
export type PermissionPattern = string;

/**
 * A catalog-typed key that still admits runtime strings: the blessed escape
 * hatch for generic wrappers that route many keys through one function
 * (`assertCanDo(actor, thing, permission: string)`). Autocomplete and
 * compile-checking survive for literal call sites; a plain `string` flows
 * through without `as never`. Used on the INTROSPECTION paths only
 * (`grantedScopes`, `explain`, `holdsAnywhere`) — gates (`can`, `require*`)
 * stay strictly typed, because a gate on an unchecked key is exactly the
 * typo class the derived types exist to prevent.
 */
export type LooseKey<K extends string> = K | (string & {});

/**
 * The pattern-shaped sibling of {@link LooseKey}: catalog-typed patterns
 * that still admit runtime strings. Used on write-path inputs (grants,
 * revokes, roles, requests), where patterns routinely arrive from role
 * editors and admin UIs at runtime — autocomplete and compile-checking
 * survive for literal call sites, and the write path validates the rest.
 */
export type LoosePattern<P extends string> = P | (string & {});

/** The reserved namespace for Alfiz's own administration permissions. */
export const ALFIZ_INTERNAL_NAMESPACE = "alfiz_internal";

export interface GrammarIssue {
  value: string;
  reason: string;
}

/** Returns true when `segment` is a valid key segment. */
export function isValidSegment(segment: string): boolean {
  return SEGMENT_RE.test(segment);
}

/**
 * Validates a concrete permission key. Returns `null` when valid, or a
 * human-debuggable issue when not.
 */
export function validateKey(key: string): GrammarIssue | null {
  if (key === "") return { value: key, reason: "empty key" };
  if (key.includes("*")) {
    return {
      value: key,
      reason: "wildcards are not allowed in a concrete key (use a pattern)",
    };
  }
  const segments = key.split(".");
  for (const segment of segments) {
    if (!isValidSegment(segment)) {
      return {
        value: key,
        reason: `invalid segment ${JSON.stringify(segment)}: segments must match ${SEGMENT_RE.source}`,
      };
    }
  }
  return null;
}

/**
 * Validates a pattern: either a valid concrete key, the bare `*`, or a valid
 * group prefix followed by `.*`. Wildcards may only be the final segment —
 * infix wildcards (`a.*.b`) are rejected.
 */
export function validatePattern(pattern: string): GrammarIssue | null {
  if (pattern === "*") return null;
  if (pattern === "") return { value: pattern, reason: "empty pattern" };
  if (pattern.endsWith(".*")) {
    const prefix = pattern.slice(0, -2);
    if (prefix.includes("*")) {
      return {
        value: pattern,
        reason: "wildcards may only appear as the final segment",
      };
    }
    return validateKey(prefix) === null
      ? null
      : { value: pattern, reason: `invalid group prefix ${JSON.stringify(prefix)}` };
  }
  if (pattern.includes("*")) {
    return {
      value: pattern,
      reason: "wildcards may only appear as a final `.*` segment or the bare `*`",
    };
  }
  return validateKey(pattern);
}

export function isValidKey(key: string): boolean {
  return validateKey(key) === null;
}

export function isValidPattern(pattern: string): boolean {
  return validatePattern(pattern) === null;
}

/** True when the pattern contains a wildcard (`*` or a `.*` suffix). */
export function isWildcard(pattern: PermissionPattern): boolean {
  return pattern === "*" || pattern.endsWith(".*");
}

/**
 * Core matching: does `pattern` match the concrete `key`?
 *
 * - `*` matches every key.
 * - `a.b.*` matches every key strictly under `a.b` (any depth), and never
 *   `a.b` itself.
 * - A concrete pattern matches only the identical key.
 */
export function patternMatchesKey(
  pattern: PermissionPattern,
  key: PermissionKey,
): boolean {
  if (pattern === "*") return true;
  if (pattern.endsWith(".*")) {
    const prefix = pattern.slice(0, -1); // keep the trailing dot: "a.b."
    return key.startsWith(prefix) && key.length > prefix.length;
  }
  return pattern === key;
}

/**
 * Does any pattern in `patterns` match `key`?
 */
export function anyPatternMatchesKey(
  patterns: Iterable<PermissionPattern>,
  key: PermissionKey,
): boolean {
  for (const pattern of patterns) {
    if (patternMatchesKey(pattern, key)) return true;
  }
  return false;
}

/**
 * Set intersection between two patterns: is there any concrete key both could
 * match? Used by visibility affordances (`canAny`), never by gates.
 *
 * - Two concrete keys intersect iff equal.
 * - A concrete key intersects a subtree pattern iff the pattern matches it.
 * - Two subtree patterns intersect iff one's prefix extends the other's
 *   (`a.*` ∩ `a.b.*` is non-empty; `a.*` ∩ `b.*` is empty).
 */
export function patternsIntersect(
  a: PermissionPattern,
  b: PermissionPattern,
): boolean {
  if (a === "*" || b === "*") return true;
  const aWild = a.endsWith(".*");
  const bWild = b.endsWith(".*");
  if (!aWild && !bWild) return a === b;
  if (aWild && !bWild) return patternMatchesKey(a, b);
  if (!aWild && bWild) return patternMatchesKey(b, a);
  const aPrefix = a.slice(0, -1); // "a.b."
  const bPrefix = b.slice(0, -1);
  return aPrefix.startsWith(bPrefix) || bPrefix.startsWith(aPrefix);
}

/** Splits a key into its segments. */
export function segmentsOf(key: PermissionKey): string[] {
  return key.split(".");
}

/** The first segment of a key or pattern — its namespace. `*` has none. */
export function namespaceOf(keyOrPattern: string): string | null {
  if (keyOrPattern === "*") return null;
  const first = keyOrPattern.split(".", 1)[0];
  return first && first !== "*" ? first : null;
}

/** True when `key` is (strictly) inside the group `groupPath`. */
export function isUnderGroup(groupPath: string, key: PermissionKey): boolean {
  return key.startsWith(groupPath + ".");
}

/** The subtree pattern selecting everything under a group path. */
export function subtreePattern(groupPath: string): PermissionPattern {
  return groupPath + ".*";
}
