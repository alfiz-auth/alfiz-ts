/**
 * Wildcard drift: the report point-in-time attestation needs and stored
 * patterns cannot answer alone.
 *
 * Forward-inclusive wildcards are a deliberate semantic commitment — a
 * stored `docs.files.*` grant absorbs keys published under that prefix
 * LATER, with no write and no re-review trigger. A grant certified in Q1
 * may therefore confer permissions that did not exist in Q1. This module
 * makes that visible: given two published catalog documents, it names every
 * key the catalog gained between them and every grant row or role whose
 * wildcard silently absorbed one.
 *
 * Pure functions over published documents and rows; the Application's
 * `listWildcardDrift` supplies both from storage (catalog history is
 * retained per publish since 0.7.0).
 */

import type { GrantRow, RoleDef } from "./access.js";
import { isExpired } from "./access.js";
import type { CatalogDocument } from "./catalog.js";
import type { PermissionKey, PermissionPattern } from "./grammar.js";
import { patternMatchesKey } from "./grammar.js";

export interface WildcardDriftFinding {
  /** What holds the absorbing pattern. */
  via:
    | { kind: "grant"; grant: GrantRow }
    | { kind: "role"; role: RoleDef; grantIds: readonly string[] };
  pattern: PermissionPattern;
  /** The keys published after `from` that this pattern now confers. */
  gainedKeys: readonly PermissionKey[];
}

export interface WildcardDriftReport {
  /** Keys in `to` that `from` did not declare. */
  gainedKeys: readonly PermissionKey[];
  /** Keys `from` declared that `to` no longer does (tombstone candidates). */
  removedKeys: readonly PermissionKey[];
  findings: readonly WildcardDriftFinding[];
}

const isWildcard = (pattern: string): boolean =>
  pattern === "*" || pattern.endsWith(".*");

/**
 * Diffs two published documents and attributes every gained key to the
 * unexpired wildcard grants (and roles, via the grants assigning them)
 * that silently absorbed it. Expired grants are skipped — they no longer
 * confer anything, gained or not.
 */
export function wildcardDrift(input: {
  from: CatalogDocument;
  to: CatalogDocument;
  grants: readonly GrantRow[];
  roles: readonly RoleDef[];
  /** Evaluation instant for expiry filtering. */
  now: number;
}): WildcardDriftReport {
  const before = new Set(input.from.leaves.map((l) => l.key));
  const after = new Set(input.to.leaves.map((l) => l.key));
  const gainedKeys = [...after].filter((k) => !before.has(k)).sort();
  const removedKeys = [...before].filter((k) => !after.has(k)).sort();

  const findings: WildcardDriftFinding[] = [];
  if (gainedKeys.length > 0) {
    // The same reading of `expiresAt` the evaluator uses. Filtering by hand
    // here made the review surface disagree with `can()` about which rows are
    // live: a row with an uncomparable expiry was live in checks and absent
    // from this report — the one combination that hides a live grant from
    // the surface built to find live grants.
    const live = input.grants.filter((g) => !isExpired(g, input.now));
    for (const grant of live) {
      if (grant.pattern === undefined || !isWildcard(grant.pattern)) continue;
      const gained = gainedKeys.filter((k) =>
        patternMatchesKey(grant.pattern!, k),
      );
      if (gained.length > 0) {
        findings.push({
          via: { kind: "grant", grant },
          pattern: grant.pattern,
          gainedKeys: gained,
        });
      }
    }
    for (const role of input.roles) {
      const grantIds = live
        .filter((g) => g.roleId === role.id)
        .map((g) => g.id);
      if (grantIds.length === 0) continue; // an unassigned role confers nothing
      for (const pattern of role.patterns) {
        if (!isWildcard(pattern)) continue;
        const gained = gainedKeys.filter((k) => patternMatchesKey(pattern, k));
        if (gained.length > 0) {
          findings.push({
            via: { kind: "role", role, grantIds },
            pattern,
            gainedKeys: gained,
          });
        }
      }
    }
  }
  return { gainedKeys, removedKeys, findings };
}
