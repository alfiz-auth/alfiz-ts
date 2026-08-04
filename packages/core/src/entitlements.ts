/**
 * The per-principal effective-access rollup — the export an access review
 * or an external IGA (Entra ID Governance, Okta IGA, ConductorOne, Veza)
 * consumes, and the answer to "what can this person actually do, and WHY".
 *
 * Raw grant rows cannot answer that: between the group DAG, role
 * indirection, implicit manager subjects, `everyone`, and revokes, the
 * effective set is a computation, not a table. This module runs that
 * computation once per principal, over the same `CheckContext` every check
 * uses — so what it reports is exactly what `can()` would answer, key by
 * key, with the conferring rows attached.
 *
 * Pure functions; the Application's `exportEntitlements` supplies the data
 * and iterates principals. The write-back path of a review stays the
 * ordinary API: revoke a grant, end-date it, or write a personal revoke.
 */

import type { CheckContext } from "./access.js";
import { grantsMatchingKey, keyHeldAnywhere } from "./access.js";
import type { GrantRow } from "./access.js";
import type { AnyCatalog } from "./catalog.js";
import type { PermissionKey } from "./grammar.js";
import { patternMatchesKey } from "./grammar.js";

export interface EntitlementSource {
  grantId: string;
  /** The subject the row names — the user, or the group/org/implicit subject it arrived through. */
  subject: string;
  /** Set when the row confers via a role. */
  roleId?: string | undefined;
  pattern: string;
  scope: string;
  expiresAt?: number | undefined;
}

export interface Entitlement {
  key: PermissionKey;
  /**
   * Whether the key is held ANYWHERE right now (revokes respected,
   * fail-closed) — `keyHeldAnywhere` semantics, scope-blind on purpose:
   * a reviewer certifies capability, and per-scope precision is what the
   * per-source `scope` fields below carry.
   */
  held: boolean;
  /** Every unexpired row that confers this key, with its scope. */
  sources: readonly EntitlementSource[];
}

export interface PrincipalEntitlements {
  userId: string;
  active: boolean;
  /** The subject closure the computation ran over — the "why" of inheritance. */
  closure: readonly string[];
  /** One entry per catalog key at least one row confers. */
  entitlements: readonly Entitlement[];
  /** Personal revokes narrowing the above. */
  revokes: readonly { revokeId: string; pattern: string; scope: string }[];
}

const sourceOf = (grant: GrantRow, pattern: string): EntitlementSource => ({
  grantId: grant.id,
  subject: grant.subject,
  roleId: grant.roleId,
  pattern,
  scope: grant.scope,
  expiresAt: grant.expiresAt,
});

/**
 * Rolls one principal's context up into reviewable entitlements: for every
 * catalog key, the conferring rows and the net held/suppressed answer.
 * Keys nothing confers are omitted — the export names access, not the
 * catalog.
 */
export function entitlementsOf(
  ctx: CheckContext,
  catalog: AnyCatalog,
): { entitlements: Entitlement[]; revokes: PrincipalEntitlements["revokes"] } {
  const entitlements: Entitlement[] = [];
  for (const key of catalog.keys) {
    const matching = grantsMatchingKey(ctx, key);
    if (matching.length === 0) continue;
    const sources: EntitlementSource[] = [];
    for (const grant of matching) {
      if (grant.roleId !== undefined) {
        const role = ctx.rows.roles.get(grant.roleId);
        for (const pattern of role?.patterns ?? []) {
          if (patternMatchesKey(pattern, key)) {
            sources.push(sourceOf(grant, pattern));
          }
        }
      } else if (grant.pattern !== undefined) {
        sources.push(sourceOf(grant, grant.pattern));
      }
    }
    entitlements.push({
      key,
      held: keyHeldAnywhere(ctx, key),
      sources,
    });
  }
  const revokes = ctx.rows.revokes
    .filter((r) => r.userId === ctx.userId)
    .map((r) => ({ revokeId: r.id, pattern: r.pattern, scope: r.scope }));
  return { entitlements, revokes };
}
