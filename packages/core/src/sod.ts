/**
 * Separation-of-duty constraints — DETECTIVE by design.
 *
 * A constraint declares two or more mutually exclusive pattern sets in the
 * catalog ("no one may hold both Vendor Admin and Payment Approver"); a
 * principal whose effective access intersects two or more of a constraint's
 * sets is a violation. Evaluation is a pure function over the same
 * `CheckContext` every check uses, run OFF the hot path — by the
 * Application's `listSodViolations` report, or preventively at grant time
 * when the deployment opts in. Nothing here adds a negative to evaluation:
 * inheritance stays union-only, precedence stays a single rule, and `can()`
 * never consults a constraint.
 *
 * Scope is deliberately ignored: holding Vendor Admin on project A and
 * Payment Approver on project B still co-locates both capabilities in one
 * person, which is what the control exists to prevent. A deployment that
 * wants scoped tolerance models it by splitting the constraint, not by a
 * scope parameter here.
 */

import type { CheckContext } from "./access.js";
import { keyHeldAnywhere } from "./access.js";
import type { AnyCatalog } from "./catalog.js";
import type { PermissionKey, PermissionPattern } from "./grammar.js";

/** One catalog-declared mutual-exclusion constraint. */
export interface SodConstraint {
  /** Stable identifier, e.g. `"vendor-vs-payments"` — referenced by reports and audits. */
  id: string;
  description?: string | undefined;
  /**
   * Two or more pattern sets. Holding access matching patterns from two or
   * more DIFFERENT sets violates the constraint; any breadth of holding
   * within one set is fine.
   */
  sets: readonly (readonly PermissionPattern[])[];
}

/** The keys a principal holds out of one constraint set. */
export interface SodSetMatch {
  setIndex: number;
  /** The concrete catalog keys held that the set's patterns cover. */
  keys: readonly PermissionKey[];
}

export interface SodViolation {
  constraintId: string;
  description: string | undefined;
  /** The sets matched — always two or more, else it is not a violation. */
  sets: readonly SodSetMatch[];
}

/**
 * Evaluates every constraint against one principal's effective access.
 * "Holds" is `keyHeldAnywhere` — any scope, revokes respected fail-closed —
 * so the report never accuses on access a global revoke has suppressed,
 * and never misses access held only at a narrow scope.
 */
export function checkSodConstraints(
  ctx: CheckContext,
  catalog: AnyCatalog,
  constraints: readonly SodConstraint[],
): SodViolation[] {
  const violations: SodViolation[] = [];
  for (const constraint of constraints) {
    const matched: SodSetMatch[] = [];
    for (let setIndex = 0; setIndex < constraint.sets.length; setIndex++) {
      const keys = new Set<PermissionKey>();
      for (const pattern of constraint.sets[setIndex]!) {
        for (const key of catalog.keysMatching(pattern)) {
          if (keyHeldAnywhere(ctx, key)) keys.add(key);
        }
      }
      if (keys.size > 0) {
        matched.push({ setIndex, keys: [...keys].sort() });
      }
    }
    if (matched.length >= 2) {
      violations.push({
        constraintId: constraint.id,
        description: constraint.description,
        sets: matched,
      });
    }
  }
  return violations;
}

/**
 * Structural validation of constraint declarations against a catalog —
 * `defineCatalog` runs this at boot (errors throw with everything else).
 *
 * The rules and their reasons:
 * - at least two sets, none empty: fewer cannot express an exclusion;
 * - every pattern must resolve to at least one ENUMERABLE catalog key: a
 *   pattern over an open region (an import with no attached document)
 *   cannot be checked, and a control that silently checks nothing is worse
 *   than a loud refusal;
 * - no key may fall in two sets of the same constraint: such a constraint
 *   flags every holder of that key, which is a declaration bug, not a
 *   finding.
 */
export function validateSodConstraints(
  catalog: AnyCatalog,
  constraints: readonly SodConstraint[],
): string[] {
  const problems: string[] = [];
  const seen = new Set<string>();
  for (const constraint of constraints) {
    const at = `constraints.sod[${JSON.stringify(constraint.id)}]`;
    if (seen.has(constraint.id)) {
      problems.push(`${at}: duplicate constraint id`);
      continue;
    }
    seen.add(constraint.id);
    if (constraint.sets.length < 2) {
      problems.push(`${at}: declare at least two mutually exclusive sets`);
      continue;
    }
    const keyToSet = new Map<PermissionKey, number>();
    constraint.sets.forEach((set, setIndex) => {
      if (set.length === 0) {
        problems.push(`${at}: set ${setIndex} is empty`);
        return;
      }
      for (const pattern of set) {
        const keys = catalog.keysMatching(pattern);
        const regions = catalog.opaqueRegions(pattern);
        if (regions.length > 0) {
          problems.push(
            `${at}: ${JSON.stringify(pattern)} reaches into an open import region — attach the owner's document; a constraint over keys this catalog cannot enumerate cannot be checked`,
          );
          continue;
        }
        if (keys.length === 0) {
          problems.push(
            `${at}: ${JSON.stringify(pattern)} matches no declared permission`,
          );
          continue;
        }
        for (const key of keys) {
          const other = keyToSet.get(key);
          if (other !== undefined && other !== setIndex) {
            problems.push(
              `${at}: ${JSON.stringify(key)} falls in sets ${other} and ${setIndex} — a key in two sets makes every holder a violator; narrow the patterns`,
            );
          } else {
            keyToSet.set(key, setIndex);
          }
        }
      }
    });
  }
  return problems;
}
