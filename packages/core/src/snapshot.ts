/**
 * The request-scoped snapshot: one provider round-trip, then synchronous
 * checks. THE pattern for server-rendered frameworks, where a single render
 * performs hundreds of conditional-UI checks inside pure helpers and
 * `.map()` callbacks that cannot become async.
 *
 * ```ts
 * const snap = await alfiz.snapshot({ userId });   // once per request
 * snap.can("docs.files.read");                     // synchronous
 * snap.can("docs.files.update_file", "docs.doc:1");
 * snap.canAny("docs.*");
 * snap.heldKeys;                                   // Set<PermissionKey>
 * ```
 *
 * A per-request snapshot is a STRONGER consistency guarantee than the
 * client's TTL cache, not a weaker one: every check in the request sees one
 * subject-data instant and one evaluation clock, instead of a cache that may
 * tick over mid-render. Staleness across requests stays bounded exactly as
 * documented for the client (the snapshot draws from the same caches;
 * `fresh: true` bypasses them).
 *
 * Scoped checks and synchrony:
 *   - The chain of every scope appearing in the principal's own grant and
 *     revoke rows is resolved at snapshot time, so `canAny`, revoke
 *     suppression, and §7.5 ancestor implication are exact — full agreement
 *     with `client.can`.
 *   - A check target whose scope TYPE declares `parent: null` (and not
 *     `multiParent`) has the chain `[scope, "*"]` by declaration — computable
 *     without I/O. Flat, top-level scope types therefore never force you
 *     async; this covers most first adoptions.
 *   - A check target of a hierarchical scope type must be pre-resolved:
 *     `client.snapshot(principal, { scopes: [...] })`. Checking an
 *     unresolved hierarchical scope THROWS rather than silently evaluating a
 *     truncated chain — a truncated chain would miss ancestor grants
 *     (fail-closed) and ancestor revokes (fail-OPEN), and the second is the
 *     direction a mistake here must never take.
 */

import type { CheckContext, CheckExplanation } from "./access.js";
import {
  checkAny,
  checkKey,
  explainKey,
  grantedScopesFor,
  keyHeldAnywhere,
  revokedScopesFor,
} from "./access.js";
import type { AnyCatalog } from "./catalog.js";
import { AccessDeniedError } from "./errors.js";
import type { LooseKey, PermissionKey } from "./grammar.js";
import { patternMatchesKey } from "./grammar.js";
import type { PrincipalRef, SubjectAccessData } from "./provider.js";
import type { ScopeId } from "./scopes.js";
import { GLOBAL_SCOPE, scopeTypeOf } from "./scopes.js";

/** Options for `AlfizClient.snapshot`. */
export interface SnapshotOptions {
  /**
   * Scope instances to pre-resolve for synchronous scoped checks. Needed
   * only for HIERARCHICAL scope types (a declared parent, or multi-parent):
   * flat top-level types, and every scope appearing in the principal's own
   * grant and revoke rows, are resolved automatically.
   */
  scopes?: readonly ScopeId[] | undefined;
  /** Bypass the client's caches: fresh closure supply, fresh ancestry. */
  fresh?: boolean | undefined;
}

/** Everything a snapshot evaluates over — assembled by `AlfizClient.snapshot`. */
export interface SnapshotInit {
  catalog: AnyCatalog;
  principal: PrincipalRef;
  data: SubjectAccessData;
  ctx: CheckContext;
  /** Resolved object closures: every granted/revoked scope, plus requested ones. */
  chains: ReadonlyMap<ScopeId, readonly ScopeId[]>;
}

const GLOBAL_CLOSURE: readonly ScopeId[] = [GLOBAL_SCOPE];

/**
 * Synchronous evaluation over one consistent instant of a principal's
 * access. Construct with `client.snapshot(principal)`; typed by the
 * catalog's derived unions exactly like the client.
 */
export class AlfizSnapshot<K extends string = string, P extends string = string> {
  /** Who this snapshot evaluates. */
  readonly principal: PrincipalRef;
  /** The raw provider data, for advanced composition (`toCheckContext` etc.). */
  readonly data: SubjectAccessData;
  /** Whether the principal is active. Inactive principals evaluate to no access. */
  readonly active: boolean;
  /** The evaluation instant (epoch ms): one clock for every check in the snapshot. */
  readonly at: number;

  private readonly catalog: AnyCatalog;
  private readonly ctx: CheckContext;
  private readonly chains: ReadonlyMap<ScopeId, readonly ScopeId[]>;
  private held: Set<PermissionKey> | null = null;

  constructor(init: SnapshotInit) {
    this.catalog = init.catalog;
    this.principal = init.principal;
    this.data = init.data;
    this.active = init.data.active;
    this.ctx = init.ctx;
    this.chains = init.chains;
    this.at = init.ctx.now;
  }

  /**
   * The object closure of a check target, synchronously: pre-resolved
   * chains first, then the flat-type derivation. Throws for an unresolved
   * hierarchical scope — see the module docblock for why guessing is not an
   * option.
   */
  private closureOf(scope: ScopeId | undefined): readonly ScopeId[] {
    if (scope === undefined || scope === GLOBAL_SCOPE) return GLOBAL_CLOSURE;
    const resolved = this.chains.get(scope);
    if (resolved) return resolved;
    const type = scopeTypeOf(scope);
    const meta = type === null ? undefined : this.catalog.scopeTypes.get(type);
    if (meta && meta.parent === null && !meta.multiParent) {
      // A top-level scope type commits to flat instances: parent is `*`.
      return [scope, GLOBAL_SCOPE];
    }
    throw new Error(
      `snapshot cannot resolve the ancestor chain of ${JSON.stringify(scope)} synchronously: ` +
        (meta
          ? `scope type ${JSON.stringify(type)} is hierarchical`
          : `scope type ${JSON.stringify(type)} is not declared in the catalog`) +
        ` — pre-resolve it with client.snapshot(principal, { scopes: [${JSON.stringify(scope)}] }), or use the async client.can`,
    );
  }

  /**
   * §7.5 ancestor implication, evaluated against the pre-resolved chains of
   * the principal's granted scopes — same result as `AlfizClient.can`.
   */
  private impliedAt(key: PermissionKey, target: ScopeId): boolean {
    if (!this.catalog.leaf(key)?.impliedOnAncestors) return false;
    for (const grantScope of grantedScopesFor(this.ctx, key)) {
      if (grantScope === GLOBAL_SCOPE || grantScope === target) continue;
      const chain = this.chains.get(grantScope);
      if (!chain || !chain.includes(target)) continue;
      const suppressed =
        this.ctx.userId !== null &&
        this.ctx.rows.revokes.some(
          (r) =>
            r.userId === this.ctx.userId &&
            patternMatchesKey(r.pattern, key) &&
            chain.includes(r.scope),
        );
      if (!suppressed) return true;
    }
    return false;
  }

  /** Synchronous `can`: agrees with `client.can` for every resolvable scope. */
  can(key: K | readonly K[], scope?: ScopeId): boolean {
    if (!this.active) return false;
    const keys: readonly PermissionKey[] = Array.isArray(key)
      ? (key as readonly string[])
      : [key as string];
    const closure = this.closureOf(scope);
    for (const k of keys) {
      if (checkKey(this.ctx, k, closure)) return true;
    }
    if (scope !== undefined && scope !== GLOBAL_SCOPE) {
      for (const k of keys) {
        if (this.impliedAt(k, scope)) return true;
      }
    }
    return false;
  }

  /**
   * Synchronous visibility affordance. Exact (not the conservative
   * approximation): every granted scope's chain was resolved at snapshot
   * time. Never a gate — same rule as the client's.
   */
  canAny(pattern: P): boolean {
    if (!this.active) return false;
    return checkAny(this.ctx, pattern, this.catalog.keys, this.chains);
  }

  /** Throwing form of `can`. */
  require(key: K | readonly K[], scope?: ScopeId): void {
    if (!this.active) {
      throw new AccessDeniedError({
        reason: "inactive",
        permission: key as PermissionKey | readonly PermissionKey[],
        scope,
      });
    }
    if (!this.can(key, scope)) {
      throw new AccessDeniedError({
        reason: "forbidden",
        permission: key as PermissionKey | readonly PermissionKey[],
        scope,
      });
    }
  }

  /** Throwing form of `canAny` — project-root visibility. */
  requireAny(pattern: P): void {
    if (!this.canAny(pattern)) {
      throw new AccessDeniedError({
        reason: this.active ? "forbidden" : "inactive",
        permission: pattern as PermissionKey,
      });
    }
  }

  /**
   * Every concrete catalog key the principal holds SOMEWHERE (see
   * `keyHeldAnywhere` for the exact semantics). Computed once per snapshot,
   * on first access — the per-request cache the "holds it anywhere"
   * conditional-UI question wants.
   */
  get heldKeys(): ReadonlySet<PermissionKey> {
    if (this.held === null) {
      this.held = new Set(
        this.active
          ? this.catalog.keys.filter((key) => keyHeldAnywhere(this.ctx, key))
          : [],
      );
    }
    return this.held;
  }

  /**
   * Does the principal hold `key` at ANY scope? The single-key form of
   * `heldKeys` — the right question for "should this button exist at all"
   * when the concrete scope is not yet known. Never a gate.
   */
  holds(key: LooseKey<K>): boolean {
    if (!this.active) return false;
    return keyHeldAnywhere(this.ctx, key as PermissionKey);
  }

  /** The listing primitive, synchronously — feed to `planListing`. */
  grantedScopes(key: LooseKey<K>): {
    granted: Set<ScopeId>;
    revoked: Set<ScopeId>;
  } {
    if (!this.active) return { granted: new Set(), revoked: new Set() };
    return {
      granted: grantedScopesFor(this.ctx, key as PermissionKey),
      revoked: revokedScopesFor(this.ctx, key as PermissionKey),
    };
  }

  /** `can` with its work shown; agrees with `can` exactly. */
  explain(
    key: LooseKey<K>,
    scope?: ScopeId,
  ): CheckExplanation & {
    objectClosure: ScopeId[];
    active: boolean;
    /** Allowed only through §7.5 ancestor implication, not a direct match. */
    implied: boolean;
  } {
    const closure = this.closureOf(scope);
    const explanation = explainKey(this.ctx, key as PermissionKey, closure);
    let allowed = explanation.allowed && this.active;
    let implied = false;
    if (
      !allowed &&
      this.active &&
      explanation.matchedRevokes.length === 0 &&
      scope !== undefined &&
      scope !== GLOBAL_SCOPE
    ) {
      implied = this.impliedAt(key as PermissionKey, scope);
      allowed = implied;
    }
    return {
      ...explanation,
      allowed,
      implied,
      objectClosure: [...closure],
      active: this.active,
    };
  }
}
