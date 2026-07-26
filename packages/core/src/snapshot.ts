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
 *   - A hierarchical LIST page cannot know its row ids until it has
 *     queried, which inverts that order. `await snap.resolve(rowScopes)`
 *     extends an existing snapshot in place — no second closure fetch, so
 *     the data instant and clock are unchanged. Guard the page, query,
 *     resolve, then check rows. (For large result sets, push the filter
 *     into the database instead — `grantedScopes` + `planListing` — rather
 *     than resolving a chain per row.)
 *
 * Checks are verified against the catalog, exactly as on the client: an
 * undeclared key or pattern raises `UnknownPermissionError` instead of
 * being evaluated.
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
import type { AnyCatalog, KeyOf, PatternOf, ScopeOf } from "./catalog.js";
import { unknownPermissionContext } from "./catalog.js";
import {
  AccessDeniedError,
  UnknownPermissionError,
  UnresolvedScopeError,
} from "./errors.js";
import type { LooseKey, PermissionKey, PermissionPattern } from "./grammar.js";
import { patternMatchesKey } from "./grammar.js";
import type { PrincipalRef, SubjectAccessData } from "./provider.js";
import type { LooseScopeId, ScopeId } from "./scopes.js";
import { GLOBAL_SCOPE, scopeTypeOf } from "./scopes.js";

/** Options for `AlfizClient.snapshot`. */
export interface SnapshotOptions<S extends string = string> {
  /**
   * Scope instances to pre-resolve for synchronous scoped checks. Needed
   * only for HIERARCHICAL scope types (a declared parent, or multi-parent):
   * flat top-level types, and every scope appearing in the principal's own
   * grant and revoke rows, are resolved automatically.
   */
  scopes?: readonly LooseScopeId<S>[] | undefined;
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
  chains: Map<ScopeId, readonly ScopeId[]>;
  /**
   * Resolves one scope's ancestor chain — the client's cached resolver,
   * bound to this snapshot's `fresh` setting. Backs `resolve()`, which
   * extends the snapshot WITHOUT re-fetching subject data, so the
   * consistency guarantee survives.
   */
  resolveChain: (scope: ScopeId) => Promise<readonly ScopeId[]>;
}

const GLOBAL_CLOSURE: readonly ScopeId[] = [GLOBAL_SCOPE];

/**
 * Synchronous evaluation over one consistent instant of a principal's
 * access. Construct with `client.snapshot(principal)`; typed by the
 * catalog's derived unions exactly like the client.
 */
export class AlfizSnapshot<
  K extends string = string,
  P extends string = string,
  S extends string = string,
> {
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
  private readonly chains: Map<ScopeId, readonly ScopeId[]>;
  private readonly resolveChain: (scope: ScopeId) => Promise<readonly ScopeId[]>;
  private held: Set<PermissionKey> | null = null;

  constructor(init: SnapshotInit) {
    this.catalog = init.catalog;
    this.principal = init.principal;
    this.data = init.data;
    this.active = init.data.active;
    this.ctx = init.ctx;
    this.chains = init.chains;
    this.resolveChain = init.resolveChain;
    this.at = init.ctx.now;
  }

  /**
   * Resolves more scope chains INTO this snapshot — no second closure
   * fetch, so the data instant and the evaluation clock are unchanged and
   * every check still sees one consistent instant.
   *
   * This is the shape hierarchical list pages want, because the page cannot
   * know its row ids until after it has queried:
   *
   * ```ts
   * const snap = await alfiz.snapshot(principal);   // guard the page
   * snap.require("docs.files.read");
   * const rows = await db.docs.findMany(...);       // now the ids exist
   * await snap.resolve(rows.map((r) => `docs.doc:${r.id}`));
   * rows.filter((r) => snap.can("docs.files.update_file", `docs.doc:${r.id}`));
   * ```
   *
   * For a LARGE result set, prefer pushing the filter into the database —
   * `grantedScopes` + `planListing` + the query helpers in listing.ts —
   * rather than resolving a chain per row; per-row checks are the N+1 this
   * library is explicit about avoiding. `resolve` is for the tens-of-rows
   * case and for enriching a snapshot mid-request.
   *
   * Already-resolved scopes are skipped; returns this snapshot for
   * chaining.
   */
  async resolve(scopes: readonly LooseScopeId<S>[]): Promise<this> {
    const missing = [
      ...new Set(
        scopes.filter((s) => s !== GLOBAL_SCOPE && !this.chains.has(s)),
      ),
    ];
    await Promise.all(
      missing.map(async (scope) => {
        this.chains.set(scope, await this.resolveChain(scope));
      }),
    );
    return this;
  }

  /** Scopes whose ancestor chain this snapshot can already evaluate. */
  get resolvedScopes(): ReadonlySet<ScopeId> {
    return new Set(this.chains.keys());
  }

  /** See `AlfizClient`'s: checks are verified against the catalog first. */
  private assertKeys(keys: readonly PermissionKey[]): void {
    for (const key of keys) {
      if (this.catalog.hasKey(key)) continue;
      throw new UnknownPermissionError({
        permission: key,
        expected: "key",
        ...unknownPermissionContext(this.catalog, key, "key"),
      });
    }
  }

  private assertPattern(pattern: PermissionPattern): void {
    if (this.catalog.isKnownPattern(pattern)) return;
    throw new UnknownPermissionError({
      permission: pattern,
      expected: "pattern",
      ...unknownPermissionContext(this.catalog, pattern, "pattern"),
    });
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
    throw new UnresolvedScopeError({
      scope,
      scopeType: type,
      declared: meta !== undefined,
      declaredScopeTypes: [...this.catalog.scopeTypes.keys()],
      resolvedScopes: [...this.chains.keys()],
    });
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
  can(key: K | readonly K[], scope?: LooseScopeId<S>): boolean {
    const keys: readonly PermissionKey[] = Array.isArray(key)
      ? (key as readonly string[])
      : [key as string];
    this.assertKeys(keys);
    if (!this.active) return false;
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
    this.assertPattern(pattern);
    if (!this.active) return false;
    return checkAny(this.ctx, pattern, this.catalog.keys, this.chains);
  }

  /** Throwing form of `can`. */
  require(key: K | readonly K[], scope?: LooseScopeId<S>): void {
    this.assertKeys(
      (Array.isArray(key) ? key : [key]) as readonly PermissionKey[],
    );
    if (!this.active) {
      throw new AccessDeniedError({
        reason: "inactive",
        permission: key as PermissionKey | readonly PermissionKey[],
        scope,
        principal: this.principal,
      });
    }
    if (!this.can(key, scope)) {
      throw new AccessDeniedError({
        reason: "forbidden",
        permission: key as PermissionKey | readonly PermissionKey[],
        scope,
        principal: this.principal,
      });
    }
  }

  /** Throwing form of `canAny` — project-root visibility. */
  requireAny(pattern: P): void {
    this.assertPattern(pattern);
    if (!this.canAny(pattern)) {
      throw new AccessDeniedError({
        reason: this.active ? "forbidden" : "inactive",
        permission: pattern as PermissionKey,
        principal: this.principal,
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
    this.assertKeys([key as PermissionKey]);
    if (!this.active) return false;
    return keyHeldAnywhere(this.ctx, key as PermissionKey);
  }

  /** The listing primitive, synchronously — feed to `planListing`. */
  grantedScopes(key: LooseKey<K>): {
    granted: Set<ScopeId>;
    revoked: Set<ScopeId>;
  } {
    this.assertKeys([key as PermissionKey]);
    if (!this.active) return { granted: new Set(), revoked: new Set() };
    return {
      granted: grantedScopesFor(this.ctx, key as PermissionKey),
      revoked: revokedScopesFor(this.ctx, key as PermissionKey),
    };
  }

  /** `can` with its work shown; agrees with `can` exactly. */
  explain(
    key: LooseKey<K>,
    scope?: LooseScopeId<S>,
  ): CheckExplanation & {
    objectClosure: ScopeId[];
    active: boolean;
    /** Allowed only through §7.5 ancestor implication, not a direct match. */
    implied: boolean;
  } {
    this.assertKeys([key as PermissionKey]);
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

/**
 * The snapshot type for a catalog — `SnapshotOf<typeof catalog>` — so a
 * snapshot stored on a request-context or actor object needs no
 * hand-written type parameters. Completes the derived-type family with
 * `KeyOf` / `PatternOf` / `ScopeOf` / `ClientOf`.
 */
export type SnapshotOf<Cat> = AlfizSnapshot<KeyOf<Cat>, PatternOf<Cat>, ScopeOf<Cat>>;
