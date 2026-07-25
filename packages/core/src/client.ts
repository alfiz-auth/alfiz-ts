/**
 * The AlfizClient: the evaluator. Checks execute in-process against
 * provider-supplied data — closures are cached as evaluation state,
 * parameterized by provider invalidation events; decisions are never cached.
 *
 * Check shapes: `can` (the only gate shape), `canAny` (visibility affordance
 * only), their throwing `require*` forms, and `can.fresh`, which bypasses all
 * caches — the intended pairing for destructive actions and time-bound
 * elevations.
 */

import type { CheckContext, CheckExplanation, RoleDef } from "./access.js";
import {
  checkAny,
  checkKey,
  explainKey,
  grantedScopesFor,
  isExpired,
  patternsOfGrant,
  revokedScopesFor,
} from "./access.js";
import type { AnyCatalog } from "./catalog.js";
import { AccessDeniedError } from "./errors.js";
import type { PermissionKey } from "./grammar.js";
import { patternMatchesKey } from "./grammar.js";
import type {
  AlfizProvider,
  PrincipalRef,
  SubjectAccessData,
} from "./provider.js";
import type { ScopeId } from "./scopes.js";
import { GLOBAL_SCOPE, objectClosureOf } from "./scopes.js";

export interface AlfizClientOptions {
  catalog: AnyCatalog;
  provider: AlfizProvider;
  /**
   * Subject-side cache TTL (ms). Subject closures are shallow, wide, and
   * high-churn; they tolerate seconds-to-minutes propagation. Default 30s.
   * This is the documented staleness bound for revocation propagation —
   * `can.fresh` is the escape hatch.
   */
  subjectCacheTtlMs?: number;
  clock?: () => number;
}

interface SubjectCacheEntry {
  data: SubjectAccessData;
  expiresAt: number;
}

const principalKey = (p: PrincipalRef): string =>
  "userId" in p ? `u:${p.userId}` : `s:${p.serviceId}`;

/** Builds the pure-evaluation context from provider-supplied data. */
export function toCheckContext(
  data: SubjectAccessData,
  now: number,
): CheckContext {
  return {
    subjectClosure: new Set(data.closure),
    userId: data.userId,
    rows: {
      grants: data.grants,
      revokes: data.revokes,
      roles: new Map(data.roles.map((r) => [r.id, r])),
    },
    now,
  };
}

export interface CanFn<K extends string> {
  (
    principal: PrincipalRef,
    key: K | readonly K[],
    scope?: ScopeId,
  ): Promise<boolean>;
  /**
   * Bypasses all caches: fresh closure supply, fresh ancestry. Use for
   * destructive surfaces and time-bound elevations, where the bounded
   * staleness of the cached path is not acceptable.
   */
  fresh(
    principal: PrincipalRef,
    key: K | readonly K[],
    scope?: ScopeId,
  ): Promise<boolean>;
}

/**
 * Generic over the catalog's derived key and pattern unions. Construct with
 * `createAlfizClient(options)` to infer both from the catalog literal.
 */
export class AlfizClient<K extends string = string, P extends string = string> {
  readonly catalog: AnyCatalog;
  readonly provider: AlfizProvider;
  readonly can: CanFn<K>;

  private readonly ttl: number;
  private readonly now: () => number;
  private readonly subjectCache = new Map<string, SubjectCacheEntry>();
  private readonly subjectInFlight = new Map<
    string,
    Promise<SubjectAccessData>
  >();
  private readonly objectCache = new Map<ScopeId, ScopeId[]>();
  private readonly unsubscribe: () => void;

  constructor(options: AlfizClientOptions) {
    this.catalog = options.catalog;
    this.provider = options.provider;
    this.ttl = options.subjectCacheTtlMs ?? 30_000;
    this.now = options.clock ?? Date.now;

    const can = (async (
      principal: PrincipalRef,
      key: K | readonly K[],
      scope?: ScopeId,
    ) => this.check(principal, key, scope, false)) as CanFn<K>;
    can.fresh = async (principal, key, scope?) =>
      this.check(principal, key, scope, true);
    this.can = can;

    this.unsubscribe = this.provider.onInvalidate((event) => {
      switch (event.type) {
        case "user":
          this.subjectCache.delete(`u:${event.userId}`);
          break;
        case "subject":
          for (const [cacheKey, entry] of this.subjectCache) {
            if (entry.data.closure.includes(event.subject)) {
              this.subjectCache.delete(cacheKey);
            }
          }
          break;
        case "scope":
          // Object chains bust immediately on move: the moved scope's own
          // chain, and every cached chain passing through it.
          this.objectCache.delete(event.scope);
          for (const [cached, chain] of this.objectCache) {
            if (chain.includes(event.scope)) this.objectCache.delete(cached);
          }
          break;
        case "role":
          // Role definitions ride inside subject data; bust conservatively.
          for (const [cacheKey, entry] of this.subjectCache) {
            if (entry.data.roles.some((r) => r.id === event.roleId)) {
              this.subjectCache.delete(cacheKey);
            }
          }
          break;
        case "catalog":
        case "all":
          this.subjectCache.clear();
          this.objectCache.clear();
          break;
      }
    });
  }

  /** Detach from the provider's invalidation stream and drop caches. */
  close(): void {
    this.unsubscribe();
    this.subjectCache.clear();
    this.objectCache.clear();
  }

  // -- data supply ----------------------------------------------------------

  private async subjectData(
    principal: PrincipalRef,
    fresh: boolean,
  ): Promise<SubjectAccessData> {
    const key = principalKey(principal);
    const now = this.now();
    if (!fresh) {
      const cached = this.subjectCache.get(key);
      if (cached && cached.expiresAt > now) return cached.data;
      const inFlight = this.subjectInFlight.get(key);
      if (inFlight) return inFlight;
    }
    const fetching = this.provider.getSubjectAccess(principal).then((data) => {
      this.subjectCache.set(key, { data, expiresAt: this.now() + this.ttl });
      this.subjectInFlight.delete(key);
      return data;
    });
    if (!fresh) this.subjectInFlight.set(key, fetching);
    try {
      return await fetching;
    } finally {
      this.subjectInFlight.delete(key);
    }
  }

  private async objectClosure(
    scope: ScopeId | undefined,
    fresh: boolean,
  ): Promise<ScopeId[]> {
    if (scope === undefined || scope === GLOBAL_SCOPE) return [GLOBAL_SCOPE];
    if (!fresh) {
      const cached = this.objectCache.get(scope);
      if (cached) return cached;
    }
    const closure = await objectClosureOf(scope, this.provider.resolveAncestors);
    this.objectCache.set(scope, closure);
    return closure;
  }

  // -- checks ---------------------------------------------------------------

  private async check(
    principal: PrincipalRef,
    key: K | readonly K[],
    scope: ScopeId | undefined,
    fresh: boolean,
  ): Promise<boolean> {
    const keys: readonly PermissionKey[] = Array.isArray(key)
      ? (key as readonly string[])
      : [key as string];
    const [data, closure] = await Promise.all([
      this.subjectData(principal, fresh),
      this.objectClosure(scope, fresh),
    ]);
    if (!data.active) return false;
    const ctx = toCheckContext(data, this.now());
    for (const k of keys) {
      if (checkKey(ctx, k, closure)) return true;
    }
    // Ancestor visibility (§7.5): a leaf marked impliedOnAncestors is implied
    // on ancestors of any scope where it is (unsuppressed) granted.
    if (scope !== undefined) {
      for (const k of keys) {
        if (!this.catalog.leaf(k)?.impliedOnAncestors) continue;
        if (await this.checkImplied(ctx, k, scope, fresh)) return true;
      }
    }
    return false;
  }

  private async checkImplied(
    ctx: CheckContext,
    key: PermissionKey,
    target: ScopeId,
    fresh: boolean,
  ): Promise<boolean> {
    for (const grantScope of grantedScopesFor(ctx, key)) {
      if (grantScope === GLOBAL_SCOPE || grantScope === target) continue;
      const chain = await this.objectClosure(grantScope, fresh);
      if (!chain.includes(target)) continue;
      // The implication carries only if the underlying grant itself is not
      // suppressed by a revoke covering the granted scope.
      const suppressed =
        ctx.userId !== null &&
        ctx.rows.revokes.some(
          (r) =>
            r.userId === ctx.userId &&
            patternMatchesKey(r.pattern, key) &&
            chain.includes(r.scope),
        );
      if (!suppressed) return true;
    }
    return false;
  }

  /**
   * The visibility affordance: does effective access intersect `pattern` at
   * all, at any scope? Never a gate — the static verifier errors on `canAny`
   * in server actions and route handlers.
   */
  async canAny(principal: PrincipalRef, pattern: P): Promise<boolean> {
    const data = await this.subjectData(principal, false);
    if (!data.active) return false;
    const ctx = toCheckContext(data, this.now());
    // Resolve each distinct granted scope's chain so revoke suppression is
    // exact rather than the conservative approximation.
    const scopes = new Set<ScopeId>();
    for (const grant of ctx.rows.grants) {
      if (grant.scope !== GLOBAL_SCOPE) scopes.add(grant.scope);
    }
    const closures = new Map<ScopeId, readonly ScopeId[]>();
    for (const s of scopes) {
      closures.set(s, await this.objectClosure(s, false));
    }
    return checkAny(ctx, pattern, this.catalog.keys, closures);
  }

  /** Throwing form of `can`. */
  async requirePermission(
    principal: PrincipalRef,
    key: K | readonly K[],
    scope?: ScopeId,
  ): Promise<void> {
    const data = await this.subjectData(principal, false);
    if (!data.active) {
      throw new AccessDeniedError({
        reason: "inactive",
        permission: key as PermissionKey | readonly PermissionKey[],
        scope,
      });
    }
    if (!(await this.can(principal, key, scope))) {
      throw new AccessDeniedError({
        reason: "forbidden",
        permission: key as PermissionKey | readonly PermissionKey[],
        scope,
      });
    }
  }

  /** Throwing form of `canAny` — project-root visibility (`requireAny("project.*")`). */
  async requireAny(principal: PrincipalRef, pattern: P): Promise<void> {
    if (!(await this.canAny(principal, pattern))) {
      throw new AccessDeniedError({
        reason: "forbidden",
        permission: pattern as PermissionKey,
      });
    }
  }

  /** `checkKey` with its work shown — the auditability surface. */
  async explain(
    principal: PrincipalRef,
    key: K,
    scope?: ScopeId,
  ): Promise<CheckExplanation & { objectClosure: ScopeId[]; active: boolean }> {
    const [data, closure] = await Promise.all([
      this.subjectData(principal, false),
      this.objectClosure(scope, false),
    ]);
    const ctx = toCheckContext(data, this.now());
    const explanation = explainKey(ctx, key as PermissionKey, closure);
    return {
      ...explanation,
      allowed: explanation.allowed && data.active,
      objectClosure: closure,
      active: data.active,
    };
  }

  /**
   * The listing primitive: scopes with matching unexpired grants for the
   * principal, plus the revoked-scope exclusion set — feed these to the
   * query helpers in listing.ts to push the filter into the database.
   */
  async grantedScopes(
    principal: PrincipalRef,
    key: K,
  ): Promise<{ granted: Set<ScopeId>; revoked: Set<ScopeId> }> {
    const data = await this.subjectData(principal, false);
    if (!data.active) return { granted: new Set(), revoked: new Set() };
    const ctx = toCheckContext(data, this.now());
    return {
      granted: grantedScopesFor(ctx, key as PermissionKey),
      revoked: revokedScopesFor(ctx, key as PermissionKey),
    };
  }

  /**
   * Every concrete catalog key the principal currently holds (at any scope),
   * revokes applied at the global level. A debugging and administration
   * surface, not a gate.
   */
  async effectiveKeys(principal: PrincipalRef): Promise<PermissionKey[]> {
    const data = await this.subjectData(principal, false);
    if (!data.active) return [];
    const ctx = toCheckContext(data, this.now());
    const roles: ReadonlyMap<string, RoleDef> = ctx.rows.roles;
    const held: PermissionKey[] = [];
    for (const key of this.catalog.keys) {
      let granted = false;
      for (const grant of ctx.rows.grants) {
        if (!ctx.subjectClosure.has(grant.subject)) continue;
        if (isExpired(grant, ctx.now)) continue;
        if (patternsOfGrant(grant, roles).some((p) => patternMatchesKey(p, key))) {
          granted = true;
          break;
        }
      }
      if (!granted) continue;
      const revoked =
        ctx.userId !== null &&
        ctx.rows.revokes.some(
          (r) => r.userId === ctx.userId && patternMatchesKey(r.pattern, key),
        );
      if (!revoked) held.push(key);
    }
    return held;
  }
}


/**
 * Constructs a client whose `can`/`canAny` are typed by the catalog's
 * derived key and pattern unions — every key at every call site is
 * compile-time verified against the catalog.
 */
export function createAlfizClient<Cat extends AnyCatalog>(
  options: Omit<AlfizClientOptions, "catalog"> & { catalog: Cat },
): AlfizClient<Cat["$key"], Cat["$pattern"]> {
  return new AlfizClient(options);
}
