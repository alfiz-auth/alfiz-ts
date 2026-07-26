/**
 * The AlfizClient: the evaluator. Checks execute in-process against
 * provider-supplied data — closures are cached as evaluation state,
 * parameterized by provider invalidation events; decisions are never cached.
 *
 * Check shapes: `can` (the only gate shape), `canAny` (visibility affordance
 * only), their throwing `require*` forms, and `can.fresh`, which bypasses all
 * caches — the intended pairing for destructive actions and time-bound
 * elevations. Server-rendered request handling has a third surface:
 * `snapshot(principal)` fetches once and then checks SYNCHRONOUSLY — see
 * snapshot.ts; it is the intended shape wherever render helpers cannot be
 * async.
 *
 * Every check is verified against the catalog before it is evaluated: a key
 * or pattern the catalog does not declare raises `UnknownPermissionError`
 * (a programming error — map it to 500, never 403) rather than being
 * evaluated. Typed keys and the static verifier cover literal call sites;
 * this covers the runtime-string paths they cannot see, and closes the hole
 * where an undeclared key would pass for any holder of a covering wildcard.
 *
 * Staleness bounds, stated honestly: subject-side data lives for
 * `subjectCacheTtlMs` (default 30s) unless an invalidation event lands
 * sooner; object ancestor chains live for `objectCacheTtlMs` (default 60s)
 * unless a `scope` event lands sooner. Providers emit `scope` events for
 * moves they perform; moves the HOST application performs in its own tables
 * must be reported via `AlfizApplication.notifyScopeMoved` (or an equivalent
 * provider event) for immediate effect — the TTL is the backstop, not the
 * mechanism.
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
import { AccessDeniedError, UnknownPermissionError } from "./errors.js";
import type { LooseKey, PermissionKey, PermissionPattern } from "./grammar.js";
import { patternMatchesKey } from "./grammar.js";
import type {
  AlfizProvider,
  PrincipalRef,
  SubjectAccessData,
} from "./provider.js";
import type { LooseScopeId, ScopeId } from "./scopes.js";
import { GLOBAL_SCOPE, objectClosureOf } from "./scopes.js";
import type { SnapshotOptions } from "./snapshot.js";
import { AlfizSnapshot } from "./snapshot.js";

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
  /**
   * Object-chain cache TTL (ms). Chains are deep, narrow, and near-static;
   * `scope` invalidation events bust them immediately on move, and this TTL
   * bounds staleness when a move was never reported. Default 60s.
   */
  objectCacheTtlMs?: number;
  /** Maximum cached principals before oldest entries are evicted. Default 10 000. */
  maxSubjectCacheEntries?: number;
  clock?: () => number;
}

interface SubjectCacheEntry {
  data: SubjectAccessData;
  expiresAt: number;
}

interface ObjectCacheEntry {
  chain: ScopeId[];
  expiresAt: number;
}

const principalKey = (p: PrincipalRef): string =>
  "userId" in p ? `u:${p.userId}` : `s:${p.serviceId}`;

/** Builds the pure-evaluation context from provider-supplied data. */
export function toCheckContext(
  data: SubjectAccessData,
  now: number,
  grantApplies?: (key: PermissionKey, grantScope: ScopeId) => boolean,
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
    grantApplies,
  };
}

export interface CanFn<K extends string, S extends string = string> {
  (
    principal: PrincipalRef,
    key: K | readonly K[],
    scope?: LooseScopeId<S>,
  ): Promise<boolean>;
  /**
   * Bypasses all caches: fresh closure supply, fresh ancestry. Use for
   * destructive surfaces and time-bound elevations, where the bounded
   * staleness of the cached path is not acceptable.
   */
  fresh(
    principal: PrincipalRef,
    key: K | readonly K[],
    scope?: LooseScopeId<S>,
  ): Promise<boolean>;
}

/**
 * Generic over the catalog's derived key, pattern, and scope-id unions.
 * Construct with `createAlfizClient(options)` to infer all three from the
 * catalog literal. Keys and patterns GATE at compile time; scope ids HINT
 * (`LooseScopeId`): literal scopes autocomplete their declared
 * `<scopeType>:` prefixes, while ids from variables flow through — the
 * instance half of a scope id is runtime data by nature.
 */
export class AlfizClient<
  K extends string = string,
  P extends string = string,
  S extends string = string,
> {
  readonly catalog: AnyCatalog;
  readonly provider: AlfizProvider;
  readonly can: CanFn<K, S>;

  private readonly subjectTtl: number;
  private readonly objectTtl: number;
  private readonly maxSubjects: number;
  private readonly now: () => number;
  private readonly subjectCache = new Map<string, SubjectCacheEntry>();
  private readonly objectCache = new Map<ScopeId, ObjectCacheEntry>();
  /**
   * Bust-during-fetch protection: every invalidation bumps the generation
   * for the affected key; a fetch only stores its result if no bust landed
   * while it was in flight.
   */
  private readonly subjectGen = new Map<string, number>();
  private readonly objectGen = new Map<ScopeId, number>();
  private readonly subjectInFlight = new Map<
    string,
    Promise<SubjectAccessData>
  >();
  private readonly unsubscribe: () => void;
  private readonly grantApplies: (
    key: PermissionKey,
    grantScope: ScopeId,
  ) => boolean;

  constructor(options: AlfizClientOptions) {
    this.catalog = options.catalog;
    this.provider = options.provider;
    this.subjectTtl = options.subjectCacheTtlMs ?? 30_000;
    this.objectTtl = options.objectCacheTtlMs ?? 60_000;
    this.maxSubjects = options.maxSubjectCacheEntries ?? 10_000;
    this.now = options.clock ?? Date.now;
    this.grantApplies = (key, grantScope) =>
      this.catalog.appliesAt(key, grantScope);

    const can = (async (
      principal: PrincipalRef,
      key: K | readonly K[],
      scope?: LooseScopeId<S>,
    ) => this.check(principal, key, scope, false)) as CanFn<K, S>;
    can.fresh = async (principal, key, scope?) =>
      this.check(principal, key, scope, true);
    this.can = can;

    this.unsubscribe = this.provider.onInvalidate((event) => {
      switch (event.type) {
        case "user":
          this.bustSubject(`u:${event.userId}`);
          break;
        case "subject":
          for (const [cacheKey, entry] of this.subjectCache) {
            if (entry.data.closure.includes(event.subject)) {
              this.bustSubject(cacheKey);
            }
          }
          break;
        case "scope":
          // Object chains bust immediately on move: the moved scope's own
          // chain, and every cached chain passing through it.
          this.bustObject(event.scope);
          for (const [cached, entry] of this.objectCache) {
            if (entry.chain.includes(event.scope)) this.bustObject(cached);
          }
          break;
        case "role":
          // Role definitions ride inside subject data; bust conservatively.
          for (const [cacheKey, entry] of this.subjectCache) {
            if (entry.data.roles.some((r) => r.id === event.roleId)) {
              this.bustSubject(cacheKey);
            }
          }
          break;
        case "catalog":
        case "all":
          for (const cacheKey of [...this.subjectCache.keys()]) {
            this.bustSubject(cacheKey);
          }
          for (const scope of [...this.objectCache.keys()]) {
            this.bustObject(scope);
          }
          break;
      }
    });
  }

  private bustSubject(cacheKey: string): void {
    this.subjectCache.delete(cacheKey);
    this.subjectGen.set(cacheKey, (this.subjectGen.get(cacheKey) ?? 0) + 1);
  }

  private bustObject(scope: ScopeId): void {
    this.objectCache.delete(scope);
    this.objectGen.set(scope, (this.objectGen.get(scope) ?? 0) + 1);
  }

  /** Detach from the provider's invalidation stream and drop caches. */
  close(): void {
    this.unsubscribe();
    this.subjectCache.clear();
    this.objectCache.clear();
    this.subjectGen.clear();
    this.objectGen.clear();
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
    const generation = this.subjectGen.get(key) ?? 0;
    const fetching = this.provider.getSubjectAccess(principal).then((data) => {
      if ((this.subjectGen.get(key) ?? 0) === generation) {
        this.subjectCache.set(key, {
          data,
          expiresAt: this.now() + this.subjectTtl,
        });
        // Bounded cache: evict oldest entries (Map preserves insertion order).
        while (this.subjectCache.size > this.maxSubjects) {
          const oldest = this.subjectCache.keys().next().value;
          if (oldest === undefined) break;
          this.subjectCache.delete(oldest);
        }
      }
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
    const now = this.now();
    if (!fresh) {
      const cached = this.objectCache.get(scope);
      if (cached && cached.expiresAt > now) return cached.chain;
    }
    const generation = this.objectGen.get(scope) ?? 0;
    const chain = await objectClosureOf(scope, this.provider.resolveAncestors);
    if ((this.objectGen.get(scope) ?? 0) === generation) {
      this.objectCache.set(scope, {
        chain,
        expiresAt: this.now() + this.objectTtl,
      });
    }
    return chain;
  }

  // -- checks ---------------------------------------------------------------

  private ctxOf(data: SubjectAccessData): CheckContext {
    return toCheckContext(data, this.now(), this.grantApplies);
  }

  /**
   * Every check is verified against the catalog before it is evaluated.
   * Typed keys and the static verifier cover literal call sites; this covers
   * the runtime-string paths they cannot see — and closes the hole where an
   * undeclared key would pass for any holder of a covering wildcard. See
   * {@link UnknownPermissionError}.
   */
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

  private async check(
    principal: PrincipalRef,
    key: K | readonly K[],
    scope: ScopeId | undefined,
    fresh: boolean,
  ): Promise<boolean> {
    const keys: readonly PermissionKey[] = Array.isArray(key)
      ? (key as readonly string[])
      : [key as string];
    this.assertKeys(keys);
    const [data, closure] = await Promise.all([
      this.subjectData(principal, fresh),
      this.objectClosure(scope, fresh),
    ]);
    if (!data.active) return false;
    const ctx = this.ctxOf(data);
    for (const k of keys) {
      if (checkKey(ctx, k, closure)) return true;
    }
    // Ancestor visibility (§7.5): a leaf marked impliedOnAncestors is implied
    // on PROPER ancestors of a granted scope — never at the global scope,
    // which would turn one narrow share into the broadest possible check
    // passing (can(u, key, "*") must agree with can(u, key)).
    if (scope !== undefined && scope !== GLOBAL_SCOPE) {
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
   * One provider round-trip, then synchronous checks: the request-scoped
   * snapshot, THE pattern for server-rendered frameworks (see snapshot.ts).
   * Resolves the chain of every scope appearing in the principal's own
   * grant and revoke rows — so `snap.canAny`, revoke suppression, and
   * ancestor implication are exact — plus any `options.scopes` you intend
   * to check against. Flat top-level scope types need no pre-resolution;
   * hierarchical ones do.
   *
   * Draws from the same caches as `can` (a snapshot is one CONSISTENT
   * instant of them, which is a stronger per-request guarantee than calling
   * `can` repeatedly); `fresh: true` bypasses the caches like `can.fresh`.
   */
  async snapshot(
    principal: PrincipalRef,
    options?: SnapshotOptions<S>,
  ): Promise<AlfizSnapshot<K, P, S>> {
    const fresh = options?.fresh ?? false;
    const data = await this.subjectData(principal, fresh);
    const ctx = this.ctxOf(data);
    const wanted = new Set<ScopeId>();
    for (const scope of options?.scopes ?? []) {
      if (scope !== GLOBAL_SCOPE) wanted.add(scope);
    }
    for (const grant of data.grants) {
      if (grant.scope !== GLOBAL_SCOPE) wanted.add(grant.scope);
    }
    for (const revoke of data.revokes) {
      if (revoke.scope !== GLOBAL_SCOPE) wanted.add(revoke.scope);
    }
    const chains = new Map<ScopeId, readonly ScopeId[]>();
    await Promise.all(
      [...wanted].map(async (scope) => {
        chains.set(scope, await this.objectClosure(scope, fresh));
      }),
    );
    return new AlfizSnapshot<K, P, S>({
      catalog: this.catalog,
      principal,
      data,
      ctx,
      chains,
      // Bound to this snapshot's freshness, so `resolve` mid-request keeps
      // the same cache posture the snapshot was taken with.
      resolveChain: (scope) => this.objectClosure(scope, fresh),
    });
  }

  /**
   * The visibility affordance: does effective access intersect `pattern` at
   * all, at any scope? Never a gate — the static verifier errors on `canAny`
   * in server actions and route handlers.
   */
  async canAny(principal: PrincipalRef, pattern: P): Promise<boolean> {
    this.assertPattern(pattern);
    const data = await this.subjectData(principal, false);
    if (!data.active) return false;
    const ctx = this.ctxOf(data);
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
    scope?: LooseScopeId<S>,
  ): Promise<void> {
    this.assertKeys(
      (Array.isArray(key) ? key : [key]) as readonly PermissionKey[],
    );
    const data = await this.subjectData(principal, false);
    if (!data.active) {
      throw new AccessDeniedError({
        reason: "inactive",
        permission: key as PermissionKey | readonly PermissionKey[],
        scope,
        principal,
      });
    }
    if (!(await this.can(principal, key, scope))) {
      throw new AccessDeniedError({
        reason: "forbidden",
        permission: key as PermissionKey | readonly PermissionKey[],
        scope,
        principal,
      });
    }
  }

  /** Throwing form of `canAny` — project-root visibility (`requireAny("project.*")`). */
  async requireAny(principal: PrincipalRef, pattern: P): Promise<void> {
    this.assertPattern(pattern);
    if (!(await this.canAny(principal, pattern))) {
      throw new AccessDeniedError({
        reason: "forbidden",
        permission: pattern as PermissionKey,
        principal,
      });
    }
  }

  /**
   * `checkKey` with its work shown — the auditability surface. Agrees with
   * `can` exactly: ancestor implication is included and reported.
   */
  async explain(
    principal: PrincipalRef,
    key: LooseKey<K>,
    scope?: LooseScopeId<S>,
  ): Promise<
    CheckExplanation & {
      objectClosure: ScopeId[];
      active: boolean;
      /** Allowed only through §7.5 ancestor implication, not a direct match. */
      implied: boolean;
    }
  > {
    this.assertKeys([key as PermissionKey]);
    const [data, closure] = await Promise.all([
      this.subjectData(principal, false),
      this.objectClosure(scope, false),
    ]);
    const ctx = this.ctxOf(data);
    const explanation = explainKey(ctx, key as PermissionKey, closure);
    let allowed = explanation.allowed && data.active;
    let implied = false;
    if (
      !allowed &&
      data.active &&
      explanation.matchedRevokes.length === 0 &&
      scope !== undefined &&
      scope !== GLOBAL_SCOPE &&
      this.catalog.leaf(key as PermissionKey)?.impliedOnAncestors
    ) {
      implied = await this.checkImplied(ctx, key as PermissionKey, scope, false);
      allowed = implied;
    }
    return {
      ...explanation,
      allowed,
      implied,
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
    key: LooseKey<K>,
  ): Promise<{ granted: Set<ScopeId>; revoked: Set<ScopeId> }> {
    this.assertKeys([key as PermissionKey]);
    const data = await this.subjectData(principal, false);
    if (!data.active) return { granted: new Set(), revoked: new Set() };
    const ctx = this.ctxOf(data);
    return {
      granted: grantedScopesFor(ctx, key as PermissionKey),
      revoked: revokedScopesFor(ctx, key as PermissionKey),
    };
  }

  /**
   * Does the principal hold `key` at ANY scope? The single-key "holds it
   * anywhere" probe (see `keyHeldAnywhere` for the exact semantics). This is
   * a legitimate — and under scoped grants, the RIGHT — question for
   * unscoped conditional UI: an instructor holding `publish_course` only at
   * the courses they teach should still see the button surface exist.
   * Never a gate: the action behind the button still gates with `can` at
   * its concrete scope. O(rows) for one key; for many keys per request,
   * prefer `snapshot(principal).heldKeys`.
   */
  async holdsAnywhere(
    principal: PrincipalRef,
    key: LooseKey<K>,
  ): Promise<boolean> {
    this.assertKeys([key as PermissionKey]);
    const data = await this.subjectData(principal, false);
    if (!data.active) return false;
    return keyHeldAnywhere(this.ctxOf(data), key as PermissionKey);
  }

  /**
   * Every concrete catalog key the principal holds SOMEWHERE: granted by an
   * applicable unexpired row at any scope, suppressed only by global-scope
   * revokes (a folder-scoped revoke narrows one subtree; it does not erase
   * a key held elsewhere). "Not a gate" does not mean "not useful": this is
   * the right feed for unscoped conditional UI under scoped grants — it is
   * simply never the thing that AUTHORIZES an action, which always gates
   * with `can` at a concrete scope. O(catalog); call once per request and
   * reuse — `snapshot(principal).heldKeys` does exactly that.
   */
  async effectiveKeys(principal: PrincipalRef): Promise<PermissionKey[]> {
    const data = await this.subjectData(principal, false);
    if (!data.active) return [];
    const ctx = this.ctxOf(data);
    return this.catalog.keys.filter((key) => keyHeldAnywhere(ctx, key));
  }
}

/**
 * Constructs a client whose `can`/`canAny` are typed by the catalog's
 * derived key and pattern unions — every key at every call site is
 * compile-time verified against the catalog — and whose scope parameters
 * autocomplete the declared `<scopeType>:` prefixes.
 */
export function createAlfizClient<Cat extends AnyCatalog>(
  options: Omit<AlfizClientOptions, "catalog"> & { catalog: Cat },
): AlfizClient<Cat["$key"], Cat["$pattern"], Cat["$scope"]> {
  return new AlfizClient(options);
}

/**
 * The client type for a catalog — `ClientOf<typeof catalog>` — so a client
 * stored on a context object needs no hand-written type parameters.
 * Completes the derived-type family with `KeyOf` / `PatternOf` /
 * `ScopeOf` / `SnapshotOf`.
 */
export type ClientOf<Cat> = AlfizClient<KeyOf<Cat>, PatternOf<Cat>, ScopeOf<Cat>>;
