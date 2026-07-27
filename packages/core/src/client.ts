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
  InvalidationEvent,
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
  /** Maximum cached principals before least-recently-used entries are evicted. Default 10 000. */
  maxSubjectCacheEntries?: number;
  /** Maximum cached object chains before least-recently-used entries are evicted. Default 10 000. */
  maxObjectCacheEntries?: number;
  /**
   * Epoch revalidation window (ms): how long a validation of the provider's
   * event log (`provider.epoch`) vouches for the caches. Within the window,
   * hits are pure memory. Past it, the next check performs ONE tiny
   * `epoch.head()` read — shared by every concurrent check, its cost
   * independent of organization size. An unchanged head proves nothing
   * changed anywhere, and entry TTLs are RENEWED; a changed head replays
   * only the missed events through the same busting logic the live stream
   * feeds. Effective cross-process staleness becomes ~this window instead
   * of the blind TTL; the TTL remains the fallback bound whenever the
   * epoch is unreadable (fail-closed: unvalidated entries expire and
   * refetch, stale data is never served past its window on error).
   *
   * Requires a provider exposing `epoch` (the Application's
   * `events.persist`); silently inert otherwise. 5 000 is a good default
   * for most deployments. Off (undefined) by default — TTL-only caching,
   * exactly the pre-epoch behavior.
   */
  revalidateAfterMs?: number;
  clock?: () => number;
}

interface SubjectCacheEntry {
  data: SubjectAccessData;
  expiresAt: number;
  /** The validation generation this entry was fetched under — see `validationGen`. */
  gen: number;
}

interface ObjectCacheEntry {
  chain: ScopeId[];
  expiresAt: number;
  gen: number;
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
  private readonly maxObjects: number;
  private readonly now: () => number;
  private readonly subjectCache = new Map<string, SubjectCacheEntry>();
  private readonly objectCache = new Map<ScopeId, ObjectCacheEntry>();
  /**
   * Secondary indexes over the caches, so invalidation events bust in
   * O(affected entries) instead of scanning every entry: subject id →
   * cache keys whose closure contains it; role id → cache keys whose data
   * references it; scope → cached scopes whose chain passes through it.
   * Maintained exclusively by the store/drop pairs below — eviction and
   * busting share them, so the indexes can never drift from the caches.
   */
  private readonly closureIndex = new Map<string, Set<string>>();
  private readonly roleIndex = new Map<string, Set<string>>();
  private readonly chainIndex = new Map<ScopeId, Set<ScopeId>>();
  /**
   * Bust-during-fetch protection: every in-flight fetch registers a
   * cancellation record; a bust marks the key's records cancelled, and a
   * fetch stores its result only if its own record survived. Records remove
   * themselves on settle, so memory is bounded by in-flight fetches — not,
   * as with the generation counters this replaces, by every key ever busted.
   */
  private readonly subjectFetchStates = new Map<
    string,
    Set<{ cancelled: boolean }>
  >();
  private readonly objectFetchStates = new Map<
    ScopeId,
    Set<{ cancelled: boolean }>
  >();
  private readonly subjectInFlight = new Map<
    string,
    Promise<SubjectAccessData>
  >();
  private readonly objectInFlight = new Map<ScopeId, Promise<ScopeId[]>>();
  /**
   * Epoch revalidation state. `knownSeq` is the newest event sequence this
   * client has accounted for (null before first contact); `validationGen`
   * increments whenever a replay (or gap bust) lands, and every cache entry
   * records the generation its fetch STARTED under. A validation renews
   * only entries fetched entirely within the current generation: an entry
   * whose fetch overlapped a replay may have read pre-event state the
   * replay could not bust (it was not yet cached, so no index covered it),
   * so it keeps its original TTL — bounded staleness, exactly the
   * pre-epoch contract — instead of being renewed indefinitely.
   */
  private readonly revalidateAfter: number | undefined;
  private knownSeq: number | null = null;
  private lastValidatedAt = 0;
  private validationGen = 0;
  private revalidating: Promise<void> | null = null;
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
    this.maxObjects = options.maxObjectCacheEntries ?? 10_000;
    this.revalidateAfter = options.revalidateAfterMs;
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

    this.unsubscribe = this.provider.onInvalidate((event) =>
      this.applyInvalidation(event),
    );
  }

  /**
   * The single event → cache-entry mapping. The live provider stream feeds
   * it directly; anything replaying persisted events (cross-process
   * revalidation) must produce identical busts, so both run through here.
   */
  private applyInvalidation(event: InvalidationEvent): void {
    switch (event.type) {
      case "user":
        this.bustSubject(`u:${event.userId}`);
        break;
      case "subject":
        for (const cacheKey of [
          ...(this.closureIndex.get(event.subject) ?? []),
        ]) {
          this.bustSubject(cacheKey);
        }
        break;
      case "scope":
        // Object chains bust immediately on move: the moved scope's own
        // chain, and every cached chain passing through it.
        this.bustObject(event.scope);
        for (const cached of [...(this.chainIndex.get(event.scope) ?? [])]) {
          this.bustObject(cached);
        }
        break;
      case "role":
        // Role definitions ride inside subject data; bust conservatively.
        for (const cacheKey of [...(this.roleIndex.get(event.roleId) ?? [])]) {
          this.bustSubject(cacheKey);
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
  }

  // -- cache maintenance ----------------------------------------------------
  // All cache and index mutation goes through these four: store on fetch,
  // drop on eviction, bust (drop + cancel in-flight) on invalidation.

  private storeSubject(cacheKey: string, entry: SubjectCacheEntry): void {
    this.dropSubject(cacheKey);
    this.subjectCache.set(cacheKey, entry);
    for (const subject of entry.data.closure) {
      let keys = this.closureIndex.get(subject);
      if (keys === undefined) this.closureIndex.set(subject, (keys = new Set()));
      keys.add(cacheKey);
    }
    for (const role of entry.data.roles) {
      let keys = this.roleIndex.get(role.id);
      if (keys === undefined) this.roleIndex.set(role.id, (keys = new Set()));
      keys.add(cacheKey);
    }
    // Bounded cache: evict least-recently-used (hits refresh recency, so
    // Map insertion order IS recency order).
    while (this.subjectCache.size > this.maxSubjects) {
      const oldest = this.subjectCache.keys().next().value;
      if (oldest === undefined) break;
      this.dropSubject(oldest);
    }
  }

  private dropSubject(cacheKey: string): void {
    const entry = this.subjectCache.get(cacheKey);
    if (entry === undefined) return;
    this.subjectCache.delete(cacheKey);
    for (const subject of entry.data.closure) {
      const keys = this.closureIndex.get(subject);
      if (keys === undefined) continue;
      keys.delete(cacheKey);
      if (keys.size === 0) this.closureIndex.delete(subject);
    }
    for (const role of entry.data.roles) {
      const keys = this.roleIndex.get(role.id);
      if (keys === undefined) continue;
      keys.delete(cacheKey);
      if (keys.size === 0) this.roleIndex.delete(role.id);
    }
  }

  private storeObject(scope: ScopeId, entry: ObjectCacheEntry): void {
    this.dropObject(scope);
    this.objectCache.set(scope, entry);
    for (const ancestor of entry.chain) {
      let scopes = this.chainIndex.get(ancestor);
      if (scopes === undefined) this.chainIndex.set(ancestor, (scopes = new Set()));
      scopes.add(scope);
    }
    while (this.objectCache.size > this.maxObjects) {
      const oldest = this.objectCache.keys().next().value;
      if (oldest === undefined) break;
      this.dropObject(oldest);
    }
  }

  private dropObject(scope: ScopeId): void {
    const entry = this.objectCache.get(scope);
    if (entry === undefined) return;
    this.objectCache.delete(scope);
    for (const ancestor of entry.chain) {
      const scopes = this.chainIndex.get(ancestor);
      if (scopes === undefined) continue;
      scopes.delete(scope);
      if (scopes.size === 0) this.chainIndex.delete(ancestor);
    }
  }

  private bustSubject(cacheKey: string): void {
    this.dropSubject(cacheKey);
    for (const state of this.subjectFetchStates.get(cacheKey) ?? []) {
      state.cancelled = true;
    }
  }

  private bustObject(scope: ScopeId): void {
    this.dropObject(scope);
    for (const state of this.objectFetchStates.get(scope) ?? []) {
      state.cancelled = true;
    }
  }

  /** Detach from the provider's invalidation stream and drop caches. */
  close(): void {
    this.unsubscribe();
    for (const cacheKey of [...this.subjectCache.keys()]) {
      this.bustSubject(cacheKey);
    }
    for (const scope of [...this.objectCache.keys()]) {
      this.bustObject(scope);
    }
    for (const states of this.subjectFetchStates.values()) {
      for (const state of states) state.cancelled = true;
    }
    for (const states of this.objectFetchStates.values()) {
      for (const state of states) state.cancelled = true;
    }
  }

  // -- epoch revalidation ----------------------------------------------------

  /**
   * The freshness gate on every cached read. `undefined` when there is
   * nothing to await — feature off, or within the revalidation window — so
   * the hot path stays a synchronous clock comparison. Past the window it
   * hands back ONE shared revalidation, coalesced across every concurrent
   * check, validating BOTH caches for every principal at once. See
   * {@link AlfizClientOptions.revalidateAfterMs} for the contract.
   */
  private maybeValidate(): Promise<void> | undefined {
    const epoch = this.provider.epoch;
    if (this.revalidateAfter === undefined || epoch === undefined) {
      return undefined;
    }
    if (
      this.knownSeq !== null &&
      this.now() - this.lastValidatedAt <= this.revalidateAfter
    ) {
      return undefined;
    }
    if (this.revalidating) return this.revalidating;
    const run = this.revalidate(epoch).finally(() => {
      this.revalidating = null;
    });
    this.revalidating = run;
    return run;
  }

  private async revalidate(epoch: NonNullable<AlfizProvider["epoch"]>): Promise<void> {
    try {
      const head = await epoch.head();
      if (this.knownSeq === null) {
        // First contact happens before anything can be cached (this gate
        // precedes every cached read), so there is nothing to catch up on.
        this.knownSeq = head;
      } else if (head < this.knownSeq) {
        // A head behind our cursor means the log was reset or restored:
        // there is no sequence to catch up along. Full bust, start over.
        this.applyInvalidation({ type: "all" });
        this.knownSeq = head;
        this.validationGen++;
      } else if (head !== this.knownSeq) {
        let cursor = this.knownSeq;
        let caughtUp = false;
        while (!caughtUp) {
          const result = await epoch.since(cursor);
          if ("gap" in result) {
            // The cursor predates retention: selective catch-up is no
            // longer possible, so everything cached is suspect.
            this.applyInvalidation({ type: "all" });
            cursor = await epoch.head();
            break;
          }
          for (const event of result.events) this.applyInvalidation(event);
          caughtUp = result.upTo <= cursor || result.events.length === 0;
          cursor = Math.max(cursor, result.upTo);
          if (cursor >= head) caughtUp = true;
        }
        this.knownSeq = cursor;
        this.validationGen++;
      }
      // Validation-renewable TTLs: entries fetched entirely within the
      // current generation are proven exact as of this instant. Entries
      // from older generations keep their original expiry (see the field
      // comment on `validationGen`).
      const validatedAt = this.now();
      this.lastValidatedAt = validatedAt;
      for (const entry of this.subjectCache.values()) {
        if (entry.gen === this.validationGen) {
          entry.expiresAt = validatedAt + this.subjectTtl;
        }
      }
      for (const entry of this.objectCache.values()) {
        if (entry.gen === this.validationGen) {
          entry.expiresAt = validatedAt + this.objectTtl;
        }
      }
    } catch {
      // Fail closed to the DATABASE, not to the cache: an unreadable epoch
      // renews nothing, so entries lapse on their original TTL and the
      // next miss pays a full provider fetch. Retry next window.
      this.lastValidatedAt = this.now();
    }
  }

  // -- data supply ----------------------------------------------------------

  /** Registers a cancellation record for an in-flight fetch on `key`. */
  private static trackFetch<K>(
    states: Map<K, Set<{ cancelled: boolean }>>,
    key: K,
  ): { state: { cancelled: boolean }; done: () => void } {
    const state = { cancelled: false };
    let set = states.get(key);
    if (set === undefined) states.set(key, (set = new Set()));
    set.add(state);
    return {
      state,
      done: () => {
        set.delete(state);
        if (set.size === 0 && states.get(key) === set) states.delete(key);
      },
    };
  }

  private async subjectData(
    principal: PrincipalRef,
    fresh: boolean,
  ): Promise<SubjectAccessData> {
    const key = principalKey(principal);
    if (!fresh) {
      const gate = this.maybeValidate();
      if (gate) await gate;
      const cached = this.subjectCache.get(key);
      if (cached && cached.expiresAt > this.now()) {
        // Refresh recency: Map insertion order doubles as the LRU order.
        this.subjectCache.delete(key);
        this.subjectCache.set(key, cached);
        return cached.data;
      }
      const inFlight = this.subjectInFlight.get(key);
      if (inFlight) return inFlight;
    }
    const gen = this.validationGen;
    const { state, done } = AlfizClient.trackFetch(this.subjectFetchStates, key);
    const fetching = this.provider.getSubjectAccess(principal).then((data) => {
      if (!state.cancelled) {
        this.storeSubject(key, {
          data,
          expiresAt: this.now() + this.subjectTtl,
          gen,
        });
      }
      return data;
    });
    if (!fresh) this.subjectInFlight.set(key, fetching);
    try {
      return await fetching;
    } finally {
      done();
      this.subjectInFlight.delete(key);
    }
  }

  private async objectClosure(
    scope: ScopeId | undefined,
    fresh: boolean,
  ): Promise<ScopeId[]> {
    if (scope === undefined || scope === GLOBAL_SCOPE) return [GLOBAL_SCOPE];
    if (!fresh) {
      const gate = this.maybeValidate();
      if (gate) await gate;
      const cached = this.objectCache.get(scope);
      if (cached && cached.expiresAt > this.now()) {
        this.objectCache.delete(scope);
        this.objectCache.set(scope, cached);
        return cached.chain;
      }
      const inFlight = this.objectInFlight.get(scope);
      if (inFlight) return inFlight;
    }
    const gen = this.validationGen;
    const { state, done } = AlfizClient.trackFetch(this.objectFetchStates, scope);
    const resolving = objectClosureOf(scope, this.provider.resolveAncestors).then(
      (chain) => {
        if (!state.cancelled) {
          this.storeObject(scope, {
            chain,
            expiresAt: this.now() + this.objectTtl,
            gen,
          });
        }
        return chain;
      },
    );
    if (!fresh) this.objectInFlight.set(scope, resolving);
    try {
      return await resolving;
    } finally {
      done();
      this.objectInFlight.delete(scope);
    }
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
