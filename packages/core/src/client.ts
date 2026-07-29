/**
 * The AlfizClient: the evaluator. Checks execute in-process against
 * provider-supplied data — closures are cached as evaluation state,
 * parameterized by provider invalidation events; decisions are never cached.
 *
 * Check shapes: `can` (the only gate shape), `canAny` (visibility affordance
 * only), their throwing `require*` forms, `holds`/`heldKeys` (the "held at
 * any scope" probes), and `can.fresh`, which bypasses all caches — the
 * intended pairing for destructive actions and time-bound elevations.
 * Server-rendered request handling has a third surface:
 * `snapshot(principal)` fetches once and then checks SYNCHRONOUSLY — see
 * snapshot.ts; it is the intended shape wherever render helpers cannot be
 * async.
 *
 * The naming rule, held everywhere: ONE NAME PER QUESTION, on every surface.
 * `can`/`require` gate, `canAny`/`requireAny` guard visibility,
 * `holds`/`heldKeys` probe unscoped possession, `explain` shows the work,
 * `grantedScopes` feeds listing — identically named on the client, the
 * snapshot, and the session surfaces.
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
 *
 * With `revalidateAfterMs` set against a provider exposing `epoch` (the
 * persisted event log), the bounds tighten: the operative staleness bound
 * becomes the revalidation window — one constant-cost head read per window
 * validates both caches for every principal, renewing TTLs while writes are
 * quiet and replaying only the missed events when they are not. The TTLs
 * then bound staleness only when the epoch is unreachable (fail-closed to
 * the database: unvalidated entries lapse and refetch). An optional
 * `cacheStore` (L2) extends the same freshness rules to cold processes.
 */

import type { CheckContext, CheckExplanation, GrantRow } from "./access.js";
import {
  checkAny,
  explainKey,
  grantedScopesFor,
  grantsMatchingKey,
  keyHeldAnywhere,
  revokedScopesFor,
} from "./access.js";
import type { CacheStore } from "./cache.js";
import type {
  CheckDecision,
  CheckObservation,
  CheckOptions,
  CheckShape,
  MetricsOptions,
} from "./metrics.js";
import {
  MetricsRecorder,
  attributionOf,
  isGateShape,
  revokeIdsOf,
} from "./metrics.js";
import type { AnyCatalog, KeyOf, PatternOf, ScopeOf } from "./catalog.js";
import { unknownPermissionContext } from "./catalog.js";
import { AccessDeniedError, UnknownPermissionError } from "./errors.js";
import type { LooseKey, PermissionKey, PermissionPattern } from "./grammar.js";
import { namespaceOf, patternMatchesKey } from "./grammar.js";
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
  /**
   * Optional shared cache tier (L2) between the in-process maps and the
   * provider — see {@link CacheStore}. Read order is L1 → L2 → provider;
   * the win is COLD processes (serverless invocations, fresh deploys)
   * finding a warm closure instead of paying the full fan-out.
   *
   * An L2 entry is served only when provably fresh: with epoch
   * revalidation on, only when it was written under exactly the current
   * event-log head (any intervening write anywhere discards it — strict,
   * and still a hit whenever writes are quiet, which is the common case);
   * without an epoch, only within the same TTL that bounds L1. Every L2
   * failure — errors, timeouts, unparseable or version-mismatched
   * envelopes — is a miss, never an answer. Writes are fire-and-forget.
   *
   * The store holds closure data inside the server trust boundary: point
   * it only at authenticated, private cache infrastructure.
   */
  cacheStore?: CacheStore;
  /** Key prefix for L2 entries. Default "alfiz:v1:". */
  cacheKeyPrefix?: string;
  /**
   * Storage TTL (ms) for L2 entries. With epoch revalidation this only
   * bounds storage growth — freshness comes from the sequence check — so
   * it defaults to 10 minutes; without an epoch it IS the freshness bound
   * and defaults to the corresponding L1 TTL.
   */
  cacheStoreTtlMs?: number;
  /** Observes swallowed L2 errors (metrics/logging). Failures are misses either way. */
  onCacheStoreError?: (error: unknown) => void;
  /**
   * Permission metrics: a `CheckObservation` per evaluated check, delivered
   * synchronously to an observer — an OpenTelemetry meter
   * (`otelMetricsObserver`), a local aggregator you read directly
   * (`createMetricsAggregator`), a provider sink that stores rolling usage
   * for revocation safeguards (`createProviderMetricsSink`), or any function.
   *
   * Off by default, and cheap when on: `sampleRate` is evaluated with one
   * `Math.random()` inside the call before anything is built, observers are
   * invoked fire-and-forget, and a throwing observer can never fail a check.
   * See metrics.ts.
   */
  metrics?: MetricsOptions | undefined;
  /**
   * What to do with a check for a permission in a namespace this catalog
   * neither owns nor imports — an *implicit* import. Default `"error"`,
   * which is the behavior that has always been there.
   *
   * - `"error"` — throw `UnknownPermissionError`, as before.
   * - `"warn"` — evaluate it, and report it once per distinct permission
   *   through {@link onExternalPermission} (default: `console.warn`).
   * - `"allow"` — evaluate it silently.
   *
   * Two things this policy deliberately never relaxes, whatever it is set
   * to. A permission under a namespace this catalog OWNS always throws: an
   * owned catalog is enumerable, so an unknown key in it is unambiguously a
   * typo. A permission under an ENUMERATED import (one with an attached
   * document) always throws too, and names what the import covers — that
   * exactness is the whole return on committing the document.
   *
   * And what it never does: **no I/O**. There is no provider lookup here,
   * no lazy fetch, no boot-time registry call. Runtime checks never leave
   * the application in any topology, and `snapshot.can()` is synchronous —
   * which is the structural proof, not just the promise, that this decision
   * has to be pure.
   *
   * The safety rule that makes the permissive modes defensible lives in
   * `access.ts`: a permission admitted by this policy is conferred only by a
   * NAMESPACE-ANCHORED grant. `zoom.*` and narrower confer it; a bare global
   * `*` does not. Without that, a typo in a foreign namespace would pass for
   * exactly the broadly-privileged users who review and test it — the
   * failure `UnknownPermissionError` exists to prevent.
   */
  externalPermissions?: "error" | "warn" | "allow";
  /**
   * Called once per distinct permission admitted under `externalPermissions:
   * "warn"`. Replaces the default `console.warn`; point it at your logger or
   * your metrics.
   */
  onExternalPermission?: (info: ExternalPermissionInfo) => void;
  clock?: () => number;
}

/**
 * Where a permission was named. The metered check shapes, plus the two
 * introspection surfaces that verify against the catalog but are never
 * counted as checks.
 */
export type PermissionSite = CheckShape | "explain" | "grantedScopes";

/** A permission admitted by the implicit-import policy. */
export interface ExternalPermissionInfo {
  permission: string;
  expected: "key" | "pattern";
  /** The foreign namespace, or `null` for the bare `*`. */
  namespace: string | null;
  /** Which surface reached it. */
  shape: PermissionSite;
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
  isUndeclared?: (key: PermissionKey) => boolean,
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
    isUndeclared,
  };
}

export interface CanFn<K extends string, S extends string = string> {
  /**
   * The gate: may the principal do `key` at `scope`? An array of keys is
   * any-of. NO SCOPE MEANS THE GLOBAL SCOPE — "may they do this
   * everywhere?", the strictest check, NOT "may they do this anywhere?".
   * The anywhere question is `holds`, and it is never a gate.
   */
  (
    principal: PrincipalRef,
    key: K | readonly K[],
    scope?: LooseScopeId<S>,
    options?: CheckOptions,
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
    options?: CheckOptions,
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
  private readonly cacheStore: CacheStore | undefined;
  private readonly cachePrefix: string;
  private readonly cacheStoreTtl: number;
  private readonly onCacheStoreError: ((error: unknown) => void) | undefined;
  private readonly unsubscribe: () => void;
  private readonly grantApplies: (
    key: PermissionKey,
    grantScope: ScopeId,
  ) => boolean;
  private readonly isUndeclared: (key: PermissionKey) => boolean;
  private readonly externalPermissions: "error" | "warn" | "allow";
  private readonly onExternalPermission: (info: ExternalPermissionInfo) => void;
  /** Reported-once set, so a render loop warns once rather than per row. */
  private readonly reportedExternal = new Set<string>();
  /** `null` when metrics are off — the branch every check path tests first. */
  private readonly recorder: MetricsRecorder | null;

  constructor(options: AlfizClientOptions) {
    this.catalog = options.catalog;
    this.provider = options.provider;
    this.subjectTtl = options.subjectCacheTtlMs ?? 30_000;
    this.objectTtl = options.objectCacheTtlMs ?? 60_000;
    this.maxSubjects = options.maxSubjectCacheEntries ?? 10_000;
    this.maxObjects = options.maxObjectCacheEntries ?? 10_000;
    this.revalidateAfter = options.revalidateAfterMs;
    this.cacheStore = options.cacheStore;
    this.cachePrefix = options.cacheKeyPrefix ?? "alfiz:v1:";
    this.cacheStoreTtl =
      options.cacheStoreTtlMs ??
      (options.revalidateAfterMs !== undefined
        ? 600_000
        : Math.max(
            options.subjectCacheTtlMs ?? 30_000,
            options.objectCacheTtlMs ?? 60_000,
          ));
    this.onCacheStoreError = options.onCacheStoreError;
    this.now = options.clock ?? Date.now;
    this.grantApplies = (key, grantScope) =>
      this.catalog.appliesAt(key, grantScope);
    this.isUndeclared = (key) => !this.catalog.hasKey(key);
    this.externalPermissions = options.externalPermissions ?? "error";
    this.onExternalPermission =
      options.onExternalPermission ??
      ((info) =>
        console.warn(
          `alfiz: ${JSON.stringify(info.permission)} is in namespace ${JSON.stringify(info.namespace)}, ` +
            `which this catalog neither owns nor imports — evaluated because \`externalPermissions\` is not "error". ` +
            `Declare it: imports: { ${info.namespace}: { permissions: { ${JSON.stringify(info.permission)}: true } } }`,
        ));
    this.recorder =
      options.metrics === undefined ? null : new MetricsRecorder(options.metrics);

    const can = (async (
      principal: PrincipalRef,
      key: K | readonly K[],
      scope?: LooseScopeId<S>,
      checkOptions?: CheckOptions,
    ) => this.check(principal, key, scope, false, "can", checkOptions)) as CanFn<K, S>;
    can.fresh = async (principal, key, scope?, checkOptions?) =>
      this.check(principal, key, scope, true, "can", checkOptions);
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

  // -- the shared cache tier (L2) --------------------------------------------
  // Envelopes are versioned JSON; `seq` is the event-log head the writer
  // had validated when the fetch began (null when it could not vouch for
  // one), `freshUntil` the wall-clock bound for epoch-less deployments.
  // Every failure or mismatch on the read side is a miss — the L2 can make
  // checks cheaper, never wronger.

  private l2Fresh(envelope: {
    v?: number;
    seq?: number | null;
    freshUntil?: number;
  }): boolean {
    if (envelope.v !== 1) return false;
    if (this.revalidateAfter !== undefined && this.provider.epoch !== undefined) {
      // Strict rule: written under exactly the current head, else discard.
      // Still a hit whenever writes are quiet — the common case. (A finer
      // rule could replay events between envelope.seq and knownSeq against
      // just this entry; start strict, it is trivially correct.)
      return (
        typeof envelope.seq === "number" && envelope.seq === this.knownSeq
      );
    }
    return (
      typeof envelope.freshUntil === "number" &&
      envelope.freshUntil > this.now()
    );
  }

  private writeL2(key: string, envelope: Record<string, unknown>): void {
    const store = this.cacheStore;
    if (store === undefined) return;
    void store
      .set(key, JSON.stringify(envelope), this.cacheStoreTtl)
      .catch((error) => this.onCacheStoreError?.(error));
  }

  private async subjectFromL2(
    cacheKey: string,
  ): Promise<SubjectAccessData | null> {
    const store = this.cacheStore;
    if (store === undefined) return null;
    try {
      const raw = await store.get(`${this.cachePrefix}sub:${cacheKey}`);
      if (raw === null) return null;
      const envelope = JSON.parse(raw) as {
        v?: number;
        seq?: number | null;
        freshUntil?: number;
        data?: SubjectAccessData;
      };
      if (!this.l2Fresh(envelope) || envelope.data === undefined) return null;
      this.storeSubject(cacheKey, {
        data: envelope.data,
        expiresAt: this.now() + this.subjectTtl,
        gen: this.validationGen,
      });
      return envelope.data;
    } catch (error) {
      this.onCacheStoreError?.(error);
      return null;
    }
  }

  private async objectFromL2(scope: ScopeId): Promise<ScopeId[] | null> {
    const store = this.cacheStore;
    if (store === undefined) return null;
    try {
      const raw = await store.get(`${this.cachePrefix}obj:${scope}`);
      if (raw === null) return null;
      const envelope = JSON.parse(raw) as {
        v?: number;
        seq?: number | null;
        freshUntil?: number;
        chain?: ScopeId[];
      };
      if (!this.l2Fresh(envelope) || envelope.chain === undefined) return null;
      this.storeObject(scope, {
        chain: envelope.chain,
        expiresAt: this.now() + this.objectTtl,
        gen: this.validationGen,
      });
      return envelope.chain;
    } catch (error) {
      this.onCacheStoreError?.(error);
      return null;
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
      if (this.cacheStore) {
        const fromL2 = await this.subjectFromL2(key);
        if (fromL2) return fromL2;
      }
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
        this.writeL2(`${this.cachePrefix}sub:${key}`, {
          v: 1,
          // Vouch for a head only if no replay intervened since this fetch
          // began — the same generation guard that gates TTL renewal.
          seq: this.validationGen === gen ? this.knownSeq : null,
          freshUntil: this.now() + this.subjectTtl,
          data,
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
      if (this.cacheStore) {
        const fromL2 = await this.objectFromL2(scope);
        if (fromL2) return fromL2;
      }
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
          this.writeL2(`${this.cachePrefix}obj:${scope}`, {
            v: 1,
            seq: this.validationGen === gen ? this.knownSeq : null,
            freshUntil: this.now() + this.objectTtl,
            chain,
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
    return toCheckContext(
      data,
      this.now(),
      this.grantApplies,
      this.isUndeclared,
    );
  }

  /**
   * The implicit-import decision, shared by the key and pattern assertions.
   * Pure and synchronous — no provider call, no fetch, nothing that could
   * put Alfiz Cloud on a request path. See `externalPermissions`.
   *
   * Throws unless the permission is genuinely outside this catalog's reach
   * AND the policy admits it. "Genuinely outside" is narrow on purpose: an
   * owned namespace is enumerable, and an enumerated import knows its own
   * keys, so in both cases an unknown permission is a mistake this codebase
   * can fix, and saying so is more useful than letting it through.
   */
  private admitExternal(
    permission: string,
    expected: "key" | "pattern",
    shape: PermissionSite,
  ): void {
    const context = unknownPermissionContext(this.catalog, permission, expected);
    const namespace = namespaceOf(permission);
    const enumeratedImport =
      namespace !== null && this.catalog.imports.get(namespace)?.enumerated;
    const admissible =
      this.externalPermissions !== "error" &&
      context.namespaceOrigin === "foreign" &&
      namespace !== null;
    if (!admissible || enumeratedImport === true) {
      throw new UnknownPermissionError({
        permission,
        expected,
        ...context,
      });
    }
    if (this.externalPermissions === "warn" && !this.reportedExternal.has(permission)) {
      this.reportedExternal.add(permission);
      this.onExternalPermission({ permission, expected, namespace, shape });
    }
  }

  /**
   * Every check is verified against the catalog before it is evaluated.
   * Typed keys and the static verifier cover literal call sites; this covers
   * the runtime-string paths they cannot see — and closes the hole where an
   * undeclared key would pass for any holder of a covering wildcard. See
   * {@link UnknownPermissionError}.
   */
  private assertKeys(keys: readonly PermissionKey[], shape: PermissionSite): void {
    for (const key of keys) {
      if (this.catalog.hasKey(key)) continue;
      this.admitExternal(key, "key", shape);
    }
  }

  private assertPattern(
    pattern: PermissionPattern,
    shape: PermissionSite,
  ): void {
    if (this.catalog.isKnownPattern(pattern)) return;
    this.admitExternal(pattern, "pattern", shape);
  }

  /**
   * The metrics half of a check, kept in one place so every shape reports
   * the same dimensions. Called ONLY after the sampling gate has already
   * kept the check, so nothing here runs on an unsampled call.
   */
  private observe(input: {
    sampleRate: number;
    shape: CheckShape;
    decision: CheckDecision;
    permission: PermissionKey | PermissionPattern | null;
    anyOf: boolean;
    scope: ScopeId | undefined;
    principal: PrincipalRef;
    matchedGrants?: readonly GrantRow[] | undefined;
    matchedRevokeIds?: readonly string[] | undefined;
    implied?: boolean | undefined;
    fresh?: boolean | undefined;
    snapshot?: boolean | undefined;
  }): void {
    const recorder = this.recorder;
    if (recorder === null) return;
    const attribution = attributionOf(input.matchedGrants ?? []);
    const observation: CheckObservation = {
      at: this.now(),
      shape: input.shape,
      gate: isGateShape(input.shape),
      decision: input.decision,
      permission: input.permission,
      anyOf: input.anyOf,
      ...recorder.scopeDimension(input.scope),
      principal: input.principal,
      matchedGrantIds: attribution.matchedGrantIds,
      soleMatchGrantId: attribution.soleMatchGrantId,
      matchedRevokeIds: input.matchedRevokeIds ?? [],
      roleIds: attribution.roleIds,
      implied: input.implied ?? false,
      fresh: input.fresh ?? false,
      snapshot: input.snapshot ?? false,
      // Derived, not passed: every shape gets the dimension without every
      // call site remembering to set it. Both tests are needed — the key
      // shapes carry a key and the pattern shapes carry a pattern, and a
      // legitimate `docs.*` is a known pattern but never a known key.
      // `permission` is null only for `heldKeys`, which names none.
      externalPermission:
        input.permission !== null &&
        !this.catalog.hasKey(input.permission) &&
        !this.catalog.isKnownPattern(input.permission)
          ? true
          : undefined,
      sampleRate: input.sampleRate,
    };
    recorder.record(observation);
  }

  /** The sampling gate, or `null` when metrics are off / this call is not observed. */
  private sampled(shape: CheckShape, options?: CheckOptions): number | null {
    if (this.recorder === null) return null;
    if (options?.observe === false) return null;
    return this.recorder.sampled(shape);
  }

  private async check(
    principal: PrincipalRef,
    key: K | readonly K[],
    scope: ScopeId | undefined,
    fresh: boolean,
    shape: "can" | "require" = "can",
    options?: CheckOptions,
  ): Promise<boolean> {
    const keys: readonly PermissionKey[] = Array.isArray(key)
      ? (key as readonly string[])
      : [key as string];
    this.assertKeys(keys, shape);
    // Sampled BEFORE the work, so an unsampled check never pays for
    // attribution — and so the decision is one comparison, not a branch per
    // matched row further down.
    const sampleRate = this.sampled(shape, options);
    const [data, closure] = await Promise.all([
      this.subjectData(principal, fresh),
      this.objectClosure(scope, fresh),
    ]);
    const observe = (
      decision: CheckDecision,
      permission: PermissionKey | null,
      matched?: {
        grants?: readonly GrantRow[] | undefined;
        revokeIds?: readonly string[] | undefined;
        implied?: boolean | undefined;
      },
    ): void => {
      if (sampleRate === null) return;
      this.observe({
        sampleRate,
        shape,
        decision,
        permission,
        anyOf: keys.length > 1,
        scope,
        principal,
        matchedGrants: matched?.grants,
        matchedRevokeIds: matched?.revokeIds,
        implied: matched?.implied,
        fresh,
      });
    };

    if (!data.active) {
      observe("deny", keys[0] ?? null);
      return false;
    }
    const ctx = this.ctxOf(data);
    // `explainKey` is what `checkKey` already calls; taking its result rather
    // than its boolean is what makes attribution free on the hot path.
    let firstDenial: CheckExplanation | null = null;
    for (const k of keys) {
      const explanation = explainKey(ctx, k, closure);
      if (explanation.allowed) {
        observe("allow", k, { grants: explanation.matchedGrants });
        return true;
      }
      firstDenial ??= explanation;
    }
    // Ancestor visibility (§7.5): a leaf marked impliedOnAncestors is implied
    // on PROPER ancestors of a granted scope — never at the global scope,
    // which would turn one narrow share into the broadest possible check
    // passing (can(u, key, "*") must agree with can(u, key)).
    if (scope !== undefined && scope !== GLOBAL_SCOPE) {
      for (const k of keys) {
        if (!this.catalog.leaf(k)?.impliedOnAncestors) continue;
        const implying = await this.checkImplied(ctx, k, scope, fresh);
        if (implying !== null) {
          observe("allow", k, { grants: implying, implied: true });
          return true;
        }
      }
    }
    observe("deny", keys[0] ?? null, {
      revokeIds: firstDenial ? revokeIdsOf(firstDenial.matchedRevokes) : [],
    });
    return false;
  }

  /**
   * §7.5 ancestor implication. Returns the grant rows at the implying scope
   * — not a boolean — because an implied allow bypasses `explainKey`'s
   * matched list entirely, and "which grant allowed this" has to stay
   * answerable for attribution and for `explain`.
   */
  private async checkImplied(
    ctx: CheckContext,
    key: PermissionKey,
    target: ScopeId,
    fresh: boolean,
  ): Promise<GrantRow[] | null> {
    const rows = grantsMatchingKey(ctx, key);
    const scopes = new Set<ScopeId>();
    for (const row of rows) scopes.add(row.scope);
    for (const grantScope of scopes) {
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
      if (!suppressed) return rows.filter((row) => row.scope === grantScope);
    }
    return null;
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
      // Snapshot checks are the render path's conditional-UI traffic — the
      // highest-volume shape there is, and the one `sampleRate.visibility`
      // exists for. `observe: false` suppresses the whole snapshot (view-as
      // previews take it).
      recorder: options?.observe === false ? null : this.recorder,
      // Bound to this snapshot's freshness, so `resolve` mid-request keeps
      // the same cache posture the snapshot was taken with.
      resolveChain: (scope) => this.objectClosure(scope, fresh),
      // The same implicit-import decision the async surface makes. Pure and
      // synchronous, which is what lets the sync surface share it at all.
      admitExternal: (permission, expected) =>
        this.admitExternal(permission, expected, "can"),
    });
  }

  /**
   * The visibility affordance: does effective access intersect `pattern` at
   * all, at any scope? Never a gate — the static verifier errors on `canAny`
   * in server actions and route handlers.
   */
  async canAny(
    principal: PrincipalRef,
    pattern: P,
    options?: CheckOptions,
  ): Promise<boolean> {
    return this.anyCheck(principal, pattern, "canAny", options);
  }

  private async anyCheck(
    principal: PrincipalRef,
    pattern: P,
    shape: "canAny" | "requireAny",
    options?: CheckOptions,
  ): Promise<boolean> {
    this.assertPattern(pattern, shape);
    const sampleRate = this.sampled(shape, options);
    const observe = (decision: CheckDecision): void => {
      if (sampleRate === null) return;
      this.observe({
        sampleRate,
        shape,
        decision,
        permission: pattern,
        anyOf: false,
        scope: undefined,
        principal,
      });
    };
    const data = await this.subjectData(principal, false);
    if (!data.active) {
      observe("deny");
      return false;
    }
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
    const allowed = checkAny(
      ctx,
      pattern,
      this.catalog.keys,
      closures,
      this.catalog.opaqueRegions(pattern),
    );
    observe(allowed ? "allow" : "deny");
    return allowed;
  }

  /**
   * Throwing form of `can` — same name on every surface (`client.require`,
   * `snapshot.require`, `session.require`).
   */
  async require(
    principal: PrincipalRef,
    key: K | readonly K[],
    scope?: LooseScopeId<S>,
    options?: CheckOptions,
  ): Promise<void> {
    const keys = (Array.isArray(key) ? key : [key]) as readonly PermissionKey[];
    this.assertKeys(keys, "require");
    const data = await this.subjectData(principal, false);
    if (!data.active) {
      const sampleRate = this.sampled("require", options);
      if (sampleRate !== null) {
        this.observe({
          sampleRate,
          shape: "require",
          decision: "deny",
          permission: keys[0] ?? null,
          anyOf: keys.length > 1,
          scope,
          principal,
        });
      }
      throw new AccessDeniedError({
        reason: "inactive",
        permission: key as PermissionKey | readonly PermissionKey[],
        scope,
        principal,
      });
    }
    // Evaluated as the `require` SHAPE, not by delegating to `can`: the
    // throwing form is the same question asked at a different call site, and
    // one call must produce one observation, not two.
    if (!(await this.check(principal, key, scope, false, "require", options))) {
      throw new AccessDeniedError({
        reason: "forbidden",
        permission: key as PermissionKey | readonly PermissionKey[],
        scope,
        principal,
      });
    }
  }

  /**
   * Throwing form of `canAny`, and exactly as narrow: it exists for ONE
   * pattern — the page-top visibility guard (`requireAny("project.*")` →
   * your 404/redirect) on a page that still gates its own read with
   * `require`. It is never an action gate; the static verifier errors on
   * `canAny`/`requireAny` in server actions and route handlers.
   */
  async requireAny(
    principal: PrincipalRef,
    pattern: P,
    options?: CheckOptions,
  ): Promise<void> {
    this.assertPattern(pattern, "requireAny");
    if (!(await this.anyCheck(principal, pattern, "requireAny", options))) {
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
      /**
       * The grants at a DESCENDANT scope that produced an implied allow.
       * Empty unless `implied` — `matchedGrants` stays strictly the rows
       * matching at this scope, which for an implied allow is none.
       */
      impliedBy: GrantRow[];
    }
  > {
    this.assertKeys([key as PermissionKey], "explain");
    const [data, closure] = await Promise.all([
      this.subjectData(principal, false),
      this.objectClosure(scope, false),
    ]);
    const ctx = this.ctxOf(data);
    const explanation = explainKey(ctx, key as PermissionKey, closure);
    let allowed = explanation.allowed && data.active;
    let implied = false;
    let impliedBy: GrantRow[] = [];
    if (
      !allowed &&
      data.active &&
      explanation.matchedRevokes.length === 0 &&
      scope !== undefined &&
      scope !== GLOBAL_SCOPE &&
      this.catalog.leaf(key as PermissionKey)?.impliedOnAncestors
    ) {
      const implying = await this.checkImplied(
        ctx,
        key as PermissionKey,
        scope,
        false,
      );
      implied = implying !== null;
      allowed = implied;
      // Reported SEPARATELY from `matchedGrants`, which stays exactly what
      // it says: rows matching at this scope. An implied allow has none —
      // that is what makes it implied — but "which grant, at which
      // descendant scope, implied this" is still the answer to "why", and
      // it is what attribution counts.
      impliedBy = implying ?? [];
    }
    return {
      ...explanation,
      allowed,
      implied,
      impliedBy,
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
    this.assertKeys([key as PermissionKey], "grantedScopes");
    const data = await this.subjectData(principal, false);
    if (!data.active) return { granted: new Set(), revoked: new Set() };
    const ctx = this.ctxOf(data);
    return {
      granted: grantedScopesFor(ctx, key as PermissionKey),
      revoked: revokedScopesFor(ctx, key as PermissionKey),
    };
  }

  /**
   * Does the principal hold `key` at ANY scope? (See `keyHeldAnywhere` for
   * the exact semantics.) This is a legitimate — and under scoped grants,
   * the RIGHT — question for unscoped conditional UI: an instructor holding
   * `publish_course` only at the courses they teach should still see the
   * button surface exist. Never a gate: the action behind the button still
   * gates with `can` at its concrete scope. Same name on every surface
   * (`snapshot.holds`, session snapshot `holds`). O(rows) for one key; for
   * many keys per request, prefer `snapshot(principal).heldKeys`.
   */
  async holds(
    principal: PrincipalRef,
    key: LooseKey<K>,
    options?: CheckOptions,
  ): Promise<boolean> {
    this.assertKeys([key as PermissionKey], "holds");
    const sampleRate = this.sampled("holds", options);
    const data = await this.subjectData(principal, false);
    const observe = (decision: CheckDecision, grants?: GrantRow[]): void => {
      if (sampleRate === null) return;
      this.observe({
        sampleRate,
        shape: "holds",
        decision,
        permission: key as PermissionKey,
        anyOf: false,
        scope: undefined,
        principal,
        matchedGrants: grants,
      });
    };
    if (!data.active) {
      observe("deny");
      return false;
    }
    const ctx = this.ctxOf(data);
    const held = keyHeldAnywhere(ctx, key as PermissionKey);
    // Attribution on an unscoped probe is still meaningful, and still only
    // computed when sampled: "this grant is the only reason the button
    // exists" is exactly the kind of thing a revocation warning should know.
    observe(
      held ? "allow" : "deny",
      held && sampleRate !== null
        ? grantsMatchingKey(ctx, key as PermissionKey)
        : undefined,
    );
    return held;
  }

  /**
   * Every concrete catalog key the principal holds SOMEWHERE: granted by an
   * applicable unexpired row at any scope, suppressed only by global-scope
   * revokes (a folder-scoped revoke narrows one subtree; it does not erase
   * a key held elsewhere). The many-key form of `holds`, same name on every
   * surface (`snapshot.heldKeys`). "Not a gate" does not mean "not useful":
   * this is the right feed for unscoped conditional UI under scoped grants
   * — it is simply never the thing that AUTHORIZES an action, which always
   * gates with `can` at a concrete scope. O(catalog); call once per request
   * and reuse — `snapshot(principal).heldKeys` does exactly that.
   */
  async heldKeys(
    principal: PrincipalRef,
    options?: CheckOptions,
  ): Promise<PermissionKey[]> {
    const sampleRate = this.sampled("heldKeys", options);
    const data = await this.subjectData(principal, false);
    const ctx = data.active ? this.ctxOf(data) : null;
    const keys =
      ctx === null ? [] : this.catalog.keys.filter((key) => keyHeldAnywhere(ctx, key));
    if (sampleRate !== null) {
      // One observation for the call, not one per key: `heldKeys` asks about
      // the whole catalog at once, so `permission` is null and per-key
      // attribution is deliberately not attempted.
      this.observe({
        sampleRate,
        shape: "heldKeys",
        decision: keys.length > 0 ? "allow" : "deny",
        permission: null,
        anyOf: false,
        scope: undefined,
        principal,
      });
    }
    return keys;
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
