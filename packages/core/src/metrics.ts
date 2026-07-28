/**
 * Permission metrics: a typed observation off every check path, a pure
 * windowed aggregator over that stream, and the revocation-safeguard math.
 *
 * The shape of the feature is deliberate. The OBSERVER is the product: a
 * structured `CheckObservation` stream lets a deployment pipe permission
 * metrics into the metrics stack it already operates — `otelMetricsObserver`
 * (otel.ts) is that adapter for OpenTelemetry, and any other sink is a
 * function. Alfiz ships the pipeline (sink → aggregate → flush → store) and
 * the two permission-shaped readings that only Alfiz can produce — per-action
 * counts and grant/revoke attribution — and stops there. It is not an
 * observability vendor: no query language, no alerting, no long-horizon
 * analytical retention.
 *
 * Three properties hold everywhere in this module:
 *
 *   - **Off the hot path's conscience.** Observation is sync, guarded, and
 *     fire-and-forget. A throwing observer can never fail a check; the error
 *     goes to `onError` and the answer is returned unchanged. Metrics are
 *     lossy by design — they are counts, not audit.
 *   - **Sampled cheaply.** `sampleRate` is evaluated with one `Math.random()`
 *     INSIDE the call, before any observation is built, so an unsampled check
 *     costs a comparison and allocates nothing. No storage read, no
 *     coordination — not pure, but fast, which is the trade a high-traffic
 *     request path wants. Every observation carries the rate that kept it, so
 *     counts extrapolate honestly (`observed / sampleRate`).
 *   - **Bounded cardinality.** Scope instances aggregate to scope TYPE by
 *     default; principals live in a bounded map with an overflow bucket;
 *     every counter map is capped and reports what it dropped. Memory is
 *     fixed regardless of traffic.
 *
 * Nothing here leaves the process on its own. Delivering batches anywhere —
 * your metrics stack, the local Application's store — is an explicit wiring
 * step the deployment makes.
 */

import type { GrantRow, RevokeRow } from "./access.js";
import type { PermissionKey, PermissionPattern } from "./grammar.js";
import type { AlfizProvider, PrincipalRef } from "./provider.js";
import type { ScopeId, ScopeType } from "./scopes.js";
import { GLOBAL_SCOPE, scopeTypeOf } from "./scopes.js";

// ---------------------------------------------------------------------------
// The observation
// ---------------------------------------------------------------------------

/**
 * Which check shape produced an observation. The distinction is load-bearing
 * rather than decorative: `can` / `require` are GATES at a concrete scope and
 * correspond one-to-one with user actions, while `canAny` / `requireAny` /
 * `holds` / `heldKeys` are visibility affordances that drive conditional UI
 * and vastly outnumber gates in any real render path. Counting them together
 * makes "how often is this action taken" unanswerable — and turns a
 * revocation warning into nonsense: "this grant matched 40 000 renders" and
 * "this grant gated 1 200 actions" are very different sentences.
 */
export type CheckShape =
  | "can"
  | "require"
  | "canAny"
  | "requireAny"
  | "holds"
  | "heldKeys";

export type CheckDecision = "allow" | "deny";

/** Gate shapes correspond to actions; everything else is visibility traffic. */
export function isGateShape(shape: CheckShape): boolean {
  return shape === "can" || shape === "require";
}

/**
 * One evaluated check, as the observer sees it. Bounded dimensions are
 * present verbatim; the unbounded ones (principal, scope instance) are
 * governed by the cardinality policy in {@link MetricsOptions}.
 */
export interface CheckObservation {
  /** Evaluation instant (epoch ms) — the client's clock, not the sink's. */
  at: number;
  shape: CheckShape;
  /** `isGateShape(shape)`, precomputed so sinks need not import it. */
  gate: boolean;
  decision: CheckDecision;
  /**
   * The concrete key that decided the check (the allowing key for an allow,
   * the first key otherwise), the pattern for pattern shapes, or `null` for
   * `heldKeys`, which answers about the whole catalog at once.
   */
  permission: PermissionKey | PermissionPattern | null;
  /** True when the call passed an any-of array — `permission` is one of several. */
  anyOf: boolean;
  /** The scope TYPE checked, or `"*"` for the global scope. Always bounded. */
  scopeType: ScopeType;
  /**
   * The scope INSTANCE — present only for scope types the deployment opted
   * into instance-level counting (see {@link MetricsOptions.scopeInstances}).
   * Unbounded by nature; off by default.
   */
  scope?: ScopeId | undefined;
  /** Who was evaluated. Aggregation keeps this bounded; sinks should too. */
  principal: PrincipalRef;
  /** Grant rows that participated in the allow. Empty on a deny. */
  matchedGrantIds: readonly string[];
  /**
   * Set when EXACTLY ONE grant row allowed this check — that row was the
   * sole matcher, and revoking it would have flipped the decision. This is
   * the counterfactually correct signal for revocation safeguards; the naive
   * "this grant matched N checks" overwarns on grants fully shadowed by a
   * broader one, which teaches admins to ignore the warning.
   */
  soleMatchGrantId: string | null;
  /** Revoke rows that suppressed the check. Non-empty implies a deny. */
  matchedRevokeIds: readonly string[];
  /** Role ids carried by the matched grants — feeds role-edit safeguards. */
  roleIds: readonly string[];
  /** Allowed through §7.5 ancestor implication rather than a direct match. */
  implied: boolean;
  /** The check bypassed the caches (`can.fresh`). */
  fresh: boolean;
  /** Evaluated on a request-scoped snapshot rather than an async client call. */
  snapshot: boolean;
  /**
   * The probability that kept this observation (1 when unsampled). Multiply
   * counts by `1 / sampleRate` to estimate the true volume — the aggregator
   * and the OTel adapter both do, and both keep the raw count alongside.
   */
  sampleRate: number;
}

/**
 * A metrics sink. Called synchronously from the check path, never awaited:
 * do cheap work here (increment a counter, push to a buffer) and let anything
 * slow happen on your own schedule. Throwing is contained, not fatal.
 */
export type MetricsObserver = (observation: CheckObservation) => void;

/**
 * Per-call metrics control, accepted by every check shape and by
 * `snapshot()`. Present for one reason: some evaluations are not traffic.
 */
export interface CheckOptions {
  /**
   * Observe this call. Default `true`. The view-as preview sets it `false`
   * on the previewed subject's side — an administrator looking through
   * someone else's eyes did not use that person's grants, and attribution
   * never follows the preview.
   */
  observe?: boolean | undefined;
}

/** Fans one observation out to several sinks; failures are isolated per sink. */
export function combineObservers(
  observers: readonly MetricsObserver[],
  onError?: (error: unknown) => void,
): MetricsObserver {
  return (observation) => {
    for (const observe of observers) {
      try {
        observe(observation);
      } catch (error) {
        onError?.(error);
      }
    }
  };
}

// ---------------------------------------------------------------------------
// Sampling and the recorder
// ---------------------------------------------------------------------------

/**
 * The sample probability, in `[0, 1]`. A number applies to every shape; the
 * object form samples gates and visibility traffic separately, which is the
 * setting a high-traffic deployment actually wants: gates are the countable
 * user actions and are worth keeping at 1, while a single server render can
 * fire hundreds of `canAny` / `holds` checks whose 1-in-100 sample says the
 * same thing at 1% of the cost.
 */
export type SampleRate =
  | number
  | {
      /** `can` / `require`. Default 1. */
      gate?: number | undefined;
      /** `canAny` / `requireAny` / `holds` / `heldKeys`. Defaults to the gate rate. */
      visibility?: number | undefined;
    };

/**
 * How scope instances are counted. `"type"` (default) folds every instance
 * into its scope type — parseable from the `type:id` format with no lookup,
 * and the only policy whose memory is bounded by schema rather than by data.
 * An array opts specific scope types into raw instance counting (some
 * deployments want per-project numbers; none want per-document cardinality
 * by default). `"instance"` opts in everything, and means it.
 */
export type ScopeInstancePolicy = "type" | "instance" | readonly ScopeType[];

export interface MetricsOptions {
  /**
   * Where observations go. An array fans out — e.g. an OTel adapter and a
   * local aggregator serving a direct-read endpoint, at once.
   */
  observer: MetricsObserver | readonly MetricsObserver[];
  /** Sample probability; see {@link SampleRate}. Default 1 (observe everything). */
  sampleRate?: SampleRate | undefined;
  /**
   * Randomness source for sampling. Defaults to `Math.random`. Injectable
   * because `Math.random` cannot be seeded and a sampled pipeline still has
   * to be testable.
   */
  random?: (() => number) | undefined;
  /** Scope-instance cardinality policy. Default `"type"`. */
  scopeInstances?: ScopeInstancePolicy | undefined;
  /**
   * Observer errors, swallowed so a broken sink can never fail a check.
   * Unset means silently ignored — which is the correct default for a lossy
   * counter, and the wrong default for debugging one.
   */
  onError?: ((error: unknown) => void) | undefined;
}

/**
 * The check paths' entry point to metrics: sample first, build second.
 * Construct once per client; `sampled(shape)` is the hot-path call and
 * returns the rate that kept the check (or `null` to skip observing), so an
 * unsampled check never allocates an observation.
 */
export class MetricsRecorder {
  private readonly observer: MetricsObserver;
  private readonly gateRate: number;
  private readonly visibilityRate: number;
  private readonly random: () => number;
  private readonly instanceTypes: ReadonlySet<ScopeType> | "all" | null;
  private readonly onError: ((error: unknown) => void) | undefined;

  constructor(options: MetricsOptions) {
    const observers = Array.isArray(options.observer)
      ? (options.observer as readonly MetricsObserver[])
      : [options.observer as MetricsObserver];
    this.onError = options.onError;
    this.observer =
      observers.length === 1 && this.onError === undefined
        ? observers[0]!
        : combineObservers(observers, this.onError);
    const rate = options.sampleRate ?? 1;
    const clamp = (value: number): number =>
      Number.isFinite(value) ? Math.min(1, Math.max(0, value)) : 1;
    if (typeof rate === "number") {
      this.gateRate = clamp(rate);
      this.visibilityRate = this.gateRate;
    } else {
      this.gateRate = clamp(rate.gate ?? 1);
      this.visibilityRate = clamp(rate.visibility ?? this.gateRate);
    }
    this.random = options.random ?? Math.random;
    const policy = options.scopeInstances ?? "type";
    this.instanceTypes =
      policy === "type"
        ? null
        : policy === "instance"
          ? "all"
          : new Set(policy);
  }

  /**
   * The sampling gate. Returns the effective rate when this check should be
   * observed, `null` when it should not. One comparison at rate 1, one
   * `random()` otherwise — no allocation either way.
   *
   * `rate = 0.1` keeps roughly one call in ten; equivalently, nine in ten
   * fall out on the comparison. Sampling decides only whether the check is
   * COUNTED; it never touches the answer.
   */
  sampled(shape: CheckShape): number | null {
    const rate = isGateShape(shape) ? this.gateRate : this.visibilityRate;
    if (rate >= 1) return 1;
    if (rate <= 0) return null;
    return this.random() < rate ? rate : null;
  }

  /** Applies the cardinality policy to a check target. */
  scopeDimension(scope: ScopeId | undefined): {
    scopeType: ScopeType;
    scope?: ScopeId | undefined;
  } {
    if (scope === undefined || scope === GLOBAL_SCOPE) {
      return { scopeType: GLOBAL_SCOPE };
    }
    const type = scopeTypeOf(scope) ?? UNKNOWN_SCOPE_TYPE;
    const keepInstance =
      this.instanceTypes === "all" ||
      (this.instanceTypes !== null && this.instanceTypes.has(type));
    return keepInstance ? { scopeType: type, scope } : { scopeType: type };
  }

  /** Guarded delivery: an observer that throws loses its observation, nothing else. */
  record(observation: CheckObservation): void {
    try {
      this.observer(observation);
    } catch (error) {
      this.onError?.(error);
    }
  }
}

/** Scope type reported for an instance id that does not parse. */
export const UNKNOWN_SCOPE_TYPE = "(unparsed)";

/** Bucket a bounded map reports overflow under. */
export const OVERFLOW_KEY = "(overflow)";

/**
 * Builds the grant-attribution half of an observation from a check's matched
 * rows — the `explainKey` output plumbed straight through. Exported because
 * anything evaluating checks outside the shipped surfaces (a custom gate, a
 * batch authorizer) should attribute identically.
 */
export function attributionOf(matchedGrants: readonly GrantRow[]): {
  matchedGrantIds: string[];
  soleMatchGrantId: string | null;
  roleIds: string[];
} {
  const matchedGrantIds: string[] = [];
  const roles = new Set<string>();
  for (const grant of matchedGrants) {
    matchedGrantIds.push(grant.id);
    if (grant.roleId !== undefined && grant.roleId !== "") roles.add(grant.roleId);
  }
  return {
    matchedGrantIds,
    // The sole-matcher test, and the whole point of §4: one matching row
    // means revoking it would have flipped this check.
    soleMatchGrantId: matchedGrants.length === 1 ? matchedGrants[0]!.id : null,
    roleIds: [...roles],
  };
}

/** The revoke half — ids only; the rows themselves never leave evaluation. */
export function revokeIdsOf(matchedRevokes: readonly RevokeRow[]): string[] {
  return matchedRevokes.map((revoke) => revoke.id);
}

// ---------------------------------------------------------------------------
// The aggregator — pure, windowed, bounded
// ---------------------------------------------------------------------------

/** Per-(permission, decision, shape, scope) counts within one window. */
export interface CheckCounter {
  permission: string;
  decision: CheckDecision;
  shape: CheckShape;
  gate: boolean;
  scopeType: ScopeType;
  scope?: ScopeId | undefined;
  /** Observations actually seen. */
  observed: number;
  /** `observed` corrected for sampling — the estimate of real traffic. */
  estimated: number;
}

/** Per-row attribution counts within one window (grants, revokes, roles). */
export interface RowUsageCounter {
  rowId: string;
  /** Participated in an allow — usage in the loose sense. */
  matched: number;
  /**
   * Was the ONLY row allowing — revoking it would have denied. Always
   * `<= matched`. This is the counter a revocation warning keys on.
   */
  soleMatch: number;
  estimatedMatched: number;
  estimatedSoleMatch: number;
  /**
   * A bounded sample of recent distinct principals — "who is using this
   * grant", which the safeguard UI wants, and which needs recency rather
   * than exact per-principal totals.
   */
  recentPrincipals: string[];
}

/**
 * One flush window's counters. Monotonic within the window and tagged with
 * the instance id and window bounds, so many app servers — each with its own
 * client — merge trivially wherever their flushes land.
 */
export interface MetricsBatch {
  instanceId: string;
  windowStart: number;
  windowEnd: number;
  checks: CheckCounter[];
  /** Grant-row attribution: `matched` and `soleMatch` per grant id. */
  grants: RowUsageCounter[];
  /**
   * Revoke-row attribution: how many checks each revoke suppressed. Deleting
   * a revoke WIDENS access, so this warning points the opposite direction
   * from the grant one — and is arguably the more security-relevant of the two.
   */
  revokes: RowUsageCounter[];
  /** Role-row attribution, for role-edit and role-delete safeguards. */
  roles: RowUsageCounter[];
  /** Distinct principals seen, exact up to the cap and flagged beyond it. */
  principals: { distinct: number; overflowed: boolean };
  /** Observations a cardinality cap refused to key. Never silently zero. */
  dropped: number;
}

export interface MetricsAggregatorOptions {
  /** Window length (ms). Default 60 000. */
  windowMs?: number | undefined;
  /** Tags every batch, so multi-instance flushes merge. Default `"default"`. */
  instanceId?: string | undefined;
  /** Called with each closed window. Errors are contained, not thrown at a check. */
  flush?: ((batch: MetricsBatch) => void) | undefined;
  /** Max distinct check counters per window. Default 10 000. */
  maxCheckKeys?: number | undefined;
  /** Max distinct grant/revoke/role ids per window, each. Default 10 000. */
  maxRowKeys?: number | undefined;
  /** Max distinct principals counted exactly per window. Default 1 000. */
  maxPrincipals?: number | undefined;
  /** Recent distinct principals retained per attributed row. Default 5. */
  maxRecentPrincipalsPerRow?: number | undefined;
  onError?: ((error: unknown) => void) | undefined;
  clock?: (() => number) | undefined;
}

interface RowAccumulator {
  matched: number;
  soleMatch: number;
  estimatedMatched: number;
  estimatedSoleMatch: number;
  recentPrincipals: Set<string>;
}

const principalId = (principal: PrincipalRef): string =>
  "userId" in principal ? `user:${principal.userId}` : `service:${principal.serviceId}`;

/**
 * The pure windowed aggregator: fold a `CheckObservation` stream into fixed
 * memory, hand out closed windows, and answer "what is happening right now"
 * without any storage at all.
 *
 * It is also the DIRECT-ACCESS API. `snapshot()` returns the live window at
 * any moment, so a deployment that wants numbers without an external metrics
 * stack can serve them from its own process:
 *
 * ```ts
 * const metrics = createMetricsAggregator();
 * const alfiz = createAlfizClient({ catalog, provider, metrics: { observer: metrics.observer } });
 *
 * // …anywhere in the app:
 * app.get("/internal/permission-metrics", () => Response.json(metrics.snapshot()));
 * ```
 *
 * Windows roll lazily, on the first observation past the boundary, so a
 * quiet process schedules nothing. Pair with {@link startMetricsFlusher}
 * when a window must close on time rather than on traffic.
 */
export class MetricsAggregator {
  readonly instanceId: string;
  /** Bind this as the client's `metrics.observer`. */
  readonly observer: MetricsObserver;

  private readonly windowMs: number;
  private readonly maxCheckKeys: number;
  private readonly maxRowKeys: number;
  private readonly maxPrincipals: number;
  private readonly maxRecentPrincipals: number;
  private readonly onFlush: ((batch: MetricsBatch) => void) | undefined;
  private readonly onError: ((error: unknown) => void) | undefined;
  private readonly now: () => number;

  private windowStart: number;
  private checks = new Map<string, CheckCounter>();
  private grants = new Map<string, RowAccumulator>();
  private revokes = new Map<string, RowAccumulator>();
  private roles = new Map<string, RowAccumulator>();
  private principals = new Set<string>();
  private principalOverflow = false;
  private dropped = 0;

  constructor(options: MetricsAggregatorOptions = {}) {
    this.windowMs = options.windowMs ?? 60_000;
    this.instanceId = options.instanceId ?? "default";
    this.onFlush = options.flush;
    this.onError = options.onError;
    this.maxCheckKeys = options.maxCheckKeys ?? 10_000;
    this.maxRowKeys = options.maxRowKeys ?? 10_000;
    this.maxPrincipals = options.maxPrincipals ?? 1_000;
    this.maxRecentPrincipals = options.maxRecentPrincipalsPerRow ?? 5;
    this.now = options.clock ?? Date.now;
    this.windowStart = this.now();
    this.observer = (observation) => this.record(observation);
  }

  record(observation: CheckObservation): void {
    const now = this.now();
    if (now - this.windowStart >= this.windowMs) this.flush(now);

    const weight = observation.sampleRate > 0 ? 1 / observation.sampleRate : 1;
    const permission = observation.permission ?? "(any)";
    const scopePart = observation.scope ?? "";
    const key = `${permission} ${observation.decision} ${observation.shape} ${observation.scopeType} ${scopePart}`;
    const existing = this.checks.get(key);
    if (existing) {
      existing.observed += 1;
      existing.estimated += weight;
    } else if (this.checks.size >= this.maxCheckKeys) {
      this.dropped += 1;
    } else {
      this.checks.set(key, {
        permission,
        decision: observation.decision,
        shape: observation.shape,
        gate: observation.gate,
        scopeType: observation.scopeType,
        ...(observation.scope === undefined ? {} : { scope: observation.scope }),
        observed: 1,
        estimated: weight,
      });
    }

    const who = principalId(observation.principal);
    if (this.principals.has(who)) {
      // Already counted.
    } else if (this.principals.size >= this.maxPrincipals) {
      this.principalOverflow = true;
    } else {
      this.principals.add(who);
    }

    // Attribution runs on gates only when it can be meaningful, but on every
    // shape when rows matched: a visibility check IS usage of the grant that
    // answered it, and the counters are separated by shape upstream anyway.
    for (const grantId of observation.matchedGrantIds) {
      this.attribute(this.grants, grantId, grantId === observation.soleMatchGrantId, weight, who);
    }
    for (const revokeId of observation.matchedRevokeIds) {
      // A revoke that matched suppressed this check outright; there is no
      // "shadowed revoke" case, so every match is a sole match.
      this.attribute(this.revokes, revokeId, true, weight, who);
    }
    for (const roleId of observation.roleIds) {
      this.attribute(
        this.roles,
        roleId,
        observation.soleMatchGrantId !== null,
        weight,
        who,
      );
    }
  }

  private attribute(
    into: Map<string, RowAccumulator>,
    rowId: string,
    sole: boolean,
    weight: number,
    who: string,
  ): void {
    let row = into.get(rowId);
    if (row === undefined) {
      if (into.size >= this.maxRowKeys) {
        this.dropped += 1;
        return;
      }
      row = {
        matched: 0,
        soleMatch: 0,
        estimatedMatched: 0,
        estimatedSoleMatch: 0,
        recentPrincipals: new Set(),
      };
      into.set(rowId, row);
    }
    row.matched += 1;
    row.estimatedMatched += weight;
    if (sole) {
      row.soleMatch += 1;
      row.estimatedSoleMatch += weight;
    }
    if (row.recentPrincipals.size < this.maxRecentPrincipals) {
      row.recentPrincipals.add(who);
    }
  }

  /** The window so far, without closing it — the direct-read surface. */
  snapshot(at?: number): MetricsBatch {
    return this.build(at ?? this.now());
  }

  /**
   * Closes the current window, hands it to the `flush` callback, and starts
   * a new one. Returns the closed batch (empty windows included — a window
   * with no traffic is itself a fact) so callers that prefer pulling can
   * ignore the callback entirely.
   */
  flush(at?: number): MetricsBatch {
    const end = at ?? this.now();
    const batch = this.build(end);
    this.checks = new Map();
    this.grants = new Map();
    this.revokes = new Map();
    this.roles = new Map();
    this.principals = new Set();
    this.principalOverflow = false;
    this.dropped = 0;
    this.windowStart = end;
    if (this.onFlush) {
      try {
        this.onFlush(batch);
      } catch (error) {
        this.onError?.(error);
      }
    }
    return batch;
  }

  private build(end: number): MetricsBatch {
    const rows = (map: Map<string, RowAccumulator>): RowUsageCounter[] =>
      [...map].map(([rowId, row]) => ({
        rowId,
        matched: row.matched,
        soleMatch: row.soleMatch,
        estimatedMatched: Math.round(row.estimatedMatched),
        estimatedSoleMatch: Math.round(row.estimatedSoleMatch),
        recentPrincipals: [...row.recentPrincipals],
      }));
    return {
      instanceId: this.instanceId,
      windowStart: this.windowStart,
      windowEnd: end,
      checks: [...this.checks.values()].map((counter) => ({
        ...counter,
        estimated: Math.round(counter.estimated),
      })),
      grants: rows(this.grants),
      revokes: rows(this.revokes),
      roles: rows(this.roles),
      principals: {
        distinct: this.principals.size,
        overflowed: this.principalOverflow,
      },
      dropped: this.dropped,
    };
  }
}

export function createMetricsAggregator(
  options?: MetricsAggregatorOptions,
): MetricsAggregator {
  return new MetricsAggregator(options);
}

/**
 * Closes windows on a timer rather than on traffic. Optional: the aggregator
 * rolls lazily on its own, and a pull-based reader (`snapshot()`) needs no
 * timer at all. The handle is `unref`'d where the runtime supports it, so it
 * never keeps a process alive.
 */
export function startMetricsFlusher(
  aggregator: MetricsAggregator,
  options: { intervalMs?: number | undefined } = {},
): () => void {
  const handle = setInterval(() => {
    aggregator.flush();
  }, options.intervalMs ?? 60_000);
  (handle as { unref?: () => void }).unref?.();
  return () => clearInterval(handle);
}

/**
 * The default consumer: aggregate locally, then batch to the provider, which
 * stores the rolling per-grant / per-revoke buckets the safeguards read back.
 * The Client only ever hands batches to its own Application — nothing
 * metrics-shaped travels further unless the Application chooses to send it.
 *
 * ```ts
 * const sink = createProviderMetricsSink(app, { intervalMs: 30_000 });
 * const alfiz = createAlfizClient({ catalog, provider: app, metrics: { observer: sink.observer } });
 * // on shutdown: await sink.stop();
 * ```
 *
 * A provider without `reportMetrics` (capability `metrics: false`) accepts
 * nothing, and the sink degrades to a local aggregator — progressive
 * disclosure, same as every other optional capability.
 */
export function createProviderMetricsSink(
  provider: AlfizProvider,
  options: MetricsAggregatorOptions & {
    intervalMs?: number | undefined;
    /**
     * Batches allowed to queue behind a slow store before new ones are
     * DROPPED. Default 4. The back-pressure rule is deliberate: if the
     * database is struggling, the correct behavior for a counter is to lose
     * counts, not to grow a queue in the process that is already under
     * strain. Drops are counted on `droppedBatches`, never silent.
     */
    maxPendingBatches?: number | undefined;
  } = {},
): {
  observer: MetricsObserver;
  aggregator: MetricsAggregator;
  /** Flush the open window and deliver it. Awaiting is optional and never required. */
  flush: () => Promise<void>;
  /** Stop the timer and deliver a final batch. */
  stop: () => Promise<void>;
  /** Batches dropped because the store could not keep up. */
  readonly droppedBatches: number;
} {
  let inFlight: Promise<void> = Promise.resolve();
  /**
   * Capability discovery, once and lazily: a provider that stores no metrics
   * is told nothing, rather than being handed batches it will reject on
   * every flush. An unreadable capability set means "not supported" — the
   * sink degrades to a local aggregator, which is the whole feature minus
   * durability.
   */
  let supported: Promise<boolean> | null = null;
  const accepts = (): Promise<boolean> =>
    (supported ??= provider
      .capabilities()
      .then((caps) => caps.metrics === true && provider.reportMetrics !== undefined)
      .catch(() => false));
  const maxPending = options.maxPendingBatches ?? 4;
  let pending = 0;
  let droppedBatches = 0;
  const deliver = (batch: MetricsBatch): void => {
    if (provider.reportMetrics === undefined) return;
    if (
      batch.checks.length === 0 &&
      batch.grants.length === 0 &&
      batch.revokes.length === 0 &&
      batch.roles.length === 0
    ) {
      return;
    }
    if (pending >= maxPending) {
      // Back-pressure: a store that cannot keep up loses counts rather than
      // accumulating a queue. Metrics are lossy by design; latency is not.
      droppedBatches += 1;
      return;
    }
    // Fire-and-forget by design: nothing awaits this chain, so a slow or
    // failing store cannot add a millisecond to any check, request, or
    // write. A failed batch is a lost count, not a lost decision.
    pending += 1;
    inFlight = inFlight
      .then(async () => {
        if (await accepts()) await provider.reportMetrics!(batch);
      })
      .catch((error: unknown) => options.onError?.(error))
      .finally(() => {
        pending -= 1;
      });
  };
  const aggregator = new MetricsAggregator({
    ...options,
    flush: (batch) => {
      deliver(batch);
      options.flush?.(batch);
    },
  });
  const stopTimer = startMetricsFlusher(aggregator, {
    intervalMs: options.intervalMs ?? options.windowMs ?? 60_000,
  });
  const flush = async (): Promise<void> => {
    aggregator.flush();
    await inFlight;
  };
  return {
    observer: aggregator.observer,
    aggregator,
    flush,
    stop: async () => {
      stopTimer();
      await flush();
    },
    get droppedBatches() {
      return droppedBatches;
    },
  };
}

// ---------------------------------------------------------------------------
// Durable buckets and the usage-read API
// ---------------------------------------------------------------------------

/**
 * What a stored counter is about. Kept to flat rollups rather than a cross
 * product: two bounded tables answer every shipped question, and a cross
 * product is where a metrics store starts growing without a ceiling.
 */
export type MetricDimension = "grant" | "revoke" | "role" | "permission" | "scopeType";

/** Metric names stored per dimension. Free-form by contract, fixed in practice. */
export const METRIC_MATCHED = "matched";
export const METRIC_SOLE_MATCH = "soleMatch";
export const METRIC_GATE_ALLOW = "gate.allow";
export const METRIC_GATE_DENY = "gate.deny";
export const METRIC_VISIBILITY_ALLOW = "visibility.allow";
export const METRIC_VISIBILITY_DENY = "visibility.deny";

export interface MetricBucketKey {
  /** Bucket start (epoch ms), aligned to the store's granularity (daily by default). */
  bucket: number;
  dimension: MetricDimension;
  /** A grant id, revoke id, role id, permission key, or scope type. */
  subject: string;
  metric: string;
}

export interface MetricBucketDelta extends MetricBucketKey {
  /** Increment. Sampling-corrected before it reaches storage. */
  count: number;
}

export type MetricBucket = MetricBucketDelta;

export interface MetricBucketQuery {
  dimension: MetricDimension;
  /** Restrict to these subjects; omit for every subject in the window. */
  subjects?: readonly string[] | undefined;
  /** Inclusive lower bound on `bucket` (epoch ms). */
  since?: number | undefined;
  /** Exclusive upper bound on `bucket` (epoch ms). */
  until?: number | undefined;
}

/** Aggregated usage for one attributed row over a window. */
export interface RowUsage {
  rowId: string;
  /** Participated in an allow. */
  matched: number;
  /** Was the only row allowing — revoking it would have denied. */
  soleMatch: number;
  windowStart: number;
  windowEnd: number;
  /** Per-bucket detail, oldest first, for sparklines and trend copy. */
  buckets: Array<{ bucket: number; matched: number; soleMatch: number }>;
}

/** Aggregated usage for one permission key, split by gate versus visibility. */
export interface PermissionUsage {
  permission: string;
  gateAllow: number;
  gateDeny: number;
  visibilityAllow: number;
  visibilityDeny: number;
  windowStart: number;
  windowEnd: number;
}

export interface UsageQuery {
  /** Restrict to these ids/keys; omit for everything in the window. */
  ids?: readonly string[] | undefined;
  /** Inclusive lower bound (epoch ms). Default: the provider's full retention. */
  since?: number | undefined;
  /** Exclusive upper bound (epoch ms). Default: now. */
  until?: number | undefined;
}

// ---------------------------------------------------------------------------
// The revocation safeguard (§4)
// ---------------------------------------------------------------------------

export type SafeguardLevel = "none" | "context" | "warning";

export interface RevocationSafeguard {
  level: SafeguardLevel;
  matched: number;
  soleMatch: number;
  /** Days covered by the underlying window, for the copy. */
  days: number;
  /** One line, safe to render verbatim. */
  headline: string;
  /** The honest qualifier. Always present, always shown. */
  detail: string;
}

export interface SafeguardOptions {
  /** `soleMatch` at or above this is a warning. Default 1 — any counterfactual counts. */
  warnAtSoleMatch?: number | undefined;
  /** What is being removed. Changes the direction of the copy. Default `"grant"`. */
  kind?: "grant" | "revoke" | "role" | undefined;
}

/**
 * Turns stored usage into the warning a grant/revoke/role removal UI should
 * render. Pure — components bind it; nothing here renders.
 *
 * Two rules the copy never breaks:
 *
 *   - It keys on `soleMatch`, not `matched`. A check satisfied by two grant
 *     rows loses nothing when one is revoked, and warning about a grant fully
 *     shadowed by a broader one teaches admins to ignore the warning.
 *     `matched` only ever contextualizes ("used often, but always alongside
 *     another grant").
 *   - It never says "safe". Usage lags, and absence of recent use is not
 *     evidence — break-glass grants are precisely the rarely-used ones. The
 *     warning says "frequently load-bearing"; silence says nothing at all.
 */
export function revocationSafeguard(
  usage: Pick<RowUsage, "matched" | "soleMatch" | "windowStart" | "windowEnd">,
  options: SafeguardOptions = {},
): RevocationSafeguard {
  const kind = options.kind ?? "grant";
  const threshold = options.warnAtSoleMatch ?? 1;
  const days = Math.max(
    1,
    Math.round((usage.windowEnd - usage.windowStart) / 86_400_000),
  );
  const period = days === 1 ? "the last day" : `the last ${days} days`;
  const noun = kind === "revoke" ? "revoke" : kind === "role" ? "role" : "grant";

  if (usage.soleMatch >= threshold) {
    return {
      level: "warning",
      matched: usage.matched,
      soleMatch: usage.soleMatch,
      days,
      headline:
        kind === "revoke"
          ? `This revoke suppressed ${usage.soleMatch} checks in ${period}. Deleting it widens access.`
          : `This ${noun} was the only thing allowing ${usage.soleMatch} checks in ${period}.`,
      detail:
        kind === "revoke"
          ? "Every one of those checks would have been allowed without it."
          : `Removing it would have denied them. It also participated in ${usage.matched} checks in total.`,
    };
  }
  if (usage.matched > 0) {
    return {
      level: "context",
      matched: usage.matched,
      soleMatch: usage.soleMatch,
      days,
      headline: `This ${noun} matched ${usage.matched} checks in ${period}, but was never the only thing allowing them.`,
      detail:
        "Another grant covered every one of those checks, so removing this one would not have changed any decision in the window.",
    };
  }
  return {
    level: "none",
    matched: 0,
    soleMatch: 0,
    days,
    headline: `No recorded use in ${period}.`,
    detail:
      "Absence of recent use is not evidence that removing this is safe: usage lags, metrics are sampled and lossy, and break-glass access is precisely the kind that goes unused for long stretches.",
  };
}
