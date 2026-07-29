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

import type { CheckContext, CheckExplanation, GrantRow } from "./access.js";
import {
  checkAny,
  explainKey,
  grantedScopesFor,
  grantsMatchingKey,
  keyHeldAnywhere,
  revokedScopesFor,
} from "./access.js";
import type {
  CheckDecision,
  CheckObservation,
  CheckShape,
  MetricsRecorder,
} from "./metrics.js";
import { attributionOf, isGateShape, revokeIdsOf } from "./metrics.js";
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
  /**
   * Record metrics observations for checks made on this snapshot. Default
   * `true` (and inert unless the client has `metrics` configured). View-as
   * previews pass `false` on the previewed subject's side — attribution
   * never follows the preview.
   */
  observe?: boolean | undefined;
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
  /**
   * The client's metrics recorder, or `null` for an unobserved snapshot.
   * Snapshot checks are synchronous and by far the highest-volume shape, so
   * the sampling gate matters most here.
   */
  recorder?: MetricsRecorder | null | undefined;
  /**
   * The client's implicit-import decision, verbatim. One name per question,
   * same behavior on every surface: a permission the async `can` admits must
   * be one the synchronous `snap.can` admits, or the two surfaces disagree
   * about what the catalog covers. Absent = strict (throw), the default.
   */
  admitExternal?: ((permission: string, expected: "key" | "pattern") => void) | undefined;
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
  private readonly recorder: MetricsRecorder | null;
  private readonly admitExternal: (
    permission: string,
    expected: "key" | "pattern",
  ) => void;
  private held: Set<PermissionKey> | null = null;

  constructor(init: SnapshotInit) {
    this.catalog = init.catalog;
    this.principal = init.principal;
    this.data = init.data;
    this.active = init.data.active;
    this.ctx = init.ctx;
    this.chains = init.chains;
    this.resolveChain = init.resolveChain;
    this.recorder = init.recorder ?? null;
    this.admitExternal =
      init.admitExternal ??
      ((permission, expected) => {
        throw new UnknownPermissionError({
          permission,
          expected,
          ...unknownPermissionContext(init.catalog, permission, expected),
        });
      });
    this.at = init.ctx.now;
  }

  /**
   * The snapshot's metrics half. `at` is the SNAPSHOT's instant, not the
   * sink's: every check in a request shares one clock, and the observation
   * stream should say so.
   */
  private observe(input: {
    sampleRate: number;
    shape: CheckShape;
    decision: CheckDecision;
    permission: PermissionKey | PermissionPattern | null;
    anyOf: boolean;
    scope: ScopeId | undefined;
    matchedGrants?: readonly GrantRow[] | undefined;
    matchedRevokeIds?: readonly string[] | undefined;
    implied?: boolean | undefined;
  }): void {
    const recorder = this.recorder;
    if (recorder === null) return;
    const attribution = attributionOf(input.matchedGrants ?? []);
    const observation: CheckObservation = {
      at: this.at,
      shape: input.shape,
      gate: isGateShape(input.shape),
      decision: input.decision,
      permission: input.permission,
      anyOf: input.anyOf,
      ...recorder.scopeDimension(input.scope),
      principal: this.principal,
      matchedGrantIds: attribution.matchedGrantIds,
      soleMatchGrantId: attribution.soleMatchGrantId,
      matchedRevokeIds: input.matchedRevokeIds ?? [],
      roleIds: attribution.roleIds,
      implied: input.implied ?? false,
      fresh: false,
      snapshot: true,
      sampleRate: input.sampleRate,
    };
    recorder.record(observation);
  }

  private sampled(shape: CheckShape): number | null {
    return this.recorder === null ? null : this.recorder.sampled(shape);
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
      this.admitExternal(key, "key");
    }
  }

  private assertPattern(pattern: PermissionPattern): void {
    if (this.catalog.isKnownPattern(pattern)) return;
    this.admitExternal(pattern, "pattern");
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
  private impliedAt(key: PermissionKey, target: ScopeId): GrantRow[] | null {
    if (!this.catalog.leaf(key)?.impliedOnAncestors) return null;
    const rows = grantsMatchingKey(this.ctx, key);
    const scopes = new Set<ScopeId>();
    for (const row of rows) scopes.add(row.scope);
    for (const grantScope of scopes) {
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
      if (!suppressed) return rows.filter((row) => row.scope === grantScope);
    }
    return null;
  }

  /** Synchronous `can`: agrees with `client.can` for every resolvable scope. */
  can(key: K | readonly K[], scope?: LooseScopeId<S>): boolean {
    return this.gate(key, scope, "can");
  }

  private gate(
    key: K | readonly K[],
    scope: LooseScopeId<S> | undefined,
    shape: "can" | "require",
  ): boolean {
    const keys: readonly PermissionKey[] = Array.isArray(key)
      ? (key as readonly string[])
      : [key as string];
    this.assertKeys(keys);
    const sampleRate = this.sampled(shape);
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
        matchedGrants: matched?.grants,
        matchedRevokeIds: matched?.revokeIds,
        implied: matched?.implied,
      });
    };
    if (!this.active) {
      observe("deny", keys[0] ?? null);
      return false;
    }
    const closure = this.closureOf(scope);
    let firstDenial: CheckExplanation | null = null;
    for (const k of keys) {
      const explanation = explainKey(this.ctx, k, closure);
      if (explanation.allowed) {
        observe("allow", k, { grants: explanation.matchedGrants });
        return true;
      }
      firstDenial ??= explanation;
    }
    if (scope !== undefined && scope !== GLOBAL_SCOPE) {
      for (const k of keys) {
        const implying = this.impliedAt(k, scope);
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
   * Synchronous visibility affordance. Exact (not the conservative
   * approximation): every granted scope's chain was resolved at snapshot
   * time. Never a gate — same rule as the client's.
   */
  canAny(pattern: P): boolean {
    return this.anyCheck(pattern, "canAny");
  }

  private anyCheck(pattern: P, shape: "canAny" | "requireAny"): boolean {
    this.assertPattern(pattern);
    const allowed =
      this.active &&
      checkAny(
        this.ctx,
        pattern,
        this.catalog.keys,
        this.chains,
        this.catalog.opaqueRegions(pattern),
      );
    const sampleRate = this.sampled(shape);
    if (sampleRate !== null) {
      this.observe({
        sampleRate,
        shape,
        decision: allowed ? "allow" : "deny",
        permission: pattern,
        anyOf: false,
        scope: undefined,
      });
    }
    return allowed;
  }

  /** Throwing form of `can`. */
  require(key: K | readonly K[], scope?: LooseScopeId<S>): void {
    const keys = (Array.isArray(key) ? key : [key]) as readonly PermissionKey[];
    this.assertKeys(keys);
    if (!this.active) {
      const sampleRate = this.sampled("require");
      if (sampleRate !== null) {
        this.observe({
          sampleRate,
          shape: "require",
          decision: "deny",
          permission: keys[0] ?? null,
          anyOf: keys.length > 1,
          scope,
        });
      }
      throw new AccessDeniedError({
        reason: "inactive",
        permission: key as PermissionKey | readonly PermissionKey[],
        scope,
        principal: this.principal,
      });
    }
    if (!this.gate(key, scope, "require")) {
      throw new AccessDeniedError({
        reason: "forbidden",
        permission: key as PermissionKey | readonly PermissionKey[],
        scope,
        principal: this.principal,
      });
    }
  }

  /**
   * Throwing form of `canAny`, and exactly as narrow: the page-top
   * visibility guard on a page that still gates its own read with
   * `require`. Never an action gate — the verifier errors on it in server
   * actions and route handlers.
   */
  requireAny(pattern: P): void {
    this.assertPattern(pattern);
    if (!this.anyCheck(pattern, "requireAny")) {
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
      // Observed on the COMPUTATION, not on each read: the set is memoized
      // per snapshot, so counting every access would count re-reads of one
      // answer as new traffic.
      const sampleRate = this.sampled("heldKeys");
      if (sampleRate !== null) {
        this.observe({
          sampleRate,
          shape: "heldKeys",
          decision: this.held.size > 0 ? "allow" : "deny",
          permission: null,
          anyOf: false,
          scope: undefined,
        });
      }
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
    const held = this.active && keyHeldAnywhere(this.ctx, key as PermissionKey);
    const sampleRate = this.sampled("holds");
    if (sampleRate !== null) {
      this.observe({
        sampleRate,
        shape: "holds",
        decision: held ? "allow" : "deny",
        permission: key as PermissionKey,
        anyOf: false,
        scope: undefined,
        matchedGrants: held
          ? grantsMatchingKey(this.ctx, key as PermissionKey)
          : undefined,
      });
    }
    return held;
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
    /**
     * The grants at a DESCENDANT scope that produced an implied allow.
     * Empty unless `implied` — see `AlfizClient.explain`.
     */
    impliedBy: GrantRow[];
  } {
    this.assertKeys([key as PermissionKey]);
    const closure = this.closureOf(scope);
    const explanation = explainKey(this.ctx, key as PermissionKey, closure);
    let allowed = explanation.allowed && this.active;
    let implied = false;
    let impliedBy: GrantRow[] = [];
    if (
      !allowed &&
      this.active &&
      explanation.matchedRevokes.length === 0 &&
      scope !== undefined &&
      scope !== GLOBAL_SCOPE
    ) {
      const implying = this.impliedAt(key as PermissionKey, scope);
      implied = implying !== null;
      allowed = implied;
      impliedBy = implying ?? [];
    }
    return {
      ...explanation,
      allowed,
      implied,
      impliedBy,
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
