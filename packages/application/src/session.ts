/**
 * Sessions and view-as. A session carries the **actor** (who is really here)
 * and the **subject** (whose access is being rendered) — never a mutated
 * single identity. The invariant: every check passes against the actor's
 * real access AND the previewed subject's, so a preview can only ever narrow
 * what is shown and can never escalate privileges.
 *
 * Two check surfaces, same names as everywhere else. The async methods
 * (`can` / `canAny` / `require` / `requireAny`) suit actions and one-off
 * checks; render paths take ONE session snapshot per request
 * (`session.snapshot()`) and check synchronously — the same
 * one-snapshot-per-request pattern the client prescribes, preserved under
 * view-as.
 *
 * Framework wiring (cookies, redirects) stays in the host app; this module
 * is the decision core plus serialization helpers.
 */

import type {
  AlfizClient,
  AlfizSnapshot,
  AnyCatalog,
  CheckContext,
  KeyOf,
  LooseKey,
  LooseScopeId,
  PatternOf,
  PermissionKey,
  PrincipalRef,
  ScopeId,
  ScopeOf,
  SnapshotOptions,
  SubjectAccessData,
} from "@alfiz/core";
import {
  AccessDeniedError,
  GLOBAL_SCOPE,
  checkAny,
  checkKey,
  keyHeldAnywhere,
  objectClosureOf,
  toCheckContext,
} from "@alfiz/core";

export type ViewAsState =
  /** Preview as a role: the subject's access becomes the role's patterns. */
  | { kind: "role"; roleId: string }
  /** Preview as an individual: full effective access, id, and memberships — data-scoped surfaces reproduce exactly what they see. */
  | { kind: "user"; userId: string };

export interface SessionOptions {
  actorUserId: string;
  viewAs?: ViewAsState | null | undefined;
}

export class AlfizSession<
  K extends string = string,
  P extends string = string,
  S extends string = string,
> {
  readonly actorUserId: string;
  readonly viewAs: ViewAsState | null;

  private readonly client: AlfizClient<K, P, S>;

  constructor(client: AlfizClient<K, P, S>, options: SessionOptions) {
    this.client = client;
    this.actorUserId = options.actorUserId;
    this.viewAs = options.viewAs ?? null;
  }

  /**
   * The id data-scoped surfaces should key on: the previewed individual's
   * during an individual preview, the actor's otherwise. Audit writes must
   * always use `actorUserId` — attribution never follows the preview.
   */
  get subjectUserId(): string {
    return this.viewAs?.kind === "user" ? this.viewAs.userId : this.actorUserId;
  }

  private get actorPrincipal(): PrincipalRef {
    return { userId: this.actorUserId };
  }

  /** Preview-narrowed check: subject allowed AND actor really allowed. */
  async can(key: K | readonly K[], scope?: LooseScopeId<S>): Promise<boolean> {
    if (!(await this.client.can(this.actorPrincipal, key, scope))) return false;
    if (this.viewAs === null) return true;
    if (this.viewAs.kind === "user") {
      // `observe: false`: an administrator looking through someone's eyes
      // did not use that person's grants. Metrics attribution never follows
      // the preview, exactly as audit attribution never does.
      return this.client.can({ userId: this.viewAs.userId }, key, scope, {
        observe: false,
      });
    }
    return this.roleCan(this.viewAs.roleId, key, scope);
  }

  async canAny(pattern: P): Promise<boolean> {
    if (!(await this.client.canAny(this.actorPrincipal, pattern))) return false;
    if (this.viewAs === null) return true;
    if (this.viewAs.kind === "user") {
      return this.client.canAny({ userId: this.viewAs.userId }, pattern, {
        observe: false,
      });
    }
    // Role previews: the role's patterns intersected with the catalog.
    return this.rolePatternIntersects(this.viewAs.roleId, pattern);
  }

  async require(key: K | readonly K[], scope?: LooseScopeId<S>): Promise<void> {
    if (!(await this.can(key, scope))) {
      throw new AccessDeniedError({
        reason: "forbidden",
        permission: key as string | readonly string[],
        scope,
        // Attribution: the denial names the ACTOR — during a preview the
        // narrowed subject is the render, but the person here is the actor.
        principal: { userId: this.actorUserId },
      });
    }
  }

  async requireAny(pattern: P): Promise<void> {
    if (!(await this.canAny(pattern))) {
      throw new AccessDeniedError({
        reason: "forbidden",
        permission: pattern,
        principal: { userId: this.actorUserId },
      });
    }
  }

  // -- role-preview evaluation ---------------------------------------------

  private async roleContext(roleId: string): Promise<CheckContext | null> {
    const role = (await this.client.provider.listRoles()).find(
      (r) => r.id === roleId,
    );
    if (!role) return null;
    const synthetic: SubjectAccessData = {
      userId: null, // a role preview has no personal revokes
      closure: ["preview:role"],
      grants: role.patterns.map((pattern, i) => ({
        id: `preview:${i}`,
        subject: "preview:role",
        pattern,
        scope: GLOBAL_SCOPE,
        provenance: { kind: "system", note: "view-as role preview" },
        createdAt: 0,
      })),
      revokes: [],
      roles: [],
      managerChain: [],
      unresolvedRoleIds: [],
      active: true,
    };
    return toCheckContext(synthetic, Date.now());
  }

  private async roleCan(
    roleId: string,
    key: K | readonly K[],
    scope?: ScopeId,
  ): Promise<boolean> {
    const ctx = await this.roleContext(roleId);
    if (!ctx) return false;
    const closure =
      scope === undefined
        ? [GLOBAL_SCOPE]
        : await objectClosureOf(scope, this.client.provider.resolveAncestors);
    const keys: readonly string[] = Array.isArray(key)
      ? (key as readonly string[])
      : [key as string];
    return keys.some((k) => checkKey(ctx, k, closure));
  }

  private async rolePatternIntersects(
    roleId: string,
    pattern: P,
  ): Promise<boolean> {
    const ctx = await this.roleContext(roleId);
    if (!ctx) return false;
    return checkAny(ctx, pattern, this.client.catalog.keys);
  }

  /**
   * The session-shaped snapshot: one fetch per identity, then SYNCHRONOUS
   * preview-narrowed checks — the same one-snapshot-per-request pattern the
   * client prescribes for render paths (see snapshot.ts), available under
   * view-as. Every check intersects the actor's snapshot with the previewed
   * subject's, so a preview can only ever narrow, exactly as on the async
   * session methods. `options` (pre-resolved scopes, freshness) applies to
   * both identities.
   */
  async snapshot(
    options?: SnapshotOptions<S>,
  ): Promise<AlfizSessionSnapshot<K, P, S>> {
    const [actor, preview] = await Promise.all([
      this.client.snapshot(this.actorPrincipal, options),
      this.previewEval(options),
    ]);
    return new AlfizSessionSnapshot({
      catalog: this.client.catalog,
      actorUserId: this.actorUserId,
      viewAs: this.viewAs,
      actor,
      preview,
    });
  }

  private async previewEval(
    options?: SnapshotOptions<S>,
  ): Promise<SessionPreviewEval<K, P, S> | null> {
    if (this.viewAs === null) return null;
    if (this.viewAs.kind === "user") {
      return {
        kind: "user",
        snap: await this.client.snapshot(
          { userId: this.viewAs.userId },
          // The previewed side is unobserved — see `can` above.
          { ...options, observe: false },
        ),
      };
    }
    // An unknown role id evaluates to no access — previews fail closed.
    return { kind: "role", ctx: await this.roleContext(this.viewAs.roleId) };
  }
}

/** How a session snapshot evaluates the previewed side of each check. */
type SessionPreviewEval<
  K extends string,
  P extends string,
  S extends string,
> =
  | { kind: "user"; snap: AlfizSnapshot<K, P, S> }
  | { kind: "role"; ctx: CheckContext | null };

interface SessionSnapshotInit<
  K extends string,
  P extends string,
  S extends string,
> {
  catalog: AnyCatalog;
  actorUserId: string;
  viewAs: ViewAsState | null;
  actor: AlfizSnapshot<K, P, S>;
  preview: SessionPreviewEval<K, P, S> | null;
}

const GLOBAL_CLOSURE: readonly ScopeId[] = [GLOBAL_SCOPE];

/**
 * Synchronous, preview-narrowed checks over one consistent instant per
 * identity. Same names, same questions as every other surface: `can` /
 * `require` gate, `canAny` / `requireAny` guard visibility, `holds` /
 * `heldKeys` probe unscoped possession. Each answer is the INTERSECTION of
 * the actor's access and the previewed subject's (no preview: the actor's
 * alone) — a preview narrows what is shown and can never escalate.
 *
 * Role previews evaluate synchronously with no extra resolution: a role's
 * patterns are global-scope by construction, so its side of a check never
 * depends on an ancestor chain. Scope pre-resolution rules for hierarchical
 * targets are the client snapshot's, applied to both identities.
 */
export class AlfizSessionSnapshot<
  K extends string = string,
  P extends string = string,
  S extends string = string,
> {
  readonly actorUserId: string;
  readonly viewAs: ViewAsState | null;

  private readonly catalog: AnyCatalog;
  private readonly actor: AlfizSnapshot<K, P, S>;
  private readonly preview: SessionPreviewEval<K, P, S> | null;
  private held: Set<PermissionKey> | null = null;

  constructor(init: SessionSnapshotInit<K, P, S>) {
    this.catalog = init.catalog;
    this.actorUserId = init.actorUserId;
    this.viewAs = init.viewAs;
    this.actor = init.actor;
    this.preview = init.preview;
  }

  /** The id data-scoped surfaces should key on — see `AlfizSession.subjectUserId`. */
  get subjectUserId(): string {
    return this.viewAs?.kind === "user" ? this.viewAs.userId : this.actorUserId;
  }

  /** The actor-side evaluation instant (epoch ms). */
  get at(): number {
    return this.actor.at;
  }

  /**
   * Resolves more scope chains into BOTH identities' snapshots — the
   * hierarchical-list-page shape, unchanged under view-as.
   */
  async resolve(scopes: readonly LooseScopeId<S>[]): Promise<this> {
    await Promise.all([
      this.actor.resolve(scopes),
      this.preview?.kind === "user"
        ? this.preview.snap.resolve(scopes)
        : Promise.resolve(),
    ]);
    return this;
  }

  /** Preview-narrowed synchronous gate: subject allowed AND actor really allowed. */
  can(key: K | readonly K[], scope?: LooseScopeId<S>): boolean {
    if (!this.actor.can(key, scope)) return false;
    if (this.preview === null) return true;
    if (this.preview.kind === "user") return this.preview.snap.can(key, scope);
    const ctx = this.preview.ctx;
    if (ctx === null) return false;
    // Role grants sit at the global scope, which is in every object
    // closure — the target's chain cannot change the role side's answer.
    const keys: readonly string[] = Array.isArray(key)
      ? (key as readonly string[])
      : [key as string];
    return keys.some((k) => checkKey(ctx, k, GLOBAL_CLOSURE));
  }

  /** Preview-narrowed synchronous visibility affordance. Never a gate. */
  canAny(pattern: P): boolean {
    if (!this.actor.canAny(pattern)) return false;
    if (this.preview === null) return true;
    if (this.preview.kind === "user") return this.preview.snap.canAny(pattern);
    const ctx = this.preview.ctx;
    return ctx !== null && checkAny(ctx, pattern, this.catalog.keys);
  }

  /** Throwing form of `can`. Denials name the ACTOR — attribution never follows the preview. */
  require(key: K | readonly K[], scope?: LooseScopeId<S>): void {
    if (!this.can(key, scope)) {
      throw new AccessDeniedError({
        reason: "forbidden",
        permission: key as string | readonly string[],
        scope,
        principal: { userId: this.actorUserId },
      });
    }
  }

  /** Throwing form of `canAny` — the page-top visibility guard, never an action gate. */
  requireAny(pattern: P): void {
    if (!this.canAny(pattern)) {
      throw new AccessDeniedError({
        reason: "forbidden",
        permission: pattern,
        principal: { userId: this.actorUserId },
      });
    }
  }

  /** Preview-narrowed "held at ANY scope" probe. Never a gate. */
  holds(key: LooseKey<K>): boolean {
    if (!this.actor.holds(key)) return false;
    if (this.preview === null) return true;
    if (this.preview.kind === "user") return this.preview.snap.holds(key);
    const ctx = this.preview.ctx;
    return ctx !== null && keyHeldAnywhere(ctx, key as PermissionKey);
  }

  /**
   * Every concrete catalog key BOTH identities hold somewhere — the
   * intersection that feeds unscoped conditional UI under view-as.
   * Computed once per snapshot, on first access.
   */
  get heldKeys(): ReadonlySet<PermissionKey> {
    if (this.held === null) {
      const actorHeld = [...this.actor.heldKeys];
      let keys: PermissionKey[];
      if (this.preview === null) {
        keys = actorHeld;
      } else if (this.preview.kind === "user") {
        const snap = this.preview.snap;
        keys = actorHeld.filter((key) => snap.heldKeys.has(key));
      } else {
        const ctx = this.preview.ctx;
        keys =
          ctx === null
            ? []
            : actorHeld.filter((key) => keyHeldAnywhere(ctx, key));
      }
      this.held = new Set(keys);
    }
    return this.held;
  }
}

/**
 * The session-snapshot type for a catalog — `SessionSnapshotOf<typeof
 * catalog>` — completing the derived-type family with `KeyOf` / `PatternOf`
 * / `ScopeOf` / `ClientOf` / `SnapshotOf` / `SessionOf`.
 */
export type SessionSnapshotOf<Cat> = AlfizSessionSnapshot<
  KeyOf<Cat>,
  PatternOf<Cat>,
  ScopeOf<Cat>
>;

/**
 * Builds a session. Starting a preview is itself permission-gated
 * (`alfiz_internal.access.view_as` on the actor's REAL access); pass
 * `viewAs` only after `assertCanViewAs` — or let this throw. Stopping a
 * preview is deliberately ungated (anti-lockout): build with `viewAs: null`.
 */
export async function createSession<
  K extends string,
  P extends string,
  S extends string,
>(
  client: AlfizClient<K, P, S>,
  options: SessionOptions,
): Promise<AlfizSession<K, P, S>> {
  if (options.viewAs != null) {
    await assertCanViewAs(client, options.actorUserId);
  }
  return new AlfizSession(client, options);
}

export async function assertCanViewAs<
  K extends string,
  P extends string,
  S extends string,
>(
  client: AlfizClient<K, P, S>,
  actorUserId: string,
): Promise<void> {
  const key = "alfiz_internal.access.view_as";
  // A catalog built with `includeAlfizInternal: false` renders no Alfiz
  // admin surface, so nobody may preview — deny. Checking the key would
  // otherwise be a malformed check against that catalog, and previews must
  // fail closed, not explode.
  const allowed =
    client.catalog.hasKey(key) && (await client.can({ userId: actorUserId }, key as K));
  if (!allowed) {
    throw new AccessDeniedError({
      reason: "forbidden",
      permission: key,
      principal: { userId: actorUserId },
    });
  }
}

/**
 * The session type for a catalog — `SessionOf<typeof catalog>` — so a
 * session stored on a request context needs no hand-written type
 * parameters. Completes the derived-type family with `KeyOf` / `PatternOf`
 * / `ClientOf` / `SnapshotOf`.
 */
export type SessionOf<Cat> = AlfizSession<KeyOf<Cat>, PatternOf<Cat>, ScopeOf<Cat>>;

/** Cookie-safe serialization for view-as state. */
export function serializeViewAs(state: ViewAsState): string {
  return `${state.kind}:${state.kind === "role" ? state.roleId : state.userId}`;
}

export function parseViewAs(raw: string | null | undefined): ViewAsState | null {
  if (!raw) return null;
  const idx = raw.indexOf(":");
  if (idx <= 0) return null;
  const kind = raw.slice(0, idx);
  const id = raw.slice(idx + 1);
  if (id === "") return null;
  if (kind === "role") return { kind: "role", roleId: id };
  if (kind === "user") return { kind: "user", userId: id };
  return null;
}
