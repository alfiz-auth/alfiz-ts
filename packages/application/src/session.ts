/**
 * Sessions and view-as. A session carries the **actor** (who is really here)
 * and the **subject** (whose access is being rendered) — never a mutated
 * single identity. The invariant: every check passes against the actor's
 * real access AND the previewed subject's, so a preview can only ever narrow
 * what is shown and can never escalate privileges.
 *
 * Framework wiring (cookies, redirects) stays in the host app; this module
 * is the decision core plus serialization helpers.
 */

import type {
  AlfizClient,
  CheckContext,
  PrincipalRef,
  ScopeId,
  SubjectAccessData,
} from "@alfiz/core";
import {
  AccessDeniedError,
  GLOBAL_SCOPE,
  checkKey,
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

export class AlfizSession<K extends string = string, P extends string = string> {
  readonly actorUserId: string;
  readonly viewAs: ViewAsState | null;

  private readonly client: AlfizClient<K, P>;

  constructor(client: AlfizClient<K, P>, options: SessionOptions) {
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
  async can(key: K | readonly K[], scope?: ScopeId): Promise<boolean> {
    if (!(await this.client.can(this.actorPrincipal, key, scope))) return false;
    if (this.viewAs === null) return true;
    if (this.viewAs.kind === "user") {
      return this.client.can({ userId: this.viewAs.userId }, key, scope);
    }
    return this.roleCan(this.viewAs.roleId, key, scope);
  }

  async canAny(pattern: P): Promise<boolean> {
    if (!(await this.client.canAny(this.actorPrincipal, pattern))) return false;
    if (this.viewAs === null) return true;
    if (this.viewAs.kind === "user") {
      return this.client.canAny({ userId: this.viewAs.userId }, pattern);
    }
    // Role previews: the role's patterns intersected with the catalog.
    return this.rolePatternIntersects(this.viewAs.roleId, pattern);
  }

  async require(key: K | readonly K[], scope?: ScopeId): Promise<void> {
    if (!(await this.can(key, scope))) {
      throw new AccessDeniedError({
        reason: "forbidden",
        permission: key as string | readonly string[],
        scope,
      });
    }
  }

  async requireAny(pattern: P): Promise<void> {
    if (!(await this.canAny(pattern))) {
      throw new AccessDeniedError({ reason: "forbidden", permission: pattern });
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
    const { checkAny } = await import("@alfiz/core");
    return checkAny(ctx, pattern, this.client.catalog.keys);
  }
}

/**
 * Builds a session. Starting a preview is itself permission-gated
 * (`alfiz_internal.access.view_as` on the actor's REAL access); pass
 * `viewAs` only after `assertCanViewAs` — or let this throw. Stopping a
 * preview is deliberately ungated (anti-lockout): build with `viewAs: null`.
 */
export async function createSession<K extends string, P extends string>(
  client: AlfizClient<K, P>,
  options: SessionOptions,
): Promise<AlfizSession<K, P>> {
  if (options.viewAs != null) {
    await assertCanViewAs(client, options.actorUserId);
  }
  return new AlfizSession(client, options);
}

export async function assertCanViewAs<K extends string, P extends string>(
  client: AlfizClient<K, P>,
  actorUserId: string,
): Promise<void> {
  const allowed = await client.can(
    { userId: actorUserId },
    "alfiz_internal.access.view_as" as K,
  );
  if (!allowed) {
    throw new AccessDeniedError({
      reason: "forbidden",
      permission: "alfiz_internal.access.view_as",
    });
  }
}

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
