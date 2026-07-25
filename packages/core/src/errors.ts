/**
 * One decision core, thin failure adapters: every gate failure carries a
 * typed reason so page redirects, API status codes, and action results are
 * derived from one object instead of four hand-rolled channels.
 */

import type { PermissionKey } from "./grammar.js";
import type { ScopeId } from "./scopes.js";

export type DenialReason =
  /** No principal at all — the identity layer produced nobody. */
  | "unauthenticated"
  /** A principal, but the check failed. */
  | "forbidden"
  /** The principal exists but is inactive. */
  | "inactive";

export class AccessDeniedError extends Error {
  override name = "AccessDeniedError";
  readonly reason: DenialReason;
  readonly permission: PermissionKey | readonly PermissionKey[] | undefined;
  readonly scope: ScopeId | undefined;

  constructor(options: {
    reason: DenialReason;
    permission?: PermissionKey | readonly PermissionKey[] | undefined;
    scope?: ScopeId | undefined;
    message?: string | undefined;
  }) {
    const what = options.permission
      ? Array.isArray(options.permission)
        ? `any of [${options.permission.join(", ")}]`
        : String(options.permission)
      : "access";
    super(
      options.message ??
        `${options.reason}: ${what}${options.scope ? ` at ${options.scope}` : ""}`,
    );
    this.reason = options.reason;
    this.permission = options.permission;
    this.scope = options.scope;
  }
}

/** True when `err` is a gate failure (for framework adapters to map). */
export function isAccessDenied(err: unknown): err is AccessDeniedError {
  return err instanceof AccessDeniedError;
}
