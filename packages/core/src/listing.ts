/**
 * Listing (reverse queries): point checks answer "can A read this doc";
 * listing pages need "every doc A can read", and naive per-row checking is an
 * N+1 death. The prescribed pattern: compute the granted scope set (cheap),
 * then push the filter into the application's database — which requires the
 * resource table to support ancestor lookup in SQL via a materialized path
 * or a closure table. These helpers ship both shapes.
 */

import type { ScopeId } from "./scopes.js";
import { GLOBAL_SCOPE, parseScopeId } from "./scopes.js";

export type ListingPlan =
  /** A global grant and no revokes: no filter needed. */
  | { mode: "all" }
  /** No matching grants (or a global revoke): provably nothing — callers must short-circuit, never run an unfiltered query. */
  | { mode: "none" }
  /** A global grant minus revoked subtrees. */
  | { mode: "all_except"; exclude: ScopeId[] }
  /** Rows whose ancestor set intersects `include`, minus `exclude` subtrees. */
  | { mode: "scoped"; include: ScopeId[]; exclude: ScopeId[] };

/**
 * Turns the granted/revoked scope sets (from `grantedScopesFor` /
 * `AlfizClient.grantedScopes`) into an executable listing plan.
 */
export function planListing(input: {
  granted: ReadonlySet<ScopeId>;
  revoked: ReadonlySet<ScopeId>;
}): ListingPlan {
  if (input.revoked.has(GLOBAL_SCOPE)) return { mode: "none" };
  const exclude = [...input.revoked].filter((s) => s !== GLOBAL_SCOPE);
  if (input.granted.has(GLOBAL_SCOPE)) {
    return exclude.length === 0 ? { mode: "all" } : { mode: "all_except", exclude };
  }
  const include = [...input.granted].filter((s) => s !== GLOBAL_SCOPE);
  if (include.length === 0) return { mode: "none" };
  return { mode: "scoped", include, exclude };
}

/** A parameterized SQL fragment — never interpolate scope ids into SQL text. */
export interface SqlFragment {
  sql: string;
  params: unknown[];
}

export interface MatPathOptions {
  /**
   * The materialized-path column: the separator-joined chain of scope tokens
   * from root to the row itself, wrapped in separators — e.g. `/f2/f9/d1/`.
   */
  pathColumn: string;
  separator?: string;
  /**
   * Maps a scope id to the token stored in the path column. Defaults to the
   * instance-id part of the scope id (`docs.folder:9` → `9`); pass identity
   * to store full scope ids.
   */
  scopeToToken?: (scope: ScopeId) => string;
  /** Placeholder style: `?` (default) or `$n` starting at `startParam`. */
  placeholder?: "?" | "$n";
  startParam?: number;
}

const defaultToken = (scope: ScopeId): string =>
  parseScopeId(scope)?.instanceId ?? scope;

const placeholders = (
  count: number,
  style: "?" | "$n",
  start: number,
): string[] =>
  Array.from({ length: count }, (_, i) =>
    style === "?" ? "?" : `$${start + i}`,
  );

/**
 * Materialized-path condition: the row's ancestor set (its own path)
 * intersects `scopes`. One `LIKE` per scope, OR-joined:
 *
 *   (path LIKE ? OR path LIKE ?)   with params ['%/9/%', '%/2/%']
 */
export function matPathCondition(
  scopes: readonly ScopeId[],
  options: MatPathOptions,
): SqlFragment {
  const sep = options.separator ?? "/";
  const token = options.scopeToToken ?? defaultToken;
  if (scopes.length === 0) return { sql: "FALSE", params: [] };
  const marks = placeholders(
    scopes.length,
    options.placeholder ?? "?",
    options.startParam ?? 1,
  );
  const sql = `(${marks
    .map((m) => `${options.pathColumn} LIKE ${m}`)
    .join(" OR ")})`;
  return {
    sql,
    params: scopes.map((s) => `%${sep}${token(s)}${sep}%`),
  };
}

export interface ClosureTableOptions {
  /** The closure table name, carrying one row per (ancestor, descendant) pair including self-pairs. */
  closureTable: string;
  ancestorColumn: string;
  descendantColumn: string;
  /** SQL expression for the listed row's scope token (e.g. `d.id`). */
  rowIdExpr: string;
  scopeToToken?: (scope: ScopeId) => string;
  placeholder?: "?" | "$n";
  startParam?: number;
}

/**
 * Closure-table condition:
 *
 *   EXISTS (SELECT 1 FROM closure c
 *           WHERE c.descendant = d.id AND c.ancestor IN (?, ?))
 */
export function closureTableCondition(
  scopes: readonly ScopeId[],
  options: ClosureTableOptions,
): SqlFragment {
  const token = options.scopeToToken ?? defaultToken;
  if (scopes.length === 0) return { sql: "FALSE", params: [] };
  const marks = placeholders(
    scopes.length,
    options.placeholder ?? "?",
    options.startParam ?? 1,
  );
  const sql = `EXISTS (SELECT 1 FROM ${options.closureTable} WHERE ${options.closureTable}.${options.descendantColumn} = ${options.rowIdExpr} AND ${options.closureTable}.${options.ancestorColumn} IN (${marks.join(", ")}))`;
  return { sql, params: scopes.map(token) };
}

/**
 * A Prisma-shaped `where` filter for the materialized-path shape. Compose it
 * yourself for `all_except` (wrap in `NOT`) — the plan says which.
 */
export function prismaMatPathWhere(
  scopes: readonly ScopeId[],
  options: {
    pathField: string;
    separator?: string;
    scopeToToken?: (scope: ScopeId) => string;
  },
): Record<string, unknown> {
  const sep = options.separator ?? "/";
  const token = options.scopeToToken ?? defaultToken;
  if (scopes.length === 0) return { [options.pathField]: { in: [] } };
  return {
    OR: scopes.map((s) => ({
      [options.pathField]: { contains: `${sep}${token(s)}${sep}` },
    })),
  };
}
