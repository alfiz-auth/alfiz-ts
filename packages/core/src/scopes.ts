/**
 * Scopes: scope types (static schema facts, declared in the catalog) versus
 * scope instances (opaque identifiers plus a parent pointer held as
 * application data).
 *
 * A scope instance id is `<scopeType>:<instanceId>` — e.g. `docs.doc:123` —
 * or the global scope `*`. The hierarchy path is never encoded in the id:
 * moving a resource is a data update to its parent pointer, and every grant
 * on it follows automatically.
 */

import type { GrammarIssue } from "./grammar.js";
import { isValidKey } from "./grammar.js";

/** A scope instance id: `*` or `<scopeType>:<instanceId>`. */
export type ScopeId = string;

/** A scope type key, dotted like a permission group: `docs.folder`. */
export type ScopeType = string;

/**
 * The shape of a scope instance id for a known scope type: the catalog's
 * derived scope union (`ScopeOf<typeof catalog>`) is built from these.
 * `scopeId("docs.doc", row.id)` returns the narrowed form, so ids built
 * through the helper flow into scope-hinted parameters without widening.
 */
export type ScopeInstanceId<T extends ScopeType = ScopeType> = `${T}:${string}`;

/**
 * A catalog-typed scope id that still admits runtime strings — the scope
 * counterpart of `LooseKey`. Scope instance ids are runtime data by nature
 * (`docs.doc:${row.id}`), so scope parameters HINT rather than gate:
 * literal call sites autocomplete `*` and every declared
 * `<scopeType>:` prefix, while ids from variables and databases flow
 * through unchanged. Keys stay strictly typed; scopes stay honest about
 * where their halves come from.
 */
export type LooseScopeId<S extends string = ScopeId> = S | (string & {});

/** The global scope. A grant with no scope is a grant at `*`. */
export const GLOBAL_SCOPE: ScopeId = "*";

export function isGlobalScope(scope: ScopeId): boolean {
  return scope === GLOBAL_SCOPE;
}

/** Builds a scope instance id from its type and opaque instance id. */
export function scopeId<T extends ScopeType>(
  type: T,
  instanceId: string,
): ScopeInstanceId<T> {
  return `${type}:${instanceId}`;
}

export interface ParsedScope {
  type: ScopeType;
  instanceId: string;
}

/** Splits `docs.doc:123` into `{ type: "docs.doc", instanceId: "123" }`. */
export function parseScopeId(scope: ScopeId): ParsedScope | null {
  if (scope === GLOBAL_SCOPE) return null;
  const idx = scope.indexOf(":");
  if (idx <= 0 || idx === scope.length - 1) return null;
  return { type: scope.slice(0, idx), instanceId: scope.slice(idx + 1) };
}

/** The scope type of an instance id, or `null` for the global scope. */
export function scopeTypeOf(scope: ScopeId): ScopeType | null {
  return parseScopeId(scope)?.type ?? null;
}

export function validateScopeId(scope: ScopeId): GrammarIssue | null {
  if (scope === GLOBAL_SCOPE) return null;
  const parsed = parseScopeId(scope);
  if (!parsed) {
    return {
      value: scope,
      reason: "scope ids are `*` or `<scopeType>:<instanceId>`",
    };
  }
  if (!isValidKey(parsed.type)) {
    return {
      value: scope,
      reason: `invalid scope type ${JSON.stringify(parsed.type)}`,
    };
  }
  return null;
}

/**
 * The application-supplied ancestry resolver — the reason runtime checks can
 * only run where the application's own tables are visible.
 *
 * Must return the ancestor chain of `scope`, ordered nearest-first, ending at
 * the global scope `*`. The chain excludes `scope` itself. For multi-parent
 * scope types the result is the deduplicated union of all parents' chains.
 */
export type AncestryResolver = (
  scope: ScopeId,
) => ScopeId[] | Promise<ScopeId[]>;

/**
 * The object closure of a scope: itself, all ancestors, and `*` — the set a
 * grant's scope must intersect to cover a check at `scope`.
 *
 * Normalizes resolver output: dedupes, guarantees `scope` first and `*` last.
 * The global scope's closure is just `["*"]`.
 */
export async function objectClosureOf(
  scope: ScopeId,
  resolve: AncestryResolver,
): Promise<ScopeId[]> {
  if (scope === GLOBAL_SCOPE) return [GLOBAL_SCOPE];
  const ancestors = await resolve(scope);
  const closure: ScopeId[] = [scope];
  const seen = new Set<ScopeId>([scope, GLOBAL_SCOPE]);
  for (const ancestor of ancestors) {
    if (!seen.has(ancestor)) {
      seen.add(ancestor);
      closure.push(ancestor);
    }
  }
  closure.push(GLOBAL_SCOPE);
  return closure;
}

/**
 * Builds an ancestry resolver from a synchronous parent-pointer lookup —
 * the simplest conforming implementation, useful for tests, in-memory
 * providers, and single-parent hierarchies. Multi-parent lookups may return
 * an array of parents; the union of chains is returned breadth-first
 * (nearest-first), deduplicated, ending at `*`.
 *
 * Object graphs must be DAGs (the owning site enforces this at the write
 * path — see graph.ts). Defensively, a cycle that reaches this resolver
 * anyway terminates via the seen-set rather than hanging; only pathological
 * depth (>10 000 levels) throws.
 */
export function parentPointerResolver(
  parentOf: (scope: ScopeId) => ScopeId | ScopeId[] | null | undefined,
): (scope: ScopeId) => ScopeId[] {
  return (scope: ScopeId): ScopeId[] => {
    const out: ScopeId[] = [];
    const seen = new Set<ScopeId>([scope]);
    let frontier: ScopeId[] = [scope];
    let hops = 0;
    while (frontier.length > 0) {
      if (++hops > 10_000) {
        throw new Error(
          `ancestry of ${JSON.stringify(scope)} exceeds 10000 levels — parent cycle?`,
        );
      }
      const next: ScopeId[] = [];
      for (const node of frontier) {
        const parents = parentOf(node);
        const list =
          parents == null ? [] : Array.isArray(parents) ? parents : [parents];
        for (const parent of list) {
          if (parent === GLOBAL_SCOPE) continue;
          if (seen.has(parent)) continue;
          seen.add(parent);
          out.push(parent);
          next.push(parent);
        }
      }
      frontier = next;
    }
    out.push(GLOBAL_SCOPE);
    return out;
  };
}
