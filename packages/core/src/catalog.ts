/**
 * The catalog: the application's single source of truth for its permission
 * tree, scope types, navigation wiring, grantability, and requestability.
 * Declared explicitly in code — never inferred from call sites, never
 * configured in a dashboard.
 *
 * Permissions are declared by their FULL DOTTED KEY, the same notation every
 * check, grant, role, and nav entry uses — so a key at a call site greps
 * straight to its declaration:
 *
 * ```ts
 * defineCatalog({
 *   namespaces: ["lms"],
 *   permissions: {
 *     "lms.courses.read": { kind: "read" },
 *     "lms.courses.delete": { destructive: true },
 *   },
 * });
 * ```
 *
 * Past a handful of keys, `group()` blocks keep the flat map from becoming a
 * wall: each block is a named, foldable unit carrying its own label and scope
 * defaults, and `permissions` accepts an array of them (mixed freely with
 * bare maps). Blocks are absolute keys too, so nothing is lost:
 *
 * ```ts
 * export const courses = group("lms.courses", { label: "Courses", scopes: ["lms.course"] }, {
 *   "lms.courses.read": { kind: "read" },
 *   "lms.courses.delete": { destructive: true },
 * });
 *
 * defineCatalog({ namespaces: ["lms"], permissions: [courses, enrollments] });
 * ```
 *
 * Blocks are OPTIONAL. A small catalog that declares ten keys in one flat map
 * is a complete, idiomatic catalog; groups exist to organize large ones, not
 * as a tax on small ones. Group levels are still folders — every dotted
 * prefix of a declared key is a group, inferred automatically, and only leaves
 * are grantable or checkable.
 *
 * `defineCatalog` throws on structural invalidity (bad segments, namespace
 * violations, a key that is also a group path) — a broken catalog should fail
 * at boot. CONVENTIONS — the blessed key depth, the naming floor, style, nav
 * wiring — are reported by `lintCatalog` and enforced at build time by
 * @alfiz-auth/verify, never thrown at boot.
 */

import { formatAlternatives } from "./errors.js";
import type { PermissionKey, PermissionPattern } from "./grammar.js";
import {
  ALFIZ_INTERNAL_NAMESPACE,
  isValidKey,
  isValidSegment,
  namespaceOf,
  patternMatchesKey,
  patternsIntersect,
  validateKey,
  validatePattern,
} from "./grammar.js";
import type { ScopeId, ScopeType } from "./scopes.js";
import { GLOBAL_SCOPE, scopeTypeOf } from "./scopes.js";
import type { ApprovalPolicyInput, RequestPromptInput } from "./requests.js";

// ---------------------------------------------------------------------------
// Input shapes
// ---------------------------------------------------------------------------

export interface PermissionLeafInput {
  /**
   * Short human-facing name for pickers and checkboxes ("Publish course").
   * `description` is the LONGER help text beside it; keeping both in the
   * catalog is what stops UI copy drifting into side tables.
   */
  label?: string;
  description?: string;
  /**
   * The read-versus-action taxonomy. Inferred from the leaf name when
   * omitted: `read` and `read_*` are reads, everything else is an action.
   */
  kind?: "read" | "action";
  /**
   * Destructive actions stand alone as their own leaf and pair with
   * `can.fresh` at enforcement points. Inferred for `delete`/`delete_*`
   * unless set explicitly.
   */
  destructive?: boolean;
  /**
   * Scope types this permission is grantable at, in addition to the global
   * scope. Omitted = inherited from the nearest enclosing group that
   * declares `scopes` (a `group()` block or a `groups` entry), else
   * grantable at `*` only. Declare explicitly (including `[]` for
   * global-only) to override the inherited default. Granting at an
   * undeclared scope type is a validation error at the write path.
   */
  scopes?: readonly ScopeType[];
  /**
   * Ancestor visibility (§7.5): when true, holding any grant of this leaf at
   * a scope implies it on the ancestors of that scope (the "shared doc shows
   * its containing folder" behavior). Off by default.
   */
  impliedOnAncestors?: boolean;
}

export type LeafInput = true | PermissionLeafInput;

/** A map of full dotted permission keys to their leaf declarations. */
export type LeafMap = Record<string, LeafInput>;

/**
 * Metadata for a group path. Groups themselves are never declared into
 * existence — every dotted prefix of a declared key IS a group. This carries
 * only what a group adds: display copy for pickers, and the scope defaults
 * its leaves inherit.
 */
export interface GroupInput {
  /** Short human-facing name for pickers; falls back to the path segment. */
  label?: string;
  description?: string;
  /**
   * Default scope types for every leaf under this group (descendant groups
   * included), overridable per leaf or by a nearer group. Saves declaring
   * an identical `scopes: [...]` on dozens of sibling leaves when a whole
   * tab is scoped to one resource type.
   */
  scopes?: readonly ScopeType[];
}

/**
 * A named, foldable unit of a catalog: one group's metadata plus the leaves
 * declared under it, keyed by their FULL dotted key. Produced by
 * {@link group}; the unit that makes per-feature catalog files possible
 * (`export const courses = group(...)`), because absolute keys compose by
 * concatenation where nested trees would need a deep merge.
 */
export interface PermissionBlock<
  P extends string = string,
  L extends LeafMap = LeafMap,
> {
  readonly kind: "block";
  readonly path: P;
  readonly group: GroupInput;
  readonly leaves: L;
}

/**
 * Compile-time proof that every key in a block lives under the block's path.
 * A stray key's VALUE slot resolves to a message string, so the error reads
 * as the fix rather than as a structural mismatch.
 */
type KeysUnderPath<P extends string, L> = {
  [K in keyof L]: K extends `${P}.${string}`
    ? L[K]
    : `alfiz: this key must start with "${P}."`;
};

/**
 * Declares a group and the permissions under it. Every key must live strictly
 * under `path` — a compile error otherwise, so the block's prefix cannot
 * silently drift from its contents:
 *
 * ```ts
 * export const courses = group("lms.courses", { label: "Courses", scopes: ["lms.course"] }, {
 *   "lms.courses.read": { kind: "read" },
 *   "lms.courses.publish": true,
 * });
 * ```
 *
 * Keys may be deeper than `path` (`lms.courses.drafts.read`); the
 * intervening groups are inferred like any other.
 */
export function group<const P extends string, const L extends LeafMap>(
  path: P,
  leaves: L & KeysUnderPath<P, L>,
): PermissionBlock<P, L>;
export function group<const P extends string, const L extends LeafMap>(
  path: P,
  meta: GroupInput,
  leaves: L & KeysUnderPath<P, L>,
): PermissionBlock<P, L>;
export function group(
  path: string,
  metaOrLeaves: GroupInput | LeafMap,
  maybeLeaves?: LeafMap,
): PermissionBlock {
  const meta = (maybeLeaves === undefined ? {} : metaOrLeaves) as GroupInput;
  const leaves = (maybeLeaves ?? metaOrLeaves) as LeafMap;
  return { kind: "block", path, group: meta, leaves };
}

/**
 * What `permissions` accepts: one flat map, one block, or an array mixing
 * both. The array form is what per-feature catalog files compose into.
 */
export type PermissionsInput =
  | LeafMap
  | PermissionBlock
  | readonly (LeafMap | PermissionBlock)[];

/** The conventions `lintCatalog` (and so `alfiz-verify`) enforces. */
export interface CatalogConventionsInput {
  /**
   * The blessed key depth. `3` — `<project>.<tab>.<permission>` — is the
   * default because depth that maps to UI structure keeps permission trees
   * comprehensible to the humans administering them. Set a different number
   * for a shallower or deeper house style, or `"any"` to opt out.
   *
   * This is a CONVENTION: a violation is a lint error reported by
   * `lintCatalog` and failed by `alfiz-verify` at build time, never a boot
   * throw. Structural invalidity still throws.
   */
  depth?: number | "any";
}

export interface CatalogConventions {
  depth: number | "any";
}

/** The default blessed key depth: `<project>.<tab>.<permission>`. */
export const DEFAULT_KEY_DEPTH = 3;

export interface ScopeTypeInput {
  description?: string;
  /**
   * The expected parent scope type; `null` for top-level types whose
   * instances parent directly to `*`. This is a COMMITMENT, not a hint: a
   * `parent: null` type's instances have the ancestor chain `[scope, "*"]`
   * by declaration, which is what lets the request-scoped snapshot check
   * them synchronously without consulting the ancestry resolver. A type
   * whose instances nest under other instances of the SAME type (folders in
   * folders) declares itself as its own parent: `{ parent: "docs.folder" }`.
   */
  parent?: ScopeType | null;
  /**
   * Loud opt-out of the single-parent default. With multi-parent enabled an
   * instance's effective access is the UNION of all parents' — some products
   * want this (shortcuts, labels-as-folders), others consider it a leak
   * vector. Off by default.
   */
  multiParent?: boolean;
  /**
   * Nothing is requestable by default. Declaring requestability here makes
   * grants at instances of this scope type requestable, with the given
   * justification prompts and approval policy.
   */
  requestable?: {
    prompts?: readonly RequestPromptInput[];
    /** Maximum grant duration a request may propose (ms). */
    maxDurationMs?: number;
    /** Require the request to propose an expiry (just-in-time only). */
    requireExpiry?: boolean;
    policy: ApprovalPolicyInput;
  };
}

export interface NavItemInput {
  label: string;
  href?: string;
  /**
   * Visibility wiring: a concrete key, an any-of array of keys, or a subtree
   * pattern (evaluated via `canAny` — visibility only; the target page still
   * gates its own read).
   */
  permission: PermissionPattern | readonly PermissionKey[];
  children?: readonly NavItemInput[];
}

/**
 * The legacy nested input shape (`projects` → `groups` → `permissions`),
 * accepted and deprecated as of 0.4.0. See `docs/MIGRATING.md`.
 *
 * @deprecated Declare permissions by their full dotted key instead.
 */
export interface LegacyGroupInput extends GroupInput {
  permissions?: Record<string, LeafInput>;
  groups?: Record<string, LegacyGroupInput>;
}

export interface CatalogInput {
  /**
   * The namespaces this application owns — its key prefixes. The first is the
   * primary. Required even standalone, where it is locally redundant:
   * catalogs are federation-shaped from the first commit.
   */
  namespaces?: readonly string[];
  /**
   * The application's primary namespace.
   *
   * @deprecated Use `namespaces: ["yourapp"]`.
   */
  namespace?: string;
  /**
   * Additional namespaces this application owns (multi-project portals).
   *
   * @deprecated Fold into `namespaces`.
   */
  additionalNamespaces?: readonly string[];
  /**
   * The permissions, keyed by their full dotted key: one flat map, one
   * `group()` block, or an array mixing both. Groups are inferred from the
   * keys — declaring blocks is an organizing convenience, never a
   * requirement.
   */
  permissions?: PermissionsInput;
  /**
   * Metadata for group paths you did not declare a `group()` block for —
   * typically the project level (`{ lms: { label: "Learning" } }`). Purely
   * optional: an undecorated group falls back to its path segment.
   */
  groups?: Record<string, GroupInput>;
  scopeTypes?: Record<string, ScopeTypeInput>;
  navigation?: readonly NavItemInput[];
  /** House conventions enforced by `lintCatalog` / `alfiz-verify`. */
  conventions?: CatalogConventionsInput;
  /**
   * Alfiz's own administration permissions ship under `alfiz_internal.*` so
   * they can never collide with the organization's needs. Included by
   * default; set false for catalogs that render no Alfiz admin surface.
   */
  includeAlfizInternal?: boolean;
  /**
   * Top-level groups — projects — in the legacy nested shape.
   *
   * @deprecated Use `permissions` with full dotted keys.
   */
  projects?: Record<string, LegacyGroupInput>;
  /**
   * @deprecated Use `conventions: { depth: "any" }`. Depth is a convention
   * enforced by the linter, not a boot-time error.
   */
  allowArbitraryDepth?: boolean;
}

// ---------------------------------------------------------------------------
// Derived template-literal types — every key and pattern at every call site
// is compile-time verified against the catalog.
// ---------------------------------------------------------------------------

type StringKeys<T> = Extract<keyof T, string>;

/**
 * Every proper dotted prefix of `S`: the group paths a key implies.
 * `"lms.courses.read"` → `"lms" | "lms.courses"`.
 */
type Prefixes<S extends string> = S extends `${infer Head}.${infer Rest}`
  ? Head | `${Head}.${Prefixes<Rest>}`
  : never;

/** The keys one `permissions` entry contributes (block or bare map). */
type EntryKeys<E> = E extends { readonly kind: "block"; readonly leaves: infer L }
  ? StringKeys<L>
  : StringKeys<E>;

type PermissionsKeys<P> = P extends readonly unknown[]
  ? EntryKeys<P[number]>
  : EntryKeys<P>;

/** Legacy: keys under one nested group. */
type KeysUnder<G, Prefix extends string> =
  | (G extends { permissions?: infer P }
      ? P extends Record<string, unknown>
        ? `${Prefix}.${StringKeys<P>}`
        : never
      : never)
  | (G extends { groups?: infer S }
      ? S extends Record<string, unknown>
        ? string extends StringKeys<S>
          ? `${Prefix}.${string}` // broad (non-literal) input: stop recursing
          : {
              [K in StringKeys<S>]: KeysUnder<S[K], `${Prefix}.${K}`>;
            }[StringKeys<S>]
        : never
      : never);

type LegacyKeys<C extends CatalogInput> = C["projects"] extends infer PR
  ? PR extends Record<string, unknown>
    ? { [P in StringKeys<PR>]: KeysUnder<PR[P], P> }[StringKeys<PR>]
    : never
  : never;

type InternalIncluded<C extends CatalogInput> =
  C["includeAlfizInternal"] extends false ? never : AlfizInternalKey;

/** Every concrete permission key of catalog input `C`. */
export type CatalogKeys<C extends CatalogInput> =
  | PermissionsKeys<C["permissions"]>
  | LegacyKeys<C>
  | InternalIncluded<C>;

/**
 * Every valid pattern of `C`: keys, group wildcards, and the bare `*`.
 * Group paths are the dotted prefixes of the keys — groups are folders that
 * exist because keys live under them, never declared into being.
 */
export type CatalogPatterns<C extends CatalogInput> =
  | "*"
  | CatalogKeys<C>
  | `${Prefixes<CatalogKeys<C>>}.*`;

/** The scope types catalog input `C` declares, as a literal union. */
export type CatalogScopeTypes<C extends CatalogInput> =
  C["scopeTypes"] extends infer S
    ? S extends Record<string, ScopeTypeInput>
      ? StringKeys<S>
      : never
    : never;

/**
 * Every scope-id SHAPE valid for `C`: the global `*`, plus
 * `<declaredScopeType>:${string}` for each declared scope type. The
 * instance half is runtime data, so this is a template union, not a closed
 * one — it exists so scope parameters autocomplete their declared prefixes
 * and so `scopeId("docs.doc", id)` composes without widening.
 */
export type CatalogScopeIds<C extends CatalogInput> =
  | "*"
  | `${CatalogScopeTypes<C>}:${string}`;

/**
 * The derived-type family reads the phantom members, so it works uniformly
 * for catalogs built from a literal (`defineCatalog`) and catalogs typed
 * from a published document (`catalogFromDocument<K, P, S>` / codegen).
 */
/** The key type of a built catalog: `KeyOf<typeof catalog>`. */
export type KeyOf<Cat> = Cat extends { readonly $key: infer K extends string }
  ? K
  : never;
/** The pattern type of a built catalog: `PatternOf<typeof catalog>`. */
export type PatternOf<Cat> = Cat extends {
  readonly $pattern: infer P extends string;
}
  ? P
  : never;
/** The scope-id type of a built catalog: `ScopeOf<typeof catalog>`. */
export type ScopeOf<Cat> = Cat extends {
  readonly $scope: infer S extends string;
}
  ? S
  : never;

// ---------------------------------------------------------------------------
// The built-in alfiz_internal catalog
// ---------------------------------------------------------------------------

/**
 * Alfiz's own administration permissions. Namespaced under `alfiz_internal.*`
 * to prevent collision with the organization's actual needs; follows the same
 * naming floor as everything else.
 */
export const ALFIZ_INTERNAL_BLOCKS = [
  group(
    "alfiz_internal.access",
    { description: "Roles, groups, grants, revokes, hierarchy, view-as" },
    {
      "alfiz_internal.access.read": {
        description: "View the access administration surface",
        kind: "read",
      },
      "alfiz_internal.access.manage_roles": {
        description: "Create, edit, delete roles",
      },
      "alfiz_internal.access.manage_groups": {
        description: "Create, edit, delete user groups and their parentage",
      },
      "alfiz_internal.access.manage_grants": {
        description: "Create and delete grants",
      },
      "alfiz_internal.access.manage_revokes": {
        description: "Create and delete personal revokes",
      },
      "alfiz_internal.access.manage_reporting": {
        description: "Edit reporting (manager) edges",
      },
      "alfiz_internal.access.view_as": {
        description: "Preview the product as a role or an individual",
      },
    },
  ),
  group(
    "alfiz_internal.requests",
    { description: "Access requests and approvals" },
    {
      "alfiz_internal.requests.read": {
        description: "View the approvals inbox",
        kind: "read",
      },
      "alfiz_internal.requests.decide_request": {
        description: "Approve or deny an access request",
      },
    },
  ),
  group(
    "alfiz_internal.audit",
    { description: "The audit log" },
    {
      "alfiz_internal.audit.read": {
        description: "Read the audit log",
        kind: "read",
      },
    },
  ),
  group(
    "alfiz_internal.catalog",
    { description: "Catalog administration" },
    {
      "alfiz_internal.catalog.read": {
        description: "View the published catalog",
        kind: "read",
      },
      "alfiz_internal.catalog.publish_catalog": {
        description: "Publish a verified catalog to the provider",
      },
    },
  ),
] as const;

const ALFIZ_INTERNAL_GROUPS: Record<string, GroupInput> = {
  [ALFIZ_INTERNAL_NAMESPACE]: { description: "Alfiz administration" },
};

export type AlfizInternalKey = EntryKeys<(typeof ALFIZ_INTERNAL_BLOCKS)[number]>;
export type AlfizInternalGroupPath = Prefixes<AlfizInternalKey>;

// ---------------------------------------------------------------------------
// Built catalog
// ---------------------------------------------------------------------------

export interface LeafMeta {
  key: PermissionKey;
  /** The group path containing this leaf (its "tab" in the blessed shape). */
  groupPath: string;
  name: string;
  /** Short human-facing name for pickers; falls back to `name` when absent. */
  label: string | undefined;
  description: string | undefined;
  kind: "read" | "action";
  destructive: boolean;
  /**
   * Scope types this leaf is grantable at, beyond the global scope —
   * RESOLVED: group-level defaults are already applied at build time.
   */
  scopes: readonly ScopeType[];
  impliedOnAncestors: boolean;
}

export interface GroupMeta {
  path: string;
  /** Short human-facing name for pickers; falls back to the path segment. */
  label: string | undefined;
  description: string | undefined;
  /** Immediate child group paths. */
  groups: readonly string[];
  /** Immediate leaf keys. */
  permissions: readonly PermissionKey[];
}

export interface ScopeTypeMeta {
  type: ScopeType;
  description: string | undefined;
  parent: ScopeType | null;
  multiParent: boolean;
  requestable: ScopeTypeInput["requestable"] | undefined;
}

export interface NavItem {
  label: string;
  href: string | undefined;
  permission: PermissionPattern | readonly PermissionKey[];
  children: readonly NavItem[];
}

export interface CatalogIssue {
  severity: "error" | "warning";
  path: string;
  message: string;
}

/** The stable wire shape of a catalog publish (part of the provider contract). */
export interface CatalogDocument {
  formatVersion: 1;
  namespace: string;
  namespaces: readonly string[];
  leaves: readonly LeafMeta[];
  groups: readonly GroupMeta[];
  scopeTypes: readonly ScopeTypeMeta[];
  navigation: readonly NavItem[];
  /**
   * The house conventions the linter enforces. Additive since 0.4.0 —
   * documents written before it read back as the default depth.
   */
  conventions?: CatalogConventions;
}

export class CatalogError extends Error {
  readonly issues: readonly CatalogIssue[];
  constructor(issues: readonly CatalogIssue[]) {
    super(
      `invalid catalog:\n${issues.map((i) => `  - ${i.path}: ${i.message}`).join("\n")}`,
    );
    this.name = "CatalogError";
    this.issues = issues;
  }
}

/**
 * The catalog seen structurally, with the derived unions erased to `string`.
 * Use this wherever "some catalog" is meant — naming `Catalog<CatalogInput>`
 * would force the recursive derived types to instantiate against the open
 * constraint (TS2589).
 */
export interface AnyCatalog {
  readonly namespace: string;
  readonly namespaces: readonly string[];
  readonly leaves: ReadonlyMap<PermissionKey, LeafMeta>;
  readonly groups: ReadonlyMap<string, GroupMeta>;
  readonly scopeTypes: ReadonlyMap<ScopeType, ScopeTypeMeta>;
  readonly navigation: readonly NavItem[];
  readonly conventions: CatalogConventions;
  readonly keys: PermissionKey[];
  readonly $key: string;
  readonly $pattern: string;
  readonly $scope: string;
  hasKey(key: string): boolean;
  hasGroup(path: string): boolean;
  leaf(key: string): LeafMeta | undefined;
  keysMatching(pattern: PermissionPattern): PermissionKey[];
  isKnownPattern(pattern: PermissionPattern): boolean;
  validateGrantableAt(
    pattern: PermissionPattern,
    scope: ScopeId,
  ): CatalogIssue | null;
  appliesAt(key: PermissionKey, grantScope: ScopeId): boolean;
  toDocument(): CatalogDocument;
}

export class Catalog<C extends CatalogInput = CatalogInput> {
  readonly namespace: string;
  /** Every namespace this catalog owns, `alfiz_internal` included when present. */
  readonly namespaces: readonly string[];
  readonly leaves: ReadonlyMap<PermissionKey, LeafMeta>;
  readonly groups: ReadonlyMap<string, GroupMeta>;
  readonly scopeTypes: ReadonlyMap<ScopeType, ScopeTypeMeta>;
  readonly navigation: readonly NavItem[];
  readonly conventions: CatalogConventions;

  /** Phantom-only members carrying the derived types. Never set at runtime. */
  declare readonly $key: CatalogKeys<C>;
  declare readonly $pattern: CatalogPatterns<C>;
  declare readonly $scope: CatalogScopeIds<C>;

  constructor(built: {
    namespace: string;
    namespaces: readonly string[];
    leaves: ReadonlyMap<PermissionKey, LeafMeta>;
    groups: ReadonlyMap<string, GroupMeta>;
    scopeTypes: ReadonlyMap<ScopeType, ScopeTypeMeta>;
    navigation: readonly NavItem[];
    conventions?: CatalogConventions;
  }) {
    this.namespace = built.namespace;
    this.namespaces = built.namespaces;
    this.leaves = built.leaves;
    this.groups = built.groups;
    this.scopeTypes = built.scopeTypes;
    this.navigation = built.navigation;
    this.conventions = built.conventions ?? { depth: DEFAULT_KEY_DEPTH };
  }

  /** All concrete keys, sorted. */
  get keys(): PermissionKey[] {
    return [...this.leaves.keys()];
  }

  hasKey(key: string): boolean {
    return this.leaves.has(key);
  }

  hasGroup(path: string): boolean {
    return this.groups.has(path);
  }

  leaf(key: string): LeafMeta | undefined {
    return this.leaves.get(key);
  }

  /** The concrete catalog keys a pattern matches (forward-inclusion made visible). */
  keysMatching(pattern: PermissionPattern): PermissionKey[] {
    return this.keys.filter((key) => patternMatchesKey(pattern, key));
  }

  /**
   * Is `pattern` meaningful against this catalog — a known key, a group
   * wildcard over a known group, or `*`? Unknown patterns are the classic
   * typo class the static verifier exists to catch.
   */
  isKnownPattern(pattern: PermissionPattern): boolean {
    if (pattern === "*") return true;
    if (pattern.endsWith(".*")) return this.groups.has(pattern.slice(0, -2));
    return this.leaves.has(pattern);
  }

  /**
   * Write-path validation for a grant's scope: granting a permission at a
   * scope type it never declared is a validation error. Wildcard patterns are
   * grantable at a scope type when at least one matched leaf is; the docs
   * state that a wildcard grant at a scope confers every matched key there.
   */
  validateGrantableAt(
    pattern: PermissionPattern,
    scope: ScopeId,
  ): CatalogIssue | null {
    if (scope === GLOBAL_SCOPE) return null;
    const type = scopeTypeOf(scope);
    if (type === null || !this.scopeTypes.has(type)) {
      const declared = [...this.scopeTypes.keys()];
      return {
        severity: "error",
        path: scope,
        message:
          `unknown scope type ${JSON.stringify(type)} — declare it in the catalog's scopeTypes` +
          (declared.length > 0
            ? ` (declared scope types: ${declared.join(", ")})`
            : ` (this catalog declares no scope types yet)`),
      };
    }
    const matched = this.keysMatching(pattern);
    if (matched.length === 0) {
      const near = closestPatterns(this, pattern, "pattern");
      return {
        severity: "error",
        path: pattern,
        message:
          `pattern matches no catalog key` +
          (near.length > 0 ? ` — did you mean ${formatAlternatives(near)}?` : ""),
      };
    }
    const grantable = matched.some((key) =>
      this.leaves.get(key)!.scopes.includes(type),
    );
    if (!grantable) {
      const declaredOnMatched = [
        ...new Set(matched.flatMap((key) => this.leaves.get(key)!.scopes)),
      ];
      return {
        severity: "error",
        path: pattern,
        message:
          `not grantable at scope type ${JSON.stringify(type)} — no matched leaf declares it` +
          (declaredOnMatched.length > 0
            ? ` (matched leaves are grantable at: ${declaredOnMatched.join(", ")}, or globally at "*")`
            : ` (matched leaves declare no scope types, so they are grantable at "*" only — add \`scopes\` on the leaf or an enclosing group)`),
      };
    }
    return null;
  }

  /**
   * The scope-type system at CHECK time: may a grant made at `grantScope`
   * confer `key` there? Global grants confer everything they match; a grant
   * at a scope instance confers only keys grantable at that scope type.
   * This is what keeps a wildcard or role grant at a narrow scope from
   * conferring keys (e.g. a folder-only `delete`) the catalog never made
   * grantable there — `validateGrantableAt` is the write-path half, this is
   * the evaluation half.
   */
  appliesAt(key: PermissionKey, grantScope: ScopeId): boolean {
    if (grantScope === GLOBAL_SCOPE) return true;
    const type = scopeTypeOf(grantScope);
    if (type === null) return false;
    const leaf = this.leaves.get(key);
    if (!leaf) return false;
    return leaf.scopes.includes(type);
  }

  /** The stable, serializable publish shape. */
  toDocument(): CatalogDocument {
    return {
      formatVersion: 1,
      namespace: this.namespace,
      namespaces: [...this.namespaces],
      leaves: [...this.leaves.values()],
      groups: [...this.groups.values()],
      scopeTypes: [...this.scopeTypes.values()],
      navigation: [...this.navigation],
      conventions: { ...this.conventions },
    };
  }
}

// ---------------------------------------------------------------------------
// defineCatalog
// ---------------------------------------------------------------------------

const inferKind = (name: string): "read" | "action" =>
  name === "read" || name.startsWith("read_") ? "read" : "action";

const inferDestructive = (name: string): boolean =>
  name === "delete" ||
  name.startsWith("delete_") ||
  name === "destroy" ||
  name.startsWith("destroy_") ||
  name.startsWith("purge_") ||
  name === "purge";

const isBlock = (value: unknown): value is PermissionBlock =>
  typeof value === "object" &&
  value !== null &&
  (value as { kind?: unknown }).kind === "block";

/** Every proper dotted prefix of a key, outermost first. */
const prefixesOf = (key: string): string[] => {
  const segments = key.split(".");
  const out: string[] = [];
  for (let i = 1; i < segments.length; i++) {
    out.push(segments.slice(0, i).join("."));
  }
  return out;
};

export function defineCatalog<const C extends CatalogInput>(
  input: C,
): Catalog<C> {
  const errors: CatalogIssue[] = [];
  const err = (path: string, message: string) =>
    errors.push({ severity: "error", path, message });

  // --- Namespaces -----------------------------------------------------------
  const namespaceList = [
    ...(input.namespaces ?? []),
    ...(input.namespace !== undefined ? [input.namespace] : []),
    ...(input.additionalNamespaces ?? []),
  ];
  if (namespaceList.length === 0) {
    err(
      "(catalog)",
      'declare at least one namespace: `namespaces: ["yourapp"]` — catalogs are federation-shaped from the first commit',
    );
  }
  const declared = new Set<string>();
  for (const ns of namespaceList) {
    if (!isValidSegment(ns)) {
      err(ns, "namespace must be a single valid segment");
      continue;
    }
    if (ns === ALFIZ_INTERNAL_NAMESPACE) {
      err(ns, `${ALFIZ_INTERNAL_NAMESPACE} is reserved for Alfiz itself`);
      continue;
    }
    declared.add(ns);
  }
  const primaryNamespace = namespaceList[0] ?? "";

  // --- Collect leaves and group metadata ------------------------------------
  const leafInputs = new Map<string, PermissionLeafInput>();
  const groupInputs = new Map<string, GroupInput>();

  const addLeaf = (key: string, value: LeafInput) => {
    if (leafInputs.has(key)) {
      err(key, "duplicate permission key");
      return;
    }
    leafInputs.set(key, value === true ? {} : value);
  };

  const addGroup = (path: string, meta: GroupInput) => {
    const existing = groupInputs.get(path);
    // A block's own metadata wins over a `groups` entry field by field, so a
    // per-feature block and a root-level label can coexist without a merge
    // order to remember.
    groupInputs.set(path, existing ? { ...existing, ...meta } : { ...meta });
  };

  const addLeafMap = (map: LeafMap, blockPath: string | null) => {
    for (const [key, value] of Object.entries(map)) {
      if (blockPath !== null && !key.startsWith(`${blockPath}.`)) {
        err(
          key,
          `is not under the block path ${JSON.stringify(blockPath)} — every key in a group() block starts with its path`,
        );
        continue;
      }
      addLeaf(key, value);
    }
  };

  const entries: Array<LeafMap | PermissionBlock> = Array.isArray(
    input.permissions,
  )
    ? [...(input.permissions as readonly (LeafMap | PermissionBlock)[])]
    : input.permissions !== undefined
      ? [input.permissions as LeafMap | PermissionBlock]
      : [];
  if (input.includeAlfizInternal !== false) {
    entries.push(...ALFIZ_INTERNAL_BLOCKS);
    for (const [path, meta] of Object.entries(ALFIZ_INTERNAL_GROUPS)) {
      addGroup(path, meta);
    }
  }
  for (const [path, meta] of Object.entries(input.groups ?? {})) {
    addGroup(path, meta);
  }
  for (const entry of entries) {
    if (isBlock(entry)) {
      addGroup(entry.path, entry.group);
      addLeafMap(entry.leaves, entry.path);
    } else {
      addLeafMap(entry, null);
    }
  }

  // --- Legacy nested shape --------------------------------------------------
  const walkLegacy = (path: string, node: LegacyGroupInput) => {
    addGroup(path, {
      ...(node.label !== undefined ? { label: node.label } : {}),
      ...(node.description !== undefined ? { description: node.description } : {}),
      ...(node.scopes !== undefined ? { scopes: node.scopes } : {}),
    });
    for (const [name, leafInput] of Object.entries(node.permissions ?? {})) {
      if (!isValidSegment(name)) {
        err(`${path}.${name}`, "invalid permission segment");
        continue;
      }
      addLeaf(`${path}.${name}`, leafInput);
    }
    for (const [name, sub] of Object.entries(node.groups ?? {})) {
      if (!isValidSegment(name)) {
        err(`${path}.${name}`, "invalid group segment");
        continue;
      }
      walkLegacy(`${path}.${name}`, sub);
    }
  };
  for (const [projectName, project] of Object.entries(input.projects ?? {})) {
    if (!isValidSegment(projectName)) {
      err(projectName, "invalid project segment");
      continue;
    }
    if (projectName === ALFIZ_INTERNAL_NAMESPACE) {
      err(
        ALFIZ_INTERNAL_NAMESPACE,
        `${ALFIZ_INTERNAL_NAMESPACE} is reserved and added automatically`,
      );
      continue;
    }
    walkLegacy(projectName, project);
  }

  // --- Structural validation of keys ---------------------------------------
  const groupPaths = new Set<string>(groupInputs.keys());
  for (const key of leafInputs.keys()) {
    const issue = validateKey(key);
    if (issue !== null) {
      err(key, issue.reason);
      continue;
    }
    if (!key.includes(".")) {
      err(
        key,
        "a permission key needs at least two segments — the first is its namespace, and a namespace is a group, never a permission",
      );
      continue;
    }
    const ns = namespaceOf(key);
    if (ns !== null && ns !== ALFIZ_INTERNAL_NAMESPACE && !declared.has(ns)) {
      err(
        key,
        `the first segment ${JSON.stringify(ns)} is not a declared namespace — add it to \`namespaces\`; catalogs must be federation-shaped from the first commit`,
      );
      continue;
    }
    for (const prefix of prefixesOf(key)) groupPaths.add(prefix);
  }
  // Groups are folders, never permissions: a key that another key extends is
  // both, which the nested shape made impossible by construction and flat keys
  // do not.
  for (const key of leafInputs.keys()) {
    if (groupPaths.has(key)) {
      err(
        key,
        "is both a permission and a group path (other keys live under it) — group levels are folders, never permissions; only the leaf is grantable",
      );
    }
  }

  // --- Scope types ----------------------------------------------------------
  const scopeTypes = new Map<ScopeType, ScopeTypeMeta>();
  for (const [type, def] of Object.entries(input.scopeTypes ?? {})) {
    if (!isValidKey(type)) {
      err(type, "scope types are dotted like permissions (e.g. docs.folder)");
      continue;
    }
    const ns = namespaceOf(type);
    if (ns !== null && !declared.has(ns)) {
      err(type, `scope type is outside the declared namespaces`);
    }
    scopeTypes.set(type, {
      type,
      description: def.description,
      parent: def.parent ?? null,
      multiParent: def.multiParent ?? false,
      requestable: def.requestable,
    });
  }
  for (const meta of scopeTypes.values()) {
    if (meta.parent !== null && !scopeTypes.has(meta.parent)) {
      err(
        meta.type,
        `parent scope type ${JSON.stringify(meta.parent)} is not declared`,
      );
    }
  }

  // --- Resolve leaves -------------------------------------------------------
  /** The nearest enclosing group that declares `scopes`; leaves override last. */
  const inheritedScopes = (key: string): readonly ScopeType[] => {
    const prefixes = prefixesOf(key);
    for (let i = prefixes.length - 1; i >= 0; i--) {
      const scopes = groupInputs.get(prefixes[i]!)?.scopes;
      if (scopes !== undefined) return scopes;
    }
    return [];
  };

  const leaves = new Map<PermissionKey, LeafMeta>();
  for (const [key, leaf] of leafInputs) {
    const segments = key.split(".");
    const name = segments.at(-1)!;
    const scopes = leaf.scopes ?? inheritedScopes(key);
    for (const type of scopes) {
      if (!scopeTypes.has(type)) {
        err(key, `references undeclared scope type ${JSON.stringify(type)}`);
      }
    }
    leaves.set(key, {
      key,
      groupPath: segments.slice(0, -1).join("."),
      name,
      label: leaf.label,
      description: leaf.description,
      kind: leaf.kind ?? inferKind(name),
      destructive: leaf.destructive ?? inferDestructive(name),
      scopes,
      impliedOnAncestors: leaf.impliedOnAncestors ?? false,
    });
  }
  // Group-declared defaults too — a group with no leaves must still not
  // reference a scope type nobody declared.
  for (const [path, meta] of groupInputs) {
    for (const type of meta.scopes ?? []) {
      if (!scopeTypes.has(type)) {
        err(path, `references undeclared scope type ${JSON.stringify(type)}`);
      }
    }
  }

  // --- Build groups ---------------------------------------------------------
  // Children keep DECLARATION order — pickers and role editors render a group
  // in the order its author wrote it (`read` before `decide`), so only the
  // top-level maps are sorted.
  const childGroups = new Map<string, string[]>();
  const childLeaves = new Map<string, PermissionKey[]>();
  const pushChild = (
    into: Map<string, string[]>,
    parent: string,
    child: string,
  ) => {
    const existing = into.get(parent);
    if (existing) existing.push(child);
    else into.set(parent, [child]);
  };
  for (const path of groupPaths) {
    if (!path.includes(".")) continue;
    const parent = path.slice(0, path.lastIndexOf("."));
    // A group whose ancestors nobody declared keys under still needs them
    // registered; the Set is iterated live, so seeded parents are visited too.
    groupPaths.add(parent);
    pushChild(childGroups, parent, path);
  }
  for (const key of leafInputs.keys()) {
    pushChild(childLeaves, key.slice(0, key.lastIndexOf(".")), key);
  }

  const groups = new Map<string, GroupMeta>();
  for (const path of groupPaths) {
    const meta = groupInputs.get(path);
    groups.set(path, {
      path,
      label: meta?.label,
      description: meta?.description,
      groups: childGroups.get(path) ?? [],
      permissions: childLeaves.get(path) ?? [],
    });
  }

  // --- Conventions ----------------------------------------------------------
  const depth =
    input.conventions?.depth ??
    (input.allowArbitraryDepth === true ? "any" : DEFAULT_KEY_DEPTH);
  if (depth !== "any" && (!Number.isInteger(depth) || depth < 2)) {
    err(
      "(conventions)",
      `conventions.depth must be an integer of at least 2, or "any" — got ${JSON.stringify(depth)}`,
    );
  }

  // Navigation (structure only; reference validity is a lint concern).
  const buildNav = (items: readonly NavItemInput[]): NavItem[] =>
    items.map((item) => ({
      label: item.label,
      href: item.href,
      permission: item.permission,
      children: buildNav(item.children ?? []),
    }));

  if (errors.length > 0) throw new CatalogError(errors);

  const sortedLeaves = new Map(
    [...leaves.entries()].sort(([a], [b]) => a.localeCompare(b)),
  );
  const sortedGroups = new Map(
    [...groups.entries()].sort(([a], [b]) => a.localeCompare(b)),
  );

  return new Catalog<C>({
    namespace: primaryNamespace,
    namespaces: [
      ...declared,
      ...(input.includeAlfizInternal !== false
        ? [ALFIZ_INTERNAL_NAMESPACE]
        : []),
    ],
    leaves: sortedLeaves,
    groups: sortedGroups,
    scopeTypes,
    navigation: buildNav(input.navigation ?? []),
    conventions: { depth },
  });
}

/**
 * A "did you mean" for unknown patterns. The near-miss every newcomer hits:
 * passing a GROUP path (`"admin"`) where a pattern is required — a valid
 * shape that names nothing, because groups are folders, never keys; the
 * pattern selecting a subtree is `"admin.*"`. Returns the corrected pattern
 * when that is the fix, else `null`. Used by the static verifier and the
 * Application's write-path errors so both report the idiom instead of a
 * bare "not in the catalog".
 */
export function suggestPattern(
  catalog: AnyCatalog,
  pattern: string,
): string | null {
  if (catalog.isKnownPattern(pattern)) return null;
  if (catalog.hasGroup(pattern)) return `${pattern}.*`;
  return null;
}

/**
 * Bounded Levenshtein distance: `null` once the distance provably exceeds
 * `max`, so scanning a large catalog for near-misses stays cheap.
 */
function editDistanceWithin(a: string, b: string, max: number): number | null {
  if (Math.abs(a.length - b.length) > max) return null;
  let prev: number[] = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const curr: number[] = [i];
    let rowMin = i;
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      const value = Math.min(
        prev[j]! + 1,
        curr[j - 1]! + 1,
        prev[j - 1]! + cost,
      );
      curr.push(value);
      if (value < rowMin) rowMin = value;
    }
    if (rowMin > max) return null;
    prev = curr;
  }
  const distance = prev[b.length]!;
  return distance <= max ? distance : null;
}

/**
 * The "did you mean" for typos (where {@link suggestPattern} is the "did
 * you mean" for the group-path idiom): declared keys — and, at pattern
 * sites, group wildcards — near `value` by edit distance, closest first.
 *
 * Also surfaces right-leaf-wrong-group mistakes (`docs.approvals.decide`
 * when the key lives under another project): keys sharing `value`'s final
 * segment are included after the edit-distance matches, but only when few
 * enough to be a real signal — a segment like `read` that ends a key in
 * every tab names nothing.
 */
export function closestPatterns(
  catalog: AnyCatalog,
  value: string,
  expected: "key" | "pattern",
  limit = 3,
): string[] {
  const candidates: string[] =
    expected === "key"
      ? catalog.keys
      : [
          ...catalog.keys,
          ...[...catalog.groups.keys()].map((path) => `${path}.*`),
        ];
  const max = Math.min(4, Math.max(2, Math.floor(value.length / 4)));
  const scored: Array<{ candidate: string; distance: number }> = [];
  for (const candidate of candidates) {
    if (candidate === value) continue;
    const distance = editDistanceWithin(value, candidate, max);
    if (distance !== null) scored.push({ candidate, distance });
  }
  const lastSegment = value.split(".").at(-1);
  if (lastSegment && lastSegment !== "" && !value.includes("*")) {
    const sameLeaf = catalog.keys.filter(
      (key) =>
        key !== value &&
        key.endsWith(`.${lastSegment}`) &&
        !scored.some((s) => s.candidate === key),
    );
    if (sameLeaf.length <= limit) {
      for (const key of sameLeaf) scored.push({ candidate: key, distance: max + 1 });
    }
  }
  scored.sort(
    (x, y) => x.distance - y.distance || x.candidate.localeCompare(y.candidate),
  );
  return scored.slice(0, limit).map((s) => s.candidate);
}

/**
 * Everything an unknown-permission error message can be built from, in one
 * catalog pass: the group-path suggestion, edit-distance near-misses, and
 * the undeclared-namespace hint. Spread into `UnknownPermissionError`
 * options (the client and snapshot do), or compose into a provider write
 * rejection (the Application does).
 */
export function unknownPermissionContext(
  catalog: AnyCatalog,
  value: string,
  expected: "key" | "pattern",
): {
  suggestion: string | null;
  didYouMean: string[];
  hint: string | undefined;
} {
  const suggestion = suggestPattern(catalog, value);
  // A group path has ONE right answer; near-miss noise would bury it.
  if (suggestion !== null) {
    return { suggestion, didYouMean: [], hint: undefined };
  }
  const didYouMean = closestPatterns(catalog, value, expected);
  let hint: string | undefined;
  const ns = namespaceOf(value);
  if (ns !== null && !catalog.namespaces.includes(ns)) {
    hint =
      `the first segment ${JSON.stringify(ns)} is not a namespace of this catalog — ` +
      `declared namespaces: ${catalog.namespaces.join(", ")}`;
  }
  return { suggestion, didYouMean, hint };
}

/**
 * A catalog whose derived unions are supplied explicitly rather than
 * inferred from a literal — the type `catalogFromDocument` returns when a
 * consumer pins the unions (typically to types emitted by
 * `alfiz-verify codegen`). Feeds `createAlfizClient` exactly like a
 * `defineCatalog` catalog does.
 */
export interface TypedCatalog<
  K extends string = string,
  P extends string = string,
  S extends string = string,
> extends AnyCatalog {
  readonly $key: K;
  readonly $pattern: P;
  readonly $scope: S;
}

/**
 * Rebuilds a Catalog from its published wire shape — the read-model side of
 * catalog publishing: registries, tooling, and the static verifier consume
 * documents, not source modules. A document is data, not a literal, so the
 * derived unions default to `string` — but a consumer that knows them (the
 * types `alfiz-verify codegen` emits from this same document) can pin them:
 *
 * ```ts
 * import type { AlfizKey, AlfizPattern, AlfizScopeId } from "./alfiz-catalog.gen.js";
 * const catalog = catalogFromDocument<AlfizKey, AlfizPattern, AlfizScopeId>(doc);
 * const client = createAlfizClient({ catalog, provider }); // fully typed
 * ```
 *
 * This is how autocomplete crosses the wire: federated apps consuming
 * another team's published catalog get the same typed `can` as the team
 * that owns the source module.
 */
export function catalogFromDocument<
  K extends string = string,
  P extends string = string,
  S extends string = string,
>(document: CatalogDocument): TypedCatalog<K, P, S> {
  if (document.formatVersion !== 1) {
    throw new CatalogError([
      {
        severity: "error",
        path: String(document.namespace),
        message: `unknown catalog format ${String(document.formatVersion)}`,
      },
    ]);
  }
  const built: AnyCatalog = new Catalog({
    namespace: document.namespace,
    namespaces: [...document.namespaces],
    leaves: new Map(document.leaves.map((l) => [l.key, l])),
    groups: new Map(document.groups.map((g) => [g.path, g])),
    scopeTypes: new Map(document.scopeTypes.map((s) => [s.type, s])),
    navigation: document.navigation,
    conventions: document.conventions ?? { depth: DEFAULT_KEY_DEPTH },
  });
  return built as TypedCatalog<K, P, S>;
}

// ---------------------------------------------------------------------------
// Catalog lint — the naming floor and wiring conventions, enforced at build
// time by @alfiz-auth/verify rather than at boot.
// ---------------------------------------------------------------------------

const VERB_NOUN_RE = /^[a-z]+(_[a-z0-9]+)+$/;
const STANDALONE_ACTIONS = new Set([
  "delete",
  "create",
  "update",
  "export",
  "import",
  "manage",
  "approve",
  "publish",
  "archive",
  "issue",
  "revoke",
  "view_as",
]);

export function lintCatalog(catalog: AnyCatalog): CatalogIssue[] {
  const issues: CatalogIssue[] = [];
  const push = (severity: "error" | "warning", path: string, message: string) =>
    issues.push({ severity, path, message });

  // The blessed key depth is a CONVENTION, checked here rather than thrown at
  // boot: a two-level integration catalog (`zoom.host`) or a deeper feature
  // tree is a house-style decision, not a structural error.
  const { depth } = catalog.conventions;
  if (depth !== "any") {
    for (const leaf of catalog.leaves.values()) {
      const actual = leaf.key.split(".").length;
      if (actual !== depth) {
        push(
          "error",
          leaf.key,
          `is ${actual} levels deep; this catalog's convention is ${depth} (${
            depth === DEFAULT_KEY_DEPTH
              ? "<project>.<tab>.<permission>"
              : `${depth} dot-separated segments`
          }) — set \`conventions: { depth: ${actual} }\` or \`"any"\` to opt out`,
        );
      }
    }
  }

  for (const group of catalog.groups.values()) {
    // A "tab" is a group that carries permissions directly.
    if (group.permissions.length === 0 && group.groups.length === 0) {
      push("error", group.path, "empty group: declare permissions or remove it");
      continue;
    }
    if (group.permissions.length === 0) continue;
    const leafMetas = group.permissions.map((k) => catalog.leaves.get(k)!);
    const hasRead = leafMetas.some((l) => l.kind === "read");
    if (!hasRead) {
      push(
        "error",
        group.path,
        "below the naming floor: every tab defines at least one read permission (`read` or `read_<thing>`)",
      );
    }
    for (const leaf of leafMetas) {
      if (leaf.kind === "read") {
        if (!/^read(_[a-z0-9_]+)?$/.test(leaf.name)) {
          push(
            "warning",
            leaf.key,
            "read permissions are `read` or `read_<thing>` in snake_case",
          );
        }
        continue;
      }
      if (!VERB_NOUN_RE.test(leaf.name) && !STANDALONE_ACTIONS.has(leaf.name)) {
        push(
          "warning",
          leaf.key,
          "actions are named `<verb>_<noun>` in snake_case (destructive actions may stand alone, e.g. `delete`)",
        );
      }
    }
  }

  // Navigation references must resolve against the catalog.
  const checkNav = (items: readonly NavItem[]) => {
    for (const item of items) {
      const patterns = Array.isArray(item.permission)
        ? item.permission
        : [item.permission as PermissionPattern];
      for (const pattern of patterns) {
        if (validatePattern(pattern) !== null) {
          push("error", item.label, `nav permission ${JSON.stringify(pattern)} is not a valid key or pattern`);
          continue;
        }
        if (!catalog.isKnownPattern(pattern)) {
          push(
            "error",
            item.label,
            `nav permission ${JSON.stringify(pattern)} references nothing in the catalog`,
          );
        } else if (
          pattern.endsWith(".*") &&
          catalog.keysMatching(pattern).length === 0
        ) {
          push(
            "warning",
            item.label,
            `nav pattern ${JSON.stringify(pattern)} currently matches no keys`,
          );
        }
      }
      checkNav(item.children);
    }
  };
  checkNav(catalog.navigation);

  // Requestability needs a resolvable policy.
  for (const st of catalog.scopeTypes.values()) {
    if (st.requestable && st.requestable.policy.stages.length === 0) {
      push(
        "error",
        st.type,
        "requestable without a resolvable policy: declare at least one approval stage",
      );
    }
  }

  // Wildcard reach sanity: patterns in nav that a role editor would store are
  // covered above; nothing else stores patterns inside the catalog itself.
  void patternsIntersect;

  return issues;
}
