/**
 * The catalog: the application's single source of truth for its permission
 * tree, scope types, navigation wiring, grantability, and requestability.
 * Declared explicitly in code — never inferred from call sites, never
 * configured in a dashboard.
 *
 * `defineCatalog` throws on structural invalidity (bad segments, namespace
 * violations, depth without the opt-out) — a broken catalog should fail at
 * boot. Semantic convention violations (the naming floor, style, nav wiring)
 * are reported by `lintCatalog` and enforced at build time by @alfiz-auth/verify.
 */

import type { PermissionKey, PermissionPattern } from "./grammar.js";
import {
  ALFIZ_INTERNAL_NAMESPACE,
  isValidKey,
  isValidSegment,
  namespaceOf,
  patternMatchesKey,
  patternsIntersect,
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
   * declares `scopes`, else grantable at `*` only. Declare explicitly
   * (including `[]` for global-only) to override the inherited default.
   * Granting at an undeclared scope type is a validation error at the
   * write path.
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

export interface GroupInput {
  /** Short human-facing name for pickers; `description` is the longer help text. */
  label?: string;
  description?: string;
  /**
   * Default scope types for every leaf under this group (descendant groups
   * included), overridable per leaf or by a nearer group. Saves declaring
   * an identical `scopes: [...]` on dozens of sibling leaves when a whole
   * tab is scoped to one resource type.
   */
  scopes?: readonly ScopeType[];
  permissions?: Record<string, LeafInput>;
  groups?: Record<string, GroupInput>;
}

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

export interface CatalogInput {
  /**
   * The application's namespace — its key prefix. Required even standalone,
   * where it is locally redundant: catalogs are federation-shaped from the
   * first commit.
   */
  namespace: string;
  /**
   * Additional namespaces this application owns (multi-project portals).
   * Each top-level project must be a declared namespace.
   */
  additionalNamespaces?: readonly string[];
  /** Top-level groups — projects. Blessed shape: project → tab → permission. */
  projects: Record<string, GroupInput>;
  scopeTypes?: Record<string, ScopeTypeInput>;
  navigation?: readonly NavItemInput[];
  /**
   * The blessed convention is exactly three levels. Setting this permits
   * arbitrary depth (2-level integration catalogs like `zoom.host`, deeper
   * nesting) — an explicit opt-out, not a default.
   */
  allowArbitraryDepth?: boolean;
  /**
   * Alfiz's own administration permissions ship under `alfiz_internal.*` so
   * they can never collide with the organization's needs. Included by
   * default; set false for catalogs that render no Alfiz admin surface.
   */
  includeAlfizInternal?: boolean;
}

// ---------------------------------------------------------------------------
// Derived template-literal types — every key and pattern at every call site
// is compile-time verified against the catalog.
// ---------------------------------------------------------------------------

type StringKeys<T> = Extract<keyof T, string>;

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

type GroupPathsUnder<G, Prefix extends string> =
  | Prefix
  | (G extends { groups?: infer S }
      ? S extends Record<string, unknown>
        ? string extends StringKeys<S>
          ? `${Prefix}.${string}` // broad (non-literal) input: stop recursing
          : {
              [K in StringKeys<S>]: GroupPathsUnder<S[K], `${Prefix}.${K}`>;
            }[StringKeys<S>]
        : never
      : never);

type ProjectKeys<C extends CatalogInput> = {
  [P in StringKeys<C["projects"]>]: KeysUnder<C["projects"][P], P>;
}[StringKeys<C["projects"]>];

type ProjectGroupPaths<C extends CatalogInput> = {
  [P in StringKeys<C["projects"]>]: GroupPathsUnder<C["projects"][P], P>;
}[StringKeys<C["projects"]>];

type InternalIncluded<C extends CatalogInput> =
  C["includeAlfizInternal"] extends false ? never : AlfizInternalKey;

type InternalGroupsIncluded<C extends CatalogInput> =
  C["includeAlfizInternal"] extends false ? never : AlfizInternalGroupPath;

/** Every concrete permission key of catalog input `C`. */
export type CatalogKeys<C extends CatalogInput> =
  | ProjectKeys<C>
  | InternalIncluded<C>;

/** Every valid pattern of `C`: keys, group wildcards, and the bare `*`. */
export type CatalogPatterns<C extends CatalogInput> =
  | "*"
  | CatalogKeys<C>
  | `${ProjectGroupPaths<C> | InternalGroupsIncluded<C>}.*`;

/** The key type of a built catalog: `KeyOf<typeof catalog>`. */
export type KeyOf<Cat> = Cat extends Catalog<infer C> ? CatalogKeys<C> : never;
/** The pattern type of a built catalog: `PatternOf<typeof catalog>`. */
export type PatternOf<Cat> = Cat extends Catalog<infer C>
  ? CatalogPatterns<C>
  : never;

// ---------------------------------------------------------------------------
// The built-in alfiz_internal catalog
// ---------------------------------------------------------------------------

/**
 * Alfiz's own administration permissions. Namespaced under `alfiz_internal.*`
 * to prevent collision with the organization's actual needs; follows the same
 * naming floor as everything else.
 */
export const ALFIZ_INTERNAL_PROJECT = {
  description: "Alfiz administration",
  groups: {
    access: {
      description: "Roles, groups, grants, revokes, hierarchy, view-as",
      permissions: {
        read: { description: "View the access administration surface", kind: "read" },
        manage_roles: { description: "Create, edit, delete roles" },
        manage_groups: { description: "Create, edit, delete user groups and their parentage" },
        manage_grants: { description: "Create and delete grants" },
        manage_revokes: { description: "Create and delete personal revokes" },
        manage_reporting: { description: "Edit reporting (manager) edges" },
        view_as: { description: "Preview the product as a role or an individual" },
      },
    },
    requests: {
      description: "Access requests and approvals",
      permissions: {
        read: { description: "View the approvals inbox", kind: "read" },
        decide_request: { description: "Approve or deny an access request" },
      },
    },
    audit: {
      description: "The audit log",
      permissions: {
        read: { description: "Read the audit log", kind: "read" },
      },
    },
    catalog: {
      description: "Catalog administration",
      permissions: {
        read: { description: "View the published catalog", kind: "read" },
        publish_catalog: { description: "Publish a verified catalog to the provider" },
      },
    },
  },
} as const satisfies GroupInput;

export type AlfizInternalKey = KeysUnder<
  typeof ALFIZ_INTERNAL_PROJECT,
  typeof ALFIZ_INTERNAL_NAMESPACE
>;
export type AlfizInternalGroupPath = GroupPathsUnder<
  typeof ALFIZ_INTERNAL_PROJECT,
  typeof ALFIZ_INTERNAL_NAMESPACE
>;

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
  readonly keys: PermissionKey[];
  readonly $key: string;
  readonly $pattern: string;
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

  /** Phantom-only members carrying the derived types. Never set at runtime. */
  declare readonly $key: CatalogKeys<C>;
  declare readonly $pattern: CatalogPatterns<C>;

  constructor(built: {
    namespace: string;
    namespaces: readonly string[];
    leaves: ReadonlyMap<PermissionKey, LeafMeta>;
    groups: ReadonlyMap<string, GroupMeta>;
    scopeTypes: ReadonlyMap<ScopeType, ScopeTypeMeta>;
    navigation: readonly NavItem[];
  }) {
    this.namespace = built.namespace;
    this.namespaces = built.namespaces;
    this.leaves = built.leaves;
    this.groups = built.groups;
    this.scopeTypes = built.scopeTypes;
    this.navigation = built.navigation;
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
      return {
        severity: "error",
        path: scope,
        message: `unknown scope type ${JSON.stringify(type)} — declare it in the catalog's scopeTypes`,
      };
    }
    const matched = this.keysMatching(pattern);
    if (matched.length === 0) {
      return {
        severity: "error",
        path: pattern,
        message: `pattern matches no catalog key`,
      };
    }
    const grantable = matched.some((key) =>
      this.leaves.get(key)!.scopes.includes(type),
    );
    if (!grantable) {
      return {
        severity: "error",
        path: pattern,
        message: `not grantable at scope type ${JSON.stringify(type)} — no matched leaf declares it`,
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

export function defineCatalog<const C extends CatalogInput>(
  input: C,
): Catalog<C> {
  const errors: CatalogIssue[] = [];
  const err = (path: string, message: string) =>
    errors.push({ severity: "error", path, message });

  const namespace = input.namespace;
  if (!isValidSegment(namespace)) {
    err(namespace, "namespace must be a single valid segment");
  }
  if (namespace === ALFIZ_INTERNAL_NAMESPACE) {
    err(namespace, `${ALFIZ_INTERNAL_NAMESPACE} is reserved for Alfiz itself`);
  }
  const declared = new Set<string>([namespace]);
  for (const extra of input.additionalNamespaces ?? []) {
    if (!isValidSegment(extra)) err(extra, "namespace must be a single valid segment");
    if (extra === ALFIZ_INTERNAL_NAMESPACE) {
      err(extra, `${ALFIZ_INTERNAL_NAMESPACE} is reserved for Alfiz itself`);
    }
    declared.add(extra);
  }

  const includeInternal = input.includeAlfizInternal !== false;
  const projects: Record<string, GroupInput> = { ...input.projects };
  if (ALFIZ_INTERNAL_NAMESPACE in projects) {
    err(
      ALFIZ_INTERNAL_NAMESPACE,
      `${ALFIZ_INTERNAL_NAMESPACE} is reserved and added automatically`,
    );
    delete projects[ALFIZ_INTERNAL_NAMESPACE];
  }
  if (includeInternal) {
    projects[ALFIZ_INTERNAL_NAMESPACE] = ALFIZ_INTERNAL_PROJECT;
  }

  const leaves = new Map<PermissionKey, LeafMeta>();
  const groups = new Map<string, GroupMeta>();
  /** Group-declared scope defaults, validated against scopeTypes below. */
  const groupScopeRefs: Array<{ path: string; scopes: readonly ScopeType[] }> = [];

  const walk = (
    path: string,
    group: GroupInput,
    inheritedScopes: readonly ScopeType[],
  ) => {
    // The nearest enclosing `scopes` declaration wins; leaves override last.
    const defaultScopes = group.scopes ?? inheritedScopes;
    if (group.scopes) groupScopeRefs.push({ path, scopes: group.scopes });
    const childGroups: string[] = [];
    const childLeaves: PermissionKey[] = [];
    for (const [name, leafInput] of Object.entries(group.permissions ?? {})) {
      if (!isValidSegment(name)) {
        err(`${path}.${name}`, "invalid permission segment");
        continue;
      }
      const key = `${path}.${name}`;
      const leaf: PermissionLeafInput = leafInput === true ? {} : leafInput;
      const depth = key.split(".").length;
      if (depth !== 3 && input.allowArbitraryDepth !== true) {
        err(
          key,
          `keys are <project>.<tab>.<permission> (3 levels) — this is ${depth}; set allowArbitraryDepth to opt out`,
        );
      }
      if (leaves.has(key)) {
        err(key, "duplicate permission key");
        continue;
      }
      leaves.set(key, {
        key,
        groupPath: path,
        name,
        label: leaf.label,
        description: leaf.description,
        kind: leaf.kind ?? inferKind(name),
        destructive: leaf.destructive ?? inferDestructive(name),
        scopes: leaf.scopes ?? defaultScopes,
        impliedOnAncestors: leaf.impliedOnAncestors ?? false,
      });
      childLeaves.push(key);
    }
    for (const [name, sub] of Object.entries(group.groups ?? {})) {
      if (!isValidSegment(name)) {
        err(`${path}.${name}`, "invalid group segment");
        continue;
      }
      const subPath = `${path}.${name}`;
      childGroups.push(subPath);
      walk(subPath, sub, defaultScopes);
    }
    groups.set(path, {
      path,
      label: group.label,
      description: group.description,
      groups: childGroups,
      permissions: childLeaves,
    });
  };

  for (const [projectName, project] of Object.entries(projects)) {
    if (!isValidSegment(projectName)) {
      err(projectName, "invalid project segment");
      continue;
    }
    if (
      projectName !== ALFIZ_INTERNAL_NAMESPACE &&
      !declared.has(projectName)
    ) {
      err(
        projectName,
        `project is not a declared namespace (namespace/additionalNamespaces) — catalogs must be federation-shaped from the first commit`,
      );
    }
    walk(projectName, project, []);
  }

  // Scope types.
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
  // Leaf scope references (group defaults are already resolved onto leaves).
  for (const leaf of leaves.values()) {
    for (const type of leaf.scopes) {
      if (!scopeTypes.has(type)) {
        err(leaf.key, `references undeclared scope type ${JSON.stringify(type)}`);
      }
    }
  }
  // Group-declared defaults too — a group with no leaves must still not
  // reference a scope type nobody declared.
  for (const ref of groupScopeRefs) {
    for (const type of ref.scopes) {
      if (!scopeTypes.has(type)) {
        err(ref.path, `references undeclared scope type ${JSON.stringify(type)}`);
      }
    }
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
    namespace,
    namespaces: [
      ...declared,
      ...(includeInternal ? [ALFIZ_INTERNAL_NAMESPACE] : []),
    ],
    leaves: sortedLeaves,
    groups: sortedGroups,
    scopeTypes,
    navigation: buildNav(input.navigation ?? []),
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
 * Rebuilds a Catalog from its published wire shape — the read-model side of
 * catalog publishing: registries, tooling, and the static verifier consume
 * documents, not source modules. Derived types are erased to `string`
 * (a document is data, not a literal), hence `AnyCatalog`.
 */
export function catalogFromDocument(document: CatalogDocument): AnyCatalog {
  if (document.formatVersion !== 1) {
    throw new CatalogError([
      {
        severity: "error",
        path: String(document.namespace),
        message: `unknown catalog format ${String(document.formatVersion)}`,
      },
    ]);
  }
  return new Catalog({
    namespace: document.namespace,
    namespaces: [...document.namespaces],
    leaves: new Map(document.leaves.map((l) => [l.key, l])),
    groups: new Map(document.groups.map((g) => [g.path, g])),
    scopeTypes: new Map(document.scopeTypes.map((s) => [s.type, s])),
    navigation: document.navigation,
  });
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
