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
 * @alfiz/verify, never thrown at boot.
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
import type { SodConstraint } from "./sod.js";
import { validateSodConstraints } from "./sod.js";
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
  /**
   * The condition seam: `true` declares that holding this permission is
   * NECESSARY but not SUFFICIENT — every gate must also pass an
   * application-supplied predicate ("approve expenses under $10k", "only
   * while status is Draft"). A gate for this key without a `condition` in
   * its options throws `MissingConditionError` at runtime and fails
   * `alfiz-verify` (`missing-condition`) in CI, which is what keeps the
   * predicate from silently living beside the check where no tool can see
   * it. The predicate itself stays application code — Alfiz never
   * evaluates attributes, it enforces that YOUR evaluation is present.
   * Off by default. Visibility shapes (`canAny`, `holds`) are unaffected:
   * a button may exist because authority exists; the gate still decides.
   */
  requiresCondition?: boolean;
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
    /**
     * The ceiling on what a request may ASK for at this scope type.
     *
     * The rest of this declaration bounds who approves and for how long;
     * without this, nothing bounded *what*. The requester supplies the
     * pattern, so `{ kind: "auto" }` — "my team may self-serve folder
     * access" — would grant a proposed `*` with no human in the loop, and
     * `*` at a scope confers every key grantable there, destructive ones
     * included.
     *
     * Each entry is a pattern a proposal must be covered by. Omitted means
     * "any declared pattern except the unbounded global `*`", which is the
     * floor and is not opt-out-able: a request for everything is never a
     * reviewable ask. Role-shaped requests are bounded by the role and are
     * unaffected.
     */
    patterns?: readonly PermissionPattern[];
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

// ---------------------------------------------------------------------------
// Imports — permissions this application REFERENCES but does not own
// ---------------------------------------------------------------------------

/**
 * An imported permission's local wiring. Everything a leaf declares, except
 * that `scopes` names scope types THIS catalog declares: the owning
 * application publishes the vocabulary, and only the importing application
 * knows which of its own resources the permission applies to — and only it
 * can resolve their ancestry.
 */
export interface ImportedPermissionInput extends PermissionLeafInput {
  scopes?: readonly ScopeType[];
}

/**
 * Imported entries, keyed by their full dotted form. Unlike `permissions`,
 * a key here may be a subtree pattern (`zoom.meetings.*`) — you interface
 * with a slice of someone else's namespace, and enumerating it is their job,
 * not yours.
 */
export type ImportedPermissionsInput = Record<
  string,
  true | ImportedPermissionInput
>;

export interface ImportInput {
  /** Provenance label: `"registry:zoom@^3"`, `"dashboard"`, `"monorepo:apps/billing"`. */
  from?: string;
  /**
   * The foreign published document. Attaching it MATERIALIZES every leaf
   * matching a declared entry into this catalog: wildcards stop being opaque,
   * `keysMatching` / `canAny` / the permission tree behave exactly as they do
   * for owned keys, and a typo becomes a build error again.
   *
   * Strongly recommended, and the reason is concrete: an import with no
   * document cannot enumerate its keys, and several affordances are only as
   * good as what they can enumerate (see {@link AnyCatalog.opaqueRegions}).
   * Fetch it in CI from the registry and commit it, exactly as you already
   * commit `alfiz-catalog.json`.
   */
  document?: CatalogDocument;
  /** Default scope types for every entry; a per-entry `scopes` wins. */
  scopes?: readonly ScopeType[];
  permissions: ImportedPermissionsInput;
  /**
   * Refuse to admit keys this catalog cannot name. A wildcard entry still
   * declares grantable vocabulary (roles, grants, and `canAny` all see it),
   * but `can()` on an unenumerated key under it throws rather than being
   * evaluated — the strict posture for an import with no document.
   */
  strict?: boolean;
}

/**
 * Pins an import's key union to types emitted by `alfiz-verify codegen`,
 * closing what a wildcard entry otherwise leaves open. `defineCatalog` cannot
 * infer keys from a runtime `document` value — a document is data, not a
 * literal — so the union crosses the wire the same way it does for
 * `catalogFromDocument`: through codegen.
 *
 * ```ts
 * // alfiz-verify codegen --catalog zoom.catalog.json --prefix Zoom --out zoom.gen.ts
 * import type { ZoomKey } from "./zoom.gen.js";
 *
 * imports: {
 *   zoom: importedKeys<ZoomKey>({
 *     from: "registry:zoom@^3",
 *     document: zoomDoc,
 *     permissions: { "zoom.meetings.*": true },
 *   }),
 * }
 * ```
 */
export function importedKeys<K extends string>(
  input: ImportInput,
): ImportInput & { readonly $keys: K } {
  return input as ImportInput & { readonly $keys: K };
}

export interface CatalogInput {
  /**
   * The namespaces this application owns — its key prefixes. The first is the
   * primary. Required even standalone, where it is locally redundant:
   * catalogs are federation-shaped from the first commit.
   *
   * Owning a namespace is not the same as being able to check keys in it:
   * permissions from another application go in {@link CatalogInput.imports}.
   */
  namespaces: readonly string[];
  /**
   * Permissions this application REFERENCES but does not own — imported from
   * a hosted dashboard or a federated application (structurally the same
   * thing: a foreign published `CatalogDocument`). Keyed by the foreign
   * namespace, which must not be one this catalog owns.
   *
   * ```ts
   * imports: {
   *   zoom: {
   *     from: "registry:zoom@^3",
   *     document: zoomDoc,
   *     scopes: ["docs.folder"],
   *     permissions: { "zoom.host": true, "zoom.meetings.*": true },
   *   },
   * }
   * ```
   */
  imports?: Record<string, ImportInput>;
  /**
   * The permissions, keyed by their full dotted key: one flat map, one
   * `group()` block, or an array mixing both. Groups are inferred from the
   * keys — declaring blocks is an organizing convenience, never a
   * requirement.
   */
  permissions: PermissionsInput;
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
   * Declarative access constraints, evaluated DETECTIVELY off the hot path.
   * `sod` declares separation-of-duty exclusions — two or more pattern
   * sets no one principal may hold across ("no one holds both Vendor Admin
   * and Payment Approver"). Validated at boot against the declared
   * vocabulary; reported by the Application's `listSodViolations`;
   * optionally enforced at grant time (`sod: { enforce: "reject" }` on the
   * Application). Never consulted by `can()` — evaluation stays union-only.
   */
  constraints?: {
    sod?: readonly SodConstraint[];
  };
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

type InternalIncluded<C extends CatalogInput> =
  C["includeAlfizInternal"] extends false ? never : AlfizInternalKey;

/** The subtree-pattern half of a union of entries, and its complement. */
type WildcardOnly<S extends string> = S extends `${string}.*` ? S : never;
type ConcreteOnly<S extends string> = S extends `${string}.*` ? never : S;
/** `"zoom.meetings.*"` → `"zoom.meetings"`. */
type RegionPrefix<S extends string> = S extends `${infer B}.*` ? B : never;

type ImportEntriesOf<C extends CatalogInput> = C["imports"] extends infer I
  ? I extends Record<string, ImportInput>
    ? I[StringKeys<I>]
    : never
  : never;

/**
 * The entries one import declares — its codegen-pinned key union when
 * `importedKeys<K>()` supplied one, else the literal keys of `permissions`.
 */
type DeclaredImportKeys<E> = E extends { readonly $keys: infer K extends string }
  ? K
  : E extends { readonly permissions: infer P }
    ? StringKeys<P>
    : never;

type ImportPermKeys<C extends CatalogInput> = DeclaredImportKeys<
  ImportEntriesOf<C>
>;

/**
 * Every CLOSED permission-key literal of `C` — owned keys plus concrete
 * imports. This, and never {@link CatalogKeys}, is what feeds `Prefixes`:
 * `Prefixes` recurses on `` `${infer Head}.${infer Rest}` ``, so handing it
 * an open template (`` `zoom.meetings.${string}` ``) recurses into
 * `` `${string}` `` and blows up inference (TS2589). See the note on
 * {@link AnyCatalog}.
 */
type OwnedCatalogKeys<C extends CatalogInput> =
  | PermissionsKeys<C["permissions"]>
  | InternalIncluded<C>;

type ConcreteCatalogKeys<C extends CatalogInput> =
  | OwnedCatalogKeys<C>
  | ConcreteOnly<ImportPermKeys<C>>;

/**
 * The open half: one template member per imported wildcard. An import whose
 * keys this catalog cannot enumerate genuinely has no closed key set, so the
 * type says exactly that — the same shape {@link CatalogScopeIds} uses for
 * the runtime half of a scope id. Pin it closed with `importedKeys<K>()`.
 */
type OpenImportKeys<C extends CatalogInput> =
  `${RegionPrefix<WildcardOnly<ImportPermKeys<C>>>}.${string}`;

/** Every permission key of catalog input `C`, owned and imported. */
export type CatalogKeys<C extends CatalogInput> =
  | ConcreteCatalogKeys<C>
  | OpenImportKeys<C>;

/**
 * Every valid pattern of `C`: keys, group wildcards, imported subtree
 * patterns, and the bare `*`. Group paths are the dotted prefixes of the
 * OWNED keys — groups are folders that exist because keys live under them,
 * never declared into being — while an imported namespace contributes only
 * the patterns the import declared, because a wildcard broader than the
 * import is a widening claim over a namespace this application does not own.
 */
export type CatalogPatterns<C extends CatalogInput> =
  | "*"
  | CatalogKeys<C>
  | `${Prefixes<OwnedCatalogKeys<C>>}.*`
  | WildcardOnly<ImportPermKeys<C>>;

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

/**
 * Every key Alfiz itself ships in the reserved namespace — the complete set
 * of keys allowed to exist there, whatever a catalog declares.
 */
const SHIPPED_INTERNAL_KEYS: ReadonlySet<string> = new Set(
  ALFIZ_INTERNAL_BLOCKS.flatMap((block) => Object.keys(block.leaves)),
);
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
  /** The condition seam — additive since 0.7.0; absent reads as false. */
  requiresCondition?: boolean;
  /**
   * Absent means owned — additive, so documents written before imports
   * existed read back as owned, exactly as `conventions` did in 0.4.0.
   * Imported leaves never appear in `toDocument()`: publishing another
   * application's keys is the namespace shadowing federation forbids.
   */
  origin?: "owned" | "imported";
  /** The `from` label of the import that contributed this leaf. */
  importedFrom?: string | undefined;
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
  /** Absent means owned. See {@link LeafMeta.origin}. */
  origin?: "owned" | "imported";
  importedFrom?: string | undefined;
}

/**
 * A declared imported wildcard whose key set this catalog CANNOT enumerate —
 * an import with no attached `document`. It behaves as vocabulary everywhere
 * a pattern is enough (grants, roles, `canAny`, the permission tree) and as a
 * membership test in `hasKey`, but it can never be expanded into keys.
 *
 * Attaching the foreign document collapses a region into concrete leaves and
 * removes it from {@link AnyCatalog.openRegions} entirely. That collapse is
 * the whole incentive gradient of the feature: enumerated imports get typo
 * safety, exact `keysMatching`, and precise revoke suppression; open ones get
 * a conservative approximation of each.
 */
export interface ImportedRegion {
  /** Always a `.*` form. */
  pattern: PermissionPattern;
  namespace: string;
  from: string | undefined;
  label: string | undefined;
  description: string | undefined;
  /** Resolved: the import's default scopes, overridden per entry. */
  scopes: readonly ScopeType[];
  /** From `ImportInput.strict` — the region declares vocabulary but admits no unenumerated key. */
  strict: boolean;
}

/** What one imported namespace contributes, as published data. */
export interface ImportManifestEntry {
  namespace: string;
  from: string | undefined;
  /** A document was attached, so this namespace is fully enumerable. */
  enumerated: boolean;
  /**
   * The entries exactly as declared — concrete keys and subtree patterns,
   * each with the local scope wiring it was given. This, not `keys`, is the
   * contract: it is what a drift report compares against the namespace
   * owner's published document, what decides whether a pattern is grantable
   * (see `isKnownPattern`), and what makes the manifest a complete
   * reconstruction source for `catalogFromDocument`.
   */
  entries: readonly {
    pattern: PermissionPattern;
    scopes: readonly ScopeType[];
  }[];
  /** Concrete keys this catalog can name — declared outright, or materialized. */
  keys: readonly PermissionKey[];
  /** Declared wildcards that could not be enumerated (empty when `enumerated`). */
  regions: readonly PermissionPattern[];
  /**
   * Whether the source declared this import `strict` — an open region that
   * admits ONLY the keys it enumerates.
   *
   * Carried on the manifest because it was previously not carried anywhere:
   * `strict` lived in the source module, never on the wire, so every
   * reconstruction defaulted to permissive. A federated consumer, and
   * `alfiz-verify` itself, then graded against a *laxer* catalog than the one
   * the publisher wrote — the strictness silently evaporated at exactly the
   * boundary it was declared to survive. Absent reads as `false`, which is
   * how manifests written before this field behave.
   */
  strict?: boolean;
}

/**
 * What an application CONSUMES, as its own wire shape — deliberately not a
 * field on {@link CatalogDocument}. What you announce and what you reference
 * are different contracts: the first is owned vocabulary others may grant
 * against, the second is a dependency others can only warn you about.
 *
 * Published through `AlfizProvider.publishImports`, which is what lets a
 * provider report the drift nobody can see today — "application `docs`
 * imports `zoom.breakout.manage`, tombstoned 30 days ago". The existing drift
 * report sees roles and grants, but never code.
 */
export interface ImportManifest {
  formatVersion: 1;
  /** The importing application's primary namespace. */
  namespace: string;
  imports: readonly ImportManifestEntry[];
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
  /**
   * Declared access constraints. Additive since 0.7.0 — documents written
   * before it read back with none.
   */
  constraints?: { sod: readonly SodConstraint[] };
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
  /**
   * Owned AND imported leaves, in one map. Deliberately not two: a parallel
   * map would need every consumer of `leaves` / `keys` — `checkAny`,
   * `heldKeys`, the snapshot, the session, request auto-stages, the
   * permission tree, `closestPatterns` — taught to union them, and any one
   * missed would fail OPEN on `checkAny` and CLOSED on `heldKeys`. Read
   * `LeafMeta.origin` (or {@link keyOrigin}) where the distinction matters.
   */
  readonly leaves: ReadonlyMap<PermissionKey, LeafMeta>;
  readonly groups: ReadonlyMap<string, GroupMeta>;
  readonly scopeTypes: ReadonlyMap<ScopeType, ScopeTypeMeta>;
  readonly navigation: readonly NavItem[];
  readonly conventions: CatalogConventions;
  /** Declared separation-of-duty constraints (empty when none). */
  readonly sodConstraints: readonly SodConstraint[];
  /** What this catalog imports, keyed by foreign namespace. */
  readonly imports: ReadonlyMap<string, ImportManifestEntry>;
  /** Imported wildcards this catalog cannot enumerate, keyed by pattern. */
  readonly openRegions: ReadonlyMap<PermissionPattern, ImportedRegion>;
  readonly keys: PermissionKey[];
  readonly ownedKeys: PermissionKey[];
  readonly importedKeys: PermissionKey[];
  readonly $key: string;
  readonly $pattern: string;
  readonly $scope: string;
  hasKey(key: string): boolean;
  /** Declared vocabulary, as opposed to merely region-admitted — see the impl. */
  isEnumeratedKey(key: string): boolean;
  hasGroup(path: string): boolean;
  leaf(key: string): LeafMeta | undefined;
  keysMatching(pattern: PermissionPattern): PermissionKey[];
  isKnownPattern(pattern: PermissionPattern): boolean;
  validateGrantableAt(
    pattern: PermissionPattern,
    scope: ScopeId,
  ): CatalogIssue | null;
  appliesAt(key: PermissionKey, grantScope: ScopeId): boolean;
  /** Where a key comes from, or `null` when this catalog does not know it. */
  keyOrigin(key: string): "owned" | "imported" | "region" | null;
  /**
   * The open regions intersecting `pattern` — precisely what
   * {@link keysMatching} provably cannot enumerate. Any affordance that
   * answers a question by expanding a pattern into keys must consult this,
   * or it silently answers "no" for an import it simply cannot see.
   */
  opaqueRegions(pattern: PermissionPattern): readonly ImportedRegion[];
  /**
   * Display data for a key, from a leaf or from the region covering it.
   * `leaf()` stays exact on purpose — synthesizing a `LeafMeta` for a
   * region key would invent `kind` and `destructive` from a string this
   * catalog never saw, and make `leaf()` lie.
   */
  describe(key: string): {
    origin: "owned" | "imported" | "region" | null;
    leaf?: LeafMeta;
    region?: ImportedRegion;
  };
  toDocument(): CatalogDocument;
  toImportManifest(): ImportManifest;
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
  readonly sodConstraints: readonly SodConstraint[];
  readonly imports: ReadonlyMap<string, ImportManifestEntry>;
  readonly openRegions: ReadonlyMap<PermissionPattern, ImportedRegion>;

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
    sodConstraints?: readonly SodConstraint[];
    imports?: ReadonlyMap<string, ImportManifestEntry>;
    openRegions?: ReadonlyMap<PermissionPattern, ImportedRegion>;
  }) {
    this.namespace = built.namespace;
    this.namespaces = built.namespaces;
    this.leaves = built.leaves;
    this.groups = built.groups;
    this.scopeTypes = built.scopeTypes;
    this.navigation = built.navigation;
    this.conventions = built.conventions ?? { depth: DEFAULT_KEY_DEPTH };
    this.sodConstraints = built.sodConstraints ?? [];
    this.imports = built.imports ?? new Map();
    this.openRegions = built.openRegions ?? new Map();
  }

  /** All concrete keys, owned and imported, sorted. */
  get keys(): PermissionKey[] {
    return [...this.leaves.keys()];
  }

  get ownedKeys(): PermissionKey[] {
    return this.keys.filter((k) => this.leaves.get(k)!.origin !== "imported");
  }

  get importedKeys(): PermissionKey[] {
    return this.keys.filter((k) => this.leaves.get(k)!.origin === "imported");
  }

  /**
   * The narrowest open region admitting `key`, or undefined. Strict regions
   * declare vocabulary but admit no unenumerated key, so they are skipped
   * here while still counting everywhere a pattern is enough.
   */
  private admittingRegion(key: string): ImportedRegion | undefined {
    // A key is never a wildcard. Without this, `patternMatchesKey` below
    // would happily match the string "zoom.meetings.*" against the region
    // "zoom.meetings.*", making `hasKey` true for a PATTERN — which would
    // let a gate check a wildcard, the one thing `can` must never do.
    if (key.includes("*")) return undefined;
    let best: ImportedRegion | undefined;
    for (const region of this.openRegions.values()) {
      if (region.strict) continue;
      if (!patternMatchesKey(region.pattern, key)) continue;
      if (best === undefined || region.pattern.length > best.pattern.length) {
        best = region;
      }
    }
    return best;
  }

  hasKey(key: string): boolean {
    return this.leaves.has(key) || this.admittingRegion(key) !== undefined;
  }

  /**
   * Whether this key is ENUMERATED vocabulary — declared as a leaf, whether
   * owned or materialized from an import's attached document — as opposed to
   * merely admitted, sight unseen, by an open non-strict import region.
   *
   * The distinction only matters in one place, and it matters a lot there:
   * the rule that a bare global `*` confers only declared vocabulary. That
   * rule exists so a typo in a foreign namespace does not pass for exactly
   * the broadly-privileged people who review and test the gate. An open
   * region made `hasKey` true for every string under it, so `zoom.host_typo`
   * became "declared" and rode in on every `*` grant — the same failure the
   * rule was written to prevent, one level down. A grant that NAMES the
   * namespace (`zoom.*`, `zoom.meetings.*`) still confers it: that grant was
   * written by someone who knew the region was open.
   */
  isEnumeratedKey(key: string): boolean {
    return this.leaves.has(key);
  }

  hasGroup(path: string): boolean {
    return this.groups.has(path);
  }

  leaf(key: string): LeafMeta | undefined {
    return this.leaves.get(key);
  }

  keyOrigin(key: string): "owned" | "imported" | "region" | null {
    const leaf = this.leaves.get(key);
    if (leaf) return leaf.origin === "imported" ? "imported" : "owned";
    return this.admittingRegion(key) !== undefined ? "region" : null;
  }

  describe(key: string): {
    origin: "owned" | "imported" | "region" | null;
    leaf?: LeafMeta;
    region?: ImportedRegion;
  } {
    const leaf = this.leaves.get(key);
    if (leaf) {
      return {
        origin: leaf.origin === "imported" ? "imported" : "owned",
        leaf,
      };
    }
    const region = this.admittingRegion(key);
    return region ? { origin: "region", region } : { origin: null };
  }

  opaqueRegions(pattern: PermissionPattern): readonly ImportedRegion[] {
    const out: ImportedRegion[] = [];
    for (const region of this.openRegions.values()) {
      if (patternsIntersect(region.pattern, pattern)) out.push(region);
    }
    return out;
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
    const ns = namespaceOf(pattern);
    if (ns !== null && this.imports.has(ns)) {
      return this.isKnownImportPattern(pattern, ns);
    }
    if (pattern.endsWith(".*")) return this.groups.has(pattern.slice(0, -2));
    return this.leaves.has(pattern);
  }

  /**
   * A pattern under an imported namespace is known only when it selects a
   * SUBSET of something the import declared. The generic group-wildcard rule
   * cannot be used here: imported group paths exist (so pickers and the tree
   * can render them), and it would make `zoom.*` known to a catalog that
   * imported only `zoom.meetings.*` — a widening claim over a namespace this
   * application does not own, and one a role editor could then store.
   */
  private isKnownImportPattern(
    pattern: PermissionPattern,
    namespace: string,
  ): boolean {
    if (!pattern.endsWith(".*") && this.leaves.has(pattern)) return true;
    const declared = this.imports.get(namespace);
    if (declared === undefined) return false;
    const selected = pattern.endsWith(".*") ? pattern.slice(0, -2) : pattern;
    return declared.entries.some(
      ({ pattern: entry }) =>
        entry === pattern ||
        (entry.endsWith(".*") && patternMatchesKey(entry, selected)),
    );
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
      // Before calling this a miss: an open region has no keys to match by
      // construction, so grantability comes from the region's own wiring.
      const regions = this.opaqueRegions(pattern);
      if (regions.length > 0) {
        const grantableHere = regions.some((r) => r.scopes.includes(type));
        if (grantableHere) return null;
        const declaredOnRegions = [...new Set(regions.flatMap((r) => r.scopes))];
        return {
          severity: "error",
          path: pattern,
          message:
            `not grantable at scope type ${JSON.stringify(type)} — it is imported from ` +
            `${JSON.stringify(regions[0]!.namespace)}, and an imported permission is grantable ` +
            `only at scope types this catalog wires it to` +
            (declaredOnRegions.length > 0
              ? ` (wired to: ${declaredOnRegions.join(", ")}, or globally at "*")`
              : ` (no scope types wired — set \`scopes\` on \`imports.${regions[0]!.namespace}\` to grant it below the global scope)`),
        };
      }
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
    if (leaf) return leaf.scopes.includes(type);
    const region = this.admittingRegion(key);
    return region ? region.scopes.includes(type) : false;
  }

  /**
   * The stable, serializable publish shape — OWNED vocabulary only.
   * Publishing imported leaves would let an application define keys in a
   * namespace it does not own, which is exactly the shadowing the registry's
   * namespace ownership exists to prevent. What this catalog consumes
   * publishes separately, through {@link toImportManifest}.
   */
  toDocument(): CatalogDocument {
    return {
      formatVersion: 1,
      namespace: this.namespace,
      namespaces: this.namespaces.filter((ns) => !this.imports.has(ns)),
      leaves: [...this.leaves.values()].filter((l) => l.origin !== "imported"),
      groups: [...this.groups.values()].filter((g) => g.origin !== "imported"),
      scopeTypes: [...this.scopeTypes.values()],
      navigation: [...this.navigation],
      conventions: { ...this.conventions },
      ...(this.sodConstraints.length > 0
        ? { constraints: { sod: [...this.sodConstraints] } }
        : {}),
    };
  }

  /** What this application references but does not own. See {@link ImportManifest}. */
  toImportManifest(): ImportManifest {
    return {
      formatVersion: 1,
      namespace: this.namespace,
      imports: [...this.imports.values()].map((entry) => ({
        ...entry,
        entries: entry.entries.map((e) => ({
          pattern: e.pattern,
          scopes: [...e.scopes],
        })),
        keys: [...entry.keys],
        regions: [...entry.regions],
      })),
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
  // Type-required, but defended anyway: catalogs also arrive from JS and
  // from config loaders the compiler never saw.
  const namespaceList = input.namespaces ?? [];
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
    : [input.permissions as LeafMap | PermissionBlock];
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
    if (ns === ALFIZ_INTERNAL_NAMESPACE) {
      // The reserved namespace was exempted from the containment check so
      // Alfiz's OWN shipped keys could pass it — but the exemption applied to
      // every key alike, so an application could mint vocabulary inside the
      // administration namespace. That is not a collision, which is already a
      // hard error; it is a key `alfiz_internal.*` grants and roles sweep up,
      // and with `includeAlfizInternal: false` an application could define
      // `alfiz_internal.access.view_as` outright — the exact key
      // `assertCanViewAs` gates on. README calls this namespace one that "can
      // never collide with yours"; only Alfiz declares in it.
      // Only Alfiz's own keys, and only when Alfiz is the one adding them:
      // under `includeAlfizInternal: false` nothing in this namespace is
      // shipped, so any key here came from the application — including, in
      // the sharpest case, its own `alfiz_internal.access.view_as`, which is
      // the exact key `assertCanViewAs` gates on.
      const shipped =
        input.includeAlfizInternal !== false && SHIPPED_INTERNAL_KEYS.has(key);
      if (!shipped) {
        err(
          key,
          `${ALFIZ_INTERNAL_NAMESPACE} is reserved for Alfiz itself — an application never declares permissions in it`,
        );
        continue;
      }
    } else if (ns !== null && !declared.has(ns)) {
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

  // --- Imports --------------------------------------------------------------
  // Vocabulary this application references but does not own. The owning app
  // publishes the keys; this app supplies the local wiring (which of ITS
  // scope types they are grantable at), because only it can resolve those
  // scopes' ancestry.
  const importedLeaves = new Map<PermissionKey, LeafMeta>();
  const openRegions = new Map<PermissionPattern, ImportedRegion>();
  const importEntries = new Map<string, ImportManifestEntry>();
  const importedNamespaces = new Set<string>();

  /** Validates scope wiring against THIS catalog's declared scope types. */
  const wiredScopes = (
    path: string,
    scopes: readonly ScopeType[],
  ): readonly ScopeType[] => {
    for (const type of scopes) {
      if (!scopeTypes.has(type)) {
        err(
          path,
          `wires imported permissions to undeclared scope type ${JSON.stringify(type)} — ` +
            `an import names scope types THIS catalog declares, never the owning application's`,
        );
      }
    }
    return scopes;
  };

  for (const [ns, spec] of Object.entries(input.imports ?? {})) {
    if (!isValidSegment(ns)) {
      err(ns, "an imported namespace is a single valid segment");
      continue;
    }
    if (ns === ALFIZ_INTERNAL_NAMESPACE) {
      err(
        ns,
        `${ALFIZ_INTERNAL_NAMESPACE} is reserved for Alfiz itself and ships with every catalog — it is never imported`,
      );
      continue;
    }
    if (declared.has(ns)) {
      err(
        ns,
        "is declared in `namespaces` — an application does not import what it owns; declare its keys in `permissions`",
      );
      continue;
    }
    importedNamespaces.add(ns);

    const defaultScopes = wiredScopes(
      `imports.${ns}`,
      spec.scopes ?? [],
    );
    const document = spec.document;
    if (document !== undefined && !document.namespaces.includes(ns)) {
      err(
        `imports.${ns}`,
        `the attached document publishes [${document.namespaces.join(", ")}]; this import declares ${JSON.stringify(ns)}`,
      );
      continue;
    }

    const entries: Array<{
      pattern: PermissionPattern;
      scopes: readonly ScopeType[];
    }> = [];
    const concreteKeys: PermissionKey[] = [];
    const regionPatterns: PermissionPattern[] = [];

    /** One imported leaf, wired locally. Document copy is metadata only. */
    const addImportedLeaf = (
      key: PermissionKey,
      entry: ImportedPermissionInput,
      fromDocument: LeafMeta | undefined,
    ) => {
      const segments = key.split(".");
      const name = segments.at(-1)!;
      importedLeaves.set(key, {
        key,
        groupPath: segments.slice(0, -1).join("."),
        name,
        label: entry.label ?? fromDocument?.label,
        description: entry.description ?? fromDocument?.description,
        kind: entry.kind ?? fromDocument?.kind ?? inferKind(name),
        destructive:
          entry.destructive ?? fromDocument?.destructive ?? inferDestructive(name),
        // Local wiring, never the document's: its scope types name the
        // owning application's resources, which this one cannot resolve.
        scopes: entry.scopes
          ? wiredScopes(key, entry.scopes)
          : defaultScopes,
        impliedOnAncestors: entry.impliedOnAncestors ?? false,
        origin: "imported",
        importedFrom: spec.from,
      });
      concreteKeys.push(key);
    };

    for (const [raw, value] of Object.entries(spec.permissions ?? {})) {
      const entry: ImportedPermissionInput = value === true ? {} : value;
      const issue = validatePattern(raw);
      if (issue !== null) {
        err(`imports.${ns}.${raw}`, issue.reason);
        continue;
      }
      if (raw === "*") {
        err(
          `imports.${ns}`,
          'an import declares specific keys or subtree patterns, never the bare "*" — importing everything from every namespace is not a contract',
        );
        continue;
      }
      if (namespaceOf(raw) !== ns) {
        err(
          `imports.${ns}.${raw}`,
          `is not under the imported namespace ${JSON.stringify(ns)} — an import never declares keys outside the namespace it names`,
        );
        continue;
      }
      const entryScopes = entry.scopes
        ? wiredScopes(raw, entry.scopes)
        : defaultScopes;
      entries.push({ pattern: raw, scopes: entryScopes });

      if (document !== undefined) {
        // Enumerated: materialize every published leaf the entry selects.
        const matched = document.leaves.filter((l) =>
          patternMatchesKey(raw, l.key),
        );
        if (matched.length === 0) {
          err(
            `imports.${ns}.${raw}`,
            `matches nothing in the published ${JSON.stringify(ns)} catalog — removed upstream, or a typo?`,
          );
          continue;
        }
        for (const leaf of matched) addImportedLeaf(leaf.key, entry, leaf);
        continue;
      }

      if (raw.endsWith(".*")) {
        regionPatterns.push(raw);
        openRegions.set(raw, {
          pattern: raw,
          namespace: ns,
          from: spec.from,
          label: entry.label,
          description: entry.description,
          scopes: entryScopes,
          strict: spec.strict === true,
        });
      } else {
        addImportedLeaf(raw, entry, undefined);
      }
    }

    // Group paths under an import exist so pickers and the permission tree
    // can render it; `isKnownPattern` deliberately does NOT read them (a
    // group wildcard broader than the import is not a pattern you may store).
    const registerGroup = (path: string) => {
      if (groupInputs.has(path)) return;
      const fromDoc = document?.groups.find((g) => g.path === path);
      const meta: GroupInput = {};
      if (fromDoc?.label !== undefined) meta.label = fromDoc.label;
      if (fromDoc?.description !== undefined) {
        meta.description = fromDoc.description;
      }
      addGroup(path, meta);
    };
    for (const key of concreteKeys) prefixesOf(key).forEach(registerGroup);
    for (const region of regionPatterns) {
      const path = region.slice(0, -2);
      prefixesOf(path).forEach(registerGroup);
      registerGroup(path);
    }

    importEntries.set(ns, {
      namespace: ns,
      from: spec.from,
      enumerated: document !== undefined,
      entries,
      keys: concreteKeys,
      regions: regionPatterns,
      // Travels with the manifest, so a reconstruction is as strict as the
      // declaration it reconstructs.
      strict: spec.strict === true,
    });
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
      ...(leaf.requiresCondition ? { requiresCondition: true } : {}),
      origin: "owned",
    });
  }
  // Imported concrete keys join the SAME map — see the note on
  // `AnyCatalog.leaves` for why there is no second one. They are already
  // fully resolved (local scope wiring applied), so they only need merging
  // and their group paths registering.
  for (const [key, meta] of importedLeaves) {
    if (leaves.has(key)) {
      err(key, "is declared both as an owned permission and as an import");
      continue;
    }
    leaves.set(key, meta);
  }
  for (const key of importedLeaves.keys()) {
    for (const prefix of prefixesOf(key)) groupPaths.add(prefix);
  }
  for (const pattern of openRegions.keys()) {
    const path = pattern.slice(0, -2);
    groupPaths.add(path);
    for (const prefix of prefixesOf(path)) groupPaths.add(prefix);
  }
  for (const key of importedLeaves.keys()) {
    if (groupPaths.has(key)) {
      err(
        key,
        "is both an imported permission and a group path (other imported entries live under it) — group levels are folders, never permissions",
      );
    }
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
  for (const key of importedLeaves.keys()) {
    pushChild(childLeaves, key.slice(0, key.lastIndexOf(".")), key);
  }

  const groups = new Map<string, GroupMeta>();
  for (const path of groupPaths) {
    const meta = groupInputs.get(path);
    // A group path is imported exactly when its namespace is: imported and
    // owned namespaces are disjoint by construction (an import of a namespace
    // in `namespaces` is rejected above).
    const ns = path.includes(".") ? namespaceOf(path) : path;
    const imported = ns !== null && importedNamespaces.has(ns);
    groups.set(path, {
      path,
      label: meta?.label,
      description: meta?.description,
      groups: childGroups.get(path) ?? [],
      permissions: childLeaves.get(path) ?? [],
      origin: imported ? "imported" : "owned",
      ...(imported
        ? { importedFrom: importEntries.get(ns)?.from }
        : {}),
    });
  }

  // --- Conventions ----------------------------------------------------------
  const depth = input.conventions?.depth ?? DEFAULT_KEY_DEPTH;
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

  const catalog = new Catalog<C>({
    namespace: primaryNamespace,
    // Imported namespaces are listed too: `namespaces` answers "does this
    // catalog speak this prefix at all", which every did-you-mean hint and
    // the verifier's classifier ask. Ownership is the narrower question, and
    // `imports` is what answers it — `toDocument()` filters on exactly that.
    namespaces: [
      ...declared,
      ...(input.includeAlfizInternal !== false
        ? [ALFIZ_INTERNAL_NAMESPACE]
        : []),
      ...importedNamespaces,
    ],
    leaves: sortedLeaves,
    groups: sortedGroups,
    scopeTypes,
    navigation: buildNav(input.navigation ?? []),
    conventions: { depth },
    sodConstraints: input.constraints?.sod ?? [],
    imports: importEntries,
    openRegions,
  });

  // Constraints validate against the BUILT catalog (they need pattern
  // expansion), so their problems surface as one CatalogError with the rest.
  if (catalog.sodConstraints.length > 0) {
    const problems = validateSodConstraints(catalog, catalog.sodConstraints);
    if (problems.length > 0) {
      throw new CatalogError(
        problems.map((message) => ({
          severity: "error" as const,
          path: "(constraints)",
          message,
        })),
      );
    }
  }
  return catalog;
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
  if (!catalog.hasGroup(pattern)) return null;
  // Imported group paths exist so pickers can render them, but a wildcard
  // over one is only storable when the import actually declared it — never
  // suggest a fix that would fail the same check.
  const suggestion = `${pattern}.*`;
  return catalog.isKnownPattern(suggestion) ? suggestion : null;
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
  // `alfiz_internal.*` is reserved vocabulary that ships with every catalog,
  // so it sits in `catalog.keys` for a deployment that never renders an admin
  // surface. Suggesting it to a probe from an application namespace answers a
  // question nobody asked — "does this deployment mount Alfiz's own
  // administration, and what are its privileged keys called" — from a typo in
  // `docs.*`. A typo *inside* the reserved namespace still gets its fix.
  const internalProbe = namespaceOf(value) === ALFIZ_INTERNAL_NAMESPACE;
  const admissible = (candidate: string): boolean =>
    internalProbe || namespaceOf(candidate) !== ALFIZ_INTERNAL_NAMESPACE;
  const catalogKeys = catalog.keys.filter(admissible);
  const candidates: string[] =
    expected === "key"
      ? catalogKeys
      : [
          ...catalogKeys,
          // Every open region's prefix is registered as a group, so this
          // covers imported subtree patterns too — filtered, because a group
          // wildcard broader than an import is not a storable pattern and
          // must never be offered as a fix.
          ...[...catalog.groups.keys()]
            .map((path) => `${path}.*`)
            .filter((p) => admissible(p) && catalog.isKnownPattern(p)),
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
    const sameLeaf = catalogKeys.filter(
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
  namespaceOrigin: "owned" | "imported" | "foreign";
  importedPatterns: readonly string[];
} {
  const ns = namespaceOf(value);
  const importEntry = ns === null ? undefined : catalog.imports.get(ns);
  const namespaceOrigin: "owned" | "imported" | "foreign" =
    importEntry !== undefined
      ? "imported"
      : ns !== null && catalog.namespaces.includes(ns)
        ? "owned"
        : "foreign";
  const importedPatterns = importEntry?.entries.map((e) => e.pattern) ?? [];

  const suggestion = suggestPattern(catalog, value);
  // A group path has ONE right answer; near-miss noise would bury it.
  if (suggestion !== null) {
    return {
      suggestion,
      didYouMean: [],
      hint: undefined,
      namespaceOrigin,
      importedPatterns,
    };
  }
  const didYouMean = closestPatterns(catalog, value, expected);
  let hint: string | undefined;
  if (namespaceOrigin === "imported") {
    // The namespace is known — this is a reach beyond what was imported,
    // which is a different fix from a typo and gets its own sentence.
    hint =
      `${JSON.stringify(ns)} is imported by this catalog, but this ${expected} is outside what it covers ` +
      `(imported: ${importedPatterns.join(", ")}) — add the key or widen the pattern in \`imports.${ns}.permissions\``;
  } else if (namespaceOrigin === "foreign") {
    const imported = [...catalog.imports.keys()];
    hint =
      `the first segment ${JSON.stringify(ns)} is not a namespace of this catalog — ` +
      `declared namespaces: ${catalog.namespaces.join(", ")}` +
      (imported.length > 0
        ? `; this catalog imports ${imported.join(", ")} — add ${JSON.stringify(ns)} to \`imports\` to reference it`
        : `. If this permission belongs to another application, declare it in the catalog's \`imports\``);
  }
  return { suggestion, didYouMean, hint, namespaceOrigin, importedPatterns };
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
export interface CatalogFromDocumentOptions {
  /**
   * What the application CONSUMES, as published by `toImportManifest()`.
   * A `CatalogDocument` carries owned vocabulary only — that is the point of
   * it — so a catalog rebuilt from one alone would treat every imported key
   * as foreign. `alfiz-verify` is the case this exists for: it grades a
   * codebase from documents, and without the manifest it would report every
   * legitimate imported key as an implicit import.
   */
  imports?: ImportManifest | undefined;
  /**
   * The namespace owners' published documents, keyed by namespace. Optional
   * enrichment: the manifest already names every key and pattern, so this
   * only recovers display copy and the read/action taxonomy.
   */
  documents?: Record<string, CatalogDocument> | undefined;
}

/**
 * The structural rules `defineCatalog` enforces on a literal, applied to a
 * document instead.
 *
 * A published document is not trusted input the way a source module is: it
 * arrives from a registry, a federated sibling, or a file fetched in CI, and
 * this is the read path codegen and federation use. Checking only
 * `formatVersion` meant a document could introduce things `defineCatalog`
 * calls errors — and two of them are security-relevant rather than merely
 * malformed:
 *
 * - a leaf whose key contains `*` becomes a "key" a gate can check, which is
 *   the one thing `can` must never do (see `admittingRegion`);
 * - a leaf outside the document's own namespaces becomes declared
 *   vocabulary, and declared vocabulary is exactly what a bare `*` grant
 *   confers — so an injected key rides in on every global grant.
 *
 * Duplicate keys mattered too: last-wins silently, and a second entry with a
 * wider `scopes` list widened where the key could be granted.
 */
function assertDocumentStructure(document: CatalogDocument): void {
  const problems: CatalogIssue[] = [];
  const err = (path: string, message: string): void => {
    problems.push({ severity: "error", path, message });
  };
  const namespaces = new Set(document.namespaces ?? []);
  const seen = new Set<string>();
  const groupPaths = new Set<string>((document.groups ?? []).map((g) => g.path));

  for (const leaf of document.leaves ?? []) {
    const key = leaf?.key;
    if (typeof key !== "string") {
      err(String(key), "every leaf needs a string key");
      continue;
    }
    if (seen.has(key)) {
      err(key, "is declared twice — a duplicate silently replaces the first");
      continue;
    }
    seen.add(key);
    const issue = validateKey(key);
    if (issue !== null) {
      err(key, issue.reason);
      continue;
    }
    if (key.includes("*")) {
      err(key, "a permission key is never a wildcard — a gate checks one concrete key");
      continue;
    }
    const ns = namespaceOf(key);
    if (ns === ALFIZ_INTERNAL_NAMESPACE) continue;
    if (ns !== null && namespaces.size > 0 && !namespaces.has(ns)) {
      err(
        key,
        `the first segment ${JSON.stringify(ns)} is not one of this document's namespaces — a document declares only what its publisher owns`,
      );
    }
  }
  for (const key of seen) {
    if (groupPaths.has(key)) {
      err(key, "is both a permission and a group path — group levels are folders, never permissions");
    }
  }

  // Scope-type parentage must be a forest: a cycle makes ancestor resolution
  // non-terminating for anything that walks it from a document-built catalog.
  const parents = new Map<string, string | null>();
  for (const type of document.scopeTypes ?? []) {
    parents.set(type.type, type.parent ?? null);
  }
  for (const [type] of parents) {
    const seenTypes = new Set<string>([type]);
    let current = parents.get(type) ?? null;
    while (current !== null) {
      if (seenTypes.has(current)) {
        err(type, `scope type parentage is cyclic through ${JSON.stringify(current)}`);
        break;
      }
      seenTypes.add(current);
      current = parents.get(current) ?? null;
    }
  }
  if (problems.length > 0) throw new CatalogError(problems);
}

export function catalogFromDocument<
  K extends string = string,
  P extends string = string,
  S extends string = string,
>(
  document: CatalogDocument,
  options: CatalogFromDocumentOptions = {},
): TypedCatalog<K, P, S> {
  if (document.formatVersion !== 1) {
    throw new CatalogError([
      {
        severity: "error",
        path: String(document.namespace),
        message: `unknown catalog format ${String(document.formatVersion)}`,
      },
    ]);
  }
  assertDocumentStructure(document);
  // A document written before imports existed carries no `origin`; a
  // document is by definition what its publisher OWNS, so absent reads as
  // owned. Normalized here rather than at every read site.
  const leaves = new Map<PermissionKey, LeafMeta>(
    document.leaves.map((l) => [l.key, { ...l, origin: l.origin ?? "owned" }]),
  );
  const groups = new Map<string, GroupMeta>(
    document.groups.map((g) => [g.path, { ...g, origin: g.origin ?? "owned" }]),
  );
  const imports = new Map<string, ImportManifestEntry>();
  const openRegions = new Map<PermissionPattern, ImportedRegion>();
  const namespaces = [...document.namespaces];

  for (const entry of options.imports?.imports ?? []) {
    imports.set(entry.namespace, entry);
    namespaces.push(entry.namespace);
    const foreign = options.documents?.[entry.namespace];
    const groupPaths = new Set<string>();

    for (const key of entry.keys) {
      const segments = key.split(".");
      const name = segments.at(-1)!;
      const published = foreign?.leaves.find((l) => l.key === key);
      const wiring = entry.entries.find((e) => patternMatchesKey(e.pattern, key));
      leaves.set(key, {
        key,
        groupPath: segments.slice(0, -1).join("."),
        name,
        label: published?.label,
        description: published?.description,
        kind: published?.kind ?? inferKind(name),
        destructive: published?.destructive ?? inferDestructive(name),
        scopes: wiring?.scopes ?? [],
        impliedOnAncestors: false,
        origin: "imported",
        importedFrom: entry.from,
      });
      for (const prefix of prefixesOf(key)) groupPaths.add(prefix);
    }

    for (const region of entry.regions) {
      const at = region.slice(0, -2);
      const wiring = entry.entries.find((e) => e.pattern === region);
      openRegions.set(region, {
        pattern: region,
        namespace: entry.namespace,
        from: entry.from,
        label: foreign?.groups.find((g) => g.path === at)?.label,
        description: undefined,
        scopes: wiring?.scopes ?? [],
        // The manifest carries `strict` now, so a reconstruction keeps the
        // posture the publisher declared instead of quietly widening to the
        // permissive default. Absent (a manifest written before the field)
        // still reads as permissive, which is what those manifests meant.
        strict: entry.strict === true,
      });
      groupPaths.add(at);
      for (const prefix of prefixesOf(at)) groupPaths.add(prefix);
    }

    for (const path of groupPaths) {
      const published = foreign?.groups.find((g) => g.path === path);
      groups.set(path, {
        path,
        label: published?.label,
        description: published?.description,
        groups: [...groupPaths].filter(
          (p) => p.startsWith(`${path}.`) && !p.slice(path.length + 1).includes("."),
        ),
        permissions: entry.keys.filter(
          (k) => k.startsWith(`${path}.`) && !k.slice(path.length + 1).includes("."),
        ),
        origin: "imported",
        importedFrom: entry.from,
      });
    }
  }

  const built: AnyCatalog = new Catalog({
    namespace: document.namespace,
    namespaces,
    leaves,
    groups,
    scopeTypes: new Map(document.scopeTypes.map((s) => [s.type, s])),
    navigation: document.navigation,
    conventions: document.conventions ?? { depth: DEFAULT_KEY_DEPTH },
    sodConstraints: document.constraints?.sod ?? [],
    imports,
    openRegions,
  });
  return built as TypedCatalog<K, P, S>;
}

// ---------------------------------------------------------------------------
// Catalog lint — the naming floor and wiring conventions, enforced at build
// time by @alfiz/verify rather than at boot.
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
  // Imported entries are exempt from every convention below. They belong to
  // another application's catalog: its depth, its naming floor, its choice of
  // which tabs carry a read. Linting them would emit errors this codebase
  // cannot fix — the wrong kind of finding for a tool whose value is that its
  // output is always actionable.
  const owned = <T extends { origin?: "owned" | "imported" }>(x: T): boolean =>
    x.origin !== "imported";

  const { depth } = catalog.conventions;
  if (depth !== "any") {
    for (const leaf of catalog.leaves.values()) {
      if (!owned(leaf)) continue;
      // Alfiz's own admin keys are three deep and are not the application's
      // to reshape, so grading them against the application's convention
      // made the README's own endorsed `conventions: { depth: 2 }` catalog
      // fail `alfiz-verify` with twelve unfixable errors. The only ways out
      // were turning off the check or the admin surface — which is how a
      // verification step stops being run at all. `unreferenced-leaf`
      // already exempts them.
      if (namespaceOf(leaf.key) === ALFIZ_INTERNAL_NAMESPACE) continue;
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
    if (!owned(group)) continue;
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
          catalog.keysMatching(pattern).length === 0 &&
          // An open region has no keys to match BY CONSTRUCTION; warning
          // that it "matches no keys" would be reporting the feature.
          catalog.opaqueRegions(pattern).length === 0
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
