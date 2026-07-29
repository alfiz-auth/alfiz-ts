/**
 * The headless, wildcard-aware permission tree: the pure selection logic
 * behind every role editor and grant picker. Whole-group selection stores the
 * `<group>.*` pattern — which is what makes forward-inclusion real rather
 * than a snapshot. No rendering here; this is state logic any UI can bind.
 */

import type { AnyCatalog, ImportedRegion, LeafMeta } from "./catalog.js";
import type { PermissionPattern } from "./grammar.js";
import { patternMatchesKey, patternsIntersect } from "./grammar.js";

export interface PermTreeNode {
  /** The group path, leaf key, or (for a region) the group path it covers. */
  path: string;
  /** Last segment. */
  name: string;
  /** Short human-facing name (catalog `label`), falling back to `name`. */
  label: string;
  /**
   * A `region` is an imported subtree whose keys this catalog cannot
   * enumerate — it selects as one unit, like a leaf, because there is
   * nothing underneath it to tick. Without this kind it would render as an
   * empty group, and an empty group is never selectable: `isNodeChecked`
   * has no leaves to satisfy, so it would be permanently untickable in
   * every role editor.
   */
  kind: "group" | "leaf" | "region";
  leaf?: LeafMeta | undefined;
  region?: ImportedRegion | undefined;
  description?: string | undefined;
  children: PermTreeNode[];
}

/** Builds the display tree from the catalog: projects → groups → leaves. */
export function buildPermissionTree(
  catalog: AnyCatalog,
): PermTreeNode[] {
  /** Regions rendered under a group path, keyed by that path. */
  const regionsAt = new Map<string, ImportedRegion[]>();
  for (const region of catalog.openRegions.values()) {
    const at = region.pattern.slice(0, -2);
    const parent = at.includes(".") ? at.slice(0, at.lastIndexOf(".")) : at;
    const existing = regionsAt.get(parent);
    if (existing) existing.push(region);
    else regionsAt.set(parent, [region]);
  }

  const build = (path: string): PermTreeNode => {
    const group = catalog.groups.get(path);
    if (!group) throw new Error(`unknown group ${JSON.stringify(path)}`);
    const regionPaths = new Set(
      (regionsAt.get(path) ?? []).map((r) => r.pattern.slice(0, -2)),
    );
    const children: PermTreeNode[] = [
      // A group that IS a region renders as the region, not as an empty
      // folder shadowing it.
      ...group.groups.filter((p) => !regionPaths.has(p)).map(build),
      ...(regionsAt.get(path) ?? []).map((region) => {
        const at = region.pattern.slice(0, -2);
        const name = at.split(".").pop()!;
        return {
          path: at,
          name,
          label: region.label ?? name,
          kind: "region" as const,
          region,
          description: region.description,
          children: [],
        };
      }),
      ...group.permissions.map((key) => {
        const leaf = catalog.leaves.get(key)!;
        return {
          path: key,
          name: leaf.name,
          label: leaf.label ?? leaf.name,
          kind: "leaf" as const,
          leaf,
          description: leaf.description,
          children: [],
        };
      }),
    ];
    const name = path.split(".").pop()!;
    return {
      path,
      name,
      label: group.label ?? name,
      kind: "group",
      description: group.description,
      children,
    };
  };
  const topLevel = [...catalog.groups.keys()].filter((p) => !p.includes("."));
  return topLevel.map(build);
}

/**
 * The pattern a node stores when ticked: `<group>.*` for groups and for
 * regions (a region IS its subtree pattern), the key for leaves.
 */
export function nodePattern(node: PermTreeNode): PermissionPattern {
  return node.kind === "leaf" ? node.path : `${node.path}.*`;
}

/** Does `pattern` cover this node's entire subtree (group) or the leaf itself? */
function patternCoversNode(
  pattern: PermissionPattern,
  node: PermTreeNode,
): boolean {
  if (node.kind === "leaf") return patternMatchesKey(pattern, node.path);
  if (pattern === "*") return true;
  if (!pattern.endsWith(".*")) return false;
  const prefix = pattern.slice(0, -2);
  return node.path === prefix || node.path.startsWith(prefix + ".");
}

/** Is `entry` inside this node's subtree (so toggling the node subsumes it)? */
function entryWithinNode(entry: PermissionPattern, node: PermTreeNode): boolean {
  if (node.kind === "leaf") return entry === node.path;
  const base = entry.endsWith(".*") ? entry.slice(0, -2) : entry;
  return base === node.path || base.startsWith(node.path + ".");
}

const leafKeysUnder = (node: PermTreeNode): string[] =>
  node.kind === "leaf"
    ? [node.path]
    : node.children.flatMap((child) => leafKeysUnder(child));

/** Regions under a node, as their stored patterns. */
const regionPatternsUnder = (node: PermTreeNode): PermissionPattern[] =>
  node.kind === "region"
    ? [nodePattern(node)]
    : node.children.flatMap((child) => regionPatternsUnder(child));

/**
 * Fully selected: every leaf AND every region under the node is covered.
 *
 * Regions are matched by intersection, not by key: they stand for keys this
 * catalog cannot enumerate, so "is it covered" is a question about patterns.
 * Counting them is also what makes an imported subtree tickable at all — a
 * region node has no leaves under it, and a node with nothing to satisfy
 * would otherwise read as permanently unchecked.
 */
export function isNodeChecked(
  selection: readonly PermissionPattern[],
  node: PermTreeNode,
): boolean {
  const keys = leafKeysUnder(node);
  const regions = regionPatternsUnder(node);
  if (keys.length === 0 && regions.length === 0) return false;
  return (
    keys.every((key) => selection.some((p) => patternMatchesKey(p, key))) &&
    regions.every((region) =>
      selection.some((p) => patternsIntersect(p, region)),
    )
  );
}

/** Partially selected: some but not all leaves under the node are covered. */
export function isNodeIndeterminate(
  selection: readonly PermissionPattern[],
  node: PermTreeNode,
): boolean {
  if (node.kind === "leaf" || node.kind === "region") return false;
  const units = [
    ...leafKeysUnder(node).map((key) => ({ value: key, region: false })),
    ...regionPatternsUnder(node).map((p) => ({ value: p, region: true })),
  ];
  const covered = units.filter((unit) =>
    selection.some((p) =>
      unit.region
        ? patternsIntersect(p, unit.value)
        : patternMatchesKey(p, unit.value),
    ),
  ).length;
  return covered > 0 && covered < units.length;
}

/**
 * The pure toggle reducer.
 *
 * Ticking ON: entries inside the node's subtree are subsumed and dropped;
 * the node's own pattern is stored (`<group>.*` for a group — the
 * forward-inclusive selection).
 *
 * Ticking OFF: the node's own entries are dropped. If a broader stored
 * wildcard covers the node, that wildcard is *exploded*: removed, and
 * replaced by the sibling subtrees along the path down to the node — the
 * siblings keep their forward-inclusive `.*` form; only the unticked
 * subtree loses coverage.
 */
export function toggleNode(
  selection: readonly PermissionPattern[],
  node: PermTreeNode,
  tree: readonly PermTreeNode[],
): PermissionPattern[] {
  const currentlyChecked = isNodeChecked(selection, node);
  if (!currentlyChecked) {
    const kept = selection.filter((entry) => !entryWithinNode(entry, node));
    return [...kept, nodePattern(node)];
  }

  let result: PermissionPattern[] = [];
  for (const entry of selection) {
    if (entryWithinNode(entry, node)) continue; // the node's own coverage goes
    if (patternCoversNode(entry, node)) {
      // A broader wildcard covers the node: explode it into siblings.
      result.push(...explodeAround(entry, node, tree));
    } else {
      result.push(entry);
    }
  }
  // Dedupe while preserving order.
  result = result.filter((p, i) => result.indexOf(p) === i);
  return result;
}

/**
 * Replaces a covering wildcard with the sibling patterns along the path from
 * the wildcard's root down to (and excluding) `node`.
 */
function explodeAround(
  cover: PermissionPattern,
  node: PermTreeNode,
  tree: readonly PermTreeNode[],
): PermissionPattern[] {
  const coverBase = cover === "*" ? null : cover.slice(0, -2);
  // The chain of group paths from cover root to the node (exclusive of node).
  const nodeSegments = node.path.split(".");
  const out: PermissionPattern[] = [];

  let siblingsAt: readonly PermTreeNode[] = tree;
  let depth = 0;
  if (coverBase !== null) {
    // Descend to the cover's own children first.
    const coverSegments = coverBase.split(".");
    for (const _segment of coverSegments) {
      const path = coverSegments.slice(0, depth + 1).join(".");
      const found = siblingsAt.find((n) => n.path === path);
      if (!found) return out; // cover references nothing in this tree
      siblingsAt = found.children;
      depth++;
    }
  }
  // Walk from that level down to the node, keeping siblings at each level.
  while (depth < nodeSegments.length) {
    const pathHere = nodeSegments.slice(0, depth + 1).join(".");
    for (const sibling of siblingsAt) {
      if (sibling.path === pathHere) continue;
      out.push(nodePattern(sibling));
    }
    const descend = siblingsAt.find((n) => n.path === pathHere);
    if (!descend) break;
    siblingsAt = descend.children;
    depth++;
  }
  return out;
}
