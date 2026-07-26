/**
 * The headless, wildcard-aware permission tree: the pure selection logic
 * behind every role editor and grant picker. Whole-group selection stores the
 * `<group>.*` pattern — which is what makes forward-inclusion real rather
 * than a snapshot. No rendering here; this is state logic any UI can bind.
 */

import type { AnyCatalog, LeafMeta } from "./catalog.js";
import type { PermissionPattern } from "./grammar.js";
import { patternMatchesKey } from "./grammar.js";

export interface PermTreeNode {
  /** The group path or leaf key. */
  path: string;
  /** Last segment. */
  name: string;
  /** Short human-facing name (catalog `label`), falling back to `name`. */
  label: string;
  kind: "group" | "leaf";
  leaf?: LeafMeta | undefined;
  description?: string | undefined;
  children: PermTreeNode[];
}

/** Builds the display tree from the catalog: projects → groups → leaves. */
export function buildPermissionTree(
  catalog: AnyCatalog,
): PermTreeNode[] {
  const build = (path: string): PermTreeNode => {
    const group = catalog.groups.get(path);
    if (!group) throw new Error(`unknown group ${JSON.stringify(path)}`);
    const children: PermTreeNode[] = [
      ...group.groups.map(build),
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

/** The pattern a node stores when ticked: `<group>.*` for groups, the key for leaves. */
export function nodePattern(node: PermTreeNode): PermissionPattern {
  return node.kind === "group" ? `${node.path}.*` : node.path;
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

/** Fully selected: every leaf under the node matches some selection entry. */
export function isNodeChecked(
  selection: readonly PermissionPattern[],
  node: PermTreeNode,
): boolean {
  const keys = leafKeysUnder(node);
  if (keys.length === 0) return false;
  return keys.every((key) => selection.some((p) => patternMatchesKey(p, key)));
}

/** Partially selected: some but not all leaves under the node are covered. */
export function isNodeIndeterminate(
  selection: readonly PermissionPattern[],
  node: PermTreeNode,
): boolean {
  if (node.kind === "leaf") return false;
  const keys = leafKeysUnder(node);
  const covered = keys.filter((key) =>
    selection.some((p) => patternMatchesKey(p, key)),
  ).length;
  return covered > 0 && covered < keys.length;
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
