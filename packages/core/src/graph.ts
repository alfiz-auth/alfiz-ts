/**
 * Graph integrity for the two inheritance graphs — group parentage and
 * (where enabled) object multi-parentage. Semantics are defined once, here,
 * and enforced by whichever site owns each graph.
 *
 * In a union-only system a cycle can express nothing except "these nodes are
 * equivalent", so DAG enforcement loses no expressive power; equivalence has
 * a dedicated construct, the virtual parent.
 *
 * Edges point in the inheritance direction: child → parent (the child
 * inherits the parent's access).
 */

export class GraphCycleError extends Error {
  readonly path: readonly string[];
  constructor(path: readonly string[]) {
    super(`cycle: ${path.join(" → ")}`);
    this.name = "GraphCycleError";
    this.path = path;
  }
}

type ParentsOf = ReadonlyMap<string, readonly string[]>;

/**
 * Would inserting the edge `child → parent` create a cycle in the graph
 * described by `parentsOf`? Returns the full cycle path (`[A, B, C, A]`)
 * when it would — a bare "cycle detected" is undebuggable — or `null`.
 */
export function findCycleForEdge(
  parentsOf: ParentsOf,
  child: string,
  parent: string,
): string[] | null {
  if (child === parent) return [child, child];
  // A cycle forms iff `child` is reachable from `parent` by walking up.
  const pathTo = new Map<string, string>(); // node -> the node we came from
  const stack = [parent];
  const visited = new Set<string>([parent]);
  while (stack.length > 0) {
    const node = stack.pop()!;
    for (const next of parentsOf.get(node) ?? []) {
      if (next === child) {
        // Reconstruct child → parent → ... → node → child.
        const upward: string[] = [];
        let cursor: string | undefined = node;
        while (cursor !== undefined) {
          upward.push(cursor);
          cursor = pathTo.get(cursor);
        }
        return [child, ...upward.reverse(), child];
      }
      if (!visited.has(next)) {
        visited.add(next);
        pathTo.set(next, node);
        stack.push(next);
      }
    }
  }
  return null;
}

/**
 * Interactive edge insertions hard-reject cycles: throws `GraphCycleError`
 * naming the full path. The caller is responsible for serializing concurrent
 * edge writes per graph (two individually-safe inserts can jointly form a
 * cycle); providers do this with an advisory lock or equivalent.
 */
export function assertEdgeInsertable(
  parentsOf: ParentsOf,
  child: string,
  parent: string,
): void {
  const cycle = findCycleForEdge(parentsOf, child, parent);
  if (cycle) throw new GraphCycleError(cycle);
}

/** Validates an entire graph; returns the first cycle found, or null. */
export function findCycle(parentsOf: ParentsOf): string[] | null {
  const WHITE = 0,
    GRAY = 1,
    BLACK = 2;
  const color = new Map<string, number>();
  const nodes = new Set<string>();
  for (const [child, parents] of parentsOf) {
    nodes.add(child);
    for (const p of parents) nodes.add(p);
  }
  const parentOfInPath = new Map<string, string>();
  for (const start of nodes) {
    if ((color.get(start) ?? WHITE) !== WHITE) continue;
    // Iterative DFS with explicit finish events.
    const stack: Array<{ node: string; enter: boolean }> = [
      { node: start, enter: true },
    ];
    while (stack.length > 0) {
      const frame = stack.pop()!;
      if (!frame.enter) {
        color.set(frame.node, BLACK);
        continue;
      }
      const c = color.get(frame.node) ?? WHITE;
      if (c === BLACK) continue;
      color.set(frame.node, GRAY);
      stack.push({ node: frame.node, enter: false });
      for (const parent of parentsOf.get(frame.node) ?? []) {
        const pc = color.get(parent) ?? WHITE;
        if (pc === GRAY) {
          // Found a back edge frame.node → parent: reconstruct the loop.
          const cycle = [parent];
          let cursor = frame.node;
          while (cursor !== parent) {
            cycle.push(cursor);
            cursor = parentOfInPath.get(cursor)!;
          }
          cycle.push(parent);
          // Reorder so it reads in edge direction: parent ← ... — reverse
          // the collected chain (we walked child-of links).
          return [cycle[0]!, ...cycle.slice(1, -1).reverse(), parent];
        }
        if (pc === WHITE) {
          parentOfInPath.set(parent, frame.node);
          stack.push({ node: parent, enter: true });
        }
      }
    }
  }
  return null;
}

export interface VirtualParentPlan {
  /** Generated id for the virtual parent node. */
  id: string;
  /** The strongly connected members that were collapsed. */
  members: string[];
}

export interface Condensation {
  /** The rewritten, acyclic graph (child → parents), including virtual nodes. */
  parentsOf: Map<string, string[]>;
  /** One virtual parent per collapsed strongly connected component. */
  virtualParents: VirtualParentPlan[];
  /** Human-facing warnings describing what was condensed. */
  warnings: string[];
}

/**
 * Bulk imports from external directories, whose nesting data no provider
 * controls, are auto-condensed rather than rejected: each strongly connected
 * component collapses into a virtual parent — the semantically correct
 * reading of a directory cycle ("these were always effectively one pool").
 *
 * Every member of the SCC becomes a child of the virtual parent; the virtual
 * parent inherits the union of the members' external parents. Access syncs;
 * membership does not (members remain distinct groups).
 */
export function condenseImportedGraph(
  parentsOf: ParentsOf,
  makeVirtualId: (members: readonly string[]) => string = (members) =>
    `virtual:${[...members].sort().join("+")}`,
): Condensation {
  const nodes = new Set<string>();
  for (const [child, parents] of parentsOf) {
    nodes.add(child);
    for (const p of parents) nodes.add(p);
  }

  // Tarjan's SCC, iterative.
  const index = new Map<string, number>();
  const low = new Map<string, number>();
  const onStack = new Set<string>();
  const sccStack: string[] = [];
  const sccOf = new Map<string, number>();
  const sccMembers: string[][] = [];
  let counter = 0;

  for (const root of nodes) {
    if (index.has(root)) continue;
    const work: Array<{ node: string; edgeIdx: number }> = [
      { node: root, edgeIdx: 0 },
    ];
    while (work.length > 0) {
      const frame = work[work.length - 1]!;
      const { node } = frame;
      if (frame.edgeIdx === 0) {
        index.set(node, counter);
        low.set(node, counter);
        counter++;
        sccStack.push(node);
        onStack.add(node);
      }
      const parents = parentsOf.get(node) ?? [];
      let advanced = false;
      while (frame.edgeIdx < parents.length) {
        const next = parents[frame.edgeIdx]!;
        frame.edgeIdx++;
        if (!index.has(next)) {
          work.push({ node: next, edgeIdx: 0 });
          advanced = true;
          break;
        } else if (onStack.has(next)) {
          low.set(node, Math.min(low.get(node)!, index.get(next)!));
        }
      }
      if (advanced) continue;
      if (frame.edgeIdx >= parents.length) {
        if (low.get(node) === index.get(node)) {
          const members: string[] = [];
          let popped: string;
          do {
            popped = sccStack.pop()!;
            onStack.delete(popped);
            sccOf.set(popped, sccMembers.length);
            members.push(popped);
          } while (popped !== node);
          sccMembers.push(members);
        }
        work.pop();
        const parentFrame = work[work.length - 1];
        if (parentFrame) {
          low.set(
            parentFrame.node,
            Math.min(low.get(parentFrame.node)!, low.get(node)!),
          );
        }
      }
    }
  }

  const virtualParents: VirtualParentPlan[] = [];
  const warnings: string[] = [];
  const rewritten = new Map<string, string[]>();
  const virtualIdOfScc = new Map<number, string>();

  const isCyclic = (sccIdx: number): boolean => {
    const members = sccMembers[sccIdx]!;
    if (members.length > 1) return true;
    const only = members[0]!;
    return (parentsOf.get(only) ?? []).includes(only); // self-loop
  };

  for (let i = 0; i < sccMembers.length; i++) {
    if (!isCyclic(i)) continue;
    const members = [...sccMembers[i]!].sort();
    const id = makeVirtualId(members);
    virtualIdOfScc.set(i, id);
    virtualParents.push({ id, members });
    warnings.push(
      `directory cycle condensed: ${members.join(" ↔ ")} collapsed under virtual parent ${JSON.stringify(id)} (these were effectively one pool)`,
    );
  }

  for (const node of nodes) {
    const sccIdx = sccOf.get(node)!;
    const virtualId = virtualIdOfScc.get(sccIdx);
    const externalParents: string[] = [];
    for (const parent of parentsOf.get(node) ?? []) {
      const parentScc = sccOf.get(parent)!;
      if (parentScc === sccIdx) continue; // intra-SCC edge disappears
      const parentVirtual = virtualIdOfScc.get(parentScc);
      const target = parentVirtual ?? parent;
      if (!externalParents.includes(target)) externalParents.push(target);
    }
    if (virtualId !== undefined) {
      // Member of a collapsed SCC: it now inherits only from the virtual
      // parent, which in turn carries the SCC's external parents.
      rewritten.set(node, [virtualId]);
      const existing = rewritten.get(virtualId) ?? [];
      for (const p of externalParents) {
        if (!existing.includes(p)) existing.push(p);
      }
      rewritten.set(virtualId, existing);
    } else if (externalParents.length > 0 || parentsOf.has(node)) {
      rewritten.set(node, externalParents);
    }
  }

  return { parentsOf: rewritten, virtualParents, warnings };
}
