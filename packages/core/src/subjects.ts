/**
 * Subjects: anything that can hold a grant — users, user groups (explicit or
 * implicit), organizations, service principals, and the built-in subject
 * `everyone`.
 *
 * Subject ids are typed string encodings so they can live in grant rows,
 * indexes, and wire formats without a parallel object model:
 *
 *   user:<id>       an individual (identity-provider user id)
 *   group:<id>      an explicit user group
 *   org:<id>        an organization (identity-provider org id)
 *   service:<id>    a service principal (machine subject)
 *   directs:<uid>   implicit group — <uid>'s direct reports
 *   orgof:<uid>     implicit group — <uid>'s transitive reports ("their org")
 *   everyone        the public subject
 */

export type SubjectId = string;

export const EVERYONE: SubjectId = "everyone";

export type SubjectKind =
  | "user"
  | "group"
  | "org"
  | "service"
  | "directs"
  | "orgof"
  | "everyone";

export interface ParsedSubject {
  kind: SubjectKind;
  id: string;
}

const PREFIXED: ReadonlySet<string> = new Set([
  "user",
  "group",
  "org",
  "service",
  "directs",
  "orgof",
]);

export function userSubject(userId: string): SubjectId {
  return `user:${userId}`;
}
export function groupSubject(groupId: string): SubjectId {
  return `group:${groupId}`;
}
export function orgSubject(orgId: string): SubjectId {
  return `org:${orgId}`;
}
export function serviceSubject(serviceId: string): SubjectId {
  return `service:${serviceId}`;
}
/** Implicit group: the direct reports of `managerUserId`. */
export function directsSubject(managerUserId: string): SubjectId {
  return `directs:${managerUserId}`;
}
/** Implicit group: everyone transitively reporting to `managerUserId`. */
export function orgOfSubject(managerUserId: string): SubjectId {
  return `orgof:${managerUserId}`;
}

export function parseSubject(subject: SubjectId): ParsedSubject | null {
  if (subject === EVERYONE) return { kind: "everyone", id: "" };
  const idx = subject.indexOf(":");
  if (idx <= 0 || idx === subject.length - 1) return null;
  const kind = subject.slice(0, idx);
  if (!PREFIXED.has(kind)) return null;
  return { kind: kind as SubjectKind, id: subject.slice(idx + 1) };
}

export function isValidSubject(subject: SubjectId): boolean {
  return parseSubject(subject) !== null;
}

/** True for the implicit-group encodings, whose membership follows the reporting edges. */
export function isImplicitGroupSubject(subject: SubjectId): boolean {
  const parsed = parseSubject(subject);
  return parsed?.kind === "directs" || parsed?.kind === "orgof";
}

/**
 * The organizational data a subject closure is computed from. All fields are
 * plain data the provider supplies; the computation is a pure function.
 */
export interface SubjectClosureInput {
  userId: string;
  /** Explicit group memberships (group ids), as stored on the user record. */
  groupIds: readonly string[];
  /**
   * Group parentage: child group id → parent group ids. Groups inherit the
   * union of their ancestors' access, so every ancestor joins the closure.
   * Must be acyclic (enforced at the write path, graph/dag).
   */
  groupParents?: ReadonlyMap<string, readonly string[]> | undefined;
  /** Organization memberships (identity-provider org ids). */
  orgIds?: readonly string[] | undefined;
  /**
   * The user's management chain, nearest manager first, derived from
   * reporting edges. Yields `directs:<manager>` for the direct manager and
   * `orgof:<m>` for every manager in the chain.
   */
  managerChain?: readonly string[] | undefined;
}

/**
 * The subject closure of a user: the user themself, every group they belong
 * to (explicit and implicit) and every ancestor of those groups, their
 * organizations, and `everyone`.
 *
 * Pure, cycle-safe (defensively — the write path guarantees a DAG), and
 * deterministic in iteration order: user, groups (breadth-first), implicit
 * groups, orgs, everyone.
 */
export function computeSubjectClosure(
  input: SubjectClosureInput,
): Set<SubjectId> {
  const closure = new Set<SubjectId>();
  closure.add(userSubject(input.userId));

  const seenGroups = new Set<string>();
  let frontier: string[] = [];
  for (const groupId of input.groupIds) {
    if (!seenGroups.has(groupId)) {
      seenGroups.add(groupId);
      frontier.push(groupId);
    }
  }
  while (frontier.length > 0) {
    const next: string[] = [];
    for (const groupId of frontier) {
      closure.add(groupSubject(groupId));
      const parents = input.groupParents?.get(groupId) ?? [];
      for (const parent of parents) {
        if (!seenGroups.has(parent)) {
          seenGroups.add(parent);
          next.push(parent);
        }
      }
    }
    frontier = next;
  }

  const chain = input.managerChain ?? [];
  const direct = chain[0];
  if (direct !== undefined) closure.add(directsSubject(direct));
  for (const manager of chain) closure.add(orgOfSubject(manager));

  for (const orgId of input.orgIds ?? []) closure.add(orgSubject(orgId));

  closure.add(EVERYONE);
  return closure;
}

/**
 * The subject closure of a service principal: itself and `everyone`.
 * Machine subjects hold grants directly; they have no memberships.
 */
export function computeServiceClosure(serviceId: string): Set<SubjectId> {
  return new Set([serviceSubject(serviceId), EVERYONE]);
}

/**
 * Derives a user's management chain (nearest-first) from reporting edges
 * (`user id → manager user id`). Pure; defensively cycle-safe — the write
 * path enforces the tree shape, but imported data passes through here too.
 */
export function managerChainOf(
  userId: string,
  reportsTo: ReadonlyMap<string, string>,
): string[] {
  const chain: string[] = [];
  const seen = new Set<string>([userId]);
  let current = reportsTo.get(userId);
  while (current !== undefined && !seen.has(current)) {
    chain.push(current);
    seen.add(current);
    current = reportsTo.get(current);
  }
  return chain;
}

/**
 * Membership of an implicit group, computed from reporting edges rather than
 * edited. `directs:<m>` is everyone whose edge points at `m`; `orgof:<m>` is
 * the transitive closure of that. The manager is not a member of their own
 * implicit groups.
 */
export function implicitGroupMembers(
  subject: SubjectId,
  reportsTo: ReadonlyMap<string, string>,
): Set<string> {
  const parsed = parseSubject(subject);
  if (!parsed || (parsed.kind !== "directs" && parsed.kind !== "orgof")) {
    throw new Error(`not an implicit group subject: ${JSON.stringify(subject)}`);
  }
  const manager = parsed.id;
  const members = new Set<string>();
  if (parsed.kind === "directs") {
    for (const [report, boss] of reportsTo) {
      if (boss === manager && report !== manager) members.add(report);
    }
    return members;
  }
  // orgof: BFS down the reporting tree.
  let frontier = [manager];
  while (frontier.length > 0) {
    const next: string[] = [];
    for (const [report, boss] of reportsTo) {
      if (frontier.includes(boss) && !members.has(report) && report !== manager) {
        members.add(report);
        next.push(report);
      }
    }
    frontier = next;
  }
  return members;
}
