/**
 * The Alfiz Cloud relay seam: the provider contract over HTTPS, in both
 * directions. One POST endpoint per Application, bearer-authenticated with
 * the relay secret minted at link time. The body is `{ op, args }`; ops
 * mirror the `AlfizProvider` methods one-to-one, plus the epoch reads, the
 * org-snapshot ops that promotion/demotion/sync ride on, and a health probe.
 *
 * `createRelayHandler` is the Application side: mount it at an internal
 * route and every relayed operation lands in the same provider methods
 * local code calls, so provider-side enforcement (org-root gating,
 * validation, graph integrity, audit) applies to relayed writes exactly as
 * to local ones. `createRelayProvider` is the calling side: an
 * `AlfizProvider` whose far side is a linked Application — the delegating
 * end never becomes a second writer.
 *
 * Design constraints the protocol encodes:
 * - `getReportingEdges` returns a `Map` in-process; the wire carries a
 *   plain record.
 * - `resolveAncestors` is a function property in-process; the wire makes
 *   it an op. It serves ADMIN surfaces only — runtime checks never leave
 *   the application, and nothing in this protocol is on any request path.
 * - Provider errors survive the wire typed: `ProviderWriteRejectedError`
 *   codes and `GraphCycleError` paths are re-thrown intact on the calling
 *   side, so a dashboard renders "cycle: a → b → a" identically for local
 *   and relayed writes.
 */

import { createHash, randomUUID, timingSafeEqual } from "node:crypto";
import type {
  AccessRequest,
  AlfizProvider,
  CatalogDocument,
  EpochSource,
  GrantRow,
  InvalidationEvent,
  InvalidationListener,
  RevokeRow,
  RoleRecord,
  ScopeId,
  UserGroup,
} from "@alfiz-auth/core";
import { GraphCycleError, ProviderWriteRejectedError } from "@alfiz-auth/core";
import type { AlfizApplication } from "./application.js";
import type { StorageDriver } from "./storage.js";

export const RELAY_PROTOCOL_VERSION = 1;

/** Every op the relay understands. */
export const RELAY_OPS = [
  "ping",
  "capabilities",
  "getSubjectAccess",
  "resolveAncestors",
  "createGrant",
  "createGrants",
  "deleteGrant",
  "listGrants",
  "countGrants",
  "createRevoke",
  "deleteRevoke",
  "listRevokes",
  "deleteSubject",
  "deleteScope",
  "submitRequest",
  "decideRequest",
  "cancelRequest",
  "listRequests",
  "listApproverQueue",
  "publishCatalog",
  "getPublishedCatalog",
  "listRoles",
  "createRole",
  "updateRole",
  "deleteRole",
  "listGroups",
  "createGroup",
  "updateGroup",
  "setGroupParents",
  "deleteGroup",
  "setGroupMembership",
  "getGroupMembers",
  "setUserActive",
  "setReportingEdge",
  "getReportingEdges",
  "dissolveVirtualParent",
  "listAuditEvents",
  "epoch.head",
  "epoch.since",
  "org.exportSnapshot",
  "org.applySnapshot",
] as const;

export type RelayOp = (typeof RELAY_OPS)[number];

export interface RelayRequest {
  op: RelayOp;
  args: unknown[];
}

export interface RelayWireError {
  name: string;
  message: string;
  /** ProviderWriteRejectedError code, when the error carries one. */
  code?: string | undefined;
  /** GraphCycleError path / CatalogError issues, when present. */
  detail?: unknown;
}

export type RelayResponse =
  | { ok: true; result: unknown }
  | { ok: false; error: RelayWireError };

export interface RelayPingResult {
  protocol: number;
  application: string;
  orgRoot: boolean;
  hasEpoch: boolean;
  auditOptIn: boolean;
}

/** The org dataset as it crosses the wire during promotion, sync, and demotion. */
export interface OrgSnapshot {
  groups: UserGroup[];
  roles: RoleRecord[];
  /** Grant rows at the global scope — the org-domain half of the row store. */
  globalGrants: GrantRow[];
  globalRevokes: RevokeRow[];
  users: Array<{
    userId: string;
    active: boolean;
    groupIds: string[];
    orgIds: string[];
    managerUserId: string | null;
  }>;
  /** Pending requests homed at the org root (global-scope proposals). */
  pendingGlobalRequests: AccessRequest[];
  catalog: { version: number; document: CatalogDocument } | null;
}

export interface ApplyOrgSnapshotInput {
  snapshot: OrgSnapshot;
  /**
   * `true`: this push transfers authority — the receiver resumes (or takes
   * up) the org-root role after applying. `false`: read-model sync; the
   * receiver stores the dataset and continues rejecting local org writes.
   */
  authority: boolean;
  /** Audited provenance source, e.g. "demotion:org_abc" or "sync:org_abc". */
  source: string;
}

/** Serialize an error for the wire without losing the parts callers act on. */
export function toWireError(error: unknown): RelayWireError {
  if (error instanceof Error) {
    const wire: RelayWireError = { name: error.name, message: error.message };
    const anyErr = error as Error & {
      code?: unknown;
      path?: unknown;
      issues?: unknown;
    };
    if (typeof anyErr.code === "string") wire.code = anyErr.code;
    if (anyErr.path !== undefined) wire.detail = { path: anyErr.path };
    if (anyErr.issues !== undefined) wire.detail = { issues: anyErr.issues };
    return wire;
  }
  return { name: "Error", message: String(error) };
}

// ---------------------------------------------------------------------------
// The Application side: the handler a customer mounts.
// ---------------------------------------------------------------------------

export interface RelayHandlerOptions {
  application: AlfizApplication | AlfizProvider;
  /**
   * The application's storage driver. Required for the org-snapshot ops
   * (promotion, demotion, read-model sync); everything else runs through
   * the provider surface alone.
   */
  storage?: StorageDriver | undefined;
  secret: string;
  applicationId: string;
  auditOptIn?: boolean | undefined;
  /**
   * Called after an authority-transfer snapshot applies, so the host can
   * reconstruct its Application with the new `orgRoot` flag. The library
   * cannot flip the flag at runtime — it is a constructor commitment.
   */
  onAuthorityChanged?: ((orgRoot: boolean) => void | Promise<void>) | undefined;
  clock?: (() => number) | undefined;
  ids?: (() => string) | undefined;
}

const digest = (value: string): Buffer =>
  createHash("sha256").update(value).digest();

function secretMatches(header: string | null, secret: string): boolean {
  if (!header) return false;
  const raw = header.startsWith("Bearer ")
    ? header.slice("Bearer ".length)
    : header;
  return timingSafeEqual(digest(raw), digest(secret));
}

async function exportOrgSnapshot(storage: StorageDriver): Promise<OrgSnapshot> {
  const [groups, roles, grants, revokes, users, pending, catalog] =
    await Promise.all([
      storage.listGroups(),
      storage.listRoles(),
      storage.listGrants({ scope: "*" }),
      storage.listRevokes({ scope: "*" }),
      storage.listUsers(),
      storage.listRequests({ state: "pending" }),
      storage.getCatalog(),
    ]);
  return {
    groups,
    roles,
    globalGrants: grants,
    globalRevokes: revokes,
    users,
    pendingGlobalRequests: pending.filter((r) => r.scope === "*"),
    catalog,
  };
}

/**
 * Replace the org-domain dataset with the snapshot: groups, roles, users'
 * org-domain fields, global-scope rows, and pending global requests. Local
 * instance-scoped rows are untouched — they were never org-domain data.
 */
async function applyOrgSnapshot(
  storage: StorageDriver,
  input: ApplyOrgSnapshotInput,
  now: number,
  newId: () => string,
): Promise<void> {
  const { snapshot } = input;
  const keepGroups = new Set(snapshot.groups.map((g) => g.id));
  const keepRoles = new Set(snapshot.roles.map((r) => r.id));

  for (const group of snapshot.groups) await storage.upsertGroup(group);
  for (const existing of await storage.listGroups()) {
    if (!keepGroups.has(existing.id)) await storage.deleteGroup(existing.id);
  }
  for (const role of snapshot.roles) await storage.upsertRole(role);
  for (const existing of await storage.listRoles()) {
    if (!keepRoles.has(existing.id)) await storage.deleteRole(existing.id);
  }
  for (const user of snapshot.users) await storage.upsertUser(user);

  for (const row of await storage.listGrants({ scope: "*" })) {
    await storage.deleteGrant(row.id);
  }
  for (const row of snapshot.globalGrants) await storage.insertGrant(row);
  for (const row of await storage.listRevokes({ scope: "*" })) {
    await storage.deleteRevoke(row.id);
  }
  for (const row of snapshot.globalRevokes) await storage.insertRevoke(row);

  for (const request of snapshot.pendingGlobalRequests) {
    const existing = await storage.getRequest(request.id);
    if (existing) await storage.updateRequest(request);
    else await storage.insertRequest(request);
  }

  await storage.appendAudit({
    id: newId(),
    at: now,
    actor: `import:${input.source}`,
    action: input.authority ? "org.authority_received" : "org.sync_applied",
    target: input.source,
    detail: {
      groups: snapshot.groups.length,
      roles: snapshot.roles.length,
      globalGrants: snapshot.globalGrants.length,
      authority: input.authority,
    },
  });
  const events: InvalidationEvent[] = [{ type: "all" }];
  await storage.appendEvents?.(events, now);
}

/** Handle one parsed relay request against the application. */
export async function handleRelayOp(
  options: RelayHandlerOptions,
  request: RelayRequest,
): Promise<RelayResponse> {
  const app = options.application;
  const clock = options.clock ?? Date.now;
  const ids = options.ids ?? randomUUID;
  try {
    if (!RELAY_OPS.includes(request.op)) {
      return {
        ok: false,
        error: {
          name: "RelayProtocolError",
          message: `unknown op ${JSON.stringify(request.op)}`,
        },
      };
    }
    const args = request.args ?? [];
    switch (request.op) {
      case "ping": {
        const caps = await app.capabilities();
        return {
          ok: true,
          result: {
            protocol: RELAY_PROTOCOL_VERSION,
            application: options.applicationId,
            orgRoot: caps.orgRoot,
            hasEpoch: app.epoch !== undefined,
            auditOptIn: options.auditOptIn ?? false,
          },
        };
      }
      case "resolveAncestors": {
        const result = await app.resolveAncestors(args[0] as string);
        return { ok: true, result };
      }
      case "getReportingEdges": {
        const edges = await app.getReportingEdges();
        return { ok: true, result: Object.fromEntries(edges) };
      }
      case "epoch.head": {
        if (!app.epoch) {
          return {
            ok: false,
            error: {
              name: "RelayProtocolError",
              message:
                "this application does not persist events (events.persist is off)",
              code: "unsupported",
            },
          };
        }
        return { ok: true, result: await app.epoch.head() };
      }
      case "epoch.since": {
        if (!app.epoch) {
          return {
            ok: false,
            error: {
              name: "RelayProtocolError",
              message:
                "this application does not persist events (events.persist is off)",
              code: "unsupported",
            },
          };
        }
        return {
          ok: true,
          result: await app.epoch.since(
            args[0] as number,
            args[1] as number | undefined,
          ),
        };
      }
      case "org.exportSnapshot": {
        if (!options.storage) {
          return {
            ok: false,
            error: {
              name: "RelayProtocolError",
              message: "org snapshot ops require the storage option",
              code: "unsupported",
            },
          };
        }
        return { ok: true, result: await exportOrgSnapshot(options.storage) };
      }
      case "org.applySnapshot": {
        if (!options.storage) {
          return {
            ok: false,
            error: {
              name: "RelayProtocolError",
              message: "org snapshot ops require the storage option",
              code: "unsupported",
            },
          };
        }
        const input = args[0] as ApplyOrgSnapshotInput;
        await applyOrgSnapshot(options.storage, input, clock(), ids);
        if ("ingestEvents" in app && typeof app.ingestEvents === "function") {
          app.ingestEvents([{ type: "all" }]);
        }
        if (input.authority !== undefined && options.onAuthorityChanged) {
          await options.onAuthorityChanged(input.authority);
        }
        return { ok: true, result: { applied: true } };
      }
      default: {
        // Every remaining op maps one-to-one onto a provider method.
        const method = (
          app as unknown as Record<string, (...a: unknown[]) => Promise<unknown>>
        )[request.op];
        if (typeof method !== "function") {
          return {
            ok: false,
            error: {
              name: "RelayProtocolError",
              message: `op ${request.op} is not supported by this application`,
              code: "unsupported",
            },
          };
        }
        const result = await method.apply(app, args);
        return { ok: true, result: result ?? null };
      }
    }
  } catch (error) {
    return { ok: false, error: toWireError(error) };
  }
}

/**
 * A web-standard handler: mount at a POST route in any framework
 * (`export const POST = createRelayHandler({...})` in Next.js, a route
 * callback in Express/Fastify via their Request adapters).
 */
export function createRelayHandler(
  options: RelayHandlerOptions,
): (request: Request) => Promise<Response> {
  return async (request: Request): Promise<Response> => {
    if (request.method !== "POST") {
      return Response.json(
        { ok: false, error: { name: "RelayProtocolError", message: "POST only" } },
        { status: 405 },
      );
    }
    if (!secretMatches(request.headers.get("authorization"), options.secret)) {
      return Response.json(
        {
          ok: false,
          error: { name: "RelayProtocolError", message: "unauthorized" },
        },
        { status: 401 },
      );
    }
    let body: RelayRequest;
    try {
      body = (await request.json()) as RelayRequest;
    } catch {
      return Response.json(
        {
          ok: false,
          error: { name: "RelayProtocolError", message: "invalid JSON body" },
        },
        { status: 400 },
      );
    }
    const result = await handleRelayOp(options, body);
    return Response.json(result, { status: 200 });
  };
}

// ---------------------------------------------------------------------------
// The calling side: an AlfizProvider whose far side is a linked Application.
// ---------------------------------------------------------------------------

export interface RelayTarget {
  url: string;
  secret: string;
  /** Timeout per relay call; administrative traffic, so generous. */
  timeoutMs?: number | undefined;
  /** Test seam: swap the transport. Defaults to global fetch. */
  fetchImpl?: typeof fetch | undefined;
}

export class RelayTransportError extends Error {
  override name = "RelayTransportError";
  constructor(
    message: string,
    readonly status?: number | undefined,
  ) {
    super(message);
  }
}

function rethrow(error: RelayWireError): never {
  if (error.name === "ProviderWriteRejectedError") {
    throw new ProviderWriteRejectedError(
      error.message,
      (error.code ?? "validation") as ConstructorParameters<
        typeof ProviderWriteRejectedError
      >[1],
    );
  }
  if (error.name === "GraphCycleError") {
    const path = (error.detail as { path?: string[] } | undefined)?.path ?? [];
    throw new GraphCycleError(path);
  }
  const generic = new Error(error.message);
  generic.name = error.name;
  throw generic;
}

/**
 * The relay client: every read and write is forwarded to the owning
 * Application, which enforces its provider-side integrity rules on relayed
 * operations exactly as on local ones — delegation, never a second writer.
 *
 * Freshness: the relay client exposes the Application's epoch, so an
 * `AlfizClient` attached to it revalidates with one tiny read per window —
 * the same cross-process mechanism the library uses over a shared database,
 * carried over HTTP instead.
 */
export class RelayProvider implements AlfizProvider {
  readonly epoch: EpochSource;
  readonly resolveAncestors: (scope: ScopeId) => Promise<ScopeId[]>;

  constructor(private readonly target: RelayTarget) {
    this.epoch = {
      head: () => this.call<number>("epoch.head", []),
      since: (seq, limit) =>
        this.call("epoch.since", limit === undefined ? [seq] : [seq, limit]),
    };
    this.resolveAncestors = (scope) =>
      this.call<ScopeId[]>("resolveAncestors", [scope]);
  }

  async call<T>(op: RelayOp, args: unknown[]): Promise<T> {
    const { url, secret, timeoutMs = 15_000, fetchImpl = fetch } = this.target;
    let response: Response;
    try {
      response = await fetchImpl(url, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${secret}`,
        },
        body: JSON.stringify({ op, args }),
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (error) {
      throw new RelayTransportError(
        `relay to ${url} failed: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
    if (!response.ok) {
      throw new RelayTransportError(
        `relay to ${url} answered ${response.status}`,
        response.status,
      );
    }
    const body = (await response.json()) as RelayResponse;
    if (!body.ok) rethrow(body.error);
    return body.result as T;
  }

  // -- health / link ---------------------------------------------------------
  ping(): Promise<RelayPingResult> {
    return this.call("ping", []);
  }

  // -- org snapshot ops (promotion, demotion, read-model sync) ---------------
  exportOrgSnapshot(): Promise<OrgSnapshot> {
    return this.call("org.exportSnapshot", []);
  }
  applyOrgSnapshot(input: ApplyOrgSnapshotInput): Promise<{ applied: true }> {
    return this.call("org.applySnapshot", [input]);
  }

  // -- AlfizProvider ---------------------------------------------------------
  capabilities(): ReturnType<AlfizProvider["capabilities"]> {
    return this.call("capabilities", []);
  }
  getSubjectAccess(
    ...args: Parameters<AlfizProvider["getSubjectAccess"]>
  ): ReturnType<AlfizProvider["getSubjectAccess"]> {
    return this.call("getSubjectAccess", args);
  }

  /**
   * The live invalidation stream never crosses processes — that is what the
   * epoch is for. A client attached to a relay provider revalidates by
   * epoch; there is nothing to subscribe to here.
   */
  onInvalidate(_listener: InvalidationListener): () => void {
    return () => {};
  }

  createGrant(
    ...args: Parameters<AlfizProvider["createGrant"]>
  ): ReturnType<AlfizProvider["createGrant"]> {
    return this.call("createGrant", args);
  }
  createGrants(
    ...args: Parameters<AlfizProvider["createGrants"]>
  ): ReturnType<AlfizProvider["createGrants"]> {
    return this.call("createGrants", args);
  }
  deleteGrant(
    ...args: Parameters<AlfizProvider["deleteGrant"]>
  ): ReturnType<AlfizProvider["deleteGrant"]> {
    return this.call("deleteGrant", args);
  }
  listGrants(
    ...args: Parameters<AlfizProvider["listGrants"]>
  ): ReturnType<AlfizProvider["listGrants"]> {
    return this.call("listGrants", args);
  }
  countGrants(
    ...args: Parameters<AlfizProvider["countGrants"]>
  ): ReturnType<AlfizProvider["countGrants"]> {
    return this.call("countGrants", args);
  }
  createRevoke(
    ...args: Parameters<AlfizProvider["createRevoke"]>
  ): ReturnType<AlfizProvider["createRevoke"]> {
    return this.call("createRevoke", args);
  }
  deleteRevoke(
    ...args: Parameters<AlfizProvider["deleteRevoke"]>
  ): ReturnType<AlfizProvider["deleteRevoke"]> {
    return this.call("deleteRevoke", args);
  }
  listRevokes(
    ...args: Parameters<AlfizProvider["listRevokes"]>
  ): ReturnType<AlfizProvider["listRevokes"]> {
    return this.call("listRevokes", args);
  }
  deleteSubject(
    ...args: Parameters<AlfizProvider["deleteSubject"]>
  ): ReturnType<AlfizProvider["deleteSubject"]> {
    return this.call("deleteSubject", args);
  }
  deleteScope(
    ...args: Parameters<AlfizProvider["deleteScope"]>
  ): ReturnType<AlfizProvider["deleteScope"]> {
    return this.call("deleteScope", args);
  }
  submitRequest(
    ...args: Parameters<AlfizProvider["submitRequest"]>
  ): ReturnType<AlfizProvider["submitRequest"]> {
    return this.call("submitRequest", args);
  }
  decideRequest(
    ...args: Parameters<AlfizProvider["decideRequest"]>
  ): ReturnType<AlfizProvider["decideRequest"]> {
    return this.call("decideRequest", args);
  }
  cancelRequest(
    ...args: Parameters<AlfizProvider["cancelRequest"]>
  ): ReturnType<AlfizProvider["cancelRequest"]> {
    return this.call("cancelRequest", args);
  }
  listRequests(
    ...args: Parameters<AlfizProvider["listRequests"]>
  ): ReturnType<AlfizProvider["listRequests"]> {
    return this.call("listRequests", args);
  }
  listApproverQueue(
    ...args: Parameters<AlfizProvider["listApproverQueue"]>
  ): ReturnType<AlfizProvider["listApproverQueue"]> {
    return this.call("listApproverQueue", args);
  }
  publishCatalog(
    ...args: Parameters<AlfizProvider["publishCatalog"]>
  ): ReturnType<AlfizProvider["publishCatalog"]> {
    return this.call("publishCatalog", args);
  }
  getPublishedCatalog(): ReturnType<AlfizProvider["getPublishedCatalog"]> {
    return this.call("getPublishedCatalog", []);
  }
  listRoles(): ReturnType<AlfizProvider["listRoles"]> {
    return this.call("listRoles", []);
  }
  createRole(
    ...args: Parameters<AlfizProvider["createRole"]>
  ): ReturnType<AlfizProvider["createRole"]> {
    return this.call("createRole", args);
  }
  updateRole(
    ...args: Parameters<AlfizProvider["updateRole"]>
  ): ReturnType<AlfizProvider["updateRole"]> {
    return this.call("updateRole", args);
  }
  deleteRole(
    ...args: Parameters<AlfizProvider["deleteRole"]>
  ): ReturnType<AlfizProvider["deleteRole"]> {
    return this.call("deleteRole", args);
  }
  listGroups(): ReturnType<AlfizProvider["listGroups"]> {
    return this.call("listGroups", []);
  }
  createGroup(
    ...args: Parameters<AlfizProvider["createGroup"]>
  ): ReturnType<AlfizProvider["createGroup"]> {
    return this.call("createGroup", args);
  }
  updateGroup(
    ...args: Parameters<AlfizProvider["updateGroup"]>
  ): ReturnType<AlfizProvider["updateGroup"]> {
    return this.call("updateGroup", args);
  }
  setGroupParents(
    ...args: Parameters<AlfizProvider["setGroupParents"]>
  ): ReturnType<AlfizProvider["setGroupParents"]> {
    return this.call("setGroupParents", args);
  }
  deleteGroup(
    ...args: Parameters<AlfizProvider["deleteGroup"]>
  ): ReturnType<AlfizProvider["deleteGroup"]> {
    return this.call("deleteGroup", args);
  }
  setGroupMembership(
    ...args: Parameters<AlfizProvider["setGroupMembership"]>
  ): ReturnType<AlfizProvider["setGroupMembership"]> {
    return this.call("setGroupMembership", args);
  }
  getGroupMembers(
    ...args: Parameters<AlfizProvider["getGroupMembers"]>
  ): ReturnType<AlfizProvider["getGroupMembers"]> {
    return this.call("getGroupMembers", args);
  }
  setUserActive(
    ...args: Parameters<AlfizProvider["setUserActive"]>
  ): ReturnType<AlfizProvider["setUserActive"]> {
    return this.call("setUserActive", args);
  }
  setReportingEdge(
    ...args: Parameters<AlfizProvider["setReportingEdge"]>
  ): ReturnType<AlfizProvider["setReportingEdge"]> {
    return this.call("setReportingEdge", args);
  }
  async getReportingEdges(): Promise<Map<string, string>> {
    const record = await this.call<Record<string, string>>(
      "getReportingEdges",
      [],
    );
    return new Map(Object.entries(record));
  }
  dissolveVirtualParent(
    ...args: Parameters<AlfizProvider["dissolveVirtualParent"]>
  ): ReturnType<AlfizProvider["dissolveVirtualParent"]> {
    return this.call("dissolveVirtualParent", args);
  }
  listAuditEvents(
    ...args: Parameters<AlfizProvider["listAuditEvents"]>
  ): ReturnType<AlfizProvider["listAuditEvents"]> {
    return this.call("listAuditEvents", args);
  }
}

export function createRelayProvider(target: RelayTarget): RelayProvider {
  return new RelayProvider(target);
}
