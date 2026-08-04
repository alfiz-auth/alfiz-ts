/**
 * The Application's side of the Alfiz Provider API: the provider contract
 * served over HTTPS, exactly as the OpenAPI document in `@alfiz/core`
 * (`openapi/alfiz-provider.v1.yaml`) specifies — `POST {base}/v1/{op}`,
 * named-field JSON bodies, object results, typed-error envelopes.
 *
 * `createProviderHandler` is what a customer mounts at an internal route:
 * every remote operation lands in the same provider methods local code
 * calls, so provider-side enforcement (org-root gating, validation, graph
 * integrity, audit) applies to remote writes exactly as to local ones. The
 * consuming side is `HostedProvider` (same package) — the same contract
 * with this handler on its far side; the delegating end never becomes a
 * second writer.
 *
 * This is the relay seam of the linked topology (dashboard ⇄ still-
 * authoritative Application), and equally the surface a managed service
 * serves to federated consumers: one wire contract, whichever side of it a
 * deployment stands on. Nothing here is on any request path — runtime
 * checks never leave the application.
 *
 * Constraints the protocol encodes (see also protocol.ts in core):
 * - `getReportingEdges` returns a `Map` in-process; the wire carries a
 *   plain object.
 * - `resolveAncestors` is a function property in-process; the wire makes
 *   it an operation. It serves ADMIN surfaces only.
 * - The live `onInvalidate` stream never crosses; the epoch operations are
 *   the cross-process invalidation transport.
 * - Provider errors survive the wire typed: `ProviderWriteRejectedError`
 *   codes and `GraphCycleError` paths are re-thrown intact on the calling
 *   side, so a dashboard renders "cycle: a → b → a" identically for local
 *   and remote writes.
 */

import { createHash, randomUUID, timingSafeEqual } from "node:crypto";
import type {
  AlfizProvider,
  ApplyOrgSnapshotInput,
  GrantInput,
  InvalidationEvent,
  OrgSnapshot,
  Provenance,
  ProviderOp,
  ProviderWireError,
  RequestInput,
  RevokeInput,
  RoleInput,
} from "@alfiz/core";
import {
  PROVIDER_API_VERSION,
  PROVIDER_OPERATIONS,
  ProviderWriteRejectedError,
  providerErrorStatus,
  toProviderWireError,
} from "@alfiz/core";
import type { AlfizApplication } from "./application.js";
import type { StorageDriver } from "./storage.js";

export type { ApplyOrgSnapshotInput, OrgSnapshot, ProviderOp };

/** One serving-side exchange, before it is wrapped in a `Response`. */
export interface ProviderOpResult {
  status: number;
  body: Record<string, unknown> | { error: ProviderWireError };
}

export interface ProviderHandlerOptions {
  application: AlfizApplication | AlfizProvider;
  /**
   * The application's storage driver. Required for the org-snapshot
   * operations (promotion, demotion, read-model sync); everything else
   * runs through the provider surface alone.
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

const KNOWN_OPS: ReadonlySet<string> = new Set(
  PROVIDER_OPERATIONS.map((o) => o.op),
);

/** A protocol-level failure: not an error the provider threw, one the API did. */
function apiError(
  status: number,
  code: string,
  message: string,
): ProviderOpResult {
  return { status, body: { error: { name: "ProviderApiError", message, code } } };
}

const unsupported = (what: string): never => {
  throw new ProviderWriteRejectedError(what, "unsupported");
};

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

/**
 * Handle one parsed operation against the application. Exposed for tests
 * and for hosts that already did their own routing; `createProviderHandler`
 * is the mountable form.
 *
 * The dispatch below is deliberately explicit rather than reflective: it is
 * the serving half of the wire contract, spelling out — once, in one place —
 * which named body field carries which method parameter and which named
 * result field carries the return. The OpenAPI document and the hosted
 * provider mirror it field for field.
 */
export async function handleProviderOp(
  options: ProviderHandlerOptions,
  op: string,
  body: Record<string, unknown>,
): Promise<ProviderOpResult> {
  const app = options.application;
  const clock = options.clock ?? Date.now;
  const ids = options.ids ?? randomUUID;
  if (!KNOWN_OPS.has(op)) {
    return apiError(404, "unknown_op", `unknown operation ${JSON.stringify(op)}`);
  }
  // Body fields are validated by the provider methods they reach, exactly
  // as every other runtime-string input is; the wire layer only routes.
  const b = body as Record<string, any>;
  try {
    const result = await (async (): Promise<Record<string, unknown>> => {
      switch (op as ProviderOp) {
        // -- transport / link ------------------------------------------------
        case "ping": {
          const caps = await app.capabilities();
          return {
            api: PROVIDER_API_VERSION,
            application: options.applicationId,
            orgRoot: caps.orgRoot,
            hasEpoch: app.epoch !== undefined,
            auditOptIn: options.auditOptIn ?? false,
          };
        }

        // -- capability discovery --------------------------------------------
        case "capabilities":
          return { ...(await app.capabilities()) };

        // -- closure supply --------------------------------------------------
        case "getSubjectAccess":
          return { ...(await app.getSubjectAccess(b.principal)) };
        case "resolveAncestors":
          return { ancestors: await app.resolveAncestors(b.scope) };

        // -- invalidation ----------------------------------------------------
        case "epoch.head": {
          if (!app.epoch) {
            return unsupported(
              "this application does not persist events (events.persist is off)",
            );
          }
          return { seq: await app.epoch.head() };
        }
        case "epoch.since": {
          if (!app.epoch) {
            return unsupported(
              "this application does not persist events (events.persist is off)",
            );
          }
          return { ...(await app.epoch.since(b.seq, b.limit)) };
        }

        // -- row operations --------------------------------------------------
        case "createGrant":
          return { grant: await app.createGrant(b.input as GrantInput) };
        case "createGrants":
          return {
            grants: await app.createGrants(b.inputs, b.provenance as Provenance),
          };
        case "deleteGrant":
          await app.deleteGrant(b.grantId, b.provenance as Provenance);
          return {};
        case "listGrants":
          return { grants: await app.listGrants(b.filter) };
        case "countGrants":
          return { count: await app.countGrants(b.filter) };
        case "createRevoke":
          return { revoke: await app.createRevoke(b.input as RevokeInput) };
        case "deleteRevoke":
          await app.deleteRevoke(b.revokeId, b.provenance as Provenance);
          return {};
        case "listRevokes":
          return { revokes: await app.listRevokes(b.filter) };

        // -- referential cleanup ---------------------------------------------
        case "deleteSubject":
          return {
            ...(await app.deleteSubject(b.subject, b.provenance as Provenance)),
          };
        case "deleteScope":
          return {
            ...(await app.deleteScope(b.scope, b.provenance as Provenance)),
          };

        // -- requests --------------------------------------------------------
        case "submitRequest":
          return { request: await app.submitRequest(b.input as RequestInput) };
        case "decideRequest":
          return { request: await app.decideRequest(b.requestId, b.decision) };
        case "cancelRequest":
          return { request: await app.cancelRequest(b.requestId, b.byUserId) };
        case "listRequests":
          return { requests: await app.listRequests(b.filter) };
        case "listApproverQueue":
          return { requests: await app.listApproverQueue(b.approverUserId) };

        // -- catalog registration --------------------------------------------
        case "publishCatalog":
          return {
            ...(await app.publishCatalog(b.document, b.provenance as Provenance)),
          };
        case "getPublishedCatalog":
          return { published: await app.getPublishedCatalog() };
        case "publishImports": {
          if (!app.publishImports) {
            return unsupported("this provider does not store import manifests");
          }
          return {
            ...(await app.publishImports(b.manifest, b.provenance as Provenance)),
          };
        }
        case "getPublishedImports": {
          if (!app.getPublishedImports) {
            return unsupported("this provider does not store import manifests");
          }
          return { published: await app.getPublishedImports() };
        }

        // -- organizational data ---------------------------------------------
        case "listRoles":
          return { roles: await app.listRoles() };
        case "createRole":
          return {
            role: await app.createRole(
              b.input as RoleInput,
              b.provenance as Provenance,
            ),
          };
        case "updateRole":
          return {
            role: await app.updateRole(
              b.roleId,
              b.input as Partial<RoleInput>,
              b.provenance as Provenance,
            ),
          };
        case "deleteRole":
          await app.deleteRole(b.roleId, b.provenance as Provenance);
          return {};
        case "listGroups":
          return { groups: await app.listGroups() };
        case "createGroup":
          return {
            group: await app.createGroup(b.input, b.provenance as Provenance),
          };
        case "updateGroup":
          return {
            group: await app.updateGroup(
              b.groupId,
              b.input,
              b.provenance as Provenance,
            ),
          };
        case "setGroupParents":
          return {
            group: await app.setGroupParents(
              b.groupId,
              b.parents,
              b.provenance as Provenance,
            ),
          };
        case "deleteGroup":
          await app.deleteGroup(b.groupId, b.provenance as Provenance);
          return {};
        case "setGroupMembership":
          await app.setGroupMembership(
            b.userId,
            b.groupIds,
            b.provenance as Provenance,
          );
          return {};
        case "getGroupMembers":
          return { userIds: await app.getGroupMembers(b.groupId) };
        case "setUserActive":
          await app.setUserActive(b.userId, b.active, b.provenance as Provenance);
          return {};
        case "setReportingEdge":
          await app.setReportingEdge(
            b.userId,
            b.managerUserId,
            b.provenance as Provenance,
          );
          return {};
        case "getReportingEdges":
          return { edges: Object.fromEntries(await app.getReportingEdges()) };
        case "dissolveVirtualParent":
          await app.dissolveVirtualParent(b.groupId, b.provenance as Provenance);
          return {};

        // -- audit -----------------------------------------------------------
        case "listAuditEvents":
          return { events: await app.listAuditEvents(b.filter) };

        // -- metrics ---------------------------------------------------------
        case "reportMetrics": {
          if (!app.reportMetrics) {
            return unsupported("this provider does not store metrics");
          }
          await app.reportMetrics(b.batch);
          return {};
        }
        case "getGrantUsage": {
          if (!app.getGrantUsage) {
            return unsupported("this provider does not store metrics");
          }
          return { usage: await app.getGrantUsage(b.query) };
        }
        case "getRevokeUsage": {
          if (!app.getRevokeUsage) {
            return unsupported("this provider does not store metrics");
          }
          return { usage: await app.getRevokeUsage(b.query) };
        }
        case "getRoleUsage": {
          if (!app.getRoleUsage) {
            return unsupported("this provider does not store metrics");
          }
          return { usage: await app.getRoleUsage(b.query) };
        }
        case "getPermissionUsage": {
          if (!app.getPermissionUsage) {
            return unsupported("this provider does not store metrics");
          }
          return { usage: await app.getPermissionUsage(b.query) };
        }
        case "getScopeTypeUsage": {
          if (!app.getScopeTypeUsage) {
            return unsupported("this provider does not store metrics");
          }
          return { usage: await app.getScopeTypeUsage(b.query) };
        }

        // -- org snapshots ---------------------------------------------------
        case "org.exportSnapshot": {
          if (!options.storage) {
            return unsupported("org snapshot operations require the storage option");
          }
          return { snapshot: await exportOrgSnapshot(options.storage) };
        }
        case "org.applySnapshot": {
          if (!options.storage) {
            return unsupported("org snapshot operations require the storage option");
          }
          const input = body as unknown as ApplyOrgSnapshotInput;
          await applyOrgSnapshot(options.storage, input, clock(), ids);
          if ("ingestEvents" in app && typeof app.ingestEvents === "function") {
            app.ingestEvents([{ type: "all" }]);
          }
          if (input.authority !== undefined && options.onAuthorityChanged) {
            await options.onAuthorityChanged(input.authority);
          }
          return { applied: true };
        }
      }
    })();
    return { status: 200, body: result };
  } catch (error) {
    const wire = toProviderWireError(error);
    return { status: providerErrorStatus(wire), body: { error: wire } };
  }
}

/** The operation named by a request URL, or `null` when the path has no `/v1/` segment. */
export function providerOpFromUrl(url: string): string | null {
  const pathname = new URL(url).pathname;
  const marker = pathname.lastIndexOf("/v1/");
  if (marker === -1) return null;
  const op = decodeURIComponent(pathname.slice(marker + "/v1/".length));
  return op.length > 0 ? op : null;
}

/**
 * A web-standard handler serving the Provider API below a mount point:
 * route `POST {base}/v1/:op` to it in any framework (a catch-all
 * `export const POST = createProviderHandler({...})` in Next.js, a route
 * callback in Express/Fastify via their Request adapters).
 */
export function createProviderHandler(
  options: ProviderHandlerOptions,
): (request: Request) => Promise<Response> {
  return async (request: Request): Promise<Response> => {
    if (request.method !== "POST") {
      const { status, body } = apiError(405, "method_not_allowed", "POST only");
      return Response.json(body, { status });
    }
    if (!secretMatches(request.headers.get("authorization"), options.secret)) {
      const { status, body } = apiError(401, "unauthorized", "unauthorized");
      return Response.json(body, { status });
    }
    const op = providerOpFromUrl(request.url);
    if (op === null) {
      const { status, body } = apiError(
        404,
        "unknown_op",
        "expected a path of the form {base}/v1/{op}",
      );
      return Response.json(body, { status });
    }
    let body: Record<string, unknown>;
    try {
      const text = await request.text();
      body = text === "" ? {} : (JSON.parse(text) as Record<string, unknown>);
      if (body === null || typeof body !== "object" || Array.isArray(body)) {
        throw new Error("not an object");
      }
    } catch {
      const { status, body: b2 } = apiError(
        400,
        "bad_request",
        "the request body must be a JSON object of the operation's named parameters",
      );
      return Response.json(b2, { status });
    }
    const result = await handleProviderOp(options, op, body);
    return Response.json(result.body, { status: result.status });
  };
}
