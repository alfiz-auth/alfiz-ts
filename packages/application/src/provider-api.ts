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
  createAlfizClient,
  providerErrorStatus,
  safeEcho,
  toProviderWireError,
} from "@alfiz/core";
import type { AlfizClient } from "@alfiz/core";
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

/**
 * The floor on the handler's shared secret, matching the one
 * `createServiceKeyShim` already enforces on service keys. This credential is
 * strictly more powerful than a service key — it reads the whole
 * organization and can replace it — so it cannot hold a weaker rule.
 *
 * The shapes this catches are not hypothetical: `process.env.X ?? ""` and
 * `` `${process.env.X}` `` (the literal string `"undefined"`) are how a
 * missing environment variable reaches this option, and the second one is a
 * credential an attacker can guess on the first try.
 */
const MIN_SECRET_LENGTH = 16;

function assertUsableSecret(secret: string): void {
  if (typeof secret !== "string" || secret.trim().length < MIN_SECRET_LENGTH) {
    throw new Error(
      `alfiz: the provider handler's secret must be at least ${MIN_SECRET_LENGTH} characters — ` +
        "it is the only credential guarding every provider operation, including reading and " +
        "replacing the entire organization. A missing environment variable reaches this option " +
        'as "" or as the literal string "undefined"; both are refused here rather than served.',
    );
  }
}

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

/**
 * The named body fields each operation cannot run without, checked at the
 * dispatch site so an absent parameter answers `422 validation` instead of
 * reaching a provider method as a property read on `undefined` and
 * surfacing as a `500` carrying a raw `TypeError` message.
 *
 * Only genuinely required fields are listed: an operation whose parameter is
 * an optional filter (`listGrants`, `listRequests`, `listAuditEvents`)
 * belongs nowhere here, because absent means "no filter" for those by
 * contract. Provenance and input *shapes* stay the provider's to validate —
 * this is presence, not schema.
 */
const REQUIRED_FIELDS: Readonly<Record<string, readonly string[]>> = {
  getSubjectAccess: ["principal"],
  resolveAncestors: ["scope"],
  check: ["principal", "key"],
  "epoch.since": ["seq"],
  createGrant: ["input"],
  createGrants: ["inputs", "provenance"],
  deleteGrant: ["grantId", "provenance"],
  createRevoke: ["input"],
  deleteRevoke: ["revokeId", "provenance"],
  deleteSubject: ["subject", "provenance"],
  deleteScope: ["scope", "provenance"],
  submitRequest: ["input"],
  decideRequest: ["requestId", "decision"],
  cancelRequest: ["requestId", "byUserId"],
  listApproverQueue: ["approverUserId"],
  publishCatalog: ["document", "provenance"],
  publishImports: ["manifest", "provenance"],
  createRole: ["input", "provenance"],
  updateRole: ["roleId", "input", "provenance"],
  deleteRole: ["roleId", "provenance"],
  createGroup: ["input", "provenance"],
  updateGroup: ["groupId", "input", "provenance"],
  setGroupParents: ["groupId", "parents", "provenance"],
  deleteGroup: ["groupId", "provenance"],
  setGroupMembership: ["userId", "groupIds", "provenance"],
  getGroupMembers: ["groupId"],
  setUserActive: ["userId", "active", "provenance"],
  setReportingEdge: ["userId", "provenance"],
  dissolveVirtualParent: ["groupId", "provenance"],
  reportMetrics: ["batch"],
  getGrantUsage: ["query"],
  getRevokeUsage: ["query"],
  getRoleUsage: ["query"],
  getPermissionUsage: ["query"],
  getScopeTypeUsage: ["query"],
  "org.applySnapshot": ["snapshot", "source"],
};

/**
 * The evaluator behind the `check` operation: one client per handler,
 * created on first use, over the application's own catalog and provider
 * surface — the same closure caches and safe defaults every in-process
 * client gets, so repeated remote checks for one principal cost one
 * closure supply, not one per call.
 */
const checkClients = new WeakMap<
  ProviderHandlerOptions,
  AlfizClient<string, string, string>
>();
function checkClientFor(
  options: ProviderHandlerOptions,
  app: AlfizProvider,
): AlfizClient<string, string, string> {
  let client = checkClients.get(options);
  if (client === undefined) {
    const catalog = (app as AlfizApplication).catalog;
    if (catalog === undefined) {
      throw new ProviderWriteRejectedError(
        "the check operation needs an Application (a provider with a catalog) on the serving side",
        "unsupported",
      );
    }
    client = createAlfizClient({ catalog, provider: app });
    checkClients.set(options, client);
  }
  return client;
}

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
 * A row array field that must be present, and every element of which must be
 * an object carrying its identifying key — `idField` differs by collection
 * (users key on `userId`, everything else on `id`), and getting it wrong
 * would reject a well-formed snapshot rather than a malformed one.
 */
function requireRows(
  value: unknown,
  field: string,
  idField: string,
): readonly any[] {
  if (!Array.isArray(value)) {
    throw new ProviderWriteRejectedError(
      `snapshot.${field} must be an array`,
      "validation",
    );
  }
  for (const [index, row] of value.entries()) {
    if (row === null || typeof row !== "object" || Array.isArray(row)) {
      throw new ProviderWriteRejectedError(
        `snapshot.${field}[${index}] must be an object`,
        "validation",
      );
    }
    if (typeof (row as Record<string, unknown>)[idField] !== "string") {
      throw new ProviderWriteRejectedError(
        `snapshot.${field}[${index}] must carry a string ${idField}`,
        "validation",
      );
    }
  }
  return value;
}

/**
 * Prove the snapshot is whole and well-formed BEFORE anything is deleted.
 *
 * The apply below is a destructive replace with no transaction under it, so
 * validation is the only thing standing between a malformed payload and an
 * organization that no longer exists. Without this pass a `null` in a late
 * array threw after the earlier phases had already deleted, the caller saw a
 * 500 and believed nothing had happened, and the audit append — the last
 * statement — never ran.
 *
 * Row *contents* are validated by the provider surface everywhere else; here
 * there is no provider surface to validate them, which is finding-shaped in
 * itself and noted on `org.applySnapshot` in the OpenAPI document.
 */
function validateOrgSnapshot(input: ApplyOrgSnapshotInput): void {
  if (typeof input?.source !== "string" || input.source.length === 0) {
    throw new ProviderWriteRejectedError(
      "an org snapshot must name its source",
      "validation",
    );
  }
  const snapshot = input.snapshot as OrgSnapshot | undefined;
  if (snapshot === null || typeof snapshot !== "object") {
    throw new ProviderWriteRejectedError(
      "org.applySnapshot needs a snapshot object",
      "validation",
    );
  }
  requireRows(snapshot.groups, "groups", "id");
  requireRows(snapshot.roles, "roles", "id");
  requireRows(snapshot.users, "users", "userId");
  requireRows(snapshot.globalGrants, "globalGrants", "id");
  requireRows(snapshot.globalRevokes, "globalRevokes", "id");
  requireRows(snapshot.pendingGlobalRequests, "pendingGlobalRequests", "id");
  if (input.authority !== undefined && typeof input.authority !== "boolean") {
    throw new ProviderWriteRejectedError(
      "snapshot authority must be a boolean when present",
      "validation",
    );
  }
}

/**
 * Replace the org-domain dataset with the snapshot: groups, roles, users'
 * org-domain fields, global-scope rows, and pending global requests. Local
 * instance-scoped rows are untouched — they were never org-domain data.
 *
 * Write ORDER is load-bearing. The seam has no transaction primitive, so the
 * intermediate states this produces are states concurrent checks really
 * observe. Revokes are therefore installed before any grant moves and
 * retired only once the new grants are in place: at no instant does the
 * store hold a set of global grants with its matching negative layer
 * missing, which is the one interleaving that answers ALLOW where the
 * correct answer is DENY.
 */
async function applyOrgSnapshot(
  storage: StorageDriver,
  input: ApplyOrgSnapshotInput,
  now: number,
  newId: () => string,
): Promise<void> {
  validateOrgSnapshot(input);
  const { snapshot } = input;
  const keepGroups = new Set(snapshot.groups.map((g) => g.id));
  const keepRoles = new Set(snapshot.roles.map((r) => r.id));

  // The negative layer goes in first and comes out last.
  const staleRevokes = await storage.listRevokes({ scope: "*" });
  const incomingRevokes = new Set(snapshot.globalRevokes.map((r) => r.id));
  for (const row of snapshot.globalRevokes) {
    if (!staleRevokes.some((existing) => existing.id === row.id)) {
      await storage.insertRevoke(row);
    }
  }

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

  for (const row of staleRevokes) {
    if (!incomingRevokes.has(row.id)) await storage.deleteRevoke(row.id);
  }

  for (const request of snapshot.pendingGlobalRequests) {
    const existing = await storage.getRequest(request.id);
    if (existing) await storage.updateRequest(request);
    else await storage.insertRequest(request);
  }

  await storage.appendAudit({
    id: newId(),
    at: now,
    actor: `import:${safeEcho(input.source, 200)}`,
    action: input.authority ? "org.authority_received" : "org.sync_applied",
    target: safeEcho(input.source, 200),
    detail: {
      groups: snapshot.groups.length,
      roles: snapshot.roles.length,
      globalGrants: snapshot.globalGrants.length,
      globalRevokes: snapshot.globalRevokes.length,
      users: snapshot.users.length,
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
  // Body field VALUES are validated by the provider methods they reach,
  // exactly as every other runtime-string input is; the wire layer only
  // routes. Field PRESENCE is this layer's job, though — a missing named
  // parameter never reaches a provider method as anything but a property
  // read on `undefined`, and the contract promises a typed envelope
  // (`protocol.ts`, the OpenAPI `ErrorEnvelope`), not a raw `TypeError`
  // message describing this file's internals.
  const b = body as Record<string, any>;
  try {
    for (const field of REQUIRED_FIELDS[op] ?? []) {
      if (b[field] === undefined || b[field] === null) {
        throw new ProviderWriteRejectedError(
          `${op} requires the ${JSON.stringify(field)} field`,
          "validation",
        );
      }
    }
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

        // -- evaluation (the non-JS check path) ------------------------------
        case "check": {
          const client = checkClientFor(options, app);
          const allowed = b.fresh
            ? await client.can.fresh(b.principal, b.key, b.scope)
            : await client.can(b.principal, b.key, b.scope);
          return { allowed };
        }

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
          // Shape first, so a malformed payload is a validation error
          // whatever else is wrong with the request.
          validateOrgSnapshot(input);
          // An authority transfer the receiver cannot enact must not be
          // reported as enacted. `orgRoot` is a constructor commitment, so
          // without the hook the flag never flips: the sender demotes itself
          // on a `{applied: true}` it should never have seen, and the
          // organization is left with no authoritative writer at all.
          //
          // Only an actual CHANGE needs the hook — a snapshot restating the
          // authority the receiver already holds transfers nothing, and is
          // the ordinary shape of a routine read-model sync.
          if (input.authority !== undefined && !options.onAuthorityChanged) {
            // Whether the flag would actually move. A provider that cannot
            // answer has no `orgRoot` flag to flip in the first place —
            // this operation is storage-only, and a host may legitimately
            // mount it without a full Application behind it.
            let currentOrgRoot: boolean | undefined;
            try {
              currentOrgRoot = (await app.capabilities()).orgRoot;
            } catch {
              currentOrgRoot = undefined;
            }
            if (currentOrgRoot !== undefined && input.authority !== currentOrgRoot) {
              return unsupported(
                "this handler cannot accept an authority transfer: `orgRoot` is a constructor " +
                  "commitment, so the host must supply `onAuthorityChanged` to rebuild its Application",
              );
            }
          }
          await applyOrgSnapshot(options.storage, input, clock(), ids);
          if ("ingestEvents" in app && typeof app.ingestEvents === "function") {
            app.ingestEvents([{ type: "all" }]);
          }
          if (input.authority !== undefined) {
            await options.onAuthorityChanged?.(input.authority);
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

/**
 * The operation named by a request URL, or `null` when the path does not
 * name exactly one.
 *
 * `lastIndexOf` is deliberate — a handler mounted at `/api/v1/alfiz` must
 * still route `/api/v1/alfiz/v1/ping` — but it also means a path carrying a
 * SECOND `/v1/` segment is read differently here than by anything in front
 * of it. `/v1/ping/v1/org.exportSnapshot` is `ping` to an nginx `location`,
 * a WAF rule, a rate limiter, and the access log; it was
 * `org.exportSnapshot` to this function. Whatever an operator believes they
 * matched on, they matched on something this handler did not run, so an
 * ambiguous path is refused rather than resolved.
 */
export function providerOpFromUrl(url: string): string | null {
  let pathname: string;
  try {
    pathname = new URL(url).pathname;
  } catch {
    return null;
  }
  const marker = pathname.lastIndexOf("/v1/");
  if (marker === -1) return null;
  // An EARLIER `/v1/` whose next segment is itself an operation name is the
  // ambiguous shape: `/v1/ping/v1/org.exportSnapshot` reads as `ping` to
  // anything matching on the first marker and as `org.exportSnapshot` here.
  // A mount path that merely contains `/v1/` — `/api/v1/alfiz/v1/ping`, the
  // case `lastIndexOf` exists for — is not ambiguous, because `alfiz` names
  // no operation, so it keeps working.
  for (let at = pathname.indexOf("/v1/"); at !== -1 && at < marker; ) {
    const rest = pathname.slice(at + "/v1/".length);
    const segment = rest.split("/", 1)[0] ?? "";
    let decoded: string;
    try {
      decoded = decodeURIComponent(segment);
    } catch {
      decoded = segment;
    }
    if (KNOWN_OPS.has(decoded)) return null;
    at = pathname.indexOf("/v1/", at + 1);
  }
  let op: string;
  try {
    // A malformed percent-escape (`/v1/ping%FF`) is a valid URL and an
    // invalid decode. Left unguarded it threw a `URIError` clean out of the
    // mounted route, where what the caller sees is whatever the host
    // framework does with an exception — often a stack-trace 500.
    op = decodeURIComponent(pathname.slice(marker + "/v1/".length));
  } catch {
    return null;
  }
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
  assertUsableSecret(options.secret);
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
