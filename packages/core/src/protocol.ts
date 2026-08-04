/**
 * The Alfiz Provider API — the provider contract's wire form, and the
 * third of its three normative artifacts:
 *
 *   1. `AlfizProvider` (provider.ts) — the contract as a TypeScript type.
 *   2. `AlfizProviderBase` (provider-base.ts) — the contract as an abstract
 *      class every provider implementation extends.
 *   3. The OpenAPI document (`openapi/alfiz-provider.v1.yaml`, described by
 *      the operation manifest below) — the contract as a language-agnostic
 *      HTTP API, portable to any implementation language.
 *
 * This module is pure data: operation names, paths, request/response
 * conventions, and the typed-error wire shape. It performs no I/O — the
 * Application serves the API (`createProviderHandler`), and the hosted
 * provider consumes it (`HostedProvider`, also in `@alfiz/application`).
 *
 * Wire conventions, fixed by this contract:
 * - Every operation is `POST {base}/v1/{op}` with a JSON object body of the
 *   operation's NAMED parameters (`{}` when there are none). The contract
 *   is method-shaped, so the API is too: one path per operation, mirroring
 *   the abstract class one-to-one, rather than a resource grammar bolted
 *   over an RPC contract. POST-only keeps the transport uniform and keeps
 *   authorization data out of URLs and shared caches.
 * - Every success is `200` with a JSON OBJECT body — never a bare array,
 *   primitive, or `null` — so every response can grow a field without a
 *   wire break. Void operations return `{}`.
 * - Every failure is a non-2xx status with an {@link ProviderWireError}
 *   envelope. The status is a transport hint; the envelope is normative —
 *   callers re-throw from `error.name` and `error.code`, so a dashboard
 *   renders "cycle: a → b → a" identically for local and remote writes.
 * - Authentication is `Authorization: Bearer <token>`; the token is minted
 *   at link time and opaque to this contract.
 * - `Map`-shaped in-process data crosses as plain JSON objects
 *   (`getReportingEdges` → `{ edges: { [userId]: managerUserId } }`), and
 *   in-process function properties (`resolveAncestors`) cross as
 *   operations. The live `onInvalidate` stream never crosses at all: the
 *   epoch (`epoch.head` / `epoch.since`) is the cross-process invalidation
 *   transport, exactly as it is between processes sharing a database.
 */

import type { GrantRow, RevokeRow } from "./access.js";
import type { CatalogDocument } from "./catalog.js";
import { GraphCycleError } from "./graph.js";
import type { AlfizProvider, RoleRecord, UserGroup } from "./provider.js";
import { ProviderWriteRejectedError } from "./provider.js";
import type { AccessRequest } from "./requests.js";

/**
 * The version of the Provider API this build speaks, carried in the path
 * prefix (`/v1/…`) and reported by `ping`. Incremented only on a wire
 * break; additive fields ride on the object-body convention instead.
 */
export const PROVIDER_API_VERSION = 1;

// ---------------------------------------------------------------------------
// The operation manifest
// ---------------------------------------------------------------------------

/**
 * How an operation relates to the contract and its capability gates.
 *
 * `method` names the `AlfizProvider` member the operation carries — present
 * for every contract method, absent for the transport-only operations
 * (`ping`, the epoch reads, the org-snapshot pair). A type-level assertion
 * below keeps this exact: every wire-crossing contract method appears in
 * the manifest, and the manifest names nothing the contract lacks.
 *
 * `requires` names the discovery gate: a provider that lacks the feature
 * answers the operation with an `unsupported` error, and advertises so in
 * advance (`capabilities()`, `ping.hasEpoch`).
 */
export interface ProviderOperationDescriptor {
  readonly op: string;
  readonly kind: "read" | "write";
  readonly method?: Exclude<keyof AlfizProvider, "onInvalidate" | "epoch">;
  readonly requires?: "epoch" | "metrics" | "imports" | "storage";
}

export const PROVIDER_OPERATIONS = [
  // -- transport / link ------------------------------------------------------
  { op: "ping", kind: "read" },

  // -- capability discovery --------------------------------------------------
  { op: "capabilities", kind: "read", method: "capabilities" },

  // -- closure supply --------------------------------------------------------
  { op: "getSubjectAccess", kind: "read", method: "getSubjectAccess" },
  { op: "resolveAncestors", kind: "read", method: "resolveAncestors" },

  // -- invalidation (the epoch is the cross-process transport) ---------------
  { op: "epoch.head", kind: "read", requires: "epoch" },
  { op: "epoch.since", kind: "read", requires: "epoch" },

  // -- row operations --------------------------------------------------------
  { op: "createGrant", kind: "write", method: "createGrant" },
  { op: "createGrants", kind: "write", method: "createGrants" },
  { op: "deleteGrant", kind: "write", method: "deleteGrant" },
  { op: "listGrants", kind: "read", method: "listGrants" },
  { op: "countGrants", kind: "read", method: "countGrants" },
  { op: "createRevoke", kind: "write", method: "createRevoke" },
  { op: "deleteRevoke", kind: "write", method: "deleteRevoke" },
  { op: "listRevokes", kind: "read", method: "listRevokes" },

  // -- referential cleanup ---------------------------------------------------
  { op: "deleteSubject", kind: "write", method: "deleteSubject" },
  { op: "deleteScope", kind: "write", method: "deleteScope" },

  // -- requests --------------------------------------------------------------
  { op: "submitRequest", kind: "write", method: "submitRequest" },
  { op: "decideRequest", kind: "write", method: "decideRequest" },
  { op: "cancelRequest", kind: "write", method: "cancelRequest" },
  { op: "listRequests", kind: "read", method: "listRequests" },
  { op: "listApproverQueue", kind: "read", method: "listApproverQueue" },

  // -- catalog registration --------------------------------------------------
  { op: "publishCatalog", kind: "write", method: "publishCatalog" },
  { op: "getPublishedCatalog", kind: "read", method: "getPublishedCatalog" },
  { op: "publishImports", kind: "write", method: "publishImports", requires: "imports" },
  { op: "getPublishedImports", kind: "read", method: "getPublishedImports", requires: "imports" },

  // -- organizational data (rejected when not org root) ----------------------
  { op: "listRoles", kind: "read", method: "listRoles" },
  { op: "createRole", kind: "write", method: "createRole" },
  { op: "updateRole", kind: "write", method: "updateRole" },
  { op: "deleteRole", kind: "write", method: "deleteRole" },
  { op: "listGroups", kind: "read", method: "listGroups" },
  { op: "createGroup", kind: "write", method: "createGroup" },
  { op: "updateGroup", kind: "write", method: "updateGroup" },
  { op: "setGroupParents", kind: "write", method: "setGroupParents" },
  { op: "deleteGroup", kind: "write", method: "deleteGroup" },
  { op: "setGroupMembership", kind: "write", method: "setGroupMembership" },
  { op: "getGroupMembers", kind: "read", method: "getGroupMembers" },
  { op: "setUserActive", kind: "write", method: "setUserActive" },
  { op: "setReportingEdge", kind: "write", method: "setReportingEdge" },
  { op: "getReportingEdges", kind: "read", method: "getReportingEdges" },
  { op: "dissolveVirtualParent", kind: "write", method: "dissolveVirtualParent" },

  // -- audit -----------------------------------------------------------------
  { op: "listAuditEvents", kind: "read", method: "listAuditEvents" },

  // -- metrics (delivered to and read from the store that keeps them) --------
  { op: "reportMetrics", kind: "write", method: "reportMetrics", requires: "metrics" },
  { op: "getGrantUsage", kind: "read", method: "getGrantUsage", requires: "metrics" },
  { op: "getRevokeUsage", kind: "read", method: "getRevokeUsage", requires: "metrics" },
  { op: "getRoleUsage", kind: "read", method: "getRoleUsage", requires: "metrics" },
  { op: "getPermissionUsage", kind: "read", method: "getPermissionUsage", requires: "metrics" },
  { op: "getScopeTypeUsage", kind: "read", method: "getScopeTypeUsage", requires: "metrics" },

  // -- org snapshots (promotion, demotion, read-model sync) ------------------
  { op: "org.exportSnapshot", kind: "read", requires: "storage" },
  { op: "org.applySnapshot", kind: "write", requires: "storage" },
] as const satisfies readonly ProviderOperationDescriptor[];

export type ProviderOp = (typeof PROVIDER_OPERATIONS)[number]["op"];

/** The path an operation is served at, relative to the provider's base URL. */
export const providerOpPath = (op: ProviderOp): string => `/v1/${op}`;

// -- Coverage, enforced at compile time --------------------------------------
// The manifest and the contract cannot drift: every wire-crossing method of
// `AlfizProvider` must appear exactly once, and the manifest may not name a
// method the contract lacks. `onInvalidate` (the in-process live stream) and
// `epoch` (a property, carried by the epoch.* operations) are the two
// deliberate exclusions.

type ContractWireMethod = {
  [K in keyof AlfizProvider]-?: NonNullable<AlfizProvider[K]> extends (
    ...args: never[]
  ) => unknown
    ? K
    : never;
}[keyof AlfizProvider] extends infer M
  ? Exclude<M, "onInvalidate">
  : never;
type ManifestMethod = NonNullable<
  (typeof PROVIDER_OPERATIONS)[number] extends infer D
    ? D extends { method: infer X }
      ? X
      : never
    : never
>;
type MethodsMissingFromManifest = Exclude<ContractWireMethod, ManifestMethod>;
type MethodsNotOnContract = Exclude<ManifestMethod, ContractWireMethod>;
// Assigning `true` fails to compile the moment either exclusion set is
// non-empty — the error names the drifted methods.
export const PROVIDER_OPERATIONS_COVER_CONTRACT: [
  MethodsMissingFromManifest,
  MethodsNotOnContract,
] extends [never, never]
  ? true
  : {
      missingFromManifest: MethodsMissingFromManifest;
      notOnContract: MethodsNotOnContract;
    } = true;

// ---------------------------------------------------------------------------
// Errors on the wire
// ---------------------------------------------------------------------------

/**
 * The typed-error envelope, `{ error: ProviderWireError }` on every non-2xx
 * response. Serialization keeps the parts callers act on: the
 * `ProviderWriteRejectedError` code, the `GraphCycleError` path, and
 * `CatalogError` issues survive the wire and are re-thrown intact.
 */
export interface ProviderWireError {
  name: string;
  message: string;
  /** {@link ProviderWriteRejectedError} code, when the error carries one. */
  code?: string | undefined;
  /** `GraphCycleError` path / `CatalogError` issues, when present. */
  detail?: unknown;
}

/** Serialize an error for the wire without losing the parts callers act on. */
export function toProviderWireError(error: unknown): ProviderWireError {
  if (error instanceof Error) {
    const wire: ProviderWireError = { name: error.name, message: error.message };
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

/**
 * The HTTP status a wire error travels under. A transport hint only — the
 * envelope is normative — but a correct hint, so generic HTTP tooling
 * (retry policies, dashboards, logs) reads the API sensibly.
 */
export function providerErrorStatus(error: ProviderWireError): number {
  switch (error.code) {
    case "validation":
      return 422;
    case "not_found":
      return 404;
    case "conflict":
    case "graph_cycle":
      return 409;
    case "not_org_root":
      return 403;
    case "unsupported":
      return 501;
    default:
      return error.name === "GraphCycleError" ? 409 : 500;
  }
}

/**
 * Re-raise a wire error as the typed error it was on the serving side, so
 * remote and local providers throw identically.
 */
export function rethrowProviderWireError(error: ProviderWireError): never {
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

// ---------------------------------------------------------------------------
// Transport-only payloads
// ---------------------------------------------------------------------------

/** The `ping` result: liveness, identity, and link-time discovery. */
export interface ProviderPingResult {
  /** {@link PROVIDER_API_VERSION} of the serving side. */
  api: number;
  /** The serving application's id, set when the link was configured. */
  application: string;
  orgRoot: boolean;
  hasEpoch: boolean;
  auditOptIn: boolean;
}

/**
 * The org dataset as it crosses the wire during promotion, demotion, and
 * read-model sync — the audited-handoff payload of §2.6. Part of the wire
 * contract because BOTH implementations speak it: an Application exports and
 * applies it through its handler, and a hosted provider carries it in either
 * direction.
 */
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
