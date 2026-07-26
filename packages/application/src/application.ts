/**
 * The Alfiz Application: the local provider. A library-embedded
 * implementation of the provider contract against the application's own
 * database (through the storage seam), with no external dependency.
 *
 * Standalone, the Application is the org root: it owns organizational-domain
 * data — groups, roles, global grants and revokes, the reporting tree — with
 * the full feature set, locally. Configured as a non-root (federated read
 * model), it serves the same data read-only and rejects org-domain writes.
 */

import type {
  AccessRequest,
  AlfizProvider,
  AnyCatalog,
  ApprovalStage,
  AuditEvent,
  CatalogDocument,
  CheckContext,
  GrantInput,
  GrantRow,
  InvalidationEvent,
  InvalidationListener,
  PrincipalRef,
  Provenance,
  RequestFilter,
  RequestInput,
  RevokeInput,
  RevokeRow,
  RoleInput,
  RoleRecord,
  ScopeId,
  SubjectAccessData,
  SubjectId,
  UserGroup,
} from "@alfiz-auth/core";
import {
  ALFIZ_INTERNAL_NAMESPACE,
  GLOBAL_SCOPE,
  ProviderWriteRejectedError,
  applyDecision,
  canDecideStage,
  checkKey,
  computeServiceClosure,
  computeSubjectClosure,
  findCycle,
  isGlobalScope,
  planVirtualParentDissolution,
  runAutoStages,
  validateGrantRow,
  validateJustification,
  validatePattern,
  validateScopeId,
} from "@alfiz-auth/core";
import type { AncestryResolver } from "@alfiz-auth/core";
import { randomUUID } from "node:crypto";
import type { StorageDriver, StoredUser } from "./storage.js";

export interface ApplicationOptions {
  catalog: AnyCatalog;
  storage: StorageDriver;
  /**
   * The ancestry seam: resolves a scope instance's ancestor chain against
   * the application's own tables — the reason checks are local forever.
   * Omit for fully-global deployments (every scope is `*`).
   */
  ancestry?: AncestryResolver | undefined;
  /**
   * Standalone (default): this Application is the org root and the single
   * writer of organizational-domain data. `false`: the org root lives
   * elsewhere; org-domain data is a synced read model and local writes to it
   * are rejected.
   */
  orgRoot?: boolean | undefined;
  clock?: (() => number) | undefined;
  ids?: (() => string) | undefined;
}

const actorOf = (p: Provenance): string => {
  switch (p.kind) {
    case "admin":
      return p.actorUserId;
    case "request":
      return p.approvedBy ?? "auto";
    case "import":
      return `import:${p.source}`;
    case "merge":
      return `merge:${p.source}`;
    case "reconciler":
      return `reconciler:${p.integrationId}`;
    case "dissolution":
      return "system";
    case "system":
      return "system";
  }
};

export interface DirectorySnapshot {
  /** External directory groups with their (possibly cyclic) nesting. */
  groups?: Array<{
    id: string;
    name: string;
    description?: string | undefined;
    parents?: readonly string[] | undefined;
  }>;
  /** userId → group ids. */
  memberships?: Record<string, readonly string[]>;
  /** userId → manager userId. */
  reportingEdges?: Record<string, string>;
  /** userId → org ids. */
  orgs?: Record<string, readonly string[]>;
  /** Users to ensure exist (unlisted users are untouched). */
  users?: Array<{ userId: string; active?: boolean | undefined }>;
}

export interface DirectoryImportResult {
  warnings: string[];
  virtualParents: Array<{ id: string; members: string[] }>;
}

export class AlfizApplication implements AlfizProvider {
  readonly catalog: AnyCatalog;
  readonly resolveAncestors: AncestryResolver;

  private readonly storage: StorageDriver;
  private readonly orgRoot: boolean;
  private readonly now: () => number;
  private readonly newId: () => string;
  private readonly listeners = new Set<InvalidationListener>();

  constructor(options: ApplicationOptions) {
    this.catalog = options.catalog;
    this.storage = options.storage;
    this.orgRoot = options.orgRoot ?? true;
    this.now = options.clock ?? Date.now;
    this.newId = options.ids ?? randomUUID;
    this.resolveAncestors = options.ancestry ?? (() => []);
  }

  // -- events ---------------------------------------------------------------

  onInvalidate(listener: InvalidationListener): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  private emit(event: InvalidationEvent): void {
    for (const listener of this.listeners) listener(event);
  }

  private emitSubject(subject: SubjectId): void {
    this.emit({ type: "subject", subject });
    if (subject.startsWith("user:")) {
      this.emit({ type: "user", userId: subject.slice("user:".length) });
    }
  }

  /**
   * The host application owns the object hierarchy behind
   * `resolveAncestors`, so only it knows when a resource moved. Call this
   * from the code path that changes a parent pointer: it emits the `scope`
   * invalidation event that busts cached ancestor chains immediately —
   * "moving a sensitive document into a restricted folder must take effect
   * at once". Without it, staleness is bounded only by the client's
   * object-chain TTL.
   */
  notifyScopeMoved(scope: ScopeId): void {
    this.emit({ type: "scope", scope });
  }

  private async audit(
    provenance: Provenance,
    action: string,
    target: string,
    detail?: unknown,
  ): Promise<void> {
    const event: AuditEvent = {
      id: this.newId(),
      at: this.now(),
      actor: actorOf(provenance),
      action,
      target,
      ...(detail === undefined ? {} : { detail }),
    };
    await this.storage.appendAudit(event);
  }

  private requireOrgRoot(what: string): void {
    if (!this.orgRoot) {
      throw new ProviderWriteRejectedError(
        `${what} is organizational-domain data: this Application is not the org root and holds it as a read model`,
        "not_org_root",
      );
    }
  }

  // -- capabilities ---------------------------------------------------------

  async capabilities() {
    const users = await this.storage.listUsers();
    let multiParent = false;
    for (const st of this.catalog.scopeTypes.values()) {
      if (st.multiParent) multiParent = true;
    }
    return {
      orgRoot: this.orgRoot,
      requests: true,
      reporting: users.some((u) => u.managerUserId !== null),
      audit: true,
      multiParent,
    };
  }

  // -- closure supply -------------------------------------------------------

  private async managerChain(userId: string): Promise<string[]> {
    const chain: string[] = [];
    const seen = new Set<string>([userId]);
    let current = (await this.storage.getUser(userId))?.managerUserId ?? null;
    while (current !== null && !seen.has(current)) {
      chain.push(current);
      seen.add(current);
      current = (await this.storage.getUser(current))?.managerUserId ?? null;
    }
    return chain;
  }

  async getSubjectAccess(principal: PrincipalRef): Promise<SubjectAccessData> {
    if ("serviceId" in principal) {
      const closure = [...computeServiceClosure(principal.serviceId)];
      const grants = await this.storage.listGrants({ subjects: closure });
      return {
        userId: null,
        closure,
        grants,
        revokes: [],
        roles: await this.rolesFor(grants),
        managerChain: [],
        unresolvedRoleIds: await this.unresolvedRolesFor(grants),
        active: true,
      };
    }

    const stored = await this.storage.getUser(principal.userId);
    // A principal the identity provider authenticated but Alfiz never
    // provisioned is still a member of `everyone` — public access is an
    // ordinary grant row, and it must reach them. Deny-by-default still
    // holds: without matching rows they can do nothing. Inactive means an
    // EXPLICIT active:false — offboarding, not absence.
    const user: StoredUser = stored ?? {
      userId: principal.userId,
      active: true,
      groupIds: [],
      orgIds: [],
      managerUserId: null,
    };
    const groups = await this.storage.listGroups();
    const groupParents = new Map<string, readonly string[]>(
      groups.map((g) => [g.id, g.parents]),
    );
    const managerChain = await this.managerChain(user.userId);
    const closure = [
      ...computeSubjectClosure({
        userId: user.userId,
        groupIds: user.groupIds,
        groupParents,
        orgIds: user.orgIds,
        managerChain,
      }),
    ];
    const grants = await this.storage.listGrants({ subjects: closure });
    const revokes = await this.storage.listRevokes({ userId: user.userId });
    return {
      userId: user.userId,
      closure,
      grants,
      revokes,
      roles: await this.rolesFor(grants),
      managerChain,
      unresolvedRoleIds: await this.unresolvedRolesFor(grants),
      active: user.active,
    };
  }

  private async rolesFor(grants: readonly GrantRow[]): Promise<RoleRecord[]> {
    const ids = [...new Set(grants.flatMap((g) => (g.roleId ? [g.roleId] : [])))];
    const roles: RoleRecord[] = [];
    for (const id of ids) {
      const role = await this.storage.getRole(id);
      if (role) roles.push(role);
    }
    return roles;
  }

  private async unresolvedRolesFor(
    grants: readonly GrantRow[],
  ): Promise<string[]> {
    const ids = [...new Set(grants.flatMap((g) => (g.roleId ? [g.roleId] : [])))];
    const missing: string[] = [];
    for (const id of ids) {
      if ((await this.storage.getRole(id)) === null) missing.push(id);
    }
    return missing;
  }

  private async contextFor(principal: PrincipalRef): Promise<{
    data: SubjectAccessData;
    ctx: CheckContext;
  }> {
    const data = await this.getSubjectAccess(principal);
    return {
      data,
      ctx: {
        subjectClosure: new Set(data.closure),
        userId: data.userId,
        rows: {
          grants: data.grants,
          revokes: data.revokes,
          roles: new Map(data.roles.map((r) => [r.id, r])),
        },
        now: this.now(),
        grantApplies: (key, grantScope) => this.catalog.appliesAt(key, grantScope),
      },
    };
  }

  // -- row operations -------------------------------------------------------

  private validateGrantInput(input: GrantInput): asserts input is GrantInput {
    const scope = input.scope ?? GLOBAL_SCOPE;
    const scopeIssue = validateScopeId(scope);
    if (scopeIssue) {
      throw new ProviderWriteRejectedError(scopeIssue.reason, "validation");
    }
    if ((input.roleId === undefined) === (input.pattern === undefined)) {
      throw new ProviderWriteRejectedError(
        "a grant carries exactly one of roleId / pattern",
        "validation",
      );
    }
    if (input.pattern !== undefined) {
      const issue = validatePattern(input.pattern);
      if (issue) {
        throw new ProviderWriteRejectedError(issue.reason, "validation");
      }
      if (!this.catalog.isKnownPattern(input.pattern)) {
        throw new ProviderWriteRejectedError(
          `pattern ${JSON.stringify(input.pattern)} references nothing in the catalog`,
          "validation",
        );
      }
      if (!isGlobalScope(scope)) {
        const grantable = this.catalog.validateGrantableAt(input.pattern, scope);
        if (grantable) {
          throw new ProviderWriteRejectedError(grantable.message, "validation");
        }
      }
    }
    if (input.expiresAt !== undefined && input.expiresAt <= this.now()) {
      throw new ProviderWriteRejectedError(
        "expiresAt is already in the past",
        "validation",
      );
    }
  }

  async createGrant(input: GrantInput): Promise<GrantRow> {
    this.validateGrantInput(input);
    const scope = input.scope ?? GLOBAL_SCOPE;
    if (isGlobalScope(scope)) this.requireOrgRoot("a global-scope grant");
    if (input.roleId !== undefined) {
      const role = await this.storage.getRole(input.roleId);
      if (!role) {
        throw new ProviderWriteRejectedError(
          `role ${JSON.stringify(input.roleId)} does not exist`,
          "not_found",
        );
      }
      if (!isGlobalScope(scope)) {
        const grantable = role.patterns.some(
          (p) => this.catalog.validateGrantableAt(p, scope) === null,
        );
        if (!grantable) {
          throw new ProviderWriteRejectedError(
            `role ${JSON.stringify(input.roleId)} has no pattern grantable at ${scope}`,
            "validation",
          );
        }
      }
    }
    const row: GrantRow = {
      id: this.newId(),
      subject: input.subject,
      roleId: input.roleId,
      pattern: input.pattern,
      scope,
      expiresAt: input.expiresAt,
      provenance: input.provenance,
      createdAt: this.now(),
    };
    const invalid = validateGrantRow(row);
    if (invalid) {
      throw new ProviderWriteRejectedError(invalid.reason, "validation");
    }
    await this.storage.insertGrant(row);
    await this.audit(input.provenance, "grant.create", row.id, {
      subject: row.subject,
      roleId: row.roleId,
      pattern: row.pattern,
      scope: row.scope,
      expiresAt: row.expiresAt,
    });
    this.emitSubject(row.subject);
    return row;
  }

  async deleteGrant(grantId: string, provenance: Provenance): Promise<void> {
    if (!this.orgRoot) {
      // Inspect before touching: org-domain rows are not ours to delete, and
      // a delete-then-undo would leave a window where the row is missing.
      const target = (await this.storage.listGrants()).find(
        (r) => r.id === grantId,
      );
      if (!target) {
        throw new ProviderWriteRejectedError("grant not found", "not_found");
      }
      if (isGlobalScope(target.scope)) {
        this.requireOrgRoot("a global-scope grant");
      }
    }
    const row = await this.storage.deleteGrant(grantId);
    if (!row) {
      throw new ProviderWriteRejectedError("grant not found", "not_found");
    }
    await this.audit(provenance, "grant.delete", grantId, {
      subject: row.subject,
    });
    this.emitSubject(row.subject);
  }

  async listGrants(filter?: {
    subject?: SubjectId | undefined;
    scope?: ScopeId | undefined;
  }): Promise<GrantRow[]> {
    return this.storage.listGrants({
      subject: filter?.subject,
      scope: filter?.scope,
    });
  }

  async createRevoke(input: RevokeInput): Promise<RevokeRow> {
    const scope = input.scope ?? GLOBAL_SCOPE;
    if (isGlobalScope(scope)) this.requireOrgRoot("a global-scope revoke");
    const issue = validatePattern(input.pattern);
    if (issue) throw new ProviderWriteRejectedError(issue.reason, "validation");
    if (!this.catalog.isKnownPattern(input.pattern)) {
      // A typo'd revoke would silently fail OPEN — the one direction a
      // mistake here must never take.
      throw new ProviderWriteRejectedError(
        `pattern ${JSON.stringify(input.pattern)} references nothing in the catalog`,
        "validation",
      );
    }
    const scopeIssue = validateScopeId(scope);
    if (scopeIssue) {
      throw new ProviderWriteRejectedError(scopeIssue.reason, "validation");
    }
    const row: RevokeRow = {
      id: this.newId(),
      userId: input.userId,
      pattern: input.pattern,
      scope,
      provenance: input.provenance,
      createdAt: this.now(),
    };
    await this.storage.insertRevoke(row);
    await this.audit(input.provenance, "revoke.create", row.id, {
      userId: row.userId,
      pattern: row.pattern,
      scope: row.scope,
    });
    this.emit({ type: "user", userId: row.userId });
    return row;
  }

  async deleteRevoke(revokeId: string, provenance: Provenance): Promise<void> {
    if (!this.orgRoot) {
      const target = (await this.storage.listRevokes()).find(
        (r) => r.id === revokeId,
      );
      if (!target) {
        throw new ProviderWriteRejectedError("revoke not found", "not_found");
      }
      if (isGlobalScope(target.scope)) {
        this.requireOrgRoot("a global-scope revoke");
      }
    }
    const row = await this.storage.deleteRevoke(revokeId);
    if (!row) {
      throw new ProviderWriteRejectedError("revoke not found", "not_found");
    }
    await this.audit(provenance, "revoke.delete", revokeId, {
      userId: row.userId,
    });
    this.emit({ type: "user", userId: row.userId });
  }

  async listRevokes(filter?: {
    userId?: string | undefined;
  }): Promise<RevokeRow[]> {
    return this.storage.listRevokes(filter);
  }

  // -- requests -------------------------------------------------------------

  /**
   * §9.3: a policy referencing management layers where no reporting
   * hierarchy is populated is a configuration error — surfaced at policy
   * creation for roles, at submission for catalog scope-type policies —
   * never silently skipped. Empty stage lists and layers < 1 are equally
   * unresolvable.
   */
  private async assertPolicyResolvable(
    stages: readonly ApprovalStage[],
  ): Promise<void> {
    if (stages.length === 0) {
      throw new ProviderWriteRejectedError(
        "requestable without a resolvable policy: declare at least one approval stage",
        "validation",
      );
    }
    for (const stage of stages) {
      if (stage.kind !== "management") continue;
      if ((stage.layers ?? 1) < 1) {
        throw new ProviderWriteRejectedError(
          "management layers must be at least 1 (the direct manager)",
          "validation",
        );
      }
      const users = await this.storage.listUsers();
      if (!users.some((u) => u.managerUserId !== null)) {
        throw new ProviderWriteRejectedError(
          "policy references management layers but no reporting hierarchy is populated",
          "validation",
        );
      }
    }
  }

  private async requestability(input: RequestInput): Promise<{
    prompts: readonly import("@alfiz-auth/core").RequestPromptInput[];
    maxDurationMs: number | undefined;
    requireExpiry: boolean;
    stages: readonly ApprovalStage[];
  }> {
    if (input.roleId !== undefined) {
      const role = await this.storage.getRole(input.roleId);
      if (!role) {
        throw new ProviderWriteRejectedError("role not found", "not_found");
      }
      if (!role.requestable) {
        throw new ProviderWriteRejectedError(
          `role ${JSON.stringify(role.name)} is not requestable`,
          "validation",
        );
      }
      const scope = input.scope ?? GLOBAL_SCOPE;
      if (!isGlobalScope(scope)) {
        // Approval writes the row without re-validation, so the same
        // grantability rule as createGrant must hold at submission.
        const grantable = role.patterns.some(
          (p) => this.catalog.validateGrantableAt(p, scope) === null,
        );
        if (!grantable) {
          throw new ProviderWriteRejectedError(
            `role ${JSON.stringify(role.name)} has no pattern grantable at ${scope}`,
            "validation",
          );
        }
      }
      return {
        prompts: role.requestable.prompts ?? [],
        maxDurationMs: role.requestable.maxDurationMs,
        requireExpiry: role.requestable.requireExpiry ?? false,
        stages: role.requestable.stages,
      };
    }
    const scope = input.scope ?? GLOBAL_SCOPE;
    if (isGlobalScope(scope)) {
      throw new ProviderWriteRejectedError(
        "pattern requests need a scope whose type declares requestability; global access is requested through requestable roles",
        "validation",
      );
    }
    const type = scope.slice(0, scope.indexOf(":"));
    const scopeType = this.catalog.scopeTypes.get(type);
    if (!scopeType?.requestable) {
      throw new ProviderWriteRejectedError(
        `scope type ${JSON.stringify(type)} is not requestable`,
        "validation",
      );
    }
    return {
      prompts: scopeType.requestable.prompts ?? [],
      maxDurationMs: scopeType.requestable.maxDurationMs,
      requireExpiry: scopeType.requestable.requireExpiry ?? false,
      stages: scopeType.requestable.policy.stages,
    };
  }

  async submitRequest(input: RequestInput): Promise<AccessRequest> {
    const scope = input.scope ?? GLOBAL_SCOPE;
    if (isGlobalScope(scope)) {
      // Requests are homed where their proposed row would live.
      this.requireOrgRoot("a global-scope access request");
    }
    if ((input.roleId === undefined) === (input.pattern === undefined)) {
      throw new ProviderWriteRejectedError(
        "a request proposes exactly one of roleId / pattern",
        "validation",
      );
    }
    if (input.pattern !== undefined) {
      const issue = validatePattern(input.pattern);
      if (issue) throw new ProviderWriteRejectedError(issue.reason, "validation");
      if (!this.catalog.isKnownPattern(input.pattern)) {
        throw new ProviderWriteRejectedError(
          `pattern ${JSON.stringify(input.pattern)} references nothing in the catalog`,
          "validation",
        );
      }
      if (!isGlobalScope(scope)) {
        const grantable = this.catalog.validateGrantableAt(input.pattern, scope);
        if (grantable) {
          throw new ProviderWriteRejectedError(grantable.message, "validation");
        }
      }
    }
    const requestability = await this.requestability(input);
    await this.assertPolicyResolvable(requestability.stages);
    const problems = validateJustification(
      requestability.prompts,
      input.justification ?? {},
    );
    if (problems.length > 0) {
      throw new ProviderWriteRejectedError(problems.join("; "), "validation");
    }
    const now = this.now();
    let proposedExpiresAt = input.proposedExpiresAt;
    if (proposedExpiresAt !== undefined && proposedExpiresAt <= now) {
      throw new ProviderWriteRejectedError(
        "proposed expiry is already in the past",
        "validation",
      );
    }
    if (requestability.requireExpiry && proposedExpiresAt === undefined) {
      throw new ProviderWriteRejectedError(
        "this access must be time-bound: propose an expiry",
        "validation",
      );
    }
    if (requestability.maxDurationMs !== undefined) {
      if (proposedExpiresAt === undefined) {
        // A maximum-duration policy caps open-ended requests too: omitting
        // the expiry must not evade the cap, so the cap becomes the expiry.
        proposedExpiresAt = now + requestability.maxDurationMs;
      } else if (proposedExpiresAt - now > requestability.maxDurationMs) {
        throw new ProviderWriteRejectedError(
          `proposed duration exceeds the maximum (${requestability.maxDurationMs} ms)`,
          "validation",
        );
      }
    }
    let request: AccessRequest = {
      id: this.newId(),
      requesterUserId: input.requesterUserId,
      roleId: input.roleId,
      pattern: input.pattern,
      scope,
      proposedExpiresAt,
      justification: input.justification ?? {},
      state: "pending",
      stageIndex: 0,
      stages: requestability.stages,
      decisions: [],
      createdAt: now,
    };
    const requester = await this.contextFor({ userId: input.requesterUserId });
    const result = runAutoStages(request, requester.ctx, now, this.catalog.keys);
    request = result.request;
    await this.storage.insertRequest(request);
    await this.audit(
      { kind: "system", note: `request by ${input.requesterUserId}` },
      "request.submit",
      request.id,
      { roleId: input.roleId, pattern: input.pattern, scope },
    );
    if (result.grantPlan) {
      await this.writeGrantFromPlan(result.grantPlan);
    }
    return request;
  }

  private async writeGrantFromPlan(
    plan: Omit<GrantRow, "id">,
  ): Promise<GrantRow> {
    const row: GrantRow = { ...plan, id: this.newId() };
    await this.storage.insertGrant(row);
    await this.audit(row.provenance, "grant.create", row.id, {
      subject: row.subject,
      roleId: row.roleId,
      pattern: row.pattern,
      scope: row.scope,
      expiresAt: row.expiresAt,
    });
    this.emitSubject(row.subject);
    return row;
  }

  private async canDecide(
    request: AccessRequest,
    deciderUserId: string,
  ): Promise<boolean> {
    const stage = request.stages[request.stageIndex];
    const decider = await this.contextFor({ userId: deciderUserId });
    if (!decider.data.active) return false;
    const requesterChain = await this.managerChain(request.requesterUserId);
    if (
      stage &&
      canDecideStage(
        stage,
        { userId: deciderUserId, ctx: decider.ctx },
        requesterChain,
      )
    ) {
      return true;
    }
    // Administrative override: holders of the Alfiz approvals permission may
    // decide any stage — the escape hatch for stages nobody can fill.
    return checkKey(
      decider.ctx,
      `${ALFIZ_INTERNAL_NAMESPACE}.requests.decide_request`,
      [GLOBAL_SCOPE],
    );
  }

  async decideRequest(
    requestId: string,
    decision: {
      deciderUserId: string;
      decision: "approved" | "denied";
      note?: string | undefined;
    },
  ): Promise<AccessRequest> {
    // Decisions are serialized per request: two concurrent deciders must not
    // both apply (a denial overwritten by an approval, duplicate grants).
    return this.storage.runExclusive(`request:${requestId}`, async () => {
      const request = await this.storage.getRequest(requestId);
      if (!request) {
        throw new ProviderWriteRejectedError("request not found", "not_found");
      }
      if (request.state !== "pending") {
        throw new ProviderWriteRejectedError(
          `request is ${request.state}`,
          "conflict",
        );
      }
      // Requests are homed where their proposed row would live: deciding a
      // global-scope request is an org-domain write.
      if (isGlobalScope(request.scope)) {
        this.requireOrgRoot("deciding a global-scope access request");
      }
      if (!(await this.canDecide(request, decision.deciderUserId))) {
        throw new ProviderWriteRejectedError(
          "not an approver for the current stage",
          "validation",
        );
      }
      const now = this.now();
      let result = applyDecision(request, {
        decidedBy: decision.deciderUserId,
        decision: decision.decision,
        at: now,
        note: decision.note,
      });
      if (result.request.state === "pending") {
        // A human approval may unlock consecutive auto stages.
        const requester = await this.contextFor({
          userId: request.requesterUserId,
        });
        const advanced = runAutoStages(
          result.request,
          requester.ctx,
          now,
          this.catalog.keys,
        );
        result = {
          request: advanced.request,
          grantPlan: advanced.grantPlan ?? result.grantPlan,
        };
      }
      if (
        result.grantPlan?.roleId !== undefined &&
        (await this.storage.getRole(result.grantPlan.roleId)) === null
      ) {
        // The role was deleted while the request was pending: approving now
        // would write a dangling-role grant that confers nothing.
        throw new ProviderWriteRejectedError(
          "the requested role no longer exists",
          "conflict",
        );
      }
      await this.storage.updateRequest(result.request);
      await this.audit(
        { kind: "admin", actorUserId: decision.deciderUserId },
        `request.${decision.decision}`,
        requestId,
        { note: decision.note },
      );
      if (result.grantPlan) {
        await this.writeGrantFromPlan(result.grantPlan);
      }
      return result.request;
    });
  }

  async cancelRequest(
    requestId: string,
    byUserId: string,
  ): Promise<AccessRequest> {
    return this.storage.runExclusive(`request:${requestId}`, async () => {
      const request = await this.storage.getRequest(requestId);
      if (!request) {
        throw new ProviderWriteRejectedError("request not found", "not_found");
      }
      if (request.requesterUserId !== byUserId) {
        throw new ProviderWriteRejectedError(
          "only the requester may cancel",
          "validation",
        );
      }
      if (request.state !== "pending") {
        throw new ProviderWriteRejectedError(
          `request is ${request.state}`,
          "conflict",
        );
      }
      const cancelled: AccessRequest = {
        ...request,
        state: "cancelled",
        decidedAt: this.now(),
      };
      await this.storage.updateRequest(cancelled);
      await this.audit(
        { kind: "admin", actorUserId: byUserId },
        "request.cancel",
        requestId,
      );
      return cancelled;
    });
  }

  async listRequests(filter?: RequestFilter): Promise<AccessRequest[]> {
    return this.storage.listRequests(filter);
  }

  async listApproverQueue(approverUserId: string): Promise<AccessRequest[]> {
    const pending = await this.storage.listRequests({ state: "pending" });
    const queue: AccessRequest[] = [];
    for (const request of pending) {
      if (await this.canDecide(request, approverUserId)) queue.push(request);
    }
    return queue;
  }

  // -- catalog registration -------------------------------------------------

  async publishCatalog(
    document: CatalogDocument,
    provenance: Provenance,
  ): Promise<{ version: number }> {
    if (document.formatVersion !== 1) {
      throw new ProviderWriteRejectedError(
        `unknown catalog format ${String(document.formatVersion)}`,
        "validation",
      );
    }
    const current = await this.storage.getCatalog();
    const version = (current?.version ?? 0) + 1;
    await this.storage.putCatalog(version, document);
    await this.audit(provenance, "catalog.publish", document.namespace, {
      version,
    });
    this.emit({ type: "catalog" });
    return { version };
  }

  async getPublishedCatalog() {
    return this.storage.getCatalog();
  }

  // -- organizational data --------------------------------------------------

  async listRoles(): Promise<RoleRecord[]> {
    return this.storage.listRoles();
  }

  private validateRolePatterns(patterns: readonly string[]): void {
    for (const pattern of patterns) {
      const issue = validatePattern(pattern);
      if (issue) throw new ProviderWriteRejectedError(issue.reason, "validation");
      if (!this.catalog.isKnownPattern(pattern)) {
        throw new ProviderWriteRejectedError(
          `pattern ${JSON.stringify(pattern)} references nothing in the catalog`,
          "validation",
        );
      }
    }
  }

  async createRole(
    input: RoleInput,
    provenance: Provenance,
  ): Promise<RoleRecord> {
    this.requireOrgRoot("a role definition");
    this.validateRolePatterns(input.patterns);
    if (input.requestable) {
      await this.assertPolicyResolvable(input.requestable.stages);
    }
    const role: RoleRecord = {
      id: this.newId(),
      name: input.name,
      description: input.description,
      patterns: [...input.patterns],
      requestable: input.requestable,
    };
    await this.storage.upsertRole(role);
    await this.audit(provenance, "role.create", role.id, { name: role.name });
    this.emit({ type: "role", roleId: role.id });
    return role;
  }

  async updateRole(
    roleId: string,
    input: Partial<RoleInput>,
    provenance: Provenance,
  ): Promise<RoleRecord> {
    this.requireOrgRoot("a role definition");
    const existing = await this.storage.getRole(roleId);
    if (!existing) {
      throw new ProviderWriteRejectedError("role not found", "not_found");
    }
    if (input.patterns) this.validateRolePatterns(input.patterns);
    if (input.requestable) {
      await this.assertPolicyResolvable(input.requestable.stages);
    }
    const updated: RoleRecord = {
      ...existing,
      ...(input.name !== undefined ? { name: input.name } : {}),
      ...(input.description !== undefined
        ? { description: input.description }
        : {}),
      ...(input.patterns !== undefined ? { patterns: [...input.patterns] } : {}),
      ...(input.requestable !== undefined
        ? { requestable: input.requestable }
        : {}),
    };
    await this.storage.upsertRole(updated);
    await this.audit(provenance, "role.update", roleId, { name: updated.name });
    this.emit({ type: "role", roleId });
    return updated;
  }

  async deleteRole(roleId: string, provenance: Provenance): Promise<void> {
    this.requireOrgRoot("a role definition");
    const holders = await this.storage.listGrants({ roleId });
    if (holders.length > 0) {
      throw new ProviderWriteRejectedError(
        `role is assigned by ${holders.length} grant(s); remove them first`,
        "conflict",
      );
    }
    const pending = (await this.storage.listRequests({ state: "pending" })).filter(
      (r) =>
        r.roleId === roleId ||
        r.stages.some((s) => s.kind === "named_approvers" && s.roleId === roleId),
    );
    if (pending.length > 0) {
      throw new ProviderWriteRejectedError(
        `role is referenced by ${pending.length} pending request(s); decide or cancel them first`,
        "conflict",
      );
    }
    await this.storage.deleteRole(roleId);
    await this.audit(provenance, "role.delete", roleId);
    this.emit({ type: "role", roleId });
  }

  async listGroups(): Promise<UserGroup[]> {
    return this.storage.listGroups();
  }

  async createGroup(
    input: {
      name: string;
      description?: string | undefined;
      parents?: string[] | undefined;
    },
    provenance: Provenance,
  ): Promise<UserGroup> {
    this.requireOrgRoot("a user group");
    return this.storage.runExclusive("groups", async () => {
      for (const parent of input.parents ?? []) {
        if ((await this.storage.getGroup(parent)) === null) {
          throw new ProviderWriteRejectedError(
            `parent group ${JSON.stringify(parent)} does not exist`,
            "not_found",
          );
        }
      }
      const group: UserGroup = {
        id: this.newId(),
        name: input.name,
        description: input.description,
        parents: [...(input.parents ?? [])],
      };
      await this.storage.upsertGroup(group);
      await this.audit(provenance, "group.create", group.id, {
        name: group.name,
      });
      this.emitSubject(`group:${group.id}`);
      return group;
    });
  }

  async setGroupParents(
    groupId: string,
    parents: string[],
    provenance: Provenance,
  ): Promise<UserGroup> {
    this.requireOrgRoot("group parentage");
    return this.storage.runExclusive("groups", async () => {
      const group = await this.storage.getGroup(groupId);
      if (!group) {
        throw new ProviderWriteRejectedError("group not found", "not_found");
      }
      for (const parent of parents) {
        if ((await this.storage.getGroup(parent)) === null) {
          throw new ProviderWriteRejectedError(
            `parent group ${JSON.stringify(parent)} does not exist`,
            "not_found",
          );
        }
      }
      const all = await this.storage.listGroups();
      const candidate = new Map<string, readonly string[]>(
        all.map((g) => [g.id, g.id === groupId ? parents : g.parents]),
      );
      const cycle = findCycle(candidate);
      if (cycle) {
        throw new ProviderWriteRejectedError(
          `cycle: ${cycle.join(" → ")}`,
          "graph_cycle",
        );
      }
      const updated: UserGroup = { ...group, parents: [...parents] };
      await this.storage.upsertGroup(updated);
      await this.audit(provenance, "group.set_parents", groupId, { parents });
      this.emitSubject(`group:${groupId}`);
      return updated;
    });
  }

  async deleteGroup(groupId: string, provenance: Provenance): Promise<void> {
    this.requireOrgRoot("a user group");
    await this.storage.runExclusive("groups", async () => {
      const group = await this.storage.getGroup(groupId);
      if (!group) {
        throw new ProviderWriteRejectedError("group not found", "not_found");
      }
      // Referential integrity, symmetrically: membership, parent references,
      // and subject rows all follow the group out.
      const members = await this.storage.listUsersInGroup(groupId);
      for (const userId of members) {
        const user = await this.storage.getUser(userId);
        if (user) {
          await this.storage.upsertUser({
            ...user,
            groupIds: user.groupIds.filter((g) => g !== groupId),
          });
        }
      }
      for (const other of await this.storage.listGroups()) {
        if (other.id !== groupId && other.parents.includes(groupId)) {
          await this.storage.upsertGroup({
            ...other,
            parents: other.parents.filter((p) => p !== groupId),
          });
          this.emitSubject(`group:${other.id}`);
        }
      }
      const subject: SubjectId = `group:${groupId}`;
      for (const grant of await this.storage.listGrants({ subject })) {
        await this.storage.deleteGrant(grant.id);
        await this.audit(provenance, "grant.delete", grant.id, {
          reason: "group deleted",
        });
      }
      await this.storage.deleteGroup(groupId);
      await this.audit(provenance, "group.delete", groupId, {
        name: group.name,
        members: members.length,
      });
      this.emitSubject(subject);
      for (const userId of members) this.emit({ type: "user", userId });
    });
  }

  async setGroupMembership(
    userId: string,
    groupIds: string[],
    provenance: Provenance,
  ): Promise<void> {
    this.requireOrgRoot("group membership");
    for (const groupId of groupIds) {
      if ((await this.storage.getGroup(groupId)) === null) {
        throw new ProviderWriteRejectedError(
          `group ${JSON.stringify(groupId)} does not exist`,
          "not_found",
        );
      }
    }
    const user = (await this.storage.getUser(userId)) ?? {
      userId,
      active: true,
      groupIds: [],
      orgIds: [],
      managerUserId: null,
    };
    await this.storage.upsertUser({ ...user, groupIds: [...new Set(groupIds)] });
    await this.audit(provenance, "user.set_groups", userId, { groupIds });
    this.emit({ type: "user", userId });
  }

  async getGroupMembers(groupId: string): Promise<string[]> {
    return this.storage.listUsersInGroup(groupId);
  }

  async setReportingEdge(
    userId: string,
    managerUserId: string | null,
    provenance: Provenance,
  ): Promise<void> {
    this.requireOrgRoot("a reporting edge");
    await this.storage.runExclusive("reporting", async () => {
      const user = (await this.storage.getUser(userId)) ?? {
        userId,
        active: true,
        groupIds: [],
        orgIds: [],
        managerUserId: null,
      };
      const oldChain = await this.managerChain(userId);
      if (managerUserId !== null) {
        if (managerUserId === userId) {
          throw new ProviderWriteRejectedError(
            `cycle: ${userId} → ${userId}`,
            "graph_cycle",
          );
        }
        // Walking up from the proposed manager must not reach the user.
        const path: string[] = [managerUserId];
        let current = (await this.storage.getUser(managerUserId))
          ?.managerUserId;
        const seen = new Set<string>([managerUserId]);
        while (current != null && !seen.has(current)) {
          path.push(current);
          if (current === userId) {
            throw new ProviderWriteRejectedError(
              `cycle: ${[userId, ...path].join(" → ")}`,
              "graph_cycle",
            );
          }
          seen.add(current);
          current = (await this.storage.getUser(current))?.managerUserId;
        }
        if (path.includes(userId)) {
          throw new ProviderWriteRejectedError(
            `cycle: ${[userId, ...path].join(" → ")}`,
            "graph_cycle",
          );
        }
        // A manager referenced by an edge is a principal: ensure the record
        // exists so chains walk through them and they can approve.
        if ((await this.storage.getUser(managerUserId)) === null) {
          await this.storage.upsertUser({
            userId: managerUserId,
            active: true,
            groupIds: [],
            orgIds: [],
            managerUserId: null,
          });
        }
      }
      await this.storage.upsertUser({ ...user, managerUserId });
      await this.audit(provenance, "user.set_manager", userId, {
        managerUserId,
      });
      const newChain = await this.managerChain(userId);
      this.emit({ type: "user", userId });
      // The edited user's own implicit groups too: their reports' closures
      // contain orgof:<userId>, and those closures just gained or lost the
      // new ancestors above them.
      for (const m of new Set([userId, ...oldChain, ...newChain])) {
        this.emit({ type: "subject", subject: `directs:${m}` });
        this.emit({ type: "subject", subject: `orgof:${m}` });
      }
    });
  }

  async getReportingEdges(): Promise<Map<string, string>> {
    const edges = new Map<string, string>();
    for (const user of await this.storage.listUsers()) {
      if (user.managerUserId !== null) {
        edges.set(user.userId, user.managerUserId);
      }
    }
    return edges;
  }

  async dissolveVirtualParent(
    groupId: string,
    provenance: Provenance,
  ): Promise<void> {
    this.requireOrgRoot("a virtual parent");
    await this.storage.runExclusive("groups", async () => {
      const parent = await this.storage.getGroup(groupId);
      if (!parent) {
        throw new ProviderWriteRejectedError("group not found", "not_found");
      }
      const all = await this.storage.listGroups();
      const children = all.filter((g) => g.parents.includes(groupId));
      const parentSubject: SubjectId = `group:${groupId}`;
      const now = this.now();
      const parentGrants = await this.storage.listGrants({
        subject: parentSubject,
      });
      const copies = planVirtualParentDissolution({
        parentSubject,
        childSubjects: children.map((c) => `group:${c.id}`),
        grants: parentGrants,
        virtualParentId: groupId,
        now,
      });
      for (const copy of copies) {
        const row: GrantRow = { ...copy, id: this.newId() };
        await this.storage.insertGrant(row);
        await this.audit(row.provenance, "grant.create", row.id, {
          subject: row.subject,
          copiedFrom: groupId,
        });
      }
      for (const grant of parentGrants) {
        await this.storage.deleteGrant(grant.id);
        await this.audit(provenance, "grant.delete", grant.id, {
          reason: "virtual parent dissolved",
          copiedTo: children.map((c) => `group:${c.id}`),
        });
      }
      // Children keep inheriting the parent's own parents, then drift freely.
      for (const child of children) {
        await this.storage.upsertGroup({
          ...child,
          parents: [
            ...new Set([
              ...child.parents.filter((p) => p !== groupId),
              ...parent.parents,
            ]),
          ],
        });
        this.emitSubject(`group:${child.id}`);
      }
      // Direct members (rare for virtual parents, possible after imports)
      // must not keep a dangling membership.
      const members = await this.storage.listUsersInGroup(groupId);
      for (const userId of members) {
        const user = await this.storage.getUser(userId);
        if (user) {
          await this.storage.upsertUser({
            ...user,
            groupIds: user.groupIds.filter((g) => g !== groupId),
          });
          this.emit({ type: "user", userId });
        }
      }
      await this.storage.deleteGroup(groupId);
      await this.audit(provenance, "group.dissolve_virtual_parent", groupId, {
        children: children.map((c) => c.id),
        copiedGrants: copies.length,
      });
      this.emitSubject(parentSubject);
    });
  }

  // -- audit ----------------------------------------------------------------

  async listAuditEvents(filter?: {
    target?: string | undefined;
    limit?: number | undefined;
  }): Promise<AuditEvent[]> {
    return this.storage.listAudit(filter);
  }

  // -- directory ingestion (org-root only) ----------------------------------

  /**
   * Directory ingestion: sync groups, memberships, reporting edges, and org
   * memberships from the identity provider or directory. Cyclic group
   * nesting — which no provider controls — is auto-condensed into virtual
   * parents with a warning. Cycle-forming reporting edges are skipped and
   * reported, never silently combined.
   */
  async importDirectory(
    snapshot: DirectorySnapshot,
    source: string,
  ): Promise<DirectoryImportResult> {
    this.requireOrgRoot("directory ingestion");
    const provenance: Provenance = { kind: "import", source };
    const warnings: string[] = [];
    const virtualParents: Array<{ id: string; members: string[] }> = [];

    await this.storage.runExclusive("groups", async () => {
      if (snapshot.groups) {
        // Condense the MERGED graph — pre-existing groups plus the snapshot
        // (snapshot wins per group) — a snapshot that is individually
        // acyclic can still close a cycle through stored parentage, and a
        // stored cycle would brick every later group-parent edit.
        const existing = await this.storage.listGroups();
        const parentsOf = new Map<string, readonly string[]>(
          existing.map((g) => [g.id, g.parents]),
        );
        for (const g of snapshot.groups) parentsOf.set(g.id, g.parents ?? []);
        const { condenseImportedGraph } = await import("@alfiz-auth/core");
        const condensed = condenseImportedGraph(parentsOf);
        warnings.push(...condensed.warnings);
        virtualParents.push(...condensed.virtualParents);
        const names = new Map(snapshot.groups.map((g) => [g.id, g]));
        const existingById = new Map(existing.map((g) => [g.id, g]));
        for (const [id, parents] of condensed.parentsOf) {
          const known = names.get(id);
          const prior = existingById.get(id);
          const priorParents = prior?.parents ?? null;
          const changed =
            known !== undefined ||
            prior === undefined ||
            priorParents === null ||
            priorParents.length !== parents.length ||
            priorParents.some((p, i) => parents[i] !== p);
          if (!changed) continue;
          await this.storage.upsertGroup({
            id,
            name: known?.name ?? prior?.name ?? id,
            description: known?.description ?? prior?.description,
            parents: [...parents],
            virtual: condensed.virtualParents.some((vp) => vp.id === id)
              ? true
              : prior?.virtual,
          });
        }
        await this.audit(provenance, "directory.import_groups", source, {
          groups: condensed.parentsOf.size,
          condensed: condensed.virtualParents.length,
        });
      }
    });

    for (const spec of snapshot.users ?? []) {
      const user = (await this.storage.getUser(spec.userId)) ?? {
        userId: spec.userId,
        active: true,
        groupIds: [],
        orgIds: [],
        managerUserId: null,
      };
      await this.storage.upsertUser({
        ...user,
        active: spec.active ?? user.active,
      });
    }

    for (const [userId, groupIds] of Object.entries(
      snapshot.memberships ?? {},
    )) {
      const user = (await this.storage.getUser(userId)) ?? {
        userId,
        active: true,
        groupIds: [],
        orgIds: [],
        managerUserId: null,
      };
      await this.storage.upsertUser({
        ...user,
        groupIds: [...new Set(groupIds)],
      });
    }

    for (const [userId, orgIds] of Object.entries(snapshot.orgs ?? {})) {
      const user = (await this.storage.getUser(userId)) ?? {
        userId,
        active: true,
        groupIds: [],
        orgIds: [],
        managerUserId: null,
      };
      await this.storage.upsertUser({ ...user, orgIds: [...new Set(orgIds)] });
    }

    if (snapshot.reportingEdges) {
      await this.storage.runExclusive("reporting", async () => {
        // Cycle detection must see the MERGED edge set: snapshot edges
        // overlaid on stored ones — a partial import composed with stored
        // edges can close a loop the snapshot alone does not contain.
        const merged = new Map<string, string>();
        for (const user of await this.storage.listUsers()) {
          if (user.managerUserId !== null) {
            merged.set(user.userId, user.managerUserId);
          }
        }
        for (const [userId, managerUserId] of Object.entries(
          snapshot.reportingEdges!,
        )) {
          // Walk upward through the merged view as it would look with this
          // edge applied; a loop back to userId is a cycle — skipped with a
          // warning, never written.
          const path = [userId];
          let current: string | undefined = managerUserId;
          let cyclic = false;
          const seen = new Set<string>([userId]);
          while (current !== undefined) {
            path.push(current);
            if (seen.has(current)) {
              cyclic = current === userId;
              break;
            }
            seen.add(current);
            current = merged.get(current);
          }
          if (cyclic) {
            warnings.push(
              `reporting cycle skipped: ${path.join(" → ")} — resolve in the directory`,
            );
            continue;
          }
          merged.set(userId, managerUserId);
          const user = (await this.storage.getUser(userId)) ?? {
            userId,
            active: true,
            groupIds: [],
            orgIds: [],
            managerUserId: null,
          };
          await this.storage.upsertUser({ ...user, managerUserId });
        }
      });
    }

    await this.audit(provenance, "directory.import", source, {
      warnings: warnings.length,
    });
    this.emit({ type: "all" });
    return { warnings, virtualParents };
  }
}

export function createApplication(options: ApplicationOptions): AlfizApplication {
  return new AlfizApplication(options);
}
