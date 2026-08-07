/**
 * Adversarial review of the Application's administrative WRITE paths:
 * privilege escalation through grant authorship, the reserved
 * `alfiz_internal.*` namespace, request-flow self-approval, separation of
 * duty, audit-chain integrity, provenance spoofing, and the brown-field
 * referential-integrity discipline.
 *
 * The threat model is a low-privileged but authenticated admin-surface user
 * trying to escalate, and a malicious approver/requester inside the request
 * flow. Every test asserts the SECURE, DESIRED behavior — a failing test is
 * a finding, never a reason to weaken the assertion.
 *
 * Where Alfiz deliberately delegates a responsibility to the host (it is a
 * library, not a service), the test pins the property the host's control
 * depends on — that the delegated hole is at least reviewable from the
 * audit log, and that the delegated defence actually works.
 */

/**
 * KNOWN-OPEN MARKER — `it.fails(...)` in this file.
 *
 * A test written as `it.fails` asserts the SECURE behavior and records that
 * Alfiz does not have it yet: it passes while the finding is open, and turns
 * RED the moment someone fixes the underlying issue. That is the point — the
 * failure is the signal to delete the `.fails` and promote the test, so a
 * fix can never land silently and a finding can never quietly rot.
 *
 * Every one of them is listed in the 0.7.1 changelog entry with its
 * severity. They are open findings, not accepted behavior.
 */
import { describe, expect, it } from "vitest";
import {
  createAlfizClient,
  defineCatalog,
  group,
  parentPointerResolver,
  patternMatchesKey,
} from "@alfiz/core";
import type { AuditEvent, Provenance, StorageDriver } from "@alfiz/core";
import {
  assertCanViewAs,
  computeAuditHash,
  createApplication,
  createSession,
  memoryDriver,
  verifyAuditChain,
} from "@alfiz/application";
import { admin, makeApp, testAncestry, testCatalog } from "./fixtures.js";

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/** A storage driver whose named method fails on demand — the "audit table is
 *  down" / "the insert lost the connection" case the write paths must survive
 *  without leaving an unaudited privileged row behind. */
function flakyDriver(
  method: keyof StorageDriver,
  shouldFail: () => boolean,
): { storage: StorageDriver; inner: StorageDriver } {
  const inner = memoryDriver();
  const storage = new Proxy(inner, {
    get(target, prop, receiver) {
      if (prop === method) {
        return async (...args: unknown[]) => {
          if (shouldFail()) throw new Error(`storage failure in ${String(prop)}`);
          return (
            Reflect.get(target, prop, receiver) as (
              ...a: unknown[]
            ) => Promise<unknown>
          ).apply(target, args);
        };
      }
      return Reflect.get(target, prop, receiver);
    },
  }) as StorageDriver;
  return { storage, inner };
}

const sodCatalog = () =>
  defineCatalog({
    namespaces: ["erp"],
    permissions: {
      "erp.vendors.read": {},
      "erp.vendors.manage_vendor": {},
      "erp.payments.read": {},
      "erp.payments.approve_payment": {},
      "erp.reports.read": {},
    },
    constraints: {
      sod: [
        {
          id: "vendor-vs-payments",
          description: "No one may both manage vendors and approve payments",
          sets: [["erp.vendors.manage_vendor"], ["erp.payments.approve_payment"]],
        },
      ],
    },
  });

const sodApp = (
  enforce?: "reject",
  storage: StorageDriver = memoryDriver(),
) => ({
  storage,
  app: createApplication({
    catalog: sodCatalog(),
    storage,
    ...(enforce ? { sod: { enforce } } : {}),
  }),
});

/** A scope type declared requestable with an auto-approval stage: the
 *  "auto-approve my team asking for folder access" shape from the spec. */
const autoRequestCatalog = () =>
  defineCatalog({
    namespaces: ["vault"],
    permissions: [
      group("vault.files", { scopes: ["vault.folder"] }, {
        "vault.files.read": true,
        "vault.files.update_file": true,
        "vault.files.delete": true,
      }),
    ],
    scopeTypes: {
      "vault.folder": {
        parent: null,
        requestable: {
          prompts: [],
          policy: {
            stages: [
              { kind: "auto", predicate: { type: "in_group", groupId: "team" } },
            ],
          },
        },
      },
    },
  });

// ===========================================================================
// 1. Escalation through grant authorship
// ===========================================================================

describe("grant authorship: containment is the host's, detectability is not", () => {
  it("never consults provenance for an authorization decision", async () => {
    const { app } = makeApp();
    const client = createAlfizClient({
      catalog: testCatalog(),
      provider: app,
      subjectCacheTtlMs: 0,
    });
    // A row that NAMES "root" as its author but is subject-bound to eve.
    await app.createGrant({
      subject: "user:eve",
      pattern: "docs.admin.*",
      provenance: { kind: "admin", actorUserId: "root" },
    });
    // Authority follows the SUBJECT, never the author named in provenance.
    expect(await client.can({ userId: "root" }, "docs.admin.manage_settings")).toBe(
      false,
    );
    expect(await client.can({ userId: "eve" }, "docs.admin.manage_settings")).toBe(
      true,
    );
    // Neither does a forged `request` provenance manufacture an approval.
    await app.createGrant({
      subject: "user:mallory",
      pattern: "docs.files.read",
      provenance: { kind: "request", requestId: "never-existed", approvedBy: "ceo" },
    });
    expect(await app.listRequests()).toEqual([]);
    client.close();
  });

  it("records the exact tuple of a self-authored broad grant in the audit log", async () => {
    // Containment ("you may only grant what you hold") is NOT enforced here —
    // it is the host's admin route that must gate the call. What the library
    // owes in exchange is a reviewable record: the audit entry must name the
    // author and the full tuple, or the delegation has no backstop at all.
    const { app } = makeApp();
    await app.createGrant({
      subject: "user:eve",
      pattern: "*",
      provenance: { kind: "admin", actorUserId: "eve" },
    });
    await app.createGrant({
      subject: "everyone",
      pattern: "alfiz_internal.access.manage_grants",
      provenance: { kind: "admin", actorUserId: "eve" },
    });
    const entries = (await app.listAuditEvents()).filter(
      (e) => e.action === "grant.create",
    );
    expect(entries).toHaveLength(2);
    for (const entry of entries) expect(entry.actor).toBe("eve");
    const details = entries.map((e) => JSON.stringify(e.detail));
    expect(details.some((d) => d.includes('"pattern":"*"'))).toBe(true);
    expect(
      details.some(
        (d) =>
          d.includes('"subject":"everyone"') &&
          d.includes("alfiz_internal.access.manage_grants"),
      ),
    ).toBe(true);
  });

  it("a scoped wildcard never smuggles the reserved admin namespace in", async () => {
    const { app } = makeApp();
    const client = createAlfizClient({
      catalog: testCatalog(),
      provider: app,
      subjectCacheTtlMs: 0,
    });
    // The broadest pattern the grammar admits, pinned to an application scope.
    await app.createGrant({
      subject: "user:eve",
      pattern: "*",
      scope: "docs.folder:9",
      provenance: admin,
    });
    expect(await client.can({ userId: "eve" }, "docs.files.read", "docs.doc:1")).toBe(
      true,
    );
    // alfiz_internal leaves declare no scope types: the scoped wildcard
    // cannot confer them, at the scope or globally.
    expect(
      await client.can({ userId: "eve" }, "alfiz_internal.access.manage_grants"),
    ).toBe(false);
    expect(await client.can({ userId: "eve" }, "alfiz_internal.access.view_as")).toBe(
      false,
    );
    await expect(
      assertCanViewAs(client, "eve"),
    ).rejects.toMatchObject({ reason: "forbidden" });
    client.close();
  });

  it("refuses to write a reserved-namespace grant at an application scope", async () => {
    const { app } = makeApp();
    await expect(
      app.createGrant({
        subject: "user:eve",
        pattern: "alfiz_internal.access.manage_grants",
        scope: "docs.folder:9",
        provenance: admin,
      }),
    ).rejects.toMatchObject({ code: "validation" });
    await expect(
      app.createGrant({
        subject: "user:eve",
        pattern: "alfiz_internal.*",
        scope: "docs.folder:9",
        provenance: admin,
      }),
    ).rejects.toMatchObject({ code: "validation" });
  });
});

// ===========================================================================
// 2. The reserved namespace
// ===========================================================================

describe("the reserved alfiz_internal namespace", () => {
  it("rejects a catalog that declares its own permission inside the reserved namespace", () => {
    // `namespaces:` and `imports:` are reservation-checked; `permissions:`
    // keys are not, so an application catalog can mint arbitrary vocabulary
    // in Alfiz's own admin namespace.
    expect(() =>
      defineCatalog({
        namespaces: ["docs"],
        permissions: {
          "docs.files.read": true,
          "alfiz_internal.access.superuser": true,
        },
      }),
    ).toThrow(/reserved/i);
  });

  it("rejects a catalog that redefines an Alfiz admin key under includeAlfizInternal: false", () => {
    // This is the sharp end: `assertCanViewAs` gates on
    // `catalog.hasKey("alfiz_internal.access.view_as")` plus a check on that
    // key. A catalog that DEFINES the key itself owns the view-as gate.
    expect(() =>
      defineCatalog({
        namespaces: ["docs"],
        includeAlfizInternal: false,
        permissions: {
          "docs.files.read": true,
          "alfiz_internal.access.view_as": true,
        },
      }),
    ).toThrow(/reserved/i);
  });

  it("rejects a collision with a shipped Alfiz admin key", () => {
    expect(() =>
      defineCatalog({
        namespaces: ["docs"],
        permissions: {
          "docs.files.read": true,
          "alfiz_internal.access.view_as": true,
        },
      }),
    ).toThrow();
  });

  it("cannot be impersonated by a near-miss or look-alike namespace", () => {
    // Exact name: reserved.
    expect(() =>
      defineCatalog({
        namespaces: ["alfiz_internal"],
        permissions: { "alfiz_internal.a.read": true },
      }),
    ).toThrow(/reserved/i);
    // Unicode look-alike (Cyrillic а): the segment grammar rejects it before
    // the reservation check ever has to be case-folded.
    expect(() =>
      defineCatalog({
        namespaces: ["аlfiz_internal"],
        permissions: { "аlfiz_internal.a.read": true },
      }),
    ).toThrow();
    // A genuinely different namespace is allowed — and does NOT fall inside
    // `alfiz_internal.*`, so a grant on the reserved subtree cannot reach it
    // and it cannot reach the reserved subtree.
    const near = defineCatalog({
      namespaces: ["alfiz_internal2"],
      permissions: { "alfiz_internal2.a.read": true },
    });
    expect(patternMatchesKey("alfiz_internal.*", "alfiz_internal2.a.read")).toBe(
      false,
    );
    expect(near.keysMatching("alfiz_internal.*")).not.toContain(
      "alfiz_internal2.a.read",
    );
    // The reserved keys present are Alfiz's shipped ones, not the app's.
    expect(near.hasKey("alfiz_internal.access.view_as")).toBe(true);
  });

  it("never lets a request propose access inside the reserved namespace", async () => {
    const { app } = makeApp();
    for (const pattern of [
      "alfiz_internal.access.manage_grants",
      "alfiz_internal.*",
    ]) {
      await expect(
        app.submitRequest({
          requesterUserId: "eve",
          pattern,
          scope: "docs.folder:9",
          justification: { why: "x" },
        }),
      ).rejects.toMatchObject({ code: "validation" });
    }
    expect(await app.listRequests()).toEqual([]);
  });
});

// ===========================================================================
// 3. Request flow: self-approval and decision integrity
// ===========================================================================

describe("request flow: the requester is never the approver", () => {
  it("refuses a requester who holds the named-approver role approving their own request", async () => {
    const { app } = makeApp();
    const owner = await app.createRole(
      { name: "Owner", patterns: ["docs.*"] },
      admin,
    );
    // eve is a legitimate approver for OTHER people's requests…
    await app.createGrant({ subject: "user:eve", roleId: owner.id, provenance: admin });
    const elevated = await app.createRole(
      {
        name: "Settings admin",
        patterns: ["docs.admin.manage_settings"],
        requestable: { stages: [{ kind: "named_approvers", roleId: owner.id }] },
      },
      admin,
    );
    const request = await app.submitRequest({
      requesterUserId: "eve",
      roleId: elevated.id,
    });
    // …but not for her own. Maker and checker must be different humans.
    await expect(
      app.decideRequest(request.id, {
        deciderUserId: "eve",
        decision: "approved",
      }),
    ).rejects.toThrow(/approver|own request|self/i);
    expect(
      (await app.listGrants({ subject: "user:eve" })).filter(
        (g) => g.roleId === elevated.id,
      ),
    ).toEqual([]);
  });

  it("refuses a requester holding the admin override approving their own request", async () => {
    const { app } = makeApp();
    await app.setReportingEdge("someone", "their-boss", admin);
    // The documented escape hatch for unfillable stages — not a licence to
    // self-serve.
    await app.createGrant({
      subject: "user:eve",
      pattern: "alfiz_internal.requests.decide_request",
      provenance: admin,
    });
    const elevated = await app.createRole(
      {
        name: "Settings admin",
        patterns: ["docs.admin.manage_settings"],
        requestable: { stages: [{ kind: "management" }] },
      },
      admin,
    );
    const request = await app.submitRequest({
      requesterUserId: "eve",
      roleId: elevated.id,
    });
    await expect(
      app.decideRequest(request.id, {
        deciderUserId: "eve",
        decision: "approved",
      }),
    ).rejects.toThrow(/approver|own request|self/i);
    const client = createAlfizClient({
      catalog: testCatalog(),
      provider: app,
      subjectCacheTtlMs: 0,
    });
    expect(
      await client.can({ userId: "eve" }, "docs.admin.manage_settings"),
    ).toBe(false);
    client.close();
  });

  it("never serves a user their own request in the approver queue", async () => {
    const { app } = makeApp();
    const owner = await app.createRole({ name: "Owner", patterns: ["docs.*"] }, admin);
    await app.createGrant({ subject: "user:eve", roleId: owner.id, provenance: admin });
    await app.createGrant({ subject: "user:pat", roleId: owner.id, provenance: admin });
    const elevated = await app.createRole(
      {
        name: "Settings admin",
        patterns: ["docs.admin.manage_settings"],
        requestable: { stages: [{ kind: "named_approvers", roleId: owner.id }] },
      },
      admin,
    );
    const mine = await app.submitRequest({
      requesterUserId: "eve",
      roleId: elevated.id,
    });
    // pat, a peer approver, sees it; eve does not see her own.
    expect((await app.listApproverQueue("pat")).map((r) => r.id)).toEqual([mine.id]);
    expect(await app.listApproverQueue("eve")).toEqual([]);
  });

  it("keeps reporting edges acyclic, so nobody can become their own approver", async () => {
    const { app } = makeApp();
    await expect(app.setReportingEdge("u", "u", admin)).rejects.toMatchObject({
      code: "graph_cycle",
    });
    await app.setReportingEdge("a", "b", admin);
    await expect(app.setReportingEdge("b", "a", admin)).rejects.toMatchObject({
      code: "graph_cycle",
    });
    await app.setReportingEdge("b", "c", admin);
    await expect(app.setReportingEdge("c", "a", admin)).rejects.toMatchObject({
      code: "graph_cycle",
    });
    expect([...(await app.getReportingEdges())].sort()).toEqual([
      ["a", "b"],
      ["b", "c"],
    ]);
  });

  it("decides once and never after cancellation; cancellation is requester-only", async () => {
    const { app } = makeApp();
    await app.setReportingEdge("eve", "jane", admin);
    const role = await app.createRole(
      {
        name: "Reader",
        patterns: ["docs.files.read"],
        requestable: { stages: [{ kind: "management" }] },
      },
      admin,
    );
    // Someone else's cancel is refused.
    const r1 = await app.submitRequest({ requesterUserId: "eve", roleId: role.id });
    await expect(app.cancelRequest(r1.id, "jane")).rejects.toThrow(/requester/);
    await expect(app.cancelRequest(r1.id, "root")).rejects.toThrow(/requester/);
    await app.cancelRequest(r1.id, "eve");
    // A cancelled request is not decidable.
    await expect(
      app.decideRequest(r1.id, { deciderUserId: "jane", decision: "approved" }),
    ).rejects.toMatchObject({ code: "conflict" });

    // A decided request is not re-decidable, and confers exactly one grant.
    const r2 = await app.submitRequest({ requesterUserId: "eve", roleId: role.id });
    await app.decideRequest(r2.id, { deciderUserId: "jane", decision: "approved" });
    await expect(
      app.decideRequest(r2.id, { deciderUserId: "jane", decision: "approved" }),
    ).rejects.toMatchObject({ code: "conflict" });
    await expect(app.cancelRequest(r2.id, "eve")).rejects.toMatchObject({
      code: "conflict",
    });
    expect(await app.listGrants({ subject: "user:eve", roleId: role.id })).toHaveLength(
      1,
    );
  });

  it.fails("refuses a request that proposes the unbounded global pattern", async () => {
    // A requestable scope type declares prompts, a duration cap and WHO
    // approves — never WHAT may be requested. The requester supplies the
    // pattern, so `*` at a requestable scope is a self-service ceiling-free
    // ask for every key grantable at that scope type.
    const { app } = makeApp();
    await expect(
      app.submitRequest({
        requesterUserId: "eve",
        pattern: "*",
        scope: "docs.folder:9",
        justification: { why: "everything please" },
      }),
    ).rejects.toMatchObject({ code: "validation" });
  });

  it.fails("an auto-approval stage never hands the requester a pattern nobody reviewed", async () => {
    const catalog = autoRequestCatalog();
    const app = createApplication({
      catalog,
      storage: memoryDriver(),
      ancestry: parentPointerResolver(() => null),
    });
    await app.createGroup({ id: "team", name: "Team" }, admin);
    await app.setGroupMembership("eve", ["team"], admin);
    // The catalog author meant "my team may self-serve folder access".
    // A bare `*` must not ride that stage into every folder-grantable key.
    await expect(
      app.submitRequest({
        requesterUserId: "eve",
        pattern: "*",
        scope: "vault.folder:secret",
      }),
    ).rejects.toMatchObject({ code: "validation" });
    const client = createAlfizClient({
      catalog,
      provider: app,
      subjectCacheTtlMs: 0,
    });
    expect(
      await client.can({ userId: "eve" }, "vault.files.delete", "vault.folder:secret"),
    ).toBe(false);
    client.close();
  });

  it.fails("freezes the patterns of a role a pending request references", async () => {
    // `deleteRole` already refuses while pending requests reference the role.
    // Rewriting its patterns is the same TOCTOU with a worse outcome: the
    // approver reviews "Reader" and the requester receives whatever the role
    // says at approval time.
    const { app } = makeApp();
    await app.setReportingEdge("eve", "jane", admin);
    const role = await app.createRole(
      {
        name: "Reader",
        patterns: ["docs.files.read"],
        requestable: { stages: [{ kind: "management" }] },
      },
      admin,
    );
    await app.submitRequest({ requesterUserId: "eve", roleId: role.id });
    await expect(
      app.updateRole(role.id, { patterns: ["*"] }, admin),
    ).rejects.toThrow(/pending request/);
  });

  it("attributes a decision to the decider in both the audit log and the grant", async () => {
    const { app } = makeApp();
    const owner = await app.createRole({ name: "Owner", patterns: ["docs.*"] }, admin);
    await app.createGrant({ subject: "user:pat", roleId: owner.id, provenance: admin });
    const elevated = await app.createRole(
      {
        name: "Settings admin",
        patterns: ["docs.admin.manage_settings"],
        requestable: { stages: [{ kind: "named_approvers", roleId: owner.id }] },
      },
      admin,
    );
    const request = await app.submitRequest({
      requesterUserId: "eve",
      roleId: elevated.id,
    });
    await app.decideRequest(request.id, {
      deciderUserId: "pat",
      decision: "approved",
    });
    const approved = (await app.listAuditEvents()).find(
      (e) => e.action === "request.approved",
    );
    expect(approved?.actor).toBe("pat");
    const [grant] = await app.listGrants({
      subject: "user:eve",
      roleId: elevated.id,
    });
    expect(grant?.provenance).toEqual({
      kind: "request",
      requestId: request.id,
      approvedBy: "pat",
    });
  });
});

// ===========================================================================
// 4. Separation of duties
// ===========================================================================

describe("separation of duty", () => {
  it("holds across a single bulk write, not only across separate calls", async () => {
    // `ApplicationOptions.sod` documents `"reject"` as covering BOTH
    // `createGrant` and `createGrants`. Each row in a batch is evaluated
    // against storage before any row is inserted, so the two halves of a
    // constraint never see each other.
    const { app } = sodApp("reject");
    await expect(
      app.createGrants(
        [
          { subject: "user:eve", pattern: "erp.vendors.manage_vendor" },
          { subject: "user:eve", pattern: "erp.payments.approve_payment" },
        ],
        admin,
      ),
    ).rejects.toMatchObject({ code: "conflict" });
    expect(await app.listGrants({ subject: "user:eve" })).toEqual([]);
    expect(await app.listSodViolations()).toEqual([]);
  });

  it("refuses the second side however it is ordered, one call at a time", async () => {
    for (const order of [
      ["erp.vendors.manage_vendor", "erp.payments.approve_payment"],
      ["erp.payments.approve_payment", "erp.vendors.manage_vendor"],
    ] as const) {
      const { app } = sodApp("reject");
      await app.createGrant({
        subject: "user:eve",
        pattern: order[0],
        provenance: admin,
      });
      await expect(
        app.createGrant({
          subject: "user:eve",
          pattern: order[1],
          provenance: admin,
        }),
      ).rejects.toMatchObject({ code: "conflict" });
      expect(await app.listSodViolations()).toEqual([]);
    }
  });

  it("refuses one pattern that spans both sides of a constraint", async () => {
    const { app } = sodApp("reject");
    await expect(
      app.createGrant({ subject: "user:eve", pattern: "erp.*", provenance: admin }),
    ).rejects.toMatchObject({ code: "conflict" });
    await expect(
      app.createGrants([{ subject: "user:eve", pattern: "erp.*" }], admin),
    ).rejects.toMatchObject({ code: "conflict" });
    expect(await app.listGrants()).toEqual([]);
  });

  it("detects retroactively: a violation created before enforcement is still reported", async () => {
    // "Grant then constrain" — the ordering bypass. Enforcement is preventive
    // only; the detective report is what must catch history.
    const shared = memoryDriver();
    const permissive = sodApp(undefined, shared).app;
    await permissive.createGrant({
      subject: "user:eve",
      pattern: "erp.vendors.manage_vendor",
      provenance: admin,
    });
    await permissive.createGrant({
      subject: "user:eve",
      pattern: "erp.payments.approve_payment",
      provenance: admin,
    });
    const strict = sodApp("reject", shared).app;
    const report = await strict.listSodViolations();
    expect(report.map((r) => r.userId)).toEqual(["eve"]);
    expect(report[0]!.violations[0]!.sets.map((s) => s.keys)).toEqual([
      ["erp.vendors.manage_vendor"],
      ["erp.payments.approve_payment"],
    ]);
    // A pre-existing violation never blocks an UNRELATED write.
    await strict.createGrant({
      subject: "user:eve",
      pattern: "erp.reports.read",
      provenance: admin,
    });
  });

  it("catches the documented role- and group-shaped escapes in the report", async () => {
    // `ApplicationOptions.sod` states plainly that group- and role-shaped
    // writes are never rejected and remain the report's job. Pin that the
    // report actually closes the loop for both.
    const viaRole = sodApp("reject").app;
    const role = await viaRole.createRole(
      { name: "Vendor admin", patterns: ["erp.vendors.manage_vendor"] },
      admin,
    );
    await viaRole.createGrant({
      subject: "user:eve",
      roleId: role.id,
      provenance: admin,
    });
    await viaRole.updateRole(
      role.id,
      { patterns: ["erp.vendors.manage_vendor", "erp.payments.approve_payment"] },
      admin,
    );
    expect((await viaRole.listSodViolations()).map((r) => r.userId)).toEqual(["eve"]);

    const viaGroup = sodApp("reject").app;
    const payments = await viaGroup.createGroup({ name: "Payments" }, admin);
    await viaGroup.createGrant({
      subject: `group:${payments.id}`,
      pattern: "erp.payments.approve_payment",
      provenance: admin,
    });
    await viaGroup.createGrant({
      subject: "user:mallory",
      pattern: "erp.vendors.manage_vendor",
      provenance: admin,
    });
    await viaGroup.setGroupMembership("mallory", [payments.id], admin);
    expect((await viaGroup.listSodViolations()).map((r) => r.userId)).toEqual([
      "mallory",
    ]);
  });

  it("evaluates per PRINCIPAL — one human behind two ids is the host's linkage", async () => {
    // The boundary, pinned so it cannot regress into a false sense of cover:
    // Alfiz sees user ids, not humans. Two identities split the constraint
    // and the report says nothing. A deployment that needs this collapses
    // the identities (or feeds `userIds` a merged view).
    const { app } = sodApp("reject");
    await app.createGrant({
      subject: "user:eve-work",
      pattern: "erp.vendors.manage_vendor",
      provenance: admin,
    });
    await app.createGrant({
      subject: "user:eve-contractor",
      pattern: "erp.payments.approve_payment",
      provenance: admin,
    });
    expect(await app.listSodViolations()).toEqual([]);
    // But once the ids are the same principal, it is caught immediately.
    await expect(
      app.createGrant({
        subject: "user:eve-work",
        pattern: "erp.payments.approve_payment",
        provenance: admin,
      }),
    ).rejects.toMatchObject({ code: "conflict" });
  });
});

// ===========================================================================
// 5. Audit chain integrity
// ===========================================================================

describe("audit chain integrity", () => {
  const chained = () => {
    const storage = memoryDriver();
    let tick = 1_000;
    const app = createApplication({
      catalog: testCatalog(),
      storage,
      ancestry: testAncestry,
      audit: { hashChain: true },
      clock: () => ++tick,
    });
    return { app, storage };
  };

  const seed = async (app: ReturnType<typeof chained>["app"], n = 5) => {
    for (let i = 0; i < n; i++) {
      await app.createGrant({
        subject: `user:u${i}`,
        pattern: "docs.files.read",
        provenance: admin,
      });
    }
    return app.listAuditEvents();
  };

  it("chains each entry to its predecessor and verifies end to end", async () => {
    const { app } = chained();
    const events = await seed(app);
    expect(events.every((e) => e.hash !== undefined)).toBe(true);
    // Genuinely a chain, not per-entry digests: every entry after the first
    // carries its predecessor's hash.
    for (let i = 1; i < events.length; i++) {
      expect(events[i]!.prevHash).toBe(events[i - 1]!.hash);
    }
    expect(verifyAuditChain(events)).toEqual({ ok: true, hashed: events.length });
  });

  it("detects modification, deletion from the middle, reordering, and insertion", async () => {
    const { app } = chained();
    const events = await seed(app);

    const edited = events.map((e, i) =>
      i === 2 ? { ...e, actor: "mallory", target: "rewritten" } : e,
    );
    expect(verifyAuditChain(edited)).toMatchObject({
      ok: false,
      index: 2,
      reason: "hash_mismatch",
    });

    const middleDeleted = [...events.slice(0, 2), ...events.slice(3)];
    expect(verifyAuditChain(middleDeleted)).toMatchObject({
      ok: false,
      index: 2,
      reason: "broken_link",
    });

    const reordered = [...events];
    [reordered[1], reordered[2]] = [reordered[2]!, reordered[1]!];
    expect(verifyAuditChain(reordered)).toMatchObject({ ok: false });

    const inserted = [
      ...events.slice(0, 2),
      { ...events[0]!, id: "forged" },
      ...events.slice(2),
    ];
    expect(verifyAuditChain(inserted)).toMatchObject({ ok: false });

    const unhashedAppended: AuditEvent[] = [
      ...events,
      { id: "z", at: 99_999, actor: "evil", action: "grant.create", target: "t" },
    ];
    expect(verifyAuditChain(unhashedAppended)).toMatchObject({
      ok: false,
      reason: "unhashed_after_chain_start",
    });
  });

  it("rejects a chain that starts by pointing at a hash it does not contain", async () => {
    const { app } = chained();
    const events = await seed(app);
    // Deleting the first entries and shipping the remainder as if it were a
    // whole log: the surviving head still names a predecessor.
    expect(verifyAuditChain(events.slice(2))).toMatchObject({
      ok: false,
      index: 0,
      reason: "broken_link",
    });
    // Stripping the link to fake a genesis breaks the digest instead.
    const faked = events
      .slice(2)
      .map((e, i) => (i === 0 ? { ...e, prevHash: undefined } : e));
    expect(verifyAuditChain(faked)).toMatchObject({
      ok: false,
      index: 0,
      reason: "hash_mismatch",
    });
    // The legitimate paged-export form still verifies with the carried hash.
    expect(verifyAuditChain(events.slice(2), { priorHash: events[1]!.hash })).toEqual({
      ok: true,
      hashed: 3,
    });
  });

  it("needs the externally anchored head to detect truncation from the END", async () => {
    const { app } = chained();
    const events = await seed(app);
    // The reviewer's out-of-band anchor, taken at export time.
    const anchoredHead = events.at(-1)!.hash;

    const truncated = events.slice(0, 3);
    // A valid prefix IS a valid chain — that is arithmetic, not a bug…
    expect(verifyAuditChain(truncated)).toEqual({ ok: true, hashed: 3 });
    // …and the anchor is exactly what catches it. This is the documented
    // tamper-EVIDENCE boundary, and the head hash is the material the
    // deployment must retain for it to hold.
    expect(truncated.at(-1)!.hash).not.toBe(anchoredHead);
    expect(events.at(-1)!.hash).toBe(anchoredHead);
  });

  it("is unkeyed: database write access plus this source recomputes a valid chain", async () => {
    const { app } = chained();
    const events = await seed(app);
    const anchoredHead = events.at(-1)!.hash;

    // The attacker edits entry 1 and re-hashes everything after it.
    const forged: AuditEvent[] = [];
    let prev: string | null = null;
    for (const [i, event] of events.entries()) {
      const base = i === 1 ? { ...event, actor: "innocent" } : { ...event };
      const hash = computeAuditHash(base, prev);
      forged.push({ ...base, ...(prev !== null ? { prevHash: prev } : {}), hash });
      prev = hash;
    }
    // The chain alone cannot tell — documented, and the reason the head must
    // be anchored somewhere Alfiz does not control.
    expect(verifyAuditChain(forged)).toEqual({ ok: true, hashed: events.length });
    // The anchor still catches it.
    expect(forged.at(-1)!.hash).not.toBe(anchoredHead);
  });

  it("aborts the write when its audit entry cannot be appended", async () => {
    // The Application already reasons that "a written row with no audit
    // entry" is the failure to design against (see `assertProvenance`). A
    // storage-level audit failure must reach the same conclusion.
    let failing = true;
    const { storage, inner } = flakyDriver("appendAudit", () => failing);
    const app = createApplication({
      catalog: testCatalog(),
      storage,
      ancestry: testAncestry,
    });
    await expect(
      app.createGrant({
        subject: "user:eve",
        pattern: "*",
        provenance: { kind: "admin", actorUserId: "eve" },
      }),
    ).rejects.toThrow();
    failing = false;
    expect(await inner.listGrants()).toEqual([]);
    expect(await inner.listAudit()).toEqual([]);
  });

  it("attributes request.submit to the requester", async () => {
    // Everything else in the flow names a person; submission is written with
    // `{ kind: "system" }`, whose note is discarded by `actorOf`, and the
    // detail carries no requester. `listAuditEvents({ actor })` therefore
    // cannot reconstruct who asked for what.
    const { app } = makeApp();
    await app.setReportingEdge("eve", "jane", admin);
    const role = await app.createRole(
      {
        name: "Reader",
        patterns: ["docs.files.read"],
        requestable: { stages: [{ kind: "management" }] },
      },
      admin,
    );
    await app.submitRequest({ requesterUserId: "eve", roleId: role.id });
    const submit = (await app.listAuditEvents()).find(
      (e) => e.action === "request.submit",
    )!;
    const attributable =
      submit.actor === "eve" ||
      (submit.detail as { requesterUserId?: string } | undefined)
        ?.requesterUserId === "eve";
    expect(attributable).toBe(true);
  });

  it("records what a bulk write conferred, not only the ids of the rows", async () => {
    // `grant.create` records subject/pattern/scope; `grant.create_bulk`
    // records only a count and row ids, and `grant.delete` records only the
    // subject — so a batch that is later deleted leaves an audit log that
    // never says what was granted.
    const { app } = makeApp();
    await app.createGrants(
      [
        { subject: "everyone", pattern: "alfiz_internal.access.manage_grants" },
        { subject: "user:eve", pattern: "docs.admin.*" },
      ],
      { kind: "admin", actorUserId: "eve" },
    );
    const bulk = (await app.listAuditEvents()).find(
      (e) => e.action === "grant.create_bulk",
    )!;
    const detail = JSON.stringify(bulk.detail);
    expect(detail).toContain("everyone");
    expect(detail).toContain("alfiz_internal.access.manage_grants");
    expect(detail).toContain("docs.admin.*");
  });
});

// ===========================================================================
// 6. Provenance spoofing
// ===========================================================================

describe("provenance is metadata, validated and never trusted", () => {
  it("cannot corrupt Object.prototype through a crafted payload", async () => {
    const { app } = makeApp();
    const hostile = JSON.parse(
      '{"kind":"admin","actorUserId":"root","__proto__":{"polluted":true},"constructor":{"prototype":{"polluted":true}}}',
    ) as Provenance;
    await app.createGrant({
      subject: "user:eve",
      pattern: "docs.files.read",
      provenance: hostile,
    });
    expect(({} as Record<string, unknown>)["polluted"]).toBeUndefined();
    expect(Object.prototype.hasOwnProperty.call(Object.prototype, "polluted")).toBe(
      false,
    );
    // The audit entry is still correctly attributed and serializable.
    const [entry] = await app.listAuditEvents();
    expect(entry!.actor).toBe("root");
    expect(() => JSON.stringify(entry)).not.toThrow();
  });

  it("persists only the fields the provenance kind declares", async () => {
    // Provenance is validated but never normalized: whatever the caller
    // hands over is written into the grant row verbatim, including a live
    // `__proto__` key that any driver doing `Object.assign`/merge on the
    // round-tripped JSON would apply as a prototype.
    const { app, storage } = makeApp();
    const hostile = JSON.parse(
      '{"kind":"admin","actorUserId":"root","__proto__":{"x":1},"note":"' +
        "A".repeat(4096) +
        '"}',
    ) as Provenance;
    await app.createGrant({
      subject: "user:eve",
      pattern: "docs.files.read",
      provenance: hostile,
    });
    const [row] = await storage.listGrants();
    expect(Object.keys(row!.provenance as object).sort()).toEqual([
      "actorUserId",
      "kind",
    ]);
  });

  it("rejects malformed provenance on every admin write before any row lands", async () => {
    const { app, storage } = makeApp();
    const bad = { kind: "admin", actorUserId: "" } as never;
    await expect(
      app.createGrant({
        subject: "user:eve",
        pattern: "docs.files.read",
        provenance: bad,
      }),
    ).rejects.toMatchObject({ code: "validation" });
    await expect(
      app.createGrants([{ subject: "user:eve", pattern: "docs.files.read" }], bad),
    ).rejects.toMatchObject({ code: "validation" });
    await expect(
      app.createRevoke({ userId: "eve", pattern: "docs.*", provenance: bad }),
    ).rejects.toMatchObject({ code: "validation" });
    expect(await storage.listGrants()).toEqual([]);
    expect(await storage.listRevokes()).toEqual([]);
    expect(await storage.listAudit()).toEqual([]);
  });
});

// ===========================================================================
// 7. Referential-integrity discipline (BROWN-FIELD)
// ===========================================================================

describe("referential integrity: stranded rows and recycled ids", () => {
  it("deleteSubject is what makes a recycled id inherit nothing", async () => {
    const { app } = makeApp();
    const client = createAlfizClient({
      catalog: testCatalog(),
      provider: app,
      subjectCacheTtlMs: 0,
    });
    await app.createGrant({
      subject: "user:u1",
      pattern: "docs.admin.*",
      provenance: admin,
    });
    await app.createGrant({
      subject: "directs:u1",
      pattern: "docs.files.delete",
      provenance: admin,
    });
    await app.deleteSubject("user:u1", admin);
    // The new hire who is handed the recycled id starts from deny-by-default.
    expect(
      await client.can({ userId: "u1" }, "docs.admin.manage_settings"),
    ).toBe(false);
    expect(await app.listGrants({ subject: "directs:u1" })).toEqual([]);
    client.close();
  });

  it("reconcileRows finds and sweeps rows a missed deletion stranded", async () => {
    // The exploit: the host deletes u1 from its own tables and forgets the
    // paired call. A new person is issued the id and inherits admin.
    const { app } = makeApp();
    const client = createAlfizClient({
      catalog: testCatalog(),
      provider: app,
      subjectCacheTtlMs: 0,
    });
    await app.createGrant({
      subject: "user:u1",
      pattern: "docs.admin.*",
      provenance: admin,
    });
    await app.createRevoke({ userId: "u1", pattern: "docs.files.*", provenance: admin });
    await app.createGrant({
      subject: "user:kept",
      pattern: "docs.files.read",
      provenance: admin,
    });
    expect(await client.can({ userId: "u1" }, "docs.admin.manage_settings")).toBe(true);

    // The defence Alfiz does offer, run as a scheduled job.
    const found = await app.reconcileRows({ userExists: (id) => id !== "u1" });
    expect(found.orphanedGrants.map((g) => g.subject)).toEqual(["user:u1"]);
    expect(found.orphanedRevokes).toHaveLength(1);
    expect(found.swept).toBe(false);

    const swept = await app.reconcileRows({
      userExists: (id) => id !== "u1",
      sweep: true,
      provenance: admin,
    });
    expect(swept.swept).toBe(true);
    expect(await client.can({ userId: "u1" }, "docs.admin.manage_settings")).toBe(
      false,
    );
    expect(await client.can({ userId: "kept" }, "docs.files.read")).toBe(true);
    // The sweep is audited like any other removal.
    const audit = await app.listAuditEvents();
    expect(
      audit.some(
        (e) =>
          e.action === "grant.delete" &&
          JSON.stringify(e.detail).includes("reconciliation"),
      ),
    ).toBe(true);
    client.close();
  });

  it("setUserActive(false) suppresses access through EVERY user-subject path", async () => {
    const { app } = makeApp();
    const staff = await app.createGroup({ name: "Staff" }, admin);
    const role = await app.createRole(
      { name: "Editor", patterns: ["docs.files.update_file"] },
      admin,
    );
    await app.setGroupMembership("eve", [staff.id], admin);
    await app.setReportingEdge("report", "eve", admin);
    await app.createGrants(
      [
        { subject: "user:eve", pattern: "docs.files.read" }, // direct
        { subject: `group:${staff.id}`, pattern: "docs.files.delete" }, // group
        { subject: "user:eve", roleId: role.id }, // role
        { subject: "everyone", pattern: "docs.admin.read" }, // everyone
        { subject: "directs:eve", pattern: "docs.admin.manage_settings" }, // implicit
      ],
      admin,
    );
    const client = createAlfizClient({
      catalog: testCatalog(),
      provider: app,
      subjectCacheTtlMs: 0,
    });
    expect(await client.can({ userId: "eve" }, "docs.files.read")).toBe(true);

    await app.setUserActive("eve", false, admin);

    for (const key of [
      "docs.files.read",
      "docs.files.delete",
      "docs.files.update_file",
      "docs.admin.read",
    ] as const) {
      expect(await client.can.fresh({ userId: "eve" }, key)).toBe(false);
    }
    expect(await client.canAny({ userId: "eve" }, "docs.*")).toBe(false);
    expect(
      [...(await client.grantedScopes({ userId: "eve" }, "docs.files.read")).granted],
    ).toEqual([]);
    expect((await client.snapshot({ userId: "eve" })).heldKeys.size).toBe(0);
    expect((await app.exportEntitlements({ userIds: ["eve"] }))[0]!.active).toBe(false);
    // Reversible, as advertised.
    await app.setUserActive("eve", true, admin);
    expect(await client.can.fresh({ userId: "eve" }, "docs.files.read")).toBe(true);
    client.close();
  });

  it("a service principal sharing a person's id is a SEPARATE subject to retire", async () => {
    // `setUserActive` is the USER switch; a machine subject is not a user and
    // is untouched by it. Offboarding a person who also holds an API token
    // must delete that subject too, or the token outlives the account.
    const { app } = makeApp();
    const client = createAlfizClient({
      catalog: testCatalog(),
      provider: app,
      subjectCacheTtlMs: 0,
    });
    await app.createGrant({
      subject: "user:eve",
      pattern: "docs.files.read",
      provenance: admin,
    });
    await app.createGrant({
      subject: "service:eve",
      pattern: "docs.files.read",
      provenance: admin,
    });
    await app.setUserActive("eve", false, admin);
    expect(await client.can({ userId: "eve" }, "docs.files.read")).toBe(false);
    // The paired call is what actually retires the machine subject.
    await app.deleteSubject("service:eve", admin);
    expect(await client.can.fresh({ serviceId: "eve" }, "docs.files.read")).toBe(false);
    client.close();
  });
});

// ===========================================================================
// 8. Ordering and atomicity of the bulk write
// ===========================================================================

describe("createGrants: validate everything first, then write", () => {
  it("leaves no partial rows when a row fails to insert mid-batch", async () => {
    let inserts = 0;
    const { storage, inner } = flakyDriver("insertGrant", () => ++inserts === 2);
    const app = createApplication({
      catalog: testCatalog(),
      storage,
      ancestry: testAncestry,
    });
    await expect(
      app.createGrants(
        [
          { subject: "user:a", pattern: "docs.files.read" },
          { subject: "user:b", pattern: "docs.files.read" },
          { subject: "user:c", pattern: "docs.files.read" },
        ],
        admin,
      ),
    ).rejects.toThrow();
    // A half-imported tenant is exactly what the bulk path exists to prevent:
    // the row that landed before the failure is compensated away.
    expect(await inner.listGrants()).toEqual([]);
    // The log is not silent about it. The batch is audited BEFORE the rows
    // (so a write can never outlive its audit entry), which means a failed
    // batch leaves an entry describing a batch that did not land — and a
    // second entry saying exactly that. Over-reporting a write that was
    // undone beats under-reporting one that survived.
    const actions = (await inner.listAudit()).map((e) => e.action);
    expect(actions).toContain("grant.create_bulk");
    expect(actions).toContain("grant.create_bulk_rolled_back");
  });

  it("rejects the whole batch on one bad input and busts every subject it touched", async () => {
    const { app } = makeApp();
    await expect(
      app.createGrants(
        [
          { subject: "user:a", pattern: "docs.files.read" },
          { subject: "user:b", pattern: "alfiz_internal.access.manage_grants", scope: "docs.folder:9" },
        ],
        admin,
      ),
    ).rejects.toMatchObject({ code: "validation" });
    expect(await app.listGrants()).toEqual([]);

    const events: Array<{ type: string }> = [];
    app.onInvalidate((e) => events.push(e));
    const rows = await app.createGrants(
      [
        { subject: "user:a", pattern: "docs.files.read" },
        { subject: "user:a", pattern: "docs.files.update_file" },
        { subject: "group:staff", pattern: "docs.admin.read" },
        { subject: "everyone", pattern: "docs.files.read" },
      ],
      admin,
    );
    expect(rows).toHaveLength(4);
    const subjects = events.filter((e) => e.type === "subject");
    // One invalidation per DISTINCT subject — all three, not just the first.
    expect(subjects).toHaveLength(3);
  });
});

// ===========================================================================
// 9. The view-as gate (the admin session surface)
// ===========================================================================

describe("view-as: the admin preview never escalates", () => {
  it("gates starting a preview and denies an actor without the reserved key", async () => {
    const { app } = makeApp();
    const client = createAlfizClient({
      catalog: testCatalog(),
      provider: app,
      subjectCacheTtlMs: 0,
    });
    await app.createGrant({
      subject: "user:eve",
      pattern: "docs.files.read",
      provenance: admin,
    });
    await app.createGrant({
      subject: "user:boss",
      pattern: "docs.*",
      provenance: admin,
    });
    await expect(
      createSession(client, {
        actorUserId: "eve",
        viewAs: { kind: "user", userId: "boss" },
      }),
    ).rejects.toMatchObject({
      reason: "forbidden",
      permission: "alfiz_internal.access.view_as",
    });
    await expect(assertCanViewAs(client, "eve")).rejects.toMatchObject({
      reason: "forbidden",
    });
    client.close();
  });

  it("intersects with the actor's real access even when the preview is broader", async () => {
    const { app } = makeApp();
    const client = createAlfizClient({
      catalog: testCatalog(),
      provider: app,
      subjectCacheTtlMs: 0,
    });
    await app.createGrants(
      [
        { subject: "user:eve", pattern: "docs.files.read" },
        { subject: "user:eve", pattern: "alfiz_internal.access.view_as" },
        { subject: "user:boss", pattern: "docs.*" },
      ],
      admin,
    );
    const session = await createSession(client, {
      actorUserId: "eve",
      viewAs: { kind: "user", userId: "boss" },
    });
    expect(await session.can("docs.admin.manage_settings")).toBe(false);
    expect(await session.can("docs.files.read")).toBe(true);
    const snap = await session.snapshot();
    expect(snap.can("docs.admin.manage_settings")).toBe(false);
    expect([...snap.heldKeys]).toEqual(["docs.files.read"]);
    // Attribution never follows the preview.
    expect(snap.actorUserId).toBe("eve");
    client.close();
  });
});
