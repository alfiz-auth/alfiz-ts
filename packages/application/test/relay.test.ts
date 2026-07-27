/**
 * The relay seam, wired in-process: the RelayProvider's fetchImpl IS the
 * createRelayHandler function, so every assertion crosses the real wire
 * format — the JSON `{ op, args }` body, the `{ ok, result }` / `{ ok,
 * error }` envelope, the bearer check, and the typed error mapping — with
 * no HTTP server involved.
 */
import { describe, expect, it } from "vitest";
import type { AlfizProvider } from "@alfiz-auth/core";
import { GraphCycleError, ProviderWriteRejectedError } from "@alfiz-auth/core";
import type {
  ApplicationOptions,
  RelayHandlerOptions,
  RelayOp,
  RelayResponse,
} from "@alfiz-auth/application";
import {
  RELAY_PROTOCOL_VERSION,
  RelayTransportError,
  createRelayHandler,
  createRelayProvider,
} from "@alfiz-auth/application";
import { admin, makeApp } from "./fixtures.js";

const SECRET = "relay-secret-from-the-link-step";
const URL = "https://app.example/internal/alfiz-relay";

const overWire =
  (handler: (request: Request) => Promise<Response>): typeof fetch =>
  (input, init) =>
    handler(new Request(input, init));

function linked(
  appOverrides: Partial<ApplicationOptions> = {},
  handlerOverrides: Partial<RelayHandlerOptions> = {},
) {
  const made = makeApp(appOverrides);
  const handler = createRelayHandler({
    application: made.app,
    storage: made.storage,
    secret: SECRET,
    applicationId: "docs",
    ...handlerOverrides,
  });
  const provider = createRelayProvider({
    url: URL,
    secret: SECRET,
    fetchImpl: overWire(handler),
  });
  return { ...made, handler, provider };
}

/** A raw wire exchange, for asserting on the envelope itself. */
async function rawCall(
  handler: (request: Request) => Promise<Response>,
  body: unknown,
  secret = SECRET,
): Promise<{ status: number; body: RelayResponse }> {
  const response = await handler(
    new Request(URL, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${secret}`,
      },
      body: JSON.stringify(body),
    }),
  );
  return { status: response.status, body: (await response.json()) as RelayResponse };
}

describe("relay round trips", () => {
  it("ping, capabilities, grants, and closure supply cross the wire", async () => {
    const { provider } = linked();

    const pong = await provider.ping();
    expect(pong).toEqual({
      protocol: RELAY_PROTOCOL_VERSION,
      application: "docs",
      orgRoot: true,
      hasEpoch: false,
      auditOptIn: false,
    });
    expect((await provider.capabilities()).requests).toBe(true);

    const row = await provider.createGrant({
      subject: "user:u1",
      pattern: "docs.files.read",
      provenance: admin,
    });
    expect(row.subject).toBe("user:u1");
    const listed = await provider.listGrants({ subject: "user:u1" });
    expect(listed).toEqual([row]);

    // The relayed write landed in the same provider methods local code
    // calls: closure supply sees it, with the audit trail attached.
    const access = await provider.getSubjectAccess({ userId: "u1" });
    expect(access.userId).toBe("u1");
    expect(access.closure).toContain("user:u1");
    expect(access.grants).toEqual([row]);
    const audit = await provider.listAuditEvents({ target: row.id });
    expect(audit.map((e) => e.action)).toEqual(["grant.create"]);
  });

  it("getReportingEdges crosses as a plain record and returns as a Map", async () => {
    const { app, handler, provider } = linked();
    await app.setReportingEdge("u1", "boss", admin);

    const raw = await rawCall(handler, { op: "getReportingEdges", args: [] });
    expect(raw.body).toEqual({ ok: true, result: { u1: "boss" } });

    const edges = await provider.getReportingEdges();
    expect(edges).toBeInstanceOf(Map);
    expect(edges.get("u1")).toBe("boss");
  });

  it("resolveAncestors is an op on the wire, a function property in-process", async () => {
    const { provider } = linked();
    expect(await provider.resolveAncestors("docs.doc:1")).toEqual([
      "docs.folder:9",
      "docs.folder:2",
      "*",
    ]);
  });
});

describe("typed error survival", () => {
  it("a not_org_root rejection re-throws as ProviderWriteRejectedError", async () => {
    const { provider } = linked({ orgRoot: false });
    const write = provider.createRole(
      { name: "Reader", patterns: ["docs.files.read"] },
      admin,
    );
    await expect(write).rejects.toBeInstanceOf(ProviderWriteRejectedError);
    await expect(write).rejects.toMatchObject({ code: "not_org_root" });
  });

  it("a group-parent cycle rejection keeps its code and named path", async () => {
    const { provider } = linked();
    await provider.createGroup({ id: "eng", name: "Engineering" }, admin);
    await provider.createGroup(
      { id: "web", name: "Web", parents: ["eng"] },
      admin,
    );
    const write = provider.setGroupParents("eng", ["web"], admin);
    await expect(write).rejects.toBeInstanceOf(ProviderWriteRejectedError);
    await expect(write).rejects.toMatchObject({ code: "graph_cycle" });
    await expect(write).rejects.toThrow(/cycle: /);
  });

  it("a GraphCycleError re-throws as GraphCycleError with the path intact", async () => {
    // The provider surface throws it where a graph write owns its own
    // enforcement; a stub keeps the assertion about the WIRE, not about
    // which site threw.
    const application = {
      setGroupParents: async () => {
        throw new GraphCycleError(["eng", "web", "eng"]);
      },
    } as unknown as AlfizProvider;
    const handler = createRelayHandler({
      application,
      secret: SECRET,
      applicationId: "docs",
    });
    const provider = createRelayProvider({
      url: URL,
      secret: SECRET,
      fetchImpl: overWire(handler),
    });
    const write = provider.setGroupParents("eng", ["web"], admin);
    await expect(write).rejects.toBeInstanceOf(GraphCycleError);
    await expect(write).rejects.toMatchObject({ path: ["eng", "web", "eng"] });
    await expect(write).rejects.toThrow("cycle: eng → web → eng");
  });
});

describe("epoch over the wire", () => {
  it("head and since serve a persisting application's event log", async () => {
    const { provider } = linked({ events: { persist: true } });
    expect((await provider.ping()).hasEpoch).toBe(true);
    expect(await provider.epoch.head()).toBe(0);

    await provider.createGrant({
      subject: "user:u1",
      pattern: "docs.files.read",
      provenance: admin,
    });
    const head = await provider.epoch.head();
    expect(head).toBeGreaterThan(0);
    const since = await provider.epoch.since(0);
    if ("gap" in since) throw new Error("unexpected gap");
    expect(since.upTo).toBe(head);
    expect(since.events).toContainEqual({ type: "subject", subject: "user:u1" });
  });

  it("epoch ops error with code unsupported when events.persist is off", async () => {
    const { handler, provider } = linked();
    const raw = await rawCall(handler, { op: "epoch.head", args: [] });
    expect(raw.status).toBe(200);
    expect(raw.body).toMatchObject({
      ok: false,
      error: { name: "RelayProtocolError", code: "unsupported" },
    });
    await expect(provider.epoch.head()).rejects.toThrow(
      /does not persist events/,
    );
  });
});

describe("org snapshot ops", () => {
  it("export → apply moves the org dataset, and the authority flag reaches the host hook", async () => {
    const root = linked();
    await root.provider.createGroup({ id: "eng", name: "Engineering" }, admin);
    const role = await root.provider.createRole(
      { id: "reader", name: "Reader", patterns: ["docs.files.read"] },
      admin,
    );
    await root.provider.setGroupMembership("u1", ["eng"], admin);
    const grant = await root.provider.createGrant({
      subject: "group:eng",
      roleId: role.id,
      provenance: admin,
    });

    const authorityChanges: boolean[] = [];
    const replica = linked(
      { orgRoot: false },
      { onAuthorityChanged: (orgRoot) => void authorityChanges.push(orgRoot) },
    );

    const snapshot = await root.provider.exportOrgSnapshot();
    expect(snapshot.groups.map((g) => g.id)).toEqual(["eng"]);
    expect(snapshot.roles.map((r) => r.id)).toEqual(["reader"]);
    expect(snapshot.globalGrants).toEqual([grant]);
    expect(snapshot.users.map((u) => u.userId)).toEqual(["u1"]);

    const applied = await replica.provider.applyOrgSnapshot({
      snapshot,
      authority: true,
      source: "demotion:org_test",
    });
    expect(applied).toEqual({ applied: true });
    expect(authorityChanges).toEqual([true]);

    // The replica now serves the dataset — including through closure supply.
    expect((await replica.provider.listGroups()).map((g) => g.id)).toEqual([
      "eng",
    ]);
    expect((await replica.provider.listRoles()).map((r) => r.id)).toEqual([
      "reader",
    ]);
    expect(await replica.provider.listGrants({ scope: "*" })).toEqual([grant]);
    const access = await replica.provider.getSubjectAccess({ userId: "u1" });
    expect(access.closure).toContain("group:eng");
    expect(access.grants).toEqual([grant]);

    // A read-model sync carries authority: false to the same hook, and the
    // provenance line distinguishes the two in the audit log.
    await replica.provider.applyOrgSnapshot({
      snapshot,
      authority: false,
      source: "sync:org_test",
    });
    expect(authorityChanges).toEqual([true, false]);
    const actions = (await replica.provider.listAuditEvents()).map(
      (e) => e.action,
    );
    expect(actions).toContain("org.authority_received");
    expect(actions).toContain("org.sync_applied");
  });

  it("snapshot ops error with code unsupported without the storage option", async () => {
    const { app } = makeApp();
    const handler = createRelayHandler({
      application: app,
      secret: SECRET,
      applicationId: "docs",
    });
    const raw = await rawCall(handler, { op: "org.exportSnapshot", args: [] });
    expect(raw.body).toMatchObject({
      ok: false,
      error: { name: "RelayProtocolError", code: "unsupported" },
    });
  });
});

describe("transport edges", () => {
  it("a wrong secret is a 401, surfaced as RelayTransportError with the status", async () => {
    const { handler } = linked();
    const raw = await rawCall(handler, { op: "ping", args: [] }, "wrong");
    expect(raw.status).toBe(401);
    expect(raw.body).toMatchObject({ ok: false });

    const provider = createRelayProvider({
      url: URL,
      secret: "wrong",
      fetchImpl: overWire(handler),
    });
    const call = provider.ping();
    await expect(call).rejects.toBeInstanceOf(RelayTransportError);
    await expect(call).rejects.toMatchObject({ status: 401 });
  });

  it("non-POST methods are a 405", async () => {
    const { handler } = linked();
    const response = await handler(new Request(URL, { method: "GET" }));
    expect(response.status).toBe(405);
  });

  it("an unknown op is a protocol error, not a crash", async () => {
    const { handler, provider } = linked();
    const raw = await rawCall(handler, { op: "org.selfDestruct", args: [] });
    expect(raw.status).toBe(200);
    expect(raw.body).toMatchObject({
      ok: false,
      error: { name: "RelayProtocolError" },
    });
    if (raw.body.ok) throw new Error("expected an error envelope");
    expect(raw.body.error.message).toContain('unknown op "org.selfDestruct"');
    await expect(
      provider.call("org.selfDestruct" as RelayOp, []),
    ).rejects.toThrow(/unknown op/);
  });
});
