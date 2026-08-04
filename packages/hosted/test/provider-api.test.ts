/**
 * Both ends of the Alfiz Provider API, wired in-process: the
 * HostedProvider's fetchImpl IS the Application's createProviderHandler,
 * so every assertion crosses the real wire format — `POST {base}/v1/{op}`,
 * the named-field JSON bodies, the object results, the typed-error
 * envelope with its status mapping, and the bearer check — with no HTTP
 * server involved.
 */
import { describe, expect, it } from "vitest";
import type { AlfizProvider, InvalidationEvent, ProviderOp } from "@alfiz/core";
import {
  AlfizProviderBase,
  GraphCycleError,
  PROVIDER_API_VERSION,
  ProviderWriteRejectedError,
} from "@alfiz/core";
import type {
  ApplicationOptions,
  ProviderHandlerOptions,
} from "@alfiz/application";
import { createProviderHandler } from "@alfiz/application";
import { HostedProvider, ProviderTransportError, createHostedProvider } from "@alfiz/hosted";
import { admin, makeApp } from "../../application/test/fixtures.js";

const SECRET = "provider-secret-from-the-link-step";
const URL_BASE = "https://app.example/internal/alfiz";

const overWire =
  (handler: (request: Request) => Promise<Response>): typeof fetch =>
  (input, init) =>
    handler(new Request(input, init));

function linked(
  appOverrides: Partial<ApplicationOptions> = {},
  handlerOverrides: Partial<ProviderHandlerOptions> = {},
) {
  const made = makeApp(appOverrides);
  const handler = createProviderHandler({
    application: made.app,
    storage: made.storage,
    secret: SECRET,
    applicationId: "docs",
    ...handlerOverrides,
  });
  const provider = createHostedProvider({
    url: URL_BASE,
    secret: SECRET,
    fetchImpl: overWire(handler),
  });
  return { ...made, handler, provider };
}

/** A raw wire exchange, for asserting on the envelope itself. */
async function rawCall(
  handler: (request: Request) => Promise<Response>,
  op: string,
  body: unknown = {},
  secret = SECRET,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const response = await handler(
    new Request(`${URL_BASE}/v1/${op}`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${secret}`,
      },
      body: JSON.stringify(body),
    }),
  );
  return {
    status: response.status,
    body: (await response.json()) as Record<string, unknown>,
  };
}

describe("the abstract provider base", () => {
  it("both implementations extend AlfizProviderBase — the split, enforced in code", () => {
    const { app, provider } = linked();
    expect(app).toBeInstanceOf(AlfizProviderBase);
    expect(provider).toBeInstanceOf(HostedProvider);
    expect(provider).toBeInstanceOf(AlfizProviderBase);
  });

  it("ingestEvents fans foreign events into the hosted provider's listener stream", () => {
    const { provider } = linked();
    const seen: InvalidationEvent[] = [];
    const unsubscribe = provider.onInvalidate((e) => seen.push(e));
    provider.ingestEvents([{ type: "user", userId: "u1" }, { type: "all" }]);
    expect(seen).toEqual([{ type: "user", userId: "u1" }, { type: "all" }]);
    unsubscribe();
    provider.ingestEvents([{ type: "catalog" }]);
    expect(seen).toHaveLength(2);
  });
});

describe("provider API round trips", () => {
  it("ping, capabilities, grants, and closure supply cross the wire", async () => {
    const { provider } = linked();

    const pong = await provider.ping();
    expect(pong).toEqual({
      api: PROVIDER_API_VERSION,
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
    expect(await provider.countGrants({ subject: "user:u1" })).toBe(1);

    // The remote write landed in the same provider methods local code
    // calls: closure supply sees it, with the audit trail attached.
    const access = await provider.getSubjectAccess({ userId: "u1" });
    expect(access.userId).toBe("u1");
    expect(access.closure).toContain("user:u1");
    expect(access.grants).toEqual([row]);
    const audit = await provider.listAuditEvents({ target: row.id });
    expect(audit.map((e) => e.action)).toEqual(["grant.create"]);
  });

  it("named-field bodies and object results are the wire shape", async () => {
    const { app, handler } = linked();
    await app.setReportingEdge("u1", "boss", admin);

    // getReportingEdges crosses as a plain object…
    const raw = await rawCall(handler, "getReportingEdges");
    expect(raw).toEqual({ status: 200, body: { edges: { u1: "boss" } } });

    // …scalar results are wrapped, never bare…
    const count = await rawCall(handler, "countGrants", { filter: {} });
    expect(count.body).toEqual({ count: 0 });

    // …and list results are named fields of an object.
    const ancestors = await rawCall(handler, "resolveAncestors", {
      scope: "docs.doc:1",
    });
    expect(ancestors.body).toEqual({
      ancestors: ["docs.folder:9", "docs.folder:2", "*"],
    });
  });

  it("getReportingEdges returns as a Map; resolveAncestors is a function property", async () => {
    const { app, provider } = linked();
    await app.setReportingEdge("u1", "boss", admin);
    const edges = await provider.getReportingEdges();
    expect(edges).toBeInstanceOf(Map);
    expect(edges.get("u1")).toBe("boss");
    expect(await provider.resolveAncestors("docs.doc:1")).toEqual([
      "docs.folder:9",
      "docs.folder:2",
      "*",
    ]);
  });
});

describe("typed error survival", () => {
  it("a not_org_root rejection re-throws as ProviderWriteRejectedError, under a 403", async () => {
    const { handler, provider } = linked({ orgRoot: false });
    const write = provider.createRole(
      { name: "Reader", patterns: ["docs.files.read"] },
      admin,
    );
    await expect(write).rejects.toBeInstanceOf(ProviderWriteRejectedError);
    await expect(write).rejects.toMatchObject({ code: "not_org_root" });

    const raw = await rawCall(handler, "createRole", {
      input: { name: "Reader", patterns: ["docs.files.read"] },
      provenance: admin,
    });
    expect(raw.status).toBe(403);
    expect(raw.body).toMatchObject({
      error: { name: "ProviderWriteRejectedError", code: "not_org_root" },
    });
  });

  it("a validation rejection travels under a 422", async () => {
    const { handler } = linked();
    const raw = await rawCall(handler, "createGrant", {
      input: { subject: "user:u1", pattern: "docs.nope.read", provenance: admin },
    });
    expect(raw.status).toBe(422);
    expect(raw.body).toMatchObject({
      error: { name: "ProviderWriteRejectedError", code: "validation" },
    });
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
    const handler = createProviderHandler({
      application,
      secret: SECRET,
      applicationId: "docs",
    });
    const provider = createHostedProvider({
      url: URL_BASE,
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

  it("epoch ops error with code unsupported (501) when events.persist is off", async () => {
    const { handler, provider } = linked();
    const raw = await rawCall(handler, "epoch.head");
    expect(raw.status).toBe(501);
    expect(raw.body).toMatchObject({
      error: { name: "ProviderWriteRejectedError", code: "unsupported" },
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
    const handler = createProviderHandler({
      application: app,
      secret: SECRET,
      applicationId: "docs",
    });
    const raw = await rawCall(handler, "org.exportSnapshot");
    expect(raw.status).toBe(501);
    expect(raw.body).toMatchObject({
      error: { name: "ProviderWriteRejectedError", code: "unsupported" },
    });
  });
});

describe("transport edges", () => {
  it("a wrong secret is a 401, surfaced as ProviderTransportError with the status", async () => {
    const { handler } = linked();
    const raw = await rawCall(handler, "ping", {}, "wrong");
    expect(raw.status).toBe(401);
    expect(raw.body).toMatchObject({ error: { name: "ProviderApiError" } });

    const provider = createHostedProvider({
      url: URL_BASE,
      secret: "wrong",
      fetchImpl: overWire(handler),
    });
    const call = provider.ping();
    await expect(call).rejects.toBeInstanceOf(ProviderTransportError);
    await expect(call).rejects.toMatchObject({ status: 401 });
  });

  it("non-POST methods are a 405", async () => {
    const { handler } = linked();
    const response = await handler(
      new Request(`${URL_BASE}/v1/ping`, { method: "GET" }),
    );
    expect(response.status).toBe(405);
  });

  it("an unknown op is a 404 protocol error, not a crash", async () => {
    const { handler, provider } = linked();
    const raw = await rawCall(handler, "org.selfDestruct");
    expect(raw.status).toBe(404);
    expect(raw.body).toMatchObject({
      error: { name: "ProviderApiError", code: "unknown_op" },
    });
    expect((raw.body.error as { message: string }).message).toContain(
      'unknown operation "org.selfDestruct"',
    );
    await expect(
      provider.call("org.selfDestruct" as ProviderOp, {}),
    ).rejects.toThrow(/unknown operation/);
  });

  it("a non-object body is a 400", async () => {
    const { handler } = linked();
    const response = await handler(
      new Request(`${URL_BASE}/v1/ping`, {
        method: "POST",
        headers: { authorization: `Bearer ${SECRET}` },
        body: JSON.stringify([1, 2, 3]),
      }),
    );
    expect(response.status).toBe(400);
  });

  it("an empty body reads as the empty parameter object", async () => {
    const { handler } = linked();
    const response = await handler(
      new Request(`${URL_BASE}/v1/ping`, {
        method: "POST",
        headers: { authorization: `Bearer ${SECRET}` },
      }),
    );
    expect(response.status).toBe(200);
    expect((await response.json()) as { api: number }).toMatchObject({
      api: PROVIDER_API_VERSION,
    });
  });

  it("a path without /v1/ is a 404", async () => {
    const { handler } = linked();
    const response = await handler(
      new Request("https://app.example/internal/alfiz", {
        method: "POST",
        headers: { authorization: `Bearer ${SECRET}` },
        body: "{}",
      }),
    );
    expect(response.status).toBe(404);
  });
});
