/**
 * Adversarial coverage of the Provider API wire seam: the mounted
 * `createProviderHandler` route as an attacker on the network sees it, and
 * `HostedProvider` as it behaves when the far side it trusts is hostile.
 *
 * `provider-api.test.ts` next door proves the contract works. This file
 * proves it does not work for anyone who should not have it, and that the
 * blast radius of the one credential the seam has is exactly what the
 * design intends and no larger. Every assertion states the SECURE
 * behavior — the ones that fail are open findings, not tests to relax.
 *
 * The seam's whole security model is a single shared bearer token: hold it
 * and you can read the entire organization (`org.exportSnapshot`) and
 * replace it (`org.applySnapshot`). There is no per-operation
 * authorization behind it, which makes three things load-bearing —
 * the credential check must be unskippable, the routing that decides WHICH
 * operation runs must not be steerable, and the operations reachable with
 * the token must not be able to violate invariants the local write path
 * enforces.
 */
import { describe, expect, it } from "vitest";
import type { OrgSnapshot } from "@alfiz/core";
import { createAlfizClient } from "@alfiz/core";
import {
  ProviderTransportError,
  createHostedProvider,
  createProviderHandler,
  providerOpFromUrl,
} from "@alfiz/application";
import { admin, makeApp, testCatalog } from "./fixtures.js";

const SECRET = "provider-secret-from-the-link-step";
const URL_BASE = "https://app.example/internal/alfiz";

function linked(secret = SECRET) {
  const made = makeApp();
  const handler = createProviderHandler({
    application: made.app,
    storage: made.storage,
    secret,
    applicationId: "docs",
  });
  return { ...made, handler };
}

/** A raw exchange with full control over headers and the URL. */
const send = (
  handler: (request: Request) => Promise<Response>,
  url: string,
  headers: HeadersInit,
  body: unknown = {},
): Promise<Response> =>
  handler(
    new Request(url, { method: "POST", headers, body: JSON.stringify(body) }),
  );

const authed = (
  handler: (request: Request) => Promise<Response>,
  op: string,
  body: unknown = {},
): Promise<Response> =>
  send(
    handler,
    `${URL_BASE}/v1/${op}`,
    { authorization: `Bearer ${SECRET}`, "content-type": "application/json" },
    body,
  );

const emptySnapshot = (): OrgSnapshot => ({
  groups: [],
  roles: [],
  globalGrants: [],
  globalRevokes: [],
  users: [],
  pendingGlobalRequests: [],
  catalog: null,
});

/** A handler over an org with one group, one role, and one global grant. */
async function seededOrg() {
  const made = linked();
  await made.app.createGroup({ id: "eng", name: "Engineering" }, admin);
  await made.app.createRole(
    { id: "reader", name: "Reader", patterns: ["docs.files.read"] },
    admin,
  );
  await made.app.createGrant({
    subject: "user:u1",
    pattern: "docs.files.read",
    provenance: admin,
  });
  return made;
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

describe("provider API authentication", () => {
  it("no operation runs before the credential check — not even ping", async () => {
    // Ordering matters more here than in an ordinary API: `ping` and
    // `capabilities` are fingerprinting surface (application id, org-root
    // status, whether events persist) and `org.exportSnapshot` is the whole
    // organization. If any of them executed before the bearer check, an
    // unauthenticated scan would map the deployment.
    const { handler, storage } = await seededOrg();
    for (const op of [
      "ping",
      "capabilities",
      "listGrants",
      "getSubjectAccess",
      "org.exportSnapshot",
      "org.applySnapshot",
    ]) {
      const response = await send(handler, `${URL_BASE}/v1/${op}`, {}, {
        snapshot: emptySnapshot(),
        authority: true,
        source: "attacker",
      });
      expect(response.status, `${op} without credentials`).toBe(401);
      const body = (await response.json()) as Record<string, unknown>;
      // Not one field of the answer may describe the deployment.
      expect(Object.keys(body)).toEqual(["error"]);
    }
    // And the unauthenticated org.applySnapshot attempt destroyed nothing.
    expect(await storage.listGroups()).toHaveLength(1);
    expect(await storage.listRoles()).toHaveLength(1);
    expect(await storage.listGrants({ scope: "*" })).toHaveLength(1);
  });

  it("the 401 answer is identical whatever the credential looked like", async () => {
    // A 401 that varies by cause is an oracle: "wrong length" vs "wrong
    // value" vs "wrong scheme" narrows a guess. All five shapes below must
    // be indistinguishable to the caller.
    const { handler } = linked();
    const answers = new Set<string>();
    for (const headers of [
      { authorization: "Bearer x" },
      { authorization: `Bearer ${"x".repeat(4096)}` },
      { authorization: `Bearer ${SECRET.slice(0, -1)}` }, // one byte short
      { authorization: "Basic YWRtaW46YWRtaW4=" },
      {},
    ]) {
      const response = await send(handler, `${URL_BASE}/v1/ping`, headers);
      answers.add(`${response.status} ${await response.text()}`);
    }
    expect(answers.size).toBe(1);
    expect([...answers][0]).toContain('"code":"unauthorized"');
  });

  it("a presented token of any length is rejected without a length-dependent crash", async () => {
    // `secretMatches` sha256-digests BOTH sides before `timingSafeEqual`.
    // That is what makes the comparison safe for attacker-chosen lengths:
    // `timingSafeEqual` throws a RangeError on unequal-length buffers, and
    // a throw here would turn a 401 into a 500 — a length oracle far
    // louder than any timing signal. Digesting first pins both sides at 32
    // bytes, so every wrong token is the same 401.
    const { handler } = linked();
    for (const length of [0, 1, 5, 100, 10_000]) {
      const response = await send(handler, `${URL_BASE}/v1/ping`, {
        authorization: `Bearer ${"a".repeat(length)}`,
      });
      expect(response.status, `token of length ${length}`).toBe(401);
    }
  });

  it("a token that merely contains the secret does not authenticate", async () => {
    // The header is either `Bearer <token>` or a bare token; anything that
    // wraps, pads, or re-schemes the secret must fail rather than be
    // helpfully unwrapped, because "helpfully unwrapped" is how a proxy
    // that stuffs its own value into Authorization becomes a bypass.
    const { handler } = linked();
    for (const value of [
      `Basic ${SECRET}`,
      `Bearer ${SECRET}extra`,
      `Bearer x${SECRET}`,
      `Bearer ${SECRET},${SECRET}`,
      `Token ${SECRET}`,
    ]) {
      const response = await send(handler, `${URL_BASE}/v1/ping`, {
        authorization: value,
      });
      expect(response.status, value).toBe(401);
    }
  });

  it("duplicate Authorization headers do not authenticate", async () => {
    // `Headers.get` joins repeated values with ", ", so a request that
    // pairs a real credential with a second one must not authenticate on
    // the strength of the first — otherwise a header-smuggling proxy that
    // appends rather than replaces becomes an entry point.
    const { handler } = linked();
    const headers = new Headers();
    headers.append("authorization", `Bearer ${SECRET}`);
    headers.append("authorization", "Bearer attacker-supplied");
    expect((await send(handler, `${URL_BASE}/v1/ping`, headers)).status).toBe(401);
  });

  it("a secret too weak to be a credential is refused at construction", async () => {
    // The single shared secret IS the authorization model for this seam,
    // and nothing else validates it. `createServiceKeyShim` in this same
    // package already refuses keys under 16 characters at construction;
    // the handler must hold the same floor, because the brown-field shapes
    // are not exotic: `secret: process.env.ALFIZ_SECRET ?? ""` yields "",
    // and `secret: \`${process.env.ALFIZ_SECRET}\`` yields the literal
    // string "undefined" — a credential an attacker guesses first.
    const { app } = makeApp();
    for (const secret of ["", "   ", "undefined", "null", "x", "1234"]) {
      expect(
        () => createProviderHandler({ application: app, secret, applicationId: "docs" }),
        `secret ${JSON.stringify(secret)} must be refused`,
      ).toThrow();
    }
    // A real link-time token is of course accepted.
    expect(() =>
      createProviderHandler({ application: app, secret: SECRET, applicationId: "docs" }),
    ).not.toThrow();
  });

  it("an empty or near-empty credential authenticates nobody", async () => {
    // The construction guard above is the primary defence: an empty secret
    // can no longer reach a mounted handler at all. This is the second half
    // of the same property — with a REAL secret configured, the comparison
    // must not degenerate for a caller who presents nothing, which is the
    // shape that would make an empty-vs-empty match exploitable if the
    // guard were ever relaxed.
    expect(() => linked("")).toThrow(/at least 16/);
    const { handler } = linked();
    for (const headers of [
      {},
      { authorization: "Bearer " },
      { authorization: "Bearer" },
      { authorization: " " },
      { authorization: "Bearer  " },
    ]) {
      expect(
        (await send(handler, `${URL_BASE}/v1/ping`, headers)).status,
        JSON.stringify(headers),
      ).toBe(401);
    }
  });
});

// ---------------------------------------------------------------------------
// Routing: which operation the request actually reaches
// ---------------------------------------------------------------------------

describe("operation routing", () => {
  it("a second /v1/ segment must not redirect the operation", async () => {
    // `providerOpFromUrl` takes the LAST `/v1/` marker, which is
    // deliberate: a mount can legitimately sit under a base that already
    // contains `/v1/`. But it means an attacker-chosen SUFFIX decides the
    // operation, and the path no longer names what runs. Anything in front
    // of the mount that reasons about the path — an nginx `location` that
    // allows `/v1/ping` for health checks, a WAF rule permitting reads
    // only, an access log an auditor reads — is then desynchronised from
    // the handler. The path below claims `ping` at its first `/v1/`
    // segment and must not serve the entire organization.
    const { handler } = await seededOrg();

    // The legitimate case the last-marker rule exists for still resolves.
    expect(providerOpFromUrl("https://app.example/api/v1/alfiz/v1/ping")).toBe("ping");

    const smuggled = `${URL_BASE}/v1/ping/v1/org.exportSnapshot`;
    expect(providerOpFromUrl(smuggled)).not.toBe("org.exportSnapshot");
    const response = await send(handler, smuggled, {
      authorization: `Bearer ${SECRET}`,
    });
    expect(await response.json()).not.toHaveProperty("snapshot");
    expect(response.status).not.toBe(200);
  });

  it("a malformed percent-escape in the path is a protocol error, not a thrown URIError", async () => {
    // `providerOpFromUrl` calls `decodeURIComponent` outside any try/catch
    // in `createProviderHandler`, so `%FF` — a valid URL, an invalid UTF-8
    // escape — throws out of the mounted route instead of answering. What
    // the caller gets then is whatever the host framework does with an
    // exception: a stack-trace 500 in dev, an unhandled rejection in a
    // hand-rolled adapter. A route that answers must always answer.
    const { handler } = linked();
    const response = await handler(
      new Request(`${URL_BASE}/v1/ping%FF`, {
        method: "POST",
        headers: { authorization: `Bearer ${SECRET}` },
        body: "{}",
      }),
    );
    expect(response.status).toBe(404);
    expect(await response.json()).toMatchObject({
      error: { name: "ProviderApiError" },
    });
  });

  it("an operation name that is not one path segment is refused", async () => {
    // Traversal and encoded separators are contained by the KNOWN_OPS
    // allowlist rather than by path sanitising, which is the right order:
    // whatever the decoder produces, only a name on the list dispatches.
    const { handler } = linked();
    for (const path of [
      `${URL_BASE}/v1/a/b`,
      `${URL_BASE}/v1/ping%2F`,
      `${URL_BASE}/v1/ping%00`,
      `${URL_BASE}/v1/%2e%2e/org.exportSnapshot`,
      `${URL_BASE}/v1/%2e%2e%2forg.exportSnapshot`,
      `${URL_BASE}/v1/PING`,
      `${URL_BASE}/v1/%20ping`,
    ]) {
      const response = await send(handler, path, {
        authorization: `Bearer ${SECRET}`,
      });
      expect(response.status, path).toBe(404);
      expect(await response.json()).toMatchObject({
        error: { name: "ProviderApiError", code: "unknown_op" },
      });
    }
  });
});

// ---------------------------------------------------------------------------
// What the error envelope is allowed to say
// ---------------------------------------------------------------------------

describe("the wire-error envelope", () => {
  it("carries only the contract's four fields — no stack, no internals", async () => {
    // `toProviderWireError` copies `name`, `message`, and the two typed
    // extras. Nothing must widen that: a stack names source paths and
    // module layout, and an unfiltered spread of a driver error would put
    // query text and row contents on the wire.
    const { handler } = linked();
    const cases: Array<[string, unknown]> = [
      ["createGrant", { input: { subject: "user:u1", pattern: "docs.nope.read", provenance: admin } }],
      ["createRole", { input: { name: "R", patterns: ["docs.files.read"] }, provenance: admin }],
      ["epoch.since", { seq: 0 }],
      ["createGrant", {}],
    ];
    for (const [op, body] of cases) {
      const response = await authed(handler, op, body);
      const payload = (await response.json()) as { error?: Record<string, unknown> };
      if (!payload.error) continue;
      for (const key of Object.keys(payload.error)) {
        expect(["name", "message", "code", "detail"], `${op} envelope key`).toContain(key);
      }
      expect(JSON.stringify(payload)).not.toMatch(/\/packages\/|node_modules|at Object\./);
    }
  });

  it("a body missing its named parameter answers typed, never a raw TypeError", async () => {
    // `handleProviderOp` casts the body to `any` and hands fields straight
    // to provider methods, so an omitted parameter dereferences
    // `undefined` deep inside the application and surfaces as a 500 whose
    // envelope reads `{"name":"TypeError","message":"Cannot read properties
    // of undefined (reading 'provenance')"}`. That breaks the contract in
    // two ways: the wire promises typed envelopes (`ProviderApiError` for
    // protocol failures, `ProviderWriteRejectedError` for domain ones), and
    // the message reports internal field names to the caller. Most
    // operations already reject a missing body with a 422; these do not.
    const { handler } = linked();
    for (const op of [
      "getSubjectAccess",
      "check",
      "createGrant",
      "createRevoke",
      "submitRequest",
      "org.applySnapshot",
    ]) {
      const response = await authed(handler, op, {});
      const payload = (await response.json()) as { error: { name: string } };
      expect(payload.error.name, `${op} with an empty body`).not.toBe("TypeError");
      expect(response.status, `${op} with an empty body`).toBeLessThan(500);
    }
  });
});

// ---------------------------------------------------------------------------
// org.applySnapshot — the largest privilege behind the one secret
// ---------------------------------------------------------------------------

describe("org snapshot operations", () => {
  it("validates the whole snapshot before it destroys anything", async () => {
    // `applyOrgSnapshot` deletes and replaces in phases with no validation
    // pass and no transaction: groups, then roles, then users, then the
    // global rows. A malformed row in a LATER phase throws after the
    // earlier phases already deleted. The request below answers 500 — so
    // the caller believes nothing happened — while every group and every
    // role is gone, and the audit append is the last statement in the
    // function, so the destruction is never recorded either.
    const { handler, storage } = await seededOrg();
    const response = await authed(handler, "org.applySnapshot", {
      snapshot: { ...emptySnapshot(), globalGrants: [null] },
      authority: false,
      source: "sync:org_test",
    });

    expect(response.status).toBeLessThan(500);
    expect(await storage.listGroups()).toHaveLength(1);
    expect(await storage.listRoles()).toHaveLength(1);
    expect(await storage.listGrants({ scope: "*" })).toHaveLength(1);
  });

  it("cannot install a group-parent cycle the direct write path rejects", async () => {
    // The module header promises that "provider-side enforcement (org-root
    // gating, validation, graph integrity, audit) applies to remote writes
    // exactly as to local ones". `org.applySnapshot` is the exception: it
    // writes to the StorageDriver directly, past every provider method. A
    // cycle `setGroupParents` answers with `graph_cycle` installs cleanly
    // through the snapshot, and the group graph is then in a state no
    // local code path can produce.
    const { handler, storage } = linked();
    const response = await authed(handler, "org.applySnapshot", {
      snapshot: {
        ...emptySnapshot(),
        groups: [
          { id: "a", name: "A", parents: ["b"] },
          { id: "b", name: "B", parents: ["a"] },
        ],
      },
      authority: false,
      source: "sync:org_test",
    });

    expect(response.status).toBeGreaterThanOrEqual(400);
    expect(await storage.listGroups()).toEqual([]);
  });

  it("cannot mint a grant whose pattern the catalog rejects", async () => {
    // The privilege-escalation shape. `createGrant` refuses a pattern the
    // catalog does not declare with a 422 — a wildcard `"*"` grant is not
    // something the write path will produce. Pushed inside a snapshot the
    // same row lands verbatim, with attacker-chosen `provenance` and
    // `createdAt`, and `check` then answers `allowed: true` for every key
    // in the catalog. One credential must not be able to write rows the
    // credentialed write path forbids.
    const { handler, storage } = linked();
    const response = await authed(handler, "org.applySnapshot", {
      snapshot: {
        ...emptySnapshot(),
        globalGrants: [
          {
            id: "injected",
            subject: "user:u1",
            pattern: "*",
            scope: "*",
            provenance: { kind: "admin", actorUserId: "attacker" },
            createdAt: 0,
          },
        ],
      },
      authority: false,
      source: "sync:org_test",
    });

    expect(response.status).toBeGreaterThanOrEqual(400);
    expect(await storage.listGrants({ scope: "*" })).toEqual([]);

    const check = await authed(handler, "check", {
      principal: { userId: "u1" },
      key: "docs.admin.manage_settings",
    });
    expect(await check.json()).toEqual({ allowed: false });
  });

  it("an authority transfer that cannot take effect must not report success", async () => {
    // `onAuthorityChanged` is optional, and `orgRoot` is a constructor
    // commitment the library cannot flip on its own. Without the hook the
    // handler still applies the dataset and answers `{applied: true}`,
    // while the receiver goes on rejecting org writes. A demotion
    // handshake that reports success without transferring authority is how
    // an organization ends up with no authoritative writer at all — or,
    // if the sending side demotes itself on that answer, with none on
    // either side.
    const made = makeApp({ orgRoot: false });
    const handler = createProviderHandler({
      application: made.app,
      storage: made.storage,
      secret: SECRET,
      applicationId: "docs",
    });
    const response = await authed(handler, "org.applySnapshot", {
      snapshot: emptySnapshot(),
      authority: true,
      source: "demotion:org_test",
    });

    expect(response.status).toBeGreaterThanOrEqual(400);
    expect(await response.json()).toMatchObject({
      error: { code: "unsupported" },
    });
  });

  it("the audited source cannot forge extra records", async () => {
    // `applyOrgSnapshot` writes `actor: \`import:${input.source}\`` with no
    // validation of `source`, and this is the ONE audit line the whole
    // destructive operation produces. A newline in a caller-supplied field
    // that lands in an actor column forges a second record in any
    // line-oriented log sink — and the field is also the only trace of who
    // replaced the organization.
    const { handler, storage } = linked();
    await authed(handler, "org.applySnapshot", {
      snapshot: emptySnapshot(),
      authority: false,
      source: "sync:x\nactor: root\naction: org.authority_received",
    });
    for (const event of await storage.listAudit()) {
      expect(event.actor).not.toMatch(/[\n\r ]/);
    }
  });
});

// ---------------------------------------------------------------------------
// HostedProvider: the consuming side, against a hostile far side
// ---------------------------------------------------------------------------

describe("HostedProvider as a client", () => {
  it("refuses a target the bearer token must not be sent to", async () => {
    // The token is the organization's credential and `call` attaches it to
    // every request to whatever `url` resolves to. `url` is
    // `url.replace(/\/$/, "") + "/v1/" + op` with no parse: "" produces
    // the root-relative "/v1/ping", and "//evil.example" produces a
    // protocol-relative URL that in any fetch implementation resolving
    // against an ambient base sends `Authorization: Bearer <secret>` to a
    // host the configuration never named. Plaintext http is the same
    // exposure on the wire, and this module's own header calls the
    // contract "served over HTTPS".
    expect(() =>
      createHostedProvider({ url: "https://dashboard.example/alfiz", secret: SECRET }),
    ).not.toThrow();
    expect(() =>
      createHostedProvider({ url: "http://127.0.0.1:3000", secret: SECRET }),
    ).not.toThrow(); // loopback is the local-development case

    for (const url of ["", "/internal/alfiz", "//evil.example", "http://app.example"]) {
      expect(
        () => createHostedProvider({ url, secret: SECRET }),
        `target ${JSON.stringify(url)} must be refused`,
      ).toThrow();
    }
  });

  it("does not follow redirects while carrying the bearer token", async () => {
    // `call` passes no `redirect`, so the default `follow` applies and a
    // compromised or merely misconfigured far side can steer the client
    // with a 307. Spec-compliant runtimes strip `Authorization` across an
    // origin change, which is the defence that saves this — but it is a
    // property of the runtime, not of this code, and it does not stop a
    // same-origin redirect from replaying an administrative POST at
    // another path. An administrative client should decline to be
    // redirected at all.
    let init: RequestInit | undefined;
    const provider = createHostedProvider({
      url: URL_BASE,
      secret: SECRET,
      fetchImpl: (async (_url: unknown, requestInit: RequestInit) => {
        init = requestInit;
        return new Response("{}", { status: 200 });
      }) as unknown as typeof fetch,
    });
    await provider.ping();
    expect(["error", "manual"]).toContain(init?.redirect);
  });

  it("never puts the secret in an error, a property, or a stack", async () => {
    // Transport errors are the values most likely to reach a log
    // aggregator or an error tracker. `call` builds its messages from the
    // endpoint, never from the credential — this pins that across all four
    // failure modes.
    const failures: Array<[string, typeof fetch]> = [
      ["network", (async () => {
        throw new Error("connect ECONNREFUSED 10.0.0.1:443");
      }) as unknown as typeof fetch],
      ["non-JSON body", (async () =>
        new Response("<html>bad gateway</html>", { status: 502 })) as unknown as typeof fetch],
      ["API error envelope", (async () =>
        new Response(
          '{"error":{"name":"ProviderApiError","message":"unauthorized","code":"unauthorized"}}',
          { status: 401 },
        )) as unknown as typeof fetch],
      ["non-ok, empty envelope", (async () =>
        new Response("{}", { status: 503 })) as unknown as typeof fetch],
    ];
    for (const [name, fetchImpl] of failures) {
      const provider = createHostedProvider({ url: URL_BASE, secret: SECRET, fetchImpl });
      const error = await provider.ping().then(
        () => new Error("expected a rejection"),
        (e: unknown) => e as Error,
      );
      const serialized =
        JSON.stringify(error, Object.getOwnPropertyNames(error)) + String(error.stack);
      expect(serialized, `${name} must not carry the secret`).not.toContain(SECRET);
    }
  });

  it("a malformed far-side answer is a transport error, never a silent undefined", async () => {
    // A compromised far side is inside this class's threat model — it is
    // the whole reason `call` re-throws typed envelopes rather than
    // trusting statuses. But the SUCCESS path casts blindly: `payload as
    // T`, then `.grants` off it. A `200 {}` therefore hands the caller
    // `undefined` typed as `GrantRow[]`, and a `200 null` throws a raw
    // TypeError from inside the library. Both smuggle a far-side defect
    // into local code as something other than "the far side is broken".
    const answer = (payload: string): typeof fetch =>
      (async () =>
        new Response(payload, {
          status: 200,
          headers: { "content-type": "application/json" },
        })) as unknown as typeof fetch;

    for (const payload of ["null", "{}", "[]", '{"grants":null}']) {
      const provider = createHostedProvider({
        url: URL_BASE,
        secret: SECRET,
        fetchImpl: answer(payload),
      });
      await expect(
        provider.listGrants({ subject: "user:u1" }),
        `listGrants over ${payload}`,
      ).rejects.toBeInstanceOf(ProviderTransportError);
      await expect(
        provider.getReportingEdges(),
        `getReportingEdges over ${payload}`,
      ).rejects.toBeInstanceOf(ProviderTransportError);
    }
  });

  it("a compromised far side cannot make a check answer yes", async () => {
    // The far side is authoritative over the rows it serves — that is the
    // delegation model — but a garbled or truncated closure-supply answer
    // must not be read as "no revokes, therefore allowed". The `active`
    // gate in the client is what holds this: a payload with no `active`
    // field denies before any row is inspected.
    const catalog = testCatalog();
    for (const payload of [
      "{}",
      "null",
      '{"active":true}',
      '{"active":true,"closure":["user:u1"],"grants":[{"id":"g","subject":"user:u1","pattern":"*","scope":"*","provenance":{"kind":"admin","actorUserId":"r"},"createdAt":0}]}',
      '{"userId":"u1","active":true,"closure":["user:u1"],"grants":[],"revokes":[],"roles":[],"managerChain":[],"unresolvedRoleIds":[]}',
    ]) {
      const provider = createHostedProvider({
        url: URL_BASE,
        secret: SECRET,
        fetchImpl: (async () => new Response(payload, { status: 200 })) as unknown as typeof fetch,
      });
      const client = createAlfizClient({ catalog, provider });
      const allowed = await client
        .can({ userId: "u1" }, "docs.files.read")
        .catch(() => "threw" as const);
      expect(allowed, `payload ${payload.slice(0, 40)}`).not.toBe(true);
    }
  });
});

// ---------------------------------------------------------------------------
// Wire data as data
// ---------------------------------------------------------------------------

describe("wire bodies are data, never structure", () => {
  it("__proto__ and constructor keys in a body do not pollute Object.prototype", async () => {
    // `handleProviderOp` reads named fields off a `JSON.parse`d body and
    // passes objects through to upsert paths. `JSON.parse` makes
    // `__proto__` an ordinary own property rather than a setter call, and
    // the storage layer keys by Map rather than by object property — this
    // pins both, across the routing body, a nested input object, and a
    // snapshot row whose id is the dangerous name.
    const { handler } = linked();
    const bodies = [
      '{"__proto__":{"pollutedA":1}}',
      '{"constructor":{"prototype":{"pollutedB":1}}}',
      '{"input":{"__proto__":{"pollutedC":1},"id":"g1","name":"G"},"provenance":{"kind":"admin","actorUserId":"root"}}',
      '{"snapshot":{"groups":[{"id":"__proto__","name":"X","parents":[]}],"roles":[],"globalGrants":[],"globalRevokes":[],"users":[],"pendingGlobalRequests":[],"catalog":null},"authority":false,"source":"sync:x"}',
    ];
    for (const op of ["ping", "createGroup", "org.applySnapshot"]) {
      for (const raw of bodies) {
        await handler(
          new Request(`${URL_BASE}/v1/${op}`, {
            method: "POST",
            headers: {
              authorization: `Bearer ${SECRET}`,
              "content-type": "application/json",
            },
            body: raw,
          }),
        );
      }
    }
    const probe = {} as Record<string, unknown>;
    expect(probe.pollutedA).toBeUndefined();
    expect(probe.pollutedB).toBeUndefined();
    expect(probe.pollutedC).toBeUndefined();
    expect(Object.getPrototypeOf({})).toBe(Object.prototype);
  });

  it("a __proto__ key crosses getReportingEdges as data on both ends", async () => {
    // `getReportingEdges` is the one operation that builds a plain object
    // out of stored keys (`Object.fromEntries`) and rebuilds a Map from it
    // on the consuming side (`Object.entries`). Both directions must treat
    // a hostile user id as a key, not as a prototype.
    const { app, handler } = linked();
    await app.setReportingEdge("__proto__", "boss", admin);
    const provider = createHostedProvider({
      url: URL_BASE,
      secret: SECRET,
      fetchImpl: ((input: RequestInfo | URL, init?: RequestInit) =>
        handler(new Request(input as RequestInfo, init))) as typeof fetch,
    });
    const edges = await provider.getReportingEdges();
    expect(edges.get("__proto__")).toBe("boss");
    expect(({} as Record<string, unknown>).boss).toBeUndefined();
    expect(Object.getPrototypeOf({})).toBe(Object.prototype);
  });
});
