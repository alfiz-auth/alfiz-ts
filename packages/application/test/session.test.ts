import { describe, expect, it } from "vitest";
import { createAlfizClient, defineCatalog } from "@alfiz-auth/core";
import {
  AlfizSession,
  createSession,
  parseViewAs,
  serializeViewAs,
} from "@alfiz-auth/application";
import { admin, makeApp, testCatalog } from "./fixtures.js";

const setup = async () => {
  const { app } = makeApp();
  const client = createAlfizClient({
    catalog: testCatalog(),
    provider: app,
    subjectCacheTtlMs: 0,
  });
  // admin-user: broad real access + view-as rights.
  await app.setGroupMembership("admin-user", [], admin);
  await app.createGrant({ subject: "user:admin-user", pattern: "docs.*", provenance: admin });
  await app.createGrant({
    subject: "user:admin-user",
    pattern: "alfiz_internal.access.view_as",
    provenance: admin,
  });
  await app.createGrant({
    subject: "user:admin-user",
    pattern: "alfiz_internal.access.read",
    provenance: admin,
  });
  // limited-user: one key.
  await app.setGroupMembership("limited-user", [], admin);
  await app.createGrant({
    subject: "user:limited-user",
    pattern: "docs.files.read",
    provenance: admin,
  });
  return { app, client };
};

describe("view-as against a catalog with no Alfiz admin surface", () => {
  it("denies rather than raising a malformed-check error", async () => {
    // `includeAlfizInternal: false` renders no Alfiz admin surface, so
    // `alfiz_internal.access.view_as` is not a key in this catalog. Starting
    // a preview must fail CLOSED — the check being unanswerable is not
    // license to explode on a page that would otherwise render.
    const { app } = makeApp({
      catalog: defineCatalog({
        namespace: "docs",
        includeAlfizInternal: false,
        projects: { docs: { groups: { files: { permissions: { read: true } } } } },
      }),
    });
    const client = createAlfizClient({
      catalog: (app as unknown as { catalog: Parameters<typeof createAlfizClient>[0]["catalog"] })
        .catalog,
      provider: app,
    });
    await app.createGrant({ subject: "user:root", pattern: "*", provenance: admin });
    await expect(
      createSession(client, { actorUserId: "root", viewAs: { kind: "user", userId: "x" } }),
    ).rejects.toMatchObject({ name: "AccessDeniedError", reason: "forbidden" });
    // Sessions without a preview are unaffected.
    const plain = await createSession(client, { actorUserId: "root" });
    expect(await plain.can("docs.files.read")).toBe(true);
  });
});

describe("plain sessions", () => {
  it("pass through the actor's access", async () => {
    const { client } = await setup();
    const session = await createSession(client, { actorUserId: "admin-user" });
    expect(await session.can("docs.files.read")).toBe(true);
    expect(await session.can("docs.admin.manage_settings")).toBe(true);
    expect(session.subjectUserId).toBe("admin-user");
  });

  it("require throws typed denials", async () => {
    const { client } = await setup();
    const session = await createSession(client, { actorUserId: "limited-user" });
    await expect(session.require("docs.admin.manage_settings")).rejects.toMatchObject({
      reason: "forbidden",
    });
  });
});

describe("view-as an individual", () => {
  it("shows the intersection: preview can only narrow, never escalate", async () => {
    const { client } = await setup();
    const session = await createSession(client, {
      actorUserId: "admin-user",
      viewAs: { kind: "user", userId: "limited-user" },
    });
    // limited-user holds it AND the admin really holds it.
    expect(await session.can("docs.files.read")).toBe(true);
    // limited-user lacks it: hidden in preview.
    expect(await session.can("docs.admin.manage_settings")).toBe(false);
    // Data-scoped surfaces adopt the previewed identity…
    expect(session.subjectUserId).toBe("limited-user");
    // …but the real actor is preserved for attribution.
    expect(session.actorUserId).toBe("admin-user");
  });

  it("never escalates: previewing a HIGHER-access user stays bounded by the actor", async () => {
    const { app, client } = await setup();
    // limited-user gets view-as rights but keeps narrow access.
    await app.createGrant({
      subject: "user:limited-user",
      pattern: "alfiz_internal.access.view_as",
      provenance: admin,
    });
    const session = await createSession(client, {
      actorUserId: "limited-user",
      viewAs: { kind: "user", userId: "admin-user" },
    });
    // admin-user holds manage_settings, but the ACTOR does not: denied.
    expect(await session.can("docs.admin.manage_settings")).toBe(false);
    expect(await session.can("docs.files.read")).toBe(true);
  });
});

describe("view-as a role", () => {
  it("the subject's access becomes the role's patterns, still intersected with the actor", async () => {
    const { app, client } = await setup();
    const role = await app.createRole(
      { name: "File clerk", patterns: ["docs.files.read", "docs.files.update_file"] },
      admin,
    );
    const session = await createSession(client, {
      actorUserId: "admin-user",
      viewAs: { kind: "role", roleId: role.id },
    });
    expect(await session.can("docs.files.read")).toBe(true);
    expect(await session.can("docs.files.update_file", "docs.doc:1")).toBe(true);
    // The role lacks admin keys — hidden even though the actor holds them.
    expect(await session.can("docs.admin.manage_settings")).toBe(false);
    // canAny narrows the same way.
    expect(await session.canAny("docs.files.*")).toBe(true);
    expect(await session.canAny("docs.admin.*")).toBe(false);
  });

  it("unknown role previews show nothing", async () => {
    const { client } = await setup();
    const session = new AlfizSession(client, {
      actorUserId: "admin-user",
      viewAs: { kind: "role", roleId: "ghost" },
    });
    expect(await session.can("docs.files.read")).toBe(false);
  });
});

describe("view-as gating", () => {
  it("starting a preview requires alfiz_internal.access.view_as on the REAL access", async () => {
    const { client } = await setup();
    await expect(
      createSession(client, {
        actorUserId: "limited-user",
        viewAs: { kind: "user", userId: "admin-user" },
      }),
    ).rejects.toMatchObject({ permission: "alfiz_internal.access.view_as" });
    // Stopping (no viewAs) is never gated — anti-lockout.
    const plain = await createSession(client, { actorUserId: "limited-user" });
    expect(await plain.can("docs.files.read")).toBe(true);
  });
});

describe("view-as serialization", () => {
  it("round-trips through the cookie encoding", () => {
    expect(parseViewAs(serializeViewAs({ kind: "role", roleId: "r1" }))).toEqual({
      kind: "role",
      roleId: "r1",
    });
    expect(parseViewAs(serializeViewAs({ kind: "user", userId: "u:1" }))).toEqual({
      kind: "user",
      userId: "u:1",
    });
    expect(parseViewAs(null)).toBe(null);
    expect(parseViewAs("garbage")).toBe(null);
    expect(parseViewAs("role:")).toBe(null);
    expect(parseViewAs("other:x")).toBe(null);
  });
});
