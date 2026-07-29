/**
 * The Application's half of imported permissions: the write path (can you
 * grant, revoke, and role-bundle vocabulary you do not own?) and the import
 * manifest (what an application CONSUMES, published separately from what it
 * announces).
 *
 * The write path is where imports earn their keep. The dominant use of a
 * foreign key is not `can()` — the application that owns the key evaluates
 * that, at its own scopes — but composition: bundling `zoom.host` into a
 * role, granting it, rendering it in a picker.
 */

import { describe, expect, it } from "vitest";
import type { CatalogDocument, ImportManifest } from "@alfiz/core";
import { ProviderWriteRejectedError, defineCatalog } from "@alfiz/core";
import { createApplication, memoryDriver } from "@alfiz/application";
import { admin, testAncestry } from "./fixtures.js";

const zoomDocument: CatalogDocument = defineCatalog({
  namespaces: ["zoom"],
  includeAlfizInternal: false,
  conventions: { depth: "any" },
  permissions: { "zoom.host": true, "zoom.meetings.read": true },
}).toDocument();

const catalogWith = (
  imports: Parameters<typeof defineCatalog>[0]["imports"],
) =>
  defineCatalog({
    namespaces: ["docs"],
    permissions: {
      "docs.files.read": { scopes: ["docs.folder"] },
      "docs.files.delete": { scopes: ["docs.folder"] },
    },
    scopeTypes: { "docs.folder": { parent: null } },
    imports,
  });

const appWith = (imports: Parameters<typeof defineCatalog>[0]["imports"]) =>
  createApplication({
    catalog: catalogWith(imports),
    storage: memoryDriver(),
    ancestry: testAncestry,
  });

describe("the write path accepts imported vocabulary", () => {
  const app = () =>
    appWith({
      zoom: {
        from: "registry:zoom@^3",
        scopes: ["docs.folder"],
        permissions: { "zoom.host": true, "zoom.meetings.*": true },
      },
    });

  it("grants an imported key", async () => {
    const grant = await app().createGrant({
      subject: "group:hosts",
      pattern: "zoom.host",
      provenance: admin,
    });
    expect(grant.pattern).toBe("zoom.host");
  });

  it("grants an imported subtree at a scope type the import was wired to", async () => {
    const grant = await app().createGrant({
      subject: "group:hosts",
      pattern: "zoom.meetings.*",
      scope: "docs.folder:9",
      provenance: admin,
    });
    expect(grant.scope).toBe("docs.folder:9");
  });

  it("bundles imported and owned patterns in one role — the federation story", async () => {
    const role = await app().createRole(
      { name: "Teacher", patterns: ["docs.files.*", "zoom.host"] },
      admin,
    );
    expect(role.patterns).toEqual(["docs.files.*", "zoom.host"]);
  });

  it("revokes an imported pattern — the negative layer must reach imports too", async () => {
    const instance = app();
    await instance.setUserActive("jane", true, admin);
    const revoke = await instance.createRevoke({
      userId: "jane",
      pattern: "zoom.meetings.*",
      provenance: admin,
    });
    expect(revoke.pattern).toBe("zoom.meetings.*");
  });

  it("rejects a pattern broader than the import", async () => {
    await expect(
      app().createGrant({
        subject: "group:hosts",
        pattern: "zoom.*",
        provenance: admin,
      }),
    ).rejects.toBeInstanceOf(ProviderWriteRejectedError);
  });

  it("rejects a grant at a scope type the import was never wired to", async () => {
    const unwired = appWith({
      zoom: { permissions: { "zoom.meetings.*": true } },
    });
    const error = await unwired
      .createGrant({
        subject: "group:hosts",
        pattern: "zoom.meetings.*",
        scope: "docs.folder:9",
        provenance: admin,
      })
      .catch((e: unknown) => e as Error);
    expect(error).toBeInstanceOf(ProviderWriteRejectedError);
    expect((error as Error).message).toMatch(/no scope types wired/);
  });
});

describe("publishing", () => {
  it("round-trips the import manifest, versioned monotonically", async () => {
    const catalog = catalogWith({
      zoom: {
        from: "registry:zoom@^3",
        document: zoomDocument,
        permissions: { "zoom.host": true },
      },
    });
    const app = createApplication({
      catalog,
      storage: memoryDriver(),
      ancestry: testAncestry,
    });

    expect((await app.capabilities()).imports).toBe(true);
    expect(await app.getPublishedImports()).toBeNull();

    expect(await app.publishImports(catalog.toImportManifest(), admin)).toEqual({
      version: 1,
    });
    expect(await app.publishImports(catalog.toImportManifest(), admin)).toEqual({
      version: 2,
    });

    const stored = await app.getPublishedImports();
    expect(stored?.version).toBe(2);
    expect(stored?.manifest.imports[0]?.namespace).toBe("zoom");
    expect(stored?.manifest.imports[0]?.enumerated).toBe(true);
  });

  it("refuses a manifest importing the publisher's own namespace", async () => {
    const app = appWith({ zoom: { permissions: { "zoom.host": true } } });
    const selfImport: ImportManifest = {
      formatVersion: 1,
      namespace: "docs",
      imports: [
        {
          namespace: "docs",
          from: undefined,
          enumerated: false,
          patterns: ["docs.other.read"],
          keys: [],
          regions: [],
        },
      ],
    };
    await expect(app.publishImports(selfImport, admin)).rejects.toThrow(
      /the publishing application's own namespace/,
    );
  });

  it("refuses a catalog document carrying keys outside its own namespaces", async () => {
    // `toDocument()` already filters imported leaves out, so a document with
    // foreign keys was hand-assembled — and shadowing another application's
    // namespace is the one thing a publish must never be able to do.
    const app = appWith({ zoom: { permissions: { "zoom.host": true } } });
    const shadowing: CatalogDocument = {
      ...zoomDocument,
      namespace: "docs",
      namespaces: ["docs"],
    };
    const error = await app
      .publishCatalog(shadowing, admin)
      .catch((e: unknown) => e as Error);
    expect(error).toBeInstanceOf(ProviderWriteRejectedError);
    expect((error as Error).message).toMatch(/outside its own namespaces/);
  });

  it("publishes owned vocabulary only, so imports never reach the registry", async () => {
    const catalog = catalogWith({
      zoom: { permissions: { "zoom.host": true } },
    });
    const app = createApplication({
      catalog,
      storage: memoryDriver(),
      ancestry: testAncestry,
    });
    await app.publishCatalog(catalog.toDocument(), admin);
    const published = await app.getPublishedCatalog();
    expect(
      published?.document.leaves.some((l) => l.key.startsWith("zoom.")),
    ).toBe(false);
  });

  it("reports imports as unsupported when the driver cannot store them", async () => {
    const storage = memoryDriver();
    delete (storage as { putImports?: unknown }).putImports;
    const app = createApplication({
      catalog: catalogWith({ zoom: { permissions: { "zoom.host": true } } }),
      storage,
      ancestry: testAncestry,
    });
    expect((await app.capabilities()).imports).toBe(false);
    await expect(
      app.publishImports(
        { formatVersion: 1, namespace: "docs", imports: [] },
        admin,
      ),
    ).rejects.toThrow(/does not store import manifests/);
  });
});
