import { describe, expect, it } from "vitest";
import { defineCatalog } from "@alfiz-auth/core";
import { generateCatalogTypes } from "../src/codegen.js";

const catalog = defineCatalog({
  namespaces: ["docs"],
  includeAlfizInternal: false,
  permissions: {
    "docs.files.read": true,
    "docs.files.update_file": true,
  },
  scopeTypes: {
    "docs.folder": { parent: null },
    "docs.doc": { parent: "docs.folder" },
  },
});

describe("generateCatalogTypes", () => {
  it("emits the four unions from a published document", () => {
    const source = generateCatalogTypes(catalog.toDocument());
    expect(source).toContain(`export type AlfizKey =`);
    expect(source).toContain(`| "docs.files.read"`);
    expect(source).toContain(`| "docs.files.update_file"`);
    expect(source).toContain(`export type AlfizPattern =`);
    expect(source).toContain(`| "docs.files.*"`);
    expect(source).toContain(`| "docs.*"`);
    expect(source).toContain(
      `export type AlfizScopeType =\n  | "docs.doc"\n  | "docs.folder";`,
    );
    expect(source).toContain(
      "export type AlfizScopeId = \"*\" | `${AlfizScopeType}:${string}`;",
    );
  });

  it("is deterministic: members are sorted, so diffs are the catalog change", () => {
    const doc = catalog.toDocument();
    const source = generateCatalogTypes(doc);
    expect(source).toBe(generateCatalogTypes(doc));
    const keyBlock = source.slice(
      source.indexOf("export type AlfizKey ="),
      source.indexOf(";"),
    );
    const keyLines = keyBlock.split("\n").filter((l) => l.startsWith("  | "));
    expect(keyLines).toEqual([...keyLines].sort());
  });

  it("honors the prefix and degrades to scope-less catalogs", () => {
    const flat = defineCatalog({
      namespaces: ["a"],
      includeAlfizInternal: false,
      permissions: { "a.t.read": true },
    });
    const source = generateCatalogTypes(flat.toDocument(), { prefix: "My" });
    expect(source).toContain("export type MyKey =");
    expect(source).toContain("export type MyScopeType = never;");
    expect(source).toContain(`export type MyScopeId = "*";`);
  });

  it("round-trips: the emitted unions match the catalog's runtime keys", () => {
    const doc = catalog.toDocument();
    const source = generateCatalogTypes(doc);
    for (const leaf of doc.leaves) {
      expect(source).toContain(JSON.stringify(leaf.key));
    }
  });
});
