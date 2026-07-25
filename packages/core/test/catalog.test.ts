import { describe, expect, expectTypeOf, it } from "vitest";
import type { KeyOf, PatternOf } from "../src/catalog.js";
import { CatalogError, defineCatalog, lintCatalog } from "../src/catalog.js";

const fixture = () =>
  defineCatalog({
    namespace: "docs",
    additionalNamespaces: ["billing"],
    projects: {
      docs: {
        description: "Documents",
        groups: {
          files: {
            permissions: {
              read: { description: "See files", scopes: ["docs.folder", "docs.doc"] },
              read_pii: true,
              update_file: { scopes: ["docs.folder", "docs.doc"] },
              delete: { scopes: ["docs.folder"] },
            },
          },
          folders: {
            permissions: {
              read: true,
              create_folder: { scopes: ["docs.folder"] },
            },
          },
        },
      },
      billing: {
        groups: {
          invoices: {
            permissions: {
              read: true,
              issue_invoice: true,
            },
          },
        },
      },
    },
    scopeTypes: {
      "docs.folder": { parent: null, description: "A folder" },
      "docs.doc": { parent: "docs.folder" },
    },
    navigation: [
      { label: "Docs", href: "/docs", permission: "docs.*" },
      { label: "Files", href: "/docs/files", permission: ["docs.files.read", "docs.files.read_pii"] },
    ],
  });

describe("defineCatalog", () => {
  it("collects keys from all projects plus alfiz_internal", () => {
    const catalog = fixture();
    expect(catalog.hasKey("docs.files.read")).toBe(true);
    expect(catalog.hasKey("billing.invoices.issue_invoice")).toBe(true);
    expect(catalog.hasKey("alfiz_internal.access.read")).toBe(true);
    expect(catalog.hasKey("alfiz_internal.requests.decide_request")).toBe(true);
    expect(catalog.hasKey("docs.files")).toBe(false);
    expect(catalog.namespaces).toContain("alfiz_internal");
  });

  it("derives read/action kinds and destructive flags", () => {
    const catalog = fixture();
    expect(catalog.leaf("docs.files.read")!.kind).toBe("read");
    expect(catalog.leaf("docs.files.read_pii")!.kind).toBe("read");
    expect(catalog.leaf("docs.files.update_file")!.kind).toBe("action");
    expect(catalog.leaf("docs.files.delete")!.destructive).toBe(true);
    expect(catalog.leaf("docs.files.update_file")!.destructive).toBe(false);
  });

  it("excludes alfiz_internal on request", () => {
    const catalog = defineCatalog({
      namespace: "solo",
      includeAlfizInternal: false,
      projects: { solo: { groups: { things: { permissions: { read: true } } } } },
    });
    expect(catalog.hasKey("alfiz_internal.access.read")).toBe(false);
    expect(catalog.namespaces).not.toContain("alfiz_internal");
  });

  it("rejects projects outside the declared namespaces", () => {
    expect(() =>
      defineCatalog({
        namespace: "docs",
        projects: { rogue: { groups: { t: { permissions: { read: true } } } } },
      }),
    ).toThrow(CatalogError);
  });

  it("rejects the reserved namespace", () => {
    expect(() =>
      defineCatalog({
        namespace: "alfiz_internal",
        projects: {},
      }),
    ).toThrow(/reserved/);
  });

  it("enforces three levels unless allowArbitraryDepth", () => {
    expect(() =>
      defineCatalog({
        namespace: "zoom",
        projects: { zoom: { permissions: { host: true } } },
      }),
    ).toThrow(/3 levels/);
    const zoom = defineCatalog({
      namespace: "zoom",
      allowArbitraryDepth: true,
      includeAlfizInternal: false,
      projects: { zoom: { permissions: { host: true } } },
    });
    expect(zoom.hasKey("zoom.host")).toBe(true);
  });

  it("rejects undeclared scope types on leaves and parents", () => {
    expect(() =>
      defineCatalog({
        namespace: "a",
        projects: { a: { groups: { t: { permissions: { read: { scopes: ["a.ghost"] } } } } } },
      }),
    ).toThrow(/undeclared scope type/);
    expect(() =>
      defineCatalog({
        namespace: "a",
        projects: { a: { groups: { t: { permissions: { read: true } } } } },
        scopeTypes: { "a.thing": { parent: "a.ghost" } },
      }),
    ).toThrow(/not declared/);
  });

  it("keysMatching shows forward-inclusion", () => {
    const catalog = fixture();
    expect(catalog.keysMatching("docs.files.*").sort()).toEqual([
      "docs.files.delete",
      "docs.files.read",
      "docs.files.read_pii",
      "docs.files.update_file",
    ]);
    expect(catalog.keysMatching("docs.files.read")).toEqual(["docs.files.read"]);
  });

  it("isKnownPattern accepts keys, group wildcards, and star", () => {
    const catalog = fixture();
    expect(catalog.isKnownPattern("*")).toBe(true);
    expect(catalog.isKnownPattern("docs.*")).toBe(true);
    expect(catalog.isKnownPattern("docs.files.*")).toBe(true);
    expect(catalog.isKnownPattern("docs.files.read")).toBe(true);
    expect(catalog.isKnownPattern("docs.ghost.*")).toBe(false);
    expect(catalog.isKnownPattern("docs.files.ghost")).toBe(false);
  });

  it("validateGrantableAt enforces scope-type declarations", () => {
    const catalog = fixture();
    expect(catalog.validateGrantableAt("docs.files.read", "*")).toBe(null);
    expect(catalog.validateGrantableAt("docs.files.read", "docs.doc:1")).toBe(null);
    // delete is folder-only
    expect(catalog.validateGrantableAt("docs.files.delete", "docs.doc:1")).not.toBe(null);
    expect(catalog.validateGrantableAt("docs.files.delete", "docs.folder:9")).toBe(null);
    // billing keys declare no scopes: global-only
    expect(
      catalog.validateGrantableAt("billing.invoices.read", "docs.folder:9"),
    ).not.toBe(null);
    // wildcard: grantable where at least one matched leaf is
    expect(catalog.validateGrantableAt("docs.files.*", "docs.doc:1")).toBe(null);
    expect(catalog.validateGrantableAt("billing.*", "docs.doc:1")).not.toBe(null);
    // unknown scope type
    expect(catalog.validateGrantableAt("docs.files.read", "ghost.thing:1")).not.toBe(null);
  });

  it("toDocument is stable and serializable", () => {
    const doc = fixture().toDocument();
    expect(doc.formatVersion).toBe(1);
    expect(doc.namespace).toBe("docs");
    expect(JSON.parse(JSON.stringify(doc))).toEqual(doc);
    const keys = doc.leaves.map((l) => l.key);
    expect(keys).toEqual([...keys].sort());
  });

  it("derives compile-time key and pattern unions", () => {
    const catalog = fixture();
    type Key = KeyOf<typeof catalog>;
    type Pattern = PatternOf<typeof catalog>;
    expectTypeOf<"docs.files.read">().toExtend<Key>();
    expectTypeOf<"billing.invoices.issue_invoice">().toExtend<Key>();
    expectTypeOf<"alfiz_internal.access.view_as">().toExtend<Key>();
    // @ts-expect-error unknown keys are rejected at compile time
    expectTypeOf<"docs.files.ghost">().toExtend<Key>();
    expectTypeOf<"docs.*">().toExtend<Pattern>();
    expectTypeOf<"docs.files.*">().toExtend<Pattern>();
    expectTypeOf<"*">().toExtend<Pattern>();
    // @ts-expect-error unknown group wildcards are rejected
    expectTypeOf<"ghost.*">().toExtend<Pattern>();
  });
});

describe("lintCatalog", () => {
  it("clean fixture has no errors", () => {
    const issues = lintCatalog(fixture()).filter((i) => i.severity === "error");
    expect(issues).toEqual([]);
  });

  it("errors on tabs without a read permission (the floor)", () => {
    const catalog = defineCatalog({
      namespace: "a",
      includeAlfizInternal: false,
      projects: { a: { groups: { t: { permissions: { do_thing: true } } } } },
    });
    const errors = lintCatalog(catalog).filter((i) => i.severity === "error");
    expect(errors.some((e) => e.path === "a.t" && /floor/.test(e.message))).toBe(true);
  });

  it("warns on non-verb_noun action names", () => {
    const catalog = defineCatalog({
      namespace: "a",
      includeAlfizInternal: false,
      projects: { a: { groups: { t: { permissions: { read: true, frobnicate: true } } } } },
    });
    const warnings = lintCatalog(catalog).filter((i) => i.severity === "warning");
    expect(warnings.some((w) => w.path === "a.t.frobnicate")).toBe(true);
  });

  it("errors on nav referencing nothing", () => {
    const catalog = defineCatalog({
      namespace: "a",
      includeAlfizInternal: false,
      projects: { a: { groups: { t: { permissions: { read: true } } } } },
      navigation: [{ label: "Ghost", permission: "a.ghost.read" }],
    });
    const errors = lintCatalog(catalog).filter((i) => i.severity === "error");
    expect(errors.some((e) => e.path === "Ghost")).toBe(true);
  });

  it("errors on requestable scope types without stages", () => {
    const catalog = defineCatalog({
      namespace: "a",
      includeAlfizInternal: false,
      projects: { a: { groups: { t: { permissions: { read: true } } } } },
      scopeTypes: {
        "a.thing": { requestable: { policy: { stages: [] } } },
      },
    });
    const errors = lintCatalog(catalog).filter((i) => i.severity === "error");
    expect(errors.some((e) => e.path === "a.thing" && /policy/.test(e.message))).toBe(true);
  });
});
