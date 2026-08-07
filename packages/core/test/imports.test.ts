/**
 * Imported permissions: vocabulary an application references but does not
 * own. The owning application publishes the keys; the importing one supplies
 * the local wiring.
 *
 * The distinction that runs through every test here is ENUMERATED versus
 * OPEN. An import with the foreign document attached knows its keys, so it
 * behaves exactly like owned vocabulary — typos throw, `keysMatching`
 * expands, the tree renders leaves. An import without one cannot enumerate
 * anything, so its wildcards become opaque REGIONS: still storable, still
 * checkable, but approximated wherever an answer would otherwise require
 * expanding a pattern into keys.
 */

import { describe, expect, it } from "vitest";
import type { CatalogDocument } from "../src/catalog.js";
import {
  CatalogError,
  defineCatalog,
  lintCatalog,
} from "../src/catalog.js";
import { buildPermissionTree, isNodeChecked, nodePattern } from "../src/tree.js";

/** The namespace owner's catalog, as it would arrive from the registry. */
const zoomDocument: CatalogDocument = defineCatalog({
  namespaces: ["zoom"],
  includeAlfizInternal: false,
  conventions: { depth: "any" },
  permissions: {
    "zoom.host": { label: "Host" },
    "zoom.meetings.read": true,
    "zoom.meetings.create_meeting": true,
    "zoom.meetings.delete": true,
  },
}).toDocument();

const withImport = (
  imports: Parameters<typeof defineCatalog>[0]["imports"],
) =>
  defineCatalog({
    namespaces: ["docs"],
    includeAlfizInternal: false,
    permissions: {
      "docs.files.read": { scopes: ["docs.folder"] },
      "docs.files.delete": { scopes: ["docs.folder"] },
    },
    scopeTypes: { "docs.folder": { parent: null } },
    imports,
  });

describe("declaring an import", () => {
  it("accepts concrete keys and subtree patterns from a foreign namespace", () => {
    const catalog = withImport({
      zoom: { from: "registry:zoom@^3", permissions: { "zoom.host": true, "zoom.meetings.*": true } },
    });
    expect(
      catalog.imports.get("zoom")?.entries.map((e) => e.pattern),
    ).toEqual(["zoom.host", "zoom.meetings.*"]);
    expect(catalog.hasKey("zoom.host")).toBe(true);
    expect(catalog.keyOrigin("zoom.host")).toBe("imported");
    expect(catalog.keyOrigin("docs.files.read")).toBe("owned");
  });

  it("refuses to import a namespace the catalog owns", () => {
    expect(() =>
      withImport({ docs: { permissions: { "docs.other.read": true } } }),
    ).toThrow(/does not import what it owns/);
  });

  it("refuses entries outside the namespace they are declared under", () => {
    expect(() =>
      withImport({ zoom: { permissions: { "stripe.charges.read": true } } }),
    ).toThrow(/not under the imported namespace/);
  });

  it("refuses the bare wildcard — importing everything is not a contract", () => {
    expect(() => withImport({ zoom: { permissions: { "*": true } } })).toThrow(
      /never the bare/,
    );
  });

  it("refuses the reserved namespace", () => {
    expect(() =>
      withImport({
        alfiz_internal: { permissions: { "alfiz_internal.access.read": true } },
      }),
    ).toThrow(/reserved for Alfiz itself/);
  });

  it("refuses scope wiring this catalog never declared", () => {
    expect(() =>
      withImport({
        zoom: { scopes: ["zoom.meeting"], permissions: { "zoom.host": true } },
      }),
    ).toThrow(/never the owning application's/);
  });

  it("refuses a document that publishes a different namespace", () => {
    expect(() =>
      withImport({
        stripe: { document: zoomDocument, permissions: { "stripe.charges.read": true } },
      }),
    ).toThrow(/publishes \[zoom\]/);
  });

  it("refuses an entry the attached document does not publish — the local half of drift", () => {
    expect(() =>
      withImport({
        zoom: { document: zoomDocument, permissions: { "zoom.breakout.*": true } },
      }),
    ).toThrow(/removed upstream, or a typo/);
    let error: unknown;
    try {
      withImport({
        zoom: { document: zoomDocument, permissions: { "zoom.hostt": true } },
      });
    } catch (err) {
      error = err;
    }
    expect(error).toBeInstanceOf(CatalogError);
  });
});

describe("an ENUMERATED import (document attached)", () => {
  const catalog = withImport({
    zoom: {
      from: "registry:zoom@^3",
      document: zoomDocument,
      scopes: ["docs.folder"],
      permissions: { "zoom.host": true, "zoom.meetings.*": true },
    },
  });

  it("materializes every published leaf the entry selects", () => {
    expect(catalog.importedKeys).toEqual([
      "zoom.host",
      "zoom.meetings.create_meeting",
      "zoom.meetings.delete",
      "zoom.meetings.read",
    ]);
    expect(catalog.ownedKeys).toEqual(["docs.files.delete", "docs.files.read"]);
    expect(catalog.imports.get("zoom")?.enumerated).toBe(true);
    expect(catalog.openRegions.size).toBe(0);
  });

  it("carries the document's display copy but never its scope types", () => {
    const leaf = catalog.leaf("zoom.host")!;
    expect(leaf.label).toBe("Host");
    expect(leaf.importedFrom).toBe("registry:zoom@^3");
    // The import's own wiring, not zoom's — this catalog can only resolve
    // ancestry for scope types it declares.
    expect(leaf.scopes).toEqual(["docs.folder"]);
  });

  it("expands wildcards exactly, so a typo is knowable", () => {
    expect(catalog.keysMatching("zoom.meetings.*")).toEqual([
      "zoom.meetings.create_meeting",
      "zoom.meetings.delete",
      "zoom.meetings.read",
    ]);
    expect(catalog.hasKey("zoom.meetings.reed")).toBe(false);
  });

  it("infers kind and destructive from the document, not from guesswork", () => {
    expect(catalog.leaf("zoom.meetings.read")!.kind).toBe("read");
    expect(catalog.leaf("zoom.meetings.delete")!.destructive).toBe(true);
  });
});

describe("an OPEN import (no document)", () => {
  const catalog = withImport({
    zoom: {
      from: "dashboard",
      scopes: ["docs.folder"],
      permissions: { "zoom.host": true, "zoom.meetings.*": { label: "Meetings" } },
    },
  });

  it("admits any well-formed key under a declared region", () => {
    expect(catalog.hasKey("zoom.meetings.create_meeting")).toBe(true);
    expect(catalog.hasKey("zoom.meetings.anything_at_all")).toBe(true);
    expect(catalog.keyOrigin("zoom.meetings.anything_at_all")).toBe("region");
    // Outside every declared entry: still unknown.
    expect(catalog.hasKey("zoom.webinars.read")).toBe(false);
  });

  it("cannot enumerate a region — which is exactly why opaqueRegions exists", () => {
    expect(catalog.keysMatching("zoom.meetings.*")).toEqual([]);
    expect(catalog.opaqueRegions("zoom.meetings.*")).toHaveLength(1);
    expect(catalog.opaqueRegions("docs.*")).toEqual([]);
  });

  it("never admits a WILDCARD as a concrete key", () => {
    // A gate checks one concrete key, never a wildcard. A region matches by
    // pattern, so without an explicit guard the string "zoom.meetings.*"
    // matches the region "zoom.meetings.*" and `can()` would accept it.
    expect(catalog.hasKey("zoom.meetings.*")).toBe(false);
    expect(catalog.hasKey("*")).toBe(false);
    expect(catalog.isKnownPattern("zoom.meetings.*")).toBe(true);
  });

  it("describes a region key without inventing a leaf for it", () => {
    // `leaf()` stays exact: synthesizing metadata from a string the catalog
    // never saw would make it lie about `kind` and `destructive`.
    expect(catalog.leaf("zoom.meetings.whatever")).toBeUndefined();
    const described = catalog.describe("zoom.meetings.whatever");
    expect(described.origin).toBe("region");
    expect(described.region?.label).toBe("Meetings");
  });

  it("wires region grantability from the import, not from nothing", () => {
    expect(catalog.appliesAt("zoom.meetings.whatever", "docs.folder:9")).toBe(true);
    expect(catalog.appliesAt("zoom.meetings.whatever", "*")).toBe(true);
    expect(
      catalog.validateGrantableAt("zoom.meetings.*", "docs.folder:9"),
    ).toBeNull();
  });

  it("reports a region as ungrantable at a scope type it was not wired to", () => {
    const unwired = withImport({
      zoom: { permissions: { "zoom.meetings.*": true } },
    });
    const issue = unwired.validateGrantableAt("zoom.meetings.*", "docs.folder:9");
    expect(issue?.message).toMatch(/no scope types wired/);
  });

  it("admits nothing unenumerated under `strict`", () => {
    const strict = withImport({
      zoom: { strict: true, permissions: { "zoom.meetings.*": true } },
    });
    // The vocabulary is still declared — you may grant it...
    expect(strict.isKnownPattern("zoom.meetings.*")).toBe(true);
    expect(strict.opaqueRegions("zoom.meetings.*")).toHaveLength(1);
    // ...but a key this catalog cannot name is not checkable.
    expect(strict.hasKey("zoom.meetings.whatever")).toBe(false);
  });
});

describe("patterns over an imported namespace", () => {
  const catalog = withImport({
    zoom: { permissions: { "zoom.host": true, "zoom.meetings.*": true } },
  });

  it("accepts a declared pattern and anything narrower", () => {
    expect(catalog.isKnownPattern("zoom.meetings.*")).toBe(true);
    expect(catalog.isKnownPattern("zoom.meetings.breakout.*")).toBe(true);
    expect(catalog.isKnownPattern("zoom.host")).toBe(true);
  });

  it("REFUSES a pattern broader than the import", () => {
    // `zoom.*` would be a widening claim over a namespace this application
    // does not own — and a role editor could then store it.
    expect(catalog.isKnownPattern("zoom.*")).toBe(false);
    expect(catalog.isKnownPattern("zoom.webinars.*")).toBe(false);
  });

  it("never suggests a broader wildcard as the fix for a group path", () => {
    // `zoom` IS a group (pickers render it), but `zoom.*` is not storable,
    // so the group-path idiom must not be offered here.
    expect(catalog.hasGroup("zoom")).toBe(true);
    const issue = catalog.validateGrantableAt("zoom", "*");
    expect(issue?.message ?? "").not.toContain('"zoom.*"');
  });
});

describe("publishing", () => {
  const catalog = withImport({
    zoom: {
      from: "registry:zoom@^3",
      document: zoomDocument,
      permissions: { "zoom.host": true },
    },
  });

  it("publishes owned vocabulary only", () => {
    const doc = catalog.toDocument();
    expect(doc.leaves.map((l) => l.key)).toEqual([
      "docs.files.delete",
      "docs.files.read",
    ]);
    expect(doc.namespaces).toEqual(["docs"]);
    expect(doc.groups.every((g) => !g.path.startsWith("zoom"))).toBe(true);
  });

  it("publishes what it consumes as a separate artifact", () => {
    const manifest = catalog.toImportManifest();
    expect(manifest).toEqual({
      formatVersion: 1,
      namespace: "docs",
      imports: [
        {
          namespace: "zoom",
          from: "registry:zoom@^3",
          enumerated: true,
          entries: [{ pattern: "zoom.host", scopes: [] }],
          keys: ["zoom.host"],
          regions: [],
          // The declared posture rides along, so a consumer reconstructing
          // this manifest gets the strictness the publisher declared rather
          // than defaulting to permissive.
          strict: false,
        },
      ],
    });
  });
});

describe("lint exempts imported entries", () => {
  it("does not hold another application's catalog to this one's conventions", () => {
    // `zoom.host` is two segments in a depth-3 catalog, and `zoom.meetings`
    // has no `read` — both would be errors if they were ours. They are not.
    const catalog = withImport({
      zoom: {
        permissions: { "zoom.host": true, "zoom.meetings.create_meeting": true },
      },
    });
    const issues = lintCatalog(catalog);
    expect(issues.filter((i) => i.path.startsWith("zoom"))).toEqual([]);
  });

  it("still lints owned entries", () => {
    const catalog = defineCatalog({
      namespaces: ["docs"],
      includeAlfizInternal: false,
      permissions: { "docs.files.delete": true },
      imports: { zoom: { permissions: { "zoom.host": true } } },
    });
    expect(
      lintCatalog(catalog).some((i) => i.path === "docs.files"),
    ).toBe(true);
  });

  it("does not warn that an open region matches no keys", () => {
    const catalog = defineCatalog({
      namespaces: ["docs"],
      includeAlfizInternal: false,
      conventions: { depth: "any" },
      permissions: { "docs.files.read": true },
      imports: { zoom: { permissions: { "zoom.meetings.*": true } } },
      navigation: [{ label: "Meetings", permission: "zoom.meetings.*" }],
    });
    expect(
      lintCatalog(catalog).filter((i) => i.label !== undefined),
    ).toEqual([]);
    expect(
      lintCatalog(catalog).some((i) => i.message.includes("matches no keys")),
    ).toBe(false);
  });
});

describe("the permission tree", () => {
  it("renders an open region as one selectable unit", () => {
    // A region has no leaves under it. Rendered as a plain group it would be
    // permanently untickable, because a node with nothing to satisfy can
    // never be fully selected.
    const catalog = withImport({
      zoom: { permissions: { "zoom.meetings.*": { label: "Meetings" } } },
    });
    const tree = buildPermissionTree(catalog);
    const zoom = tree.find((n) => n.path === "zoom")!;
    const region = zoom.children.find((n) => n.kind === "region")!;
    expect(region.path).toBe("zoom.meetings");
    expect(region.label).toBe("Meetings");
    expect(nodePattern(region)).toBe("zoom.meetings.*");
    expect(isNodeChecked([], region)).toBe(false);
    expect(isNodeChecked(["zoom.meetings.*"], region)).toBe(true);
    expect(isNodeChecked(["*"], region)).toBe(true);
  });

  it("renders an enumerated import as ordinary leaves", () => {
    const catalog = withImport({
      zoom: { document: zoomDocument, permissions: { "zoom.meetings.*": true } },
    });
    const tree = buildPermissionTree(catalog);
    const meetings = tree
      .find((n) => n.path === "zoom")!
      .children.find((n) => n.path === "zoom.meetings")!;
    expect(meetings.kind).toBe("group");
    expect(meetings.children.map((c) => c.path)).toEqual([
      "zoom.meetings.create_meeting",
      "zoom.meetings.delete",
      "zoom.meetings.read",
    ]);
  });
});
