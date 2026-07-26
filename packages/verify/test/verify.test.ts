import { describe, expect, it } from "vitest";
import { catalogFromDocument, defineCatalog } from "@alfiz-auth/core";
import { verifyProject } from "../src/verify.js";
import type { VerifyIssue } from "../src/verify.js";

const catalog = defineCatalog({
  namespace: "docs",
  includeAlfizInternal: false,
  projects: {
    docs: {
      groups: {
        files: {
          permissions: {
            read: true,
            update_file: true,
            delete: true,
          },
        },
      },
    },
  },
  navigation: [{ label: "Files", href: "/files", permission: "docs.files.read" }],
});

const run = (
  sources: Record<string, string>,
  overrides: Partial<Parameters<typeof verifyProject>[0]> = {},
) =>
  verifyProject({
    catalog,
    files: Object.keys(sources),
    read: (file) => sources[file]!,
    ...overrides,
  });

const byRule = (issues: VerifyIssue[], rule: VerifyIssue["rule"]) =>
  issues.filter((i) => i.rule === rule);

describe("unknown-pattern", () => {
  it("errors on keys and patterns the catalog does not declare", () => {
    const report = run({
      "app/page.ts": `
        await client.requirePermission(user, "docs.files.raed");
        await client.can(user, "docs.ghost.*");
      `,
    });
    const unknown = byRule(report.issues, "unknown-pattern");
    expect(unknown.length).toBe(2);
    expect(unknown[0]!.message).toContain("docs.files.raed");
    expect(unknown[0]!.line).toBe(2);
  });

  it("accepts known keys, group wildcards, any-of arrays, and the star", () => {
    const report = run({
      "app/page.ts": `
        await client.can(user, "docs.files.read");
        await client.can(user, ["docs.files.read", "docs.files.update_file"]);
        await client.canAny(user, "docs.*");
        await client.requireAny(user, "*");
      `,
    });
    expect(byRule(report.issues, "unknown-pattern")).toEqual([]);
  });

  it("ignores strings outside the catalog's namespaces and non-pattern strings", () => {
    const report = run({
      "app/page.ts": `
        await other.can(user, "stripe.charges.create");
        await client.can(user, "docs.files.read", "docs.folder:9");
        console.log("hello world", "a.b!c");
      `,
    });
    expect(byRule(report.issues, "unknown-pattern")).toEqual([]);
  });
});

describe("visibility-as-gate", () => {
  it("errors on canAny/requireAny in 'use server' files and route handlers", () => {
    const report = run({
      "app/actions.ts": `
        "use server";
        export async function doThing() {
          if (await client.canAny(user, "docs.*")) return;
        }
      `,
      "app/api/thing/route.ts": `
        export async function GET() {
          await client.requireAny(user, "docs.*");
        }
      `,
      "app/page.ts": `
        await client.canAny(user, "docs.*"); // fine in pages/components
      `,
    });
    const bad = byRule(report.issues, "visibility-as-gate");
    expect(bad.length).toBe(2);
    expect(bad.map((i) => i.file).sort()).toEqual([
      "app/actions.ts",
      "app/api/thing/route.ts",
    ]);
  });
});

describe("ungated-action", () => {
  it("errors on exported async server actions containing no gate", () => {
    const report = run({
      "app/actions.ts": `
        "use server";
        export async function gated(id: string) {
          await gateAction("docs.files.update_file");
          return save(id);
        }
        export async function ungated(id: string) {
          return save(id);
        }
        export const alsoUngated = async (id: string) => save(id);
        async function internalHelper() { return 1; } // not exported: fine
      `,
    });
    const bad = byRule(report.issues, "ungated-action");
    expect(bad.map((i) => i.message)).toEqual([
      expect.stringContaining('"ungated"'),
      expect.stringContaining('"alsoUngated"'),
    ]);
  });

  it("does not flag functions in ordinary files", () => {
    const report = run({
      "lib/util.ts": `export async function helper() { return 1; }`,
    });
    expect(byRule(report.issues, "ungated-action")).toEqual([]);
  });

  it("a gate inside a nested callback still gates the enclosing action", () => {
    const report = run({
      "app/actions.ts": `
        "use server";
        export async function moveThing(id: string) {
          return withTransaction(async (tx) => {
            await gateAction("docs.files.update_file");
            return tx.save(id);
          });
        }
      `,
    });
    expect(byRule(report.issues, "ungated-action")).toEqual([]);
  });
});

describe("unreferenced-leaf", () => {
  it("warns on leaves no gate or nav item references", () => {
    // docs.files.read is in nav; update_file gated below; delete unreferenced.
    const report = run({
      "app/actions.ts": `await gateAction("docs.files.update_file");`,
    });
    const warnings = byRule(report.issues, "unreferenced-leaf");
    expect(warnings.length).toBe(1);
    expect(warnings[0]!.message).toContain("docs.files.delete");
  });

  it("a group wildcard reference covers its subtree", () => {
    const report = run({
      "app/page.ts": `await client.requireAny(user, "docs.files.*");`,
    });
    expect(byRule(report.issues, "unreferenced-leaf")).toEqual([]);
  });
});

describe("client-reachable-secret", () => {
  it("errors when a forbidden identifier appears in a 'use client' module", () => {
    const report = run(
      {
        "app/widget.tsx": `
          "use client";
          const key = process.env.ALFIZ_SERVICE_KEYS;
        `,
        "server/keys.ts": `const key = process.env.ALFIZ_SERVICE_KEYS;`,
      },
      { forbidClientIdentifiers: ["ALFIZ_SERVICE_KEYS"] },
    );
    const bad = byRule(report.issues, "client-reachable-secret");
    expect(bad.length).toBe(1);
    expect(bad[0]!.file).toBe("app/widget.tsx");
  });
});

describe("catalog rule + report totals", () => {
  it("catalog lint issues ride along and totals add up", () => {
    const floorless = defineCatalog({
      namespace: "a",
      includeAlfizInternal: false,
      projects: { a: { groups: { t: { permissions: { do_thing: true } } } } },
    });
    const report = verifyProject({ catalog: floorless, files: [] });
    expect(byRule(report.issues, "catalog").some((i) => /floor/.test(i.message))).toBe(true);
    expect(report.errorCount + report.warningCount).toBe(report.issues.length);
  });
});

describe("catalogFromDocument round-trip", () => {
  it("a rebuilt catalog verifies identically", () => {
    const rebuilt = catalogFromDocument(catalog.toDocument());
    const report = verifyProject({
      catalog: rebuilt,
      files: ["a.ts"],
      read: () => `await client.can(user, "docs.files.raed");`,
    });
    expect(byRule(report.issues, "unknown-pattern").length).toBe(1);
    expect(rebuilt.keysMatching("docs.*").length).toBe(3);
  });
});
