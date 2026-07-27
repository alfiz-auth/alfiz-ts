import { describe, expect, it } from "vitest";
import { catalogFromDocument, defineCatalog } from "@alfiz-auth/core";
import { verifyProject } from "../src/verify.js";
import type { VerifyIssue } from "../src/verify.js";

const catalog = defineCatalog({
  namespaces: ["docs"],
  includeAlfizInternal: false,
  permissions: {
    "docs.files.read": true,
    "docs.files.update_file": true,
    "docs.files.delete": true,
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
        await client.require(user, "docs.files.raed");
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
      "app/holds-action.ts": `
        "use server";
        export async function doOther() {
          // holds is the "any scope" probe — never a gate.
          if (await client.holds(user, "docs.files.read")) return;
        }
      `,
      "app/page.ts": `
        await client.canAny(user, "docs.*"); // fine in pages/components
      `,
    });
    const bad = byRule(report.issues, "visibility-as-gate");
    expect(bad.length).toBe(3);
    expect(bad.map((i) => i.file).sort()).toEqual([
      "app/actions.ts",
      "app/api/thing/route.ts",
      "app/holds-action.ts",
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

describe("project gate wrappers via gateNames/visibilityNames/serverFilePatterns", () => {
  it("custom gate names count as gates and their key literals are validated", () => {
    const report = run(
      {
        "app/actions.ts": `
          "use server";
          export async function destroy(id: string) {
            await gateDestructiveAction("docs.files.delete");
            return remove(id);
          }
          export async function edit(id: string) {
            await assertTeaches(actor, id, "docs.files.update_file");
            return save(id);
          }
        `,
      },
      {
        gateNames: [
          "can",
          "gateAction",
          "gateDestructiveAction",
          "assertTeaches",
        ],
      },
    );
    expect(byRule(report.issues, "ungated-action")).toEqual([]);
    // Keys inside wrappers count as referenced: no unreferenced-leaf noise.
    expect(byRule(report.issues, "unreferenced-leaf")).toEqual([]);
  });

  it("custom visibility names are flagged as gates in server files", () => {
    const report = run(
      {
        "app/actions.ts": `
          "use server";
          export async function thing() {
            if (await showIfAny(user, "docs.*")) return;
          }
        `,
      },
      { visibilityNames: ["canAny", "requireAny", "showIfAny"] },
    );
    expect(byRule(report.issues, "visibility-as-gate").length).toBe(1);
  });

  it("custom server-file patterns pull files into enforcement analysis", () => {
    const report = run(
      {
        "server/handlers/update.ts": `
          export async function handler() { return save(); }
        `,
      },
      { serverFilePatterns: [/server\/handlers\//] },
    );
    expect(byRule(report.issues, "ungated-action").length).toBe(1);
  });
});

describe("alfiz-verify-ignore-file pragma", () => {
  it("skips the file with a recorded reason; keys and actions inside are invisible", () => {
    const report = run({
      "app/api/system/route.ts": `
        // alfiz-verify-ignore-file system trust domain: authenticates by deploy key, must survive a DB outage
        export async function POST() {
          return doSystemThing();
        }
      `,
      "app/actions.ts": `await gateAction("docs.files.update_file");`,
    });
    expect(byRule(report.issues, "ungated-action")).toEqual([]);
    expect(report.skippedFiles).toEqual([
      {
        file: "app/api/system/route.ts",
        reason:
          "system trust domain: authenticates by deploy key, must survive a DB outage",
      },
    ]);
  });

  it("a pragma without a reason still skips, but warns", () => {
    const report = run({
      "app/api/system/route.ts": `
        // alfiz-verify-ignore-file
        export async function POST() { return doSystemThing(); }
      `,
    });
    expect(byRule(report.issues, "ungated-action")).toEqual([]);
    const warnings = byRule(report.issues, "ignored-file");
    expect(warnings.length).toBe(1);
    expect(warnings[0]!.severity).toBe("warning");
  });

  it("works below a license header, but not after code begins", () => {
    const report = run({
      "a.ts": `
        /* copyright someone */
        // alfiz-verify-ignore-file generated bindings
        export async function x() { return 1; }
      `,
      "b.ts": `
        export const y = 1;
        // alfiz-verify-ignore-file too late — this is not a leading comment
        export async function z() { return 1; }
      `,
    });
    expect(report.skippedFiles.map((s) => s.file)).toEqual(["a.ts"]);
  });

  it("counts below a directive prologue — the placement every RSC file forces", () => {
    // "use server" on line 1 is what the framework docs show, what
    // formatters preserve, and what every contributor writes.
    const report = run({
      "app/api/system/route.ts": `
        "use server";
        // alfiz-verify-ignore-file system trust domain: survives a DB outage
        export async function POST() { return doSystemThing(); }
      `,
      "app/widget.tsx": `
        'use client';
        'use strict';
        // alfiz-verify-ignore-file vendored, gates upstream
        export async function Widget() { return null; }
      `,
      "app/above.ts": `
        // alfiz-verify-ignore-file also fine above the directive
        "use server";
        export async function act() { return 1; }
      `,
    });
    expect(report.skippedFiles.map((s) => s.file).sort()).toEqual([
      "app/above.ts",
      "app/api/system/route.ts",
      "app/widget.tsx",
    ]);
    expect(byRule(report.issues, "ungated-action")).toEqual([]);
  });

  it("is recognized inside a JSDoc header", () => {
    const report = run({
      "a.ts": `
        /**
         * The system trust domain.
         * alfiz-verify-ignore-file authenticates by deploy key
         */
        export async function POST() { return 1; }
      `,
    });
    expect(report.skippedFiles[0]?.reason).toBe("authenticates by deploy key");
  });

  it("prose that merely mentions the pragma is not a pragma", () => {
    const report = run({
      "app/actions.ts": `
        // See docs: write \`// alfiz-verify-ignore-file <reason>\` to opt out.
        "use server";
        export async function ungated() { return 1; }
      `,
    });
    expect(report.skippedFiles).toEqual([]);
    expect(byRule(report.issues, "ungated-action").length).toBe(1);
  });

  it("a misplaced pragma warns instead of silently doing nothing", () => {
    const report = run({
      "app/actions.ts": `
        "use server";
        export async function first() { await gateAction("docs.files.read"); }
        // alfiz-verify-ignore-file too late to count
        export async function second() { return 1; }
      `,
    });
    // Still scanned — the safe direction — and the ungated action is caught.
    expect(report.skippedFiles).toEqual([]);
    expect(byRule(report.issues, "ungated-action").length).toBe(1);
    // …and the inert pragma is called out, at its own line.
    const warned = byRule(report.issues, "ignored-file");
    expect(warned.length).toBe(1);
    expect(warned[0]!.severity).toBe("warning");
    expect(warned[0]!.line).toBe(4);
    expect(warned[0]!.message).toMatch(/does nothing/);
  });
});

describe("group-path near-miss", () => {
  it('says "did you mean docs.*" when a group path is used as a pattern', () => {
    const report = run({
      "app/page.ts": `await client.requireAny(user, "docs");`,
    });
    const unknown = byRule(report.issues, "unknown-pattern");
    expect(unknown.length).toBe(1);
    expect(unknown[0]!.message).toContain('did you mean "docs.*"');
    expect(unknown[0]!.message).toContain("group");
  });

  it("plain typos get the closest declared key — never the bogus group idiom", () => {
    const report = run({
      "app/page.ts": `await client.can(user, "docs.files.raed");`,
    });
    const unknown = byRule(report.issues, "unknown-pattern");
    expect(unknown.length).toBe(1);
    expect(unknown[0]!.message).toContain('did you mean "docs.files.read"');
    expect(unknown[0]!.message).not.toContain("group");
  });
});

describe("catalog rule + report totals", () => {
  it("catalog lint issues ride along and totals add up", () => {
    const floorless = defineCatalog({
      namespaces: ["a"],
      includeAlfizInternal: false,
      permissions: { "a.t.do_thing": true },
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
