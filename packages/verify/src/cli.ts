#!/usr/bin/env node
/**
 * alfiz-verify — run the static checks from the command line.
 *
 * Subcommand: `alfiz-verify codegen --catalog <doc.json> [--out <file>]
 * [--prefix <Name>]` — emit derived key/pattern/scope-id type unions from a
 * published catalog document (stdout when --out is omitted). This is how
 * consumers of the WIRE shape (federated apps, other repos) get the same
 * typed `can` as the catalog's own module: pin the emitted types with
 * `catalogFromDocument<AlfizKey, AlfizPattern, AlfizScopeId>(doc)`.
 *
 * Config (alfiz-verify.config.json, or --config <path>):
 *   {
 *     "catalog": "alfiz-catalog.json",        // catalog.toDocument() output
 *     "include": ["src", "app"],              // directories or files
 *     "exclude": ["node_modules", "dist"],    // path substrings to skip
 *     "gateNames": ["assertTeaches"],         // YOUR gate wrappers — ADDED to the defaults
 *     "visibilityNames": ["showIfAny"],       // your visibility wrappers — added to the defaults
 *     "serverFilePatterns": ["app/actions/"], // RegExp sources — added to the defaults
 *     "forbidClientIdentifiers": ["ALFIZ_SERVICE_KEYS"]
 *   }
 *
 * The name lists are ADDITIVE here: the CLI is the batteries-included path,
 * and forgetting to restate `can` should not un-gate your whole codebase.
 * Full replacement (dropping the defaults) is the programmatic API:
 * `verifyProject({ gateNames: [...] })`.
 *
 * Files that authenticate OUTSIDE the catalog by design (system trust
 * domains, deploy-key surfaces) opt out in-file, with a reason:
 *
 *   // alfiz-verify-ignore-file system trust domain, authenticates by deploy key
 *
 * Emit the catalog document from your catalog module, e.g.:
 *   node --experimental-strip-types -e \
 *     'import("./src/alfiz.ts").then(m => console.log(JSON.stringify(m.catalog.toDocument())))' \
 *     > alfiz-catalog.json
 *
 * Exit code 1 when any error-severity issue is found.
 */

import { readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { catalogFromDocument } from "@alfiz-auth/core";
import { generateCatalogTypes } from "./codegen.js";
import {
  DEFAULT_GATE_NAMES,
  DEFAULT_SERVER_FILE_PATTERNS,
  DEFAULT_VISIBILITY_NAMES,
  verifyProject,
} from "./verify.js";

interface CliConfig {
  catalog: string;
  include?: string[];
  exclude?: string[];
  /** Project gate wrappers, added to the built-in gate names. */
  gateNames?: string[];
  /** Project visibility wrappers, added to the built-in visibility names. */
  visibilityNames?: string[];
  /** RegExp sources for extra server-file paths, added to the built-ins. */
  serverFilePatterns?: string[];
  forbidClientIdentifiers?: string[];
}

const DEFAULT_EXCLUDES = ["node_modules", "dist", ".next", ".git"];
const SOURCE_RE = /\.(ts|tsx|mts|cts)$/;

function collectFiles(
  roots: readonly string[],
  excludes: readonly string[],
): string[] {
  const files: string[] = [];
  const excluded = (path: string) => excludes.some((e) => path.includes(e));
  const walk = (path: string) => {
    if (excluded(path)) return;
    const stats = statSync(path, { throwIfNoEntry: false });
    if (!stats) return;
    if (stats.isDirectory()) {
      for (const entry of readdirSync(path)) walk(join(path, entry));
    } else if (SOURCE_RE.test(path) && !path.endsWith(".d.ts")) {
      files.push(path);
    }
  };
  for (const root of roots) walk(root);
  return files;
}

/** `--flag value` lookup; returns undefined when the flag is absent. */
function flagValue(argv: string[], flag: string): string | undefined {
  const idx = argv.indexOf(flag);
  return idx >= 0 ? argv[idx + 1] : undefined;
}

function runCodegen(argv: string[]): number {
  const catalogPath = flagValue(argv, "--catalog");
  if (!catalogPath) {
    console.error(
      "alfiz-verify codegen: --catalog <catalog-document.json> is required " +
        "(emit one with catalog.toDocument(); see the header of this CLI)",
    );
    return 2;
  }
  let document;
  try {
    document = JSON.parse(readFileSync(resolve(catalogPath), "utf8"));
  } catch (err) {
    console.error(
      `alfiz-verify codegen: cannot read catalog ${catalogPath}: ${String(err)}`,
    );
    return 2;
  }
  // Round-trip through catalogFromDocument so a malformed document fails
  // here, loudly, instead of emitting types from garbage.
  catalogFromDocument(document);
  const source = generateCatalogTypes(document, {
    prefix: flagValue(argv, "--prefix"),
  });
  const out = flagValue(argv, "--out");
  if (out) {
    writeFileSync(resolve(out), source);
    console.error(`alfiz-verify codegen: wrote ${out}`);
  } else {
    process.stdout.write(source);
  }
  return 0;
}

function main(argv: string[]): number {
  if (argv[0] === "codegen") return runCodegen(argv.slice(1));
  const configFlag = argv.indexOf("--config");
  const configPath = resolve(
    configFlag >= 0 && argv[configFlag + 1]
      ? argv[configFlag + 1]!
      : "alfiz-verify.config.json",
  );
  let config: CliConfig;
  try {
    config = JSON.parse(readFileSync(configPath, "utf8")) as CliConfig;
  } catch (err) {
    console.error(`alfiz-verify: cannot read config ${configPath}: ${String(err)}`);
    return 2;
  }
  const document = JSON.parse(readFileSync(resolve(config.catalog), "utf8"));
  const catalog = catalogFromDocument(document);
  const files = collectFiles(config.include ?? ["src"], [
    ...DEFAULT_EXCLUDES,
    ...(config.exclude ?? []),
  ]);

  let extraServerPatterns: RegExp[];
  try {
    extraServerPatterns = (config.serverFilePatterns ?? []).map(
      (source) => new RegExp(source),
    );
  } catch (err) {
    console.error(`alfiz-verify: bad serverFilePatterns entry: ${String(err)}`);
    return 2;
  }

  const report = verifyProject({
    catalog,
    files,
    gateNames: [...DEFAULT_GATE_NAMES, ...(config.gateNames ?? [])],
    visibilityNames: [
      ...DEFAULT_VISIBILITY_NAMES,
      ...(config.visibilityNames ?? []),
    ],
    serverFilePatterns: [...DEFAULT_SERVER_FILE_PATTERNS, ...extraServerPatterns],
    forbidClientIdentifiers: config.forbidClientIdentifiers,
  });

  for (const issue of report.issues) {
    const where = issue.line > 0 ? `${issue.file}:${issue.line}` : issue.file;
    console.error(
      `${issue.severity === "error" ? "✖" : "⚠"} [${issue.rule}] ${where} — ${issue.message}`,
    );
  }
  for (const skipped of report.skippedFiles) {
    console.error(`○ [ignored] ${skipped.file} — ${skipped.reason}`);
  }
  console.error(
    `alfiz-verify: ${files.length} file(s), ${report.skippedFiles.length} ignored, ${report.errorCount} error(s), ${report.warningCount} warning(s)`,
  );
  return report.errorCount > 0 ? 1 : 0;
}

process.exitCode = main(process.argv.slice(2));
