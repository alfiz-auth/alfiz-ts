#!/usr/bin/env node
/**
 * alfiz-verify — run the static checks from the command line.
 *
 * Config (alfiz-verify.config.json, or --config <path>):
 *   {
 *     "catalog": "alfiz-catalog.json",        // catalog.toDocument() output
 *     "include": ["src", "app"],              // directories or files
 *     "exclude": ["node_modules", "dist"],    // path substrings to skip
 *     "forbidClientIdentifiers": ["ALFIZ_SERVICE_KEYS"]
 *   }
 *
 * Emit the catalog document from your catalog module, e.g.:
 *   node --experimental-strip-types -e \
 *     'import("./src/alfiz.ts").then(m => console.log(JSON.stringify(m.catalog.toDocument())))' \
 *     > alfiz-catalog.json
 *
 * Exit code 1 when any error-severity issue is found.
 */

import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { catalogFromDocument } from "@alfiz/core";
import { verifyProject } from "./verify.js";

interface CliConfig {
  catalog: string;
  include?: string[];
  exclude?: string[];
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

function main(argv: string[]): number {
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

  const report = verifyProject({
    catalog,
    files,
    forbidClientIdentifiers: config.forbidClientIdentifiers,
  });

  for (const issue of report.issues) {
    const where = issue.line > 0 ? `${issue.file}:${issue.line}` : issue.file;
    console.error(
      `${issue.severity === "error" ? "✖" : "⚠"} [${issue.rule}] ${where} — ${issue.message}`,
    );
  }
  console.error(
    `alfiz-verify: ${files.length} file(s), ${report.errorCount} error(s), ${report.warningCount} warning(s)`,
  );
  return report.errorCount > 0 ? 1 : 0;
}

process.exitCode = main(process.argv.slice(2));
