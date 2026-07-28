/**
 * Static verification: the four-point wiring checklist enforced by tooling,
 * not discipline. Agents are exactly the users who will skip step three of
 * four — these checks are what make the shipped convention document
 * trustworthy for agent use.
 *
 * Syntax-level analysis (no type checker needed): each file is parsed with
 * the TypeScript compiler API and scanned for check/gate call sites.
 */

import { readFileSync } from "node:fs";
import ts from "typescript";
import type { AnyCatalog } from "@alfiz/core";
import {
  ALFIZ_INTERNAL_NAMESPACE,
  formatAlternatives,
  isValidPattern,
  lintCatalog,
  namespaceOf,
  unknownPermissionContext,
} from "@alfiz/core";

export type VerifySeverity = "error" | "warning";

export interface VerifyIssue {
  severity: VerifySeverity;
  rule:
    | "unknown-pattern"
    | "visibility-as-gate"
    | "ungated-action"
    | "unreferenced-leaf"
    | "client-reachable-secret"
    | "ignored-file"
    | "catalog";
  file: string;
  line: number;
  message: string;
}

export interface VerifyOptions {
  catalog: AnyCatalog;
  /** Files to scan (paths are labels; content comes from `read`). */
  files: readonly string[];
  /** Reads a file's source text. Defaults to fs. */
  read?: ((file: string) => string) | undefined;
  /**
   * Names treated as concrete-permission gates. Property accesses match on
   * the final name (`client.can`, `session.require`, `can.fresh`).
   * REPLACES the defaults — a project with its own guard wrappers (the
   * pattern the conventions encourage; `gateAction` is itself one) passes
   * `[...DEFAULT_GATE_NAMES, "assertTeaches", ...]`. Without this, every
   * action gated through a wrapper reads as ungated.
   */
  gateNames?: readonly string[] | undefined;
  /**
   * Names treated as visibility affordances — never valid as gates.
   * Replaces `DEFAULT_VISIBILITY_NAMES`; spread them in to extend.
   */
  visibilityNames?: readonly string[] | undefined;
  /**
   * Files counted as server enforcement points even without a
   * `"use server"` directive (route handlers). Matched against the path.
   * Replaces `DEFAULT_SERVER_FILE_PATTERNS`; spread them in to extend.
   */
  serverFilePatterns?: readonly RegExp[] | undefined;
  /**
   * Identifiers that must never appear in a `"use client"` module — the
   * client-reach guard for service-key material (fails the build if the key
   * module becomes client-reachable).
   */
  forbidClientIdentifiers?: readonly string[] | undefined;
}

export interface VerifyReport {
  issues: VerifyIssue[];
  /** Concrete keys referenced by at least one scanned call site or nav item. */
  referencedKeys: Set<string>;
  /** Files skipped by the `alfiz-verify-ignore-file` pragma, with their reasons. */
  skippedFiles: Array<{ file: string; reason: string }>;
  errorCount: number;
  warningCount: number;
}

/**
 * The built-in gate names. A project's own wrappers (`gateDestructiveAction`,
 * `assertTeaches`, …) are exactly the convention the docs encourage — pass
 * them via `gateNames`, and spread these in unless you deliberately want to
 * stop counting the built-ins: `[...DEFAULT_GATE_NAMES, "assertTeaches"]`.
 * (The CLI's `gateNames` config is additive for that reason.)
 */
export const DEFAULT_GATE_NAMES = [
  "can",
  "fresh",
  "require",
  // Not an Alfiz method (the client's is `require`); recognized because it
  // is a common host-app wrapper name, like the two below.
  "requirePermission",
  "gateAction",
  "apiRequirePermission",
] as const;
/**
 * Names that are never valid as gates: the visibility affordances
 * (`canAny`/`requireAny`) and the "held at any scope" probe (`holds` —
 * `heldKeys` is a property access, not a call, so it cannot read as a gate).
 */
export const DEFAULT_VISIBILITY_NAMES = ["canAny", "requireAny", "holds"] as const;
export const DEFAULT_SERVER_FILE_PATTERNS: readonly RegExp[] = [
  /app\/.*route\.(t|j)sx?$/,
  /pages\/api\//,
];

/** A found `alfiz-verify-ignore-file` pragma and whether it takes effect. */
export interface IgnorePragma {
  /** The reason text; `""` when the pragma carried none. */
  reason: string;
  /** 1-based line the pragma sits on. */
  line: number;
  /**
   * False when the pragma sits past the header region and is therefore
   * inert. Reported as a warning rather than silently ignored: a security
   * tool that quietly drops its own escape hatch is the wrong failure
   * direction — the adopter sees an unchanged error count and concludes the
   * pragma does not work.
   */
  effective: boolean;
}

/**
 * The out-of-domain escape hatch: `// alfiz-verify-ignore-file <reason>` in
 * a file's header — the leading comments, plus anywhere inside the
 * directive prologue — skips the whole file. For surfaces that authenticate
 * outside the catalog by design (the trust domain SPECIFICATION §2.7
 * endorses, which must survive a database outage and cannot gate on catalog
 * keys by construction), where "no gate" is the architecture, not an
 * omission. The reason is required: an unexplained exemption in a security
 * tool is how exemptions rot.
 *
 * The header region follows JavaScript's own rule rather than a stricter
 * one. A directive prologue (`"use server"`, `"use client"`, `"use strict"`)
 * is a run of string-literal statements at the top of a file, and the
 * language permits comments both BEFORE and BETWEEN them — so both of these
 * are the header, and both count:
 *
 * ```ts
 * // alfiz-verify-ignore-file reason      "use server";
 * "use server";                           // alfiz-verify-ignore-file reason
 * ```
 *
 * Every React Server Components file starts with that directive on line 1;
 * requiring the pragma above it would make the natural placement the broken
 * one. Scanning stops at the first statement that is not part of the
 * prologue.
 *
 * Recognized inside line comments and block comments (including the ` * `
 * continuation of a JSDoc header), and only when the pragma STARTS the
 * comment's text — so prose that merely mentions the pragma is not one.
 */
export function findIgnorePragma(sourceText: string): IgnorePragma | null {
  const PRAGMA = /^alfiz-verify-ignore-file\b[ \t]*(.*)$/;
  const DIRECTIVE = /^(?:"[^"]*"|'[^']*')\s*;?\s*$/;

  /** Comment text on this line, with its marker stripped; null if none. */
  const commentText = (line: string, inBlock: boolean): string | null => {
    if (inBlock) return line.replace(/^\*+[ \t]?/, "");
    if (line.startsWith("//")) return line.slice(2).trim();
    if (line.startsWith("/*")) {
      return line.replace(/^\/\*+[ \t]?/, "").replace(/\*\/.*$/, "").trim();
    }
    return null;
  };

  const lines = sourceText.split(/\r?\n/);
  let inBlock = false;
  let inHeader = true;
  let fallback: IgnorePragma | null = null;

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i]!;
    const line = raw.trim();
    const text = commentText(line, inBlock);

    if (text !== null) {
      const match = PRAGMA.exec(text);
      if (match) {
        const found: IgnorePragma = {
          reason: match[1]!.trim(),
          line: i + 1,
          effective: inHeader,
        };
        // An effective pragma wins immediately; a misplaced one is
        // remembered so the caller can say where it is.
        if (inHeader) return found;
        fallback ??= found;
      }
    }

    if (inBlock) {
      if (line.includes("*/")) {
        inBlock = false;
        if (line.slice(line.indexOf("*/") + 2).trim() !== "") inHeader = false;
      }
      continue;
    }
    if (line === "" || line.startsWith("//")) continue;
    if (line.startsWith("/*")) {
      if (!line.includes("*/")) inBlock = true;
      else if (line.slice(line.indexOf("*/") + 2).trim() !== "") inHeader = false;
      continue;
    }
    // A directive-prologue statement keeps the header open; anything else
    // ends it — but keep scanning, so a misplaced pragma can be reported.
    if (!DIRECTIVE.test(line)) inHeader = false;
  }
  return fallback;
}

const calleeName = (expr: ts.Expression): string | null => {
  if (ts.isIdentifier(expr)) return expr.text;
  if (ts.isPropertyAccessExpression(expr)) return expr.name.text;
  return null;
};

const hasDirective = (source: ts.SourceFile, directive: string): boolean => {
  for (const statement of source.statements) {
    if (
      ts.isExpressionStatement(statement) &&
      ts.isStringLiteral(statement.expression)
    ) {
      if (statement.expression.text === directive) return true;
      continue; // directive prologue may hold several strings
    }
    break;
  }
  return false;
};

const lineOf = (source: ts.SourceFile, node: ts.Node): number =>
  source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1;

/** String literals inside an argument: bare literal or array of literals. */
const literalsIn = (arg: ts.Expression): ts.StringLiteralLike[] => {
  if (ts.isStringLiteralLike(arg)) return [arg];
  if (ts.isArrayLiteralExpression(arg)) {
    return arg.elements.filter((e): e is ts.StringLiteralLike =>
      ts.isStringLiteralLike(e),
    );
  }
  return [];
};

export function verifyProject(options: VerifyOptions): VerifyReport {
  const catalog = options.catalog;
  const gates = new Set(options.gateNames ?? DEFAULT_GATE_NAMES);
  const visibility = new Set(options.visibilityNames ?? DEFAULT_VISIBILITY_NAMES);
  const serverPatterns = options.serverFilePatterns ?? DEFAULT_SERVER_FILE_PATTERNS;
  const forbidden = new Set(options.forbidClientIdentifiers ?? []);
  const read =
    options.read ?? ((file: string) => readFileSync(file, "utf8"));

  const issues: VerifyIssue[] = [];
  const referencedKeys = new Set<string>();
  const skippedFiles: Array<{ file: string; reason: string }> = [];
  const namespaces = new Set(catalog.namespaces);

  /** Is this literal plausibly a permission reference we should validate? */
  const isOurs = (text: string): boolean => {
    if (!isValidPattern(text)) return false;
    if (text === "*") return true;
    const ns = namespaceOf(text);
    return ns !== null && namespaces.has(ns);
  };

  for (const file of options.files) {
    const text = read(file);
    const pragma = findIgnorePragma(text);
    if (pragma !== null && !pragma.effective) {
      // Inert, so the file IS scanned (the safe direction) — but say so,
      // rather than leaving the adopter to infer it from an error count
      // that did not move.
      issues.push({
        severity: "warning",
        rule: "ignored-file",
        file,
        line: pragma.line,
        message:
          "alfiz-verify-ignore-file found here, but it is not in the file header, so it does nothing — move it above the first statement (comments before or between `use server`/`use client` directives are fine)",
      });
    }
    if (pragma !== null && pragma.effective) {
      if (pragma.reason === "") {
        issues.push({
          severity: "warning",
          rule: "ignored-file",
          file,
          line: pragma.line,
          message:
            "alfiz-verify-ignore-file without a reason — say why this surface is out of the catalog's domain (e.g. \"system trust domain, authenticates by deploy key\")",
        });
      }
      skippedFiles.push({
        file,
        reason: pragma.reason === "" ? "(no reason given)" : pragma.reason,
      });
      continue;
    }
    const source = ts.createSourceFile(
      file,
      text,
      ts.ScriptTarget.Latest,
      true,
      file.endsWith(".tsx") ? ts.ScriptKind.TSX : ts.ScriptKind.TS,
    );
    const isServerFile =
      hasDirective(source, "use server") ||
      serverPatterns.some((p) => p.test(file));
    const isClientFile = hasDirective(source, "use client");

    /** Server actions must contain a gate; track exported async fns. */
    const gatedFunctions = new Set<ts.Node>();
    const exportedAsyncFunctions: Array<{ node: ts.Node; name: string }> = [];

    /**
     * Every function enclosing the node, innermost outward: a gate inside a
     * transaction callback still gates the exported action that runs it.
     */
    const enclosingFunctions = (node: ts.Node): ts.Node[] => {
      const out: ts.Node[] = [];
      let current: ts.Node | undefined = node.parent;
      while (current) {
        if (
          ts.isFunctionDeclaration(current) ||
          ts.isFunctionExpression(current) ||
          ts.isArrowFunction(current) ||
          ts.isMethodDeclaration(current)
        ) {
          out.push(current);
        }
        current = current.parent;
      }
      return out;
    };

    const visit = (node: ts.Node): void => {
      if (isClientFile && ts.isIdentifier(node) && forbidden.has(node.text)) {
        issues.push({
          severity: "error",
          rule: "client-reachable-secret",
          file,
          line: lineOf(source, node),
          message: `${JSON.stringify(node.text)} referenced in a "use client" module — service-key material must never be client-reachable`,
        });
      }

      if (ts.isCallExpression(node)) {
        const name = calleeName(node.expression);
        if (name !== null && (gates.has(name) || visibility.has(name))) {
          for (const fn of enclosingFunctions(node)) gatedFunctions.add(fn);

          for (const arg of node.arguments) {
            for (const literal of literalsIn(arg)) {
              const text = literal.text;
              if (!isOurs(text)) continue;
              if (catalog.hasKey(text)) {
                referencedKeys.add(text);
              } else if (!catalog.isKnownPattern(text)) {
                // The near-miss a newcomer hits first: a GROUP path where a
                // pattern belongs. `"admin"` is a valid shape and a declared
                // namespace, but groups are folders — the project-root
                // visibility idiom is `"admin.*"`. Say so; and for plain
                // typos, name the closest declared keys.
                const { suggestion, didYouMean, hint } =
                  unknownPermissionContext(catalog, text, "pattern");
                issues.push({
                  severity: "error",
                  rule: "unknown-pattern",
                  file,
                  line: lineOf(source, literal),
                  message: suggestion
                    ? `${JSON.stringify(text)} is a group, not a key — groups are folders, and subtree patterns end in .*: did you mean ${JSON.stringify(suggestion)}?`
                    : `${JSON.stringify(text)} is not in the catalog (typo, or an undeclared key)` +
                      (didYouMean.length > 0
                        ? ` — did you mean ${formatAlternatives(didYouMean)}?`
                        : "") +
                      (hint ? ` (${hint})` : ""),
                });
              } else {
                // A known group wildcard: mark every key under it referenced.
                for (const key of catalog.keysMatching(text)) {
                  referencedKeys.add(key);
                }
              }
            }
          }

          if (visibility.has(name) && isServerFile) {
            issues.push({
              severity: "error",
              rule: "visibility-as-gate",
              file,
              line: lineOf(source, node),
              message: `${name}() is a visibility affordance, never a gate — server actions and route handlers gate on a concrete permission (can/require*)`,
            });
          }
        }
      }

      if (
        isServerFile &&
        ts.isFunctionDeclaration(node) &&
        node.modifiers?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword) &&
        node.modifiers.some((m) => m.kind === ts.SyntaxKind.AsyncKeyword)
      ) {
        exportedAsyncFunctions.push({
          node,
          name: node.name?.text ?? "<anonymous>",
        });
      }
      // Exported const arrow actions: export const foo = async (...) => {...}
      if (
        isServerFile &&
        ts.isVariableStatement(node) &&
        node.modifiers?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword)
      ) {
        for (const decl of node.declarationList.declarations) {
          if (
            decl.initializer &&
            (ts.isArrowFunction(decl.initializer) ||
              ts.isFunctionExpression(decl.initializer)) &&
            decl.initializer.modifiers?.some(
              (m) => m.kind === ts.SyntaxKind.AsyncKeyword,
            )
          ) {
            exportedAsyncFunctions.push({
              node: decl.initializer,
              name: ts.isIdentifier(decl.name) ? decl.name.text : "<anonymous>",
            });
          }
        }
      }

      ts.forEachChild(node, visit);
    };
    visit(source);

    for (const action of exportedAsyncFunctions) {
      if (!gatedFunctions.has(action.node)) {
        issues.push({
          severity: "error",
          rule: "ungated-action",
          file,
          line: lineOf(source, action.node),
          message: `exported server action ${JSON.stringify(action.name)} contains no gate — every action gates on a concrete permission before doing work`,
        });
      }
    }
  }

  // Navigation references count as (visibility) references.
  const walkNav = (items: AnyCatalog["navigation"]): void => {
    for (const item of items) {
      const patterns = Array.isArray(item.permission)
        ? item.permission
        : [item.permission as string];
      for (const pattern of patterns) {
        for (const key of catalog.keysMatching(pattern)) referencedKeys.add(key);
      }
      walkNav(item.children);
    }
  };
  walkNav(catalog.navigation);

  // Coverage: catalog leaves no scanned gate or nav item references.
  // alfiz_internal.* leaves are gated inside Alfiz's own surfaces, not the
  // application's code, so they are exempt.
  for (const key of catalog.keys) {
    if (namespaceOf(key) === ALFIZ_INTERNAL_NAMESPACE) continue;
    if (!referencedKeys.has(key)) {
      issues.push({
        severity: "warning",
        rule: "unreferenced-leaf",
        file: "<catalog>",
        line: 0,
        message: `${JSON.stringify(key)} is declared but referenced by no gate or nav item — dead permission, or missing enforcement?`,
      });
    }
  }

  // Catalog lint rides along, so one command covers the whole checklist.
  for (const issue of lintCatalog(catalog)) {
    issues.push({
      severity: issue.severity,
      rule: "catalog",
      file: "<catalog>",
      line: 0,
      message: `${issue.path}: ${issue.message}`,
    });
  }

  return {
    issues,
    referencedKeys,
    skippedFiles,
    errorCount: issues.filter((i) => i.severity === "error").length,
    warningCount: issues.filter((i) => i.severity === "warning").length,
  };
}
