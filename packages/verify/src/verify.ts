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
import type { AnyCatalog } from "@alfiz-auth/core";
import {
  ALFIZ_INTERNAL_NAMESPACE,
  isValidPattern,
  lintCatalog,
  namespaceOf,
} from "@alfiz-auth/core";

export type VerifySeverity = "error" | "warning";

export interface VerifyIssue {
  severity: VerifySeverity;
  rule:
    | "unknown-pattern"
    | "visibility-as-gate"
    | "ungated-action"
    | "unreferenced-leaf"
    | "client-reachable-secret"
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
   */
  gateNames?: readonly string[] | undefined;
  /** Names treated as visibility affordances — never valid as gates. */
  visibilityNames?: readonly string[] | undefined;
  /**
   * Files counted as server enforcement points even without a
   * `"use server"` directive (route handlers). Matched against the path.
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
  errorCount: number;
  warningCount: number;
}

const DEFAULT_GATES = [
  "can",
  "fresh",
  "require",
  "requirePermission",
  "gateAction",
  "apiRequirePermission",
];
const DEFAULT_VISIBILITY = ["canAny", "requireAny"];
const DEFAULT_SERVER_PATTERNS = [
  /app\/.*route\.(t|j)sx?$/,
  /pages\/api\//,
];

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
  const gates = new Set(options.gateNames ?? DEFAULT_GATES);
  const visibility = new Set(options.visibilityNames ?? DEFAULT_VISIBILITY);
  const serverPatterns = options.serverFilePatterns ?? DEFAULT_SERVER_PATTERNS;
  const forbidden = new Set(options.forbidClientIdentifiers ?? []);
  const read =
    options.read ?? ((file: string) => readFileSync(file, "utf8"));

  const issues: VerifyIssue[] = [];
  const referencedKeys = new Set<string>();
  const namespaces = new Set(catalog.namespaces);

  /** Is this literal plausibly a permission reference we should validate? */
  const isOurs = (text: string): boolean => {
    if (!isValidPattern(text)) return false;
    if (text === "*") return true;
    const ns = namespaceOf(text);
    return ns !== null && namespaces.has(ns);
  };

  for (const file of options.files) {
    const source = ts.createSourceFile(
      file,
      read(file),
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
                issues.push({
                  severity: "error",
                  rule: "unknown-pattern",
                  file,
                  line: lineOf(source, literal),
                  message: `${JSON.stringify(text)} is not in the catalog (typo, or an undeclared key)`,
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
    errorCount: issues.filter((i) => i.severity === "error").length,
    warningCount: issues.filter((i) => i.severity === "warning").length,
  };
}
