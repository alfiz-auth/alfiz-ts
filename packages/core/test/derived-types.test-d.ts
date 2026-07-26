/**
 * Type-level regression tests for the derived-type family. These exist
 * because the failure mode is SILENT: a change that makes `KeysUnder`
 * widen to `${string}` keeps every call site compiling — autocomplete and
 * typo-checking just quietly disappear. Exact-union assertions here turn
 * that regression into a build failure.
 *
 * Typecheck-only (vitest typecheck, `*.test-d.ts`): this file is never
 * executed, so `declare const` fixtures are fine and cheap.
 */

import { describe, expectTypeOf, it } from "vitest";
import type {
  AlfizClient,
  AlfizProvider,
  CatalogDocument,
  ClientOf,
  KeyOf,
  PatternOf,
  ScopeOf,
  SnapshotOf,
} from "../src/index.js";
import {
  catalogFromDocument,
  createAlfizClient,
  defineCatalog,
  scopeId,
} from "../src/index.js";

const catalog = defineCatalog({
  namespace: "docs",
  includeAlfizInternal: false,
  projects: {
    docs: {
      groups: {
        files: {
          permissions: {
            read: true,
            update_file: { scopes: ["docs.folder"] },
            delete: { destructive: true, scopes: ["docs.folder"] },
          },
        },
      },
    },
  },
  scopeTypes: {
    "docs.folder": { parent: "docs.folder" },
    "docs.doc": { parent: "docs.folder" },
  },
});

type Key = KeyOf<typeof catalog>;
type Pattern = PatternOf<typeof catalog>;
type Scope = ScopeOf<typeof catalog>;

declare const client: ClientOf<typeof catalog>;
declare const snapshot: SnapshotOf<typeof catalog>;
declare const provider: AlfizProvider;
declare const document: CatalogDocument;
declare const runtimeScope: string;

describe("derived unions stay EXACT literal unions (the anti-widening guard)", () => {
  it("KeyOf is the exact key union", () => {
    expectTypeOf<Key>().toEqualTypeOf<
      "docs.files.read" | "docs.files.update_file" | "docs.files.delete"
    >();
  });

  it("PatternOf is keys + group wildcards + the bare *", () => {
    expectTypeOf<Pattern>().toEqualTypeOf<
      "*" | Key | "docs.*" | "docs.files.*"
    >();
  });

  it("ScopeOf is * + declared scope-type templates", () => {
    expectTypeOf<Scope>().toEqualTypeOf<
      "*" | `docs.folder:${string}` | `docs.doc:${string}`
    >();
  });

  it("a catalog with no scope types derives the global scope only", () => {
    const flat = defineCatalog({
      namespace: "a",
      includeAlfizInternal: false,
      projects: { a: { groups: { t: { permissions: { read: true } } } } },
    });
    expectTypeOf<ScopeOf<typeof flat>>().toEqualTypeOf<"*">();
  });
});

describe("gates reject typos at compile time; scope parameters hint", () => {
  it("can() takes only declared keys", () => {
    void client.can({ userId: "u" }, "docs.files.read");
    void client.can({ userId: "u" }, ["docs.files.read", "docs.files.delete"]);
    // @ts-expect-error — misspelled key
    void client.can({ userId: "u" }, "docs.files.raed");
    // @ts-expect-error — a pattern is not a gate key
    void client.can({ userId: "u" }, "docs.files.*");
  });

  it("canAny() takes only declared patterns", () => {
    void client.canAny({ userId: "u" }, "docs.*");
    // @ts-expect-error — undeclared group wildcard
    void client.canAny({ userId: "u" }, "ghost.*");
  });

  it("scope parameters autocomplete declared prefixes but admit runtime strings", () => {
    void client.can({ userId: "u" }, "docs.files.read", "docs.doc:123");
    void client.can({ userId: "u" }, "docs.files.read", runtimeScope);
    void snapshot.can("docs.files.read", "docs.folder:1");
    void snapshot.can("docs.files.read", runtimeScope);
  });

  it("scopeId() narrows, so built ids satisfy the derived scope union", () => {
    const built = scopeId("docs.doc", "123");
    expectTypeOf(built).toEqualTypeOf<`docs.doc:${string}`>();
    expectTypeOf(built).toExtend<Scope>();
  });
});

describe("document-typed catalogs thread the unions end to end", () => {
  it("catalogFromDocument<K, P, S> feeds createAlfizClient", () => {
    const typed = catalogFromDocument<Key, Pattern, Scope>(document);
    expectTypeOf<KeyOf<typeof typed>>().toEqualTypeOf<Key>();
    expectTypeOf<PatternOf<typeof typed>>().toEqualTypeOf<Pattern>();
    expectTypeOf<ScopeOf<typeof typed>>().toEqualTypeOf<Scope>();
    const fromDoc = createAlfizClient({ catalog: typed, provider });
    expectTypeOf(fromDoc).toEqualTypeOf<AlfizClient<Key, Pattern, Scope>>();
  });

  it("an untyped document stays honest: string, not a phantom union", () => {
    const untyped = catalogFromDocument(document);
    expectTypeOf<KeyOf<typeof untyped>>().toEqualTypeOf<string>();
  });
});
