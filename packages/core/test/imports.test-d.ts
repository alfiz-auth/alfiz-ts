/**
 * Type-level coverage for imports. This file matters more than most: the
 * derived-union family fails SILENTLY when it regresses — widening to
 * `${string}` keeps every call site compiling — so only assertions catch it.
 *
 * The two things under test are the ones a wildcard import puts in tension:
 * an open import genuinely has no closed key set, so `KeyOf` must widen to
 * admit it; and `Prefixes` must never see that widening, or its recursion
 * runs into `${string}` and inference collapses (TS2589).
 */

import { describe, expectTypeOf, it } from "vitest";
import type { KeyOf, PatternOf } from "../src/catalog.js";
import { defineCatalog, importedKeys } from "../src/catalog.js";

const base = {
  namespaces: ["docs"],
  includeAlfizInternal: false,
  permissions: {
    "docs.files.read": true,
    "docs.files.delete": true,
  },
} as const;

describe("concrete imports close the union", () => {
  const catalog = defineCatalog({
    ...base,
    imports: {
      zoom: { permissions: { "zoom.host": true, "zoom.meetings.read": true } },
    },
  });
  type Key = KeyOf<typeof catalog>;

  it("adds each imported key as a literal, exactly like an owned one", () => {
    expectTypeOf<Key>().toEqualTypeOf<
      "docs.files.read" | "docs.files.delete" | "zoom.host" | "zoom.meetings.read"
    >();
  });

  it("still rejects a typo — in either namespace", () => {
    expectTypeOf<"docs.files.raed">().not.toExtend<Key>();
    expectTypeOf<"zoom.hostt">().not.toExtend<Key>();
  });

  it("does not synthesize group wildcards for the imported namespace", () => {
    type Pattern = PatternOf<typeof catalog>;
    // Owned groups produce wildcards; imported ones do not, because a
    // wildcard broader than the import is a widening claim over a namespace
    // this application does not own.
    expectTypeOf<"docs.files.*">().toExtend<Pattern>();
    expectTypeOf<"docs.*">().toExtend<Pattern>();
    expectTypeOf<"zoom.*">().not.toExtend<Pattern>();
    expectTypeOf<"zoom.meetings.*">().not.toExtend<Pattern>();
  });
});

describe("a wildcard import opens the union — precisely, and no further", () => {
  const catalog = defineCatalog({
    ...base,
    imports: { zoom: { permissions: { "zoom.meetings.*": true } } },
  });
  type Key = KeyOf<typeof catalog>;
  type Pattern = PatternOf<typeof catalog>;

  it("admits anything under the imported subtree", () => {
    expectTypeOf<"zoom.meetings.create_meeting">().toExtend<Key>();
    expectTypeOf<"zoom.meetings.anything">().toExtend<Key>();
  });

  it("admits NOTHING outside it — the open half is one template, not a hole", () => {
    // This is the assertion that matters. If the widening were sloppier
    // (say `${string}`), an owned-namespace typo would start compiling and
    // the derived types would be worth nothing.
    expectTypeOf<"docs.files.raed">().not.toExtend<Key>();
    expectTypeOf<"zoom.host">().not.toExtend<Key>();
    expectTypeOf<"stripe.charges.read">().not.toExtend<Key>();
  });

  it("makes the declared pattern storable, but not a broader one", () => {
    expectTypeOf<"zoom.meetings.*">().toExtend<Pattern>();
    expectTypeOf<"zoom.*">().not.toExtend<Pattern>();
  });
});

describe("importedKeys<K>() closes what a wildcard leaves open", () => {
  // Standing in for `import type { ZoomKey } from "./zoom.gen.js"` — the
  // union `alfiz-verify codegen` emits from the namespace owner's document.
  type ZoomKey = "zoom.host" | "zoom.meetings.read";

  const catalog = defineCatalog({
    ...base,
    imports: {
      zoom: importedKeys<ZoomKey>({ permissions: { "zoom.meetings.*": true } }),
    },
  });
  type Key = KeyOf<typeof catalog>;

  it("pins the imported half to the generated union", () => {
    expectTypeOf<Key>().toEqualTypeOf<
      "docs.files.read" | "docs.files.delete" | ZoomKey
    >();
    expectTypeOf<"zoom.meetings.anything">().not.toExtend<Key>();
  });
});

describe("no import, no change", () => {
  it("leaves the derived unions exactly as they were", () => {
    const catalog = defineCatalog(base);
    expectTypeOf<KeyOf<typeof catalog>>().toEqualTypeOf<
      "docs.files.read" | "docs.files.delete"
    >();
    expectTypeOf<PatternOf<typeof catalog>>().toEqualTypeOf<
      "*" | "docs.files.read" | "docs.files.delete" | "docs.*" | "docs.files.*"
    >();
  });
});

describe("TS2589 insurance", () => {
  it("compiles a catalog with many imported keys alongside a deep owned tree", () => {
    // `Prefixes` recurses per dotted segment over the OWNED keys only. If an
    // open template ever reached it, this would not compile.
    const catalog = defineCatalog({
      namespaces: ["docs"],
      includeAlfizInternal: false,
      conventions: { depth: "any" },
      permissions: {
        "docs.a.b.c.read": true,
        "docs.a.b.c.update_thing": true,
        "docs.a.b.d.read": true,
        "docs.e.f.g.read": true,
      },
      imports: {
        zoom: {
          permissions: {
            "zoom.a.read": true,
            "zoom.b.read": true,
            "zoom.c.read": true,
            "zoom.d.read": true,
            "zoom.e.read": true,
            "zoom.f.*": true,
            "zoom.g.*": true,
          },
        },
        stripe: {
          permissions: {
            "stripe.charges.read": true,
            "stripe.refunds.*": true,
          },
        },
      },
    });
    expectTypeOf<"docs.a.b.c.read">().toExtend<KeyOf<typeof catalog>>();
    expectTypeOf<"zoom.f.anything">().toExtend<KeyOf<typeof catalog>>();
    expectTypeOf<"stripe.charges.read">().toExtend<KeyOf<typeof catalog>>();
    expectTypeOf<"docs.a.b.*">().toExtend<PatternOf<typeof catalog>>();
  });
});
