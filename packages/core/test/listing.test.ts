import { describe, expect, it } from "vitest";
import {
  closureTableCondition,
  matPathCondition,
  planListing,
  prismaMatPathWhere,
} from "../src/listing.js";

describe("planListing", () => {
  it("global grant, no revokes → all", () => {
    expect(planListing({ granted: new Set(["*"]), revoked: new Set() })).toEqual({ mode: "all" });
  });

  it("global revoke → none, regardless of grants", () => {
    expect(
      planListing({ granted: new Set(["*", "f:1"]), revoked: new Set(["*"]) }),
    ).toEqual({ mode: "none" });
  });

  it("no grants → none", () => {
    expect(planListing({ granted: new Set(), revoked: new Set() })).toEqual({ mode: "none" });
  });

  it("global grant with scoped revokes → all_except", () => {
    expect(
      planListing({ granted: new Set(["*"]), revoked: new Set(["f:9"]) }),
    ).toEqual({ mode: "all_except", exclude: ["f:9"] });
  });

  it("scoped grants → scoped include/exclude", () => {
    expect(
      planListing({ granted: new Set(["f:1", "f:2"]), revoked: new Set(["f:9"]) }),
    ).toEqual({ mode: "scoped", include: ["f:1", "f:2"], exclude: ["f:9"] });
  });
});

describe("matPathCondition", () => {
  it("one parameterized LIKE per scope, full scope ids by default (no cross-type collisions)", () => {
    const frag = matPathCondition(["docs.folder:9", "docs.folder:2"], {
      pathColumn: "path",
    });
    expect(frag.sql).toBe("(path LIKE ? ESCAPE '\\' OR path LIKE ? ESCAPE '\\')");
    expect(frag.params).toEqual(["%/docs.folder:9/%", "%/docs.folder:2/%"]);
  });

  it("escapes LIKE metacharacters in tokens — '_' ids must not act as wildcards", () => {
    const frag = matPathCondition(["docs.folder:user_abc"], { pathColumn: "path" });
    expect(frag.params).toEqual(["%/docs.folder:user\\_abc/%"]);
    const pct = matPathCondition(["docs.folder:a%b"], { pathColumn: "path" });
    expect(pct.params).toEqual(["%/docs.folder:a\\%b/%"]);
  });

  it("rejects tokens containing the separator — they would forge path boundaries", () => {
    expect(() =>
      matPathCondition(["docs.folder:a/b"], { pathColumn: "path" }),
    ).toThrow(/separator/);
  });

  it("supports $n placeholders and custom separators/tokens", () => {
    const frag = matPathCondition(["docs.folder:9"], {
      pathColumn: "p.path",
      separator: "|",
      placeholder: "$n",
      startParam: 3,
      scopeToToken: (s) => s.split(":")[1]!,
    });
    expect(frag.sql).toBe("(p.path LIKE $3 ESCAPE '\\')");
    expect(frag.params).toEqual(["%|9|%"]);
  });

  it("empty scope set is provably false", () => {
    expect(matPathCondition([], { pathColumn: "path" }).sql).toBe("FALSE");
  });
});

describe("closureTableCondition", () => {
  it("EXISTS over the closure table", () => {
    const frag = closureTableCondition(["docs.folder:9", "docs.folder:2"], {
      closureTable: "doc_closure",
      ancestorColumn: "ancestor",
      descendantColumn: "descendant",
      rowIdExpr: "d.id",
    });
    expect(frag.sql).toBe(
      "EXISTS (SELECT 1 FROM doc_closure WHERE doc_closure.descendant = d.id AND doc_closure.ancestor IN (?, ?))",
    );
    expect(frag.params).toEqual(["docs.folder:9", "docs.folder:2"]);
  });
});

describe("prismaMatPathWhere", () => {
  it("builds an OR of contains filters", () => {
    expect(
      prismaMatPathWhere(["docs.folder:9"], { pathField: "path" }),
    ).toEqual({ OR: [{ path: { contains: "/docs.folder:9/" } }] });
  });
});
