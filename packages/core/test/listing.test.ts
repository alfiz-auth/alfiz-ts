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
  it("one parameterized LIKE per scope, instance ids by default", () => {
    const frag = matPathCondition(["docs.folder:9", "docs.folder:2"], {
      pathColumn: "path",
    });
    expect(frag.sql).toBe("(path LIKE ? OR path LIKE ?)");
    expect(frag.params).toEqual(["%/9/%", "%/2/%"]);
  });

  it("supports $n placeholders and custom separators/tokens", () => {
    const frag = matPathCondition(["docs.folder:9"], {
      pathColumn: "p.path",
      separator: "|",
      placeholder: "$n",
      startParam: 3,
      scopeToToken: (s) => s,
    });
    expect(frag.sql).toBe("(p.path LIKE $3)");
    expect(frag.params).toEqual(["%|docs.folder:9|%"]);
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
    expect(frag.params).toEqual(["9", "2"]);
  });
});

describe("prismaMatPathWhere", () => {
  it("builds an OR of contains filters", () => {
    expect(
      prismaMatPathWhere(["docs.folder:9"], { pathField: "path" }),
    ).toEqual({ OR: [{ path: { contains: "/9/" } }] });
  });
});
