import { describe, expect, it } from "vitest";
import type {
  CheckContext,
  GrantRow,
  RevokeRow,
  RoleDef,
} from "../src/access.js";
import {
  checkAny,
  checkKey,
  explainKey,
  grantedScopesFor,
  planVirtualParentDissolution,
  revokedScopesFor,
  validateGrantRow,
} from "../src/access.js";

const NOW = 1_000_000;
let seq = 0;

const grant = (
  subject: string,
  what: { pattern?: string; roleId?: string },
  scope = "*",
  expiresAt?: number,
): GrantRow => ({
  id: `g${++seq}`,
  subject,
  pattern: what.pattern,
  roleId: what.roleId,
  scope,
  expiresAt,
  provenance: { kind: "admin", actorUserId: "root" },
  createdAt: NOW - 1000,
});

const revoke = (userId: string, pattern: string, scope = "*"): RevokeRow => ({
  id: `r${++seq}`,
  userId,
  pattern,
  scope,
  provenance: { kind: "admin", actorUserId: "root" },
  createdAt: NOW - 1000,
});

const ctx = (
  grants: GrantRow[],
  revokes: RevokeRow[] = [],
  roles: RoleDef[] = [],
  closure: string[] = ["user:u1", "everyone"],
  userId: string | null = "u1",
): CheckContext => ({
  subjectClosure: new Set(closure),
  userId,
  rows: { grants, revokes, roles: new Map(roles.map((r) => [r.id, r])) },
  now: NOW,
});

describe("validateGrantRow", () => {
  it("requires exactly one of roleId/pattern", () => {
    expect(validateGrantRow(grant("user:u1", { pattern: "a.b.c" }))).toBe(null);
    expect(validateGrantRow(grant("user:u1", { roleId: "role1" }))).toBe(null);
    expect(validateGrantRow(grant("user:u1", {}))).not.toBe(null);
    expect(
      validateGrantRow(grant("user:u1", { pattern: "a.b.c", roleId: "r" })),
    ).not.toBe(null);
  });
});

describe("checkKey — positive path", () => {
  it("direct pattern grant at global scope", () => {
    const c = ctx([grant("user:u1", { pattern: "docs.files.read" })]);
    expect(checkKey(c, "docs.files.read", ["*"])).toBe(true);
    expect(checkKey(c, "docs.files.delete", ["*"])).toBe(false);
  });

  it("wildcard grants are forward-inclusive", () => {
    const c = ctx([grant("user:u1", { pattern: "docs.*" })]);
    expect(checkKey(c, "docs.files.read", ["*"])).toBe(true);
    expect(checkKey(c, "docs.brand_new_tab.brand_new_action", ["*"])).toBe(true);
    expect(checkKey(c, "billing.invoices.read", ["*"])).toBe(false);
  });

  it("role grants resolve to the role's patterns", () => {
    const roles: RoleDef[] = [
      { id: "role1", name: "Reader", patterns: ["docs.files.read", "docs.folders.*"] },
    ];
    const c = ctx([grant("user:u1", { roleId: "role1" })], [], roles);
    expect(checkKey(c, "docs.files.read", ["*"])).toBe(true);
    expect(checkKey(c, "docs.folders.create_folder", ["*"])).toBe(true);
    expect(checkKey(c, "docs.files.delete", ["*"])).toBe(false);
  });

  it("unknown roles confer nothing", () => {
    const c = ctx([grant("user:u1", { roleId: "ghost" })]);
    expect(checkKey(c, "docs.files.read", ["*"])).toBe(false);
  });

  it("grants to any closure member count (groups, orgs, everyone)", () => {
    const closure = ["user:u1", "group:teachers", "org:acme", "everyone"];
    for (const subject of closure) {
      const c = ctx([grant(subject, { pattern: "docs.files.read" })], [], [], closure);
      expect(checkKey(c, "docs.files.read", ["*"])).toBe(true);
    }
  });

  it("grants to subjects outside the closure do not count", () => {
    const c = ctx([grant("group:admins", { pattern: "docs.files.read" })]);
    expect(checkKey(c, "docs.files.read", ["*"])).toBe(false);
  });

  it("public access is an ordinary row with subject everyone", () => {
    const c = ctx(
      [grant("everyone", { pattern: "docs.files.read" }, "docs.doc:public1")],
      [],
      [],
      ["user:u2", "everyone"],
    );
    expect(checkKey(c, "docs.files.read", ["docs.doc:public1", "*"])).toBe(true);
    expect(checkKey(c, "docs.files.read", ["docs.doc:other", "*"])).toBe(false);
  });
});

describe("checkKey — scoped grants and object closure", () => {
  it("a grant at an ancestor covers the target", () => {
    const c = ctx([grant("user:u1", { pattern: "docs.files.read" }, "docs.folder:9")]);
    const closure = ["docs.doc:1", "docs.folder:9", "docs.folder:2", "*"];
    expect(checkKey(c, "docs.files.read", closure)).toBe(true);
  });

  it("a grant at an unrelated scope does not", () => {
    const c = ctx([grant("user:u1", { pattern: "docs.files.read" }, "docs.folder:77")]);
    expect(checkKey(c, "docs.files.read", ["docs.doc:1", "docs.folder:9", "*"])).toBe(false);
  });

  it("a global grant covers every scope", () => {
    const c = ctx([grant("user:u1", { pattern: "docs.files.read" })]);
    expect(checkKey(c, "docs.files.read", ["docs.doc:1", "docs.folder:9", "*"])).toBe(true);
  });

  it("a scoped grant does not leak to global checks", () => {
    const c = ctx([grant("user:u1", { pattern: "docs.files.read" }, "docs.folder:9")]);
    expect(checkKey(c, "docs.files.read", ["*"])).toBe(false);
  });
});

describe("checkKey — expiry", () => {
  it("expired grants stop matching exactly as deleted ones would", () => {
    const c = ctx([grant("user:u1", { pattern: "docs.files.read" }, "*", NOW - 1)]);
    expect(checkKey(c, "docs.files.read", ["*"])).toBe(false);
  });

  it("boundary: a grant expiring exactly now no longer matches", () => {
    const c = ctx([grant("user:u1", { pattern: "docs.files.read" }, "*", NOW)]);
    expect(checkKey(c, "docs.files.read", ["*"])).toBe(false);
  });

  it("future expiry still matches (time-bound access)", () => {
    const c = ctx([grant("user:u1", { pattern: "docs.files.read" }, "*", NOW + 60_000)]);
    expect(checkKey(c, "docs.files.read", ["*"])).toBe(true);
  });
});

describe("checkKey — negative always wins, scope-inclusive", () => {
  it("a personal revoke beats a direct grant at the same scope", () => {
    const c = ctx(
      [grant("user:u1", { pattern: "docs.files.read" })],
      [revoke("u1", "docs.files.read")],
    );
    expect(checkKey(c, "docs.files.read", ["*"])).toBe(false);
  });

  it("a revoke at an ancestor suppresses a DEEPER direct grant", () => {
    // The spec's chosen surprise-avoidance: folder-level revoke beats a
    // direct document grant.
    const c = ctx(
      [grant("user:u1", { pattern: "docs.files.read" }, "docs.doc:1")],
      [revoke("u1", "docs.files.read", "docs.folder:9")],
    );
    expect(checkKey(c, "docs.files.read", ["docs.doc:1", "docs.folder:9", "*"])).toBe(false);
  });

  it("a global revoke suppresses everything matching", () => {
    const c = ctx(
      [grant("user:u1", { pattern: "docs.*" }, "docs.doc:1")],
      [revoke("u1", "docs.*")],
    );
    expect(checkKey(c, "docs.files.read", ["docs.doc:1", "*"])).toBe(false);
  });

  it("a revoke at a NARROWER scope does not suppress the check at a broader one", () => {
    const c = ctx(
      [grant("user:u1", { pattern: "docs.files.read" })],
      [revoke("u1", "docs.files.read", "docs.folder:9")],
    );
    // Checking at an unrelated doc: revoke's scope is not in this closure.
    expect(checkKey(c, "docs.files.read", ["docs.doc:55", "docs.folder:70", "*"])).toBe(true);
    // Checking under the revoked folder: suppressed.
    expect(checkKey(c, "docs.files.read", ["docs.doc:1", "docs.folder:9", "*"])).toBe(false);
  });

  it("revokes beat wildcard grants inherited from groups", () => {
    const c = ctx(
      [grant("group:teachers", { pattern: "mathaniyy.*" })],
      [revoke("u1", "mathaniyy.approvals.decide_student")],
      [],
      ["user:u1", "group:teachers", "everyone"],
    );
    expect(checkKey(c, "mathaniyy.approvals.decide_student", ["*"])).toBe(false);
    expect(checkKey(c, "mathaniyy.approvals.read_student", ["*"])).toBe(true);
  });

  it("revokes only apply to the user themself (personal-only)", () => {
    const c = ctx(
      [grant("group:teachers", { pattern: "docs.files.read" })],
      [revoke("u2", "docs.files.read")],
      [],
      ["user:u1", "group:teachers", "everyone"],
    );
    expect(checkKey(c, "docs.files.read", ["*"])).toBe(true);
  });

  it("machine subjects (userId null) have no personal revokes", () => {
    const c = ctx(
      [grant("service:cron", { pattern: "docs.files.read" })],
      [revoke("cron", "docs.files.read")],
      [],
      ["service:cron", "everyone"],
      null,
    );
    expect(checkKey(c, "docs.files.read", ["*"])).toBe(true);
  });

  it("a wildcard revoke suppresses concrete grants under it", () => {
    const c = ctx(
      [grant("user:u1", { pattern: "docs.files.delete" })],
      [revoke("u1", "docs.*")],
    );
    expect(checkKey(c, "docs.files.delete", ["*"])).toBe(false);
  });
});

describe("explainKey", () => {
  it("shows matched grants and winning revokes", () => {
    const g = grant("group:teachers", { pattern: "docs.*" });
    const r = revoke("u1", "docs.files.delete");
    const c = ctx([g], [r], [], ["user:u1", "group:teachers", "everyone"]);
    const explained = explainKey(c, "docs.files.delete", ["*"]);
    expect(explained.allowed).toBe(false);
    expect(explained.matchedGrants).toEqual([g]);
    expect(explained.matchedRevokes).toEqual([r]);

    const allowed = explainKey(c, "docs.files.read", ["*"]);
    expect(allowed.allowed).toBe(true);
    expect(allowed.matchedGrants).toEqual([g]);
    expect(allowed.matchedRevokes).toEqual([]);
  });
});

describe("checkAny — visibility affordance", () => {
  const CATALOG_KEYS = [
    "mathaniyy.approvals.read_student",
    "mathaniyy.approvals.decide_student",
    "mathaniyy.schedule.read",
    "admin.access.read",
  ];

  it("true when any catalog key under the pattern is granted", () => {
    const c = ctx([grant("user:u1", { pattern: "mathaniyy.schedule.read" })]);
    expect(checkAny(c, "mathaniyy.*", CATALOG_KEYS)).toBe(true);
    expect(checkAny(c, "admin.*", CATALOG_KEYS)).toBe(false);
  });

  it("wildcard grants intersect group patterns", () => {
    const c = ctx([grant("user:u1", { pattern: "mathaniyy.approvals.*" })]);
    expect(checkAny(c, "mathaniyy.*", CATALOG_KEYS)).toBe(true);
  });

  it("scoped grants make the surface visible", () => {
    const c = ctx([
      grant("user:u1", { pattern: "mathaniyy.schedule.read" }, "class:7b"),
    ]);
    expect(checkAny(c, "mathaniyy.*", CATALOG_KEYS)).toBe(true);
  });

  it("false when the pattern matches no catalog key", () => {
    const c = ctx([grant("user:u1", { pattern: "*" })]);
    expect(checkAny(c, "nonexistent.*", CATALOG_KEYS)).toBe(false);
  });

  it("a fully-revoking pattern hides the surface", () => {
    const c = ctx(
      [grant("user:u1", { pattern: "mathaniyy.schedule.read" })],
      [revoke("u1", "mathaniyy.*")],
    );
    expect(checkAny(c, "mathaniyy.*", CATALOG_KEYS)).toBe(false);
  });

  it("a revoke on one key leaves other granted keys visible", () => {
    const c = ctx(
      [grant("user:u1", { pattern: "mathaniyy.approvals.*" })],
      [revoke("u1", "mathaniyy.approvals.decide_student")],
    );
    expect(checkAny(c, "mathaniyy.*", CATALOG_KEYS)).toBe(true);
  });

  it("with grant-scope closures, an ancestor revoke fully suppresses a scoped grant", () => {
    const c = ctx(
      [grant("user:u1", { pattern: "mathaniyy.schedule.read" }, "class:7b")],
      [revoke("u1", "mathaniyy.schedule.read", "school:main")],
    );
    const closures = new Map([["class:7b", ["class:7b", "school:main", "*"]]]);
    expect(checkAny(c, "mathaniyy.*", CATALOG_KEYS, closures)).toBe(false);
    // Without closures we over-show (documented, visibility-only).
    expect(checkAny(c, "mathaniyy.*", CATALOG_KEYS)).toBe(true);
  });

  it("expired grants do not create visibility", () => {
    const c = ctx([grant("user:u1", { pattern: "mathaniyy.*" }, "*", NOW - 1)]);
    expect(checkAny(c, "mathaniyy.*", CATALOG_KEYS)).toBe(false);
  });
});

describe("listing primitives", () => {
  it("grantedScopesFor collects scopes of matching unexpired rows", () => {
    const roles: RoleDef[] = [{ id: "reader", name: "Reader", patterns: ["docs.files.read"] }];
    const c = ctx(
      [
        grant("user:u1", { pattern: "docs.files.read" }, "docs.folder:9"),
        grant("group:team", { roleId: "reader" }, "docs.folder:2"),
        grant("user:u1", { pattern: "docs.files.read" }, "*", NOW - 1), // expired
        grant("user:u1", { pattern: "billing.invoices.read" }, "docs.folder:77"),
        grant("group:other", { pattern: "docs.files.read" }, "docs.folder:88"),
      ],
      [],
      roles,
      ["user:u1", "group:team", "everyone"],
    );
    expect(grantedScopesFor(c, "docs.files.read")).toEqual(
      new Set(["docs.folder:9", "docs.folder:2"]),
    );
  });

  it("revokedScopesFor collects the user's matching revoke scopes", () => {
    const c = ctx(
      [],
      [revoke("u1", "docs.*", "docs.folder:9"), revoke("u1", "other.thing.read")],
    );
    expect(revokedScopesFor(c, "docs.files.read")).toEqual(
      new Set(["docs.folder:9"]),
    );
  });
});

describe("planVirtualParentDissolution", () => {
  it("copies the parent's unexpired grants to each child with provenance", () => {
    const parentGrant = grant("group:vp1", { pattern: "billing.invoices.read" }, "region:eu");
    const expired = grant("group:vp1", { pattern: "billing.invoices.export" }, "*", NOW - 1);
    const unrelated = grant("group:other", { pattern: "x.y.z" });
    const copies = planVirtualParentDissolution({
      parentSubject: "group:vp1",
      childSubjects: ["group:a", "group:b"],
      grants: [parentGrant, expired, unrelated],
      virtualParentId: "vp1",
      now: NOW,
    });
    expect(copies.length).toBe(2);
    expect(copies.map((c) => c.subject).sort()).toEqual(["group:a", "group:b"]);
    for (const copy of copies) {
      expect(copy.pattern).toBe("billing.invoices.read");
      expect(copy.scope).toBe("region:eu");
      expect(copy.provenance).toEqual({
        kind: "dissolution",
        virtualParentId: "vp1",
        originalGrantId: parentGrant.id,
      });
    }
  });
});
