/**
 * Adversarial security tests for the STORAGE SEAM and the Prisma driver.
 *
 * Scope: query construction, filter semantics, driver-contract conformance,
 * pagination bounds, LIKE/injection surface, uniqueness, and the
 * partial-failure ("fails open?") direction of multi-row operations.
 *
 * Method: the package deliberately keeps `@prisma/client` out of the
 * dependency graph, so these assert on the query objects the driver BUILDS
 * (via the structural mock in `mock-delegates.ts`) and on behaviour the
 * memory driver — the reference implementation — must agree with. Every
 * assertion states the SECURE, DESIRED behaviour. A failing test is a
 * finding, not a test to relax.
 */

/**
 * KNOWN-OPEN MARKER — `it.fails(...)` in this file.
 *
 * A test written as `it.fails` asserts the SECURE behavior and records that
 * Alfiz does not have it yet: it passes while the finding is open, and turns
 * RED the moment someone fixes the underlying issue. That is the point — the
 * failure is the signal to delete the `.fails` and promote the test, so a
 * fix can never land silently and a finding can never quietly rot.
 *
 * Every one of them is listed in the 0.7.1 changelog entry with its
 * severity. They are open findings, not accepted behavior.
 */
import { describe, expect, it } from "vitest";
import {
  createApplication,
  handleProviderOp,
  memoryDriver,
} from "@alfiz/application";
import type { StorageDriver } from "@alfiz/application";
import { defineCatalog } from "@alfiz/core";
import type {
  AccessRequest,
  AuditEvent,
  GrantRow,
  Provenance,
  RevokeRow,
} from "@alfiz/core";
import { prismaDriver } from "../src/index.js";
import { mockDelegates } from "./mock-delegates.js";

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

const admin: Provenance = { kind: "admin", actorUserId: "root" };

const grant = (
  id: string,
  subject: string,
  over: Partial<GrantRow> = {},
): GrantRow => ({
  id,
  subject,
  pattern: "docs.files.read",
  scope: "*",
  provenance: admin,
  createdAt: 1,
  ...over,
});

const revoke = (
  id: string,
  userId: string,
  over: Partial<RevokeRow> = {},
): RevokeRow => ({
  id,
  userId,
  pattern: "docs.*",
  scope: "*",
  provenance: admin,
  createdAt: 1,
  ...over,
});

const auditEvent = (id: string, at: number, over: Partial<AuditEvent> = {}) =>
  ({
    id,
    at,
    actor: "root",
    action: "grant.create",
    target: "t",
    ...over,
  }) as AuditEvent;

/** The same driver contract, over Prisma and over the reference driver. */
const bothDrivers = (): Array<[string, StorageDriver]> => [
  ["prisma", prismaDriver(mockDelegates())],
  ["memory", memoryDriver()],
];

const seedGrants = async (driver: StorageDriver): Promise<void> => {
  await driver.insertGrant(grant("g1", "user:u1"));
  await driver.insertGrant(grant("g2", "group:eng", { scope: "docs.folder:9" }));
  await driver.insertGrant(
    grant("g3", "user:u2", { pattern: undefined, roleId: "role-admin" }),
  );
};

const tick = (): Promise<void> => new Promise((r) => setTimeout(r, 0));

// ---------------------------------------------------------------------------
// 1. Filter semantics: what does an ABSENT / undefined / null field mean?
// ---------------------------------------------------------------------------

describe("filter semantics: the 'missing field silently means everything' class", () => {
  it("listGrants: absent filter, {}, and all-fields-undefined mean 'every row' — identically on both drivers", async () => {
    // `Application.listGrants` always builds the all-undefined shape
    // ({subject: q?.subject, scope: q?.scope, roleId: q?.roleId}), so this
    // is the literal production input for an unfiltered admin query.
    for (const [name, driver] of bothDrivers()) {
      await seedGrants(driver);
      const shapes = [
        undefined,
        {},
        { subject: undefined, scope: undefined, roleId: undefined },
      ];
      for (const filter of shapes) {
        expect(
          (await driver.listGrants(filter)).length,
          `${name} listGrants ${JSON.stringify(filter)}`,
        ).toBe(3);
        expect(
          await driver.countGrants(filter),
          `${name} countGrants ${JSON.stringify(filter)}`,
        ).toBe(3);
      }
    }
  });

  it("listGrants/countGrants: an EMPTY `subjects` closure returns NO rows — never 'everything'", async () => {
    // The closure-supply path passes `{subjects: closure}`. If an empty
    // closure widened to a table scan, every check would see every grant.
    for (const [name, driver] of bothDrivers()) {
      await seedGrants(driver);
      expect(await driver.listGrants({ subjects: [] }), name).toEqual([]);
      expect(await driver.countGrants({ subjects: [] }), name).toBe(0);
    }
  });

  it("listGrants/countGrants: contradictory subject + subjects is provably empty, not a scan", async () => {
    for (const [name, driver] of bothDrivers()) {
      await seedGrants(driver);
      const filter = { subject: "user:u1", subjects: ["user:u2"] } as const;
      expect(await driver.listGrants(filter), name).toEqual([]);
      expect(await driver.countGrants(filter), name).toBe(0);
    }
  });

  it("listGrants({ roleId: null }) must not widen to every pattern grant", async () => {
    // `null` reaches the seam from JSON (`{"filter":{"roleId":null}}` over
    // the provider API; `Application.listGrants` forwards it verbatim).
    // Prisma reads `where: { roleId: null }` on a NULLABLE column as
    // `roleId IS NULL` — i.e. EVERY pattern grant in the organization.
    // The reference driver returns nothing. Both must return nothing.
    for (const [name, driver] of bothDrivers()) {
      await seedGrants(driver);
      const filter = { roleId: null } as unknown as { roleId?: string };
      expect(await driver.listGrants(filter), `${name} listGrants`).toEqual([]);
      expect(await driver.countGrants(filter), `${name} countGrants`).toBe(0);
    }
  });

  it("countGrants agrees with listGrants for out-of-contract filter values too", async () => {
    for (const [name, driver] of bothDrivers()) {
      await seedGrants(driver);
      const filters = [
        { roleId: null },
        { roleId: "" },
        { subjects: [] },
        { subject: "user:u1", subjects: ["user:u2"] },
      ] as unknown as Array<{ roleId?: string }>;
      for (const filter of filters) {
        expect(
          await driver.countGrants(filter),
          `${name} ${JSON.stringify(filter)}`,
        ).toBe((await driver.listGrants(filter)).length);
      }
    }
  });

  it("listGrants: an UNKNOWN filter key is ignored identically by both drivers", async () => {
    // Pins the (currently unspecified) seam semantics: a typo'd or
    // attacker-supplied extra key must not change the result set, and must
    // not change it DIFFERENTLY per driver. The widening itself is a
    // contract-documentation gap, recorded in the report.
    for (const [name, driver] of bothDrivers()) {
      await seedGrants(driver);
      const filter = { subjekt: "user:u1" } as unknown as { subject?: string };
      expect((await driver.listGrants(filter)).length, name).toBe(3);
    }
  });

  it("listRevokes: absent filter, {}, and all-fields-undefined mean 'every row' identically", async () => {
    for (const [name, driver] of bothDrivers()) {
      await driver.insertRevoke(revoke("r1", "u1"));
      await driver.insertRevoke(revoke("r2", "u2", { scope: "docs.folder:9" }));
      for (const filter of [
        undefined,
        {},
        { userId: undefined, scope: undefined },
      ]) {
        expect(
          (await driver.listRevokes(filter)).length,
          `${name} ${JSON.stringify(filter)}`,
        ).toBe(2);
      }
    }
  });

  it("listRevokes: a user filter never drops that user's global-scope revoke", async () => {
    // A dropped REVOKE row is an access-control failure, not a UI bug.
    for (const [name, driver] of bothDrivers()) {
      await driver.insertRevoke(revoke("r1", "u1"));
      await driver.insertRevoke(revoke("r2", "u1", { scope: "docs.folder:9" }));
      await driver.insertRevoke(revoke("r3", "u2"));
      expect(
        (await driver.listRevokes({ userId: "u1" })).map((r) => r.id).sort(),
        name,
      ).toEqual(["r1", "r2"]);
    }
  });

  it("listRequests: state/requesterUserId filters never widen on undefined", async () => {
    const base: AccessRequest = {
      id: "req1",
      requesterUserId: "u1",
      pattern: "docs.files.read",
      scope: "*",
      justification: {},
      state: "pending",
      stageIndex: 0,
      stages: [],
      decisions: [],
      createdAt: 1,
    };
    for (const [name, driver] of bothDrivers()) {
      await driver.insertRequest(base);
      await driver.insertRequest({ ...base, id: "req2", state: "approved" });
      expect((await driver.listRequests()).length, name).toBe(2);
      expect(
        (await driver.listRequests({ state: undefined })).length,
        name,
      ).toBe(2);
      expect(
        (await driver.listRequests({ state: "pending" })).map((r) => r.id),
        name,
      ).toEqual(["req1"]);
    }
  });
});

// ---------------------------------------------------------------------------
// 2. Injection: scope / pattern strings must be VALUES, never query fragments
// ---------------------------------------------------------------------------

describe("injection surface: scope and pattern ids are values, not fragments", () => {
  it("a scope id carrying SQL/LIKE metacharacters matches only itself", async () => {
    for (const [name, driver] of bothDrivers()) {
      await driver.insertGrant(grant("a", "user:u1", { scope: "docs.folder:9" }));
      await driver.insertGrant(grant("b", "user:u1", { scope: "docs.folder:%" }));
      await driver.insertGrant(grant("c", "user:u1", { scope: "docs.folder:_" }));
      await driver.insertGrant(
        grant("d", "user:u1", { scope: "docs.folder:'; DROP TABLE x--" }),
      );

      // `%` must not act as a wildcard...
      expect(
        (await driver.listGrants({ scope: "docs.folder:%" })).map((g) => g.id),
        name,
      ).toEqual(["b"]);
      // ...nor `_` as a single-character wildcard.
      expect(
        (await driver.listGrants({ scope: "docs.folder:_" })).map((g) => g.id),
        name,
      ).toEqual(["c"]);
      // ...and a quote-bearing id round-trips as data.
      expect(
        (await driver.listGrants({ scope: "docs.folder:'; DROP TABLE x--" })).map(
          (g) => g.id,
        ),
        name,
      ).toEqual(["d"]);
      expect((await driver.listGrants()).length, name).toBe(4);
    }
  });

  it("the grant where-clause is built from equality/`in` only — no contains/startsWith/mode", async () => {
    const db = mockDelegates();
    const seen: unknown[] = [];
    const inner = db.alfizGrant.findMany.bind(db.alfizGrant);
    db.alfizGrant.findMany = async (args?: never) => {
      seen.push(args);
      return inner(args);
    };
    const driver = prismaDriver(db);
    await driver.listGrants({ scope: "docs.folder:%" });
    await driver.listGrants({ subjects: ["user:a", "user:b"] });
    await driver.listGrants({ subject: "user:a", roleId: "r1" });

    const banned = [
      "contains",
      "startsWith",
      "endsWith",
      "search",
      "mode",
      "not",
      "AND",
      "OR",
      "NOT",
    ];
    const flatten = (value: unknown): string[] =>
      value !== null && typeof value === "object"
        ? Object.entries(value as Record<string, unknown>).flatMap(([k, v]) => [
            k,
            ...flatten(v),
          ])
        : [];
    for (const args of seen) {
      for (const key of flatten(args)) {
        expect(banned, JSON.stringify(args)).not.toContain(key);
      }
    }
    expect(seen[0]).toEqual({ where: { scope: "docs.folder:%" } });
    expect(seen[1]).toEqual({ where: { subject: { in: ["user:a", "user:b"] } } });
    expect(seen[2]).toEqual({ where: { subject: "user:a", roleId: "r1" } });
  });

  it("audit orderBy is a literal constant — never a field name from input", async () => {
    const db = mockDelegates();
    const seen: Array<Record<string, unknown>> = [];
    const inner = db.alfizAudit.findMany.bind(db.alfizAudit);
    db.alfizAudit.findMany = async (args?: never) => {
      seen.push((args ?? {}) as Record<string, unknown>);
      return inner(args);
    };
    const driver = prismaDriver(db);
    await driver.listAudit({ target: "%' OR 1=1--", limit: 5 });
    await driver.listAudit({ cursor: { at: 1, id: "x" }, limit: 5 });
    for (const args of seen) {
      expect(args.orderBy).toEqual([{ at: "asc" }, { id: "asc" }]);
    }
    expect(seen[0]?.where).toEqual({ target: "%' OR 1=1--" });
  });

  it("the driver touches only Alfiz model delegates — no $queryRaw/$executeRaw/$transaction", async () => {
    const known = new Set([
      "alfizGrant",
      "alfizRevoke",
      "alfizRole",
      "alfizGroup",
      "alfizGroupParent",
      "alfizUser",
      "alfizMembership",
      "alfizRequest",
      "alfizCatalog",
      "alfizCatalogVersion",
      "alfizImports",
      "alfizAudit",
      "alfizEpoch",
      "alfizEvent",
      "alfizMetric",
    ]);
    const touched = new Set<string>();
    const raw = mockDelegates();
    const watched = new Proxy(raw as unknown as Record<string, unknown>, {
      get(target, prop, receiver) {
        if (typeof prop === "string") touched.add(prop);
        return Reflect.get(target, prop, receiver);
      },
    }) as unknown as ReturnType<typeof mockDelegates>;

    const driver = prismaDriver(watched);
    await driver.insertGrant(grant("g1", "user:u1"));
    await driver.listGrants({ subject: "user:u1" });
    await driver.countGrants();
    await driver.deleteGrant("g1");
    await driver.insertRevoke(revoke("r1", "u1"));
    await driver.listRevokes({ userId: "u1" });
    await driver.upsertRole({ id: "r", name: "R", patterns: ["docs.*"] });
    await driver.listRoles();
    await driver.upsertGroup({ id: "gr", name: "G", parents: [] });
    await driver.listGroups();
    await driver.upsertUser({
      userId: "u1",
      active: true,
      groupIds: ["gr"],
      orgIds: [],
      managerUserId: null,
    });
    await driver.listUsers();
    await driver.listUsersInGroup("gr");
    await driver.appendAudit(auditEvent("a1", 1));
    await driver.listAudit({ limit: 1 });
    await driver.appendEvents!([{ type: "all" }], 1);
    await driver.headSeq!();
    await driver.eventsSince!(0, 10);
    await driver.recordMetrics!([
      { bucket: 0, dimension: "grant", subject: "g1", metric: "matched", count: 1 },
    ]);
    await driver.readMetrics!({ dimension: "grant" });

    const unexpected = [...touched].filter((k) => !known.has(k));
    expect(unexpected).toEqual([]);
    expect([...touched].filter((k) => k.startsWith("$"))).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// 3. Pagination and limits
// ---------------------------------------------------------------------------

describe("pagination: a limit must bound the result, in every direction", () => {
  const seedAudit = async (driver: StorageDriver): Promise<void> => {
    for (let i = 0; i < 5; i++) await driver.appendAudit(auditEvent(`a${i}`, i));
  };

  it("prisma listAudit never returns more rows than `limit` — including 0 and negative", async () => {
    const driver = prismaDriver(mockDelegates());
    await seedAudit(driver);
    for (const limit of [0, 1, 3, 5, 50, -1, -3]) {
      const rows = await driver.listAudit({ limit });
      expect(rows.length, `limit=${limit}`).toBeLessThanOrEqual(Math.max(limit, 0));
    }
  });

  it("memory listAudit never returns more rows than `limit` — including 0 and negative", async () => {
    // The reference driver computes `rows.slice(-limit)`: `-0` is `0`, so
    // `limit: 0` returns the WHOLE audit table, and a negative limit skips
    // the oldest |limit| entries instead of bounding the page.
    const driver = memoryDriver();
    await seedAudit(driver);
    for (const limit of [0, 1, 3, 5, 50, -1, -3]) {
      const rows = await driver.listAudit({ limit });
      expect(rows.length, `limit=${limit}`).toBeLessThanOrEqual(Math.max(limit, 0));
    }
  });

  it("listAudit({ limit: 1 }) is the NEWEST event on both drivers (the hash-chain seed)", async () => {
    // `Application.audit` seeds the hash chain head from this exact call;
    // seeding from the OLDEST entry silently forks the chain.
    for (const [name, driver] of bothDrivers()) {
      await seedAudit(driver);
      expect((await driver.listAudit({ limit: 1 })).map((e) => e.id), name).toEqual(
        ["a4"],
      );
    }
  });

  it("cursor paging visits every audit row exactly once — no skipped rows", async () => {
    for (const [name, driver] of bothDrivers()) {
      for (let i = 0; i < 6; i++) {
        // Two events share each `at`, so ordering ties exercise the (at, id)
        // tiebreak that keeps a page boundary from dropping a row.
        await driver.appendAudit(auditEvent(`e${i}`, Math.floor(i / 2)));
      }
      const seen: string[] = [];
      let cursor: { at: number; id: string } | undefined;
      for (let guard = 0; guard < 20; guard++) {
        const page: AuditEvent[] = await driver.listAudit({
          limit: 2,
          ...(cursor ? { cursor } : {}),
        });
        if (page.length === 0) break;
        seen.push(...page.map((e) => e.id));
        const last = page[page.length - 1]!;
        cursor = { at: last.at, id: last.id };
      }
      // The very first page has no cursor, so it is the LAST `limit` rows by
      // contract; page from the beginning explicitly instead.
      const all = await driver.listAudit();
      const fromStart: string[] = [];
      let c: { at: number; id: string } | undefined = {
        at: all[0]!.at,
        id: all[0]!.id,
      };
      fromStart.push(all[0]!.id);
      for (let guard = 0; guard < 20; guard++) {
        const page: AuditEvent[] = await driver.listAudit({ limit: 2, cursor: c });
        if (page.length === 0) break;
        fromStart.push(...page.map((e) => e.id));
        const last = page[page.length - 1]!;
        c = { at: last.at, id: last.id };
      }
      expect(fromStart, name).toEqual(all.map((e) => e.id));
      expect(new Set(fromStart).size, name).toBe(all.length);
      expect(seen.length, name).toBeGreaterThan(0);
    }
  });

  it("eventsSince must never hand Prisma a NEGATIVE `take` (which silently means 'last N')", async () => {
    // `epoch.since(seq, limit)` forwards an attacker-supplied `limit`
    // straight through (`limit ?? 500` keeps a negative). Prisma reads a
    // negative `take` as "the LAST N of the ordered result": the caller
    // then advances its cursor to head having replayed only the newest
    // events, permanently dropping every invalidation in between.
    const db = mockDelegates();
    const seen: Array<{ take?: number }> = [];
    const inner = db.alfizEvent!.findMany.bind(db.alfizEvent!);
    db.alfizEvent!.findMany = async (args: never) => {
      seen.push(args as { take?: number });
      return inner(args);
    };
    const driver = prismaDriver(db);
    await driver.appendEvents!(
      [
        { type: "user", userId: "u1" },
        { type: "user", userId: "u2" },
        { type: "user", userId: "u3" },
      ],
      1_000,
    );
    await driver.eventsSince!(0, -1);
    expect(seen.length).toBeGreaterThan(0);
    for (const args of seen) {
      expect(
        args.take === undefined || args.take >= 0,
        `driver passed take=${String(args.take)} to Prisma (negative take = "last N")`,
      ).toBe(true);
    }
  });
});

// ---------------------------------------------------------------------------
// 4. The persisted invalidation log
// ---------------------------------------------------------------------------

describe("event log: replay must not skip an event", () => {
  it("eventsSince stops at a HOLE in the sequence instead of advancing past it", async () => {
    // Sequence numbers are allocated by an atomic increment on the epoch row
    // BEFORE the event rows are inserted, so a concurrent appender leaves a
    // window in which seq N+1 is visible while seq N is not yet committed.
    // Returning N+1 and reporting `upTo: N+1` retires seq N forever: the
    // reader's cache is never invalidated for it, so a revoked grant keeps
    // being served. `eventsSince` must return only the CONTIGUOUS prefix.
    const db = mockDelegates();
    const driver = prismaDriver(db);
    await driver.appendEvents!(
      [
        { type: "user", userId: "u1" },
        { type: "user", userId: "u2" },
        { type: "user", userId: "u3" },
      ],
      1_000,
    );
    // seq 2 is allocated but its row is not yet readable (in flight).
    const inner = db.alfizEvent!.findMany.bind(db.alfizEvent!);
    db.alfizEvent!.findMany = async (args: never) =>
      (await inner(args)).filter((row) => row.seq !== 2n);

    const page = await driver.eventsSince!(0, 100);
    expect("gap" in page).toBe(false);
    if ("gap" in page) return;
    expect(page.events.map((e) => (e.type === "user" ? e.userId : "?"))).toEqual([
      "u1",
    ]);
    expect(page.upTo).toBe(1);
  });

  it("two driver instances (two nodes) never allocate overlapping event sequences", async () => {
    const db = mockDelegates();
    const nodeA = prismaDriver(db);
    const nodeB = prismaDriver(db);
    await Promise.all([
      nodeA.appendEvents!([{ type: "user", userId: "a1" }, { type: "user", userId: "a2" }], 1),
      nodeB.appendEvents!([{ type: "user", userId: "b1" }, { type: "user", userId: "b2" }], 1),
    ]);
    const all = await nodeA.eventsSince!(0, 100);
    expect("gap" in all).toBe(false);
    if ("gap" in all) return;
    expect(all.events.length).toBe(4);
    expect(await nodeA.headSeq!()).toBe(4);
  });
});

// ---------------------------------------------------------------------------
// 5. Uniqueness and torn reads
// ---------------------------------------------------------------------------

describe("uniqueness: the schema's primary keys must be enforced by every driver", () => {
  it("prisma: re-inserting a grant/revoke/request id is rejected, never a silent overwrite", async () => {
    const driver = prismaDriver(mockDelegates());
    await driver.insertGrant(grant("g1", "user:u1"));
    await expect(
      driver.insertGrant(grant("g1", "user:attacker", { scope: "*" })),
    ).rejects.toThrow();
    await driver.insertRevoke(revoke("r1", "u1"));
    await expect(driver.insertRevoke(revoke("r1", "u2"))).rejects.toThrow();
    expect((await driver.listGrants())[0]?.subject).toBe("user:u1");
  });

  it("memory: re-inserting a grant/revoke id is rejected, never a silent overwrite", async () => {
    // `AlfizGrant.id` is a primary key. A driver that lets a second write
    // with the same id REPLACE the row diverges from the database it is a
    // reference for — an org snapshot carrying a chosen id would rewrite a
    // live grant on one driver and error on the other.
    const driver = memoryDriver();
    await driver.insertGrant(grant("g1", "user:u1"));
    await expect(
      driver.insertGrant(grant("g1", "user:attacker", { scope: "*" })),
    ).rejects.toThrow();
    await driver.insertRevoke(revoke("r1", "u1"));
    await expect(driver.insertRevoke(revoke("r1", "u2"))).rejects.toThrow();
  });

  it.fails("deleteGrant returns null when the row vanished between the read and the delete", async () => {
    // The driver reads the row, then issues deleteMany — and ignores the
    // affected-row count, so a concurrent deleter makes it report a
    // deletion it did not perform (a duplicate audited `grant.delete`).
    const db = mockDelegates();
    const driver = prismaDriver(db);
    await driver.insertGrant(grant("g1", "user:u1"));
    const innerFind = db.alfizGrant.findUnique.bind(db.alfizGrant);
    db.alfizGrant.findUnique = async (args: { where: { id: string } }) => {
      const row = await innerFind(args);
      // A concurrent actor deletes it right after our read.
      await db.alfizGrant.deleteMany({ where: { id: args.where.id } });
      return row;
    };
    expect(await driver.deleteGrant("g1")).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// 6. Transactionality: which partial failures leave a MORE PERMISSIVE state?
// ---------------------------------------------------------------------------

describe("transactionality: partial failures must not fail open", () => {
  it.fails("upsertRole never leaves the role transiently unreadable", async () => {
    // The Prisma driver implements upsertRole as deleteMany + create, and
    // `updateRole` is NOT wrapped in runExclusive, so a concurrent reader
    // sees the role missing. "Unknown roles confer nothing" — every grant
    // conferring it silently denies for the width of the window.
    const db = mockDelegates();
    const driver = prismaDriver(db);
    await driver.upsertRole({ id: "role1", name: "v1", patterns: ["docs.a"] });

    let release = (): void => {};
    const gate = new Promise<void>((r) => {
      release = r;
    });
    const innerCreate = db.alfizRole.create.bind(db.alfizRole);
    db.alfizRole.create = async (args: never) => {
      await gate;
      return innerCreate(args);
    };

    const pending = driver.upsertRole({
      id: "role1",
      name: "v2",
      patterns: ["docs.a", "docs.b"],
    });
    await tick();
    const midFlight = await driver.getRole("role1");
    release();
    await pending;
    expect(midFlight).not.toBeNull();
  });

  it.fails("upsertRole does not destroy the existing role when the write half fails", async () => {
    const db = mockDelegates();
    const driver = prismaDriver(db);
    await driver.upsertRole({ id: "role1", name: "v1", patterns: ["docs.a"] });
    db.alfizRole.create = async () => {
      throw new Error("transient database failure");
    };
    await expect(
      driver.upsertRole({ id: "role1", name: "v2", patterns: ["docs.b"] }),
    ).rejects.toThrow();
    expect(await driver.getRole("role1")).not.toBeNull();
  });

  it.fails("concurrent upsertRole calls converge instead of raising a duplicate-key error", async () => {
    const driver = prismaDriver(mockDelegates());
    await driver.upsertRole({ id: "role1", name: "v0", patterns: [] });
    await expect(
      Promise.all([
        driver.upsertRole({ id: "role1", name: "vA", patterns: ["docs.a"] }),
        driver.upsertRole({ id: "role1", name: "vB", patterns: ["docs.b"] }),
      ]),
    ).resolves.toBeDefined();
    expect(await driver.getRole("role1")).not.toBeNull();
  });

  it("createGrants is all-or-nothing: a failed batch leaves no live, unaudited grants", async () => {
    // The Application validates every input up front, then writes the rows
    // one at a time with no transaction. A failure on row N leaves rows
    // 1..N-1 LIVE and the batch audit entry never written: real access with
    // no audit record, and the caller believes the batch was rejected.
    const db = mockDelegates();
    let creates = 0;
    const innerCreate = db.alfizGrant.create.bind(db.alfizGrant);
    db.alfizGrant.create = async (args: never) => {
      if (++creates === 3) throw new Error("transient database failure");
      return innerCreate(args);
    };
    const storage = prismaDriver(db);
    const app = createApplication({
      catalog: defineCatalog({
        namespaces: ["docs"],
        permissions: [{ "docs.files.read": true, "docs.files.write": true }],
        scopeTypes: {},
      }),
      storage,
      clock: () => 1_000,
    });
    await expect(
      app.createGrants(
        [
          { subject: "user:u1", pattern: "docs.files.read" },
          { subject: "user:u2", pattern: "docs.files.read" },
          { subject: "user:u3", pattern: "docs.files.read" },
        ],
        admin,
      ),
    ).rejects.toThrow();
    expect(await storage.listGrants()).toEqual([]);
  });

  it("org.applySnapshot never exposes a window with global grants live and global revokes gone", async () => {
    // applyOrgSnapshot replaces global rows as delete-all-then-insert-all,
    // grants FIRST and revokes SECOND. Between "all old revokes deleted"
    // and "all new revokes inserted" the store holds a full set of grants
    // and NO negative layer — every check in that window answers ALLOW
    // where the correct answer is DENY. This is the happy path, not a
    // crash path.
    const db = mockDelegates();
    const base = prismaDriver(db);
    await base.insertGrant(grant("old-g", "user:u1"));
    await base.insertRevoke(revoke("old-r", "u1"));

    const samples: Array<{ grants: number; revokes: number }> = [];
    const mutators = new Set([
      "insertGrant",
      "deleteGrant",
      "insertRevoke",
      "deleteRevoke",
      "upsertRole",
      "deleteRole",
      "upsertGroup",
      "deleteGroup",
      "upsertUser",
      "insertRequest",
      "updateRequest",
    ]);
    const watched = new Proxy(base, {
      get(target, prop, receiver) {
        const value = Reflect.get(target, prop, receiver);
        if (typeof value !== "function") return value;
        const bound = value.bind(target);
        if (typeof prop !== "string" || !mutators.has(prop)) return bound;
        return async (...args: unknown[]) => {
          const out = await bound(...args);
          samples.push({
            grants: (await base.listGrants({ scope: "*" })).length,
            revokes: (await base.listRevokes({ scope: "*" })).length,
          });
          return out;
        };
      },
    }) as StorageDriver;

    const result = await handleProviderOp(
      {
        application: {} as never,
        storage: watched,
        secret: "s",
        applicationId: "app",
      },
      "org.applySnapshot",
      {
        snapshot: {
          groups: [],
          roles: [],
          users: [],
          globalGrants: [grant("new-g", "user:u1")],
          globalRevokes: [revoke("new-r", "u1")],
          pendingGlobalRequests: [],
          catalog: null,
        },
        authority: false,
        source: "sync:test",
      },
    );
    expect(result.status).toBe(200);
    expect(await base.listRevokes({ scope: "*" })).toHaveLength(1);

    const failOpen = samples.filter((s) => s.grants > 0 && s.revokes === 0);
    expect(failOpen).toEqual([]);
  });

  it("deleteUser removes the record and its edges; a partial failure never leaves memberships behind", async () => {
    const db = mockDelegates();
    const driver = prismaDriver(db);
    await driver.upsertUser({
      userId: "u1",
      active: true,
      groupIds: ["g1", "g2"],
      orgIds: [],
      managerUserId: null,
    });
    db.alfizUser.deleteMany = async () => {
      throw new Error("transient database failure");
    };
    await expect(driver.deleteUser("u1")).rejects.toThrow();
    // Edges are deleted first, so the surviving state is STRICTER, never
    // more permissive: the user must not still be a group member.
    expect(await driver.listUsersInGroup("g1")).toEqual([]);
    expect(await driver.listUsersInGroup("g2")).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// 7. Seam semantics the shipped conformance suite does NOT pin down
//    (all currently hold on both bundled drivers; these lock them in so a
//     third-party driver cannot diverge and still be called "conformant")
// ---------------------------------------------------------------------------

describe("conformance gaps: semantics driver-suite.ts leaves unasserted", () => {
  it("upsertRole DOWNGRADE clears `requestable` — a role made non-requestable stays non-requestable", async () => {
    // The suite only upgrades (no requestable -> requestable). A driver
    // implementing upsert as a partial `update` would leave the old policy
    // in place: the role stays requestable after being locked down.
    for (const [name, driver] of bothDrivers()) {
      await driver.upsertRole({
        id: "role1",
        name: "R",
        patterns: ["docs.a"],
        requestable: { stages: [{ kind: "management" }] },
      });
      await driver.upsertRole({ id: "role1", name: "R", patterns: ["docs.a"] });
      expect((await driver.getRole("role1"))?.requestable ?? undefined, name).toBe(
        undefined,
      );
    }
  });

  it("upsertGroup REMOVES parent edges dropped from the record", async () => {
    // Detaching a group from its parent is a de-privileging write. A driver
    // that only adds edges leaves the child inheriting the parent's grants.
    for (const [name, driver] of bothDrivers()) {
      await driver.upsertGroup({ id: "p1", name: "P1", parents: [] });
      await driver.upsertGroup({ id: "p2", name: "P2", parents: [] });
      await driver.upsertGroup({ id: "c", name: "C", parents: ["p1", "p2"] });
      await driver.upsertGroup({ id: "c", name: "C", parents: ["p2"] });
      expect((await driver.getGroup("c"))?.parents, name).toEqual(["p2"]);
      expect(
        (await driver.listGroups()).find((g) => g.id === "c")?.parents,
        `${name} listGroups`,
      ).toEqual(["p2"]);
    }
  });

  it("upsertUser REMOVES memberships dropped from the record", async () => {
    for (const [name, driver] of bothDrivers()) {
      const base = { userId: "u1", active: true, orgIds: [], managerUserId: null };
      await driver.upsertUser({ ...base, groupIds: ["g1", "g2"] });
      await driver.upsertUser({ ...base, groupIds: ["g2"] });
      expect((await driver.getUser("u1"))?.groupIds, name).toEqual(["g2"]);
      expect(await driver.listUsersInGroup("g1"), name).toEqual([]);
      expect(await driver.listUsersInGroup("g2"), name).toEqual(["u1"]);
    }
  });

  it("deleteGroup drops the group's own parent edges but not edges naming it as parent", async () => {
    for (const [name, driver] of bothDrivers()) {
      await driver.upsertGroup({ id: "p", name: "P", parents: [] });
      await driver.upsertGroup({ id: "m", name: "M", parents: ["p"] });
      await driver.upsertGroup({ id: "c", name: "C", parents: ["m"] });
      await driver.deleteGroup("m");
      expect(await driver.getGroup("m"), name).toBeNull();
      // The child's record still names the deleted parent — repairing that
      // is the Application's job, and both drivers must agree it survives.
      expect((await driver.getGroup("c"))?.parents, name).toEqual(["m"]);
    }
  });

  it("getRoles: empty input, absent ids, and no unrequested rows", async () => {
    // The OPTIONAL batch read on the hot closure-supply path — the suite
    // never exercises it at all.
    for (const [name, driver] of bothDrivers()) {
      await driver.upsertRole({ id: "a", name: "A", patterns: [] });
      await driver.upsertRole({ id: "b", name: "B", patterns: [] });
      expect(await driver.getRoles!([]), name).toEqual([]);
      const got = await driver.getRoles!(["a", "missing"]);
      expect(got.map((r) => r.id), name).toEqual(["a"]);
      const dup = await driver.getRoles!(["a", "a"]);
      expect(new Set(dup.map((r) => r.id)), name).toEqual(new Set(["a"]));
    }
  });

  it("putImports/getImports round-trip (never exercised by the suite)", async () => {
    for (const [name, driver] of bothDrivers()) {
      if (!driver.putImports || !driver.getImports) continue;
      expect(await driver.getImports(), name).toBeNull();
      const manifest = { formatVersion: 1 as const, imports: [] };
      await driver.putImports(3, manifest as never);
      expect((await driver.getImports())?.version, name).toBe(3);
    }
  });

  it("runExclusive releases the lock when the body throws — no deadlock", async () => {
    for (const [name, driver] of bothDrivers()) {
      await expect(
        driver.runExclusive("k", async () => {
          throw new Error("boom");
        }),
      ).rejects.toThrow("boom");
      // A driver that leaked the lock on error would hang here forever.
      const after = await Promise.race([
        driver.runExclusive("k", async () => "ok"),
        new Promise((r) => setTimeout(() => r("DEADLOCK"), 200)),
      ]);
      expect(after, name).toBe("ok");
    }
  });

  it("runExclusive does not serialize ACROSS keys (a single global lock is not conformant)", async () => {
    for (const [name, driver] of bothDrivers()) {
      const order: string[] = [];
      await Promise.all([
        driver.runExclusive("groups", async () => {
          await new Promise((r) => setTimeout(r, 25));
          order.push("groups");
        }),
        driver.runExclusive("reporting", async () => {
          order.push("reporting");
        }),
      ]);
      expect(order, name).toEqual(["reporting", "groups"]);
    }
  });
});

// ---------------------------------------------------------------------------
// 8. Cross-driver value mapping
// ---------------------------------------------------------------------------

describe("value mapping: out-of-contract numbers must not diverge between drivers", () => {
  it("listAudit with a non-integer time bound behaves the same on both drivers", async () => {
    // `toBig` is a bare `BigInt(value)`: a fractional or NaN bound from the
    // wire (`{"filter":{"from":0.5}}`) throws RangeError on Prisma while the
    // reference driver quietly filters. A driver contract that does not pin
    // this leaves each implementation to invent its own answer.
    const results: Array<{ name: string; outcome: string }> = [];
    for (const [name, driver] of bothDrivers()) {
      await driver.appendAudit(auditEvent("a0", 0));
      await driver.appendAudit(auditEvent("a1", 1));
      try {
        const rows = await driver.listAudit({ from: 0.5 });
        results.push({ name, outcome: `rows:${rows.map((r) => r.id).join(",")}` });
      } catch (error) {
        results.push({ name, outcome: `throw:${(error as Error).name}` });
      }
    }
    expect(results[0]?.outcome).toBe(results[1]?.outcome);
  });

  it("grant rows round-trip subject/scope strings byte-for-byte, including odd characters", async () => {
    const nasty = [
      "user:ünïcødé",
      "user:with space",
      "user:%_\\",
      "group:tab\there",
    ];
    for (const [name, driver] of bothDrivers()) {
      for (const [i, subject] of nasty.entries()) {
        await driver.insertGrant(grant(`n${i}`, subject));
      }
      for (const subject of nasty) {
        expect(
          (await driver.listGrants({ subject })).map((g) => g.subject),
          `${name} ${subject}`,
        ).toEqual([subject]);
      }
    }
  });
});
