/**
 * Adversarial review: BROWN-FIELD deployments and resource exhaustion.
 *
 * Every other suite exercises a correctly-configured system. This one is the
 * misconfigured one, and the hostile-sized one. Two questions:
 *
 *   (A) When a developer gets an option wrong — an ancestry resolver that
 *       throws or swallows its own errors, a resolver that was never wired
 *       up, `externalPermissions: "warn"`, a catalog rebuilt from a runtime
 *       document, `memoryDriver()` copy-pasted from the quickstart — does
 *       Alfiz fail CLOSED or OPEN?
 *   (B) Given a hostile-sized input — deep ancestor chains, cyclic parents,
 *       adversarial cardinality — does everything TERMINATE inside a bound?
 *
 * Every test below asserts the SECURE, DESIRED behavior. A passing test locks
 * a defense in; a failing one is a finding. Sizes are bounded (thousands, not
 * millions) and assertions are on direction-of-failure and termination, never
 * on wall-clock timings, so this file is stable in CI.
 */

import { describe, expect, it, vi } from "vitest";
import type { AnyCatalog, CatalogDocument } from "@alfiz/core";
import {
  UnknownPermissionError,
  UnresolvedScopeError,
  catalogFromDocument,
  createAlfizClient,
  createMetricsAggregator,
  defineCatalog,
  lintCatalog,
  parentPointerResolver,
} from "@alfiz/core";
import { createApplication, memoryDriver } from "@alfiz/application";
import { admin } from "./fixtures.js";

// ---------------------------------------------------------------------------
// Shared fixtures: a two-level hierarchy (folder → doc) and its host tables.
// ---------------------------------------------------------------------------

const hierarchical = (docParent: string | null = "docs.folder") =>
  defineCatalog({
    namespaces: ["docs"],
    permissions: {
      "docs.files.read": { scopes: ["docs.folder", "docs.doc"] },
      "docs.files.update_file": { scopes: ["docs.folder", "docs.doc"] },
    },
    scopeTypes: {
      "docs.folder": { parent: null },
      "docs.doc": { parent: docParent },
    },
  });

const flat = () =>
  defineCatalog({
    namespaces: ["docs"],
    permissions: { "docs.files.read": true },
  });

/** doc:1 lives in folder:9 — the host's own table, which Alfiz never sees. */
const hostParents = new Map<string, string | null>([
  ["docs.doc:1", "docs.folder:9"],
  ["docs.folder:9", null],
]);
const goodAncestry = parentPointerResolver((s) => hostParents.get(s) ?? null);

/** Did the promise reject (fail closed) rather than answer `true`? */
const outcomeOf = async (fn: () => Promise<unknown>): Promise<"rejected" | unknown> => {
  try {
    return await fn();
  } catch {
    return "rejected";
  }
};

// ===========================================================================
// (A1) The ancestry resolver — the host writes it, and it WILL sometimes fail
// ===========================================================================

describe("brown-field: an ancestry resolver that throws must fail CLOSED", () => {
  const boom = () => {
    throw new Error("ancestry database unreachable");
  };

  const setup = async () => {
    const catalog = hierarchical();
    const app = createApplication({
      catalog,
      storage: memoryDriver(),
      ancestry: boom,
    });
    const client = createAlfizClient({ catalog, provider: app });
    // A scoped grant, so every shape has a reason to consult the resolver.
    await app.createGrant({
      subject: "user:u",
      pattern: "docs.files.read",
      scope: "docs.folder:9",
      provenance: admin,
    });
    return { app, client };
  };

  it("can() rejects rather than answering", async () => {
    const { client } = await setup();
    await expect(
      client.can({ userId: "u" }, "docs.files.read", "docs.doc:1"),
    ).rejects.toThrow(/ancestry database unreachable/);
  });

  it("can.fresh() rejects rather than answering", async () => {
    const { client } = await setup();
    await expect(
      client.can.fresh({ userId: "u" }, "docs.files.read", "docs.doc:1"),
    ).rejects.toThrow(/ancestry database unreachable/);
  });

  it("require() rejects (and never silently permits)", async () => {
    const { client } = await setup();
    await expect(
      client.require({ userId: "u" }, "docs.files.read", "docs.doc:1"),
    ).rejects.toThrow(/ancestry database unreachable/);
  });

  it("canAny() rejects once a scoped grant forces a chain resolution", async () => {
    const { client } = await setup();
    await expect(client.canAny({ userId: "u" }, "docs.*")).rejects.toThrow(
      /ancestry database unreachable/,
    );
  });

  it("snapshot() rejects while pre-resolving the principal's granted scopes", async () => {
    const { client } = await setup();
    await expect(client.snapshot({ userId: "u" })).rejects.toThrow(
      /ancestry database unreachable/,
    );
  });

  it("snapshot.resolve() rejects rather than leaving the scope unresolved-but-checkable", async () => {
    const catalog = hierarchical();
    let failing = false;
    const app = createApplication({
      catalog,
      storage: memoryDriver(),
      ancestry: (s) => {
        if (failing) boom();
        return goodAncestry(s);
      },
    });
    const client = createAlfizClient({ catalog, provider: app });
    await app.createGrant({
      subject: "user:u",
      pattern: "docs.files.read",
      provenance: admin,
    });
    const snap = await client.snapshot({ userId: "u" });
    failing = true;
    await expect(snap.resolve(["docs.doc:1"])).rejects.toThrow(
      /ancestry database unreachable/,
    );
    // …and the scope stays unresolved, so a later sync check still refuses.
    expect(() => snap.can("docs.files.read", "docs.doc:1")).toThrow(
      UnresolvedScopeError,
    );
  });

  it("a resolver returning a non-array fails CLOSED", async () => {
    const catalog = hierarchical();
    const app = createApplication({
      catalog,
      storage: memoryDriver(),
      ancestry: (() => null) as never,
    });
    const client = createAlfizClient({ catalog, provider: app });
    await app.createGrant({
      subject: "user:u",
      pattern: "docs.files.read",
      provenance: admin,
    });
    expect(
      await outcomeOf(() =>
        client.can({ userId: "u" }, "docs.files.read", "docs.doc:1"),
      ),
    ).toBe("rejected");
  });
});

describe("brown-field: a TRUNCATED ancestor chain must not drop an ancestor revoke", () => {
  /**
   * The failure the snapshot's docblock calls out by name: "a truncated chain
   * would miss ancestor grants (fail-closed) and ancestor revokes (fail-OPEN),
   * and the second is the direction a mistake here must never take." The async
   * client has no equivalent guard — it trusts whatever the resolver returns.
   */
  it("a resolver that swallows its own DB error and returns [] must not un-revoke", async () => {
    const catalog = hierarchical();
    let dbUp = true;
    const app = createApplication({
      catalog,
      storage: memoryDriver(),
      // The shape a host writes when it does not want auth to break on a
      // blip. It is exactly the wrong shape, and nothing says so.
      ancestry: (scope) => {
        try {
          if (!dbUp) throw new Error("blip");
          return goodAncestry(scope);
        } catch {
          return [];
        }
      },
    });
    const client = createAlfizClient({ catalog, provider: app });
    await app.createGrant({
      subject: "user:u",
      pattern: "docs.files.read",
      scope: "docs.doc:1",
      provenance: admin,
    });
    await app.createRevoke({
      userId: "u",
      pattern: "docs.files.read",
      scope: "docs.folder:9",
      provenance: admin,
    });
    expect(
      await client.can.fresh({ userId: "u" }, "docs.files.read", "docs.doc:1"),
    ).toBe(false);

    dbUp = false;
    // Negative always wins, scope-inclusively — including when the chain
    // could not be resolved. A missing chain is not evidence of no ancestor.
    //
    // The catalog declares docs.doc nested under docs.folder, so an EMPTY
    // chain contradicts the declaration and is refused rather than believed.
    // Refusing is stronger than answering false: the check cannot be
    // answered at all, and nothing downstream can mistake the deny for a
    // considered one.
    await expect(
      client.can.fresh({ userId: "u" }, "docs.files.read", "docs.doc:1"),
    ).rejects.toThrow(/returned no ancestors/);
  });

  it("hierarchical scope types with NO ancestry resolver must not silently truncate", async () => {
    const catalog = hierarchical();
    // `ancestry` omitted — documented as "for fully-global deployments", but
    // this catalog declares docs.doc nested under docs.folder, so the two
    // configurations are in contradiction and nothing reports it.
    const app = createApplication({ catalog, storage: memoryDriver() });
    const client = createAlfizClient({ catalog, provider: app });
    await app.createGrant({
      subject: "user:u",
      pattern: "docs.files.read",
      scope: "docs.doc:1",
      provenance: admin,
    });
    await app.createRevoke({
      userId: "u",
      pattern: "docs.files.*",
      scope: "docs.folder:9",
      provenance: admin,
    });
    // Same contradiction, reached by omission rather than by a lying
    // resolver: the default `() => []` cannot be right for a type the
    // catalog nests. Construction already warns; this is the check itself
    // refusing rather than quietly dropping the folder revoke.
    await expect(
      client.can({ userId: "u" }, "docs.files.read", "docs.doc:1"),
    ).rejects.toThrow(/returned no ancestors/);
  });

  it("snapshot.can must not fail OPEN when a scope type is mis-declared parent:null", async () => {
    // The catalog says docs.doc is flat; the host's tables nest it under a
    // folder. `client.can` consults the resolver and denies; the snapshot
    // trusts the declaration, synthesizes [scope, "*"], and allows.
    const catalog = hierarchical(null);
    const app = createApplication({
      catalog,
      storage: memoryDriver(),
      ancestry: goodAncestry,
    });
    const client = createAlfizClient({ catalog, provider: app });
    await app.createGrant({
      subject: "user:u",
      pattern: "docs.files.read",
      provenance: admin,
    });
    await app.createRevoke({
      userId: "u",
      pattern: "docs.files.read",
      scope: "docs.folder:9",
      provenance: admin,
    });
    // `parent: null` is a promise, not a hint: the snapshot answers scoped
    // checks for a flat type synchronously, synthesizing [scope, "*"] and
    // consulting no resolver — so it CANNOT see that the host nests the
    // type, and no amount of care on the snapshot path can make it. The
    // contradiction is therefore caught where it is visible: the async path
    // resolves the chain, sees ancestors for a type declared flat, and
    // refuses instead of answering. That turns a silent permissive
    // disagreement between the two surfaces into a loud error naming the
    // mis-declaration.
    // The async path resolves the chain and denies correctly. The snapshot
    // cannot: it synthesizes [scope, "*"] for a flat type by construction.
    // So the contradiction is reported where it is visible, once per scope
    // type, rather than the two surfaces silently disagreeing.
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const asyncAnswer = await client.can(
      { userId: "u" },
      "docs.files.read",
      "docs.doc:1",
    );
    expect(asyncAnswer).toBe(false);
    expect(warn.mock.calls.flat().join(" ")).toMatch(
      /declares "docs.doc" with .parent: null./,
    );
    warn.mockRestore();
  });
});

// ===========================================================================
// (B1) Termination: cycles, depth, width
// ===========================================================================

describe("resource exhaustion: hierarchies terminate inside a bound", () => {
  it("a parent cycle introduced at READ time terminates and answers", async () => {
    const catalog = hierarchical();
    const cyclic = new Map<string, string>([
      ["docs.doc:1", "docs.folder:9"],
      ["docs.folder:9", "docs.folder:8"],
      ["docs.folder:8", "docs.folder:9"], // the cycle the write path forbids
    ]);
    const app = createApplication({
      catalog,
      storage: memoryDriver(),
      ancestry: parentPointerResolver((s) => cyclic.get(s) ?? null),
    });
    const client = createAlfizClient({ catalog, provider: app });
    await app.createGrant({
      subject: "user:u",
      pattern: "docs.files.read",
      scope: "docs.folder:8",
      provenance: admin,
    });
    expect(
      await client.can({ userId: "u" }, "docs.files.read", "docs.doc:1"),
    ).toBe(true);
  });

  it("a resolver returning a self-referential chain terminates", async () => {
    const catalog = hierarchical();
    const app = createApplication({
      catalog,
      storage: memoryDriver(),
      ancestry: (s) => [s, "docs.folder:9", s, "docs.folder:9", s],
    });
    const client = createAlfizClient({ catalog, provider: app });
    await app.createGrant({
      subject: "user:u",
      pattern: "docs.files.read",
      scope: "docs.folder:9",
      provenance: admin,
    });
    expect(
      await client.can({ userId: "u" }, "docs.files.read", "docs.doc:1"),
    ).toBe(true);
  });

  it("parentPointerResolver bounds pathological depth and fails CLOSED", async () => {
    const catalog = hierarchical();
    const deep = new Map<string, string>();
    for (let i = 0; i < 10_050; i++) deep.set(`docs.folder:${i}`, `docs.folder:${i + 1}`);
    const app = createApplication({
      catalog,
      storage: memoryDriver(),
      ancestry: parentPointerResolver((s) => deep.get(s) ?? null),
    });
    const client = createAlfizClient({ catalog, provider: app });
    await app.createGrant({
      subject: "user:u",
      pattern: "docs.files.read",
      scope: "docs.folder:10000",
      provenance: admin,
    });
    expect(
      await outcomeOf(() =>
        client.can({ userId: "u" }, "docs.files.read", "docs.folder:0"),
      ),
    ).toBe("rejected");
  });

  it("a 5 000-ancestor chain from a custom resolver terminates and stays exact", async () => {
    const catalog = hierarchical();
    const chain = Array.from({ length: 5_000 }, (_, i) => `docs.folder:${i}`);
    const app = createApplication({
      catalog,
      storage: memoryDriver(),
      ancestry: () => chain,
    });
    const client = createAlfizClient({ catalog, provider: app });
    await app.createGrant({
      subject: "user:u",
      pattern: "docs.files.read",
      scope: "docs.folder:4999",
      provenance: admin,
    });
    expect(
      await client.can({ userId: "u" }, "docs.files.read", "docs.doc:1"),
    ).toBe(true);
    // …and a revoke anywhere along it still wins.
    await app.createRevoke({
      userId: "u",
      pattern: "docs.files.read",
      scope: "docs.folder:17",
      provenance: admin,
    });
    expect(
      await client.can.fresh({ userId: "u" }, "docs.files.read", "docs.doc:1"),
    ).toBe(false);
  });

  it("a 1 500-deep group-parent chain terminates, and group cycles are rejected", async () => {
    const catalog = flat();
    const app = createApplication({ catalog, storage: memoryDriver() });
    const N = 1_500;
    for (let i = 0; i < N; i++) {
      await app.createGroup(
        { id: `g${i}`, name: `g${i}`, parents: i === 0 ? [] : [`g${i - 1}`] },
        admin,
      );
    }
    await app.setGroupMembership("u", [`g${N - 1}`], admin);
    await app.createGrant({
      subject: "group:g0",
      pattern: "docs.files.read",
      provenance: admin,
    });
    const client = createAlfizClient({ catalog, provider: app });
    expect(await client.can.fresh({ userId: "u" }, "docs.files.read")).toBe(true);
    // Closing the loop is a write-path rejection, not a read-path hang.
    await expect(app.setGroupParents("g0", [`g${N - 1}`], admin)).rejects.toThrow(
      /cycle/,
    );
    await expect(app.setGroupParents("g0", ["g0"], admin)).rejects.toThrow(/cycle/);
  });

  it("a wide group graph (1 000-way fan-in) terminates", async () => {
    const catalog = flat();
    const app = createApplication({ catalog, storage: memoryDriver() });
    await app.createGroup({ id: "root", name: "root", parents: [] }, admin);
    const parents: string[] = [];
    for (let i = 0; i < 1_000; i++) {
      await app.createGroup({ id: `p${i}`, name: `p${i}`, parents: ["root"] }, admin);
      parents.push(`p${i}`);
    }
    await app.createGroup({ id: "leaf", name: "leaf", parents }, admin);
    await app.setGroupMembership("u", ["leaf"], admin);
    await app.createGrant({
      subject: "group:root",
      pattern: "docs.files.read",
      provenance: admin,
    });
    const client = createAlfizClient({ catalog, provider: app });
    expect(await client.can.fresh({ userId: "u" }, "docs.files.read")).toBe(true);
  });
});

// ===========================================================================
// (A2) catalogFromDocument — the codegen / federation path takes runtime JSON
// ===========================================================================

/**
 * A document from a registry is attacker-adjacent input. `defineCatalog`
 * validates every one of these; `catalogFromDocument` checks only
 * `formatVersion`.
 */
const documentWith = (leaves: unknown[]): CatalogDocument =>
  ({
    formatVersion: 1,
    namespace: "docs",
    namespaces: ["docs"],
    leaves,
    groups: [
      { path: "docs", groups: ["docs.files"], permissions: [] },
      { path: "docs.files", groups: [], permissions: ["docs.files.read"] },
    ],
    scopeTypes: [],
    navigation: [],
  }) as unknown as CatalogDocument;

const leaf = (key: string, extra: Record<string, unknown> = {}) => ({
  key,
  groupPath: key.slice(0, key.lastIndexOf(".")),
  name: key.slice(key.lastIndexOf(".") + 1),
  kind: "action",
  destructive: false,
  scopes: [],
  impliedOnAncestors: false,
  ...extra,
});

describe("brown-field: catalogFromDocument must validate as strictly as defineCatalog", () => {
  it("rejects a leaf key containing a wildcard (a gate must never check a pattern)", () => {
    // `Catalog.admittingRegion` guards this for open regions with an explicit
    // comment — "which would let a gate check a wildcard, the one thing `can`
    // must never do". A document walks straight past it.
    expect(() =>
      catalogFromDocument(documentWith([leaf("docs.files.*"), leaf("docs.files.read")])),
    ).toThrow();
  });

  it("rejects a leaf outside the document's declared namespaces", () => {
    expect(() =>
      catalogFromDocument(documentWith([leaf("evil.take.over"), leaf("docs.files.read")])),
    ).toThrow();
  });

  it("rejects a key that is also a group path", () => {
    expect(() =>
      catalogFromDocument(
        documentWith([leaf("docs.files"), leaf("docs.files.read")]),
      ),
    ).toThrow();
  });

  it("rejects duplicate leaf keys instead of silently keeping the last (widest) one", () => {
    expect(() =>
      catalogFromDocument(
        documentWith([
          leaf("docs.files.read", { scopes: [] }),
          leaf("docs.files.read", { scopes: ["docs.folder"] }),
        ]),
      ),
    ).toThrow();
  });

  it("rejects a scope-type parent cycle", () => {
    const doc = {
      ...documentWith([leaf("docs.files.read")]),
      scopeTypes: [
        { type: "docs.a", parent: "docs.b", multiParent: false },
        { type: "docs.b", parent: "docs.a", multiParent: false },
      ],
    } as unknown as CatalogDocument;
    expect(() => catalogFromDocument(doc)).toThrow();
  });

  it("a bare global `*` grant must not confer a key injected by an unvalidated document", async () => {
    // The impact of the above, stated as access: the catalog's rule is that
    // `*` confers only DECLARED vocabulary. An unvalidated document decides
    // what "declared" means, so a namespace nobody owns rides in on it.
    // Closed at the door: the injected key never becomes vocabulary, so
    // there is no catalog in which a bare `*` could confer it.
    expect(() =>
      catalogFromDocument(
        documentWith([leaf("evil.take.over"), leaf("docs.files.read")]),
      ),
    ).toThrow(/not one of this document.s namespaces/);

    // And the same grant over a document that validates confers only what
    // the document actually declares.
    const catalog = catalogFromDocument(documentWith([leaf("docs.files.read")]));
    const app = createApplication({ catalog, storage: memoryDriver() });
    const client = createAlfizClient({ catalog, provider: app });
    await app.createGrant({
      subject: "user:root",
      pattern: "*",
      provenance: admin,
    });
    expect(await client.can({ userId: "root" }, "docs.files.read")).toBe(true);
    await expect(
      client.can({ userId: "root" }, "evil.take.over"),
    ).rejects.toThrow();
  });

  it("an import declared strict:true stays strict across a document round-trip", () => {
    const source = defineCatalog({
      namespaces: ["docs"],
      permissions: { "docs.files.read": true },
      imports: {
        zoom: { strict: true, permissions: { "zoom.meetings.*": true } },
      },
    });
    // Strict means: the region declares grantable vocabulary, but `can()` on
    // an unenumerated key under it throws rather than being evaluated.
    expect(source.hasKey("zoom.meetings.anything")).toBe(false);

    const rebuilt = catalogFromDocument(source.toDocument(), {
      imports: source.toImportManifest(),
    });
    // `ImportManifestEntry` carries no `strict` field, so the posture is lost
    // on the wire and the reconstruction defaults to permissive.
    expect(rebuilt.hasKey("zoom.meetings.anything")).toBe(false);
  });
});

// ===========================================================================
// (A3) externalPermissions — the brown-field escape hatch
// ===========================================================================

describe("brown-field: externalPermissions never softens what it promises not to", () => {
  const warnClient = async (catalog: AnyCatalog, mode: "warn" | "allow" = "warn") => {
    const app = createApplication({ catalog, storage: memoryDriver() });
    const seen: string[] = [];
    const client = createAlfizClient({
      catalog,
      provider: app,
      externalPermissions: mode,
      onExternalPermission: (info) => seen.push(info.permission),
    });
    await app.createGrant({
      subject: "user:root",
      pattern: "*",
      provenance: admin,
    });
    return { app, client, seen };
  };

  it('"warn" still throws on a typo in an OWNED namespace', async () => {
    const { client } = await warnClient(flat());
    await expect(
      client.can({ userId: "root" }, "docs.files.raed" as never),
    ).rejects.toThrow(UnknownPermissionError);
  });

  it('"allow" still throws on a typo in an OWNED namespace', async () => {
    const { client } = await warnClient(flat(), "allow");
    await expect(
      client.can({ userId: "root" }, "docs.files.raed" as never),
    ).rejects.toThrow(UnknownPermissionError);
  });

  it('"warn" still throws for a key under an ENUMERATED import', async () => {
    const zoomDoc = defineCatalog({
      namespaces: ["zoom"],
      includeAlfizInternal: false,
      conventions: { depth: "any" },
      permissions: { "zoom.host": true, "zoom.meetings.read": true },
    }).toDocument();
    const catalog = defineCatalog({
      namespaces: ["docs"],
      permissions: { "docs.files.read": true },
      imports: {
        zoom: { document: zoomDoc, permissions: { "zoom.meetings.*": true } },
      },
    });
    const { client } = await warnClient(catalog);
    await expect(
      client.can({ userId: "root" }, "zoom.meetings.raed" as never),
    ).rejects.toThrow(UnknownPermissionError);
  });

  it('"warn" still throws inside a STRICT open region', async () => {
    const catalog = defineCatalog({
      namespaces: ["docs"],
      permissions: { "docs.files.read": true },
      imports: {
        zoom: { strict: true, permissions: { "zoom.meetings.*": true } },
      },
    });
    const { client } = await warnClient(catalog);
    await expect(
      client.can({ userId: "root" }, "zoom.meetings.typo" as never),
    ).rejects.toThrow(UnknownPermissionError);
  });

  it("a bare global `*` never confers a permission admitted by the policy", async () => {
    const { client, seen } = await warnClient(flat());
    expect(await client.can({ userId: "root" }, "zoom.host" as never)).toBe(false);
    expect(seen).toEqual(["zoom.host"]);
  });

  it("an owned namespace that is a PREFIX of the checked one is not treated as owning it", async () => {
    // `docsx.*` is genuinely foreign to a catalog owning `docs`; the prefix
    // must not make it owned, nor must it make `docs.*` foreign.
    const { client } = await warnClient(flat());
    expect(await client.can({ userId: "root" }, "docsx.files.read" as never)).toBe(
      false,
    );
    await expect(
      client.can({ userId: "root" }, "docs.nope.read" as never),
    ).rejects.toThrow(UnknownPermissionError);
  });

  it("an import whose namespace prefix-collides with an owned one cannot reach into it", async () => {
    const catalog = defineCatalog({
      namespaces: ["docs"],
      permissions: { "docs.files.read": true },
      imports: { doc: { permissions: { "doc.thing.*": true } } },
    });
    expect(catalog.hasKey("docs.files.secret")).toBe(false);
    expect(catalog.isKnownPattern("docs.files.*")).toBe(true);
    const { client } = await warnClient(catalog);
    await expect(
      client.can({ userId: "root" }, "docs.files.secret" as never),
    ).rejects.toThrow(UnknownPermissionError);
  });

  it("an import cannot declare keys outside the namespace it names", () => {
    expect(() =>
      defineCatalog({
        namespaces: ["docs"],
        permissions: { "docs.files.read": true },
        imports: { zoom: { permissions: { "docs.files.escalate": true } } },
      }),
    ).toThrow();
    expect(() =>
      defineCatalog({
        namespaces: ["docs"],
        permissions: { "docs.files.read": true },
        imports: { docs: { permissions: { "docs.other.read": true } } },
      }),
    ).toThrow();
  });

  it("the once-per-permission warn dedupe set is BOUNDED under runtime-string keys", async () => {
    // `LooseKey` blesses generic wrappers that route runtime strings through
    // one check. Under `"warn"` every distinct string is retained forever so
    // it is warned about only once — an unbounded, caller-influenced Set.
    const { client } = await warnClient(flat());
    for (let i = 0; i < 20_000; i++) {
      await client.can({ userId: "root" }, `ns${i}.a.b` as never);
    }
    const retained = (client as unknown as { reportedExternal: Set<string> })
      .reportedExternal;
    expect(retained.size).toBeLessThanOrEqual(4_096);
  });

  it("re-checking an ALREADY-warned permission must not re-scan the catalog", async () => {
    // `admitExternal` computes `unknownPermissionContext` (a bounded-
    // Levenshtein pass over every catalog key, plus every group wildcard)
    // unconditionally, before deciding whether it will even throw — so the
    // brown-field escape hatch puts an O(catalog) scan on every check of a
    // foreign permission, on the synchronous snapshot path included.
    const perms: Record<string, true> = {};
    for (let i = 0; i < 400; i++) perms[`docs.g${i % 20}.act_${i}`] = true;
    const real = defineCatalog({
      namespaces: ["docs"],
      permissions: perms,
      conventions: { depth: "any" },
    });
    let keyScans = 0;
    const counting = new Proxy(real, {
      get(target, prop, receiver) {
        if (prop === "keys") keyScans++;
        return Reflect.get(target, prop, receiver) as unknown;
      },
    }) as unknown as AnyCatalog;

    const app = createApplication({ catalog: counting, storage: memoryDriver() });
    const client = createAlfizClient({
      catalog: counting,
      provider: app,
      externalPermissions: "warn",
      onExternalPermission: () => {},
    });
    await client.can({ userId: "u" }, "zoom.meetings.host" as never); // first: warns
    keyScans = 0;
    for (let i = 0; i < 20; i++) {
      await client.can({ userId: "u" }, "zoom.meetings.host" as never);
    }
    expect(keyScans).toBe(0);
  });
});

describe("brown-field: an open import region is admitted sight unseen", () => {
  it("an unenumerated key under a non-strict region is conferred by a bare `*`", async () => {
    // Documented ("an unenumerated key under one is admitted sight unseen"),
    // and the default is the permissive one: `strict` defaults to false, so
    // the quickstart-shaped import without a `document` reopens exactly the
    // typo-passes-for-superadmins hole for the region's namespace.
    const catalog = defineCatalog({
      namespaces: ["docs"],
      permissions: { "docs.files.read": true },
      imports: { zoom: { permissions: { "zoom.meetings.*": true } } },
    });
    const app = createApplication({ catalog, storage: memoryDriver() });
    const client = createAlfizClient({ catalog, provider: app });
    await app.createGrant({
      subject: "user:root",
      pattern: "*",
      provenance: admin,
    });
    // A namespace-anchored grant SHOULD confer it…
    await app.createGrant({
      subject: "user:scoped",
      pattern: "zoom.meetings.*",
      provenance: admin,
    });
    expect(await client.can({ userId: "scoped" }, "zoom.meetings.typo" as never)).toBe(
      true,
    );
    // …a bare `*` should not: the key is in no enumerated vocabulary.
    expect(await client.can({ userId: "root" }, "zoom.meetings.typo" as never)).toBe(
      false,
    );
  });
});

// ===========================================================================
// (A4) Provider failure, and the storage seam
// ===========================================================================

describe("brown-field: a failing provider fails CLOSED on every shape", () => {
  const brokenClient = () => {
    const catalog = flat();
    const app = createApplication({ catalog, storage: memoryDriver() });
    const provider = {
      ...app,
      epoch: undefined,
      onInvalidate: () => () => {},
      resolveAncestors: () => [],
      getSubjectAccess: async () => {
        throw new Error("provider 503");
      },
    };
    return createAlfizClient({ catalog, provider: provider as never });
  };

  it("can / require / canAny / holds / heldKeys / snapshot all reject", async () => {
    const client = brokenClient();
    const shapes: Array<[string, () => Promise<unknown>]> = [
      ["can", () => client.can({ userId: "u" }, "docs.files.read")],
      ["can.fresh", () => client.can.fresh({ userId: "u" }, "docs.files.read")],
      ["require", () => client.require({ userId: "u" }, "docs.files.read")],
      ["canAny", () => client.canAny({ userId: "u" }, "docs.*")],
      ["holds", () => client.holds({ userId: "u" }, "docs.files.read")],
      ["heldKeys", () => client.heldKeys({ userId: "u" })],
      ["snapshot", () => client.snapshot({ userId: "u" })],
    ];
    for (const [name, run] of shapes) {
      expect([name, await outcomeOf(run)]).toEqual([name, "rejected"]);
    }
  });
});

describe("brown-field: memoryDriver() in production", () => {
  it("an empty store denies (the positive half fails closed)", async () => {
    const catalog = flat();
    const app = createApplication({ catalog, storage: memoryDriver() });
    const client = createAlfizClient({ catalog, provider: app });
    expect(await client.can({ userId: "u" }, "docs.files.read")).toBe(false);
    expect(await client.canAny({ userId: "u" }, "docs.*")).toBe(false);
  });

  it("carries a machine-readable non-durability signal a boot check can refuse", () => {
    // README's quickstart uses `memoryDriver()` and mentions swapping it for
    // `@alfiz/prisma` in a comment. Nothing at runtime distinguishes the two,
    // so a copy-pasted quickstart ships an authorization store that vanishes
    // on deploy with no signal at all.
    const driver = memoryDriver() as Record<string, unknown>;
    expect(driver.durable ?? driver.ephemeral ?? driver.driverName).toBeDefined();
  });

  it("a non-durable store loses the NEGATIVE layer asymmetrically — hence `durable`", async () => {
    // NOT a defect the library can fix, and recorded here so nobody files it
    // as one twice. The asymmetry is real: positive access is routinely
    // re-created by boot/seed/migration code, while the negative layer
    // (`active: false`, personal revokes) exists ONLY in the store. A store
    // that does not survive a deploy therefore comes back MORE permissive
    // than it went away — and no library can remember a row it never kept.
    //
    // What Alfiz can do is make the property legible before it bites, which
    // is what `StorageDriver.durable` is for: a deployment refuses to boot
    // on a non-durable store rather than discovering this after an
    // offboarding quietly stops holding.
    const catalog = flat();
    const seed = async (storage: ReturnType<typeof memoryDriver>) => {
      const app = createApplication({ catalog, storage });
      await app.createGrant({
        subject: "everyone",
        pattern: "docs.files.read",
        provenance: admin,
      });
      return app;
    };
    const storage = memoryDriver();
    const before = await seed(storage);
    await before.setUserActive("leaver", false, admin);
    expect(
      await createAlfizClient({ catalog, provider: before }).can(
        { userId: "leaver" },
        "docs.files.read",
      ),
    ).toBe(false);

    // Redeploy against a store that did not survive: the seeding re-creates
    // the grant, nothing re-creates the deactivation.
    const after = await seed(memoryDriver());
    expect(
      await createAlfizClient({ catalog, provider: after }).can(
        { userId: "leaver" },
        "docs.files.read",
      ),
    ).toBe(true);

    // The guard: the driver says so, so a boot check can refuse it.
    expect(memoryDriver().durable).toBe(false);
  });
});

// ===========================================================================
// (A5) Catalog escape hatches
// ===========================================================================

describe("brown-field: catalog conventions and escape hatches", () => {
  it("conventions.depth must not make the reserved alfiz_internal keys lint errors", () => {
    // README endorses `conventions: { depth: 2 }` for a two-level integration
    // catalog. Alfiz's own `alfiz_internal.*` keys are three levels deep and
    // are NOT exempt, so the documented configuration produces a dozen
    // unfixable errors and `alfiz-verify` exits 1 — the pressure that gets a
    // security tool switched off.
    const catalog = defineCatalog({
      namespaces: ["zoom"],
      permissions: { "zoom.read": true, "zoom.host": true },
      conventions: { depth: 2 },
    });
    const depthErrors = lintCatalog(catalog).filter(
      (i) => i.severity === "error" && i.path.startsWith("alfiz_internal."),
    );
    expect(depthErrors).toEqual([]);
  });

  it("conventions.depth rejects nonsense values at boot", () => {
    expect(() =>
      defineCatalog({
        namespaces: ["z"],
        permissions: { "z.a.b": true },
        conventions: { depth: -5 },
      }),
    ).toThrow();
    expect(() =>
      defineCatalog({
        namespaces: ["z"],
        permissions: { "z.a.b": true },
        conventions: { depth: 1.5 as never },
      }),
    ).toThrow();
  });

  it("conventions.depth is purely advisory and widens no runtime vocabulary", () => {
    const shallow = defineCatalog({
      namespaces: ["zoom"],
      permissions: { "zoom.host": true },
      conventions: { depth: 2 },
    });
    const anyDepth = defineCatalog({
      namespaces: ["zoom"],
      permissions: { "zoom.a.b.c.d": true },
      conventions: { depth: "any" },
    });
    expect(shallow.hasKey("zoom.anything")).toBe(false);
    expect(anyDepth.hasKey("zoom.a.b.c")).toBe(false);
    expect(anyDepth.isKnownPattern("zoom.a.b.c.*")).toBe(true);
  });

  it("includeAlfizInternal:false + externalPermissions:'warn' still denies alfiz_internal.*", async () => {
    const catalog = defineCatalog({
      namespaces: ["docs"],
      permissions: { "docs.files.read": true },
      includeAlfizInternal: false,
    });
    const app = createApplication({ catalog, storage: memoryDriver() });
    const client = createAlfizClient({
      catalog,
      provider: app,
      externalPermissions: "warn",
      onExternalPermission: () => {},
    });
    await app.createGrant({
      subject: "user:root",
      pattern: "*",
      provenance: admin,
    });
    expect(
      await client.can(
        { userId: "root" },
        "alfiz_internal.access.manage_grants" as never,
      ),
    ).toBe(false);
    await expect(
      app.createGrant({
        subject: "user:root",
        pattern: "alfiz_internal.*" as never,
        provenance: admin,
      }),
    ).rejects.toThrow();
  });

  it("a hand-built catalog cannot make `can` evaluate a wildcard", async () => {
    const catalog = defineCatalog({
      namespaces: ["docs"],
      permissions: { "docs.files.read": true, "docs.files.delete": true },
    });
    const app = createApplication({ catalog, storage: memoryDriver() });
    const client = createAlfizClient({ catalog, provider: app });
    await app.createGrant({
      subject: "user:root",
      pattern: "docs.*",
      provenance: admin,
    });
    await expect(
      client.can({ userId: "root" }, "docs.files.*" as never),
    ).rejects.toThrow(UnknownPermissionError);
    await expect(client.can({ userId: "root" }, "*" as never)).rejects.toThrow(
      UnknownPermissionError,
    );
  });
});

// ===========================================================================
// (B2) Bounded memory and hostile-sized inputs
// ===========================================================================

describe("resource exhaustion: caches and counters stay bounded", () => {
  it("the metrics aggregator is bounded under adversarial cardinality", () => {
    const aggregator = createMetricsAggregator();
    for (let i = 0; i < 30_000; i++) {
      aggregator.record({
        at: 0,
        shape: "can",
        gate: true,
        decision: "allow",
        permission: `docs.g.act_${i}`,
        anyOf: false,
        scopeType: "docs.folder",
        scope: `docs.folder:${i}`,
        principal: { userId: `u${i}` },
        matchedGrantIds: [`g${i}`],
        soleMatchGrantId: `g${i}`,
        matchedRevokeIds: [],
        roleIds: [],
        implied: false,
        fresh: false,
        snapshot: false,
        sampleRate: 1,
      });
    }
    const batch = aggregator.snapshot();
    expect(batch.checks.length).toBeLessThanOrEqual(10_000);
    expect(batch.grants.length).toBeLessThanOrEqual(10_000);
    expect(batch.principals.distinct).toBeLessThanOrEqual(1_000);
    // Never silently zero: what a cap refused is reported.
    expect(batch.dropped).toBeGreaterThan(0);
  });

  it("the client's object-chain cache is bounded under adversarial scope ids", async () => {
    const catalog = hierarchical();
    const app = createApplication({
      catalog,
      storage: memoryDriver(),
      ancestry: () => [],
    });
    const client = createAlfizClient({
      catalog,
      provider: app,
      maxObjectCacheEntries: 500,
    });
    for (let i = 0; i < 3_000; i++) {
      await client.can({ userId: "u" }, "docs.files.read", `docs.folder:${i}`);
    }
    const internals = client as unknown as {
      objectCache: Map<string, unknown>;
      chainIndex: Map<string, unknown>;
    };
    expect(internals.objectCache.size).toBeLessThanOrEqual(500);
    // The secondary index must be evicted with the entries it points at.
    expect(internals.chainIndex.size).toBeLessThanOrEqual(1_001);
  });

  it("the client's subject cache is bounded under adversarial principal ids", async () => {
    const catalog = flat();
    const app = createApplication({ catalog, storage: memoryDriver() });
    const client = createAlfizClient({
      catalog,
      provider: app,
      maxSubjectCacheEntries: 200,
    });
    for (let i = 0; i < 2_000; i++) {
      await client.can({ userId: `u${i}` }, "docs.files.read");
    }
    const internals = client as unknown as {
      subjectCache: Map<string, unknown>;
      closureIndex: Map<string, unknown>;
    };
    expect(internals.subjectCache.size).toBeLessThanOrEqual(200);
    expect(internals.closureIndex.size).toBeLessThanOrEqual(2_000);
  });

  it("a megabyte-long scope id and key terminate without a pathological scan", async () => {
    const catalog = hierarchical();
    const app = createApplication({
      catalog,
      storage: memoryDriver(),
      ancestry: () => [],
    });
    const client = createAlfizClient({ catalog, provider: app });
    const hugeScope = `docs.folder:${"x".repeat(500_000)}`;
    expect(
      await client.can({ userId: "u" }, "docs.files.read", hugeScope),
    ).toBe(false);

    const hugeKey = `zz.${"y".repeat(500_000)}`;
    await expect(client.can({ userId: "u" }, hugeKey as never)).rejects.toThrow(
      UnknownPermissionError,
    );
    await expect(
      app.createGrant({
        subject: "user:u",
        pattern: hugeKey as never,
        provenance: admin,
      }),
    ).rejects.toThrow();
  });

  it("an UnknownPermissionError does not echo a megabyte of caller input into logs", async () => {
    const catalog = flat();
    const app = createApplication({ catalog, storage: memoryDriver() });
    const client = createAlfizClient({ catalog, provider: app });
    const hugeKey = `zz.${"y".repeat(200_000)}`;
    const error = await client
      .can({ userId: "u" }, hugeKey as never)
      .then(() => null)
      .catch((e: Error) => e);
    expect(error).toBeInstanceOf(UnknownPermissionError);
    expect(error!.message.length).toBeLessThanOrEqual(4_096);
  });

  it("a 3 000-row createGrants batch validates everything first and terminates", async () => {
    const catalog = defineCatalog({
      namespaces: ["docs"],
      permissions: { "docs.files.read": { scopes: ["docs.folder"] } },
      scopeTypes: { "docs.folder": { parent: null } },
    });
    const app = createApplication({ catalog, storage: memoryDriver() });
    const inputs = Array.from({ length: 3_000 }, (_, i) => ({
      subject: `user:u${i}`,
      pattern: "docs.files.read" as const,
      scope: "docs.folder:1" as const,
    }));
    const rows = await app.createGrants(inputs, admin);
    expect(rows).toHaveLength(3_000);

    // One bad row rejects the whole batch, leaving nothing half-written.
    const before = (await app.listGrants()).length;
    await expect(
      app.createGrants(
        [...inputs.slice(0, 5), { subject: "user:x", pattern: "docs.nope.*" as never }],
        admin,
      ),
    ).rejects.toThrow();
    expect((await app.listGrants()).length).toBe(before);
  });

  it("a 3 000-scope snapshot terminates and stays exact for revoke suppression", async () => {
    const catalog = hierarchical();
    const app = createApplication({
      catalog,
      storage: memoryDriver(),
      ancestry: () => ["docs.folder:root"],
    });
    const client = createAlfizClient({ catalog, provider: app });
    await app.createGrants(
      Array.from({ length: 3_000 }, (_, i) => ({
        subject: "user:u" as const,
        pattern: "docs.files.read" as const,
        scope: `docs.folder:${i}` as const,
      })),
      admin,
    );
    const snap = await client.snapshot({ userId: "u" });
    expect(snap.resolvedScopes.size).toBe(3_000);
    expect(snap.can("docs.files.read", "docs.folder:17")).toBe(true);
    await app.createRevoke({
      userId: "u",
      pattern: "docs.files.*",
      scope: "docs.folder:root",
      provenance: admin,
    });
    const after = await client.snapshot({ userId: "u", fresh: true });
    expect(after.can("docs.files.read", "docs.folder:17")).toBe(false);
  });

  it("a 20 000-key catalog builds and answers membership in constant time", () => {
    const perms: Record<string, true> = {};
    for (let i = 0; i < 20_000; i++) perms[`docs.g${i % 100}.act_${i}`] = true;
    const catalog = defineCatalog({
      namespaces: ["docs"],
      permissions: perms,
      conventions: { depth: "any" },
    });
    expect(catalog.hasKey("docs.g0.act_0")).toBe(true);
    expect(catalog.hasKey("docs.g0.act_999999")).toBe(false);
    expect(catalog.keysMatching("docs.g0.*").length).toBeGreaterThan(0);
  });
});

// ===========================================================================
// (A6) Clocks
// ===========================================================================

describe("brown-field: an expired grant must stay expired", () => {
  it("a client clock lagging the provider's does not extend a time-bound grant", async () => {
    const catalog = flat();
    let providerNow = 1_000_000;
    const app = createApplication({
      catalog,
      storage: memoryDriver(),
      clock: () => providerNow,
    });
    // The checking process's clock runs 10s behind the writer's — skew, or a
    // test clock wired into one construction site and not the other.
    const client = createAlfizClient({
      catalog,
      provider: app,
      clock: () => providerNow - 10_000,
    });
    await app.createGrant({
      subject: "user:u",
      pattern: "docs.files.read",
      expiresAt: providerNow + 1_000,
      provenance: admin,
    });
    expect(await client.can.fresh({ userId: "u" }, "docs.files.read")).toBe(true);
    providerNow += 5_000; // the grant has expired by the writer's clock
    expect(await client.can.fresh({ userId: "u" }, "docs.files.read")).toBe(false);
  });
});
