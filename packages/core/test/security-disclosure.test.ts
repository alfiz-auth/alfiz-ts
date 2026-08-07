/**
 * Information disclosure: what an error, a suggestion, a listing, a picker
 * tree, or a diagnostic NAMES — and to whom.
 *
 * Every one of these surfaces is routinely rendered to an end user (a 403
 * page, a toast, a dashboard) or returned across the Provider API. Anything
 * they name is disclosed to whoever can trigger them, and the person who can
 * trigger a check is not always the person entitled to the vocabulary,
 * structure, or rows that come back.
 *
 * Two of Alfiz's best features are also oracles by construction, and this
 * file is about their BOUNDS, not about removing them:
 *
 *   - `UnknownPermissionError` "names the closest declared keys, so the typo
 *     carries its own fix" (README). That is deliberate. What must hold is
 *     that it stays a *fix*, not a *dump*: capped, distance-limited, and
 *     never reaching across a boundary the catalog draws.
 *   - `GraphCycleError` re-throws "intact" across the wire with paths like
 *     "a → b → a" (protocol.ts). Also deliberate — a bare "cycle detected"
 *     is undebuggable. What must hold is that only graph node ids ride
 *     along, never rows, subjects, or patterns.
 *
 * The rest is hygiene an authorization library owes its host: the offending
 * INPUT is echoed back on every one of these paths, so it must be
 * neutralized (control characters that forge log lines or repaint a
 * terminal) and bounded (a caller-sized string must not become a
 * caller-sized log entry). And the viewer-scoped surfaces — `heldKeys`,
 * `explain`, `grantedScopes`, the entitlement rollup — must name only what
 * the evaluated principal's own closure reaches, even when the provider
 * hands over a row set containing other people's rows.
 */

import { describe, expect, it } from "vitest";
import type { GrantRow, RevokeRow } from "../src/access.js";
import { grantedScopesFor } from "../src/access.js";
import {
  closestPatterns,
  defineCatalog,
  unknownPermissionContext,
} from "../src/catalog.js";
import { createAlfizClient, toCheckContext } from "../src/client.js";
import { entitlementsOf } from "../src/entitlements.js";
import {
  AccessDeniedError,
  UnknownPermissionError,
  UnresolvedScopeError,
  formatAlternatives,
} from "../src/errors.js";
import { GraphCycleError, assertEdgeInsertable } from "../src/graph.js";
import { ALFIZ_INTERNAL_NAMESPACE } from "../src/grammar.js";
import { planListing } from "../src/listing.js";
import type { AlfizProvider, SubjectAccessData } from "../src/provider.js";
import { RequestStateError, applyDecision, validateJustification } from "../src/requests.js";
import { buildPermissionTree } from "../src/tree.js";
import type { PermTreeNode } from "../src/tree.js";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/**
 * A catalog that deliberately KEEPS `alfiz_internal` (the default), because
 * the reserved-namespace questions below are about a catalog that renders an
 * Alfiz admin surface — the shape most deployments have.
 */
const catalog = defineCatalog({
  namespaces: ["docs", "hr"],
  permissions: {
    "docs.files.read": { scopes: ["docs.folder"] },
    "docs.files.update_file": { scopes: ["docs.folder"] },
    "docs.files.manage_grants": { scopes: ["docs.folder"] },
    "hr.salary.read_band": true,
    "hr.termination.initiate": true,
  },
  scopeTypes: {
    "docs.folder": { parent: null },
    "docs.doc": { parent: "docs.folder" },
  },
});

/** The same vocabulary with the reserved namespace switched off. */
const noInternalCatalog = defineCatalog({
  namespaces: ["docs", "hr"],
  includeAlfizInternal: false,
  permissions: {
    "docs.files.read": true,
    "docs.files.manage_grants": true,
    "hr.salary.read_band": true,
  },
});

const grant = (over: Partial<GrantRow> = {}): GrantRow => ({
  id: "g1",
  subject: "user:u1",
  pattern: "docs.files.read",
  scope: "*",
  provenance: { kind: "admin", actorUserId: "root" },
  createdAt: 0,
  ...over,
});

const providerWith = (
  data: Partial<SubjectAccessData> = {},
): AlfizProvider =>
  ({
    getSubjectAccess: async (): Promise<SubjectAccessData> => ({
      userId: "u1",
      closure: ["user:u1", "everyone"],
      grants: [grant()],
      revokes: [],
      roles: [],
      managerChain: [],
      unresolvedRoleIds: [],
      active: true,
      ...data,
    }),
    resolveAncestors: () => ["*"],
    onInvalidate: () => () => {},
  }) as unknown as AlfizProvider;

/** ESC and a newline: the two characters that forge a log line or repaint a terminal. */
const ESC = "\u001b";
const HOSTILE = `${ESC}[2J${ESC}[31m\nALFIZ: access granted to everyone\r`;

/** Any raw C0 control character surviving into a message is the failure. */
const hasRawControlChars = (s: string): boolean =>
  // eslint-disable-next-line no-control-regex
  /[\u0000-\u001f\u007f]/.test(s);

// ---------------------------------------------------------------------------
// 1. The suggestion engine: a fix, not a catalog dump
// ---------------------------------------------------------------------------

describe("suggestions are bounded — the did-you-mean is a fix, not a dump", () => {
  it("never returns more than the documented cap, however near the probe is", () => {
    // The disclosure budget per probe. A probe engineered to sit close to
    // MANY declared keys must still hand back a handful, or one malformed
    // check becomes a partial catalog export.
    const wide = defineCatalog({
      namespaces: ["docs"],
      includeAlfizInternal: false,
      permissions: Object.fromEntries(
        Array.from({ length: 60 }, (_, i) => [
          `docs.files.read_${String(i).padStart(2, "0")}`,
          true,
        ]),
      ),
    });
    for (const probe of [
      "docs.files.read_",
      "docs.files.read_0",
      "docs.files.reed_01",
      "docs.files.*",
    ]) {
      expect(closestPatterns(wide, probe, "key").length).toBeLessThanOrEqual(3);
      expect(closestPatterns(wide, probe, "pattern").length).toBeLessThanOrEqual(3);
    }
  });

  it("a garbage key harvests nothing — the distance bound is real", () => {
    // The enumeration attack: a caller who can influence a runtime permission
    // string (a nav table, a generic `assertCanDo(actor, thing, key)` wrapper,
    // an API body) probes with junk and reads the catalog out of the replies.
    // Junk must return silence.
    for (const probe of [
      "a",
      "ab",
      "zzzzzz.qqqq.wwww",
      "aaaaaaaaaaaaaaaaaaaaaaaa",
      "qqqqqqqqqqqq",
    ]) {
      expect(closestPatterns(catalog, probe, "key")).toEqual([]);
    }
  });

  it("blind probing recovers effectively nothing from a large catalog", () => {
    // Quantifying the oracle rather than hand-waving at it: 2000+ blind
    // probes against a 200-key catalog. The edit-distance bound (and its
    // length pre-filter) means a probe only pays out when the attacker
    // ALREADY knows a key to within a few characters — which is guided
    // guessing, not enumeration.
    const big = defineCatalog({
      namespaces: ["docs"],
      includeAlfizInternal: false,
      conventions: { depth: "any" },
      permissions: Object.fromEntries(
        Array.from({ length: 200 }, (_, i) => [
          `docs.area${i % 20}.verb_${i}`,
          true,
        ]),
      ),
    });
    const alphabet = "abcdefghijklmnopqrstuvwxyz";
    const harvested = new Set<string>();
    let probes = 0;
    for (const a of alphabet) {
      for (const b of alphabet) {
        for (const suffix of ["", "_read", ".read", ".x.y"]) {
          probes++;
          for (const hit of closestPatterns(big, `docs.${a}${b}${suffix}`, "key")) {
            harvested.add(hit);
          }
        }
      }
    }
    expect(probes).toBeGreaterThan(2000);
    // A few percent at most; certainly not the vocabulary.
    expect(harvested.size).toBeLessThan(big.keys.length / 10);
  });

  it("never offers a pattern the catalog would reject — no unstorable fixes", () => {
    // A suggestion that fails the same validation is worse than silence: it
    // sends the caller round the loop again, and it names a region the
    // catalog does not actually cover.
    const withImport = defineCatalog({
      namespaces: ["docs"],
      includeAlfizInternal: false,
      permissions: { "docs.files.read": true },
      imports: { zoom: { permissions: { "zoom.meetings.*": true } } },
    });
    for (const probe of ["zoom.*", "zoom.meeting.*", "zoom.recordings.*"]) {
      for (const suggested of closestPatterns(withImport, probe, "pattern")) {
        expect(withImport.isKnownPattern(suggested)).toBe(true);
      }
    }
  });

  it("stays silent about the reserved admin namespace for a probe in an owned one", () => {
    // `alfiz_internal.*` is Alfiz's own administration vocabulary — the
    // manage_grants / manage_roles / view_as / audit.read surface. A typo in
    // the APPLICATION's own namespace is a question about the application's
    // vocabulary; answering it with the admin vocabulary hands the prober a
    // map of the privileged surface they were not asking about, and tells
    // them this deployment mounts it. The right-leaf-wrong-group heuristic
    // (a key sharing the probe's final segment) is what reaches across.
    for (const probe of [
      "docs.settings.manage_roles",
      "docs.settings.publish_catalog",
      "docs.admin.view_as",
      "docs.folders.manage_grants",
      "hr.people.manage_groups",
    ]) {
      const suggested = closestPatterns(catalog, probe, "key");
      expect(
        suggested.filter((s) => s.startsWith(`${ALFIZ_INTERNAL_NAMESPACE}.`)),
      ).toEqual([]);
    }
  });

  it("honours includeAlfizInternal: false everywhere the vocabulary could surface", () => {
    // The documented escape hatch ("set false for catalogs that render no
    // Alfiz admin surface") has to be airtight, or it is not an escape hatch:
    // no reserved key in the suggester, and none in the picker tree.
    expect(
      closestPatterns(noInternalCatalog, "docs.settings.manage_roles", "key"),
    ).toEqual([]);
    expect(
      noInternalCatalog.keys.filter((k) =>
        k.startsWith(`${ALFIZ_INTERNAL_NAMESPACE}.`),
      ),
    ).toEqual([]);
    const paths: string[] = [];
    const walk = (nodes: readonly PermTreeNode[]): void => {
      for (const node of nodes) {
        paths.push(node.path);
        walk(node.children);
      }
    };
    walk(buildPermissionTree(noInternalCatalog));
    expect(paths.filter((p) => p.startsWith(ALFIZ_INTERNAL_NAMESPACE))).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// 2. The offending input is echoed — so neutralize it and bound it
// ---------------------------------------------------------------------------

describe("echoed input is neutralized", () => {
  it("UnknownPermissionError escapes control characters in the permission", () => {
    // These messages land in logs, in terminals, and on 500 pages. A raw
    // newline forges a log line; a raw ESC repaints a terminal (and can hide
    // the lines above it). `JSON.stringify` is what makes the echo safe.
    const err = new UnknownPermissionError({
      permission: `docs.${HOSTILE}`,
      expected: "key",
    });
    expect(hasRawControlChars(err.message)).toBe(false);
    // Still legible — neutralized, not deleted.
    expect(err.message).toContain("docs.");
  });

  it("UnknownPermissionError bounds the echo — a huge input is not a huge message", async () => {
    // A runtime-string check path takes its key from a request. Echoing an
    // unbounded caller-supplied string means the caller sizes every log
    // entry, every wire error, and every retained Error object: a 200 KB
    // permission becomes a 200 KB message, repeated per request.
    const client = createAlfizClient({ catalog, provider: providerWith() });
    const huge = `docs.${"z".repeat(200_000)}`;
    const err = (await client
      .can({ userId: "u1" }, huge as never)
      .catch((e: unknown) => e)) as Error;
    expect(err).toBeInstanceOf(UnknownPermissionError);
    expect(err.message.length).toBeLessThan(1_000);
    // The prefix has to survive, or the message stops being debuggable.
    expect(err.message).toContain("docs.zzzz");
  });

  it("AccessDeniedError escapes control characters in the scope id", async () => {
    // Scope ids are runtime data by construction — `docs.doc:${id}` where the
    // id comes off a URL path segment. A denial message interpolating one raw
    // lets an unauthenticated visitor write arbitrary lines into the
    // application's log by requesting a crafted URL, and lets them repaint a
    // terminal tailing it.
    const client = createAlfizClient({ catalog, provider: providerWith() });
    const err = (await client
      .require(
        { userId: "u1" },
        "docs.files.manage_grants",
        `docs.folder:${HOSTILE}` as never,
      )
      .catch((e: unknown) => e)) as AccessDeniedError;
    expect(err).toBeInstanceOf(AccessDeniedError);
    expect(hasRawControlChars(err.message)).toBe(false);
  });

  it("UnresolvedScopeError escapes the scope and caps the resolved list", async () => {
    // The diagnostic that reports what IS resolved has to stop somewhere:
    // the resolved set is per-request and can be a whole list page of ids.
    const client = createAlfizClient({ catalog, provider: providerWith() });
    const snap = await client.snapshot({ userId: "u1" }, {
      scopes: Array.from({ length: 40 }, (_, i) => `docs.folder:${i}`),
    } as never);
    const err = (() => {
      try {
        snap.can("docs.files.read", `docs.doc:${HOSTILE}` as never);
        return null;
      } catch (e) {
        return e as UnresolvedScopeError;
      }
    })();
    expect(err).toBeInstanceOf(UnresolvedScopeError);
    expect(hasRawControlChars(err!.message)).toBe(false);
    expect(err!.message).toMatch(/and \d+ more/);
    expect(err!.message.length).toBeLessThan(2_000);
  });

  it("formatAlternatives quotes every alternative, so none can break the sentence", () => {
    // Suggestions come from the catalog today, but this is the one function
    // that splices a list into prose — quoting is what keeps a value from
    // reading as narration.
    expect(formatAlternatives(["a b", "c, or d"])).toBe('"a b" or "c, or d"');
    expect(hasRawControlChars(formatAlternatives([`x${ESC}[31m`]))).toBe(false);
  });

  it("a denial names the decision, never the rows behind it", async () => {
    // `AccessDeniedError` is the one error in this library that is *meant*
    // for an end user. It may name the permission, the scope, and the
    // principal being gated — all of which the caller already supplied — and
    // must not name grant ids, subjects (group names are org structure), or
    // provenance actor ids. The pointer to `explain()` is for the developer;
    // the rows stay behind it.
    const client = createAlfizClient({
      catalog,
      provider: providerWith({
        grants: [
          grant({
            id: "grant_7f21",
            subject: "group:project_falcon_leads",
            provenance: { kind: "admin", actorUserId: "ceo_jane" },
          }),
        ],
      }),
    });
    const err = (await client
      .require({ userId: "u1" }, "hr.termination.initiate")
      .catch((e: unknown) => e)) as AccessDeniedError;
    expect(err).toBeInstanceOf(AccessDeniedError);
    for (const secret of ["grant_7f21", "project_falcon_leads", "ceo_jane"]) {
      expect(err.message).not.toContain(secret);
    }
  });
});

// ---------------------------------------------------------------------------
// 3. externalPermissions: "warn" — the brown-field softening
// ---------------------------------------------------------------------------

describe('externalPermissions: "warn" does not become a second disclosure channel', () => {
  it("the default console.warn handler neutralizes the caller's string", async () => {
    // The whole point of "warn" is that the permission string is UNKNOWN —
    // i.e. it came from somewhere the catalog does not control, which in a
    // brown-field migration is exactly where request-shaped strings arrive.
    // The default handler builds a paste-able `imports:` snippet, and the
    // namespace half of it is interpolated straight into the sentence.
    const seen: string[] = [];
    const original = console.warn;
    console.warn = (m: unknown) => {
      seen.push(String(m));
    };
    try {
      const client = createAlfizClient({
        catalog,
        provider: providerWith(),
        externalPermissions: "warn",
      });
      await client
        .can({ userId: "u1" }, `evil${HOSTILE}.thing` as never)
        .catch(() => {});
    } finally {
      console.warn = original;
    }
    expect(seen).toHaveLength(1);
    expect(hasRawControlChars(seen[0]!)).toBe(false);
  });

  it("the report-once set is bounded — caller strings cannot grow it forever", async () => {
    // "Reported once per distinct permission" means the client retains every
    // distinct string it has ever been asked about, keyed by caller input.
    // On a runtime-string path that is an unbounded, attacker-driven cache in
    // a long-lived process — and an unbounded stream of log lines with it.
    const client = createAlfizClient({
      catalog,
      provider: providerWith(),
      externalPermissions: "warn",
      onExternalPermission: () => {},
    });
    for (let i = 0; i < 5_000; i++) {
      await client.can({ userId: "u1" }, `ns${i}.thing.read` as never).catch(() => {});
    }
    const retained = (client as unknown as { reportedExternal: Set<string> })
      .reportedExternal;
    expect(retained.size).toBeLessThanOrEqual(1_024);
  });

  it("the warn path discloses no more vocabulary than the throw path", async () => {
    // The softened mode must not become the chatty one: what the callback
    // carries is the caller's own string and its namespace, never catalog
    // keys, near-misses, or the declared-namespace roster.
    const seen: Record<string, unknown>[] = [];
    const client = createAlfizClient({
      catalog,
      provider: providerWith(),
      externalPermissions: "warn",
      onExternalPermission: (info) =>
        seen.push(info as unknown as Record<string, unknown>),
    });
    await client.can({ userId: "u1" }, "stripe.charges.create" as never);
    expect(seen).toEqual([
      {
        permission: "stripe.charges.create",
        expected: "key",
        namespace: "stripe",
        shape: "can",
      },
    ]);
    const serialized = JSON.stringify(seen);
    for (const key of catalog.keys) expect(serialized).not.toContain(key);
  });
});

// ---------------------------------------------------------------------------
// 4. What one probe tells an outsider about the catalog's shape
// ---------------------------------------------------------------------------

describe("the undeclared-namespace hint", () => {
  it("names the catalog's whole namespace and import roster from a single probe", () => {
    // Locking in what this costs, because it is a deliberate developer
    // affordance whose blast radius is easy to misjudge: ONE probe with a
    // string near nothing returns the complete list of namespaces the
    // catalog owns plus every namespace it imports. There is no per-probe
    // budget to spend down and nothing to guess. If this message can reach a
    // non-developer, the deployment's application inventory is public.
    //
    // The bound that DOES hold, and is the point of the test: it is a list of
    // NAMESPACES, never of keys — the vocabulary itself stays behind the
    // edit-distance bound.
    const { hint, didYouMean } = unknownPermissionContext(
      catalog,
      "zzzz.qqqq.wwww",
      "key",
    );
    expect(hint).toContain("docs");
    expect(hint).toContain("hr");
    expect(didYouMean).toEqual([]);
    for (const key of catalog.keys) expect(hint).not.toContain(key);
  });
});

// ---------------------------------------------------------------------------
// 5. Viewer-scoped surfaces: only the evaluated principal's own reach
// ---------------------------------------------------------------------------

/**
 * A deliberately POLLUTED row set: rows for a subject outside the principal's
 * closure, and another user's personal revoke. A correct provider would never
 * hand these over — which is exactly why the evaluator must not depend on it.
 */
const pollutedProvider = (): AlfizProvider =>
  providerWith({
    grants: [
      grant({ id: "mine", subject: "user:u1", pattern: "docs.files.read" }),
      grant({
        id: "theirs",
        subject: "group:executive_severance_committee",
        pattern: "hr.termination.initiate",
        provenance: { kind: "admin", actorUserId: "ceo_jane" },
      }),
    ],
    revokes: [
      {
        id: "their_revoke",
        userId: "u2",
        pattern: "docs.files.*",
        scope: "*",
        provenance: { kind: "admin", actorUserId: "ceo_jane" },
        createdAt: 0,
      } as RevokeRow,
    ],
  });

describe("snapshot introspection names only the principal's own reach", () => {
  it("heldKeys never names a key from a namespace the principal has no row in", async () => {
    // `heldKeys` feeds conditional UI wholesale, so a key that leaks in here
    // renders a button — and tells the viewer that the capability exists.
    const snap = await createAlfizClient({
      catalog,
      provider: pollutedProvider(),
    }).snapshot({ userId: "u1" });
    expect([...snap.heldKeys]).toEqual(["docs.files.read"]);
    expect([...snap.heldKeys].some((k) => k.startsWith("hr."))).toBe(false);
  });

  it("explain returns no row belonging to a subject outside the closure", async () => {
    // `explain` is the "why" surface every denial message points at. It
    // legitimately shows the rows behind the VIEWER's own access — group
    // subjects and provenance included — and must show nobody else's.
    const client = createAlfizClient({ catalog, provider: pollutedProvider() });
    const explanation = await client.explain(
      { userId: "u1" },
      "hr.termination.initiate",
    );
    expect(explanation.allowed).toBe(false);
    expect(explanation.matchedGrants).toEqual([]);
    const serialized = JSON.stringify(explanation);
    expect(serialized).not.toContain("executive_severance_committee");
    expect(serialized).not.toContain("ceo_jane");
  });

  it("explain never surfaces another user's personal revoke", async () => {
    const client = createAlfizClient({ catalog, provider: pollutedProvider() });
    const explanation = await client.explain({ userId: "u1" }, "docs.files.read");
    expect(explanation.matchedRevokes).toEqual([]);
    expect(explanation.allowed).toBe(true);
  });

  it("grantedScopes leaks no scope id from a foreign subject's rows", async () => {
    // The listing primitive: a scope id names a real object in the host's
    // database, so an over-broad granted set both over-lists rows AND
    // discloses the existence of objects the viewer cannot reach.
    const client = createAlfizClient({ catalog, provider: pollutedProvider() });
    const { granted } = await client.grantedScopes(
      { userId: "u1" },
      "hr.termination.initiate",
    );
    expect([...granted]).toEqual([]);
  });
});

describe("listing plans fail closed", () => {
  it("no grants yields `none`, never `all`", () => {
    // The disclosure failure mode of a listing plan is silent and total: a
    // plan that degrades to "all" when the granted set is empty runs an
    // unfiltered query and returns every row in the table.
    expect(planListing({ granted: new Set(), revoked: new Set() })).toEqual({
      mode: "none",
    });
    expect(
      planListing({ granted: new Set(["docs.folder:1"]), revoked: new Set(["*"]) }),
    ).toEqual({ mode: "none" });
  });

  it("a scoped plan carries only the scopes the principal was granted", () => {
    const plan = planListing({
      granted: new Set(["docs.folder:9"]),
      revoked: new Set(["docs.folder:9/secret"]),
    });
    expect(plan).toEqual({
      mode: "scoped",
      include: ["docs.folder:9"],
      exclude: ["docs.folder:9/secret"],
    });
  });
});

describe("the entitlement rollup is one principal's, not the org's", () => {
  it("names no row outside the closure and no other user's revoke", async () => {
    // `exportEntitlements` output goes to access reviewers and external IGA
    // tools. It is a per-principal document by contract; a row from another
    // subject riding along would put one reviewer's certification decision on
    // another team's access.
    const data = await pollutedProvider().getSubjectAccess({ userId: "u1" });
    const ctx = toCheckContext(data, Date.now());
    const { entitlements, revokes } = entitlementsOf(ctx, catalog);
    expect(entitlements.map((e) => e.key)).toEqual(["docs.files.read"]);
    expect(revokes).toEqual([]);
    const serialized = JSON.stringify({ entitlements, revokes });
    expect(serialized).not.toContain("executive_severance_committee");
    expect(serialized).not.toContain("their_revoke");
  });

  it("grantedScopesFor agrees — the pure primitive filters by closure too", () => {
    const data: SubjectAccessData = {
      userId: "u1",
      closure: ["user:u1"],
      grants: [
        grant({ subject: "group:not_mine", scope: "docs.folder:classified" }),
      ],
      revokes: [],
      roles: [],
      managerChain: [],
      unresolvedRoleIds: [],
      active: true,
    };
    const ctx = toCheckContext(data, Date.now());
    expect([...grantedScopesFor(ctx, "docs.files.read")]).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// 6. The picker tree
// ---------------------------------------------------------------------------

describe("the permission tree discloses vocabulary, never rows", () => {
  it("carries catalog metadata only — no principal, no subjects, no ids", () => {
    // `buildPermissionTree` takes a catalog and nothing else, which is the
    // structural guarantee: a role editor or grant picker rendered from it
    // cannot leak org data through the tree, because the tree never saw any.
    // Filtering the tree to what the VIEWER may administer is the host's job
    // and is not something this function can do — worth pinning so nobody
    // mistakes it for a viewer-scoped surface.
    const tree = buildPermissionTree(catalog);
    const paths: string[] = [];
    const fields = new Set<string>();
    const walk = (nodes: readonly PermTreeNode[]): void => {
      for (const node of nodes) {
        paths.push(node.path);
        for (const field of Object.keys(node)) fields.add(field);
        walk(node.children);
      }
    };
    walk(tree);
    // Every path is catalog vocabulary and nothing else.
    for (const path of paths) {
      expect(catalog.hasKey(path) || catalog.hasGroup(path)).toBe(true);
    }
    // No node field is a row field. A picker that grew a `grantedBy` or a
    // `heldBy` would start disclosing org data to everyone who opens it.
    expect([...fields].sort()).toEqual(
      [
        "children",
        "description",
        "kind",
        "label",
        "leaf",
        "name",
        "path",
      ].sort(),
    );
    // And no VALUE anywhere in the tree is a subject id or a scope instance.
    const serialized = JSON.stringify(tree);
    for (const rowish of [
      "user:",
      "group:",
      "org:",
      "service:",
      "everyone",
      "provenance",
      "createdAt",
      "expiresAt",
      "grantId",
    ]) {
      expect(serialized).not.toContain(rowish);
    }
  });
});

// ---------------------------------------------------------------------------
// 7. GraphCycleError: documented disclosure, bounded
// ---------------------------------------------------------------------------

describe("GraphCycleError carries the path and nothing else", () => {
  it("names graph node ids only — no rows, patterns, or members", () => {
    // Documented and deliberate (protocol.ts: the path survives the wire so a
    // dashboard renders "cycle: a → b → a" identically for local and remote
    // writes). The bound: the caller named two of these nodes, and learns the
    // ids of the intermediates on the path — group STRUCTURE, which is the
    // minimum a cycle report can be. It must not grow into group names,
    // membership, or the rows hanging off those groups.
    const parents = new Map<string, string[]>([
      ["grp_b", ["grp_c"]],
      ["grp_c", ["grp_a"]],
    ]);
    const err = (() => {
      try {
        assertEdgeInsertable(parents, "grp_a", "grp_b");
        return null;
      } catch (e) {
        return e as GraphCycleError;
      }
    })();
    expect(err).toBeInstanceOf(GraphCycleError);
    expect(err!.path).toEqual(["grp_a", "grp_b", "grp_c", "grp_a"]);
    // The message is a function of the path alone.
    expect(err!.message).toBe(`cycle: ${err!.path.join(" → ")}`);
  });
});

// ---------------------------------------------------------------------------
// 8. Requests: justification text is the sensitive part
// ---------------------------------------------------------------------------

describe("request diagnostics keep the justification out of the message", () => {
  it("validation problems name the prompt id, never the answer", () => {
    // A justification answer is free text a requester wrote about why they
    // need access — routinely an incident number, a customer name, or a
    // colleague's name. Validation failures are shown back in the request
    // form and logged; the prompt ID is enough to fix the form.
    const problems = validateJustification(
      [
        { id: "reason", label: "Why?", required: true },
        { id: "ticket", label: "Ticket", kind: "select", options: ["A", "B"] },
      ],
      { reason: "", ticket: "investigating employee alice@example.com" },
    );
    expect(problems).toHaveLength(2);
    for (const problem of problems) {
      expect(problem).not.toContain("alice@example.com");
    }
  });

  it("a state error names the request and its state, not who is on it", () => {
    // The most likely audience for this error is the requester retrying a
    // decided request — who must not learn the approver's identity, the note
    // behind the decision, or that another stage ever existed.
    const err = (() => {
      try {
        applyDecision(
          {
            id: "req_1",
            requesterUserId: "u1",
            pattern: "hr.termination.initiate",
            scope: "*",
            justification: { reason: "investigating alice@example.com" },
            state: "denied",
            stageIndex: 0,
            stages: [{ kind: "named_approvers", roleId: "role_secret_owners" }],
            decisions: [
              {
                stageIndex: 0,
                decidedBy: "ceo_jane",
                decision: "denied",
                at: 0,
                note: "she is under investigation",
              },
            ],
            createdAt: 0,
          },
          { decidedBy: "u2", decision: "approved", at: 1 },
        );
        return null;
      } catch (e) {
        return e as RequestStateError;
      }
    })();
    expect(err).toBeInstanceOf(RequestStateError);
    for (const secret of [
      "ceo_jane",
      "under investigation",
      "alice@example.com",
      "role_secret_owners",
    ]) {
      expect(err!.message).not.toContain(secret);
    }
  });
});
