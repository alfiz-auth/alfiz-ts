import { describe, expect, it } from "vitest";
import type { GrantRow, RevokeRow, RoleDef } from "../src/access.js";
import { defineCatalog } from "../src/catalog.js";
import { createAlfizClient } from "../src/client.js";
import type {
  CheckObservation,
  MetricsBatch,
  MetricsObserver,
} from "../src/metrics.js";
import {
  createMetricsAggregator,
  createProviderMetricsSink,
  revocationSafeguard,
} from "../src/metrics.js";
import { otelMetricsObserver } from "../src/otel.js";
import type {
  AlfizProvider,
  InvalidationListener,
  ProviderCapabilities,
  SubjectAccessData,
} from "../src/provider.js";

const catalog = defineCatalog({
  namespaces: ["docs"],
  includeAlfizInternal: false,
  permissions: {
    "docs.files.read": { scopes: ["docs.folder", "docs.doc"] },
    "docs.files.read_listing": {
      scopes: ["docs.folder"],
      impliedOnAncestors: true,
    },
    "docs.files.update_file": { scopes: ["docs.folder", "docs.doc"] },
    "docs.files.delete": { scopes: ["docs.folder"] },
  },
  scopeTypes: {
    "docs.folder": { parent: "docs.folder" },
    "docs.doc": { parent: "docs.folder" },
  },
});

function fakeProvider(state: {
  grants: GrantRow[];
  revokes?: RevokeRow[];
  roles?: RoleDef[];
  active?: boolean;
  parents?: Record<string, string>;
  capabilities?: Partial<ProviderCapabilities>;
  onReport?: (batch: MetricsBatch) => void;
}) {
  const provider = {
    capabilities: async (): Promise<ProviderCapabilities> => ({
      orgRoot: true,
      requests: true,
      reporting: false,
      audit: true,
      multiParent: false,
      metrics: false,
      ...state.capabilities,
    }),
    getSubjectAccess: async (): Promise<SubjectAccessData> => ({
      userId: "u1",
      closure: ["user:u1", "everyone"],
      grants: state.grants,
      revokes: state.revokes ?? [],
      roles: state.roles ?? [],
      managerChain: [],
      unresolvedRoleIds: [],
      active: state.active ?? true,
    }),
    resolveAncestors: (scope: string) => {
      const chain: string[] = [];
      let current: string | undefined = state.parents?.[scope];
      while (current !== undefined) {
        chain.push(current);
        current = state.parents?.[current];
      }
      chain.push("*");
      return chain;
    },
    onInvalidate: (_listener: InvalidationListener) => () => undefined,
    ...(state.onReport === undefined
      ? {}
      : {
          reportMetrics: async (batch: MetricsBatch) => {
            state.onReport!(batch);
          },
        }),
  };
  return provider as typeof provider & AlfizProvider;
}

let nextId = 0;
const g = (
  subject: string,
  what: { pattern?: string; roleId?: string },
  scope = "*",
): GrantRow => ({
  id: `grant-${++nextId}`,
  subject,
  pattern: what.pattern,
  roleId: what.roleId,
  scope,
  provenance: { kind: "admin", actorUserId: "root" },
  createdAt: 0,
});

const r = (pattern: string, scope = "*"): RevokeRow => ({
  id: `revoke-${++nextId}`,
  userId: "u1",
  pattern,
  scope,
  provenance: { kind: "admin", actorUserId: "root" },
  createdAt: 0,
});

/** Collects observations, and is the whole sink contract. */
function collector(): { seen: CheckObservation[]; observer: MetricsObserver } {
  const seen: CheckObservation[] = [];
  return { seen, observer: (observation) => seen.push(observation) };
}

describe("check observations", () => {
  it("reports the dimensions of an allowed gate, attributed to its grant", async () => {
    const grant = g("user:u1", { pattern: "docs.files.read" }, "docs.folder:9");
    const { seen, observer } = collector();
    const client = createAlfizClient({
      catalog,
      provider: fakeProvider({
        grants: [grant],
        parents: { "docs.doc:1": "docs.folder:9" },
      }),
      metrics: { observer },
    });

    expect(await client.can({ userId: "u1" }, "docs.files.read", "docs.doc:1")).toBe(
      true,
    );
    expect(seen).toHaveLength(1);
    expect(seen[0]).toMatchObject({
      shape: "can",
      gate: true,
      decision: "allow",
      permission: "docs.files.read",
      anyOf: false,
      // Scope instances fold to their TYPE by default.
      scopeType: "docs.doc",
      principal: { userId: "u1" },
      matchedGrantIds: [grant.id],
      soleMatchGrantId: grant.id,
      matchedRevokeIds: [],
      implied: false,
      fresh: false,
      snapshot: false,
      sampleRate: 1,
    });
    expect(seen[0]!.scope).toBeUndefined();
  });

  it("soleMatch is set only when exactly one row allowed", async () => {
    const one = g("user:u1", { pattern: "docs.files.read" });
    const two = g("everyone", { pattern: "docs.*" });
    const { seen, observer } = collector();
    const client = createAlfizClient({
      catalog,
      provider: fakeProvider({ grants: [one, two] }),
      metrics: { observer },
    });

    await client.can({ userId: "u1" }, "docs.files.read");
    expect(seen[0]!.matchedGrantIds).toEqual([one.id, two.id]);
    // Two rows allowed: revoking either changes nothing, so neither is the
    // counterfactual. This is the overwarning the safeguard exists to avoid.
    expect(seen[0]!.soleMatchGrantId).toBeNull();
  });

  it("attributes the revoke that suppressed a denied check", async () => {
    const revoke = r("docs.files.*");
    const { seen, observer } = collector();
    const client = createAlfizClient({
      catalog,
      provider: fakeProvider({
        grants: [g("user:u1", { pattern: "docs.files.read" })],
        revokes: [revoke],
      }),
      metrics: { observer },
    });

    expect(await client.can({ userId: "u1" }, "docs.files.read")).toBe(false);
    expect(seen[0]).toMatchObject({
      decision: "deny",
      matchedGrantIds: [],
      soleMatchGrantId: null,
      matchedRevokeIds: [revoke.id],
    });
  });

  it("attributes role ids through role grants", async () => {
    const grant = g("user:u1", { roleId: "role-lead" });
    const { seen, observer } = collector();
    const client = createAlfizClient({
      catalog,
      provider: fakeProvider({
        grants: [grant],
        roles: [{ id: "role-lead", name: "Project Lead", patterns: ["docs.*"] }],
      }),
      metrics: { observer },
    });

    await client.can({ userId: "u1" }, "docs.files.read");
    expect(seen[0]!.roleIds).toEqual(["role-lead"]);
  });

  it("attributes an implied (§7.5) allow to the grant that implied it", async () => {
    const grant = g(
      "user:u1",
      { pattern: "docs.files.read_listing" },
      "docs.folder:9",
    );
    const { seen, observer } = collector();
    const client = createAlfizClient({
      catalog,
      provider: fakeProvider({
        grants: [grant],
        parents: { "docs.folder:9": "docs.folder:2" },
      }),
      metrics: { observer },
    });

    expect(
      await client.can({ userId: "u1" }, "docs.files.read_listing", "docs.folder:2"),
    ).toBe(true);
    expect(seen[0]).toMatchObject({
      decision: "allow",
      implied: true,
      matchedGrantIds: [grant.id],
      soleMatchGrantId: grant.id,
    });
  });

  it("names the shape: require, canAny, requireAny, holds, heldKeys", async () => {
    const { seen, observer } = collector();
    const client = createAlfizClient({
      catalog,
      provider: fakeProvider({ grants: [g("user:u1", { pattern: "docs.*" })] }),
      metrics: { observer },
    });

    await client.require({ userId: "u1" }, "docs.files.read");
    await client.canAny({ userId: "u1" }, "docs.*");
    await client.requireAny({ userId: "u1" }, "docs.*");
    await client.holds({ userId: "u1" }, "docs.files.read");
    await client.heldKeys({ userId: "u1" });

    expect(seen.map((o) => o.shape)).toEqual([
      "require",
      "canAny",
      "requireAny",
      "holds",
      "heldKeys",
    ]);
    // Gate versus visibility, the distinction the counters turn on.
    expect(seen.map((o) => o.gate)).toEqual([true, false, false, false, false]);
    // `require` delegating to `can` would double-count; it does not.
    expect(seen.filter((o) => o.shape === "can")).toHaveLength(0);
    expect(seen[4]!.permission).toBeNull();
  });

  it("marks can.fresh and snapshot checks", async () => {
    const { seen, observer } = collector();
    const client = createAlfizClient({
      catalog,
      provider: fakeProvider({ grants: [g("user:u1", { pattern: "docs.*" })] }),
      metrics: { observer },
    });

    await client.can.fresh({ userId: "u1" }, "docs.files.delete", "docs.folder:1");
    const snap = await client.snapshot({ userId: "u1" });
    snap.can("docs.files.read");

    expect(seen[0]).toMatchObject({ fresh: true, snapshot: false });
    expect(seen[1]).toMatchObject({ fresh: false, snapshot: true });
  });

  it("a snapshot taken with observe:false records nothing", async () => {
    const { seen, observer } = collector();
    const client = createAlfizClient({
      catalog,
      provider: fakeProvider({ grants: [g("user:u1", { pattern: "docs.*" })] }),
      metrics: { observer },
    });

    const snap = await client.snapshot({ userId: "u1" }, { observe: false });
    snap.can("docs.files.read");
    snap.canAny("docs.*");
    snap.holds("docs.files.read");
    expect(seen).toHaveLength(0);

    await client.can({ userId: "u1" }, "docs.files.read", undefined, {
      observe: false,
    });
    expect(seen).toHaveLength(0);
  });

  it("an inactive principal still produces a deny observation", async () => {
    const { seen, observer } = collector();
    const client = createAlfizClient({
      catalog,
      provider: fakeProvider({
        grants: [g("user:u1", { pattern: "docs.*" })],
        active: false,
      }),
      metrics: { observer },
    });

    expect(await client.can({ userId: "u1" }, "docs.files.read")).toBe(false);
    expect(seen[0]).toMatchObject({ decision: "deny", matchedGrantIds: [] });
  });

  it("a throwing observer never fails a check", async () => {
    const errors: unknown[] = [];
    const client = createAlfizClient({
      catalog,
      provider: fakeProvider({ grants: [g("user:u1", { pattern: "docs.*" })] }),
      metrics: {
        observer: () => {
          throw new Error("sink is down");
        },
        onError: (error) => errors.push(error),
      },
    });

    expect(await client.can({ userId: "u1" }, "docs.files.read")).toBe(true);
    expect(errors).toHaveLength(1);
    expect((errors[0] as Error).message).toBe("sink is down");
  });

  it("fans out to several observers, isolating failures", async () => {
    const a = collector();
    const b = collector();
    const errors: unknown[] = [];
    const client = createAlfizClient({
      catalog,
      provider: fakeProvider({ grants: [g("user:u1", { pattern: "docs.*" })] }),
      metrics: {
        observer: [
          a.observer,
          () => {
            throw new Error("noisy sink");
          },
          b.observer,
        ],
        onError: (error) => errors.push(error),
      },
    });

    await client.can({ userId: "u1" }, "docs.files.read");
    expect(a.seen).toHaveLength(1);
    expect(b.seen).toHaveLength(1);
    expect(errors).toHaveLength(1);
  });
});

describe("sampling", () => {
  const clientWith = (
    sampleRate: unknown,
    random: () => number,
    observer: MetricsObserver,
  ) =>
    createAlfizClient({
      catalog,
      provider: fakeProvider({ grants: [g("user:u1", { pattern: "docs.*" })] }),
      metrics: {
        observer,
        sampleRate: sampleRate as number,
        random,
      },
    });

  it("keeps roughly the configured fraction and records the rate", async () => {
    const { seen, observer } = collector();
    // Cycles 0.05, 0.15, …, 0.95: exactly one in ten below 0.1.
    let tick = 0;
    const client = clientWith(0.1, () => (tick++ % 10) / 10 + 0.05, observer);

    for (let i = 0; i < 100; i++) {
      await client.can({ userId: "u1" }, "docs.files.read");
    }
    expect(seen).toHaveLength(10);
    // The rate travels with the observation, so counts extrapolate.
    expect(seen.every((o) => o.sampleRate === 0.1)).toBe(true);
  });

  it("rate 0 observes nothing; rate 1 never calls random", async () => {
    const dropped = collector();
    let randomCalls = 0;
    const off = clientWith(0, () => (randomCalls++, 0), dropped.observer);
    await off.can({ userId: "u1" }, "docs.files.read");
    expect(dropped.seen).toHaveLength(0);
    expect(randomCalls).toBe(0);

    const all = collector();
    const on = clientWith(1, () => (randomCalls++, 0), all.observer);
    await on.can({ userId: "u1" }, "docs.files.read");
    expect(all.seen).toHaveLength(1);
    expect(randomCalls).toBe(0);
  });

  it("samples gates and visibility traffic separately", async () => {
    const { seen, observer } = collector();
    // Always 0.5: keeps gates (rate 1) and drops visibility (rate 0.02).
    const client = clientWith({ gate: 1, visibility: 0.02 }, () => 0.5, observer);

    await client.can({ userId: "u1" }, "docs.files.read");
    await client.require({ userId: "u1" }, "docs.files.read");
    await client.canAny({ userId: "u1" }, "docs.*");
    await client.holds({ userId: "u1" }, "docs.files.read");

    expect(seen.map((o) => o.shape)).toEqual(["can", "require"]);
  });

  it("sampling never changes an answer", async () => {
    const client = clientWith(0, () => 1, () => undefined);
    expect(await client.can({ userId: "u1" }, "docs.files.read")).toBe(true);
    expect(await client.can({ userId: "u1" }, "docs.files.read", "docs.doc:1")).toBe(
      true,
    );
  });
});

describe("scope-instance cardinality policy", () => {
  const observe = async (scopeInstances: unknown) => {
    const { seen, observer } = collector();
    const client = createAlfizClient({
      catalog,
      provider: fakeProvider({
        grants: [g("user:u1", { pattern: "docs.*" })],
        parents: { "docs.doc:7": "docs.folder:1" },
      }),
      metrics: { observer, scopeInstances: scopeInstances as "type" },
    });
    await client.can({ userId: "u1" }, "docs.files.read", "docs.doc:7");
    return seen[0]!;
  };

  it("folds instances into their scope type by default", async () => {
    const observation = await observe(undefined);
    expect(observation.scopeType).toBe("docs.doc");
    expect(observation.scope).toBeUndefined();
  });

  it("keeps instances for opted-in scope types only", async () => {
    expect((await observe(["docs.doc"])).scope).toBe("docs.doc:7");
    expect((await observe(["docs.folder"])).scope).toBeUndefined();
    expect((await observe("instance")).scope).toBe("docs.doc:7");
  });

  it("reports the global scope as its own type", async () => {
    const { seen, observer } = collector();
    const client = createAlfizClient({
      catalog,
      provider: fakeProvider({ grants: [g("user:u1", { pattern: "docs.*" })] }),
      metrics: { observer },
    });
    await client.can({ userId: "u1" }, "docs.files.read");
    expect(seen[0]!.scopeType).toBe("*");
  });
});

describe("the aggregator", () => {
  const observation = (
    over: Partial<CheckObservation> = {},
  ): CheckObservation => ({
    at: 0,
    shape: "can",
    gate: true,
    decision: "allow",
    permission: "docs.files.read",
    anyOf: false,
    scopeType: "docs.doc",
    principal: { userId: "u1" },
    matchedGrantIds: ["grant-a"],
    soleMatchGrantId: "grant-a",
    matchedRevokeIds: [],
    roleIds: [],
    implied: false,
    fresh: false,
    snapshot: false,
    sampleRate: 1,
    ...over,
  });

  it("counts checks, and extrapolates sampled ones", () => {
    const aggregator = createMetricsAggregator({ clock: () => 0 });
    aggregator.record(observation());
    aggregator.record(observation());
    aggregator.record(observation({ sampleRate: 0.1 }));

    // The sample rate is not part of the counter key — mixed-rate
    // observations of the same check fold into one counter, `observed`
    // counting what was seen and `estimated` what it stands for.
    const batch = aggregator.snapshot();
    expect(batch.checks).toHaveLength(1);
    expect(batch.checks[0]).toMatchObject({ observed: 3, estimated: 12 });
  });

  it("separates decision, shape, and scope type", () => {
    const aggregator = createMetricsAggregator({ clock: () => 0 });
    aggregator.record(observation());
    aggregator.record(observation({ decision: "deny" }));
    aggregator.record(observation({ shape: "canAny", gate: false }));
    aggregator.record(observation({ scopeType: "*" }));
    expect(aggregator.snapshot().checks).toHaveLength(4);
  });

  it("accumulates matched and soleMatch per grant", () => {
    const aggregator = createMetricsAggregator({ clock: () => 0 });
    aggregator.record(observation());
    aggregator.record(
      observation({ matchedGrantIds: ["grant-a", "grant-b"], soleMatchGrantId: null }),
    );

    const [a, b] = aggregator.snapshot().grants;
    expect(a).toMatchObject({ rowId: "grant-a", matched: 2, soleMatch: 1 });
    expect(b).toMatchObject({ rowId: "grant-b", matched: 1, soleMatch: 0 });
  });

  it("counts a matched revoke as a suppression", () => {
    const aggregator = createMetricsAggregator({ clock: () => 0 });
    aggregator.record(
      observation({
        decision: "deny",
        matchedGrantIds: [],
        soleMatchGrantId: null,
        matchedRevokeIds: ["revoke-a"],
      }),
    );
    expect(aggregator.snapshot().revokes[0]).toMatchObject({
      rowId: "revoke-a",
      matched: 1,
      soleMatch: 1,
    });
  });

  it("keeps a bounded set of recent principals per row", () => {
    const aggregator = createMetricsAggregator({
      clock: () => 0,
      maxRecentPrincipalsPerRow: 2,
    });
    for (const userId of ["a", "b", "c", "d"]) {
      aggregator.record(observation({ principal: { userId } }));
    }
    expect(aggregator.snapshot().grants[0]!.recentPrincipals).toEqual([
      "user:a",
      "user:b",
    ]);
  });

  it("bounds principals with an overflow flag rather than growing", () => {
    const aggregator = createMetricsAggregator({
      clock: () => 0,
      maxPrincipals: 2,
    });
    for (const userId of ["a", "b", "c", "d"]) {
      aggregator.record(observation({ principal: { userId } }));
    }
    expect(aggregator.snapshot().principals).toEqual({
      distinct: 2,
      overflowed: true,
    });
  });

  it("caps check keys and reports what it dropped", () => {
    const aggregator = createMetricsAggregator({ clock: () => 0, maxCheckKeys: 1 });
    aggregator.record(observation({ permission: "docs.files.read" }));
    aggregator.record(observation({ permission: "docs.files.delete" }));
    const batch = aggregator.snapshot();
    expect(batch.checks).toHaveLength(1);
    expect(batch.dropped).toBe(1);
  });

  it("rolls the window lazily and hands the closed one to flush", () => {
    const flushed: MetricsBatch[] = [];
    let now = 1_000;
    const aggregator = createMetricsAggregator({
      windowMs: 100,
      clock: () => now,
      flush: (batch) => flushed.push(batch),
    });
    aggregator.record(observation());
    now = 1_050;
    aggregator.record(observation());
    expect(flushed).toHaveLength(0);

    now = 1_200;
    aggregator.record(observation());
    expect(flushed).toHaveLength(1);
    expect(flushed[0]).toMatchObject({ windowStart: 1_000, windowEnd: 1_200 });
    expect(flushed[0]!.checks[0]!.observed).toBe(2);
    // The window that closed is gone; the new one holds only the third.
    expect(aggregator.snapshot().checks[0]!.observed).toBe(1);
  });

  it("tags batches with the instance id, so many servers merge", () => {
    const aggregator = createMetricsAggregator({
      instanceId: "web-3",
      clock: () => 0,
    });
    expect(aggregator.snapshot().instanceId).toBe("web-3");
  });

  it("is the direct-read API: snapshot does not close the window", () => {
    const aggregator = createMetricsAggregator({ clock: () => 0 });
    aggregator.record(observation());
    expect(aggregator.snapshot().checks[0]!.observed).toBe(1);
    expect(aggregator.snapshot().checks[0]!.observed).toBe(1);
  });
});

describe("the provider sink", () => {
  it("delivers batches only to a provider that accepts metrics", async () => {
    const delivered: MetricsBatch[] = [];
    const provider = fakeProvider({
      grants: [],
      capabilities: { metrics: true },
      onReport: (batch) => delivered.push(batch),
    });
    const sink = createProviderMetricsSink(provider, { windowMs: 10_000 });
    sink.aggregator.record({
      at: 0,
      shape: "can",
      gate: true,
      decision: "allow",
      permission: "docs.files.read",
      anyOf: false,
      scopeType: "*",
      principal: { userId: "u1" },
      matchedGrantIds: ["grant-a"],
      soleMatchGrantId: "grant-a",
      matchedRevokeIds: [],
      roleIds: [],
      implied: false,
      fresh: false,
      snapshot: false,
      sampleRate: 1,
    });
    await sink.flush();
    await sink.stop();

    expect(delivered).toHaveLength(1);
    expect(delivered[0]!.grants[0]!.rowId).toBe("grant-a");
  });

  it("sends nothing to a provider whose metrics capability is off", async () => {
    const delivered: MetricsBatch[] = [];
    const provider = fakeProvider({
      grants: [],
      capabilities: { metrics: false },
      onReport: (batch) => delivered.push(batch),
    });
    const sink = createProviderMetricsSink(provider);
    sink.aggregator.record({
      at: 0,
      shape: "can",
      gate: true,
      decision: "allow",
      permission: "docs.files.read",
      anyOf: false,
      scopeType: "*",
      principal: { userId: "u1" },
      matchedGrantIds: ["grant-a"],
      soleMatchGrantId: null,
      matchedRevokeIds: [],
      roleIds: [],
      implied: false,
      fresh: false,
      snapshot: false,
      sampleRate: 1,
    });
    await sink.stop();
    expect(delivered).toHaveLength(0);
  });

  it("a failing store never surfaces on the caller's path", async () => {
    const errors: unknown[] = [];
    const provider = {
      ...fakeProvider({ grants: [], capabilities: { metrics: true } }),
      reportMetrics: async () => {
        throw new Error("database is down");
      },
    } as unknown as AlfizProvider;
    const sink = createProviderMetricsSink(provider, {
      onError: (error) => errors.push(error),
    });
    sink.aggregator.record({
      at: 0,
      shape: "can",
      gate: true,
      decision: "allow",
      permission: "docs.files.read",
      anyOf: false,
      scopeType: "*",
      principal: { userId: "u1" },
      matchedGrantIds: ["grant-a"],
      soleMatchGrantId: null,
      matchedRevokeIds: [],
      roleIds: [],
      implied: false,
      fresh: false,
      snapshot: false,
      sampleRate: 1,
    });
    await expect(sink.stop()).resolves.toBeUndefined();
    expect((errors[0] as Error).message).toBe("database is down");
  });
});

describe("the OpenTelemetry adapter", () => {
  function fakeMeter() {
    const adds: Array<{
      name: string;
      value: number;
      attributes?: Record<string, unknown>;
    }> = [];
    const meter = {
      createCounter: (name: string) => ({
        add: (value: number, attributes?: Record<string, unknown>) =>
          adds.push({ name, value, attributes }),
      }),
    };
    return { adds, meter };
  }

  it("writes checks and attribution into the meter", async () => {
    const { adds, meter } = fakeMeter();
    const grant = g("user:u1", { pattern: "docs.files.read" });
    const client = createAlfizClient({
      catalog,
      provider: fakeProvider({ grants: [grant] }),
      metrics: { observer: otelMetricsObserver({ meter }) },
    });

    await client.can({ userId: "u1" }, "docs.files.read");

    expect(adds.map((a) => a.name)).toEqual([
      "alfiz.checks",
      "alfiz.grant.matched",
      "alfiz.grant.sole_match",
    ]);
    expect(adds[0]!.attributes).toMatchObject({
      permission: "docs.files.read",
      decision: "allow",
      shape: "can",
      gate: true,
      scope_type: "*",
    });
    expect(adds[1]!.attributes).toMatchObject({ grant_id: grant.id });
  });

  it("extrapolates sampled counts by default", async () => {
    const { adds, meter } = fakeMeter();
    const client = createAlfizClient({
      catalog,
      provider: fakeProvider({ grants: [g("user:u1", { pattern: "docs.*" })] }),
      metrics: {
        observer: otelMetricsObserver({ meter, attribution: false }),
        sampleRate: 0.25,
        random: () => 0,
      },
    });
    await client.can({ userId: "u1" }, "docs.files.read");
    expect(adds[0]!.value).toBe(4);
  });

  it("omits principals unless asked, and merges static attributes", async () => {
    const { adds, meter } = fakeMeter();
    const client = createAlfizClient({
      catalog,
      provider: fakeProvider({ grants: [g("user:u1", { pattern: "docs.*" })] }),
      metrics: {
        observer: otelMetricsObserver({
          meter,
          attribution: false,
          attributes: { service: "docs-web" },
        }),
      },
    });
    await client.can({ userId: "u1" }, "docs.files.read");
    expect(adds[0]!.attributes).toMatchObject({ service: "docs-web" });
    expect(adds[0]!.attributes).not.toHaveProperty("principal");

    const withPrincipals = fakeMeter();
    const client2 = createAlfizClient({
      catalog,
      provider: fakeProvider({ grants: [g("user:u1", { pattern: "docs.*" })] }),
      metrics: {
        observer: otelMetricsObserver({
          meter: withPrincipals.meter,
          attribution: false,
          principals: true,
        }),
      },
    });
    await client2.can({ userId: "u1" }, "docs.files.read");
    expect(withPrincipals.adds[0]!.attributes).toMatchObject({
      principal: "user:u1",
    });
  });
});

describe("the revocation safeguard", () => {
  const window = { windowStart: 0, windowEnd: 7 * 86_400_000 };

  it("warns on sole matches, and states the counterfactual", () => {
    const safeguard = revocationSafeguard({
      matched: 1_200,
      soleMatch: 1_200,
      ...window,
    });
    expect(safeguard.level).toBe("warning");
    expect(safeguard.headline).toContain("only thing allowing 1200 checks");
    expect(safeguard.headline).toContain("the last 7 days");
  });

  it("contextualizes a shadowed grant instead of warning about it", () => {
    const safeguard = revocationSafeguard({
      matched: 40_000,
      soleMatch: 0,
      ...window,
    });
    // The naive metric would warn here; a grant fully shadowed by a broader
    // one loses nothing when revoked.
    expect(safeguard.level).toBe("context");
    expect(safeguard.headline).toContain("never the only thing");
  });

  it("never says an unused grant is safe to revoke", () => {
    const safeguard = revocationSafeguard({ matched: 0, soleMatch: 0, ...window });
    expect(safeguard.level).toBe("none");
    expect(safeguard.headline).toBe("No recorded use in the last 7 days.");
    expect(safeguard.detail).toContain("not evidence");
    expect(safeguard.detail).toContain("break-glass");
    expect(safeguard.headline + safeguard.detail).not.toContain("safe to");
  });

  it("points the other direction for a revoke", () => {
    const safeguard = revocationSafeguard(
      { matched: 30, soleMatch: 30, ...window },
      { kind: "revoke" },
    );
    expect(safeguard.headline).toContain("suppressed 30 checks");
    expect(safeguard.headline).toContain("widens access");
  });
});
