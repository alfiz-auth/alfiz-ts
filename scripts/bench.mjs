#!/usr/bin/env node
/**
 * The published performance envelope: synthetic organizations against the
 * in-memory driver, exercising the paths a deployment actually pays for —
 * cold closure supply (the expensive miss), warm checks (the common case),
 * and deep object-chain resolution.
 *
 * Run: `npm run build && node scripts/bench.mjs`
 *
 * Honesty notes, also printed with the results:
 * - The memory driver scans; a database driver indexes. Cold-miss numbers
 *   here are an UPPER bound for an indexed store on the same shapes, and
 *   grant-count scaling reflects the scan, not the algebra.
 * - Warm checks never touch the driver, so those numbers transfer directly.
 * - Timings are wall-clock on whatever ran this; treat shapes, not
 *   absolute microseconds, as the result.
 */

import { performance } from "node:perf_hooks";
import {
  createAlfizClient,
  defineCatalog,
  parentPointerResolver,
} from "@alfiz/core";
import { createApplication, memoryDriver } from "@alfiz/application";

const quantile = (sorted, q) =>
  sorted[Math.min(sorted.length - 1, Math.floor(q * sorted.length))];

const stats = (samples) => {
  const sorted = [...samples].sort((a, b) => a - b);
  return {
    p50: quantile(sorted, 0.5),
    p99: quantile(sorted, 0.99),
    max: sorted[sorted.length - 1],
  };
};

const keyOf = (k) => `bench.g${Math.floor((k % 200) / 10)}.read_${k % 200}`;

const fmt = (ms) =>
  ms >= 1 ? `${ms.toFixed(2)}ms` : `${(ms * 1000).toFixed(0)}µs`;

function catalogOf(keys) {
  const permissions = {};
  for (let i = 0; i < keys; i++) {
    permissions[`bench.g${Math.floor(i / 10)}.read_${i}`] = {
      scopes: ["bench.node"],
    };
  }
  return defineCatalog({
    namespaces: ["bench"],
    includeAlfizInternal: false,
    permissions,
    scopeTypes: { "bench.node": { parent: "bench.node" } },
  });
}

async function scenario({ grants, users, groupChain, hierarchyDepth }) {
  const catalog = catalogOf(200);
  const storage = memoryDriver();
  const parents = new Map();
  for (let d = 1; d <= hierarchyDepth; d++) {
    parents.set(`bench.node:${d}`, d > 1 ? `bench.node:${d - 1}` : null);
  }
  const app = createApplication({
    catalog,
    storage,
    ancestry: parentPointerResolver((s) => parents.get(s) ?? null),
    events: { persist: false },
  });
  const admin = { kind: "admin", actorUserId: "root" };

  // A nested group chain every user belongs to the bottom of.
  let parent = null;
  const chain = [];
  for (let d = 0; d < groupChain; d++) {
    const g = await app.createGroup(
      { id: `chain-${d}`, name: `Chain ${d}`, parents: parent ? [parent] : [] },
      admin,
    );
    chain.push(g.id);
    parent = g.id;
  }
  const bottom = chain[chain.length - 1];

  // Grant rows: spread over users, the chain groups, and scopes.
  const inputs = [];
  for (let i = 0; i < grants; i++) {
    const key = keyOf(i);
    const subject =
      i % 10 === 0
        ? `group:${chain[i % groupChain]}`
        : `user:u${i % users}`;
    inputs.push({
      subject,
      pattern: key,
      scope: i % 3 === 0 ? `bench.node:${(i % hierarchyDepth) + 1}` : undefined,
    });
  }
  // Insert through storage directly: seeding speed, not write-path bench.
  let id = 0;
  for (const input of inputs) {
    await storage.insertGrant({
      id: `g${id++}`,
      subject: input.subject,
      pattern: input.pattern,
      scope: input.scope ?? "*",
      provenance: admin,
      createdAt: 1,
    });
  }
  for (let u = 0; u < users; u++) {
    await storage.upsertUser({
      userId: `u${u}`,
      active: true,
      groupIds: [bottom],
      orgIds: [],
      managerUserId: u > 0 ? `u${u - 1}` : null,
    });
  }

  const client = createAlfizClient({ catalog, provider: app });

  // Cold closure supply: distinct users, caches empty for each.
  const cold = [];
  const coldRounds = Math.min(users, 200);
  for (let u = 0; u < coldRounds; u++) {
    const t0 = performance.now();
    await client.can(
      { userId: `u${u}` },
      keyOf(0),
      `bench.node:${hierarchyDepth}`,
    );
    cold.push(performance.now() - t0);
  }

  // Warm checks: one principal, cached closures, deep scope.
  await client.can({ userId: "u0" }, keyOf(0));
  const warm = [];
  for (let i = 0; i < 5_000; i++) {
    const t0 = performance.now();
    await client.can(
      { userId: "u0" },
      keyOf(i),
      `bench.node:${(i % hierarchyDepth) + 1}`,
    );
    warm.push(performance.now() - t0);
  }

  client.close();
  return { cold: stats(cold), warm: stats(warm) };
}

const shapes = [
  { grants: 10_000, users: 1_000, groupChain: 20, hierarchyDepth: 20 },
  { grants: 100_000, users: 10_000, groupChain: 50, hierarchyDepth: 20 },
  { grants: 1_000_000, users: 50_000, groupChain: 200, hierarchyDepth: 20 },
];

console.log("alfiz bench — memory driver, node", process.version);
for (const shape of shapes) {
  const started = performance.now();
  const result = await scenario(shape);
  console.log(
    `grants=${shape.grants.toLocaleString()} users=${shape.users.toLocaleString()} ` +
      `groupChain=${shape.groupChain} depth=${shape.hierarchyDepth}\n` +
      `  cold closure+check  p50=${fmt(result.cold.p50)} p99=${fmt(result.cold.p99)} max=${fmt(result.cold.max)}\n` +
      `  warm check          p50=${fmt(result.warm.p50)} p99=${fmt(result.warm.p99)} max=${fmt(result.warm.max)}\n` +
      `  (scenario total ${(performance.now() - started).toFixed(0)}ms)`,
  );
}
console.log(
  "\nnote: the memory driver SCANS grant rows per closure fetch; an indexed",
);
console.log(
  "database driver pays per-matching-row, so cold p99 here is an upper bound.",
);
console.log("warm checks never touch the driver and transfer directly.");
