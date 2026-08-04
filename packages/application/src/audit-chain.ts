/**
 * Audit tamper-evidence: an optional SHA-256 hash chain over the audit log.
 *
 * With `audit: { hashChain: true }` on the Application, every audit entry
 * carries `hash` — a digest of the entry's canonical serialization plus the
 * previous entry's hash (`prevHash`) — so editing, deleting, or reordering
 * any entry breaks every hash after it. The chain begins at the first entry
 * written with chaining on (`prevHash: null` serialized as absence), so it
 * can be enabled mid-life: earlier unhashed entries simply precede the
 * chain, and `verifyAuditChain` verifies the hashed suffix.
 *
 * What this is: tamper-EVIDENCE — a reviewer who exports the log and stores
 * the head hash out-of-band can later prove the exported prefix unchanged.
 * What this is not: tamper-PROOF — an attacker with database write access
 * and this source can rewrite and re-hash the whole chain; anchoring the
 * head externally (a ticket, a WORM bucket, a signature) is what makes the
 * evidence hard, and it is deliberately left to the deployment.
 */

import { createHash } from "node:crypto";
import type { AuditEvent } from "@alfiz/core";

/**
 * Deterministic JSON: objects serialize with sorted keys at every depth, so
 * a `detail` payload hashes identically however a JSON column round-trips
 * key order (Postgres `jsonb` does not preserve it).
 */
export function stableAuditJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map((v) => stableAuditJson(v === undefined ? null : v)).join(",")}]`;
  }
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${entries
    .map(([k, v]) => `${JSON.stringify(k)}:${stableAuditJson(v)}`)
    .join(",")}}`;
}

/**
 * The hash of one audit entry given its predecessor's hash (`null` at the
 * chain head). Covers every field a reviewer relies on; `prevHash` is inside
 * the digest, which is what makes the entries a chain rather than a set.
 */
export function computeAuditHash(
  event: Pick<AuditEvent, "id" | "at" | "actor" | "action" | "target" | "detail">,
  prevHash: string | null,
): string {
  const canonical = stableAuditJson([
    prevHash,
    event.id,
    event.at,
    event.actor,
    event.action,
    event.target,
    event.detail === undefined ? null : event.detail,
  ]);
  return createHash("sha256").update(canonical, "utf8").digest("hex");
}

export type AuditChainResult =
  | { ok: true; /** Entries participating in the chain. */ hashed: number }
  | {
      ok: false;
      /** Index into the supplied array of the entry that breaks the chain. */
      index: number;
      reason: "hash_mismatch" | "broken_link" | "unhashed_after_chain_start";
    };

/**
 * Verifies a hash chain over events in log order (ascending `at`, `id` —
 * exactly what `listAuditEvents` returns). Unhashed entries may precede the
 * chain (it was enabled mid-life) but never interrupt it: once the first
 * hashed entry appears, every later entry must be hashed and linked.
 *
 * Two modes, chosen by `options.priorHash`:
 *
 * - **Omitted — full-log verification.** The first hashed entry must be a
 *   chain GENESIS (`prevHash` absent): a first entry pointing at some prior
 *   hash means the entries before it were deleted, and that is a finding,
 *   not a start.
 * - **Provided — export-window verification.** The first hashed entry must
 *   link to exactly `priorHash` — the hash of the last event of the
 *   previous export window (or `null` for the first window). This is what
 *   lets paged exports be verified window by window with one carried hash.
 */
export function verifyAuditChain(
  events: readonly AuditEvent[],
  options?: { priorHash?: string | null },
): AuditChainResult {
  let prev: string | null = options?.priorHash ?? null;
  let started = false;
  let hashed = 0;
  for (let i = 0; i < events.length; i++) {
    const event = events[i]!;
    if (event.hash === undefined) {
      if (started) return { ok: false, index: i, reason: "unhashed_after_chain_start" };
      continue;
    }
    if ((event.prevHash ?? null) !== prev) {
      return { ok: false, index: i, reason: "broken_link" };
    }
    if (computeAuditHash(event, event.prevHash ?? null) !== event.hash) {
      return { ok: false, index: i, reason: "hash_mismatch" };
    }
    prev = event.hash;
    started = true;
    hashed++;
  }
  return { ok: true, hashed };
}
