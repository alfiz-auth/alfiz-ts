/**
 * The local service-principal shim: shared backend key(s) in environment
 * variables, validated server-side with a timing-safe comparison and a
 * rotation list — so a standalone deployment is never forced onto a managed
 * service merely to expose an API. Pair with @alfiz/verify's client-reach
 * guard, which fails the build if a key module becomes client-reachable.
 *
 * A verified key yields a `service:<id>` machine subject; grant to it like
 * any other subject. Machine subjects have no personal revokes.
 */

import { createHash, timingSafeEqual } from "node:crypto";
import type { PrincipalRef } from "@alfiz/core";

export interface ServiceKeyConfig {
  /** Becomes the machine subject `service:<serviceId>`. */
  serviceId: string;
  /**
   * Accepted keys, current first. Keep the previous key during rotation
   * ("current,previous"), then drop it.
   */
  keys: readonly string[];
}

export type ServiceVerification =
  | { ok: true; serviceId: string; principal: PrincipalRef }
  | { ok: false };

const digest = (value: string): Buffer =>
  createHash("sha256").update(value, "utf8").digest();

/** Constant-time equality over same-length digests. */
const safeEqual = (a: string, b: string): boolean =>
  timingSafeEqual(digest(a), digest(b));

export interface ServiceKeyShim {
  /**
   * Verifies an `Authorization` header (`Bearer <key>`) or a bare key.
   * Never leaks which part failed.
   */
  verify(authorizationOrKey: string | null | undefined): ServiceVerification;
}

export function createServiceKeyShim(
  configs: readonly ServiceKeyConfig[],
): ServiceKeyShim {
  for (const config of configs) {
    if (config.keys.length === 0 || config.keys.some((k) => k.length < 16)) {
      throw new Error(
        `service ${JSON.stringify(config.serviceId)}: keys must be at least 16 characters`,
      );
    }
  }
  return {
    verify(authorizationOrKey) {
      if (!authorizationOrKey) return { ok: false };
      const presented = authorizationOrKey.startsWith("Bearer ")
        ? authorizationOrKey.slice("Bearer ".length)
        : authorizationOrKey;
      for (const config of configs) {
        for (const key of config.keys) {
          if (safeEqual(presented, key)) {
            return {
              ok: true,
              serviceId: config.serviceId,
              principal: { serviceId: config.serviceId },
            };
          }
        }
      }
      return { ok: false };
    },
  };
}

/**
 * Parses the conventional environment shape: `ALFIZ_SERVICE_KEYS` =
 * `"<serviceId>:<currentKey>[,<previousKey>];<serviceId2>:..."`.
 */
export function parseServiceKeysEnv(raw: string | undefined): ServiceKeyConfig[] {
  if (!raw) return [];
  return raw
    .split(";")
    .filter((entry) => entry.trim() !== "")
    .map((entry) => {
      const idx = entry.indexOf(":");
      if (idx <= 0) {
        throw new Error(
          "ALFIZ_SERVICE_KEYS entries are `<serviceId>:<key>[,<previousKey>]`",
        );
      }
      return {
        serviceId: entry.slice(0, idx).trim(),
        keys: entry
          .slice(idx + 1)
          .split(",")
          .map((k) => k.trim())
          .filter((k) => k !== ""),
      };
    });
}
