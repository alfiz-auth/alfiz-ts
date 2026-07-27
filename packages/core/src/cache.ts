/**
 * The shared cache seam (L2): an optional tier between the client's
 * in-process maps and the provider, for deployments where processes are
 * many or short-lived (serverless) and an in-process cache is cold more
 * often than it is warm.
 *
 * The interface is deliberately minimal and string-valued so that ANY
 * external cache clears it with a ~10-line adapter in host code — Redis
 * and everything RESP-compatible (Valkey, KeyDB, Dragonfly, ElastiCache,
 * Upstash), HTTP caches (Upstash REST, Momento), or a DynamoDB table.
 * Core takes no dependency on any of them; `respCacheStore` below adapts
 * the two dominant Redis-client call shapes structurally, the same way
 * the Prisma driver adapts a generated client without importing it.
 *
 * Trust boundary: a CacheStore holds closure data and sits INSIDE the
 * server-side trust boundary — whoever can write to it can grant
 * themselves access. Point it only at authenticated, private cache
 * infrastructure, never at anything a user can reach.
 */

export interface CacheStore {
  /** The value at `key`, or null when absent/expired. Errors are treated as misses. */
  get(key: string): Promise<string | null>;
  /** Stores `value` at `key` with a time-to-live in milliseconds. */
  set(key: string, value: string, ttlMs: number): Promise<void>;
  delete(key: string): Promise<void>;
}

// ---------------------------------------------------------------------------
// RESP-family adapter
// ---------------------------------------------------------------------------

/**
 * The `node-redis` call shape: expiry rides an options object
 * (`set(key, value, { PX: ttlMs })`).
 */
export interface NodeRedisLikeClient {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, options: { PX: number }): Promise<unknown>;
  del(key: string): Promise<unknown>;
}

/**
 * The `ioredis` call shape: expiry rides positional arguments
 * (`set(key, value, "PX", ttlMs)`).
 */
export interface IoRedisLikeClient {
  get(key: string): Promise<string | null>;
  set(
    key: string,
    value: string,
    mode: "PX",
    ttlMs: number,
  ): Promise<unknown>;
  del(key: string): Promise<unknown>;
}

export type RespLikeClient = NodeRedisLikeClient | IoRedisLikeClient;

/**
 * Adapts any RESP-speaking client to {@link CacheStore} — first-party
 * support for the Redis protocol family without a dependency on any
 * client library. Both dominant call conventions are supported; the
 * adapter probes with the options-object shape first and remembers what
 * the client accepted. A rejected probe writes nothing (the server
 * rejects the whole command), so detection never leaves a key without
 * its TTL.
 */
export function respCacheStore(client: RespLikeClient): CacheStore {
  let style: "options" | "positional" | undefined;
  const setWith = async (
    chosen: "options" | "positional",
    key: string,
    value: string,
    ttlMs: number,
  ): Promise<void> => {
    if (chosen === "options") {
      await (client as NodeRedisLikeClient).set(key, value, { PX: ttlMs });
    } else {
      await (client as IoRedisLikeClient).set(key, value, "PX", ttlMs);
    }
  };
  return {
    async get(key) {
      return client.get(key);
    },
    async set(key, value, ttlMs) {
      if (style !== undefined) return setWith(style, key, value, ttlMs);
      try {
        await setWith("options", key, value, ttlMs);
        style = "options";
      } catch {
        await setWith("positional", key, value, ttlMs);
        style = "positional";
      }
    },
    async delete(key) {
      await client.del(key);
    },
  };
}
