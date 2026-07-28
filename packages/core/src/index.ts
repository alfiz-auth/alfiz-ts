/**
 * @alfiz/core — the Alfiz Client.
 *
 * Every capability here is a pure function over data a provider supplies:
 * the grammar and pattern matcher, catalog machinery and derived types,
 * closure evaluation and the effective-access algebra, check shapes,
 * graph integrity, request/policy evaluation, listing helpers, the headless
 * permission tree, closure caches, and the provider contract. No storage,
 * no I/O of its own.
 */

export * from "./grammar.js";
export * from "./scopes.js";
export * from "./subjects.js";
export * from "./graph.js";
export * from "./access.js";
export * from "./catalog.js";
export * from "./requests.js";
export * from "./provider.js";
export * from "./cache.js";
export * from "./errors.js";
export * from "./client.js";
export * from "./snapshot.js";
export * from "./listing.js";
export * from "./tree.js";
export * from "./metrics.js";
export * from "./otel.js";
