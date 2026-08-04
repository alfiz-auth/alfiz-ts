/**
 * @alfiz/hosted — the hosted provider.
 *
 * The provider contract with its far side reached over the Alfiz Provider
 * API: the Dashboard and Federation seam. Everything is forwarded to the
 * serving side — a linked Application's handler, or a managed service —
 * which enforces its own integrity rules; nothing is stored or decided
 * here. Fetch-only, no Node dependency: usable from any data-plane-less
 * consumer (a dashboard, a CLI, audit tooling).
 */

export * from "./hosted-provider.js";
