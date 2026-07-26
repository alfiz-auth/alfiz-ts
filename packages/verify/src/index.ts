/**
 * @alfiz-auth/verify — build-time verification of the four-point checklist:
 * typed keys are the compiler's half; these checks cover what types cannot —
 * unknown keys behind dynamic call shapes, visibility affordances used as
 * gates, exported actions with no gate at all, unreferenced catalog leaves,
 * catalog convention violations, and client-reachable service-key material.
 */

export * from "./verify.js";
export * from "./codegen.js";
