/**
 * The OpenTelemetry adapter: a `MetricsObserver` that writes permission
 * checks into an OTel `Meter`.
 *
 * This is the intended shape of the whole metrics feature. OpenTelemetry
 * already owns the dashboard, query, alerting, and retention contract, and
 * piping Alfiz into the stack a deployment already operates is strictly more
 * useful than hosting a second one: their dashboards, their alerting, their
 * retention, joined with their application metrics. The adapter is small on
 * purpose — the observer interface is the product, and this file is the
 * proof that an adapter against it is trivial.
 *
 * `@opentelemetry/api` is NOT a dependency. The two interfaces below are the
 * structural subset this adapter uses, which a real `Meter` satisfies
 * without a cast:
 *
 * ```ts
 * import { metrics } from "@opentelemetry/api";
 *
 * const alfiz = createAlfizClient({
 *   catalog,
 *   provider,
 *   metrics: {
 *     observer: otelMetricsObserver({ meter: metrics.getMeter("alfiz") }),
 *     sampleRate: { gate: 1, visibility: 0.02 },
 *   },
 * });
 * ```
 *
 * The same ten lines against StatsD, Prometheus, or a log line are the same
 * ten lines; nothing here is privileged.
 */

import type { CheckObservation, MetricsObserver } from "./metrics.js";

/** The attribute shape OTel accepts on a measurement. */
export type OtelAttributes = Record<string, string | number | boolean>;

/** The structural subset of an OTel `Counter` used here. */
export interface OtelCounter {
  add(value: number, attributes?: OtelAttributes): void;
}

/** The structural subset of an OTel `Meter` used here. */
export interface OtelMeter {
  createCounter(
    name: string,
    options?: { description?: string; unit?: string; valueType?: unknown },
  ): OtelCounter;
}

export interface OtelObserverOptions {
  /** A `Meter` from `metrics.getMeter(...)`. */
  meter: OtelMeter;
  /** Instrument-name prefix. Default `"alfiz."`. */
  prefix?: string | undefined;
  /** Attributes merged into every measurement (service, env, tenant, …). */
  attributes?: OtelAttributes | undefined;
  /**
   * Attribute measurements to grant / revoke / role row ids, emitting the
   * `matched` and `sole_match` instruments. Row-count cardinality — bounded,
   * but real. This is what lets revocation safeguards be built in YOUR
   * metrics stack rather than only in Alfiz's store. Default `true`.
   */
  attribution?: boolean | undefined;
  /**
   * Add the principal as an attribute. Unbounded cardinality and
   * PII-adjacent; off by default, and a bad idea in most backends.
   */
  principals?: boolean | undefined;
  /**
   * Add the scope INSTANCE when the observation carries one (which requires
   * opting the scope type in on the client first). Default `true` — if you
   * asked for instances upstream, you meant to see them.
   */
  scopeInstances?: boolean | undefined;
  /**
   * Correct for sampling: add `1 / sampleRate` instead of 1, so a 2%-sampled
   * counter still reads as real traffic. Default `true`. Turn it off to
   * count observations rather than estimate checks — at `sampleRate: 1`
   * (the default) the two are identical.
   */
  extrapolate?: boolean | undefined;
}

/**
 * Instruments emitted (with the default prefix):
 *
 *   - `alfiz.checks` — every observed check. Attributes: `permission`,
 *     `decision`, `shape`, `gate`, `scope_type`, `implied`, `fresh`,
 *     `snapshot` (+ `scope`, `principal` when enabled).
 *   - `alfiz.grant.matched` / `alfiz.grant.sole_match` — per `grant_id`.
 *   - `alfiz.revoke.matched` — per `revoke_id`; a suppressed check.
 *   - `alfiz.role.matched` — per `role_id`.
 *
 * `sole_match` is the one to alert on before revoking a grant: it counts the
 * checks that grant was the ONLY row allowing, so its value is exactly the
 * number of checks that would have flipped to deny. `matched` counts
 * participation, including checks another grant would have allowed anyway.
 */
export function otelMetricsObserver(
  options: OtelObserverOptions,
): MetricsObserver {
  const prefix = options.prefix ?? "alfiz.";
  const base = options.attributes ?? {};
  const attribution = options.attribution ?? true;
  const withPrincipals = options.principals ?? false;
  const withScopes = options.scopeInstances ?? true;
  const extrapolate = options.extrapolate ?? true;

  const counter = (name: string, description: string): OtelCounter =>
    options.meter.createCounter(`${prefix}${name}`, {
      description,
      unit: "{check}",
    });

  const checks = counter("checks", "Permission checks evaluated by Alfiz");
  const grantMatched = attribution
    ? counter("grant.matched", "Checks a grant row participated in allowing")
    : null;
  const grantSole = attribution
    ? counter(
        "grant.sole_match",
        "Checks a grant row was the SOLE matcher for — revoking it would have denied them",
      )
    : null;
  const revokeMatched = attribution
    ? counter("revoke.matched", "Checks a revoke row suppressed")
    : null;
  const roleMatched = attribution
    ? counter("role.matched", "Checks a role's patterns participated in allowing")
    : null;

  const weightOf = (observation: CheckObservation): number =>
    extrapolate && observation.sampleRate > 0 ? 1 / observation.sampleRate : 1;

  return (observation) => {
    const weight = weightOf(observation);
    const attributes: OtelAttributes = {
      ...base,
      permission: observation.permission ?? "(any)",
      decision: observation.decision,
      shape: observation.shape,
      gate: observation.gate,
      scope_type: observation.scopeType,
      implied: observation.implied,
      fresh: observation.fresh,
      snapshot: observation.snapshot,
    };
    if (withScopes && observation.scope !== undefined) {
      attributes["scope"] = observation.scope;
    }
    if (withPrincipals) {
      attributes["principal"] =
        "userId" in observation.principal
          ? `user:${observation.principal.userId}`
          : `service:${observation.principal.serviceId}`;
    }
    checks.add(weight, attributes);

    if (!attribution) return;
    for (const grantId of observation.matchedGrantIds) {
      grantMatched!.add(weight, { ...base, grant_id: grantId });
    }
    if (observation.soleMatchGrantId !== null) {
      grantSole!.add(weight, {
        ...base,
        grant_id: observation.soleMatchGrantId,
        gate: observation.gate,
      });
    }
    for (const revokeId of observation.matchedRevokeIds) {
      revokeMatched!.add(weight, { ...base, revoke_id: revokeId });
    }
    for (const roleId of observation.roleIds) {
      roleMatched!.add(weight, { ...base, role_id: roleId });
    }
  };
}
