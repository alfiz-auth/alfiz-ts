/**
 * The event poller: push-like invalidation for long-lived multi-node
 * deployments, with no pub/sub infrastructure. It tails the persisted
 * invalidation log (`events.persist`) on an interval and re-emits what it
 * finds into the local Application's listener stream, so clients attached
 * to THIS process bust within one poll of a write on ANY process.
 *
 * Strictly optional sugar: correctness never depends on it. A client with
 * `revalidateAfterMs` already validates against the log on its own
 * schedule; the poller just moves invalidation from read time to poll
 * time. Own writes come back around too (they are in the log) — a
 * duplicate bust of an already-busted entry, harmless.
 */

import type { InvalidationEvent } from "@alfiz/core";

/** What the poller needs: the Application's log view and its local re-emit. */
export interface EventPollerSource {
  epoch?:
    | {
        head(): Promise<number>;
        since(
          seq: number,
          limit?: number,
        ): Promise<
          { upTo: number; events: InvalidationEvent[] } | { gap: true }
        >;
      }
    | undefined;
  ingestEvents(events: readonly InvalidationEvent[]): void;
}

export interface EventPollerOptions {
  /** Poll interval in ms. Default 5 000. */
  intervalMs?: number | undefined;
  /** Observes polling errors (the poller retries on the next tick regardless). */
  onError?: ((error: unknown) => void) | undefined;
}

export interface EventPoller {
  /** Stops polling. Idempotent. */
  stop(): void;
}

/**
 * Starts tailing `source`'s event log. Throws when the source has no
 * `epoch` (persistence is off) — a silent no-op poller would read as
 * working invalidation. The first tick starts from the CURRENT head:
 * local caches already reflect local history, and foreign history is
 * bounded by the client TTLs the poller is tightening, not replacing.
 */
export function startEventPoller(
  source: EventPollerSource,
  options?: EventPollerOptions,
): EventPoller {
  const epoch = source.epoch;
  if (epoch === undefined) {
    throw new Error(
      "startEventPoller requires event persistence (the Application's events.persist option)",
    );
  }
  const intervalMs = options?.intervalMs ?? 5_000;
  let cursor: number | null = null;
  let stopped = false;
  let ticking = false;

  const tick = async (): Promise<void> => {
    if (ticking) return; // never overlap slow polls
    ticking = true;
    try {
      if (cursor === null) {
        cursor = await epoch.head();
        return;
      }
      // Drain to the head — multiple pages if a burst landed.
      for (;;) {
        const result = await epoch.since(cursor);
        if (stopped) return;
        if ("gap" in result) {
          source.ingestEvents([{ type: "all" }]);
          cursor = await epoch.head();
          return;
        }
        if (result.events.length === 0) return;
        source.ingestEvents(result.events);
        if (result.upTo <= cursor) return; // defensive: no progress
        cursor = result.upTo;
      }
    } catch (error) {
      options?.onError?.(error);
    } finally {
      ticking = false;
    }
  };

  const timer = setInterval(() => void tick(), intervalMs);
  // Never hold a process open just to poll a cache signal.
  timer.unref?.();
  void tick();

  return {
    stop() {
      stopped = true;
      clearInterval(timer);
    },
  };
}
