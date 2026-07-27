# Permission Metrics — Feasibility Analysis

Status: analysis only; no code changes proposed yet. Assesses live metrics for
permission checks ("what is being hit, and by who"), the two motivating use
cases — revocation safeguards and free per-action metrics — the federated
centralized dashboard, and user-reported custom metrics.

**Verdict: feasible, and the collection layer really is practically free —
the implementation already computes and discards the exact attribution data
the safeguard use case needs.** Two decisions need to be made deliberately
before any code: an amendment to the §17/§18 "the Service cannot observe
checks" guarantee before anything flows to a centralized dashboard, and a
scope boundary on custom metrics so this stays a seam rather than an
observability product.

---

## 1. Why collection is nearly free — confirmed in the implementation

Two properties of the current code make check-level metrics cheap in a way
that is not merely plausible but already visible in the source:

**Decisions are never cached** (§12; `client.ts` header comment). Closures
are cached; every logical check still runs evaluation. So an observation
hook at the evaluation layer sees *true* per-action counts — there is no
decision cache silently absorbing 95% of checks and undercounting usage.
This is the property that makes "free per-action metrics" real rather than
approximate.

**Full grant attribution is already computed on every check and thrown
away.** `checkKey` is literally implemented as `explainKey(...).allowed`
(`access.ts:210-216`): every check already materializes `matchedGrants` and
`matchedRevokes` — the complete list of rows that satisfied or suppressed
the decision — and then discards everything but the boolean. Recording
"grant row X satisfied a check" costs a map increment on data already in
hand. No new evaluation work, no second pass, no `explain()` call on the
hot path.

There is also a single choke point to instrument: every check shape —
`can`, `can.fresh`, `require*`, `canAny`, `snapshot.can`, `holdsAnywhere`,
`effectiveKeys` — bottoms out in `AlfizClient` methods or
`AlfizSnapshot` sync evaluation over the same `CheckContext`. One observer
seam covers the whole surface.

Estimated hot-path overhead: O(1) map increments per check on
already-materialized arrays, plus one bounded-map insertion for
high-cardinality dimensions. Effectively free, as conjectured.

## 2. Design constraints the architecture imposes

These are not blockers; they dictate the shape of the design.

**The Client reports; the provider stores.** §2.1's "the Client holds no
storage and performs no I/O of its own" has never meant the Client is
hermetic — every closure fetch is I/O *through the provider contract*.
The conforming delivery channel for metrics is therefore the same one:
a batch-report method on `AlfizProvider` (mirroring how audit is served
over the contract), capability-gated by a `metrics` flag exactly like
`audit`. The Client accumulates windowed counters **in memory only** —
ephemeral evaluation state with the same standing as the closure caches
(§12), never durable — because snapshot checks are synchronous and gates
are hot, so per-check provider calls are impossible; it then delivers
batches through the contract, and the provider owns storage and
retention. Nothing durable ever lives client-side.

This structure also buys topology-transparency for free: standalone, the
Application stores usage locally; federated, the *Application* decides
whether batches flow further up. Since a Client only ever attaches to its
local Application, the Client never reports toward the Service in any
topology — the §5 question collapses to one opt-in at the
Application→Service boundary, exactly where the audit-stream precedent
already sits.

Beneath the contract method, a host-injectable observer remains the
right primitive: it is the BYO-sink seam (§6) for deployments piping
into their own metrics stack, and "batch to the provider" is simply its
default consumer. Layer assignment per the §16 governing rule:

| Piece | Home | Why |
| --- | --- | --- |
| Observation emission (observer seam, `CheckObservation` type) | Client | Pure emission during evaluation |
| Windowed in-memory aggregation, counter merge | Client | Ephemeral evaluation state, like closure caches |
| Batch delivery | Provider contract (optional capability) | The Client's one sanctioned I/O channel |
| Storage, retention, compaction | Application | Durable rows in the local database |
| Usage read surface for admin components | Provider contract (optional capability) | Same pattern as `audit` |
| Uplink of aggregates (opt-in) | Application → Service | Same boundary as the hosted audit stream |
| Cross-application aggregation, hosted dashboard | Service | Cross-application vantage |

**Snapshot checks are synchronous.** `snapshot.can()` is the blessed shape
for server-rendered pages and cannot await anything. The observer must be
synchronous, fire-and-forget, allocation-light, and wrapped so that a
throwing observer can never fail a check. Metrics are lossy by design:
dropping observations under pressure is always correct; failing or slowing
a check never is. There must also be no feedback path — nothing in
evaluation may ever read metrics state.

**Sessions double-check.** `AlfizSession.can` evaluates the actor's real
access AND the preview subject's (`session.ts:72-79`). Observations need a
check-shape dimension (and ideally a preview marker) so a view-as session
doesn't double-count, and so attribution follows the session rule that
already exists for audit: attribution never follows the preview.

**Visibility checks are not actions.** `canAny`, `heldKeys`,
`holdsAnywhere`, and snapshot conditional-UI checks vastly outnumber gates
and don't correspond to user actions. The check-shape dimension lets
"per-action metrics" default to gate shapes (`can`/`require*`/`can.fresh`
at concrete scopes) while visibility traffic is still countable
separately. This distinction is load-bearing for the revocation-safeguard
numbers too: "this grant matched 40,000 renders" and "this grant gated
1,200 actions" are very different warnings.

## 3. Cardinality and aggregation policy

Per-observation dimensions split cleanly into bounded and unbounded:

- **Bounded:** permission key (catalog-sized), decision (allow/deny),
  check shape (~6 values), grant row id / revoke row id (row-count-sized),
  role id (via the matched grant's `roleId`).
- **Unbounded:** principal, scope instance.

Policy that keeps memory fixed:

- Scope instances aggregate to **scope type** by default — parseable from
  the `type:id` instance format with no lookup. Raw instance-level counting
  is opt-in per scope type (some deployments will want per-project numbers;
  none want per-document cardinality by default).
- Principals go in a bounded map with eviction — the client already sets
  precedent with `maxSubjectCacheEntries` — giving exact counts for up to N
  principals per window and an overflow bucket beyond. "Who is using this
  grant" for the safeguard UI needs recent distinct principals, not exact
  per-principal totals, so a bounded recent-set per grant id suffices.
- Counters are monotonic within a flush window and tagged with instance id
  + window bounds, so multi-instance deployments (many app servers, each
  with its own client) merge trivially wherever flushes land.

## 4. The revocation-safeguard use case — the metric must be "sole matcher"

The naive metric overwarns. A check satisfied by two grant rows loses
nothing when one is revoked; warning "this grant matched 1,200 checks"
against a grant fully shadowed by a broader one teaches admins to ignore
the warning. The counterfactually correct signal is available for free at
the same place: when `matchedGrants.length === 1`, that row was the *sole*
matcher — revoking it would have flipped those checks. Per grant id, keep
both counters:

- `matched` — participated in an allow (usage in the loose sense);
- `soleMatch` — was the only row allowing (revocation would have denied).

The warning keys on `soleMatch`; `matched` contextualizes ("used often,
but always alongside the Editors group grant").

Same machinery, mirrored, for revokes: `matchedRevokes` attribution gives
"this revoke is actively suppressing N checks/day" — and since *deleting a
revoke widens access*, that warning points the opposite direction and is
arguably the more security-relevant of the two.

Wrinkles, all minor:

- **Ancestor implication** (§7.5, `checkImplied`) allows without going
  through `explainKey`'s matched list; attributing the underlying grant
  needs a few lines of plumbing there.
- **Role-conferred grants:** a matched grant row carrying a `roleId` also
  informs role-edit/delete safeguards ("this role's `billing.*` pattern was
  the sole matcher for N checks"), a natural follow-on.
- **The heuristic must be stated honestly.** Usage lags, and absence of
  recent use never means safe to revoke — break-glass grants are precisely
  the rarely-used ones. The warning copy is "this is frequently load-
  bearing," never "this one is safe."

Storage: a rolling window per grant id (e.g. daily buckets, bounded by
grants × retention days) flushed by batch upsert on an interval — write
amplification is bounded and off the request path. Surface it through the
existing patterns: a `metrics` flag on `ProviderCapabilities` (exactly like
`audit`), optional `StorageDriver` methods, a provider read method for the
headless grant/revoke components to render usage — components already
render capability-gated, so progressive disclosure (§1) is preserved:
deployments that don't opt in see nothing.

## 5. Federation: the §17/§18 tension is the one real architectural decision

The spec commits, three times and emphatically, to the check path being
invisible to the Service:

- §1: "The check path is unmetered because it is unmeterable… per-check
  pricing is impossible by construction — a guarantee, not a policy."
- §17: "nothing on the request path of the customer's application is ever
  counted, priced, or throttled by the Service."
- §18: "the Service cannot observe checks, by construction."

A centralized dashboard of check metrics makes checks observable to the
Service. That converts "impossible by construction" into "we promise not
to price it" — a real weakening of a differentiating guarantee, and it
must be a deliberate spec amendment, not a side effect of a feature.

The Client-reports-to-provider structure (§2) contains this decision to
a single boundary: the Client only ever delivers batches to its local
Application, so nothing metrics-shaped can reach the Service except by
the Application choosing to forward it. The saving precedent for that
forwarding already exists: the opt-in hosted audit stream (§2.7) — "the
only data that flows up, and it is append-only history, never
evaluated." Metrics can ride an identical posture, and the guarantee
survives in a slightly narrowed, still-honest form:

1. **Opt-in per deployment**, default off. Standalone and linked-without-
   opt-in deployments ship nothing; the local feature set (safeguards,
   per-action counts) is complete without the Service, per the §16 rule.
2. **Aggregated before upload.** The client/Application aggregates into
   windowed counters; the Service receives batches, never individual
   checks. "The Service can never observe an individual check" remains
   true by construction; only windowed counts are disclosed, voluntarily.
3. **Append-only, never evaluated, never metered.** Same posture as
   hosted audit retention; explicitly excluded from the metering
   dimensions of §17 (retained *volume* could be metered exactly as audit
   volume is — that meters storage work performed, not checks).
4. **Principal-free by default on the uplink.** Per-principal usage is
   PII-adjacent; the centralized dashboard gets aggregates and bounded
   distinct-counts unless a deployment explicitly opts principals in.

If the team is unwilling to amend §17/§18, the conclusion is not "don't
build metrics" — it is "metrics stay local," which still delivers both
primary use cases, since safeguards and per-action metrics are consumed
where the checks run anyway. Only the cross-application dashboard is
gated on the amendment.

## 6. Custom metrics: build the seam, not the product

The pipeline (sink → aggregate → flush → uplink) generalizes to arbitrary
named counters trivially — that part is true. But dashboards, query
languages, alerting, and retention for arbitrary metrics is the business
of being an observability vendor, and OpenTelemetry already owns that
contract. "It's a powerful system" argues for making the *seam* powerful,
not for hosting the data.

Recommended posture, in priority order:

1. **The observer is the custom-metrics feature.** A structured, typed
   `CheckObservation` stream lets any deployment pipe permission metrics
   into the metrics stack they already operate — an OTel/StatsD adapter is
   ~50 lines against the observer interface, and can ship as an example or
   a tiny package. This is strictly more powerful than hosting: their
   dashboards, their alerting, their retention, joined with their
   application metrics. It also flows the data in the *opposite* direction
   from the Service, which keeps §17/§18 untouched for these users.
2. **Host-defined counters through the Alfiz aggregator** — a small
   `metrics.count(name, tags)` convenience so app-level events can appear
   alongside permission metrics on the hosted dashboard — is acceptable
   *if* explicitly bounded: counters and tags only, capped cardinality, no
   general-purpose querying, no promise of being anyone's primary metrics
   system. This is the "not our primary business, but don't cripple it"
   compromise.
3. **Do not** build metric dashboards beyond the permission-shaped ones,
   alerting, or long-horizon analytical retention. That is where the cost
   curve turns vertical and the differentiation is negative.

## 7. Phasing and cost

**Phase 1 — Client observer + pure aggregator.** `CheckObservation` type,
an `observer` client option invoked (guarded, sync) from the check paths
and snapshot, attribution plumbed from `explainKey` results and
`checkImplied`; a pure windowed-aggregation utility with a flush callback.
No contract change, no storage, no spec change. Roughly 200–400 LOC plus
tests. This alone unlocks per-action metrics into any existing metrics
stack, today.

**Phase 2 — Contract delivery + Application usage store + safeguards.**
`metrics` capability flag, the batch-report and usage-read methods on
`AlfizProvider` (with "batch to the provider" wired up as the default
observer consumer, per §2), optional `StorageDriver` methods (memory +
Prisma), rolling per-grant/per-revoke buckets with retention compaction,
and usage/warning rendering in the headless grant and revoke components.
This is the largest in-repo phase: contract surface, schema, two drivers,
retention policy, component work. Still bounded and conventional.

**Phase 3 — Service uplink + hosted dashboard.** Rides the audit-stream
pattern; mostly lives outside this repo. **Blocked on the §17/§18
amendment decision (§5 above), which should be made before Phase 2 settles
the wire shapes.**

**Phase 4 (optional) — custom counters** per the §6 boundary.

## 8. Risks, summarized

| Risk | Severity | Mitigation |
| --- | --- | --- |
| Weakening the "unmeterable check path" guarantee | High (strategic, not technical) | Deliberate spec amendment; aggregate-only, opt-in uplink (§5) |
| Cardinality blowup (principals × scope instances) | Medium | Scope-type default, bounded maps, overflow buckets (§3) |
| Overwarning on revocation (shadowed grants) | Medium (product trust) | `soleMatch` counter, honest copy (§4) |
| Scope creep into observability vendor | Medium | The §6 boundary, decided up front |
| Hot-path overhead / a throwing observer failing checks | Low | Sync fire-and-forget, guarded invocation, lossy by design (§2) |
| Per-principal data as PII under federation | Low–Medium | Principal-free uplink by default (§5) |

None are technical blockers. The proposal is sound; the collection layer
is as cheap as hoped; the decisions that need human judgment are the
guarantee amendment and the custom-metrics boundary.
