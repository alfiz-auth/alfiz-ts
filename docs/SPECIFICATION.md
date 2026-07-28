# Permissions Layer — System Specification

An authorization system delivered in three layers. The **Client** is the core tooling: the permission grammar, evaluation semantics, catalog machinery, check shapes, enforcement points, static verification, and headless components — every part of the system that is a pure function over data supplied to it, with no infrastructure dependencies. The **Application** is a local provider serving one codebase against one database (the sole hard requirement), with no external dependency: storage, workflows, sessions, and identity-provider integration for a single application. The **Service** is a managed provider with a richer toolset, exposed to Clients through the *same provider contract* the Application implements, and offered in two accretive tiers: **hosted administration** — a managed dashboard, admin seats, and audit retention operating by relay against a still-authoritative Application — and **federation** — catalog registry, cross-application composition, integration provisioning, and the centralized org root.

Orthogonal to the layers is a movable role, the **organizational root** (§2.5): the single authoritative home of organizational-domain data — hierarchy, groups, roles, global grants — held by the Application when standalone and by the Service when federated.

Identity (users, sessions, organizations) is deliberately left to identity providers (Clerk and similar); resource data (documents, folders, hierarchies) is deliberately left to the application's own database. Runtime checks never leave the application.

## 1. Design principles

**The layer line is architectural, not commercial.** A capability belongs to the Client if it is a pure function over provided data; to the Application if one database satisfies it; to the Service only if it requires infrastructure or vantage no single application has; and organizational-domain capabilities are homed at the org root, wherever that currently sits. No layer is artificially limited, and the Service never gates a capability that could have run locally. The Service's commercial surface therefore has two distinct characters, stated plainly: **hosted administration is convenience** — assembled from the same headless kit and the same contract any customer could self-host, replaceable by construction — while **federation is capability**, the machinery that genuinely requires central infrastructure or cross-application vantage. Section 16 enumerates the split explicitly.

**Organizational-domain data has exactly one writer.** Data keyed to the organization rather than to any application — reporting hierarchy, user groups, role definitions, global-scope grants — lives at the org root, and everyone else holds a synced read model. This is not because such data requires cross-application vantage (a standalone org has managers too), but because two writers would fork the organization. The org root moves by audited promotion and demotion (§2.6), never by concurrent authority.

**No infrastructure opinions, all semantic opinions.** The Client is unopinionated about storage, transport, and deployment — any conforming provider serves it. It is *maximally* opinionated about semantics: union-only inheritance, negative-always-wins precedence, forward-inclusive wildcards, the naming floor. The semantic opinions are the product and are not pluggable.

**The catalog is explicit and lives in code.** Permissions are declared in a single source-of-truth catalog module per application, not inferred from call sites and not configured in a dashboard. Call-site checks are verified *against* the catalog at build time, but the catalog carries structure that call sites cannot express: navigation wiring, the read-versus-action taxonomy, scope-type declarations, and requestability (§9.2). Under federation the catalog additionally becomes a published contract (§5.2).

**Inheritance is union-only; negation is personal-only.** Groups, roles, and object hierarchies can only widen access. The single negative layer is the individual revoke, and it always wins. This invariant is load-bearing: it makes cycle condensation sound (§10.3), keeps precedence a single rule rather than a matrix, keeps effective access auditable — and makes org-root merges tractable (§2.6), since positive access data unions safely.

**Hierarchy is data, resolved at check time.** Grants are stored once, at the node where they are made, and never fanned out. Checks walk *up* ancestor chains (O(depth)), never *down* subtrees (O(subtree)). The application owns its hierarchies and exposes them through resolver interfaces.

**Everything reduces to the grant row.** Roles, groups, public access, machine scopes, approved access requests, and provisioned integrations are all expressed as, or resolve to, the one atomic tuple (§8.1). New features must compose with the existing algebra rather than introduce parallel semantics.

**Bounded staleness, stated honestly.** Caching operates on closures, not decisions, with a documented propagation bound and a fresh-read escape hatch for destructive actions.

**The check path is never metered, because the Service is never in it.** Runtime checks execute in-process against local data and never touch the Service in any topology, so per-check pricing is impossible by construction — a guarantee, not a policy. The Service meters only the work it alone performs: relay sessions and admin seats, sync and registry operations, reconciler runs, retained audit volume (§17). Usage observed is work performed; an idle deployment accrues nothing.

The guarantee is about the Service's *vantage*, not about observability as such. An application may of course count its own checks, and §18 specifies the machinery for doing so — a local observation stream feeding the deployment's own metrics stack and its own store. That data belongs to the deployment, never crosses the boundary, and is not a metering dimension. Stating the guarantee as "checks are unobservable" would have been the stronger sentence and the false one.

**Progressive disclosure.** Machinery a deployment has not opted into is invisible. Nothing is requestable, approvable, multi-parent, or workflow-bound by default; a small application sees a small system.

**AI-native means convention plus verification.** The Client ships a machine-legible convention document intended for agent context, and static checks that verify generated wiring rather than merely guiding it.

## 2. Architecture

### 2.1 The Client

The Client is the evaluator. It comprises: the grammar and pattern matcher; closure evaluation and the effective-access algebra; the catalog definition API and its derived template-literal types; the check shapes (`can`, `canAny`, their `require*` forms and `can.fresh`); enforcement points; static verification; closure caches (as evaluation state, §12); and the headless administration components, which render a catalog and speak only the provider contract. Every Client capability is a pure function over data a provider supplies. The Client holds no storage and performs no I/O of its own.

### 2.2 The provider contract

The provider contract is the single load-bearing interface of the system, implemented identically by the Application and the Service. It comprises: **closure supply** (subject closures and, via the ancestry seam, object closures); **row operations** (grant, revoke, and request CRUD, with provenance and expiry); **catalog registration** (accept a verified catalog publish); **graph writes** (group parentage, virtual parents, reporting edges — with the integrity semantics of §10 enforced provider-side); and **invalidation events** (a stream of closure-bust notifications the Client's caches consume). The wire format of grant tuples, revoke rows, request objects, and catalog publishes is fixed by the contract, so a Client cannot observe which provider it is attached to except through capability discovery (a provider advertises which optional capabilities it supports, and the components render accordingly, preserving progressive disclosure).

The Service implements the contract in two roles: **authoritatively**, for data it owns, and **by delegation**, for a linked Application's data (§2.7) — forwarding reads and writes to the owning Application, which enforces its provider-side integrity rules on relayed operations exactly as on local ones. Delegation is invisible to an attached Client except through capability discovery, and it never makes the Service a second writer.

### 2.3 The Application

The Application is the local provider: a library-embedded implementation of the contract against the application's own database, with no external dependency beyond that database. It always owns: local storage of instance-scoped grants, revokes, and requests; write-path graph integrity for local object graphs; request workflows for application-scoped access; session construction and view-as; identity-adapter session verification; and the local service-principal shim. When standalone, it additionally holds the org root (§2.5). A Client attached to a standalone Application is the complete system for one organization with one application.

### 2.4 The Service

The Service is the managed provider: the same contract, richer capabilities, offered in two accretive tiers.

**Hosted administration** serves a linked, still-standalone Application (§2.7): the hosted dashboard — the assembled, styled, maintained product built from the same headless kit (§13.4) — with managed admin seats for non-engineer administrators; the hosted approvals inbox rendering the Application's own request queue; and opt-in hosted audit retention and export, a durable append-only copy of the Application's audit stream for compliance horizons longer than the application cares to keep locally. Everything in this tier operates by delegation: the Application remains the org root and the sole writer, and every relayed operation passes through its provider-side enforcement. The tier is deliberately replaceable — a customer can self-assemble the identical surface from the headless kit — and is offered as convenience, never as gated capability.

**Federation** owns what genuinely requires cross-application vantage or central infrastructure: hosting the org root; the catalog registry (namespace ownership, publish versioning, tombstones); cross-namespace role composition; cross-application request routing and org-wide aggregation; provision-and-reconcile integrations and drift reporting; service-principal credential minting; and cross-application audit aggregation.

The Service enforces the identical graph-integrity semantics as the Application for the graphs it owns — one specification of the rules at the contract level, enforcement at whichever site owns the data.

### 2.5 The organizational root

The org root is a role, not a layer: the current single authoritative home of all **organizational-domain data**. That dataset comprises: the reporting hierarchy and the implicit groups derived from it (§6.4); user groups — definitions, memberships, parentage, and group-side virtual parents (§6.3); role definitions (§6.2); global-scope grants and global-scope revokes (§8); approval policies attached to org-root entities (§9.3); the org-wide approvals inbox for org-scoped requests (§9.4); directory ingestion — syncing organizations, group mappings, and reporting edges from the identity provider or directory (§15); and the audit log of all writes to the above.

The homing rule: **standalone, the Application is the org root; federated, the Service is.** A standalone organization's only provider is trivially the authoritative home of its organizational data, which is why a standalone deployment gets the *full* feature set — including management-layer approvals against a locally-stored hierarchy — with no external dependency. What is *not* org-root, at either home: instance-scoped grants and revokes, object graphs, ancestry resolution, and sessions (always Application — resource-shaped and runtime-shaped); and the registry, reconcilers, credential minting, and cross-app aggregation (always Service — these require central infrastructure or cross-application vantage, not merely an authoritative home).

Every non-root party holds the org-root dataset as a synced read model, evaluated locally by the Client like all other provider data, and rejects local writes to it.

### 2.6 Promotion, demotion, and merges

Authority moves only by audited handoff.

**Promotion.** Promotion typically proceeds from the linked state (§2.7) — the link's relay and audit machinery is already in place, and promotion adds only the authority transfer. Federating an Application that has been acting as org root imports its organizational dataset into the Service through the same validation paths that already exist for external input (directory-import condensation, §10.2, for graphs; ordinary row import for grants). Authority transfers atomically: thereafter the Application receives the dataset back as a synced read model and rejects local org-domain writes. Pending requests with management stages survive promotion untouched — they reference *stages* ("2 layers up"), not resolved approver identities, and resolve against the promoted hierarchy at next evaluation.

**Merges.** When a second Application federates and also carries local org-domain data, mergeability follows the algebra. Positive access data — groups, role definitions, global grants — **unions safely**, because inheritance is union-only; name collisions are flagged for rename, identities remain opaque IDs, and the union can only widen (which the audit log records). Revokes also union safely, since unioning negatives only narrows. The **reporting hierarchy does not auto-merge**: a tree is not union-safe (a user cannot have two managers), so conflicting trees are surfaced for human resolution in the promotion flow, never silently combined.

**Demotion.** Leaving the federation runs the machinery in reverse: the org-root dataset snapshots down to the sole remaining Application, which resumes authority — exactly parallel to virtual-parent dissolution (§10.3), and recorded with the same provenance discipline. Authority handoffs as audited snapshots is a single pattern used everywhere it arises.

### 2.7 Composition topology

The same-contract property does **not** mean an application's Client connects directly to the remote Service. Three attachment states exist, and the distinctions preserve the system's invariants:

**Linked: Application-with-relay.** A standalone Application may register with the Service without federating. Nothing moves: the Application remains the org root and the sole writer of everything it stores. The Service records the link, authenticates dashboard sessions (admin seats), and relays contract operations between data-plane-less consumers and the Application; the opt-in audit stream (§2.4) is the only data that flows up, and it is append-only history, never evaluated. Unlinking deletes the link and the relay state — no snapshot or handoff is required, because no authority ever moved. Linking is the intended first step of the growth path: the hosted dashboard becomes available the day a non-engineer needs to administer access, while the deployment remains architecturally standalone.

**Federated: Application-with-upstream.** An application's Client always attaches to its local Application. Federating means the Application acquires the Service as an *upstream*: it publishes its catalog up; syncs the org-root read model and other central data down; relays upstream-driven invalidation events into the local stream; and keeps instance-scoped grants, ancestry resolution, and runtime checks strictly local. This is what keeps "runtime checks never leave the application" and the no-dual-write property true under federation — the Service cannot evaluate scoped checks, because it cannot see the application's resource tables, and it never needs to.

**Data-plane-less consumers: direct Client→Service.** Anything that owns no resources — the hosted administration dashboard, CLIs, audit tooling, reconciler consoles — is a Client attached directly to the Service as its provider — which serves it authoritatively for federated data and by delegation for linked Applications' data. This is the payoff of the shared contract: the hosted dashboard is assembled from the same headless components and the same Client calling the same interface as a self-built admin page, merely pointed at the other implementation.

An organization wanting Service-intrinsic capabilities (e.g. a provisioned Zoom integration, §14) with only one application does not acquire them in the Application; it federates with a single member — the same topology at its minimum size — keeping the Application's zero-dependency promise intact.

### 2.8 Data placement

Under linking the Service holds nothing authoritative: only the link registration, relay and metering state, and the opt-in retained audit stream; all authoritative data remains where standalone placement puts it. Under federation the Service holds the org-root dataset plus scope *types* and published catalogs. Each Application keeps its instance-scoped grants locally, since they reference resource rows only it can resolve. Runtime checks are local and in-process in every topology: a Client evaluates against its compiled-in catalog, its Application's local rows, and the synced org-root read model. Nothing resource-shaped is ever replicated out of the application.

## 3. Permission grammar

### 3.1 Namespaces and keys

Every application declares a **namespace** — its key prefix — even when standalone, where it is locally redundant. This is required so that catalogs are federation-shaped from the first commit; an unprefixed catalog would collide with registry ownership the day a second application appears.

Every permission key is dot-separated. The blessed convention is exactly three levels:

```
<project>.<tab>.<permission>
```

`<project>` and `<tab>` are group levels — folders, never permissions themselves. `<permission>` is the leaf: the only grantable, checkable unit. Group levels are *inferred*: every dotted prefix of a declared key is a group, which is why depth is free and why a key that another key extends — being both a folder and a leaf — is rejected.

Depth is a **convention, not a structural rule**. The Client permits any depth and ships three levels as the default because depth that maps to UI structure (project → section → action) keeps permission trees comprehensible to the humans administering them; a catalog declaring a different house style (`conventions: { depth }`) builds, and the deviation is reported by catalog lint at build time (§13.2) rather than thrown at boot. Structural invalidity — a malformed segment, an undeclared namespace, a key that is also a group path — still fails at boot.

### 3.2 Naming conventions

Every tab defines, at minimum, read permission(s) and one action permission per distinct action. Reads are prefixed `read` — bare `read` when the tab has a single readable surface, `read_<thing>` when it exposes distinct surfaces (e.g. `read` alongside `read_pii`). Actions are named `<verb>_<noun>` (`decide_student`, `advance_stage`). Destructive actions always stand alone as their own leaf (`delete`) and are never bundled into a broader permission. More granularity than this floor is encouraged where a surface warrants it; less is a catalog-lint error (§13.2).

### 3.3 Wildcards

Every consumer of permissions supports subtree wildcards: `*` matches everything; `<project>.*` matches a whole project; `<project>.<tab>.*` matches everything under a tab. Wildcards are **forward-inclusive**: a stored `mathaniyy.approvals.*` pattern grants permissions added under that group in the future, automatically. This is a deliberate semantic commitment with a known tradeoff — a role holding `admin.*` silently acquires every future admin capability — and the Client owns and documents it rather than making it configurable. Pickers and role editors store the `<group>.*` pattern when a whole group is selected, which is what makes forward-inclusion real rather than a snapshot. Forward-inclusion also does the heavy lifting under federation: a role holding a subtree pattern absorbs newly published permissions with no registry coordination (§5.3).

Broad-versus-narrow authority over a resource family — "may issue codes in every payment namespace" versus "only application-fee codes" — is not modeled with parallel blanket-and-variant permission keys. It is modeled with **scopes**: one permission (`issue_code`), granted at a broad scope or a narrow one (§7). The grammar keeps one key per action; the scope system carries the breadth.

## 4. The catalog

The catalog module declares the application's permission tree, scope types (§7.1), navigation wiring, per-scope-type grantability, and requestability (§9.2). It is the single source of truth for the application: template-literal types are derived from it, static verification checks call sites against it, and the administration components render from it.

Permissions are declared by their **full dotted key** — the same notation every check, grant, role pattern, and navigation entry uses — so the catalog reads in the language of the system it describes and a key at a call site greps to its declaration. Grouping is an organizing affordance layered on top, never a requirement: a small catalog is one flat map of keys, and a large one is composed from `group()` blocks, each a named unit carrying one group's metadata and scope defaults. Because keys are absolute, blocks compose by concatenation rather than by structural merge, which is what makes a per-feature catalog file — declared next to the code it gates — a supported layout rather than a workaround. The catalog is authored against the Client and verified by the Client; *publishing* it is a provider operation — the Application stores it locally, the Service versions and registers it (§5). The catalog is application-domain, not organizational-domain: each application owns its namespace's catalog at every topology, which is why catalogs publish rather than promote.

## 5. Federation

### 5.1 Applicability

This section applies only when an Application has the Service as upstream. A standalone Application ignores it entirely — as does a linked one (§2.7): the link carries relay traffic, not an upstream, and no publish, sync, or promotion machinery engages until federation.

### 5.2 The catalog as published contract

Deployment ends with a publish step: the Application pushes its namespace's catalog — the verified, explicit catalog, not a raw call-site scan — to the registry, the way a service publishes an OpenAPI schema. The registry enforces **namespace ownership**: publisher credentials are scoped to a prefix, so no application can define or shadow another's keys. Read access to another application's published catalog is itself gated by registry permissions expressed in the system's own grammar, answering inter-application isolation with the system's own machinery.

Publishes are **versioned** monotonically per namespace, and out-of-order publishes are rejected, so a rollback deploy cannot un-publish newer keys.

**Contracts are portable by construction.** Three data-model commitments keep cross-tenant integration possible without designing for it: publisher identity is separate from consumer tenancy (a namespace is published once and consumable by many federations, registry-style); contracts are consumable read-only across tenant boundaries; and grants are strictly tenant-local. Only vocabulary ever crosses a business boundary — never access data. The integration-adapter pattern (§14) is already the consumption side of this shape; no further marketplace machinery is specified or promised.

### 5.3 Catalog lifecycle

**Additions** require no coordination: forward-inclusive wildcards absorb new keys into existing subtree grants automatically, and new leaves otherwise simply appear in editors.

**Removals are tombstones, never deletes.** A key an application stops publishing may still be referenced by central roles and grant rows; hard deletion would silently rewrite role meanings. Tombstoned keys stop matching checks but remain visible in editors as deprecated, and the registry produces a drift report ("role X references 3 permissions no longer published by any application").

**Skew is bounded and safe-by-direction.** During rolling deploys the registry briefly disagrees with some running instance's compiled catalog. Enforcement is always local to each instance's own catalog; combined with forward-inclusive grants, skew in the widening direction is safe and skew in the narrowing direction is merely stale — the same bounded-staleness posture as §12, and stated alongside it.

## 6. Subjects

A **subject** is anything that can hold a grant: individual users, user groups (explicit or implicit), organizations (sourced from the identity provider), and the built-in subject `everyone`. Public access is not special-cased anywhere; "anyone can read this document" is an ordinary grant row whose subject is `everyone`, the subject-side mirror of the global scope.

### 6.1 Users

Users originate in the identity provider. The system stores no user profile data; it references provider user IDs and reads organization membership through the identity adapter (§15).

### 6.2 Roles

A role is a named bundle of permission patterns (leaves and wildcards). Roles have a human-facing name and description only — their identity is an opaque internal ID, so renaming a role never breaks assignments. Roles carry no negative patterns. Role definitions are **organizational-domain data, homed at the org root**: locally authored and stored when standalone, centrally defined when federated — where they may compose patterns across namespaces ("Teacher" grants `mathaniyy.students.*` and `zoom.host`), the capability that requires the registry to exist.

### 6.3 User groups

A user group is a named bundle of access — roles and direct permission grants, exactly the positive half of a role — plus a membership. It exists to grant a cohort at once. Membership is stored on the user record (`user.userGroups: string[]`), so "a person's groups" is a field read and "a group's members" is one indexed query.

**Groups are organizational-domain data, homed at the org root.** A cohort of people is an organizational fact, not an application's: eighty teachers are the org's teachers whichever applications they touch. Standalone, the Application authors and stores them; federated, they live centrally and sync down, and applications reject local group writes.

**Groups nest.** A group may declare one or more parent groups and inherits the union of their access; the canonical use is mirroring organizational hierarchy. The membership graph must be a directed acyclic graph (§10).

**Groups never revoke.** A group contributes only positively to effective access. The only negative layer in the entire system is the personal revoke (§8.3).

### 6.4 Reporting edges and implicit groups

A user record may carry a **reports-to** edge naming their manager. From reporting edges the system derives **implicit groups** — "Jane Doe's directs" and, transitively, "Jane Doe's org" — whose membership is computed from the edges rather than edited. Implicit groups are otherwise ordinary union-only subjects: they can be granted to, appear in subject closures, and be referenced by auto-approval predicates (§9.3). They cannot be manually edited (membership follows the edges) and cannot declare parents (their nesting *is* the reporting hierarchy).

The reporting hierarchy is **organizational-domain data, homed at the org root** — a standalone organization has managers too, and its Application stores the tree locally with the full feature set that depends on it. Implicit-group *semantics* are defined at the contract level, so the Client evaluates them identically whichever home populates them. Reporting edges also drive approval routing (§9.3).

### 6.5 Subject closure

The subject closure of a user is the transitive set: the user themself, every group they belong to (explicit and implicit), every ancestor of those groups, their organizations, and `everyone`. Subject closures are typically shallow and wide, and churn frequently; this shapes their caching policy (§12).

## 7. Scopes

### 7.1 Scope types versus scope instances

**Scope types** are static schema facts and live in the catalog, dotted like permissions: `docs.doc`, `docs.folder`. The catalog declares which permissions and roles are grantable at which scope types — granting `docs.reader` at a `billing.invoice` scope is a validation error. This is the system's analogue of a Zanzibar type system, and under federation, scope types are part of the published contract.

**Scope instances** are opaque identifiers — `docs.doc:123` — plus a parent pointer held as application data. The hierarchy path is never encoded in the instance key: user-defined hierarchies are mutable, and a path-encoded key would change a resource's identity (orphaning every grant on it) whenever it moved. Moving a resource is a data update to its parent pointer; every grant on it, and everything it inherits, follows automatically.

There is always a global scope, `*`. A grant with no scope is a grant at `*`; a fully global application is simply the degenerate case where `*` is the only scope in use, requiring no scope machinery at all. Intermediate breadths are ordinary scope nodes: a "payments" scope containing per-namespace child scopes lets one `issue_code` permission be granted broadly (at `payments`) or narrowly (at `payments.application_fees`) with no additional keys — the pattern that subsumes blanket-and-variant permission families.

### 7.2 Object inheritance and the ancestry resolver

Grants are stored at the node where they are made and never fanned out to descendants. At check time the Client resolves the target scope's ancestor chain — `doc:123 → folder:9 → folder:2 → *` — and a grant at any ancestor covers the target. Grant cost is O(1); check cost is O(path depth); moving a subtree moves its access for free; revoking a grant is deleting one row.

No layer of this system owns the hierarchy, because the hierarchy is application data. The contract is an application-supplied resolver:

```ts
resolveAncestors(scope: ScopeId): ScopeId[] // ordered, nearest-first, ending at "*"
```

The resolver may be backed by a parent-pointer walk, a materialized path column, or a closure table; the Client is indifferent for point checks, but prescriptive for listing queries (§11). The resolver is the reason applications attach to a local Application rather than directly to the Service: only the local process can resolve ancestry against the application's own tables.

### 7.3 Multi-parent objects

Single parent is the blessed default, enforced unless explicitly opted out per scope type. With multi-parent enabled, an object's effective access is the **union** of all parents' — a semantics some products want (shortcuts, labels-as-folders) and others consider a leak vector, so the opt-out is loud in both API and documentation. Multi-parent object graphs are DAGs under the same enforcement as group graphs (§10), with cycle detection and deduplication in closure computation.

### 7.4 Object closure

The object closure of a scope is itself plus all ancestors plus `*`. Object closures are typically deep, narrow, and nearly static — the opposite dynamics of subject closures — which is why the two sides get different cache policies (§12).

### 7.5 Ancestor visibility

Whether a grant at a scope implies limited visibility of its ancestors (the "shared doc shows its containing folder as a shortcut" behavior) is a product policy, not a check-semantics rule. The catalog can express it declaratively — marking a listing-read permission as auto-implied on ancestors of any granted scope — and the Client evaluates the implication during checks. Off by default.

## 8. Grants, revokes, and effective access

### 8.1 The grant tuple

The atomic unit of the system is the grant row:

```
(subject, role-or-permission-pattern, scope, expiry?)
```

Subject is any §6 subject; the middle element is either a role ID or a raw permission pattern (leaf or wildcard); scope is a scope instance ID or `*`; expiry is optional. An expired grant stops matching checks exactly as a deleted one would, but remains for audit. Expiry is what makes time-bound and just-in-time access (§9.5) an ordinary row rather than a parallel mechanism. Every grant row carries provenance: who or what created it — an administrator directly, an approved request (§9), a virtual-parent dissolution (§10.3), an org-root merge (§2.6), or a reconciler (§14).

Grant rows are homed by their scope: **global-scope grants (`scope = *`) are organizational-domain data at the org root; instance-scoped grants always live in the owning Application.** "Global role assignment" and "personal permission grant" are both just rows of this shape with scope `*`.

Gates may accept an any-of array of keys where a surface is legitimately reachable under multiple permissions.

Every row operation carries **provenance**, and provenance is validated at the write path alongside patterns, scopes, and role references — before any row is written, since a later rejection would leave a written row with no audit entry.

Because grant rows reference subjects and scopes as opaque strings — never foreign keys into the application's tables — the provider contract carries the cleanup half of the row operations: `deleteSubject` and `deleteScope` sweep the rows referencing a principal or a resource the host has deleted, in the same code path as the deletion, exactly as `notifyScopeMoved` pairs with moves. Without this discipline the rows strand silently, and identifier reuse would resurrect them as live access.

### 8.2 The check

`can(subject, permission, scope)` resolves to: **does any unexpired grant row connect a member of the subject closure to a member of the object closure, whose pattern (directly or via the named role's patterns) matches the permission?**

Both closures are small sets; the check is one indexed query, or an in-memory match against cached closures plus a grant lookup. This is reachability between two closures — the same shape as a Zanzibar check, executed in-process against provider-supplied data, in every topology.

A second check shape, `canAny(subject, pattern)`, answers whether the subject's effective access intersects a permission-key pattern at all — "does the viewer hold *anything* under `mathaniyy.*`?" Its uses and its deliberate limits are specified in §13.1.

### 8.3 Revokes and precedence

Revokes are personal-only: a revoke row is `(user, pattern, scope)` and only individual users may hold them. Revokes are homed like grants: global-scope revokes at the org root, instance-scoped revokes in the owning Application. Effective access is:

```
union( user's own roles + grants,
       every subject-closure member's roles + grants )
  minus  the user's personal revokes
```

Precedence is a single rule, **negative-always-wins, scope-inclusive**: a revoke at any scope suppresses matching access at that scope *and every descendant scope*, regardless of where in either graph the positive grant sits — including a direct grant on a deeper object. The alternative (most-specific-scope-wins, where a direct document grant overrides a folder-level revoke) is coherent but rejected: "a revoke silently overridden by a grant somewhere deeper" is the class of surprise that becomes a security incident. The rule is not configurable; a product needing exception-style sharing models it with grants at narrower positive scopes, not with overridable negatives.

## 9. Access requests

### 9.1 A request is a proposed grant tuple

An access request is a proposed row: `(requester, role-or-pattern, scope, expiry?)` plus a justification payload and a workflow state. Approval **is** the act of writing the grant row, with provenance linking it to the request; denial writes nothing. The request system therefore adds no new access semantics — it is a workflow that gates row creation, and everything downstream (closures, checks, revokes, expiry, audit) applies unchanged. "Request editor over this folder" and "request admin on this project" are the same object at different scopes. Requests are homed where their proposed row would live: requests for global-scope grants or org-root roles run at the org root; requests for instance-scoped grants run in the owning Application. The request object is part of the provider contract (§2.2), so its shape is identical against either provider and workflows deepen on federation without migration.

### 9.2 Requestability is catalog data

Nothing is requestable by default. A role or scope-type declares itself requestable in the catalog, optionally with the justification prompts a requester must answer (free-text or structured policy-adherence questions). A user may request any requestable role they can *view* — role visibility is itself permission-gated, so visibility is the precondition and no separate request-permission layer exists. An application that declares nothing requestable renders no request UI anywhere; a deployment without approval needs never sees the machinery.

### 9.3 Approval policies

An approval policy attaches to a requestable role or scope-type — and is homed with what it attaches to (org-root policies on org-root roles, application policies on catalog scope-types). Policies resolve by the system's usual nearest-ancestor rule: a policy declared on a namespace or scope-type node governs requests under it unless a nearer node declares its own. A policy is composed of ordered stages, each one of:

**Auto-approval predicates.** A condition on the requester evaluated against their subject closure — membership in a group (explicit or implicit), holding a pattern, belonging to an org. This is the same evaluation machinery as `can()`; no separate rules engine exists. An application owner expressing "auto-approve my team" is declaring a predicate on an implicit group.

**Named approvers.** Approval by a subject holding a designated role — canonically the application owner, expressed as a role on the namespace.

**Management layers.** Approval by the requester's manager, or N transitive layers upward, resolved by walking the reporting edges (§6.4). Routing *evaluation* is edge-walking — ordinary closure-adjacent math available wherever the hierarchy is visible, which under federation includes every Application via the synced org-root read model. Standalone deployments therefore run management-layer stages fully locally against their own tree. A policy referencing management layers where no reporting hierarchy is populated is a configuration error surfaced at policy creation, not silently skipped.

### 9.4 Aggregation

A provider's approver queue serves the requests it homes. Standalone, the Application's queue *is* the organization's approvals inbox — aggregation across one application is the identity function. Under linking, the hosted inbox is that same queue rendered by relay: a UI convenience over the identity function, adding no aggregation semantics. Under federation, the org root hosts the org-wide inbox for org-scoped requests, and the genuinely Service-intrinsic capability is **cross-application aggregation**: one inbox spanning every member Application's local request queues, which definitionally requires the cross-application vantage. Providers advertise supported stages and aggregation through capability discovery (§2.2), and the request components render accordingly.

### 9.5 Time-bound and just-in-time access

A request may carry a proposed expiry, and a policy may impose a maximum duration or require one. An approved time-bound request is simply a grant row with an expiry — just-in-time elevation with automatic lapse, composed entirely from §8.1. The shipped examples pair time-bound elevation with `can.fresh` (§12) for destructive surfaces.

## 10. Graph integrity

Graph-integrity semantics are defined once, at the contract level, and enforced at the site that owns each graph: the Application for object graphs, the org root for group graphs and the reporting tree.

### 10.1 DAG enforcement

Both inheritance graphs — group parentage and (where enabled) object multi-parentage — must be acyclic, sharing one enforcement code path per site. In a union-only system a cycle can express nothing except "these nodes are equivalent": every node in a cycle necessarily converges to identical effective access, so DAG enforcement loses no expressive power, and equivalence has a dedicated construct (§10.3).

Acyclicity is checked **transactionally**. Two concurrent edge insertions can each be individually cycle-free while jointly forming a cycle, so edge writes are serialized per graph via an advisory lock keyed on tenant. These are administrative operations measured in writes per day; serialization is the correct simplicity tradeoff. Reporting edges (§6.4) are a tree under the same transactional enforcement.

### 10.2 Cycle-containing input

Interactive edits that would create a cycle are **hard-rejected**, with the full cycle path named in the error (`A → B → C → A`); a bare "cycle detected" is undebuggable. Bulk imports from external directories (Entra, Okta, LDAP), whose nesting data no provider controls, are **auto-condensed** with a warning: the strongly connected component is collapsed into a virtual parent, which is the semantically correct reading of a directory cycle ("these were always effectively one pool"). Org-root promotion (§2.6) reuses this same import-validation path.

### 10.3 Virtual parents (sync)

When an administrator wants several groups (or several objects) to confer identical access, the construct is a **virtual parent** they all inherit from — the manual condensation of what a cycle would otherwise express. Two semantics are fixed:

**It syncs access, not membership.** A shared parent means the children confer the same permissions; it does not mirror who belongs to them. Membership mirroring (dynamic groups) is a different feature and out of scope.

**Dissolution is a snapshot.** Disabling sync dissolves the parent by copying its grants down to each child, after which the children drift freely — the desired meaning of "let them diverge." The dissolution and the provenance of every copied grant are written to the audit log, so "why do both groups hold `billing.read`?" remains answerable after the parent no longer exists. Org-root demotion (§2.6) is the same snapshot-with-provenance pattern applied to authority itself.

## 11. Listing (reverse queries)

Point checks answer "can A read *this* doc?" cheaply. They do not answer "list every doc A can read," which every listing page needs, and naive per-row checking is an N+1 death. The prescribed pattern:

First compute the user's **granted scope set** — the scopes appearing in unexpired grant rows for any member of the subject closure with a matching pattern. This is cheap: a handful of rows.

Then push the filter into the application's database: *rows whose ancestor set intersects the granted scope set*. That query is only efficient if the resource table supports ancestor lookup in SQL, so the system is prescriptive here: enabling scoped permissions over a hierarchy requires the resource table to carry either a **materialized path** column or a **closure table**, and the Client ships query helpers for both shapes. This prescription — a bit of schema in exchange for solving listing in the application's own database with no synced store — is the system's core tradeoff against Zanzibar-style services, and is stated as such in the documentation.

## 12. Caching and staleness

**Closures are cached; decisions are not.** A decision cache (`can(A, p, s) → true`) has an enormous keyspace and diffuse invalidation. Closure caches are small and locally invalidated: a subject closure busts only when that user's memberships, reporting edges, or an ancestor group's parentage change; an object chain busts only when that object (or an ancestor) moves. Grant and revoke rows are read fresh or on short TTL — single indexed lookups, not the expensive part. Expiry requires no invalidation at all: expired rows are filtered at read time.

The caches live in the **Client**, as evaluation state; **invalidation events are part of the provider contract**. The Application emits them from its own writes and from identity-adapter webhooks; org-root writes at the Service emit them through the upstream sync into the same local stream. Cache policy is thus a Client behavior parameterized by provider events, identical in every topology and whichever home the org root occupies.

The two sides carry **different policies** matching their dynamics. Subject closures (shallow, wide, high-churn) tolerate seconds-to-minutes propagation. Object chains (deep, narrow, near-static) bust immediately on move, because moving a sensitive document into a restricted folder must take effect at once, and a single-chain bust is cheap enough to afford that.

**Staleness is bounded and stated.** Bounded staleness means bounded over-access after a revocation (Zanzibar's "new enemy problem"). The documentation states the bound rather than implying instantaneity, and the API provides `can.fresh(...)`, which bypasses all caches. The shipped examples use `can.fresh` for destructive actions and time-bound elevations — the intended pairing with the standalone destructive leaves of §3.2.

### 12.1 Revalidation and the event log

The live invalidation stream never leaves the writing process, so in a multi-process deployment the TTL was the only cross-process bound — and in a serverless one, where every invocation starts cold, the caches barely applied at all. The remedy is to make the events durable: with **event persistence** on, the Application appends every invalidation event it emits to a sequenced log in the same database before the write returns, and exposes the log on the provider as `epoch` (`head()` / `since(seq)`). One single-row read — constant cost, independent of organization size, grant count, and event volume — answers "did anything change anywhere?".

A client configured with a **revalidation window** passes cached reads through a freshness gate: within the window, a clock comparison; past it, one `head()` read shared by every concurrent check. An unchanged head proves every cached closure still exact, and entry TTLs are **renewed** — this is a conscious amendment to the TTL contract above: with revalidation on, the TTL is no longer the staleness bound but the *fallback* bound, and the operative bound becomes the revalidation window (plus one in-flight request). A changed head is caught up selectively: `since(cursor)` returns only the missed events, replayed through the same busting logic the live stream feeds — identical semantics, different arrival path. A cursor older than the log's retention gets a *gap* and busts everything. Renewal is generation-guarded: an entry whose fetch overlapped a replay may hold state the replay could not bust (it was not yet cached), so it keeps its original TTL rather than being renewed — the one race where renewal would otherwise unbound staleness.

Failure is closed toward the database, never toward the cache: an unreadable epoch renews nothing, entries lapse on their TTLs, and misses pay full provider fetches. Under epoch failure the system degrades to exactly the pre-epoch contract, never below it.

An optional **shared cache tier** (`CacheStore`) extends the same discipline to cold processes: closures — never decisions — are mirrored to an external cache under a versioned envelope stamped with the head the writer had validated. A cold process serves an entry only when the stamp equals the current head (with an epoch) or within the same TTL that bounds the in-process tier (without one); every error or mismatch is a miss. The store sits inside the server trust boundary. For long-lived multi-node deployments that want push-like latency without pub/sub infrastructure, an optional poller tails the log and re-emits foreign events locally; it is sugar over the mechanism, never the mechanism.

## 13. Enforcement and tooling (Client)

### 13.1 Check shapes and enforcement points

There are two check shapes. **`can(subject, key, scope?)`** tests a concrete permission and is the only shape usable as an authorization gate. **`canAny(subject, pattern)`** tests whether effective access intersects a permission-key pattern at all, and is a *visibility affordance only*: it drives whether a project, section, or navigation entry appears ("show the project iff the viewer holds anything under `mathaniyy.*`"; "show the settings icon iff anything under `admin.*`"). `canAny` is never a gate — every page and action still gates on a concrete permission — and the static verifier (§13.2) errors on `canAny` appearing in a server action or route handler. There is no special-cased project-access helper; project-root visibility is `requireAny("project.*")`, the `require*` forms being the throwing variants of both shapes.

Both shapes are **verified against the catalog before they are evaluated**: a key or pattern the catalog does not declare is a programming error, raised as such, never answered. This is the runtime half of the same rule the typed keys and the static verifier enforce at build time, and it exists because both silent alternatives are wrong in the directions that matter — an undeclared key is matched by a covering wildcard, so a misspelled gate would *pass* for exactly the broadly-privileged principals who review and test it; an undeclared pattern matches no catalog key, so a visibility question would answer `false` to a question that was never asked. Enforcement therefore covers the runtime-string paths (navigation tables, configuration, generic wrappers over many keys) that static analysis cannot reach.

Both shapes additionally exist on the **request-scoped snapshot** (`client.snapshot(principal)`): one closure supply, then synchronous evaluation over that single instant — the blessed pattern for server-rendered frameworks, whose render helpers perform many conditional-UI checks and cannot be async. A snapshot is a consistency *upgrade* within a request (one data instant, one clock) and inherits the client's staleness bounds across requests. Scope types declared top-level (`parent: null`) commit to flat instances — chains of `[scope, "*"]` by declaration — which is what keeps scoped checks on them synchronous; hierarchical targets are pre-resolved at snapshot construction, and an unresolved hierarchical target is an error rather than a truncated (fail-open on ancestor revokes) evaluation. The unscoped "holds it anywhere" probes (`holds`, and its many-key form `heldKeys`) are the sanctioned feed for conditional UI under scoped grants — a button may exist because authority exists *somewhere* — and are never gates. Check shapes are named identically on every surface — client, snapshot, session, and session snapshot spell `can` / `require` / `canAny` / `requireAny` / `holds` / `heldKeys` the same way, so the question determines the name regardless of where it is asked.

Every action or surface gates at four points, and is not done until all four hold: the **page** (`require(key)`, with project roots additionally guarded by `requireAny` for visibility, each page still gating its own read); **navigation visibility** (the nav item's `permission` field in the catalog — a concrete key, an any-of array, or a pattern evaluated via `canAny`); the **server action or route handler** (`gateAction(key)` / `apiRequirePermission(key)`, with bundled actions touching several surfaces gating each field path on its own permission); and **conditional UI** (`can(session, key)` for every button and panel). All accept scoped forms taking a scope instance.

### 13.2 Static verification

The four-point checklist is enforced by tooling, not discipline. The Client ships build-time checks: **typed keys** via template-literal types derived from the catalog, so every key and pattern at every call site is compile-time verified; **coverage linting**, warning on catalog leaves referenced by no gate and erroring on exported server actions containing no gate at all; **gate-shape linting**, erroring on `canAny` used in server actions or route handlers; and **catalog linting**, erroring on keys that deviate from the catalog's declared depth convention, on tabs below the "read + one-permission-per-action" floor, on scope-type violations, on requestable declarations without a resolvable policy, and on missing namespace declarations. The split is deliberate and load-bearing: what is structurally broken fails at boot, what is merely off-convention fails in CI — so a house style is a setting the linter enforces rather than a law the constructor imposes. These checks are what makes the shipped convention document trustworthy for agent use: agents are exactly the users who will skip step three of four, and verification catches what convention alone would not.

### 13.3 View-as

An administrator holding the access-read permission can preview the portal as a **role** (the session's access becomes the role's patterns) or as an **individual** (the session adopts that person's full effective access, plus their user ID and group memberships, so data-scoped surfaces reproduce exactly what they see). The two subjects are mutually exclusive, held in httpOnly cookies, applied at session construction by the Application. The invariant: `can()` and `canAny()` always additionally check the viewer's **real** access, so a preview can only ever narrow what is shown and can never escalate privileges. The one-snapshot-per-request pattern survives view-as: a session snapshot fetches once per identity, then answers every check shape synchronously as the actor ∩ preview intersection.

### 13.4 Headless administration components

The Client ships a headless component kit rendering from the catalog and speaking only the provider contract: the wildcard-aware permission tree (whole-group selection stores the `<group>.*` pattern), the role editor, grant and revoke pickers, group membership editors, the request-and-approve surfaces (request form with justification prompts, approver queue), and the view-as switcher. The kit is complete by design — every workflow the hosted dashboard exposes is buildable from it — and the Client additionally ships only a minimal, unstyled reference assembly: enough to administer a deployment end-to-end and to prove the kit composes, and nothing more. The hosted dashboard (§2.4) is the Service's assembled, styled, and maintained product, built from the identical components speaking the identical contract, attached directly to the Service — which serves federated data authoritatively and linked Applications by delegation (§2.7). The dashboard is therefore replaceable by construction: what is sold is assembly, polish, hosting, and seats, never a workflow the kit withholds. Components respect capability discovery, so surfaces for capabilities a provider lacks simply do not render — including org-domain editors rendering read-only against a provider that is not the org root.

## 14. Enforcement modes

The system has two enforcement modes with explicitly different guarantees.

**Gate-at-runtime**: the application calls `can()` on its own request path. Enforcement happens at check time, with the bounded cache staleness of §12. This is the mode for everything the application itself serves, in every topology.

**Provision-and-reconcile** (Service, federation tier): for external systems that will never call `can()` — the canonical example being internal gating of a third-party product like Zoom. An integration adapter publishes that product's contract as a versioned namespace catalog (`zoom.*` for a given Zoom API version); a reconciler agent continuously converges the external system's actual state (licenses, host rights, room access) toward what the grant store says, and flags **drift** where state was changed directly in the external system's own admin panel. A grant row is a grant row in both modes — a gate reads it or a reconciler enacts it — and access requests target provisioned roles identically (an approved `zoom.host` request writes the same row a reconciler then enacts). But the guarantee differs and is stated: gated permissions are enforced at check time within the staleness bound; provisioned permissions are enforced at reconcile cadence with drift detection. A contract version bump is a first-class migration event: the adapter publishes v2 types, tombstones v1, and the drift report surfaces every role still referencing v1 keys.

Provision-and-reconcile is Service-homed not by the org-root logic but by infrastructure: reconcilers are long-running agents holding standing credentials to external systems, which an embedded Application is not positioned to operate. Conceptually the *gated resource* (the org's Zoom seats) is organizational; a single-application org wanting it federates at minimum size (§2.7) rather than the Application absorbing reconciler machinery.

## 15. Identity provider adapter

The identity adapter has two halves, split by the org-root logic. **Session verification** — verifying tokens, constructing sessions — is runtime, per-application machinery and always attaches to the Application. **Directory ingestion** — syncing organizations, group mappings, and reporting edges from the identity provider or directory, and emitting the corresponding invalidation events — populates organizational-domain data and therefore attaches to the **org root**: the standalone Application ingests directly; under federation the Service ingests, and Applications receive the results through the synced read model. This removes any ambiguity about dual consumers: one directory, one ingesting home, everyone else reads the model.

The reference adapter targets Clerk; the interface is provider-agnostic. The system does not duplicate identity-provider features — organizations, invitations, session management — and deliberately exceeds them where they are coarse: unlimited roles, arbitrary grouping, nested groups, scoped grants, resource-level checks, and access requests are all system-side, keyed to provider identities.

## 16. Layer assignment

The governing rule: **Client if it is a pure function over provided data; Application if one database satisfies it; Service if it requires central infrastructure or cross-application vantage; Org root — Application when standalone, Service when federated — for organizational-domain data, which must have exactly one writer.**

| Capability | Home | Why |
| --- | --- | --- |
| Grammar, wildcards, pattern matching | Client | Pure functions |
| Catalog definition, typed keys, derived types | Client | Build-time, data-free |
| Closure evaluation, effective-access algebra | Client | Pure math over supplied closures |
| Check shapes (`can`, `canAny`, `can.fresh`), enforcement points | Client | Evaluation over provider data |
| Closure caches | Client | Evaluation state, parameterized by provider events |
| Static verification (coverage, gate-shape, catalog lints) | Client | Compile-time, per-codebase |
| Headless admin components | Client | Render a catalog, speak only the contract |
| Implicit-group and routing *semantics* | Client (contract-defined) | Evaluation is closure/edge math wherever data is visible |
| Ancestry-resolver interface, listing query helpers | Client (interface) / app-supplied (implementation) | Hierarchy is the app's own data |
| Instance-scoped grants, revokes, and requests; provenance; expiry filtering | Application | Resource-shaped rows in the local database |
| Object-graph integrity (multi-parent DAGs) | Application | Local graph writes |
| Application-scoped request workflows and approver queue | Application | One app's rows and subjects suffice |
| Sessions, view-as, identity-adapter session verification | Application | Runtime session state |
| Service-scope *enforcement*, local key shim | Application | Gate side is local; env-var shim serves standalone deployments |
| Reporting hierarchy and implicit-group population | Org root | Organizational data; single writer |
| User groups: definitions, membership, parentage, group virtual parents | Org root | Cohorts are org facts, not app facts |
| Role definitions | Org root | Org vocabulary of access bundles |
| Global-scope grants and revokes | Org root | Org-person-to-pattern assignments |
| Org-root approval policies; org-scoped request workflows; org approvals inbox | Org root | Attach to org-root entities |
| Directory ingestion (orgs, group sync, reporting edges) | Org root | Populates org-domain data; one ingesting home |
| Org-domain audit log | Org root | Records the single writer's writes |
| Catalog registry, namespace ownership, versioning, tombstones, portability | Service | Cross-application by definition |
| Cross-namespace role composition | Service | Requires the registry's cross-app catalog view |
| Cross-application request aggregation (federated inbox spanning member apps) | Service | Definitionally cross-application |
| Provision-and-reconcile integrations, drift reports | Service | Standing external credentials + long-running agents (infrastructure, not org-root data) |
| Service-principal credential minting, issuance, rotation | Service | Credential infrastructure is centralized |
| Cross-application audit aggregation | Service | Aggregates member Applications' local events |
| Hosted dashboard: assembly, styling, hosting, admin-seat management | Service (hosted tier) | Convenience over the headless kit; replaceable by construction |
| Relay for data-plane-less consumers against linked Applications | Service (hosted tier) | Brokering infrastructure; forwards, never writes |
| Hosted audit retention and export | Service (hosted tier) | Durable retention infrastructure; append-only convenience over the local log |
| Check observation stream, sampling, aggregation | Client | Pure functions over the checks it already evaluates |
| Revocation-safeguard math (`soleMatch`, warning copy) | Client | Pure function over supplied usage |
| Metric storage, rolling usage buckets, retention | Application | One database satisfies it; the rows are the application's own |
| Metering | Service | Counts only Service-side work; the check path is invisible to it |

The most tempting places to blur lines are split deliberately. The service-principal seam: the Client defines machine scopes, the Application enforces them, the Service mints credentials, and the documented local shim (shared backend key in an environment variable, validated server-side, with a CI guard failing the build if the key module becomes client-reachable) ensures a standalone deployment is never forced onto the Service merely to expose an API. The org-root seam: organizational-domain capabilities are fully present standalone (a lone Application runs management-layer approvals against its own tree), and federation *moves* them rather than unlocking them — what federation genuinely adds is only what appears in the Service rows above. The hosted seam: the dashboard tier withholds no workflow — the headless kit builds the identical surface — so under linking the paid line is assembly and operation, and only under federation is it capability.

## 17. Metering

Pricing is usage-based, and the meterable surface is a technical fact of the architecture rather than a commercial choice. Runtime checks never touch the Service in any topology, so per-check metering is impossible by construction. The guarantee is stated affirmatively: **nothing on the request path of the customer's application is ever counted, priced, or throttled by the Service.**

What the Service can observe — and therefore what it meters — is exactly the work it performs: **admin seats** (authenticated dashboard sessions); **linked and federated applications** (relay and sync endpoints maintained); **provisioned connectors** (reconcilers operated, per integration); and **retained audit volume** (events ingested and stored under hosted retention). Registry and sync operations (catalog publishes, org-root read-model sync) are guardrail dimensions, not headline meters. Every dimension corresponds to standing infrastructure or performed work, so usage tracks value delivered and an idle link accrues nothing.

Meters are customer-legible through the same machinery as everything else: current counts per dimension are provider data readable over the contract, so a self-built admin page can render them exactly as the hosted dashboard does, and hard caps are configurable per dimension so a deployment can bound its spend absolutely. Crossing a cap degrades the metered convenience (the relay, retention ingest, a reconciler's cadence) and never any locally-running capability — an over-cap deployment loses hosted polish, not permissions.

**Permission metrics (§18) are not a metering dimension and are not visible here.** They are the deployment's own counts of its own checks, held in its own database; the Service neither receives them nor bills on them. The two features are named similarly and share nothing: metering counts work the Service performed, metrics count checks the application performed.

## 18. Permission metrics

Two questions have no good answer from access data alone. *Which permissions are actually exercised, and how often?* — the per-action metric a product owner asks before deprecating a surface. And *if I revoke this grant, what breaks?* — the question an administrator asks with the delete button already under the cursor. Both are answerable at the one place that sees every check: the Client, in the application's own process.

### 18.1 The observation stream is the feature

Every evaluated check emits a structured `CheckObservation` to an optional client-configured observer: the shape (`can` / `require` / `canAny` / `requireAny` / `holds` / `heldKeys`), the decision, the permission, the scope, the principal, and the rows that decided it. Invocation is synchronous, guarded, and fire-and-forget — a throwing observer loses its observation and nothing else, and no observer failure, slowness, or outage can affect a decision or add latency to one.

The observer is deliberately the *product*, not an implementation detail. A structured stream lets a deployment pipe permission metrics into the metrics stack it already runs — an OpenTelemetry adapter ships in the Client and is a few dozen lines against the same interface, as any StatsD, Prometheus, or log-line sink would be. This is strictly more capable than hosting the data would be (their dashboards, their alerting, their retention, joined to their application metrics), and it flows in the opposite direction from the Service.

### 18.2 Sampling

The stream carries a sample probability, evaluated with one random draw inside the call before any observation is constructed: an unsampled check costs a comparison and allocates nothing. Gates and visibility traffic sample separately, because they differ by orders of magnitude — a single server render fires hundreds of `canAny` and `holds` checks, while gates correspond one-to-one with user actions and are usually worth keeping in full.

Sampling is a property of *observation only*: it can never change an answer. Every observation carries the rate that kept it, so counts extrapolate honestly, and both the observed and estimated figures are retained rather than one being silently substituted for the other.

### 18.3 Cardinality

Per-observation dimensions split into bounded and unbounded, and the unbounded ones are governed rather than stored:

- **Bounded:** permission key (catalog-sized), decision, check shape (six values), grant / revoke / role row id (row-count-sized), scope type.
- **Unbounded:** principal, scope instance.

Scope instances aggregate to **scope type** by default — parseable from the `type:id` format with no lookup — with raw instance counting opt-in per scope type. Principals go in a bounded map with an overflow flag, giving exact distinct counts up to a cap and an honest "and more" beyond it, plus a bounded recent-principal set per attributed row (the safeguard UI needs "who is using this grant", not exact per-principal totals). Every counter map is capped and reports what it dropped. Counters are monotonic within a flush window and tagged with an instance id and window bounds, so many app servers' batches merge wherever they land.

### 18.4 Attribution, and why the safeguard counts sole matchers

The naive revocation metric overwarns. A check satisfied by two grant rows loses nothing when one is revoked, so "this grant matched 1 200 checks" against a row fully shadowed by a broader one teaches administrators to ignore the warning. The counterfactually correct signal is free at the same place: when exactly one row allowed a check, that row was the **sole matcher**, and revoking it would have flipped the decision. Both counters are kept per row:

- `matched` — participated in an allow (usage in the loose sense);
- `soleMatch` — was the only row allowing (revocation would have denied).

Warnings key on `soleMatch`; `matched` contextualizes ("used often, but always alongside the Editors group grant"). The same machinery, mirrored, serves revokes: a revoke's counter says "this is actively suppressing N checks", and since *deleting a revoke widens access*, that warning points the opposite direction and is the more security-relevant of the two. Role ids ride along on matched grants, so role edits and deletions get the same treatment.

Ancestor implication (§7.5) allows without producing a matched list, so the implying grants are reported explicitly rather than left unattributed — an implied allow is still somebody's grant.

**The heuristic is stated honestly wherever it is rendered.** Usage lags, metrics are sampled and lossy, and absence of recent use never means safe to revoke — break-glass grants are precisely the rarely-used ones. The copy says "frequently load-bearing"; it never says "safe".

### 18.5 Storage and reads

An Application may optionally store what it is sent: rolling counter buckets (daily by default) keyed by grant id, revoke id, role id, permission key, or scope type, bounded by attributed rows × retention ÷ granularity and compacted by deleting buckets past retention. Delivery is a batch upsert of pre-aggregated windows, off the request path and never awaited by it; back-pressure drops batches rather than growing a queue, because the correct failure mode for a counter under load is losing counts, not adding latency. Counters accumulate, so batches from every app server sum into deployment-wide numbers.

Reads are ordinary provider methods (`getGrantUsage`, `getRevokeUsage`, `getRoleUsage`, `getPermissionUsage`, `getScopeTypeUsage`), gated by a `metrics` capability flag exactly like `audit`: a deployment that has not opted in advertises `false`, stores nothing, and renders nothing. Per-permission counts keep gate and visibility traffic separate and never sum them — forty thousand renders and twelve actions are different numbers.

Attribution follows the actor, never the preview: a view-as session records the administrator's own check and explicitly does not attribute the previewed person's grants, on the same rule that governs audit.

### 18.6 What is deliberately not built

Metrics are **local**. The Client hands batches to its own Application and nothing carries them further; under linking, the relay lets a dashboard *read* what the Application stored, in the same direction as every other relayed read. There is no uplink, no central metrics store, and no cross-application metrics dashboard — that would make checks observable to the Service and would require amending §1 and §17, which this specification does not do.

Beyond the permission-shaped readings above, Alfiz does not become an observability vendor: no query language, no alerting, no long-horizon analytical retention, no general-purpose custom counters. The observer interface is the extension point, and it is a better one than any of those would be.

## 19. Non-goals

The system does not maintain a synced external store of resource-shaped authorization data at any layer (instance-scoped grants live in the application's database; only org-root and catalog data federates). It does not support direct Client→Service attachment for resource-owning applications (the Application is always in the path; only data-plane-less consumers attach directly). It does not permit concurrent writers to organizational-domain data (the org root is singular, and moves only by audited promotion or demotion). It does not auto-merge reporting hierarchies (trees are not union-safe; conflicts require human resolution). It does not support negative grants on groups, roles, or objects (personal revokes only). It does not perform membership mirroring between groups (virtual parents sync access only). It does not offer configurable precedence or pluggable semantics (the Client's semantic opinions are fixed). It does not move access data across tenant boundaries under any circumstance — cross-business integration, if it ever occurs, shares contracts only (§5.2). It does not permit the Service to write a linked Application's data (the relay forwards; only the owner applies, under its own enforcement). It does not meter, price, or throttle anything on the application's request path — the Service cannot observe checks, by construction, and permission metrics (§18) do not change that: they stay in the deployment that produced them. It does not host permission metrics centrally, aggregate them across applications, or offer a query language, alerting, or analytical retention over them — the observation stream exists so that the metrics stack a deployment already operates can do all of that better. And it does not perform cross-application *checks*: administration centralizes, enforcement never does. Every runtime check, in every topology, runs in-process against the application's own catalog and database.
