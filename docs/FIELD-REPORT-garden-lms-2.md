# Field report 2 — Garden LMS on Alfiz 0.2.0

The first report ([FIELD-REPORT-garden-lms.md](FIELD-REPORT-garden-lms.md))
came out of replacing Garden's hand-rolled RBAC with Alfiz 0.1.2. This one
comes out of upgrading that same codebase to 0.2.0 and adopting the surface
that landed in response.

**Verdict: every accepted item is genuinely fixed, and the fixes are
subtractive.** The upgrade *deleted* 409 lines of Garden and added 257 — net
−152 across the files that touch Alfiz, with no loss of behaviour. That is the
right shape for a library maturing: the adopter's workaround layer shrinks.

| # | 0.1.2 finding | Status | What it bought Garden |
| --- | --- | --- | --- |
| §1 | `can()` async in an SSR app | **Fixed** | `client.snapshot` replaced a hand-assembled `SubjectAccessData` + `toCheckContext` + `effectiveKeys`; actor.ts −66 lines |
| §2 | Prisma driver needs a cast | **Fixed** | `prismaDriver(client)` typechecks against the generated client; cast deleted |
| §3 | Deleted principals strand grants | **Fixed** | `deleteSubject`/`deleteScope` replaced both sweeps and clean up *more* (stored record, implicit-group grants, pending requests) |
| §4 | Missing write APIs | **Fixed** | Caller-supplied ids killed a resolve-by-name cache; `setUserActive` and `updateGroup` removed every `importDirectory` detour — Garden now has none |
| §5 | Verify CLI can't describe a project | **Fixed** | Back on the stock CLI; the 109-line bespoke runner is deleted |
| §6 | `holdsAnywhere`, `LooseKey`, group `scopes`, `label`, bulk grants | **Fixed** | 44 scope annotations → 7; the side `DETAILS` map folded back into the catalog; `as never` gone |
| §7 | Two semantics needing a callout | **Fixed** | `docs/MIGRATING.md` |

Verified end to end: 284 files / 21 ignored / 0 errors from `alfiz-verify`,
clean `tsc --noEmit`, clean `next build`, seed, and four semantic check suites
(scoping, tokens, groups, deletion) all passing.

Notes on individual fixes, then the new friction.

## What the fixes actually felt like

**`client.snapshot` is the right shape.** It is now the whole of Garden's
evaluation state: `const snapshot = await alfiz.snapshot(principal)` on the
actor, and `can`/`canAny`/`holds` are synchronous against it. The documented
framing — *a per-request snapshot is a stronger consistency guarantee than the
TTL cache, not a weaker one* — is the sentence that makes the pattern
adoptable, because it converts what looks like a workaround into the
recommended path.

The `parent: null` → `[scope, "*"]` **commitment** matters as much as the API.
Garden's course scope is flat, so it never has to pre-declare anything, and
that is now a contract rather than an implementation detail I was relying on.

**The Prisma pinning file is the standout.** `prisma-client-shape.ts` — a
compile-only replica of the generated client's types with per-model
assignability assertions — means a future delegate change that would reimpose
the cast fails Alfiz's own build instead of my adopter's. That is a stronger
fix than the type narrowing it protects.

**`deleteSubject` did more than asked.** My `dropAllAccessFor` swept grants
and revokes; Alfiz's also removes the stored user record, implicit-group
(`directs:`/`orgof:`) grants, and cancels pending requests — three cleanups I
had not thought about and would have shipped without. Leaving reporting edges
*pointing at* the deleted user for the host to reassign is the right call, and
worth having documented in the method itself.

## New friction found in 0.2.0

### 1. The ignore pragma must precede `"use server"`, and fails silently

**Severity: medium-high, because it fails silent in a security tool.**

`ignoreFilePragma` scans the leading comment region and stops at "the first
real code line". A `"use server"` / `"use client"` directive is a real code
line, so a pragma placed *after* it is never seen.

Every React Server Components codebase puts that directive on line 1 — it's
what the framework docs show, what formatters preserve, and what every
contributor will write. My first pass put the pragma underneath it in 9 files.
Nothing failed: the files simply stayed unignored, and the only signal was
that the error count didn't drop. In a tool whose job is to catch missing
gates, a silently-ignored exemption is the wrong failure direction — I could
just as easily have concluded the pragma didn't work and given up on it.

Worth noting that JavaScript itself allows comments before a directive
prologue — `// comment` then `"use server";` is legal and Next.js accepts it
(Garden's build passes with all 21 pragmas on line 1). So the language's own
rule is the one to follow.

**Proposal.** Skip a leading directive prologue when scanning: string-literal
expression statements at the top of a file are part of the prologue, not the
end of the comment region. And regardless of that fix, emit a **warning** when
the pragma text appears in a file but outside the region where it counts —
"found `alfiz-verify-ignore-file` at line 3, but it must precede the first
statement" turns a silent no-op into a two-second fix.

### 2. `canAny` on a bare group path silently answers `false`

**Severity: medium — this one bit, and cost a debugging cycle.**

`snapshot.canAny("admin")` is well-typed (a bare group path is a valid
`PermissionPattern`, and `admin` is a declared namespace), evaluates happily,
matches no leaf, and returns `false`. The caller meant `"admin.*"`.

0.2.0 catches this at *call sites with literal arguments* — the verifier's new
`suggestPattern` message is exactly right, and it's what made me change
Garden's three `requireDomainAccess("admin")` sites to `"admin.*"` in the first
place. But a **runtime** string bypasses it entirely. Garden's nav items carry
`domain: "reports.*"` as data; when I refactored `canSeeDomain` from a manual
prefix scan onto `snapshot.canAny`, one caller in a check script still passed
the bare form and the whole `learn` nav section silently vanished. No error, no
warning — a false where the honest answer is "you asked the wrong question".

**Proposal.** Make the runtime agree with the verifier. Either normalize (a
pattern naming a known group becomes its subtree wildcard) or throw with the
same `suggestPattern` message the verifier already produces. Silently
answering `false` to a malformed visibility question is the one option that
neither works nor complains. Given that `canAny` is *only* ever a visibility
affordance, normalizing is defensible; throwing is safer. Either beats the
status quo.

### 3. Provenance is not validated at the write path

**Severity: medium — the error is unactionable.**

A provenance whose `actorUserId` is `undefined` at runtime (a JS caller, a
wrapper whose argument went missing, a `as any` anywhere upstream) passes
through `createRole` / `updateGroup` / every other write and fails inside the
audit writer:

```
PrismaClientValidationError:
Invalid `db.alfizAudit.create()` invocation in
  /node_modules/@alfiz-auth/prisma/dist/driver.js:427:33
    + actor: String
Argument `actor` is missing.
```

Nothing in that message names provenance, Alfiz, or the call the developer
made. It points at a `dist` file inside a dependency and at a Prisma argument
the user never wrote. I hit it from a stale two-argument call to my own
`updateGroup` wrapper after 0.2.0 added the provenance parameter — a
TypeScript error in application code, but the file that called it wasn't in my
`tsconfig` include, so the first signal was this.

The write path already validates patterns, scopes, graph integrity, and role
references, and rejects them with a clean `ProviderWriteRejectedError`.
Provenance is the one required input that isn't checked.

**Proposal.** Validate provenance where every other input is validated:
`ProviderWriteRejectedError("provenance.actorUserId is required for kind
'admin'", "validation")`. `actorOf()` in application.ts is the single
choke point — it already switches on every kind, so it can assert there.

### 4. `listGrants` still has no `roleId` filter on the provider contract

**Severity: low-medium — a scaling papercut, and a leftover from report 1.**

`GrantFilter` in the storage seam has `roleId`, and `deleteRole` uses it
internally to find blocking holders. The provider's `listGrants` still exposes
only `subject` and `scope`.

So "how many people hold this role" — which Garden's `/admin/roles` renders
for every row — has to `listGrants()` with no filter and group in memory. At
Garden's demo scale that's 18 rows. At a real tenant's it's every grant in the
organization, on a page load, to render a count column.

**Proposal.** Add `roleId` to the provider's `listGrants` filter — the storage
layer already supports it, so this is a one-line passthrough. A
`countGrants(filter)` would be better still for the count case, but the filter
alone fixes the scaling.

### 5. No `SnapshotOf<typeof catalog>` alias

**Severity: cosmetic.**

`KeyOf<typeof catalog>` and `PatternOf<typeof catalog>` exist; storing a
snapshot on a request-context object means writing
`AlfizSnapshot<PermissionKey, PermissionPattern>` by hand. Every adopter that
puts a snapshot on their actor/session type writes the two-parameter form.
`SnapshotOf<Cat>` (and `ClientOf<Cat>`, same argument) would round out the
derived-type family.

### 6. Snapshot ergonomics for hierarchical list pages

**Severity: low — not a bug, and the current behaviour is the safe one.**

The throw-rather-than-truncate choice for unresolved hierarchical scopes is
right, and the reasoning (a truncated chain misses ancestor revokes, which
fails *open*) is exactly the right thing to be strict about.

But it does invert the natural order for a hierarchical app: a page listing 50
folders must know all 50 ids *before* it can build the snapshot it wanted to
guard with. Garden never hits this — course scopes are flat — so this is
observation rather than complaint. The blessed pattern is probably: snapshot
for the page guard, query, then a second `snapshot({ scopes })` for the rows,
or `grantedScopes` + the listing helpers instead of per-row checks. Whichever
it is, `docs/MIGRATING.md` and the snapshot docblock are the places to say so;
right now a reader meeting the throw has to work out the shape themselves.

## Still true, still fine

Two things from report 1 that 0.2.0 deliberately did not change, and
shouldn't:

- **Global grants satisfy scoped checks**, so adopting scopes means splitting
  roles. `docs/MIGRATING.md` now leads with this, which is the right
  placement — it is the single fact that decides whether a migration is real
  or a no-op.
- **Learning scope stays application logic.** Garden's "published + actively
  enrolled" test is resource state, not access data, and Alfiz leaving it
  alone remains correct.

## Suggested priority

1. **§1 pragma placement + silent failure** — a security tool that silently
   ignores its own escape hatch is the highest-severity item here, and both
   halves are small fixes.
2. **§2 `canAny` on a bare group path** — it fails weird rather than loud, and
   the fix already exists as `suggestPattern`.
3. **§3 provenance validation** — one assertion in `actorOf`, turns an
   unactionable Prisma error into a normal rejection.
4. **§4 `roleId` filter** — one-line passthrough, removes a full-table scan
   from a common admin page.
5. **§5 / §6** — cosmetic and documentation.
