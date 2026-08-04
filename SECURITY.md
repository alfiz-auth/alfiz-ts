# Security Policy

Alfiz is an authorization layer; bugs here are security bugs by definition.
Report them privately and we will treat them with that weight.

## Reporting a vulnerability

- **Email:** hello@alfiz.dev, subject line starting with `[SECURITY]`.
- Alternatively, use GitHub's private vulnerability reporting on
  [`alfiz-auth/alfiz-ts`](https://github.com/alfiz-auth/alfiz-ts/security/advisories)
  if it is enabled for your account.

Please include: the affected package and version, a minimal reproduction
(catalog + rows + the check that answers wrongly is the ideal shape), and the
impact as you understand it. Do not open a public issue for anything you
believe is exploitable.

You will receive an acknowledgement within 3 business days. We ask for a
coordinated disclosure window of up to 90 days; fixes ship as a patch release
on the current minor, with the advisory credited to you unless you prefer
otherwise.

## Scope

- `@alfiz/core`, `@alfiz/application`, `@alfiz/prisma`, `@alfiz/verify` —
  in scope. Wrong-answer bugs (a check that allows what the rows deny, a
  revoke that fails to suppress, a cache serving past its stated bound), the
  provider API's authentication, and `alfiz-verify` false-negatives on its
  documented rules are all valid reports.
- The documented staleness bounds themselves are not vulnerabilities: a
  revocation observed within the configured propagation bound is behavior
  the caching page states. Reports that a bound is *violated* are in scope.
- Alfiz Cloud (the hosted service) has its own reporting route at
  hello@alfiz.dev; reports sent here will be forwarded.

## Supported versions

Pre-1.0, only the latest published minor receives security fixes. From 1.0,
the previous major will receive security fixes for 12 months after its
successor ships — the support-window commitment lives in the changelog.
