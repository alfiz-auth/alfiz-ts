# @alfiz-auth/verify

Static verification: the four-point wiring checklist enforced by tooling,
not discipline. Typed keys catch typos the compiler can see; this catches
the rest:

- **unknown-pattern** — a string at a `can`/`require*`/`gateAction` call
  site that is not a catalog key or known group wildcard. (The same rule
  runs at runtime in `@alfiz-auth/core` for the string paths static
  analysis cannot see; this is the build-time half.)
- **visibility-as-gate** — `canAny`/`requireAny` inside a `"use server"`
  file or route handler. Visibility affordances are never gates.
- **ungated-action** — an exported async function in a `"use server"` file
  containing no gate call at all.
- **unreferenced-leaf** — a catalog leaf no gate or nav item references
  (dead permission, or missing enforcement).
- **catalog** — `lintCatalog` violations: the naming floor, nav wiring,
  requestability without a policy.
- **client-reachable-secret** — a forbidden identifier (service-key env
  vars) appearing in a `"use client"` module.

## Describe YOUR project, not a hypothetical one

Real projects gate through their own wrappers — the conventions encourage
it (`gateAction` is itself one). Declare them, or every wrapped action
reads as ungated and the noise buries the real findings:

- `gateNames` / `visibilityNames` — your wrapper function names. In the CLI
  config these are **added** to the built-in defaults; on `verifyProject`
  they **replace** them (spread `DEFAULT_GATE_NAMES` /
  `DEFAULT_VISIBILITY_NAMES` to extend).
- `serverFilePatterns` — extra paths treated as server enforcement points
  (RegExp sources in the CLI config, added to the defaults).
- Out-of-domain surfaces — files that authenticate outside the catalog *by
  design* (system trust domains that must survive a database outage) opt
  out in-file, with a reason, and are listed in the report's
  `skippedFiles`:

  ```ts
  "use server";
  // alfiz-verify-ignore-file system trust domain: authenticates by deploy key
  ```

  The pragma belongs in the file header: the leading comments, above or
  below a `"use server"` / `"use client"` directive — JavaScript permits
  comments before and between directive-prologue statements, and so does
  this. A pragma without a reason still skips, but warns; a pragma past the
  first statement is inert and is *reported* as inert, because a security
  tool that silently drops its own escape hatch teaches you the escape
  hatch doesn't work.

## Usage

Programmatic (recommended — no JSON step):

```ts
import { DEFAULT_GATE_NAMES, verifyProject } from "@alfiz-auth/verify";
import { catalog } from "./src/alfiz.js";

const report = verifyProject({
  catalog,
  files: myGlob("src/**/*.{ts,tsx}"),
  gateNames: [...DEFAULT_GATE_NAMES, "assertTeaches", "gateDestructiveAction"],
  forbidClientIdentifiers: ["ALFIZ_SERVICE_KEYS"],
});
process.exitCode = report.errorCount > 0 ? 1 : 0;
```

CLI: export the catalog document once (`catalog.toDocument()` → JSON), then

```
alfiz-verify --config alfiz-verify.config.json
```

```jsonc
{
  "catalog": "alfiz-catalog.json",
  "include": ["src", "app"],
  "gateNames": ["assertTeaches", "gateDestructiveAction"],
  "serverFilePatterns": ["app/actions/"],
  "forbidClientIdentifiers": ["ALFIZ_SERVICE_KEYS"]
}
```
