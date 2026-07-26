# @alfiz-auth/verify

Static verification: the four-point wiring checklist enforced by tooling,
not discipline. Typed keys catch typos the compiler can see; this catches
the rest:

- **unknown-pattern** — a string at a `can`/`require*`/`gateAction` call
  site that is not a catalog key or known group wildcard.
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

## Usage

Programmatic (recommended — no JSON step):

```ts
import { verifyProject } from "@alfiz-auth/verify";
import { catalog } from "./src/alfiz.js";

const report = verifyProject({
  catalog,
  files: myGlob("src/**/*.{ts,tsx}"),
  forbidClientIdentifiers: ["ALFIZ_SERVICE_KEYS"],
});
process.exitCode = report.errorCount > 0 ? 1 : 0;
```

CLI: export the catalog document once (`catalog.toDocument()` → JSON), then

```
alfiz-verify --config alfiz-verify.config.json
```

with `{ "catalog": "alfiz-catalog.json", "include": ["src", "app"] }`.
