import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

const pkg = (name: string) =>
  fileURLToPath(new URL(`packages/${name}/src/index.ts`, import.meta.url));

export default defineConfig({
  resolve: {
    alias: {
      "@alfiz/core": pkg("core"),
      "@alfiz/application": pkg("application"),
      "@alfiz/hosted": pkg("hosted"),
    },
  },
  test: {
    include: ["packages/*/test/**/*.test.ts"],
    environment: "node",
    // Type-level regression tests: the derived-union family fails SILENTLY
    // (widening to `${string}` keeps everything compiling), so the exact
    // assertions in *.test-d.ts run under tsc on every `vitest run`.
    typecheck: {
      enabled: true,
      checker: "tsc",
      include: ["packages/*/test/**/*.test-d.ts"],
      tsconfig: "./tsconfig.typecheck.json",
    },
  },
});
