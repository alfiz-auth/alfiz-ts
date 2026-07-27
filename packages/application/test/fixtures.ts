import { defineCatalog, group } from "@alfiz-auth/core";
import type { AncestryResolver } from "@alfiz-auth/core";
import { parentPointerResolver } from "@alfiz-auth/core";
import { createApplication, memoryDriver } from "@alfiz-auth/application";
import type { ApplicationOptions } from "@alfiz-auth/application";

export const testCatalog = () =>
  defineCatalog({
    namespaces: ["docs"],
    permissions: [
      group("docs.files", { scopes: ["docs.folder", "docs.doc"] }, {
        "docs.files.read": true,
        "docs.files.update_file": true,
        "docs.files.delete": { scopes: ["docs.folder"] },
      }),
      {
        "docs.admin.read": true,
        "docs.admin.manage_settings": true,
      },
    ],
    scopeTypes: {
      // Folders nest in folders (see testParents): self-referencing parent.
      "docs.folder": {
        parent: "docs.folder",
        requestable: {
          prompts: [{ id: "why", label: "Why do you need this?" }],
          maxDurationMs: 7 * 24 * 3600_000,
          policy: { stages: [{ kind: "named_approvers", roleId: "" }] },
        },
      },
      "docs.doc": { parent: "docs.folder" },
    },
  });

export const testParents = new Map<string, string | null>([
  ["docs.doc:1", "docs.folder:9"],
  ["docs.doc:2", "docs.folder:9"],
  ["docs.folder:9", "docs.folder:2"],
  ["docs.folder:2", null],
  ["docs.folder:77", null],
]);

export const testAncestry: AncestryResolver = parentPointerResolver(
  (scope) => testParents.get(scope) ?? null,
);

export function makeApp(overrides: Partial<ApplicationOptions> = {}) {
  const storage = memoryDriver();
  let tick = 1_000_000;
  const app = createApplication({
    catalog: testCatalog(),
    storage,
    ancestry: testAncestry,
    clock: () => tick,
    ...overrides,
  });
  return {
    app,
    storage,
    advance: (ms: number) => {
      tick += ms;
    },
    now: () => tick,
  };
}

export const admin = { kind: "admin", actorUserId: "root" } as const;
