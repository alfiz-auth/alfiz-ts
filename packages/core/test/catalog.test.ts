import { describe, expect, expectTypeOf, it } from "vitest";
import type { KeyOf, PatternOf } from "../src/catalog.js";
import type { AlfizClient, ClientOf } from "../src/client.js";
import type { SnapshotOf } from "../src/snapshot.js";
import {
  catalogFromDocument,
  defineCatalog,
  group,
  lintCatalog,
} from "../src/catalog.js";

const fixture = () =>
  defineCatalog({
    namespaces: ["docs", "billing"],
    groups: { docs: { description: "Documents" } },
    permissions: [
      {
        "docs.files.read": {
          description: "See files",
          scopes: ["docs.folder", "docs.doc"],
        },
        "docs.files.read_pii": true,
        "docs.files.update_file": { scopes: ["docs.folder", "docs.doc"] },
        "docs.files.delete": { scopes: ["docs.folder"] },
      },
      {
        "docs.folders.read": true,
        "docs.folders.create_folder": { scopes: ["docs.folder"] },
      },
      {
        "billing.invoices.read": true,
        "billing.invoices.issue_invoice": true,
      },
    ],
    scopeTypes: {
      "docs.folder": { parent: null, description: "A folder" },
      "docs.doc": { parent: "docs.folder" },
    },
    navigation: [
      { label: "Docs", href: "/docs", permission: "docs.*" },
      { label: "Files", href: "/docs/files", permission: ["docs.files.read", "docs.files.read_pii"] },
    ],
  });

describe("defineCatalog", () => {
  it("collects keys from all projects plus alfiz_internal", () => {
    const catalog = fixture();
    expect(catalog.hasKey("docs.files.read")).toBe(true);
    expect(catalog.hasKey("billing.invoices.issue_invoice")).toBe(true);
    expect(catalog.hasKey("alfiz_internal.access.read")).toBe(true);
    expect(catalog.hasKey("alfiz_internal.requests.decide_request")).toBe(true);
    expect(catalog.hasKey("docs.files")).toBe(false);
    expect(catalog.namespaces).toContain("alfiz_internal");
  });

  it("derives read/action kinds and destructive flags", () => {
    const catalog = fixture();
    expect(catalog.leaf("docs.files.read")!.kind).toBe("read");
    expect(catalog.leaf("docs.files.read_pii")!.kind).toBe("read");
    expect(catalog.leaf("docs.files.update_file")!.kind).toBe("action");
    expect(catalog.leaf("docs.files.delete")!.destructive).toBe(true);
    expect(catalog.leaf("docs.files.update_file")!.destructive).toBe(false);
  });

  it("group-level scopes are inherited by leaves, nearest declaration wins, leaf overrides", () => {
    const catalog = defineCatalog({
      namespaces: ["lms"],
      includeAlfizInternal: false,
      conventions: { depth: "any" },
      permissions: [
        group("lms.courses", { scopes: ["lms.course"] }, {
          "lms.courses.read": true, // inherits ["lms.course"]
          "lms.courses.publish_course": true, // inherits ["lms.course"]
          "lms.courses.manage_catalog": { scopes: [] }, // explicit []: global-only
          "lms.courses.grade_student": { scopes: ["lms.cohort"] }, // leaf override
          "lms.courses.sessions.read": true, // deeper: inherits from `lms.courses`
        }),
        // A nearer declaration wins, even in its own block.
        group("lms.courses.cohorts", { scopes: ["lms.cohort"] }, {
          "lms.courses.cohorts.read": true,
        }),
        { "lms.reports.read": true }, // no declaration anywhere: global-only
      ],
      scopeTypes: {
        "lms.course": { parent: null },
        "lms.cohort": { parent: null },
      },
    });
    expect(catalog.leaf("lms.courses.read")!.scopes).toEqual(["lms.course"]);
    expect(catalog.leaf("lms.courses.publish_course")!.scopes).toEqual(["lms.course"]);
    expect(catalog.leaf("lms.courses.manage_catalog")!.scopes).toEqual([]);
    expect(catalog.leaf("lms.courses.grade_student")!.scopes).toEqual(["lms.cohort"]);
    expect(catalog.leaf("lms.courses.sessions.read")!.scopes).toEqual(["lms.course"]);
    expect(catalog.leaf("lms.courses.cohorts.read")!.scopes).toEqual(["lms.cohort"]);
    expect(catalog.leaf("lms.reports.read")!.scopes).toEqual([]);
    // Grantability follows the inherited declaration.
    expect(catalog.appliesAt("lms.courses.read", "lms.course:9")).toBe(true);
    expect(catalog.appliesAt("lms.courses.manage_catalog", "lms.course:9")).toBe(false);
  });

  it("a group-declared scope default referencing an undeclared type is an error", () => {
    expect(() =>
      defineCatalog({
        namespaces: ["a"],
        includeAlfizInternal: false,
        permissions: [
          group("a.t", { scopes: ["a.ghost"] }, { "a.t.read": true }),
        ],
      }),
    ).toThrow(/undeclared scope type/);
  });

  it("a bare flat map is a complete catalog — groups are never required", () => {
    const catalog = defineCatalog({
      namespaces: ["todo"],
      includeAlfizInternal: false,
      permissions: {
        "todo.tasks.read": { kind: "read" },
        "todo.tasks.create_task": true,
        "todo.tasks.delete": true,
      },
    });
    expect(catalog.keys).toEqual([
      "todo.tasks.create_task",
      "todo.tasks.delete",
      "todo.tasks.read",
    ]);
    // The group levels exist — inferred from the keys, undeclared and unlabelled.
    expect(catalog.hasGroup("todo")).toBe(true);
    expect(catalog.hasGroup("todo.tasks")).toBe(true);
    expect(catalog.groups.get("todo.tasks")!.label).toBeUndefined();
    expect(catalog.isKnownPattern("todo.tasks.*")).toBe(true);
    expect(catalog.isKnownPattern("todo.*")).toBe(true);
    // ...and are still folders, never keys.
    expect(catalog.hasKey("todo.tasks")).toBe(false);
    expect(lintCatalog(catalog)).toEqual([]);
  });

  it("blocks and bare maps compose in one array — the per-feature-file shape", () => {
    // What each feature file would export.
    const courses = group("lms.courses", { label: "Courses", scopes: ["lms.course"] }, {
      "lms.courses.read": { kind: "read" },
      "lms.courses.publish": true,
    });
    const enrollments = group("lms.enrollments", { label: "Enrollments" }, {
      "lms.enrollments.read": { kind: "read" },
      "lms.enrollments.enroll_student": true,
    });
    const catalog = defineCatalog({
      namespaces: ["lms"],
      includeAlfizInternal: false,
      groups: { lms: { label: "Learning" } },
      permissions: [courses, enrollments, { "lms.reports.read": { kind: "read" } }],
      scopeTypes: { "lms.course": { parent: null } },
    });
    expect(catalog.groups.get("lms.courses")!.label).toBe("Courses");
    expect(catalog.groups.get("lms")!.label).toBe("Learning");
    expect(catalog.leaf("lms.courses.publish")!.scopes).toEqual(["lms.course"]);
    expect(catalog.leaf("lms.reports.read")!.scopes).toEqual([]);
    expect(catalog.groups.get("lms")!.groups).toEqual([
      "lms.courses",
      "lms.enrollments",
      "lms.reports",
    ]);
    expect(lintCatalog(catalog)).toEqual([]);
  });

  it("a single block is accepted without wrapping it in an array", () => {
    const catalog = defineCatalog({
      namespaces: ["a"],
      includeAlfizInternal: false,
      permissions: group("a.t", { "a.t.read": true }),
    });
    expect(catalog.hasKey("a.t.read")).toBe(true);
  });

  it("group children keep declaration order, not alphabetical order", () => {
    const catalog = defineCatalog({
      namespaces: ["a"],
      includeAlfizInternal: false,
      permissions: {
        "a.t.read": true,
        "a.t.zzz_last": true,
        "a.t.approve_thing": true,
      },
    });
    expect(catalog.groups.get("a.t")!.permissions).toEqual([
      "a.t.read",
      "a.t.zzz_last",
      "a.t.approve_thing",
    ]);
  });

  it("rejects a key that is also a group path", () => {
    expect(() =>
      defineCatalog({
        namespaces: ["docs"],
        includeAlfizInternal: false,
        permissions: {
          "docs.files": true, // both a leaf and the parent of the next key
          "docs.files.read": true,
        },
      }),
    ).toThrow(/both a permission and a group path/);
  });

  it("rejects a single-segment key", () => {
    expect(() =>
      defineCatalog({
        namespaces: ["docs"],
        includeAlfizInternal: false,
        permissions: { docs: true },
      }),
    ).toThrow(/at least two segments/);
  });

  it("rejects a block key that is not under the block path", () => {
    expect(() =>
      defineCatalog({
        namespaces: ["lms"],
        includeAlfizInternal: false,
        // The compile-time check is in derived-types.test-d.ts; this is the
        // runtime half, for keys arriving from a non-literal source.
        permissions: [
          group("lms.courses", { "lms.enrollments.read": true } as never),
        ],
      }),
    ).toThrow(/is not under the block path/);
  });

  it("rejects a duplicate key across two blocks", () => {
    expect(() =>
      defineCatalog({
        namespaces: ["lms"],
        includeAlfizInternal: false,
        permissions: [
          group("lms.courses", { "lms.courses.read": true }),
          group("lms.courses", { "lms.courses.read": true }),
        ],
      }),
    ).toThrow(/duplicate permission key/);
  });

  it("requires at least one namespace", () => {
    // Omitting the field entirely is a compile error; an empty list is the
    // type-valid way to get here, and from JS so is omitting it.
    expect(() =>
      defineCatalog({ namespaces: [], permissions: { "a.b.c": true } }),
    ).toThrow(/declare at least one namespace/);
    expect(() =>
      defineCatalog({ permissions: { "a.b.c": true } } as never),
    ).toThrow(/declare at least one namespace/);
  });

  it("rejects keys outside the declared namespaces", () => {
    expect(() =>
      defineCatalog({
        namespaces: ["docs"],
        permissions: { "rogue.t.read": true },
      }),
    ).toThrow(/is not a declared namespace/);
  });

  it("labels ride on leaves and groups and survive the document round-trip", () => {
    const catalog = defineCatalog({
      namespaces: ["docs"],
      includeAlfizInternal: false,
      groups: { docs: { label: "Documents" } },
      permissions: group(
        "docs.files",
        { label: "Files & uploads", description: "Everything under /files" },
        {
          "docs.files.read": true,
          "docs.files.update_file": {
            label: "Edit files",
            description: "Longer help text",
          },
        },
      ),
    });
    expect(catalog.leaf("docs.files.update_file")!.label).toBe("Edit files");
    expect(catalog.leaf("docs.files.update_file")!.description).toBe("Longer help text");
    expect(catalog.leaf("docs.files.read")!.label).toBeUndefined();
    expect(catalog.groups.get("docs.files")!.label).toBe("Files & uploads");
    expect(catalog.groups.get("docs")!.label).toBe("Documents");
    const rebuilt = catalogFromDocument(catalog.toDocument());
    expect(rebuilt.leaf("docs.files.update_file")!.label).toBe("Edit files");
    expect(rebuilt.groups.get("docs.files")!.label).toBe("Files & uploads");
  });

  it("excludes alfiz_internal on request", () => {
    const catalog = defineCatalog({
      namespaces: ["solo"],
      includeAlfizInternal: false,
      permissions: { "solo.things.read": true },
    });
    expect(catalog.hasKey("alfiz_internal.access.read")).toBe(false);
    expect(catalog.namespaces).not.toContain("alfiz_internal");
  });

  it("rejects the reserved namespace", () => {
    expect(() =>
      defineCatalog({
        namespaces: ["alfiz_internal"],
        permissions: {},
      }),
    ).toThrow(/reserved/);
  });

  it("treats key depth as a lint, not a boot error", () => {
    // A two-level integration catalog BUILDS — depth is house style, not
    // structural validity — and the linter is what reports the deviation.
    const zoom = defineCatalog({
      namespaces: ["zoom"],
      includeAlfizInternal: false,
      permissions: { "zoom.host": true },
    });
    expect(zoom.hasKey("zoom.host")).toBe(true);
    expect(lintCatalog(zoom)).toContainEqual(
      expect.objectContaining({
        severity: "error",
        path: "zoom.host",
        message: expect.stringContaining("2 levels deep"),
      }),
    );

    // Declaring the convention silences it.
    const declared = defineCatalog({
      namespaces: ["zoom"],
      includeAlfizInternal: false,
      conventions: { depth: 2 },
      permissions: { "zoom.host": true, "zoom.read": { kind: "read" } },
    });
    expect(
      lintCatalog(declared).filter((i) => i.message.includes("levels deep")),
    ).toEqual([]);

    // As does opting out entirely.
    const anyDepth = defineCatalog({
      namespaces: ["zoom"],
      includeAlfizInternal: false,
      conventions: { depth: "any" },
      permissions: { "zoom.read": { kind: "read" }, "zoom.meetings.rooms.host": true },
    });
    expect(
      lintCatalog(anyDepth).filter((i) => i.message.includes("levels deep")),
    ).toEqual([]);

    expect(anyDepth.conventions).toEqual({ depth: "any" });
  });

  it("rejects undeclared scope types on leaves and parents", () => {
    expect(() =>
      defineCatalog({
        namespaces: ["a"],
        permissions: { "a.t.read": { scopes: ["a.ghost"] }, },
      }),
    ).toThrow(/undeclared scope type/);
    expect(() =>
      defineCatalog({
        namespaces: ["a"],
        permissions: { "a.t.read": true },
        scopeTypes: { "a.thing": { parent: "a.ghost" } },
      }),
    ).toThrow(/not declared/);
  });

  it("keysMatching shows forward-inclusion", () => {
    const catalog = fixture();
    expect(catalog.keysMatching("docs.files.*").sort()).toEqual([
      "docs.files.delete",
      "docs.files.read",
      "docs.files.read_pii",
      "docs.files.update_file",
    ]);
    expect(catalog.keysMatching("docs.files.read")).toEqual(["docs.files.read"]);
  });

  it("isKnownPattern accepts keys, group wildcards, and star", () => {
    const catalog = fixture();
    expect(catalog.isKnownPattern("*")).toBe(true);
    expect(catalog.isKnownPattern("docs.*")).toBe(true);
    expect(catalog.isKnownPattern("docs.files.*")).toBe(true);
    expect(catalog.isKnownPattern("docs.files.read")).toBe(true);
    expect(catalog.isKnownPattern("docs.ghost.*")).toBe(false);
    expect(catalog.isKnownPattern("docs.files.ghost")).toBe(false);
  });

  it("validateGrantableAt enforces scope-type declarations", () => {
    const catalog = fixture();
    expect(catalog.validateGrantableAt("docs.files.read", "*")).toBe(null);
    expect(catalog.validateGrantableAt("docs.files.read", "docs.doc:1")).toBe(null);
    // delete is folder-only
    expect(catalog.validateGrantableAt("docs.files.delete", "docs.doc:1")).not.toBe(null);
    expect(catalog.validateGrantableAt("docs.files.delete", "docs.folder:9")).toBe(null);
    // billing keys declare no scopes: global-only
    expect(
      catalog.validateGrantableAt("billing.invoices.read", "docs.folder:9"),
    ).not.toBe(null);
    // wildcard: grantable where at least one matched leaf is
    expect(catalog.validateGrantableAt("docs.files.*", "docs.doc:1")).toBe(null);
    expect(catalog.validateGrantableAt("billing.*", "docs.doc:1")).not.toBe(null);
    // unknown scope type
    expect(catalog.validateGrantableAt("docs.files.read", "ghost.thing:1")).not.toBe(null);
  });

  it("toDocument is stable and serializable", () => {
    const doc = fixture().toDocument();
    expect(doc.formatVersion).toBe(1);
    expect(doc.namespace).toBe("docs");
    expect(JSON.parse(JSON.stringify(doc))).toEqual(doc);
    const keys = doc.leaves.map((l) => l.key);
    expect(keys).toEqual([...keys].sort());
  });

  it("derives compile-time key and pattern unions", () => {
    const catalog = fixture();
    type Key = KeyOf<typeof catalog>;
    type Pattern = PatternOf<typeof catalog>;
    expectTypeOf<"docs.files.read">().toExtend<Key>();
    expectTypeOf<"billing.invoices.issue_invoice">().toExtend<Key>();
    expectTypeOf<"alfiz_internal.access.view_as">().toExtend<Key>();
    // @ts-expect-error unknown keys are rejected at compile time
    expectTypeOf<"docs.files.ghost">().toExtend<Key>();
    expectTypeOf<"docs.*">().toExtend<Pattern>();
    expectTypeOf<"docs.files.*">().toExtend<Pattern>();
    expectTypeOf<"*">().toExtend<Pattern>();
    // @ts-expect-error unknown group wildcards are rejected
    expectTypeOf<"ghost.*">().toExtend<Pattern>();
  });

  it("ClientOf / SnapshotOf carry the same unions, so context objects need no type parameters", () => {
    const catalog = fixture();
    type Client = ClientOf<typeof catalog>;
    type Snapshot = SnapshotOf<typeof catalog>;
    expectTypeOf<Client>().toExtend<AlfizClient<KeyOf<typeof catalog>, PatternOf<typeof catalog>>>();
    expectTypeOf<Snapshot["can"]>().parameter(0).toExtend<KeyOf<typeof catalog> | readonly KeyOf<typeof catalog>[]>();
    expectTypeOf<Snapshot["canAny"]>().parameter(0).toExtend<PatternOf<typeof catalog>>();
    // The shape an adopter stores on their actor/session object.
    type Actor = { userId: string; alfiz: SnapshotOf<typeof catalog> };
    expectTypeOf<Actor["alfiz"]["heldKeys"]>().toExtend<ReadonlySet<string>>();
  });
});

describe("lintCatalog", () => {
  it("clean fixture has no errors", () => {
    const issues = lintCatalog(fixture()).filter((i) => i.severity === "error");
    expect(issues).toEqual([]);
  });

  it("errors on tabs without a read permission (the floor)", () => {
    const catalog = defineCatalog({
      namespaces: ["a"],
      includeAlfizInternal: false,
      permissions: { "a.t.do_thing": true },
    });
    const errors = lintCatalog(catalog).filter((i) => i.severity === "error");
    expect(errors.some((e) => e.path === "a.t" && /floor/.test(e.message))).toBe(true);
  });

  it("warns on non-verb_noun action names", () => {
    const catalog = defineCatalog({
      namespaces: ["a"],
      includeAlfizInternal: false,
      permissions: { "a.t.read": true, "a.t.frobnicate": true },
    });
    const warnings = lintCatalog(catalog).filter((i) => i.severity === "warning");
    expect(warnings.some((w) => w.path === "a.t.frobnicate")).toBe(true);
  });

  it("errors on nav referencing nothing", () => {
    const catalog = defineCatalog({
      namespaces: ["a"],
      includeAlfizInternal: false,
      permissions: { "a.t.read": true },
      navigation: [{ label: "Ghost", permission: "a.ghost.read" }],
    });
    const errors = lintCatalog(catalog).filter((i) => i.severity === "error");
    expect(errors.some((e) => e.path === "Ghost")).toBe(true);
  });

  it("errors on requestable scope types without stages", () => {
    const catalog = defineCatalog({
      namespaces: ["a"],
      includeAlfizInternal: false,
      permissions: { "a.t.read": true },
      scopeTypes: {
        "a.thing": { requestable: { policy: { stages: [] } } },
      },
    });
    const errors = lintCatalog(catalog).filter((i) => i.severity === "error");
    expect(errors.some((e) => e.path === "a.thing" && /policy/.test(e.message))).toBe(true);
  });
});

describe("groups are inferred from keys", () => {
  it("a `groups` entry naming a path with no keys is reported as empty", () => {
    // Groups come from the keys, so the only way to conjure one with nothing
    // under it is to name it in the metadata map — which is a typo, and lints.
    const catalog = defineCatalog({
      namespaces: ["a"],
      includeAlfizInternal: false,
      groups: { "a.hollow": { label: "Hollow" } },
      permissions: { "a.t.read": true },
    });
    expect(catalog.hasGroup("a.hollow")).toBe(true);
    expect(lintCatalog(catalog)).toContainEqual(
      expect.objectContaining({
        path: "a.hollow",
        message: expect.stringContaining("empty group"),
      }),
    );
  });

  it("every dotted prefix of a key becomes a group, at any depth", () => {
    const catalog = defineCatalog({
      namespaces: ["a"],
      includeAlfizInternal: false,
      conventions: { depth: "any" },
      permissions: { "a.b.c.d.read": true },
    });
    expect([...catalog.groups.keys()]).toEqual(["a", "a.b", "a.b.c", "a.b.c.d"]);
    expect(catalog.groups.get("a.b")!.groups).toEqual(["a.b.c"]);
    expect(catalog.groups.get("a.b.c.d")!.permissions).toEqual(["a.b.c.d.read"]);
  });
});
