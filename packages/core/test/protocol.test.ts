/**
 * The wire contract's three artifacts cannot drift: the `AlfizProvider`
 * interface and the operation manifest are held together at compile time
 * (see PROVIDER_OPERATIONS_COVER_CONTRACT in protocol.ts); this suite
 * holds the manifest and the OpenAPI document together at test time. A
 * contract method added without a manifest entry fails the build; a
 * manifest entry added without an OpenAPI path — or an OpenAPI path
 * serving nothing — fails here.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { parse } from "yaml";
import {
  PROVIDER_API_VERSION,
  PROVIDER_OPERATIONS,
  PROVIDER_OPERATIONS_COVER_CONTRACT,
  providerErrorStatus,
  providerOpPath,
  rethrowProviderWireError,
  toProviderWireError,
  GraphCycleError,
  ProviderWriteRejectedError,
} from "@alfiz/core";

const openapiPath = fileURLToPath(
  new URL("../openapi/alfiz-provider.v1.yaml", import.meta.url),
);

interface OpenApiDocument {
  openapi: string;
  info: { version: string };
  paths: Record<string, { post?: { operationId?: string; responses?: Record<string, unknown> } }>;
  components: { schemas: Record<string, unknown> };
}

const doc = parse(readFileSync(openapiPath, "utf8")) as OpenApiDocument;

describe("the operation manifest", () => {
  it("covers the contract (compile-time assertion holds)", () => {
    expect(PROVIDER_OPERATIONS_COVER_CONTRACT).toBe(true);
  });

  it("names every operation exactly once", () => {
    const ops = PROVIDER_OPERATIONS.map((o) => o.op);
    expect(new Set(ops).size).toBe(ops.length);
  });
});

describe("the OpenAPI document", () => {
  it("is OpenAPI 3.1 and its major version is the Provider API version", () => {
    expect(doc.openapi).toBe("3.1.0");
    expect(doc.info.version.split(".")[0]).toBe(String(PROVIDER_API_VERSION));
  });

  it("serves exactly the manifest's operations, one POST path each", () => {
    const expected = PROVIDER_OPERATIONS.map((o) => providerOpPath(o.op)).sort();
    expect(Object.keys(doc.paths).sort()).toEqual(expected);
    for (const [path, item] of Object.entries(doc.paths)) {
      expect(item.post, `${path} must define post`).toBeDefined();
      expect(Object.keys(item)).toEqual(["post"]);
    }
  });

  it("gives every operation a unique operationId, a 200, and a default error", () => {
    const ids = new Set<string>();
    for (const [path, item] of Object.entries(doc.paths)) {
      const post = item.post!;
      expect(post.operationId, `${path} needs an operationId`).toBeTruthy();
      expect(ids.has(post.operationId!), `duplicate operationId ${post.operationId}`).toBe(false);
      ids.add(post.operationId!);
      expect(post.responses?.["200"], `${path} needs a 200 response`).toBeDefined();
      expect(post.responses?.["default"], `${path} needs the default error response`).toBeDefined();
    }
  });

  it("every $ref resolves to a defined component", () => {
    const refs = new Set<string>();
    const walk = (node: unknown): void => {
      if (Array.isArray(node)) {
        for (const item of node) walk(item);
        return;
      }
      if (node !== null && typeof node === "object") {
        for (const [key, value] of Object.entries(node)) {
          if (key === "$ref" && typeof value === "string") refs.add(value);
          else walk(value);
        }
      }
    };
    walk(doc);
    expect(refs.size).toBeGreaterThan(0);
    const resolve = (ref: string): unknown => {
      expect(ref.startsWith("#/"), `external ref ${ref}`).toBe(true);
      let node: unknown = doc;
      for (const segment of ref.slice(2).split("/")) {
        expect(
          node !== null && typeof node === "object" && segment in (node as object),
          `unresolvable $ref ${ref} (at ${segment})`,
        ).toBe(true);
        node = (node as Record<string, unknown>)[segment];
      }
      return node;
    };
    for (const ref of refs) resolve(ref);
  });

  it("declares no orphan schemas — every component is reachable from a path", () => {
    const serialized = JSON.stringify(doc.paths) + JSON.stringify(doc.components);
    for (const name of Object.keys(doc.components.schemas)) {
      expect(
        serialized.includes(`#/components/schemas/${name}`),
        `schema ${name} is referenced nowhere`,
      ).toBe(true);
    }
  });
});

describe("the wire error mapping", () => {
  it("serializes and re-throws ProviderWriteRejectedError with its code", () => {
    const wire = toProviderWireError(
      new ProviderWriteRejectedError("nope", "not_org_root"),
    );
    expect(wire).toEqual({
      name: "ProviderWriteRejectedError",
      message: "nope",
      code: "not_org_root",
    });
    expect(providerErrorStatus(wire)).toBe(403);
    expect(() => rethrowProviderWireError(wire)).toThrowError(
      ProviderWriteRejectedError,
    );
  });

  it("serializes and re-throws GraphCycleError with its path", () => {
    const wire = toProviderWireError(new GraphCycleError(["a", "b", "a"]));
    expect(wire.name).toBe("GraphCycleError");
    expect(wire.detail).toEqual({ path: ["a", "b", "a"] });
    expect(providerErrorStatus(wire)).toBe(409);
    try {
      rethrowProviderWireError(wire);
      expect.unreachable();
    } catch (error) {
      expect(error).toBeInstanceOf(GraphCycleError);
      expect((error as GraphCycleError).path).toEqual(["a", "b", "a"]);
    }
  });

  it("maps every rejection code to its transport status", () => {
    const status = (code: string) =>
      providerErrorStatus({ name: "ProviderWriteRejectedError", message: "", code });
    expect(status("validation")).toBe(422);
    expect(status("not_found")).toBe(404);
    expect(status("conflict")).toBe(409);
    expect(status("graph_cycle")).toBe(409);
    expect(status("not_org_root")).toBe(403);
    expect(status("unsupported")).toBe(501);
    expect(providerErrorStatus({ name: "Error", message: "boom" })).toBe(500);
  });
});
