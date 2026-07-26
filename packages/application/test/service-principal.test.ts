import { describe, expect, it } from "vitest";
import {
  createServiceKeyShim,
  parseServiceKeysEnv,
} from "@alfiz-auth/application";

const KEY = "a-sufficiently-long-backend-key";
const OLD = "the-previous-rotation-era-key!!";

describe("createServiceKeyShim", () => {
  const shim = createServiceKeyShim([{ serviceId: "backend", keys: [KEY, OLD] }]);

  it("verifies Bearer headers and bare keys", () => {
    expect(shim.verify(`Bearer ${KEY}`)).toMatchObject({
      ok: true,
      serviceId: "backend",
      principal: { serviceId: "backend" },
    });
    expect(shim.verify(KEY)).toMatchObject({ ok: true });
  });

  it("accepts the previous key during rotation", () => {
    expect(shim.verify(`Bearer ${OLD}`)).toMatchObject({ ok: true });
  });

  it("rejects wrong, empty, and absent keys without detail", () => {
    expect(shim.verify(`Bearer wrong-key-wrong-key-wrong-key`)).toEqual({ ok: false });
    expect(shim.verify("")).toEqual({ ok: false });
    expect(shim.verify(null)).toEqual({ ok: false });
    expect(shim.verify(undefined)).toEqual({ ok: false });
    expect(shim.verify(`Bearer ${KEY} `)).toEqual({ ok: false });
  });

  it("distinguishes services by key", () => {
    const multi = createServiceKeyShim([
      { serviceId: "backend", keys: [KEY] },
      { serviceId: "cron", keys: ["another-32-char-key-for-cron!!!!"] },
    ]);
    expect(multi.verify("another-32-char-key-for-cron!!!!")).toMatchObject({
      serviceId: "cron",
    });
  });

  it("refuses weak keys at construction", () => {
    expect(() => createServiceKeyShim([{ serviceId: "x", keys: ["short"] }])).toThrow(/16/);
    expect(() => createServiceKeyShim([{ serviceId: "x", keys: [] }])).toThrow(/16/);
  });
});

describe("parseServiceKeysEnv", () => {
  it("parses the conventional env shape with rotation lists", () => {
    expect(
      parseServiceKeysEnv(`backend:${KEY},${OLD};cron:another-32-char-key-for-cron!!!!`),
    ).toEqual([
      { serviceId: "backend", keys: [KEY, OLD] },
      { serviceId: "cron", keys: ["another-32-char-key-for-cron!!!!"] },
    ]);
    expect(parseServiceKeysEnv(undefined)).toEqual([]);
    expect(parseServiceKeysEnv("")).toEqual([]);
    expect(() => parseServiceKeysEnv("no-colon")).toThrow();
  });
});
