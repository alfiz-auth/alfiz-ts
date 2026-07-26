import { describe, it } from "vitest";
import { memoryDriver } from "@alfiz-auth/application";
import { driverContractCases } from "./driver-suite.js";

describe("memoryDriver passes the storage contract", () => {
  for (const testCase of driverContractCases) {
    it(testCase.name, async () => {
      await testCase.run(memoryDriver());
    });
  }
});
