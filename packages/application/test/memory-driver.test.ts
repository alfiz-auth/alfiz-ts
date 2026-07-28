import { describe, it } from "vitest";
import { memoryDriver } from "@alfiz-auth/application";
import {
  driverContractCases,
  eventLogContractCases,
  metricsContractCases,
} from "./driver-suite.js";

describe("memoryDriver passes the storage contract", () => {
  for (const testCase of [
    ...driverContractCases,
    ...eventLogContractCases,
    ...metricsContractCases,
  ]) {
    it(testCase.name, async () => {
      await testCase.run(memoryDriver());
    });
  }
});
