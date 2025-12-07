import { describe, it, expect } from "@jest/globals";
import {
  INJECTION_TEST_CASES,
  validateRiskDetection,
} from "./injection-cases.js";
import { detectKnownRisks, ResponseMetadata } from "../types.js";

describe("Prompt Injection Detection", () => {
  INJECTION_TEST_CASES.forEach((testCase) => {
    it(`detects risks for ${testCase.name}`, () => {
      const payload = testCase.payload;
      const metadata: ResponseMetadata = {
        truncated: false,
        totalLength: payload.length,
        startIndex: 0,
        fetchedLength: payload.length,
        contentType: "text/html",
      };

      const risks = detectKnownRisks(payload, metadata);
      const result = validateRiskDetection(testCase, risks);

      expect(result.passed).toBe(true);
    });
  });
});
