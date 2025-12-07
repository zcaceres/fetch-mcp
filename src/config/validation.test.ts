// src/config/validation.test.ts
// Tests for configuration validation

describe("Configuration Validation", () => {
  const originalEnv = process.env;

  beforeEach(() => {
    jest.resetModules();
    process.env = { ...originalEnv };
  });

  afterAll(() => {
    process.env = originalEnv;
  });

  describe("Default Configuration", () => {
    it("should return no errors for valid configuration", () => {
      // Default values are valid
      const { validateConfiguration } = require("./validation");
      const errors = validateConfiguration();
      expect(errors).toHaveLength(0);
    });
  });

  describe("REQUEST_TIMEOUT Validation", () => {
    it("should detect invalid REQUEST_TIMEOUT", () => {
      process.env.REQUEST_TIMEOUT = "invalid";
      jest.resetModules();
      const { validateConfiguration } = require("./validation");
      const errors = validateConfiguration();
      expect(errors.some((e: any) => e.variable === "REQUEST_TIMEOUT")).toBe(
        true,
      );
    });

    it("should detect zero REQUEST_TIMEOUT", () => {
      process.env.REQUEST_TIMEOUT = "0";
      jest.resetModules();
      const { validateConfiguration } = require("./validation");
      const errors = validateConfiguration();
      expect(errors.some((e: any) => e.variable === "REQUEST_TIMEOUT")).toBe(
        true,
      );
    });

    it("should accept positive REQUEST_TIMEOUT", () => {
      process.env.REQUEST_TIMEOUT = "5000";
      jest.resetModules();
      const { validateConfiguration } = require("./validation");
      const errors = validateConfiguration();
      expect(errors.some((e: any) => e.variable === "REQUEST_TIMEOUT")).toBe(
        false,
      );
    });
  });

  describe("MAX_REDIRECTS Validation", () => {
    it("should detect negative MAX_REDIRECTS", () => {
      process.env.MAX_REDIRECTS = "-5";
      jest.resetModules();
      const { validateConfiguration } = require("./validation");
      const errors = validateConfiguration();
      expect(errors.some((e: any) => e.variable === "MAX_REDIRECTS")).toBe(
        true,
      );
    });

    it("should accept zero MAX_REDIRECTS", () => {
      process.env.MAX_REDIRECTS = "0";
      jest.resetModules();
      const { validateConfiguration } = require("./validation");
      const errors = validateConfiguration();
      expect(errors.some((e: any) => e.variable === "MAX_REDIRECTS")).toBe(
        false,
      );
    });
  });

  describe("DEFAULT_LIMIT Validation", () => {
    it("should detect negative DEFAULT_LIMIT", () => {
      process.env.DEFAULT_LIMIT = "-100";
      jest.resetModules();
      const { validateConfiguration } = require("./validation");
      const errors = validateConfiguration();
      expect(errors.some((e: any) => e.variable === "DEFAULT_LIMIT")).toBe(
        true,
      );
    });

    it("should allow zero DEFAULT_LIMIT (unlimited)", () => {
      process.env.DEFAULT_LIMIT = "0";
      jest.resetModules();
      const { validateConfiguration } = require("./validation");
      const errors = validateConfiguration();
      expect(errors.some((e: any) => e.variable === "DEFAULT_LIMIT")).toBe(
        false,
      );
    });
  });

  describe("Cache Configuration", () => {
    it("should detect invalid CACHE_TTL when cache is enabled", () => {
      process.env.ENABLE_CACHE = "true";
      process.env.CACHE_TTL = "invalid";
      jest.resetModules();
      const { validateConfiguration } = require("./validation");
      const errors = validateConfiguration();
      expect(errors.some((e: any) => e.variable === "CACHE_TTL")).toBe(true);
    });

    it("should warn about long CACHE_TTL", () => {
      process.env.ENABLE_CACHE = "true";
      process.env.CACHE_TTL = "7200000"; // 2 hours
      jest.resetModules();
      const { validateConfiguration } = require("./validation");
      const results = validateConfiguration();
      const warning = results.find(
        (e: any) => e.variable === "CACHE_TTL" && e.severity === "warning",
      );
      expect(warning).toBeDefined();
      expect(warning?.message).toContain("cache poisoning");
    });

    it("should not validate CACHE_TTL when cache is disabled", () => {
      process.env.ENABLE_CACHE = "false";
      process.env.CACHE_TTL = "invalid";
      jest.resetModules();
      const { validateConfiguration } = require("./validation");
      const errors = validateConfiguration();
      expect(errors.some((e: any) => e.variable === "CACHE_TTL")).toBe(false);
    });
  });

  describe("Rate Limiting Configuration", () => {
    it("should detect negative MAX_REQUESTS_PER_MINUTE", () => {
      process.env.MAX_REQUESTS_PER_MINUTE = "-10";
      jest.resetModules();
      const { validateConfiguration } = require("./validation");
      const errors = validateConfiguration();
      expect(
        errors.some((e: any) => e.variable === "MAX_REQUESTS_PER_MINUTE"),
      ).toBe(true);
    });

    it("should allow zero MAX_REQUESTS_PER_MINUTE (disabled)", () => {
      process.env.MAX_REQUESTS_PER_MINUTE = "0";
      jest.resetModules();
      const { validateConfiguration } = require("./validation");
      const errors = validateConfiguration();
      expect(
        errors.some((e: any) => e.variable === "MAX_REQUESTS_PER_MINUTE"),
      ).toBe(false);
    });
  });

  describe("Worker Configuration", () => {
    it("should detect invalid HTML_WORKER_TIMEOUT", () => {
      process.env.HTML_WORKER_TIMEOUT = "invalid";
      jest.resetModules();
      const { validateConfiguration } = require("./validation");
      const errors = validateConfiguration();
      expect(
        errors.some((e: any) => e.variable === "HTML_WORKER_TIMEOUT"),
      ).toBe(true);
    });

    it("should detect invalid HTML_WORKER_MAX_MB", () => {
      process.env.HTML_WORKER_MAX_MB = "0";
      jest.resetModules();
      const { validateConfiguration } = require("./validation");
      const errors = validateConfiguration();
      expect(errors.some((e: any) => e.variable === "HTML_WORKER_MAX_MB")).toBe(
        true,
      );
    });

    it("should accept valid HTML_WORKER_TIMEOUT", () => {
      process.env.HTML_WORKER_TIMEOUT = "5000";
      jest.resetModules();
      const { validateConfiguration } = require("./validation");
      const errors = validateConfiguration();
      expect(
        errors.some((e: any) => e.variable === "HTML_WORKER_TIMEOUT"),
      ).toBe(false);
    });
  });
});
