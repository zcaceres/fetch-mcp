// src/logging/index.test.ts
// Tests for logging and metrics utilities

import { describe, it, expect, beforeEach, afterEach } from "@jest/globals";

describe("logging module", () => {
  let consoleErrorSpy: jest.SpyInstance;

  beforeEach(() => {
    consoleErrorSpy = jest.spyOn(console, "error").mockImplementation();
  });

  afterEach(() => {
    consoleErrorSpy.mockRestore();
    delete process.env.ENABLE_METRICS;
    delete process.env.LOG_LEVEL;
    delete process.env.LOG_FORMAT;
  });

  describe("emitMetric", () => {
    it("should emit metrics when enabled", async () => {
      process.env.ENABLE_METRICS = "true";
      jest.resetModules();

      const { emitMetric } = await import("./index.js");

      emitMetric({
        timestamp: "2024-01-01T00:00:00.000Z",
        type: "fetch_request",
        url: "https://example.com",
        tool: "fetch_html",
        duration: 100,
        status: "success",
        contentLength: 1000,
      });

      expect(consoleErrorSpy).toHaveBeenCalled();
      const output = consoleErrorSpy.mock.calls[0][0];
      expect(output).toContain("fetch_request");
    });

    it("should not emit metrics when disabled", async () => {
      delete process.env.ENABLE_METRICS;
      jest.resetModules();

      const { emitMetric } = await import("./index.js");

      emitMetric({
        timestamp: "2024-01-01T00:00:00.000Z",
        type: "fetch_request",
        url: "https://example.com",
        tool: "fetch_html",
        duration: 100,
        status: "success",
      });

      expect(consoleErrorSpy).not.toHaveBeenCalled();
    });

    it("should emit JSON format by default", async () => {
      process.env.ENABLE_METRICS = "true";
      delete process.env.LOG_FORMAT;
      jest.resetModules();

      const { emitMetric } = await import("./index.js");

      emitMetric({
        timestamp: "2024-01-01T00:00:00.000Z",
        type: "fetch_request",
        url: "https://example.com",
        tool: "fetch_json",
        duration: 50,
        status: "success",
      });

      expect(consoleErrorSpy).toHaveBeenCalled();
      const output = consoleErrorSpy.mock.calls[0][0];
      // Should be valid JSON
      const parsed = JSON.parse(output);
      expect(parsed.type).toBe("fetch_request");
      expect(parsed.tool).toBe("fetch_json");
    });

    it("should emit pretty format when configured", async () => {
      process.env.ENABLE_METRICS = "true";
      process.env.LOG_FORMAT = "pretty";
      jest.resetModules();

      const { emitMetric } = await import("./index.js");

      emitMetric({
        timestamp: "2024-01-01T00:00:00.000Z",
        type: "fetch_request",
        url: "https://example.com",
        tool: "fetch_txt",
        duration: 75,
        status: "error",
        errorType: "NetworkError",
      });

      expect(consoleErrorSpy).toHaveBeenCalled();
      const output = consoleErrorSpy.mock.calls[0][0];
      expect(output).toContain("METRIC");
      expect(output).toContain("fetch_txt");
      expect(output).toContain("error");
      expect(output).toContain("75ms");
    });

    it("should include cached flag when present", async () => {
      process.env.ENABLE_METRICS = "true";
      jest.resetModules();

      const { emitMetric } = await import("./index.js");

      emitMetric({
        timestamp: "2024-01-01T00:00:00.000Z",
        type: "fetch_request",
        url: "https://example.com",
        tool: "fetch_html",
        duration: 5,
        status: "success",
        cached: true,
      });

      expect(consoleErrorSpy).toHaveBeenCalled();
      const output = consoleErrorSpy.mock.calls[0][0];
      const parsed = JSON.parse(output);
      expect(parsed.cached).toBe(true);
    });
  });

  describe("log", () => {
    it("should log at error level by default", async () => {
      delete process.env.LOG_LEVEL;
      jest.resetModules();

      const { log } = await import("./index.js");

      log("error", "Test error message");
      expect(consoleErrorSpy).toHaveBeenCalled();

      consoleErrorSpy.mockClear();

      log("debug", "Test debug message");
      expect(consoleErrorSpy).not.toHaveBeenCalled();
    });

    it("should respect LOG_LEVEL setting", async () => {
      process.env.LOG_LEVEL = "debug";
      jest.resetModules();

      const { log } = await import("./index.js");

      log("debug", "Debug message");
      expect(consoleErrorSpy).toHaveBeenCalled();
    });

    it("should include data in log output", async () => {
      process.env.LOG_LEVEL = "info";
      jest.resetModules();

      const { log } = await import("./index.js");

      log("info", "Test message", { key: "value", count: 42 });

      expect(consoleErrorSpy).toHaveBeenCalled();
      const output = consoleErrorSpy.mock.calls[0][0];
      const parsed = JSON.parse(output);
      expect(parsed.message).toBe("Test message");
      expect(parsed.key).toBe("value");
      expect(parsed.count).toBe(42);
    });

    it("should format pretty logs correctly", async () => {
      process.env.LOG_LEVEL = "warn";
      process.env.LOG_FORMAT = "pretty";
      jest.resetModules();

      const { log } = await import("./index.js");

      log("warn", "Warning message", { detail: "info" });

      expect(consoleErrorSpy).toHaveBeenCalled();
      const output = consoleErrorSpy.mock.calls[0][0];
      expect(output).toContain("WARN");
      expect(output).toContain("Warning message");
      expect(output).toContain("detail");
    });

    it("should log info when level is info or higher", async () => {
      process.env.LOG_LEVEL = "info";
      jest.resetModules();

      const { log } = await import("./index.js");

      log("info", "Info message");
      expect(consoleErrorSpy).toHaveBeenCalled();

      consoleErrorSpy.mockClear();

      log("warn", "Warning message");
      expect(consoleErrorSpy).toHaveBeenCalled();

      consoleErrorSpy.mockClear();

      log("error", "Error message");
      expect(consoleErrorSpy).toHaveBeenCalled();
    });
  });
});
