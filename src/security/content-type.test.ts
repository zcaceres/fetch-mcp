// src/security/content-type.test.ts
// Tests for content-type validation

import { describe, it, expect, beforeEach, afterEach } from "@jest/globals";

describe("checkContentType", () => {
  // Helper to create a mock Response
  function createMockResponse(contentType: string | null): Response {
    const headers = new Headers();
    if (contentType) {
      headers.set("content-type", contentType);
    }
    return {
      headers,
    } as unknown as Response;
  }

  beforeEach(() => {
    // Ensure validation is enabled
    process.env.VALIDATE_CONTENT_TYPE = "true";
    jest.resetModules();
  });

  afterEach(() => {
    delete process.env.VALIDATE_CONTENT_TYPE;
  });

  describe("HTML validation", () => {
    it("should accept text/html", async () => {
      const { checkContentType } = await import("./content-type.js");
      const response = createMockResponse("text/html");

      expect(() =>
        checkContentType(
          response,
          ["text/html", "application/xhtml+xml"],
          "fetch_html",
        ),
      ).not.toThrow();
    });

    it("should accept text/html with charset", async () => {
      const { checkContentType } = await import("./content-type.js");
      const response = createMockResponse("text/html; charset=utf-8");

      expect(() =>
        checkContentType(
          response,
          ["text/html", "application/xhtml+xml"],
          "fetch_html",
        ),
      ).not.toThrow();
    });

    it("should accept application/xhtml+xml", async () => {
      const { checkContentType } = await import("./content-type.js");
      const response = createMockResponse("application/xhtml+xml");

      expect(() =>
        checkContentType(
          response,
          ["text/html", "application/xhtml+xml"],
          "fetch_html",
        ),
      ).not.toThrow();
    });

    it("should reject application/json for HTML", async () => {
      const { checkContentType } = await import("./content-type.js");
      const response = createMockResponse("application/json");

      expect(() =>
        checkContentType(
          response,
          ["text/html", "application/xhtml+xml"],
          "fetch_html",
        ),
      ).toThrow(/Unexpected content type for fetch_html.*application\/json/);
    });
  });

  describe("JSON validation", () => {
    it("should accept application/json", async () => {
      const { checkContentType } = await import("./content-type.js");
      const response = createMockResponse("application/json");

      expect(() =>
        checkContentType(
          response,
          ["application/json", "application/ld+json", "text/json"],
          "fetch_json",
        ),
      ).not.toThrow();
    });

    it("should accept application/ld+json", async () => {
      const { checkContentType } = await import("./content-type.js");
      const response = createMockResponse("application/ld+json");

      expect(() =>
        checkContentType(
          response,
          ["application/json", "application/ld+json", "text/json"],
          "fetch_json",
        ),
      ).not.toThrow();
    });

    it("should reject text/html for JSON", async () => {
      const { checkContentType } = await import("./content-type.js");
      const response = createMockResponse("text/html");

      expect(() =>
        checkContentType(
          response,
          ["application/json", "application/ld+json", "text/json"],
          "fetch_json",
        ),
      ).toThrow(/Unexpected content type for fetch_json.*text\/html/);
    });
  });

  describe("text validation", () => {
    it("should accept text/plain", async () => {
      const { checkContentType } = await import("./content-type.js");
      const response = createMockResponse("text/plain");

      expect(() =>
        checkContentType(response, ["text/plain", "text/html"], "fetch_txt"),
      ).not.toThrow();
    });

    it("should reject image/png for text", async () => {
      const { checkContentType } = await import("./content-type.js");
      const response = createMockResponse("image/png");

      expect(() =>
        checkContentType(response, ["text/plain", "text/html"], "fetch_txt"),
      ).toThrow(/Unexpected content type for fetch_txt.*image\/png/);
    });
  });

  describe("edge cases", () => {
    it("should allow missing content-type header", async () => {
      const { checkContentType } = await import("./content-type.js");
      const response = createMockResponse(null);

      expect(() =>
        checkContentType(response, ["text/html"], "fetch_html"),
      ).not.toThrow();
    });

    it("should ignore charset and other parameters", async () => {
      const { checkContentType } = await import("./content-type.js");
      const response = createMockResponse(
        "text/html; charset=iso-8859-1; boundary=something",
      );

      expect(() =>
        checkContentType(response, ["text/html"], "fetch_html"),
      ).not.toThrow();
    });

    it("should be case-insensitive", async () => {
      const { checkContentType } = await import("./content-type.js");
      const response = createMockResponse("TEXT/HTML");

      expect(() =>
        checkContentType(response, ["text/html"], "fetch_html"),
      ).not.toThrow();
    });
  });

  describe("when disabled", () => {
    it("should skip validation when VALIDATE_CONTENT_TYPE=false", async () => {
      process.env.VALIDATE_CONTENT_TYPE = "false";
      jest.resetModules();

      const { checkContentType } = await import("./content-type.js");
      const response = createMockResponse("application/octet-stream");

      // Should not throw even though content type doesn't match
      expect(() =>
        checkContentType(response, ["text/html"], "fetch_html"),
      ).not.toThrow();
    });
  });
});
