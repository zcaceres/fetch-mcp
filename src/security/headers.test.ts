// src/security/headers.test.ts
// Tests for header security functions

import { describe, it, expect } from "@jest/globals";
import { sanitizeUrlForError, sanitizeHeaders } from "./headers.js";

describe("Header security", () => {
  describe("sanitizeUrlForError", () => {
    it("should remove query string from URLs", () => {
      const result = sanitizeUrlForError(
        "https://example.com/path?token=secret&api_key=12345",
      );
      expect(result).toBe("https://example.com/path");
      expect(result).not.toContain("token=secret");
      expect(result).not.toContain("api_key=12345");
    });

    it("should remove hash from URLs", () => {
      const result = sanitizeUrlForError("https://example.com/path#section");
      expect(result).toBe("https://example.com/path");
      expect(result).not.toContain("#section");
    });

    it("should preserve protocol, host, and path", () => {
      const result = sanitizeUrlForError(
        "https://api.example.com:8080/v1/users",
      );
      expect(result).toBe("https://api.example.com:8080/v1/users");
    });

    it("should handle URLs with no path", () => {
      const result = sanitizeUrlForError("https://example.com?secret=value");
      expect(result).toBe("https://example.com/");
    });

    it("should return [invalid URL] for malformed URLs", () => {
      const result = sanitizeUrlForError("not-a-valid-url");
      expect(result).toBe("[invalid URL]");
    });

    it("should handle empty string", () => {
      const result = sanitizeUrlForError("");
      expect(result).toBe("[invalid URL]");
    });
  });

  describe("sanitizeHeaders", () => {
    it("should return empty object for undefined headers", () => {
      const result = sanitizeHeaders(undefined);
      expect(result).toEqual({});
    });

    it("should return empty object for null headers", () => {
      const result = sanitizeHeaders(undefined);
      expect(result).toEqual({});
    });

    it("should pass through safe custom headers", () => {
      const headers = {
        "X-Custom-Header": "safe-value",
        Accept: "application/json",
        "Content-Type": "application/json",
      };
      const result = sanitizeHeaders(headers);
      expect(result["X-Custom-Header"]).toBe("safe-value");
      expect(result["Accept"]).toBe("application/json");
      expect(result["Content-Type"]).toBe("application/json");
    });

    it("should strip Host header", () => {
      const headers = {
        Host: "evil.com",
        "X-Custom": "value",
      };
      const result = sanitizeHeaders(headers);
      expect(result["Host"]).toBeUndefined();
      expect(result["X-Custom"]).toBe("value");
    });

    it("should strip Authorization header by default", () => {
      const headers = {
        Authorization: "Bearer secret-token",
        "X-Custom": "value",
      };
      const result = sanitizeHeaders(headers);
      expect(result["Authorization"]).toBeUndefined();
      expect(result["X-Custom"]).toBe("value");
    });

    it("should strip Cookie header by default", () => {
      const headers = {
        Cookie: "session=abc123",
        "X-Custom": "value",
      };
      const result = sanitizeHeaders(headers);
      expect(result["Cookie"]).toBeUndefined();
      expect(result["X-Custom"]).toBe("value");
    });

    it("should strip headers with CRLF characters (header injection)", () => {
      const headers = {
        "X-Injected\r\nEvil": "value",
        "X-Safe": "value",
      };
      const result = sanitizeHeaders(headers);
      expect(result["X-Injected\r\nEvil"]).toBeUndefined();
      expect(result["X-Safe"]).toBe("value");
    });

    it("should strip headers with newline in value", () => {
      const headers = {
        "X-Header": "value\r\nX-Injected: evil",
        "X-Safe": "value",
      };
      const result = sanitizeHeaders(headers);
      expect(result["X-Header"]).toBeUndefined();
      expect(result["X-Safe"]).toBe("value");
    });

    it("should strip auth headers when stripAuth is true (cross-origin redirect)", () => {
      const headers = {
        Authorization: "Bearer token",
        Cookie: "session=123",
        "X-Custom": "value",
      };
      const result = sanitizeHeaders(headers, true);
      expect(result["Authorization"]).toBeUndefined();
      expect(result["Cookie"]).toBeUndefined();
      expect(result["X-Custom"]).toBe("value");
    });

    it("should handle case-insensitive header matching", () => {
      const headers = {
        host: "evil.com",
        HOST: "evil.com",
        Host: "evil.com",
        authorization: "Bearer token",
        AUTHORIZATION: "Bearer token",
      };
      const result = sanitizeHeaders(headers);
      expect(result["host"]).toBeUndefined();
      expect(result["HOST"]).toBeUndefined();
      expect(result["Host"]).toBeUndefined();
      expect(result["authorization"]).toBeUndefined();
      expect(result["AUTHORIZATION"]).toBeUndefined();
    });

    it("should strip Proxy-Authorization header", () => {
      const headers = {
        "Proxy-Authorization": "Basic abc123",
      };
      const result = sanitizeHeaders(headers);
      expect(result["Proxy-Authorization"]).toBeUndefined();
    });

    it("should strip Set-Cookie header", () => {
      const headers = {
        "Set-Cookie": "malicious=value",
      };
      const result = sanitizeHeaders(headers);
      expect(result["Set-Cookie"]).toBeUndefined();
    });
  });
});
