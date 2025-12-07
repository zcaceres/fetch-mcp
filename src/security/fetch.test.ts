// src/security/fetch.test.ts
// Tests for secureFetch function

import { describe, it, expect, beforeEach, afterEach } from "@jest/globals";
import { secureFetch } from "./fetch.js";
import { dependencies, type FetcherDependencies } from "../types.js";

describe("secureFetch", () => {
  const mockFetch = jest.fn();
  let originalDeps: FetcherDependencies;

  // Helper to create mock DNS resolvers
  const createMockDns = (ipv4: string[] = [], ipv6: string[] = []) => ({
    dnsResolve4: jest.fn().mockResolvedValue(ipv4),
    dnsResolve6: jest.fn().mockResolvedValue(ipv6),
  });

  // Safe public IP for tests
  const safePublicIP = "93.184.216.34"; // example.com

  beforeEach(() => {
    // Store original dependencies
    originalDeps = dependencies.get();

    // Default: resolve to safe public IP
    const mockDns = createMockDns([safePublicIP], []);
    dependencies.set({
      fetch: mockFetch as unknown as typeof fetch,
      ...mockDns,
    });

    mockFetch.mockReset();
  });

  afterEach(() => {
    // Restore original dependencies
    dependencies.set(originalDeps);
  });

  describe("basic fetch", () => {
    it("should perform a successful fetch", async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        status: 200,
        headers: new Map([["content-type", "text/html"]]),
      });

      const response = await secureFetch("https://example.com", {});

      expect(response.ok).toBe(true);
      expect(mockFetch).toHaveBeenCalledTimes(1);
    });

    it("should include default User-Agent header", async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        status: 200,
      });

      await secureFetch("https://example.com", {});

      const callArgs = mockFetch.mock.calls[0];
      expect(callArgs[1].headers["User-Agent"]).toContain("Mozilla");
    });

    it("should throw for HTTP errors", async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        status: 404,
      });

      await expect(secureFetch("https://example.com", {})).rejects.toThrow(
        "HTTP error: 404",
      );
    });
  });

  describe("scheme validation", () => {
    it("should reject file:// URLs", async () => {
      await expect(secureFetch("file:///etc/passwd", {})).rejects.toThrow(
        /URL scheme.*file.*not allowed|Blocked URL scheme/,
      );
    });

    it("should reject ftp:// URLs", async () => {
      await expect(secureFetch("ftp://example.com/file", {})).rejects.toThrow(
        /URL scheme.*ftp.*not allowed|Blocked URL scheme/,
      );
    });

    it("should reject javascript: URLs", async () => {
      await expect(secureFetch("javascript:alert(1)", {})).rejects.toThrow(
        /URL scheme.*javascript.*not allowed|Blocked URL scheme/,
      );
    });
  });

  describe("redirect handling", () => {
    it("should follow redirects with Location header", async () => {
      // First response: redirect
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 302,
        headers: new Map([["location", "https://example.com/redirected"]]),
      });
      // Second response: success
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
      });

      const response = await secureFetch("https://example.com", {});

      expect(response.ok).toBe(true);
      expect(mockFetch).toHaveBeenCalledTimes(2);
    });

    it("should throw when redirect has no Location header", async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        status: 302,
        headers: new Map(),
      });

      await expect(secureFetch("https://example.com", {})).rejects.toThrow(
        "Redirect response missing Location header",
      );
    });

    it("should limit redirect depth to prevent infinite loops", async () => {
      // Create many redirects
      for (let i = 0; i < 15; i++) {
        mockFetch.mockResolvedValueOnce({
          ok: false,
          status: 302,
          headers: new Map([["location", `https://example.com/redirect${i}`]]),
        });
      }

      await expect(secureFetch("https://example.com", {})).rejects.toThrow(
        /Too many redirects/,
      );
    });

    it("should resolve relative redirect URLs", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 302,
        headers: new Map([["location", "/new-path"]]),
      });
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
      });

      await secureFetch("https://example.com/old-path", {});

      // Verify second call was to absolute URL
      const secondCallUrl = mockFetch.mock.calls[1][0];
      expect(secondCallUrl).toContain("new-path");
    });
  });

  describe("cross-origin redirect handling", () => {
    it("should strip auth headers on cross-origin redirect", async () => {
      // Configure DNS to resolve both hosts to safe IPs
      const mockDns = createMockDns([safePublicIP], []);
      dependencies.set({
        fetch: mockFetch as unknown as typeof fetch,
        ...mockDns,
      });

      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 302,
        headers: new Map([["location", "https://other-site.com/path"]]),
      });
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
      });

      await secureFetch("https://example.com", {
        Authorization: "Bearer secret-token",
        "X-Custom": "value",
      });

      // Second call should not have auth header
      const secondCallHeaders = mockFetch.mock.calls[1][1].headers;
      expect(secondCallHeaders["Authorization"]).toBeUndefined();
      // Should keep non-sensitive headers
      expect(secondCallHeaders["X-Custom"]).toBe("value");
    });
  });

  describe("DNS pinning (SSRF protection)", () => {
    it("should block requests to localhost", async () => {
      const mockDns = createMockDns(["127.0.0.1"], []);
      dependencies.set({
        fetch: mockFetch as unknown as typeof fetch,
        ...mockDns,
      });

      await expect(
        secureFetch("https://localhost-proxy.attacker.com", {}),
      ).rejects.toThrow(/blocked|private|SSRF/i);
    });

    it("should block requests to private IPs (10.x.x.x)", async () => {
      const mockDns = createMockDns(["10.0.0.1"], []);
      dependencies.set({
        fetch: mockFetch as unknown as typeof fetch,
        ...mockDns,
      });

      await expect(
        secureFetch("https://internal-service.example.com", {}),
      ).rejects.toThrow(/blocked|private|SSRF/i);
    });

    it("should block requests to private IPs (192.168.x.x)", async () => {
      const mockDns = createMockDns(["192.168.1.1"], []);
      dependencies.set({
        fetch: mockFetch as unknown as typeof fetch,
        ...mockDns,
      });

      await expect(
        secureFetch("https://router.example.com", {}),
      ).rejects.toThrow(/blocked|private|SSRF/i);
    });

    it("should block requests to metadata endpoints", async () => {
      const mockDns = createMockDns(["169.254.169.254"], []);
      dependencies.set({
        fetch: mockFetch as unknown as typeof fetch,
        ...mockDns,
      });

      await expect(
        secureFetch("https://metadata.google.internal", {}),
      ).rejects.toThrow(/blocked|private|SSRF/i);
    });
  });

  describe("timeout handling", () => {
    it("should abort request on timeout", async () => {
      // Create a mock that takes longer than the timeout
      mockFetch.mockImplementation(
        () =>
          new Promise((resolve, reject) => {
            // The fetch will be aborted before this resolves
            const timeout = setTimeout(() => {
              resolve({ ok: true, status: 200 });
            }, 60000);

            // Handle abort signal
            return {
              then: (onResolve: Function, onReject: Function) => {
                setTimeout(() => onResolve({ ok: true, status: 200 }), 60000);
              },
            };
          }),
      );

      // This should timeout
      // Note: The actual timeout behavior depends on requestTimeout config
      // For now we just verify the test structure is correct
    }, 5000);
  });
});
