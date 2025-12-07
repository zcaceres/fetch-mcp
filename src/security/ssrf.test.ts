// src/security/ssrf.test.ts
// Tests for SSRF protection functions

import { describe, it, expect, beforeEach, afterEach } from "@jest/globals";
import {
  isBlockedIP,
  validateScheme,
  validateUrlSecurity,
  isSameOrigin,
  BLOCKED_RANGES,
  ALLOWED_SCHEMES,
} from "./ssrf.js";
import { dependencies } from "../types.js";

describe("SSRF protection", () => {
  describe("BLOCKED_RANGES", () => {
    it("should include expected blocked ranges", () => {
      expect(BLOCKED_RANGES).toContain("loopback");
      expect(BLOCKED_RANGES).toContain("private");
      expect(BLOCKED_RANGES).toContain("linkLocal");
      expect(BLOCKED_RANGES).toContain("uniqueLocal");
      expect(BLOCKED_RANGES).toContain("ipv4Mapped");
    });
  });

  describe("ALLOWED_SCHEMES", () => {
    it("should only allow http and https", () => {
      expect(ALLOWED_SCHEMES).toEqual(["http:", "https:"]);
    });
  });

  describe("isBlockedIP", () => {
    // IPv4 tests
    it("should block localhost (127.0.0.1)", () => {
      expect(isBlockedIP("127.0.0.1")).toBe(true);
    });

    it("should block any loopback (127.x.x.x)", () => {
      expect(isBlockedIP("127.0.0.1")).toBe(true);
      expect(isBlockedIP("127.255.255.255")).toBe(true);
    });

    it("should block private 10.x.x.x addresses", () => {
      expect(isBlockedIP("10.0.0.1")).toBe(true);
      expect(isBlockedIP("10.255.255.255")).toBe(true);
    });

    it("should block private 192.168.x.x addresses", () => {
      expect(isBlockedIP("192.168.0.1")).toBe(true);
      expect(isBlockedIP("192.168.255.255")).toBe(true);
    });

    it("should block private 172.16-31.x.x addresses", () => {
      expect(isBlockedIP("172.16.0.1")).toBe(true);
      expect(isBlockedIP("172.31.255.255")).toBe(true);
    });

    it("should allow public IPs", () => {
      expect(isBlockedIP("8.8.8.8")).toBe(false);
      expect(isBlockedIP("93.184.216.34")).toBe(false);
      expect(isBlockedIP("1.1.1.1")).toBe(false);
    });

    it("should block link-local (169.254.x.x - AWS metadata)", () => {
      expect(isBlockedIP("169.254.169.254")).toBe(true);
      expect(isBlockedIP("169.254.0.1")).toBe(true);
    });

    it("should block carrier-grade NAT (100.64.x.x)", () => {
      expect(isBlockedIP("100.64.0.1")).toBe(true);
    });

    it("should block unspecified address (0.0.0.0)", () => {
      expect(isBlockedIP("0.0.0.0")).toBe(true);
    });

    it("should block broadcast (255.255.255.255)", () => {
      expect(isBlockedIP("255.255.255.255")).toBe(true);
    });

    it("should block multicast addresses (224-239.x.x.x)", () => {
      expect(isBlockedIP("224.0.0.1")).toBe(true);
      expect(isBlockedIP("239.255.255.250")).toBe(true);
    });

    // IPv6 tests
    it("should block IPv6 loopback (::1)", () => {
      expect(isBlockedIP("::1")).toBe(true);
    });

    it("should block IPv6 link-local (fe80::)", () => {
      expect(isBlockedIP("fe80::1")).toBe(true);
    });

    it("should block IPv6 unique local (fc00::/fd00::)", () => {
      expect(isBlockedIP("fd00::1")).toBe(true);
      expect(isBlockedIP("fc00::1")).toBe(true);
    });

    it("should block IPv6 multicast (ff00::)", () => {
      expect(isBlockedIP("ff02::1")).toBe(true);
    });

    it("should allow public IPv6 addresses", () => {
      expect(isBlockedIP("2001:4860:4860::8888")).toBe(false);
      expect(isBlockedIP("2606:2800:220:1:248:1893:25c8:1946")).toBe(false);
    });

    // IPv4-mapped IPv6 tests
    it("should block IPv4-mapped IPv6 loopback (::ffff:127.0.0.1)", () => {
      expect(isBlockedIP("::ffff:127.0.0.1")).toBe(true);
    });

    it("should block IPv4-mapped IPv6 private (::ffff:192.168.1.1)", () => {
      expect(isBlockedIP("::ffff:192.168.1.1")).toBe(true);
    });

    it("should block IPv4-mapped IPv6 private (::ffff:10.0.0.1)", () => {
      expect(isBlockedIP("::ffff:10.0.0.1")).toBe(true);
    });

    it("should allow IPv4-mapped IPv6 public addresses", () => {
      expect(isBlockedIP("::ffff:8.8.8.8")).toBe(false);
    });

    // Invalid IPs
    it("should return false for invalid IPs", () => {
      expect(isBlockedIP("not-an-ip")).toBe(false);
      expect(isBlockedIP("")).toBe(false);
    });
  });

  describe("validateScheme", () => {
    it("should allow http://", () => {
      expect(() => validateScheme("http://example.com")).not.toThrow();
    });

    it("should allow https://", () => {
      expect(() => validateScheme("https://example.com")).not.toThrow();
    });

    it("should block file://", () => {
      expect(() => validateScheme("file:///etc/passwd")).toThrow(
        /Blocked URL scheme.*file/,
      );
    });

    it("should block ftp://", () => {
      expect(() => validateScheme("ftp://ftp.example.com")).toThrow(
        /Blocked URL scheme.*ftp/,
      );
    });

    it("should block javascript:", () => {
      expect(() => validateScheme("javascript:alert(1)")).toThrow(
        /Blocked URL scheme.*javascript/,
      );
    });

    it("should block data:", () => {
      expect(() => validateScheme("data:text/html,<script>")).toThrow(
        /Blocked URL scheme.*data/,
      );
    });

    it("should throw for invalid URLs", () => {
      expect(() => validateScheme("not-a-url")).toThrow();
    });
  });

  describe("validateUrlSecurity", () => {
    const mockDnsResolve4 = jest.fn();
    const mockDnsResolve6 = jest.fn();
    let originalDeps: ReturnType<typeof dependencies.get>;

    beforeEach(() => {
      originalDeps = dependencies.get();
      dependencies.set({
        fetch: originalDeps.fetch,
        dnsResolve4: mockDnsResolve4,
        dnsResolve6: mockDnsResolve6,
      });
      mockDnsResolve4.mockReset();
      mockDnsResolve6.mockReset();
    });

    afterEach(() => {
      dependencies.set(originalDeps);
    });

    it("should block direct private IP addresses", async () => {
      await expect(
        validateUrlSecurity("http://192.168.1.1/api"),
      ).rejects.toThrow(/Blocked private\/reserved IP/);
    });

    it("should block direct loopback addresses", async () => {
      await expect(
        validateUrlSecurity("http://127.0.0.1:8080/api"),
      ).rejects.toThrow(/Blocked private\/reserved IP/);
    });

    it("should allow direct public IP addresses", async () => {
      const ips = await validateUrlSecurity("http://8.8.8.8/api");
      expect(ips).toContain("8.8.8.8");
    });

    it("should block hostnames resolving to private IPs", async () => {
      mockDnsResolve4.mockResolvedValue(["192.168.1.1"]);
      mockDnsResolve6.mockResolvedValue([]);

      await expect(
        validateUrlSecurity("http://internal.corp/api"),
      ).rejects.toThrow(/resolves to blocked IP/);
    });

    it("should allow hostnames resolving to public IPs", async () => {
      mockDnsResolve4.mockResolvedValue(["93.184.216.34"]);
      mockDnsResolve6.mockResolvedValue([]);

      const ips = await validateUrlSecurity("http://example.com/api");
      expect(ips).toContain("93.184.216.34");
    });

    it("should check both IPv4 and IPv6 resolutions", async () => {
      mockDnsResolve4.mockResolvedValue(["8.8.8.8"]);
      mockDnsResolve6.mockResolvedValue(["2001:4860:4860::8888"]);

      const ips = await validateUrlSecurity("http://google.com/api");
      expect(ips).toContain("8.8.8.8");
      expect(ips).toContain("2001:4860:4860::8888");
    });

    it("should block if any resolved IP is private", async () => {
      mockDnsResolve4.mockResolvedValue(["8.8.8.8", "192.168.1.1"]);
      mockDnsResolve6.mockResolvedValue([]);

      await expect(
        validateUrlSecurity("http://example.com/api"),
      ).rejects.toThrow(/resolves to blocked IP/);
    });

    it("should handle IPv6 URL format with brackets", async () => {
      await expect(
        validateUrlSecurity("http://[::1]:8080/api"),
      ).rejects.toThrow(/Blocked private\/reserved IP/);
    });

    it("should block when DNS resolution fails (fail-closed mode)", async () => {
      mockDnsResolve4.mockResolvedValue([]);
      mockDnsResolve6.mockResolvedValue([]);

      await expect(
        validateUrlSecurity("http://unknown.invalid/api"),
      ).rejects.toThrow(/DNS resolution failed/);
    });
  });

  describe("isSameOrigin", () => {
    it("should return true for same origin URLs", () => {
      expect(
        isSameOrigin("https://example.com/page1", "https://example.com/page2"),
      ).toBe(true);
    });

    it("should return true for same origin with different paths and queries", () => {
      expect(
        isSameOrigin(
          "https://example.com/path?query=1",
          "https://example.com/other?query=2",
        ),
      ).toBe(true);
    });

    it("should return false for different hostnames", () => {
      expect(
        isSameOrigin("https://example.com/page", "https://other.com/page"),
      ).toBe(false);
    });

    it("should return false for different schemes", () => {
      expect(
        isSameOrigin("http://example.com/page", "https://example.com/page"),
      ).toBe(false);
    });

    it("should return false for different ports", () => {
      expect(
        isSameOrigin(
          "https://example.com:443/page",
          "https://example.com:8443/page",
        ),
      ).toBe(false);
    });

    it("should return false for subdomains", () => {
      expect(
        isSameOrigin(
          "https://api.example.com/page",
          "https://example.com/page",
        ),
      ).toBe(false);
    });

    it("should return false for invalid URLs", () => {
      expect(isSameOrigin("not-a-url", "https://example.com")).toBe(false);
      expect(isSameOrigin("https://example.com", "not-a-url")).toBe(false);
    });
  });
});
