import { describe, it, expect, beforeEach, afterAll, jest, spyOn } from "bun:test";
import dns from "node:dns";
import { isReservedIP } from "./Fetcher";
import { Fetcher } from "./Fetcher";

describe("isReservedIP", () => {
  // ─── IPv4: Reserved ranges that MUST be blocked ───

  describe("IPv4 — 0.0.0.0/8 (\"This\" network)", () => {
    it.each([
      "0.0.0.0",
      "0.0.0.1",
      "0.255.255.255",
    ])("should block %s", (ip) => {
      expect(isReservedIP(ip)).toBe(true);
    });
  });

  describe("IPv4 — 10.0.0.0/8 (Private, RFC 1918)", () => {
    it.each([
      "10.0.0.0",
      "10.0.0.1",
      "10.255.255.255",
      "10.128.0.1",
    ])("should block %s", (ip) => {
      expect(isReservedIP(ip)).toBe(true);
    });
  });

  describe("IPv4 — 100.64.0.0/10 (Shared/CGN)", () => {
    it.each([
      "100.64.0.0",
      "100.64.0.1",
      "100.127.255.255",
      "100.100.100.100",
    ])("should block %s", (ip) => {
      expect(isReservedIP(ip)).toBe(true);
    });

    it.each([
      "100.63.255.255",  // just below range
      "100.128.0.0",     // just above range
    ])("should allow %s (outside CGN range)", (ip) => {
      expect(isReservedIP(ip)).toBe(false);
    });
  });

  describe("IPv4 — 127.0.0.0/8 (Loopback)", () => {
    it.each([
      "127.0.0.0",
      "127.0.0.1",
      "127.255.255.255",
      "127.0.0.2",
    ])("should block %s", (ip) => {
      expect(isReservedIP(ip)).toBe(true);
    });
  });

  describe("IPv4 — 169.254.0.0/16 (Link-local)", () => {
    it.each([
      "169.254.0.0",
      "169.254.0.1",
      "169.254.255.255",
      "169.254.169.254",  // AWS metadata endpoint
    ])("should block %s", (ip) => {
      expect(isReservedIP(ip)).toBe(true);
    });

    it("should allow 169.253.255.255 (below range)", () => {
      expect(isReservedIP("169.253.255.255")).toBe(false);
    });

    it("should allow 169.255.0.0 (above range)", () => {
      expect(isReservedIP("169.255.0.0")).toBe(false);
    });
  });

  describe("IPv4 — 172.16.0.0/12 (Private, RFC 1918)", () => {
    it.each([
      "172.16.0.0",
      "172.16.0.1",
      "172.31.255.255",
      "172.20.0.1",
    ])("should block %s", (ip) => {
      expect(isReservedIP(ip)).toBe(true);
    });

    it.each([
      "172.15.255.255",  // just below range
      "172.32.0.0",      // just above range
    ])("should allow %s (outside 172.16/12)", (ip) => {
      expect(isReservedIP(ip)).toBe(false);
    });
  });

  describe("IPv4 — 192.0.0.0/24 (IETF protocol assignments)", () => {
    it.each([
      "192.0.0.0",
      "192.0.0.1",
      "192.0.0.255",
    ])("should block %s", (ip) => {
      expect(isReservedIP(ip)).toBe(true);
    });
  });

  describe("IPv4 — 192.0.2.0/24 (TEST-NET-1)", () => {
    it.each([
      "192.0.2.0",
      "192.0.2.1",
      "192.0.2.255",
    ])("should block %s", (ip) => {
      expect(isReservedIP(ip)).toBe(true);
    });
  });

  describe("IPv4 — 192.88.99.0/24 (6to4 relay anycast)", () => {
    it.each([
      "192.88.99.0",
      "192.88.99.1",
      "192.88.99.255",
    ])("should block %s", (ip) => {
      expect(isReservedIP(ip)).toBe(true);
    });
  });

  describe("IPv4 — 192.168.0.0/16 (Private, RFC 1918)", () => {
    it.each([
      "192.168.0.0",
      "192.168.0.1",
      "192.168.1.1",
      "192.168.255.255",
    ])("should block %s", (ip) => {
      expect(isReservedIP(ip)).toBe(true);
    });
  });

  describe("IPv4 — 198.18.0.0/15 (Benchmarking)", () => {
    it.each([
      "198.18.0.0",
      "198.18.0.1",
      "198.19.255.255",
    ])("should block %s", (ip) => {
      expect(isReservedIP(ip)).toBe(true);
    });

    it.each([
      "198.17.255.255",
      "198.20.0.0",
    ])("should allow %s (outside benchmarking range)", (ip) => {
      expect(isReservedIP(ip)).toBe(false);
    });
  });

  describe("IPv4 — 198.51.100.0/24 (TEST-NET-2)", () => {
    it.each([
      "198.51.100.0",
      "198.51.100.1",
      "198.51.100.255",
    ])("should block %s", (ip) => {
      expect(isReservedIP(ip)).toBe(true);
    });
  });

  describe("IPv4 — 203.0.113.0/24 (TEST-NET-3)", () => {
    it.each([
      "203.0.113.0",
      "203.0.113.1",
      "203.0.113.255",
    ])("should block %s", (ip) => {
      expect(isReservedIP(ip)).toBe(true);
    });
  });

  describe("IPv4 — 224.0.0.0/4 (Multicast) — CVE-2025-8020", () => {
    it.each([
      "224.0.0.0",
      "224.0.0.1",      // All hosts multicast
      "224.0.0.251",    // mDNS
      "224.0.0.252",    // LLMNR
      "233.0.0.1",      // mid-range multicast
      "239.255.255.250", // SSDP/UPnP
      "239.255.255.255", // top of multicast
    ])("should block %s", (ip) => {
      expect(isReservedIP(ip)).toBe(true);
    });
  });

  describe("IPv4 — 240.0.0.0/4 (Reserved) + broadcast", () => {
    it.each([
      "240.0.0.0",
      "240.0.0.1",
      "248.0.0.1",
      "254.255.255.255",
      "255.255.255.255",  // broadcast
    ])("should block %s", (ip) => {
      expect(isReservedIP(ip)).toBe(true);
    });
  });

  // ─── IPv4: Public IPs that MUST be allowed ───

  describe("IPv4 — Public addresses (should be allowed)", () => {
    it.each([
      "1.1.1.1",         // Cloudflare DNS
      "8.8.8.8",         // Google DNS
      "8.8.4.4",         // Google DNS secondary
      "93.184.216.34",   // example.com
      "104.16.0.1",      // Cloudflare
      "142.250.80.46",   // google.com
      "151.101.1.140",   // Reddit
      "13.107.42.14",    // Microsoft
      "223.255.255.255", // just below multicast range
      "100.63.255.255",  // just below CGN range
      "100.128.0.0",     // just above CGN range
      "11.0.0.1",        // just above 10/8
      "126.255.255.255", // just below loopback
      "128.0.0.1",       // just above loopback
      "172.15.255.255",  // just below 172.16/12
      "172.32.0.0",      // just above 172.16/12
    ])("should allow %s", (ip) => {
      expect(isReservedIP(ip)).toBe(false);
    });
  });

  // ─── IPv6: Reserved ranges ───

  describe("IPv6 — Loopback and unspecified", () => {
    it("should block ::  (unspecified)", () => {
      expect(isReservedIP("::")).toBe(true);
    });

    it("should block ::1 (loopback)", () => {
      expect(isReservedIP("::1")).toBe(true);
    });
  });

  describe("IPv6 — IPv4-mapped (::ffff:x.x.x.x)", () => {
    it("should block ::ffff:127.0.0.1 (mapped loopback)", () => {
      expect(isReservedIP("::ffff:127.0.0.1")).toBe(true);
    });

    it("should block ::ffff:10.0.0.1 (mapped private)", () => {
      expect(isReservedIP("::ffff:10.0.0.1")).toBe(true);
    });

    it("should block ::ffff:192.168.1.1 (mapped private)", () => {
      expect(isReservedIP("::ffff:192.168.1.1")).toBe(true);
    });

    it("should block ::ffff:224.0.0.1 (mapped multicast)", () => {
      expect(isReservedIP("::ffff:224.0.0.1")).toBe(true);
    });

    it("should allow ::ffff:8.8.8.8 (mapped public)", () => {
      expect(isReservedIP("::ffff:8.8.8.8")).toBe(false);
    });

    it("should allow ::ffff:93.184.216.34 (mapped public)", () => {
      expect(isReservedIP("::ffff:93.184.216.34")).toBe(false);
    });
  });

  describe("IPv6 — NAT64 (64:ff9b::)", () => {
    it("should block 64:ff9b::1", () => {
      expect(isReservedIP("64:ff9b::1")).toBe(true);
    });
  });

  describe("IPv6 — Discard (100::)", () => {
    it("should block 100::1", () => {
      expect(isReservedIP("100::1")).toBe(true);
    });
  });

  describe("IPv6 — Documentation (2001:db8::)", () => {
    it.each([
      "2001:db8::1",
      "2001:db8:ffff::1",
    ])("should block %s", (ip) => {
      expect(isReservedIP(ip)).toBe(true);
    });
  });

  describe("IPv6 — Teredo (2001::)", () => {
    it("should block 2001::1", () => {
      expect(isReservedIP("2001::1")).toBe(true);
    });
  });

  describe("IPv6 — 6to4 (2002::)", () => {
    it("should block 2002::1", () => {
      expect(isReservedIP("2002::1")).toBe(true);
    });
  });

  describe("IPv6 — Unique local (fc00::/7)", () => {
    it.each([
      "fc00::1",
      "fd00::1",
      "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
    ])("should block %s", (ip) => {
      expect(isReservedIP(ip)).toBe(true);
    });
  });

  describe("IPv6 — Link-local (fe80::/10)", () => {
    it.each([
      "fe80::1",
      "fe80::1%eth0",  // with zone ID — may not match, but worth checking
      "feb0::1",
    ])("should block %s", (ip) => {
      expect(isReservedIP(ip)).toBe(true);
    });
  });

  describe("IPv6 — Multicast (ff00::/8)", () => {
    it.each([
      "ff00::1",
      "ff02::1",       // all nodes
      "ff02::fb",      // mDNS
      "ff05::1",       // site-local all nodes
      "ff0e::1",       // global multicast
    ])("should block %s", (ip) => {
      expect(isReservedIP(ip)).toBe(true);
    });
  });

  describe("IPv6 — Public addresses (should be allowed)", () => {
    it.each([
      "2607:f8b0:4004:800::200e",  // Google
      "2606:4700:4700::1111",       // Cloudflare DNS
      "2620:0:862:ed1a::1",         // Wikipedia
    ])("should allow %s", (ip) => {
      expect(isReservedIP(ip)).toBe(false);
    });
  });

  // ─── Edge cases ───

  describe("Invalid / non-IP input (fail closed)", () => {
    it.each([
      "",
      "not-an-ip",
      "example.com",
      "999.999.999.999",
      "1.2.3",
      "1.2.3.4.5",
    ])("should block invalid input: %s", (ip) => {
      expect(isReservedIP(ip)).toBe(true);
    });
  });
});

// ─── Integration tests: Fetcher SSRF protection with isReservedIP ───

describe("Fetcher SSRF — multicast bypass (CVE-2025-8020)", () => {
  const originalFetch = globalThis.fetch;
  const mockFetch = jest.fn();
  const originalLookup = dns.promises.lookup;

  afterAll(() => {
    globalThis.fetch = originalFetch;
    dns.promises.lookup = originalLookup;
  });

  beforeEach(() => {
    jest.clearAllMocks();
    globalThis.fetch = mockFetch as any;
    Fetcher.hasYtDlp = false;
  });

  it("should block direct requests to multicast IPs in URL", async () => {
    dns.promises.lookup = (async () => ({ address: "224.0.0.1", family: 4 })) as any;
    const result = await Fetcher.html({ url: "http://224.0.0.1/" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("private address");
  });

  it("should block hostnames resolving to multicast IPs", async () => {
    dns.promises.lookup = (async () => ({ address: "239.255.255.250", family: 4 })) as any;
    const result = await Fetcher.html({ url: "https://evil.example.com/" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("resolved to private IP");
  });

  it("should block post-redirect to multicast IPs", async () => {
    const lookupSpy = spyOn(dns.promises, "lookup")
      .mockResolvedValueOnce({ address: "93.184.216.34", family: 4 } as any)
      .mockResolvedValueOnce({ address: "224.0.0.251", family: 4 } as any);

    mockFetch.mockResolvedValueOnce({
      ok: true,
      url: "http://224.0.0.251/secret",
      text: jest.fn().mockResolvedValueOnce("secret"),
    });

    const result = await Fetcher.html({ url: "https://example.com" });
    expect(result.isError).toBe(true);
    lookupSpy.mockRestore();
  });

  it("should block IPv6 multicast in URL", async () => {
    dns.promises.lookup = (async () => ({ address: "ff02::1", family: 6 })) as any;
    const result = await Fetcher.html({ url: "http://[ff02::1]/" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("private address");
  });

  it("should block IPv4-mapped IPv6 with private address", async () => {
    dns.promises.lookup = (async () => ({ address: "::ffff:127.0.0.1", family: 6 })) as any;
    const result = await Fetcher.html({ url: "http://[::ffff:127.0.0.1]/" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("private IP");
  });

  it("should allow public IPs", async () => {
    dns.promises.lookup = (async () => ({ address: "93.184.216.34", family: 4 })) as any;
    mockFetch.mockResolvedValueOnce({
      ok: true,
      text: jest.fn().mockResolvedValueOnce("<html>ok</html>"),
    });
    const result = await Fetcher.html({ url: "https://example.com" });
    expect(result.isError).toBe(false);
  });

  describe("boundary IPs around multicast range", () => {
    it("should allow 223.255.255.255 (just below multicast)", async () => {
      dns.promises.lookup = (async () => ({ address: "223.255.255.255", family: 4 })) as any;
      mockFetch.mockResolvedValueOnce({
        ok: true,
        text: jest.fn().mockResolvedValueOnce("<html>ok</html>"),
      });
      const result = await Fetcher.html({ url: "http://223.255.255.255/" });
      expect(result.isError).toBe(false);
    });

    it("should block 224.0.0.0 (start of multicast)", async () => {
      dns.promises.lookup = (async () => ({ address: "224.0.0.0", family: 4 })) as any;
      const result = await Fetcher.html({ url: "http://224.0.0.0/" });
      expect(result.isError).toBe(true);
    });

    it("should block 239.255.255.255 (end of multicast)", async () => {
      dns.promises.lookup = (async () => ({ address: "239.255.255.255", family: 4 })) as any;
      const result = await Fetcher.html({ url: "http://239.255.255.255/" });
      expect(result.isError).toBe(true);
    });

    it("should block 240.0.0.0 (start of reserved, above multicast)", async () => {
      dns.promises.lookup = (async () => ({ address: "240.0.0.0", family: 4 })) as any;
      const result = await Fetcher.html({ url: "http://240.0.0.0/" });
      expect(result.isError).toBe(true);
    });
  });
});
