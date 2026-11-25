import { describe, it, expect, afterEach, spyOn } from "bun:test";
import dns from "node:dns";
import {
  isReservedIP,
  parseIPv6ToGroups,
  validateUrl,
  validateYouTubeUrl,
  resolveAndValidateHost,
  createSafeLookup,
} from "./ssrf";
import { Fetcher } from "./Fetcher";

const originalLookup = dns.promises.lookup;

afterEach(() => {
  dns.promises.lookup = originalLookup;
  Fetcher.hasYtDlp = null;
});

describe("isReservedIP", () => {
  describe("IPv4 reserved ranges", () => {
    it.each([
      // 0.0.0.0/8
      "0.0.0.0",
      "0.255.255.255",
      // 10.0.0.0/8
      "10.0.0.0",
      "10.0.0.1",
      "10.255.255.255",
      // 100.64.0.0/10 (CGNAT)
      "100.64.0.0",
      "100.100.100.100",
      "100.127.255.255",
      // 127.0.0.0/8 (Loopback)
      "127.0.0.0",
      "127.0.0.1",
      "127.255.255.255",
      // 169.254.0.0/16 (Link-local / IMDS)
      "169.254.0.0",
      "169.254.169.254",
      "169.254.255.255",
      // 172.16.0.0/12
      "172.16.0.0",
      "172.24.0.1",
      "172.31.255.255",
      // 192.0.0.0/24, 192.0.2.0/24, 192.88.99.0/24, 192.168.0.0/16
      "192.0.0.1",
      "192.0.2.1",
      "192.88.99.1",
      "192.168.0.0",
      "192.168.1.1",
      "192.168.255.255",
      // 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24
      "198.18.0.1",
      "198.19.255.255",
      "198.51.100.1",
      "203.0.113.1",
      // 224.0.0.0/4 (Multicast — CVE-2025-8020)
      "224.0.0.0",
      "224.0.0.1",
      "224.0.0.251",
      "239.255.255.255",
      // 240.0.0.0/4 (Reserved + Broadcast)
      "240.0.0.0",
      "255.255.255.255",
    ])("blocks reserved IPv4: %s", (ip) => {
      expect(isReservedIP(ip)).toBe(true);
    });

    it.each([
      "1.1.1.1",
      "8.8.8.8",
      "93.184.216.34",
      "100.63.255.255",
      "100.128.0.0",
      "172.15.255.255",
      "172.32.0.0",
      "192.167.255.255",
      "192.169.0.0",
      "198.17.255.255",
      "198.20.0.0",
      "223.255.255.255",
    ])("allows public IPv4: %s", (ip) => {
      expect(isReservedIP(ip)).toBe(false);
    });
  });

  describe("IPv6 reserved ranges and bypass forms", () => {
    it.each([
      // Unspecified & loopback (compressed and expanded)
      "::",
      "0:0:0:0:0:0:0:0",
      "::1",
      "0:0:0:0:0:0:0:1",
      "0000:0000:0000:0000:0000:0000:0000:0001",
      // Deprecated IPv4-compatible (::/96)
      "::127.0.0.1",
      "::7f00:1",
      "::169.254.169.254",
      // IPv4-mapped IPv6 — dotted, WHATWG hex, and expanded forms
      "::ffff:127.0.0.1",
      "::ffff:7f00:1",
      "::ffff:7f00:0001",
      "0:0:0:0:0:ffff:127.0.0.1",
      "0:0:0:0:0:ffff:7f00:1",
      "0000:0000:0000:0000:0000:ffff:7f00:0001",
      "::ffff:169.254.169.254",
      "::ffff:a9fe:a9fe",
      "::ffff:10.0.0.1",
      "::ffff:0a00:0001",
      "::ffff:192.168.1.1",
      "::ffff:c0a8:0101",
      "::ffff:172.16.0.1",
      "::ffff:ac10:0001",
      "::ffff:100.64.0.1",
      "::ffff:224.0.0.1",
      "::ffff:e000:0001",
      "::ffff:0.0.0.0",
      "::ffff:0:0",
      // IPv4-translated (RFC 2765)
      "::ffff:0:127.0.0.1",
      "::ffff:0:7f00:1",
      // NAT64 (RFC 6052 & RFC 8215)
      "64:ff9b::127.0.0.1",
      "64:ff9b::7f00:1",
      "64:ff9b::a9fe:a9fe",
      "64:ff9b:1::1",
      // Discard, Teredo, Benchmarking, ORCHID, Documentation, 6to4
      "100::1",
      "2001::1",
      "2001:2::1",
      "2001:10::1",
      "2001:20::1",
      "2001:db8::1",
      "2002:7f00:1::1",
      "2002:c0a8:101::1",
      // ULA, Link-local, Site-local, Multicast
      "fc00::1",
      "fd12:3456:789a::1",
      "fe80::1",
      "febf::1",
      "fec0::1",
      "ff02::1",
      "ff00::1",
    ])("blocks reserved IPv6: %s", (ip) => {
      expect(isReservedIP(ip)).toBe(true);
    });

    it.each([
      "2606:2800:220:1:248:1893:25c8:1946", // example.com
      "2606:4700:4700::1111", // Cloudflare
      "2001:4860:4860::8888", // Google DNS
      "::ffff:93.184.216.34", // Public IPv4-mapped (dotted)
      "::ffff:5db8:d822", // Public IPv4-mapped (hex)
    ])("allows public IPv6: %s", (ip) => {
      expect(isReservedIP(ip)).toBe(false);
    });
  });

  describe("invalid input (fail closed)", () => {
    it.each([
      "",
      "not-an-ip",
      "example.com",
      "999.999.999.999",
      "1.2.3",
      "fe80::1%eth0",
      "::1::1",
    ])("fails closed for invalid input: %s", (input) => {
      expect(isReservedIP(input)).toBe(true);
    });

    it("parseIPv6ToGroups returns null for malformed input", () => {
      expect(parseIPv6ToGroups("not-ipv6")).toBeNull();
      expect(parseIPv6ToGroups("fe80::1%lo0")).toBeNull();
    });
  });
});

describe("validateUrl", () => {
  it.each([
    "http://[::ffff:127.0.0.1]/",
    "http://[::ffff:7f00:1]/",
    "http://[::ffff:169.254.169.254]/latest/meta-data/",
    "http://[0:0:0:0:0:ffff:127.0.0.1]/",
    "http://[::127.0.0.1]/",
    "http://[64:ff9b::127.0.0.1]/",
    "http://[64:ff9b::169.254.169.254]/",
    "http://224.0.0.1/",
    "http://0x7f000001/",
    "http://2130706433/",
    "http://localhost/",
    "http://localhost./",
    "http://LOCALHOST./",
    "http://sub.localhost/",
    "http://a.b.localhost./",
  ])("blocks SSRF bypass URL: %s", (url) => {
    expect(() => validateUrl(url)).toThrow("Fetcher blocked");
  });

  it("allows public URLs", () => {
    expect(validateUrl("https://example.com/path").hostname).toBe("example.com");
    expect(validateUrl("http://93.184.216.34/").hostname).toBe("93.184.216.34");
  });
});

describe("validateYouTubeUrl", () => {
  it.each([
    "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
    "https://youtube.com/watch?v=dQw4w9WgXcQ",
    "https://m.youtube.com/watch?v=dQw4w9WgXcQ",
    "https://music.youtube.com/watch?v=dQw4w9WgXcQ",
    "https://youtu.be/dQw4w9WgXcQ",
  ])("allows YouTube URL: %s", (url) => {
    expect(() => validateYouTubeUrl(url)).not.toThrow();
  });

  it.each([
    "http://127.0.0.1:8080/secret",
    "http://169.254.169.254/latest/meta-data/",
    "http://[::ffff:127.0.0.1]/",
    "https://evil.example.com/watch?v=123",
    "https://youtube.com.evil.com/watch?v=123",
    "file:///etc/passwd",
  ])("blocks non-YouTube / SSRF URL: %s", (url) => {
    expect(() => validateYouTubeUrl(url)).toThrow("Fetcher blocked");
  });
});

describe("resolveAndValidateHost & createSafeLookup", () => {
  it("blocks when any record in multi-record DNS response is private", async () => {
    const spy = spyOn(dns.promises, "lookup").mockResolvedValueOnce([
      { address: "93.184.216.34", family: 4 },
      { address: "127.0.0.1", family: 4 },
    ] as any);

    await expect(resolveAndValidateHost("dual.example.com")).rejects.toThrow(
      "resolved to private IP",
    );
    expect(spy).toHaveBeenCalledWith("dual.example.com", { all: true });
  });

  it("blocks when AAAA record is IPv4-mapped private IP", async () => {
    spyOn(dns.promises, "lookup").mockResolvedValueOnce([
      { address: "93.184.216.34", family: 4 },
      { address: "::ffff:169.254.169.254", family: 6 },
    ] as any);

    await expect(resolveAndValidateHost("imds.example.com")).rejects.toThrow(
      "resolved to private IP",
    );
  });

  it("fails closed when DNS lookup throws", async () => {
    spyOn(dns.promises, "lookup").mockRejectedValueOnce(new Error("ENOTFOUND"));

    await expect(resolveAndValidateHost("nonexistent.invalid")).rejects.toThrow(
      "DNS lookup failed",
    );
  });

  it("fails closed when DNS lookup returns empty array", async () => {
    spyOn(dns.promises, "lookup").mockResolvedValueOnce([] as any);

    await expect(resolveAndValidateHost("empty.example.com")).rejects.toThrow(
      "returned no addresses",
    );
  });

  it("createSafeLookup returns all validated records when options.all is true", async () => {
    spyOn(dns.promises, "lookup").mockResolvedValueOnce([
      { address: "93.184.216.34", family: 4 },
    ] as any);

    const lookup = createSafeLookup();
    const res = await new Promise<dns.LookupAddress[]>((resolve, reject) => {
      lookup("example.com", { all: true }, (err, addresses) => {
        if (err) reject(err);
        else resolve(addresses as unknown as dns.LookupAddress[]);
      });
    });

    expect(res).toEqual([{ address: "93.184.216.34", family: 4 }]);
  });

  it("createSafeLookup rejects private IPs via callback error", async () => {
    spyOn(dns.promises, "lookup").mockResolvedValueOnce([
      { address: "10.0.0.5", family: 4 },
    ] as any);

    const lookup = createSafeLookup();
    await expect(
      new Promise((resolve, reject) => {
        lookup("internal.example.com", { all: true }, (err, addresses) => {
          if (err) reject(err);
          else resolve(addresses);
        });
      }),
    ).rejects.toThrow("resolved to private IP");
  });
});

describe("Fetcher.youtubeTranscript SSRF hardening", () => {
  it("blocks non-YouTube URLs before invoking yt-dlp", async () => {
    Fetcher.hasYtDlp = true;
    const result = await Fetcher.youtubeTranscript({
      url: "http://127.0.0.1:8080/internal",
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Fetcher blocked");
  });

  it("blocks arbitrary external domains even when yt-dlp is available", async () => {
    Fetcher.hasYtDlp = true;
    const result = await Fetcher.youtubeTranscript({
      url: "https://attacker.example.com/redirect",
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("only allows YouTube URLs");
  });

  it("blocks YouTube hostname if DNS resolves to private IP before yt-dlp", async () => {
    Fetcher.hasYtDlp = true;
    spyOn(dns.promises, "lookup").mockResolvedValueOnce([
      { address: "127.0.0.1", family: 4 },
    ] as any);

    const result = await Fetcher.youtubeTranscript({
      url: "https://www.youtube.com/watch?v=test",
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("resolved to private IP");
  });
});
