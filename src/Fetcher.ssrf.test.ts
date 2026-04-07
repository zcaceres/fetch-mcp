/**
 * PoC test for CWE-918: DNS rebinding TOCTOU race in Fetcher.ts
 *
 * The vulnerability: validateResolvedIp() resolves DNS and checks the IP,
 * then fetch() resolves DNS *again* internally. An attacker controlling DNS
 * can return a public IP for validation and a private IP for the actual fetch.
 *
 * Additionally, redirects are followed automatically before validation,
 * meaning requests to private IPs from redirect targets have already completed
 * by the time response.url is checked.
 *
 * The fix: resolve DNS once, validate the IP, and pin the resolved IP by
 * rewriting the fetch URL to use the IP directly (with Host header and TLS SNI).
 * Redirects are followed manually with validation at each hop.
 */
import { describe, it, expect, beforeEach, afterEach, jest } from "bun:test";
import dns from "node:dns";
import { Fetcher } from "./Fetcher";

describe("CWE-918: DNS rebinding TOCTOU", () => {
  const originalLookup = dns.promises.lookup;
  const originalFetch = globalThis.fetch;

  beforeEach(() => {
    globalThis.fetch = originalFetch;
    dns.promises.lookup = originalLookup;
    Fetcher.hasYtDlp = false;
  });

  afterEach(() => {
    dns.promises.lookup = originalLookup;
    globalThis.fetch = originalFetch;
  });

  it("should pin resolved IP: fetch URL uses validated IP, not hostname", async () => {
    const attackUrl = "http://rebind.test:8080/path";

    // Mock DNS to return public IP (validation passes)
    dns.promises.lookup = (async () => {
      return { address: "93.184.216.34", family: 4 };
    }) as any;

    // Spy on real fetch to see what URL it receives
    const fetchSpy = jest.fn().mockResolvedValue(
      new Response("<html>ok</html>", { status: 200 })
    );
    globalThis.fetch = fetchSpy as any;

    await Fetcher.html({ url: attackUrl });

    // After fix: fetch should be called with the resolved IP, not the hostname.
    // This eliminates the TOCTOU because the runtime can't re-resolve DNS.
    expect(fetchSpy).toHaveBeenCalled();
    const fetchedUrl = fetchSpy.mock.calls[0][0] as string;
    expect(fetchedUrl).toContain("93.184.216.34");
    expect(fetchedUrl).not.toContain("rebind.test");
  });

  it("should validate redirect targets BEFORE following them", async () => {
    const startUrl = "http://public.example.com/start";

    dns.promises.lookup = (async (hostname: string) => {
      if (hostname === "public.example.com") {
        return { address: "93.184.216.34", family: 4 };
      }
      return { address: "127.0.0.1", family: 4 };
    }) as any;

    // First fetch returns a redirect to a private IP
    const fetchSpy = jest.fn().mockResolvedValueOnce(
      new Response(null, {
        status: 302,
        headers: { Location: "http://127.0.0.1/secret" },
      })
    );
    globalThis.fetch = fetchSpy as any;

    const result = await Fetcher.html({ url: startUrl });

    // The redirect to 127.0.0.1 must be blocked
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("private");

    // fetch should only have been called once — the redirect must NOT have been followed
    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });

  it("should include Host header when pinning IP", async () => {
    const url = "http://example.com/page";

    dns.promises.lookup = (async () => {
      return { address: "93.184.216.34", family: 4 };
    }) as any;

    const fetchSpy = jest.fn().mockResolvedValue(
      new Response("<html>ok</html>", { status: 200 })
    );
    globalThis.fetch = fetchSpy as any;

    await Fetcher.html({ url });

    expect(fetchSpy).toHaveBeenCalled();
    const fetchOptions = fetchSpy.mock.calls[0][1] as RequestInit;
    const headers = fetchOptions.headers as Record<string, string>;
    expect(headers["Host"]).toBe("example.com");
  });

  it("should properly follow valid redirects with IP pinning", async () => {
    const startUrl = "http://example.com/start";

    dns.promises.lookup = (async (hostname: string) => {
      if (hostname === "example.com") {
        return { address: "93.184.216.34", family: 4 };
      }
      if (hostname === "cdn.example.com") {
        return { address: "104.18.26.120", family: 4 };
      }
      return originalLookup(hostname);
    }) as any;

    const fetchSpy = jest.fn()
      .mockResolvedValueOnce(
        new Response(null, {
          status: 302,
          headers: { Location: "http://cdn.example.com/page" },
        })
      )
      .mockResolvedValueOnce(
        new Response("<html>final page</html>", { status: 200 })
      );
    globalThis.fetch = fetchSpy as any;

    const result = await Fetcher.html({ url: startUrl });
    expect(result.isError).toBe(false);
    expect(result.content[0].text).toContain("final page");

    // Both fetch calls should use IP addresses, not hostnames
    const firstUrl = fetchSpy.mock.calls[0][0] as string;
    const secondUrl = fetchSpy.mock.calls[1][0] as string;
    expect(firstUrl).toContain("93.184.216.34");
    expect(secondUrl).toContain("104.18.26.120");
  });

  it("should handle relative redirect URLs", async () => {
    const startUrl = "http://example.com/start";

    dns.promises.lookup = (async () => {
      return { address: "93.184.216.34", family: 4 };
    }) as any;

    const fetchSpy = jest.fn()
      .mockResolvedValueOnce(
        new Response(null, {
          status: 301,
          headers: { Location: "/final" },
        })
      )
      .mockResolvedValueOnce(
        new Response("<html>final</html>", { status: 200 })
      );
    globalThis.fetch = fetchSpy as any;

    const result = await Fetcher.html({ url: startUrl });
    expect(result.isError).toBe(false);
    expect(result.content[0].text).toContain("final");
  });

  it("should reject too many redirects", async () => {
    const startUrl = "http://example.com/loop";

    dns.promises.lookup = (async () => {
      return { address: "93.184.216.34", family: 4 };
    }) as any;

    // Create an infinite redirect loop
    const fetchSpy = jest.fn().mockResolvedValue(
      new Response(null, {
        status: 302,
        headers: { Location: "http://example.com/loop" },
      })
    );
    globalThis.fetch = fetchSpy as any;

    const result = await Fetcher.html({ url: startUrl });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("redirect");
  });
});
