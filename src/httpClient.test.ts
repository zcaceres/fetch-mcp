import { describe, it, expect, afterEach, spyOn } from "bun:test";
import dns from "node:dns";
import http from "node:http";
import type net from "node:net";
import zlib from "node:zlib";
import {
  isNoProxyMatch,
  resolveProxyUrl,
  safeHttpGet,
  stripCrossOriginHeaders,
} from "./httpClient";

const originalLookup = dns.promises.lookup;

function createLocalLookup(allowedHosts: Set<string>, onCall?: (host: string) => void): net.LookupFunction {
  return (hostname, options, cb) => {
    onCall?.(hostname);
    if (!allowedHosts.has(hostname)) {
      const err = new Error(`Unexpected lookup for ${hostname}`) as NodeJS.ErrnoException;
      if (options && typeof options === "object" && options.all) {
        (cb as any)(err, []);
      } else {
        cb(err, "", 0);
      }
      return;
    }
    if (options && typeof options === "object" && options.all) {
      (cb as any)(null, [{ address: "127.0.0.1", family: 4 }]);
    } else {
      cb(null, "127.0.0.1", 4);
    }
  };
}

function startServer(
  handler: (req: http.IncomingMessage, res: http.ServerResponse) => void,
): Promise<{ server: http.Server; port: number }> {
  return new Promise((resolve) => {
    const server = http.createServer(handler);
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address() as net.AddressInfo;
      resolve({ server, port: addr.port });
    });
  });
}

function closeServer(server: http.Server): Promise<void> {
  return new Promise((resolve) => server.close(() => resolve()));
}

afterEach(() => {
  dns.promises.lookup = originalLookup;
});

describe("resolveProxyUrl & isNoProxyMatch", () => {
  it("resolves HTTPS_PROXY, HTTP_PROXY, and ALL_PROXY with correct precedence", () => {
    const httpsTarget = new URL("https://example.com/");
    const httpTarget = new URL("http://example.com/");

    expect(
      resolveProxyUrl(httpsTarget, undefined, {
        HTTPS_PROXY: "http://https-proxy:8443",
        HTTP_PROXY: "http://http-proxy:8080",
      })?.href,
    ).toBe("http://https-proxy:8443/");

    expect(
      resolveProxyUrl(httpTarget, undefined, {
        HTTPS_PROXY: "http://https-proxy:8443",
        HTTP_PROXY: "http://http-proxy:8080",
      })?.href,
    ).toBe("http://http-proxy:8080/");

    expect(
      resolveProxyUrl(httpsTarget, undefined, {
        all_proxy: "127.0.0.1:9000",
      })?.href,
    ).toBe("http://127.0.0.1:9000/");
  });

  it("prefers explicit proxy over env vars and normalizes bare host:port", () => {
    const target = new URL("https://example.com/");
    expect(
      resolveProxyUrl(target, "127.0.0.1:8888", {
        HTTPS_PROXY: "http://env-proxy:8080",
      })?.href,
    ).toBe("http://127.0.0.1:8888/");
  });

  it("respects NO_PROXY / no_proxy for env proxies", () => {
    const target = new URL("https://api.internal.example.com:8443/");
    expect(isNoProxyMatch(target, "example.com")).toBe(true);
    expect(isNoProxyMatch(target, ".example.com")).toBe(true);
    expect(isNoProxyMatch(target, "api.internal.example.com:8443")).toBe(true);
    expect(isNoProxyMatch(target, "api.internal.example.com:443")).toBe(false);
    expect(isNoProxyMatch(target, "*")).toBe(true);
    expect(isNoProxyMatch(target, "other.com")).toBe(false);

    expect(
      resolveProxyUrl(target, undefined, {
        HTTPS_PROXY: "http://proxy:8080",
        NO_PROXY: "other.com, .example.com",
      }),
    ).toBeUndefined();
  });

  it("rejects unsupported proxy protocols", () => {
    expect(() =>
      resolveProxyUrl(new URL("https://example.com/"), "socks5://127.0.0.1:1080"),
    ).toThrow('Unsupported proxy protocol "socks5:"');
  });
});

describe("stripCrossOriginHeaders", () => {
  it("strips Authorization, Cookie, and Proxy-Authorization case-insensitively", () => {
    const cleaned = stripCrossOriginHeaders({
      Authorization: "Bearer secret",
      cookie: "session=abc",
      "Proxy-Authorization": "Basic xyz",
      "X-Custom": "keep-me",
    });
    expect(cleaned).toEqual({ "X-Custom": "keep-me" });
  });
});

describe("safeHttpGet integration tests", () => {
  it("blocks redirect to private IP BEFORE sending any request to the internal target", async () => {
    let internalHits = 0;
    const internal = await startServer((_req, res) => {
      internalHits++;
      res.end("TOP SECRET");
    });

    const publicSrv = await startServer((_req, res) => {
      res.writeHead(302, { Location: `http://127.0.0.1:${internal.port}/secret` });
      res.end();
    });

    try {
      await expect(
        safeHttpGet({
          url: `http://public.example.test:${publicSrv.port}/start`,
          lookup: createLocalLookup(new Set(["public.example.test"])),
          env: {},
        }),
      ).rejects.toThrow("Fetcher blocked request to private address");

      expect(internalHits).toBe(0);
    } finally {
      await closeServer(publicSrv.server);
      await closeServer(internal.server);
    }
  });

  it("blocks redirect to IPv4-mapped IPv6 loopback BEFORE connecting", async () => {
    let internalHits = 0;
    const internal = await startServer((_req, res) => {
      internalHits++;
      res.end("TOP SECRET");
    });

    const publicSrv = await startServer((_req, res) => {
      res.writeHead(302, { Location: `http://[::ffff:127.0.0.1]:${internal.port}/secret` });
      res.end();
    });

    try {
      await expect(
        safeHttpGet({
          url: `http://public.example.test:${publicSrv.port}/start`,
          lookup: createLocalLookup(new Set(["public.example.test"])),
          env: {},
        }),
      ).rejects.toThrow("Fetcher blocked request to private address");

      expect(internalHits).toBe(0);
    } finally {
      await closeServer(publicSrv.server);
      await closeServer(internal.server);
    }
  });

  it("follows public redirects, resolves DNS once per hop, and strips Authorization/Cookie cross-origin", async () => {
    const receivedHeaders: Record<string, string | string[] | undefined>[] = [];
    const targetSrv = await startServer((req, res) => {
      receivedHeaders.push(req.headers);
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.end("final destination");
    });

    const originSrv = await startServer((_req, res) => {
      res.writeHead(302, { Location: `http://other.example.test:${targetSrv.port}/final` });
      res.end();
    });

    const lookupCalls: string[] = [];
    try {
      const resp = await safeHttpGet({
        url: `http://origin.example.test:${originSrv.port}/start`,
        headers: {
          Authorization: "Bearer super-secret",
          Cookie: "sid=123",
          "X-Trace": "preserved",
        },
        lookup: createLocalLookup(
          new Set(["origin.example.test", "other.example.test"]),
          (h) => lookupCalls.push(h),
        ),
        env: {},
      });

      expect(resp.ok).toBe(true);
      expect(resp.text).toBe("final destination");
      expect(lookupCalls).toEqual(["origin.example.test", "other.example.test"]);
      expect(receivedHeaders).toHaveLength(1);
      expect(receivedHeaders[0].authorization).toBeUndefined();
      expect(receivedHeaders[0].cookie).toBeUndefined();
      expect(receivedHeaders[0]["x-trace"]).toBe("preserved");
    } finally {
      await closeServer(originSrv.server);
      await closeServer(targetSrv.server);
    }
  });

  it("enforces maxRedirects limit", async () => {
    const loopSrv = await startServer((_req, res) => {
      res.writeHead(302, { Location: "/loop" });
      res.end();
    });

    try {
      await expect(
        safeHttpGet({
          url: `http://loop.example.test:${loopSrv.port}/loop`,
          maxRedirects: 2,
          lookup: createLocalLookup(new Set(["loop.example.test"])),
          env: {},
        }),
      ).rejects.toThrow("Too many redirects");
    } finally {
      await closeServer(loopSrv.server);
    }
  });

  it("decompresses gzip responses and enforces maxBytes on decompressed output", async () => {
    const smallPayload = "Hello compressed world!";
    const bigPayload = "A".repeat(2000);

    const srv = await startServer((req, res) => {
      const body = req.url === "/big" ? bigPayload : smallPayload;
      res.writeHead(200, { "Content-Encoding": "gzip" });
      res.end(zlib.gzipSync(Buffer.from(body)));
    });

    try {
      const okResp = await safeHttpGet({
        url: `http://gzip.example.test:${srv.port}/small`,
        maxBytes: 1024,
        lookup: createLocalLookup(new Set(["gzip.example.test"])),
        env: {},
      });
      expect(okResp.text).toBe(smallPayload);

      await expect(
        safeHttpGet({
          url: `http://gzip.example.test:${srv.port}/big`,
          maxBytes: 500,
          lookup: createLocalLookup(new Set(["gzip.example.test"])),
          env: {},
        }),
      ).rejects.toThrow("Response too large");
    } finally {
      await closeServer(srv.server);
    }
  });

  it("blocks DNS resolution to private IP via default safeLookup (no TOCTOU double-lookup)", async () => {
    const spy = spyOn(dns.promises, "lookup").mockResolvedValueOnce([
      { address: "127.0.0.1", family: 4 },
    ] as any);

    await expect(
      safeHttpGet({
        url: "http://rebind.example.test/",
        env: {},
      }),
    ).rejects.toThrow("resolved to private IP");

    expect(spy).toHaveBeenCalledTimes(1);
  });

  it("routes HTTP requests through operator HTTP_PROXY env var with Proxy-Authorization", async () => {
    let seenUrl: string | undefined;
    let seenProxyAuth: string | undefined;
    const proxySrv = await startServer((req, res) => {
      seenUrl = req.url;
      seenProxyAuth = req.headers["proxy-authorization"];
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.end("proxied response");
    });

    try {
      const resp = await safeHttpGet({
        url: "http://target.example.com/hello?a=1",
        env: {
          HTTP_PROXY: `http://user:pass@127.0.0.1:${proxySrv.port}`,
        },
      });

      expect(resp.ok).toBe(true);
      expect(resp.text).toBe("proxied response");
      expect(seenUrl).toBe("http://target.example.com/hello?a=1");
      expect(seenProxyAuth).toBe(`Basic ${Buffer.from("user:pass").toString("base64")}`);
    } finally {
      await closeServer(proxySrv.server);
    }
  });

  it("still blocks private target URLs even when HTTP_PROXY is configured", async () => {
    let proxyHits = 0;
    const proxySrv = await startServer((_req, res) => {
      proxyHits++;
      res.end("should never happen");
    });

    try {
      await expect(
        safeHttpGet({
          url: "http://169.254.169.254/latest/meta-data/",
          env: { HTTP_PROXY: `http://127.0.0.1:${proxySrv.port}` },
        }),
      ).rejects.toThrow("Fetcher blocked request to private address");
      expect(proxyHits).toBe(0);
    } finally {
      await closeServer(proxySrv.server);
    }
  });
});
