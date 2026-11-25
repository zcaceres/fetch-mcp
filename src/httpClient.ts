import http from "node:http";
import https from "node:https";
import net from "node:net";
import tls from "node:tls";
import zlib from "node:zlib";
import { createSafeLookup, normalizeHostname, validateUrl } from "./ssrf.js";

export const DEFAULT_USER_AGENT =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

const DEFAULT_MAX_REDIRECTS = 10;
const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_MAX_BYTES = 10 * 1024 * 1024; // 10 MB
const MAX_CONNECT_HEADER_BYTES = 16 * 1024;

const REDIRECT_STATUS_CODES = new Set([301, 302, 303, 307, 308]);
const SENSITIVE_CROSS_ORIGIN_HEADERS = new Set([
  "authorization",
  "cookie",
  "proxy-authorization",
]);

export interface HttpRequestOptions {
  url: string;
  headers?: Record<string, string>;
  proxy?: string;
  maxBytes?: number;
  maxRedirects?: number;
  timeoutMs?: number;
  lookup?: net.LookupFunction;
  env?: NodeJS.ProcessEnv;
}

export interface HttpResponse {
  status: number;
  ok: boolean;
  url: string;
  headers: Record<string, string | string[] | undefined>;
  text: string;
}

interface SingleRequestResult {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  redirectLocation?: string;
  text?: string;
}

function getEffectivePort(url: URL): string {
  if (url.port) return url.port;
  return url.protocol === "https:" ? "443" : "80";
}

export function isNoProxyMatch(targetUrl: URL, noProxy?: string): boolean {
  if (!noProxy) return false;
  const host = normalizeHostname(targetUrl.hostname);
  const port = getEffectivePort(targetUrl);

  for (const rawEntry of noProxy.split(",")) {
    const entry = rawEntry.trim().toLowerCase();
    if (!entry) continue;
    if (entry === "*") return true;

    let entryHost = entry;
    let entryPort: string | undefined;

    if (entry.startsWith("[")) {
      const closing = entry.indexOf("]");
      if (closing !== -1) {
        entryHost = entry.slice(1, closing);
        if (entry[closing + 1] === ":") {
          entryPort = entry.slice(closing + 2);
        }
      }
    } else {
      const lastColon = entry.lastIndexOf(":");
      if (lastColon !== -1 && entry.indexOf(":") === lastColon) {
        entryHost = entry.slice(0, lastColon);
        entryPort = entry.slice(lastColon + 1);
      }
    }

    if (entryPort && entryPort !== port) {
      continue;
    }

    const pattern = entryHost.replace(/^\.+/, "").replace(/\.+$/, "");
    if (!pattern) continue;

    if (host === pattern || host.endsWith(`.${pattern}`)) {
      return true;
    }
  }

  return false;
}

/**
 * Resolves the proxy URL for a target request.
 * Explicit `proxy` (CLI `--proxy`) takes precedence; otherwise checks standard
 * operator environment variables while respecting `NO_PROXY` / `no_proxy`.
 */
export function resolveProxyUrl(
  targetUrl: URL,
  explicitProxy?: string,
  env: NodeJS.ProcessEnv = process.env,
): URL | undefined {
  let rawProxy = explicitProxy?.trim();

  if (!rawProxy) {
    const noProxy = env.NO_PROXY || env.no_proxy;
    if (isNoProxyMatch(targetUrl, noProxy)) {
      return undefined;
    }

    if (targetUrl.protocol === "https:") {
      rawProxy =
        env.HTTPS_PROXY ||
        env.https_proxy ||
        env.HTTP_PROXY ||
        env.http_proxy ||
        env.ALL_PROXY ||
        env.all_proxy;
    } else if (targetUrl.protocol === "http:") {
      rawProxy =
        env.HTTP_PROXY ||
        env.http_proxy ||
        env.ALL_PROXY ||
        env.all_proxy;
    }
    rawProxy = rawProxy?.trim();
  }

  if (!rawProxy) return undefined;

  const normalized = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(rawProxy)
    ? rawProxy
    : `http://${rawProxy}`;

  const parsed = new URL(normalized);
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error(
      `Unsupported proxy protocol "${parsed.protocol}". Only HTTP and HTTPS proxies are supported.`,
    );
  }

  return parsed;
}

function buildProxyAuthHeader(proxyUrl: URL): string | undefined {
  if (!proxyUrl.username && !proxyUrl.password) return undefined;
  const creds = `${decodeURIComponent(proxyUrl.username)}:${decodeURIComponent(proxyUrl.password)}`;
  return `Basic ${Buffer.from(creds).toString("base64")}`;
}

export function stripCrossOriginHeaders(
  headers: Record<string, string>,
): Record<string, string> {
  const result: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    if (!SENSITIVE_CROSS_ORIGIN_HEADERS.has(key.toLowerCase())) {
      result[key] = value;
    }
  }
  return result;
}

function openConnectTunnel(
  proxyUrl: URL,
  targetUrl: URL,
  timeoutMs: number,
): Promise<tls.TLSSocket> {
  return new Promise((resolve, reject) => {
    const proxyPort = Number(getEffectivePort(proxyUrl));
    const proxyHost = normalizeHostname(proxyUrl.hostname);
    const targetHost = normalizeHostname(targetUrl.hostname);
    const targetPort = getEffectivePort(targetUrl);
    const authority = targetHost.includes(":")
      ? `[${targetHost}]:${targetPort}`
      : `${targetHost}:${targetPort}`;

    const rawSocket: net.Socket =
      proxyUrl.protocol === "https:"
        ? tls.connect({ host: proxyHost, port: proxyPort, servername: proxyHost })
        : net.connect({ host: proxyHost, port: proxyPort });

    let settled = false;
    let headerBuf = Buffer.alloc(0);

    const fail = (err: Error) => {
      if (settled) return;
      settled = true;
      rawSocket.destroy();
      reject(err);
    };

    rawSocket.setTimeout(timeoutMs, () => {
      fail(new Error(`Proxy CONNECT timed out after ${timeoutMs}ms`));
    });
    rawSocket.on("error", fail);

    const onConnect = () => {
      const proxyAuth = buildProxyAuthHeader(proxyUrl);
      const lines = [
        `CONNECT ${authority} HTTP/1.1`,
        `Host: ${authority}`,
      ];
      if (proxyAuth) {
        lines.push(`Proxy-Authorization: ${proxyAuth}`);
      }
      lines.push("", "");
      rawSocket.write(lines.join("\r\n"));
    };

    if (proxyUrl.protocol === "https:") {
      rawSocket.once("secureConnect", onConnect);
    } else {
      rawSocket.once("connect", onConnect);
    }

    const onData = (chunk: Buffer) => {
      headerBuf = Buffer.concat([headerBuf, chunk]);
      const headerEnd = headerBuf.indexOf("\r\n\r\n");
      if (headerEnd === -1) {
        if (headerBuf.length > MAX_CONNECT_HEADER_BYTES) {
          fail(new Error("Proxy CONNECT response headers too large"));
        }
        return;
      }

      rawSocket.off("data", onData);
      rawSocket.off("error", fail);
      rawSocket.setTimeout(0);

      const headerText = headerBuf.subarray(0, headerEnd).toString("latin1");
      const statusLine = headerText.split("\r\n")[0] ?? "";
      const statusMatch = statusLine.match(/^HTTP\/\d+\.\d+\s+(\d{3})/);
      const statusCode = statusMatch ? Number(statusMatch[1]) : 0;

      if (statusCode !== 200) {
        fail(new Error(`Proxy CONNECT failed: ${statusLine || "invalid response"}`));
        return;
      }

      const remainder = headerBuf.subarray(headerEnd + 4);
      if (remainder.length > 0) {
        rawSocket.unshift(remainder);
      }

      const tlsSocket = tls.connect({
        socket: rawSocket,
        servername: net.isIP(targetHost) ? undefined : targetHost,
      });

      tlsSocket.once("error", (err) => {
        if (!settled) {
          settled = true;
          reject(err);
        }
      });
      tlsSocket.once("secureConnect", () => {
        if (!settled) {
          settled = true;
          resolve(tlsSocket);
        }
      });
    };

    rawSocket.on("data", onData);
    rawSocket.once("end", () => {
      fail(new Error("Proxy closed connection during CONNECT handshake"));
    });
  });
}

function readIncomingBody(
  res: http.IncomingMessage,
  req: http.ClientRequest,
  maxBytes: number,
): Promise<string> {
  return new Promise((resolve, reject) => {
    const contentLengthHeader = res.headers["content-length"];
    const contentLengthStr = Array.isArray(contentLengthHeader)
      ? contentLengthHeader[0]
      : contentLengthHeader;
    if (contentLengthStr) {
      const parsedLength = parseInt(contentLengthStr, 10);
      if (!Number.isNaN(parsedLength) && parsedLength > maxBytes) {
        res.destroy();
        req.destroy();
        reject(
          new Error(
            `Response too large: ${contentLengthStr} bytes exceeds ${maxBytes} byte limit`,
          ),
        );
        return;
      }
    }

    const encodingHeader = res.headers["content-encoding"];
    const encoding = (
      Array.isArray(encodingHeader) ? encodingHeader[0] : encodingHeader
    )
      ?.toLowerCase()
      .trim();

    let decompressor: zlib.Gunzip | zlib.Inflate | zlib.BrotliDecompress | null = null;
    if (encoding === "gzip" || encoding === "x-gzip") {
      decompressor = zlib.createGunzip();
    } else if (encoding === "deflate") {
      decompressor = zlib.createInflate();
    } else if (encoding === "br") {
      decompressor = zlib.createBrotliDecompress();
    }

    let settled = false;
    let rawBytes = 0;
    let decodedBytes = 0;
    const chunks: Buffer[] = [];

    const fail = (err: Error) => {
      if (settled) return;
      settled = true;
      res.destroy();
      decompressor?.destroy();
      req.destroy();
      reject(err);
    };

    res.on("error", fail);

    if (decompressor) {
      res.on("data", (chunk: Buffer) => {
        rawBytes += chunk.byteLength;
        if (rawBytes > maxBytes) {
          fail(
            new Error(
              `Response too large: exceeded ${maxBytes} byte limit while reading`,
            ),
          );
        }
      });

      decompressor.on("error", fail);
      decompressor.on("data", (chunk: Buffer) => {
        decodedBytes += chunk.byteLength;
        if (decodedBytes > maxBytes) {
          fail(
            new Error(
              `Response too large: exceeded ${maxBytes} byte limit while reading`,
            ),
          );
          return;
        }
        chunks.push(chunk);
      });
      decompressor.on("end", () => {
        if (settled) return;
        settled = true;
        resolve(Buffer.concat(chunks).toString("utf-8"));
      });

      res.pipe(decompressor);
    } else {
      res.on("data", (chunk: Buffer) => {
        decodedBytes += chunk.byteLength;
        if (decodedBytes > maxBytes) {
          fail(
            new Error(
              `Response too large: exceeded ${maxBytes} byte limit while reading`,
            ),
          );
          return;
        }
        chunks.push(chunk);
      });
      res.on("end", () => {
        if (settled) return;
        settled = true;
        resolve(Buffer.concat(chunks).toString("utf-8"));
      });
    }
  });
}

async function singleHttpGet(
  targetUrl: URL,
  headers: Record<string, string>,
  opts: {
    proxyUrl?: URL;
    maxBytes: number;
    timeoutMs: number;
    lookup: net.LookupFunction;
  },
): Promise<SingleRequestResult> {
  const { proxyUrl, maxBytes, timeoutMs, lookup } = opts;

  let tunnelSocket: tls.TLSSocket | undefined;
  if (proxyUrl && targetUrl.protocol === "https:") {
    tunnelSocket = await openConnectTunnel(proxyUrl, targetUrl, timeoutMs);
  }

  return new Promise((resolve, reject) => {
    let settled = false;
    const finishError = (err: Error) => {
      if (settled) return;
      settled = true;
      tunnelSocket?.destroy();
      reject(err);
    };

    const onResponse = (res: http.IncomingMessage) => {
      const status = res.statusCode ?? 0;
      const locationHeader = res.headers.location;
      const location = Array.isArray(locationHeader)
        ? locationHeader[0]
        : locationHeader;

      if (REDIRECT_STATUS_CODES.has(status) && location) {
        res.destroy();
        if (!settled) {
          settled = true;
          resolve({
            status,
            headers: res.headers,
            redirectLocation: location,
          });
        }
        return;
      }

      readIncomingBody(res, req, maxBytes)
        .then((text) => {
          if (!settled) {
            settled = true;
            resolve({ status, headers: res.headers, text });
          }
        })
        .catch(finishError);
    };

    let req: http.ClientRequest;

    if (proxyUrl && targetUrl.protocol === "http:") {
      const proxyAuth = buildProxyAuthHeader(proxyUrl);
      const reqHeaders: Record<string, string> = {
        ...headers,
        Host: targetUrl.host,
        ...(proxyAuth ? { "Proxy-Authorization": proxyAuth } : {}),
      };
      const transport = proxyUrl.protocol === "https:" ? https : http;
      req = transport.request(
        {
          protocol: proxyUrl.protocol,
          hostname: normalizeHostname(proxyUrl.hostname),
          port: Number(getEffectivePort(proxyUrl)),
          path: targetUrl.href,
          method: "GET",
          headers: reqHeaders,
          agent: false,
          timeout: timeoutMs,
        },
        onResponse,
      );
    } else if (tunnelSocket) {
      req = https.request(
        {
          protocol: "https:",
          hostname: normalizeHostname(targetUrl.hostname),
          port: Number(getEffectivePort(targetUrl)),
          path: `${targetUrl.pathname}${targetUrl.search}`,
          method: "GET",
          headers,
          agent: false,
          createConnection: () => tunnelSocket!,
          timeout: timeoutMs,
        },
        onResponse,
      );
    } else {
      const transport = targetUrl.protocol === "https:" ? https : http;
      req = transport.request(
        {
          protocol: targetUrl.protocol,
          hostname: normalizeHostname(targetUrl.hostname),
          port: Number(getEffectivePort(targetUrl)),
          path: `${targetUrl.pathname}${targetUrl.search}`,
          method: "GET",
          headers,
          agent: false,
          lookup,
          timeout: timeoutMs,
        },
        onResponse,
      );
    }

    req.on("timeout", () => {
      req.destroy(new Error(`Request timed out after ${timeoutMs}ms`));
    });
    req.on("error", finishError);
    req.end();
  });
}

function hasHeaderCaseInsensitive(
  headers: Record<string, string>,
  name: string,
): boolean {
  const target = name.toLowerCase();
  return Object.keys(headers).some((k) => k.toLowerCase() === target);
}

/**
 * Performs an SSRF-hardened HTTP(S) GET request:
 * - Validates initial URL and every redirect hop before connecting
 * - Pins DNS resolution directly to the socket via `lookup` (prevents DNS rebinding TOCTOU)
 * - Strips Authorization / Cookie headers on cross-origin redirects
 * - Enforces `maxBytes` on both raw and decompressed response bodies
 * - Supports operator environment proxies (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY`)
 */
export async function safeHttpGet(
  options: HttpRequestOptions,
): Promise<HttpResponse> {
  const maxBytes = options.maxBytes ?? DEFAULT_MAX_BYTES;
  const maxRedirects = options.maxRedirects ?? DEFAULT_MAX_REDIRECTS;
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const lookup = options.lookup ?? createSafeLookup();

  let currentUrl = validateUrl(options.url);
  let currentHeaders: Record<string, string> = {
    "User-Agent": DEFAULT_USER_AGENT,
    ...options.headers,
  };
  if (!hasHeaderCaseInsensitive(currentHeaders, "accept-encoding")) {
    currentHeaders["Accept-Encoding"] = "gzip, deflate, br";
  }

  for (let hop = 0; hop <= maxRedirects; hop++) {
    const proxyUrl = resolveProxyUrl(currentUrl, options.proxy, options.env);

    let result: SingleRequestResult;
    try {
      result = await singleHttpGet(currentUrl, currentHeaders, {
        proxyUrl,
        maxBytes,
        timeoutMs,
        lookup,
      });
    } catch (e: unknown) {
      if (e instanceof Error) {
        if (
          e.message.startsWith("Fetcher blocked") ||
          e.message.startsWith("Response too large") ||
          e.message.startsWith("Unsupported proxy protocol")
        ) {
          throw e;
        }
        throw new Error(`Failed to fetch ${options.url}: ${e.message}`);
      }
      throw new Error(`Failed to fetch ${options.url}: Unknown error`);
    }

    if (result.redirectLocation) {
      if (hop >= maxRedirects) {
        throw new Error(
          `Failed to fetch ${options.url}: Too many redirects (exceeded ${maxRedirects})`,
        );
      }

      const nextHref = new URL(result.redirectLocation, currentUrl).href;
      const nextUrl = validateUrl(nextHref);

      if (nextUrl.origin !== currentUrl.origin) {
        currentHeaders = stripCrossOriginHeaders(currentHeaders);
      }

      currentUrl = nextUrl;
      continue;
    }

    return {
      status: result.status,
      ok: result.status >= 200 && result.status < 300,
      url: currentUrl.href,
      headers: result.headers,
      text: result.text ?? "",
    };
  }

  throw new Error(
    `Failed to fetch ${options.url}: Too many redirects (exceeded ${maxRedirects})`,
  );
}
