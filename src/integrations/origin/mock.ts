import zlib from 'node:zlib';
import type { FetchError, Headers, ResolvedIp, TargetUrl, WireResponse } from '../../fetching/nouns.ts';
import type { HttpGetPort } from '../../fetching/ports.ts';
import { REQUEST_TIMEOUT_MS } from '../../fetching/verbs.ts';
import { redactProxyUrl } from '../../policy/queries.ts';
import { err, ok, type Result } from '../../shared/result.ts';

type OriginEntry =
  | { readonly kind: 'response'; readonly status: number; readonly headers: Headers; readonly rawBytes: Uint8Array }
  | { readonly kind: 'fail'; readonly reason: string }
  | { readonly kind: 'proxy_fail'; readonly reason: string }
  | { readonly kind: 'timeout'; readonly timeoutMs: number };

const encoder = new TextEncoder();

const compressBytes = (encoding: string, text: string): Uint8Array => {
  const lower = encoding.toLowerCase();
  if (lower === 'gzip' || lower === 'x-gzip') return zlib.gzipSync(text);
  if (lower === 'deflate') return zlib.deflateSync(text);
  if (lower === 'br') return zlib.brotliCompressSync(text);
  return encoder.encode(text);
};

export type OriginMock = {
  readonly get: HttpGetPort;
  readonly serve: (url: string, status: number, body: string, headers?: Headers) => void;
  readonly header: (url: string, name: string, value: string) => Result<void, string>;
  readonly compress: (url: string, encoding: string, body: string) => void;
  readonly repeat: (url: string, count: number, encoding?: string) => void;
  readonly corrupt: (url: string, encoding: string) => void;
  readonly redirect: (url: string, status: number, location: string) => void;
  readonly fail: (url: string, reason: string) => void;
  readonly proxyFail: (url: string, reason: string) => void;
  readonly timeout: (url: string, timeoutMs?: number) => void;
  readonly lastHeaders: (url: string) => Headers | undefined;
  readonly lastPinned: (url: string) => readonly ResolvedIp[] | undefined;
  readonly lastProxy: (url: string) => string | null | undefined;
  readonly attempts: (url: string) => number;
};

export const createOriginMock = (): OriginMock => {
  const routes = new Map<string, OriginEntry>();
  const recordedHeaders = new Map<string, Headers>();
  const recordedPinned = new Map<string, readonly ResolvedIp[]>();
  const recordedProxy = new Map<string, string | null>();
  const attemptCounts = new Map<string, number>();

  const normalizeKey = (url: string): string => {
    try {
      return new URL(url).href;
    } catch {
      return url;
    }
  };

  const get: HttpGetPort = async (
    url: TargetUrl,
    headers: Headers,
    pinnedIps: readonly ResolvedIp[],
    proxyUrl?: string,
  ): Promise<Result<WireResponse, FetchError>> => {
    const key = normalizeKey(url);
    recordedHeaders.set(key, { ...headers });
    recordedPinned.set(key, [...pinnedIps]);
    recordedProxy.set(key, proxyUrl ?? null);
    attemptCounts.set(key, (attemptCounts.get(key) ?? 0) + 1);

    const entry = routes.get(key);
    if (!entry) {
      return err({ kind: 'network_error', message: `Network error fetching ${url}: no mock response registered` });
    }
    if (entry.kind === 'fail') {
      return err({ kind: 'network_error', message: `Network error fetching ${url}: ${entry.reason}` });
    }
    if (entry.kind === 'proxy_fail') {
      const via = proxyUrl !== undefined ? ` via proxy ${redactProxyUrl(proxyUrl)}` : '';
      return err({ kind: 'network_error', message: `Network error fetching ${url}${via}: ${entry.reason}` });
    }
    if (entry.kind === 'timeout') {
      return err({
        kind: 'timeout',
        message: `Request timed out after ${entry.timeoutMs}ms fetching ${url}`,
      });
    }
    return ok({
      status: entry.status,
      url,
      headers: entry.headers,
      rawBytes: entry.rawBytes,
    });
  };

  return {
    get,
    serve: (url, status, body, headers = {}) => {
      routes.set(normalizeKey(url), { kind: 'response', status, headers, rawBytes: encoder.encode(body) });
    },
    header: (url, name, value) => {
      const key = normalizeKey(url);
      const existing = routes.get(key);
      if (existing?.kind !== 'response') {
        return err(`No served response registered for ${url}`);
      }
      routes.set(key, { ...existing, headers: { ...existing.headers, [name]: value } });
      return ok(undefined);
    },
    compress: (url, encoding, body) => {
      routes.set(normalizeKey(url), {
        kind: 'response',
        status: 200,
        headers: { 'content-encoding': encoding },
        rawBytes: compressBytes(encoding, body),
      });
    },
    repeat: (url, count, encoding) => {
      const text = 'a'.repeat(count);
      const headers: Headers = encoding ? { 'content-encoding': encoding } : {};
      const rawBytes = encoding ? compressBytes(encoding, text) : encoder.encode(text);
      routes.set(normalizeKey(url), { kind: 'response', status: 200, headers, rawBytes });
    },
    corrupt: (url, encoding) => {
      routes.set(normalizeKey(url), {
        kind: 'response',
        status: 200,
        headers: { 'content-encoding': encoding },
        rawBytes: encoder.encode('corrupted-compressed-payload'),
      });
    },
    redirect: (url, status, location) => {
      routes.set(normalizeKey(url), {
        kind: 'response',
        status,
        headers: { location },
        rawBytes: new Uint8Array(0),
      });
    },
    fail: (url, reason) => {
      routes.set(normalizeKey(url), { kind: 'fail', reason });
    },
    proxyFail: (url, reason) => {
      routes.set(normalizeKey(url), { kind: 'proxy_fail', reason });
    },
    timeout: (url, timeoutMs = REQUEST_TIMEOUT_MS) => {
      routes.set(normalizeKey(url), { kind: 'timeout', timeoutMs });
    },
    lastHeaders: (url) => recordedHeaders.get(normalizeKey(url)),
    lastPinned: (url) => recordedPinned.get(normalizeKey(url)),
    lastProxy: (url) => recordedProxy.get(normalizeKey(url)),
    attempts: (url) => attemptCounts.get(normalizeKey(url)) ?? 0,
  };
};
