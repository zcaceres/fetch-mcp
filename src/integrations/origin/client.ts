import type dns from 'node:dns';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import type { FetchError, Headers, ResolvedIp, TargetUrl, WireResponse } from '../../fetching/nouns.ts';
import type { HttpGetPort } from '../../fetching/ports.ts';
import { normalizeHostname } from '../../fetching/queries.ts';
import { MAX_RESPONSE_BYTES, REQUEST_TIMEOUT_MS } from '../../fetching/verbs.ts';
import { redactProxyUrl } from '../../policy/queries.ts';
import { err, ok, type Result } from '../../shared/result.ts';
import {
  buildProxyAuthHeader,
  openHttpConnectTunnel,
  openSocks4Tunnel,
  openSocks5Tunnel,
  type TunnelError,
  wrapTlsOverTunnel,
} from './proxy.ts';

const REDIRECT_STATUS_CODES = new Set([301, 302, 303, 307, 308]);
const SINGLE_VALUE_HEADERS = new Set(['location', 'content-length', 'content-type', 'content-encoding']);

export type RealHttpGetOptions = {
  readonly maxBytes?: number;
  readonly timeoutMs?: number;
};

class SingleHttpTunnelAgent extends http.Agent {
  private readonly tunnel: net.Socket;

  constructor(tunnel: net.Socket) {
    super({ keepAlive: false });
    this.tunnel = tunnel;
  }

  createConnection(
    _options: http.ClientRequestArgs,
    callback?: (err: Error | null, socket: net.Socket) => void,
  ): net.Socket {
    if (callback) {
      callback(null, this.tunnel);
    }
    return this.tunnel;
  }
}

class SingleHttpsTunnelAgent extends https.Agent {
  private readonly tunnel: net.Socket;

  constructor(tunnel: net.Socket) {
    super({ keepAlive: false });
    this.tunnel = tunnel;
  }

  createConnection(
    _options: https.RequestOptions,
    callback?: (err: Error | null, socket: net.Socket) => void,
  ): net.Socket {
    if (callback) {
      callback(null, this.tunnel);
    }
    return this.tunnel;
  }
}

const getEffectivePort = (url: URL): number => {
  if (url.port) return Number(url.port);
  return url.protocol === 'https:' ? 443 : 80;
};

const normalizeIncomingHeaders = (raw: http.IncomingHttpHeaders): Headers => {
  const result: Record<string, string> = {};
  for (const [key, value] of Object.entries(raw)) {
    if (typeof value === 'string') {
      result[key] = value;
    } else if (Array.isArray(value) && value.length > 0) {
      const first = value[0];
      if (first !== undefined) {
        result[key] = SINGLE_VALUE_HEADERS.has(key.toLowerCase()) ? first : value.join(', ');
      }
    }
  }
  return result;
};

export const createPinnedLookup = (pinnedIps: readonly ResolvedIp[]): net.LookupFunction => {
  const records: dns.LookupAddress[] = pinnedIps.map((address) => ({
    address,
    family: net.isIPv6(address) ? 6 : 4,
  }));

  return (hostname, options, callback) => {
    const wantsAll = typeof options === 'object' && options !== null && options.all === true;

    if (records.length === 0) {
      const error: NodeJS.ErrnoException = new Error(`Blocked Target URL: no pinned IP available for "${hostname}"`);
      if (wantsAll) {
        process.nextTick(callback, error, []);
      } else {
        process.nextTick(callback, error, '', 0);
      }
      return;
    }

    if (wantsAll) {
      process.nextTick(callback, null, records);
      return;
    }

    const familyFilter =
      typeof options === 'number'
        ? options
        : typeof options === 'object' && options !== null && typeof options.family === 'number'
          ? options.family
          : 0;
    const match =
      familyFilter === 4 || familyFilter === 6 ? records.find((record) => record.family === familyFilter) : records[0];
    if (!match) {
      const error: NodeJS.ErrnoException = new Error(
        `Blocked Target URL: no IPv${familyFilter} address found for "${hostname}"`,
      );
      process.nextTick(callback, error, '', 0);
      return;
    }

    process.nextTick(callback, null, match.address, match.family);
  };
};

const mapTunnelError = (url: TargetUrl, redactedProxy: string, timeoutMs: number, error: TunnelError): FetchError =>
  error.kind === 'timeout'
    ? { kind: 'timeout', message: `Request timed out after ${timeoutMs}ms fetching ${url}` }
    : { kind: 'network_error', message: `Network error fetching ${url} via proxy ${redactedProxy}: ${error.message}` };

const openProxyTunnelIfNeeded = async (
  parsedProxy: URL,
  targetUrl: URL,
  timeoutMs: number,
): Promise<Result<net.Socket | undefined, TunnelError>> => {
  const isHttpProxy = parsedProxy.protocol === 'http:' || parsedProxy.protocol === 'https:';
  if (isHttpProxy && targetUrl.protocol === 'http:') {
    return ok(undefined);
  }

  let baseSocket: Result<net.Socket, TunnelError>;
  if (isHttpProxy) {
    baseSocket = await openHttpConnectTunnel(parsedProxy, targetUrl, timeoutMs);
  } else if (parsedProxy.protocol === 'socks4:' || parsedProxy.protocol === 'socks4a:') {
    baseSocket = await openSocks4Tunnel(parsedProxy, targetUrl, timeoutMs);
  } else if (parsedProxy.protocol === 'socks5:' || parsedProxy.protocol === 'socks5h:') {
    baseSocket = await openSocks5Tunnel(parsedProxy, targetUrl, timeoutMs);
  } else {
    return err({ kind: 'proxy_error', message: `Unsupported proxy protocol "${parsedProxy.protocol}"` });
  }

  if (!baseSocket.ok) return baseSocket;

  if (targetUrl.protocol === 'https:') {
    return wrapTlsOverTunnel(baseSocket.value, targetUrl, timeoutMs);
  }
  return baseSocket;
};

/**
 * Real IP-pinned HTTP(S) GET port implementing `HttpGetPort` (D5, D8, D9, D18, D23, I2, I5).
 * Pins direct connections strictly to `pinnedIps`; routes proxied connections through HTTP, HTTPS CONNECT,
 * or SOCKS4/4a/5/5h tunnels with credential-redacted error reporting.
 */
export const createRealHttpGet = (options: RealHttpGetOptions = {}): HttpGetPort => {
  const maxBytes = options.maxBytes ?? MAX_RESPONSE_BYTES;
  const timeoutMs = options.timeoutMs ?? REQUEST_TIMEOUT_MS;

  return async (
    url: TargetUrl,
    headers: Headers,
    pinnedIps: readonly ResolvedIp[],
    proxyUrl?: string,
  ): Promise<Result<WireResponse, FetchError>> => {
    const targetUrl = new URL(url);
    const parsedProxy = proxyUrl !== undefined ? new URL(proxyUrl) : undefined;
    const redactedProxy = proxyUrl !== undefined ? redactProxyUrl(proxyUrl) : undefined;

    let tunnelSocket: net.Socket | undefined;
    if (parsedProxy && redactedProxy) {
      const opened = await openProxyTunnelIfNeeded(parsedProxy, targetUrl, timeoutMs);
      if (!opened.ok) {
        return err(mapTunnelError(url, redactedProxy, timeoutMs, opened.error));
      }
      tunnelSocket = opened.value;
    }

    return new Promise((resolve) => {
      let settled = false;
      const finish = (result: Result<WireResponse, FetchError>): void => {
        if (settled) return;
        settled = true;
        resolve(result);
      };

      const networkErrorMessage = (detail: string): string =>
        redactedProxy
          ? `Network error fetching ${url} via proxy ${redactedProxy}: ${detail}`
          : `Network error fetching ${url}: ${detail}`;

      const onResponse = (res: http.IncomingMessage): void => {
        const status = res.statusCode ?? 0;
        const resHeaders = normalizeIncomingHeaders(res.headers);
        const location = resHeaders.location;

        if (REDIRECT_STATUS_CODES.has(status) && location !== undefined && location.length > 0) {
          res.destroy();
          finish(ok({ status, url, headers: resHeaders, rawBytes: new Uint8Array(0) }));
          return;
        }

        const contentLengthStr = resHeaders['content-length'];
        if (contentLengthStr !== undefined) {
          const declared = Number.parseInt(contentLengthStr, 10);
          if (!Number.isNaN(declared) && declared > maxBytes) {
            res.destroy();
            req.destroy();
            finish(
              err({
                kind: 'response_too_large',
                message: `Response too large: ${contentLengthStr.trim()} bytes exceeds ${maxBytes} byte limit`,
              }),
            );
            return;
          }
        }

        const chunks: Buffer[] = [];
        let totalBytes = 0;

        res.on('data', (chunk: Buffer) => {
          totalBytes += chunk.byteLength;
          if (totalBytes > maxBytes) {
            res.destroy();
            req.destroy();
            finish(
              err({
                kind: 'response_too_large',
                message: `Response too large: exceeded ${maxBytes} byte limit`,
              }),
            );
            return;
          }
          chunks.push(chunk);
        });

        res.on('end', () => {
          finish(
            ok({
              status,
              url,
              headers: resHeaders,
              rawBytes: new Uint8Array(Buffer.concat(chunks)),
            }),
          );
        });

        res.on('error', (error: Error) => {
          finish(err({ kind: 'network_error', message: networkErrorMessage(error.message) }));
        });
      };

      let req: http.ClientRequest;

      try {
        if (parsedProxy && !tunnelSocket) {
          // HTTP or HTTPS proxy forwarding an http: target via absolute-URI request
          const proxyAuth = buildProxyAuthHeader(parsedProxy);
          const reqHeaders: Record<string, string> = {
            ...headers,
            Host: targetUrl.host,
            ...(proxyAuth ? { 'Proxy-Authorization': proxyAuth } : {}),
          };
          const transport = parsedProxy.protocol === 'https:' ? https : http;
          req = transport.request(
            {
              protocol: parsedProxy.protocol,
              hostname: normalizeHostname(parsedProxy.hostname),
              port: getEffectivePort(parsedProxy),
              path: targetUrl.href,
              method: 'GET',
              headers: reqHeaders,
              agent: false,
              timeout: timeoutMs,
            },
            onResponse,
          );
        } else if (tunnelSocket) {
          const established = tunnelSocket;
          const isHttps = targetUrl.protocol === 'https:';
          const transport = isHttps ? https : http;
          const agent = isHttps ? new SingleHttpsTunnelAgent(established) : new SingleHttpTunnelAgent(established);
          req = transport.request(
            {
              protocol: targetUrl.protocol,
              hostname: normalizeHostname(targetUrl.hostname),
              port: getEffectivePort(targetUrl),
              path: `${targetUrl.pathname}${targetUrl.search}`,
              method: 'GET',
              headers: { ...headers },
              agent,
              timeout: timeoutMs,
            },
            onResponse,
          );
        } else {
          const transport = targetUrl.protocol === 'https:' ? https : http;
          const lookup = createPinnedLookup(pinnedIps);
          req = transport.request(
            {
              protocol: targetUrl.protocol,
              hostname: normalizeHostname(targetUrl.hostname),
              port: getEffectivePort(targetUrl),
              path: `${targetUrl.pathname}${targetUrl.search}`,
              method: 'GET',
              headers: { ...headers },
              agent: false,
              lookup,
              timeout: timeoutMs,
            },
            onResponse,
          );
        }
      } catch (error: unknown) {
        tunnelSocket?.destroy();
        const code = typeof error === 'object' && error !== null && 'code' in error ? String(error.code) : '';
        const detail = error instanceof Error ? error.message : String(error);
        if (code === 'ERR_INVALID_HTTP_TOKEN' || code === 'ERR_INVALID_CHAR') {
          finish(err({ kind: 'invalid_request', message: detail }));
          return;
        }
        finish(err({ kind: 'network_error', message: networkErrorMessage(detail) }));
        return;
      }

      req.on('timeout', () => {
        req.destroy();
        tunnelSocket?.destroy();
        finish(err({ kind: 'timeout', message: `Request timed out after ${timeoutMs}ms fetching ${url}` }));
      });

      req.on('error', (error: Error) => {
        tunnelSocket?.destroy();
        if (error.message.startsWith('Blocked Target URL:')) {
          finish(err({ kind: 'blocked_url', message: error.message }));
          return;
        }
        finish(err({ kind: 'network_error', message: networkErrorMessage(error.message) }));
      });

      req.end();
    });
  };
};
