import type dns from 'node:dns';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import type { FetchError, Headers, ResolvedIp, TargetUrl, WireResponse } from '../../fetching/nouns.ts';
import type { HttpGetPort } from '../../fetching/ports.ts';
import { normalizeHostname } from '../../fetching/queries.ts';
import { MAX_RESPONSE_BYTES, REQUEST_TIMEOUT_MS } from '../../fetching/verbs.ts';
import { err, ok, type Result } from '../../shared/result.ts';

const REDIRECT_STATUS_CODES = new Set([301, 302, 303, 307, 308]);
const SINGLE_VALUE_HEADERS = new Set(['location', 'content-length', 'content-type', 'content-encoding']);

export type RealHttpGetOptions = {
  readonly maxBytes?: number;
  readonly timeoutMs?: number;
};

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

const createPinnedLookup = (pinnedIps: readonly ResolvedIp[]): net.LookupFunction => {
  const records: dns.LookupAddress[] = pinnedIps.map((address) => ({
    address,
    family: net.isIPv6(address) ? 6 : 4,
  }));

  return (hostname, options, callback) => {
    const wantsAll = typeof options === 'object' && options !== null && options.all === true;

    if (records.length === 0) {
      const error: NodeJS.ErrnoException = new Error(`Blocked Target URL: no pinned IP available for "${hostname}"`);
      if (wantsAll) {
        callback(error, []);
      } else {
        callback(error, '', 0);
      }
      return;
    }

    if (wantsAll) {
      callback(null, records);
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
      callback(error, '', 0);
      return;
    }

    callback(null, match.address, match.family);
  };
};

/**
 * Real IP-pinned HTTP(S) GET port implementing `HttpGetPort` (D8, D9, D18, I2, I5).
 * Pins socket connections strictly to `pinnedIps`, streams wire bytes under `maxBytes`,
 * aborts on `timeoutMs`, and never auto-retries.
 */
export const createRealHttpGet = (options: RealHttpGetOptions = {}): HttpGetPort => {
  const maxBytes = options.maxBytes ?? MAX_RESPONSE_BYTES;
  const timeoutMs = options.timeoutMs ?? REQUEST_TIMEOUT_MS;

  return (
    url: TargetUrl,
    headers: Headers,
    pinnedIps: readonly ResolvedIp[],
  ): Promise<Result<WireResponse, FetchError>> =>
    new Promise((resolve) => {
      const targetUrl = new URL(url);
      const transport = targetUrl.protocol === 'https:' ? https : http;
      const lookup = createPinnedLookup(pinnedIps);

      let settled = false;
      const finish = (result: Result<WireResponse, FetchError>): void => {
        if (settled) return;
        settled = true;
        resolve(result);
      };

      const req = transport.request(
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
        (res) => {
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
            finish(err({ kind: 'network_error', message: `Network error fetching ${url}: ${error.message}` }));
          });
        },
      );

      req.on('timeout', () => {
        req.destroy();
        finish(err({ kind: 'timeout', message: `Request timed out after ${timeoutMs}ms fetching ${url}` }));
      });

      req.on('error', (error: Error) => {
        if (error.message.startsWith('Blocked Target URL:')) {
          finish(err({ kind: 'blocked_url', message: error.message }));
          return;
        }
        finish(err({ kind: 'network_error', message: `Network error fetching ${url}: ${error.message}` }));
      });

      req.end();
    });
};
