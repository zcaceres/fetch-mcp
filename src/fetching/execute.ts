import type { Result } from '../shared/result.ts';
import { type FetchError, type Headers, type RawFetchInput, ResolvedIp, type WindowedExcerpt } from './nouns.ts';
import type { FetchPorts } from './ports.ts';
import { isIpLiteral, normalizeHostname, windowedExcerpt } from './queries.ts';
import {
  DEFAULT_LIMIT,
  decodeResponseBody,
  evaluateResponse,
  MAX_REDIRECTS,
  MAX_RESPONSE_BYTES,
  prepareFetch,
  validateRawResponseSize,
  validateRedirectHop,
  validateResolvedIps,
} from './verbs.ts';

const REDIRECT_STATUS_CODES = new Set([301, 302, 303, 307, 308]);

export type ExecuteFetchOptions = {
  readonly defaultLimit?: number;
  readonly maxResponseBytes?: number;
  readonly maxRedirects?: number;
};

const findHeaderCaseInsensitive = (headers: Headers, target: string): string | undefined => {
  const lower = target.toLowerCase();
  let found: string | undefined;
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === lower) found = value;
  }
  return found;
};

/**
 * Shared port-injected orchestration for `fetch` used by the harness, CLI, and MCP server.
 * Performs no direct I/O; delegates network and DNS access solely through `ports`.
 */
export const executeFetch = async (
  input: RawFetchInput,
  ports: FetchPorts,
  options: ExecuteFetchOptions = {},
): Promise<Result<WindowedExcerpt, FetchError>> => {
  const defaultLimit = options.defaultLimit ?? DEFAULT_LIMIT;
  const maxResponseBytes = options.maxResponseBytes ?? MAX_RESPONSE_BYTES;
  const maxRedirects = options.maxRedirects ?? MAX_REDIRECTS;

  const prepared = prepareFetch(input, defaultLimit);
  if (!prepared.ok) return prepared;

  let currentUrl = prepared.value.url;
  let currentHeaders = prepared.value.headers;

  for (let hop = 0; ; hop++) {
    let proxyUrl: string | undefined;
    if (ports.resolveProxy) {
      const resolvedProxy = ports.resolveProxy(currentUrl);
      if (!resolvedProxy.ok) return resolvedProxy;
      proxyUrl = resolvedProxy.value;
    }

    const host = normalizeHostname(new URL(currentUrl).hostname);
    let pinnedIps: readonly ResolvedIp[];

    if (proxyUrl !== undefined) {
      // Delegated hostname DNS to proxy per D8/D23; local URL & reserved-IP literal SSRF validation already ran.
      pinnedIps = [];
    } else if (isIpLiteral(host)) {
      pinnedIps = [ResolvedIp(host)];
    } else {
      const lookup = await ports.dnsLookup(host);
      if (!lookup.ok) return lookup;
      const validated = validateResolvedIps(host, lookup.value);
      if (!validated.ok) return validated;
      pinnedIps = validated.value;
    }

    const wire = await ports.httpGet(currentUrl, currentHeaders, pinnedIps, proxyUrl);
    if (!wire.ok) return wire;

    const rawSizeCheck = validateRawResponseSize(wire.value.headers, wire.value.rawBytes, maxResponseBytes);
    if (!rawSizeCheck.ok) return rawSizeCheck;

    const location = findHeaderCaseInsensitive(wire.value.headers, 'location')?.trim();
    if (REDIRECT_STATUS_CODES.has(wire.value.status) && location !== undefined && location.length > 0) {
      const nextHop = validateRedirectHop(currentUrl, location, currentHeaders, hop, maxRedirects);
      if (!nextHop.ok) return nextHop;
      currentUrl = nextHop.value.nextUrl;
      currentHeaders = nextHop.value.headers;
      continue;
    }

    if (wire.value.status < 200 || wire.value.status >= 300) {
      return {
        ok: false,
        error: {
          kind: 'http_error',
          message: `HTTP error ${wire.value.status} fetching ${currentUrl}`,
        },
      };
    }

    const body = decodeResponseBody(currentUrl, wire.value.headers, wire.value.rawBytes, maxResponseBytes);
    if (!body.ok) return body;

    const rendered = evaluateResponse(
      { ...prepared.value, url: currentUrl, headers: currentHeaders },
      {
        status: wire.value.status,
        url: wire.value.url,
        headers: wire.value.headers,
        body: body.value,
      },
    );
    if (!rendered.ok) return rendered;

    return { ok: true, value: windowedExcerpt(rendered.value, prepared.value.window) };
  }
};
