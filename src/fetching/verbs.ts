import { err, ok, type Result } from '../shared/result.ts';
import {
  type FetchError,
  type FetchRequest,
  type Headers,
  type RawFetchInput,
  type RawResponse,
  type RedirectStep,
  RenderedOutput,
  ResolvedIp,
  TargetUrl,
  WEB_FORMATS,
  type WebFormat,
} from './nouns.ts';
import { isIpLiteral, isReservedIp, normalizeHostname, stripCrossOriginHeaders } from './queries.ts';

export const DEFAULT_LIMIT = 5000;
export const MAX_REDIRECTS = 10;

const isWebFormat = (value: string): value is WebFormat => (WEB_FORMATS as readonly string[]).includes(value);

const isLocalHostname = (host: string): boolean => host === '' || host === 'localhost' || host.endsWith('.localhost');

const isNonNegativeInt = (n: number): boolean => Number.isInteger(n) && n >= 0;

const validateParsedUrl = (parsed: URL): Result<TargetUrl, FetchError> => {
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return err({
      kind: 'blocked_url',
      message: `Blocked Target URL: disallowed scheme "${parsed.protocol}" (only http: and https: are allowed)`,
    });
  }

  const host = normalizeHostname(parsed.hostname);
  if (isLocalHostname(host) || (isIpLiteral(host) && isReservedIp(host))) {
    return err({ kind: 'blocked_url', message: `Blocked Target URL: private address "${host}"` });
  }

  return ok(TargetUrl(parsed.href));
};

/**
 * Validates a raw Fetch Request against Format, Window bounds, and Target URL rules (D4, D8, D9, D14, I1).
 */
export const prepareFetch = (
  input: RawFetchInput,
  defaultLimit: number = DEFAULT_LIMIT,
): Result<FetchRequest, FetchError> => {
  if (!isWebFormat(input.format)) {
    return err({ kind: 'invalid_request', message: `Unsupported Format: "${input.format}"` });
  }

  let parsed: URL;
  try {
    parsed = new URL(input.url);
  } catch {
    return err({ kind: 'invalid_request', message: `Invalid Target URL: "${input.url}"` });
  }

  const validatedUrl = validateParsedUrl(parsed);
  if (!validatedUrl.ok) return validatedUrl;

  const startIndex = input.startIndex ?? 0;
  if (!isNonNegativeInt(startIndex)) {
    return err({ kind: 'invalid_request', message: 'Invalid startIndex: must be a non-negative integer' });
  }

  const maxLength = input.maxLength ?? defaultLimit;
  if (!isNonNegativeInt(maxLength)) {
    return err({ kind: 'invalid_request', message: 'Invalid maxLength: must be a non-negative integer' });
  }

  return ok({
    url: validatedUrl.value,
    format: input.format,
    headers: input.headers ?? {},
    window: { startIndex, maxLength },
  });
};

/**
 * Validates all DNS records returned for a hostname on direct connections (D8, I2).
 * Fails closed on empty results or any reserved/malformed IP.
 */
export const validateResolvedIps = (
  hostname: string,
  addresses: readonly string[],
): Result<readonly ResolvedIp[], FetchError> => {
  if (addresses.length === 0) {
    return err({
      kind: 'blocked_url',
      message: `Blocked Target URL: DNS lookup returned no addresses for "${hostname}"`,
    });
  }

  const validated: ResolvedIp[] = [];
  for (const ip of addresses) {
    if (isReservedIp(ip)) {
      return err({
        kind: 'blocked_url',
        message: `Blocked Target URL: hostname "${hostname}" resolved to private IP "${ip}"`,
      });
    }
    validated.push(ResolvedIp(ip));
  }

  return ok(validated);
};

/**
 * Validates one HTTP redirect hop, enforcing maxRedirects, per-hop SSRF checks,
 * and cross-origin sensitive header stripping (D8, D9, I1, I4).
 */
export const validateRedirectHop = (
  currentUrl: TargetUrl,
  location: string,
  headers: Headers,
  hop: number,
  maxRedirects: number = MAX_REDIRECTS,
): Result<RedirectStep, FetchError> => {
  if (hop >= maxRedirects) {
    return err({
      kind: 'too_many_redirects',
      message: `Too many redirects (exceeded ${maxRedirects})`,
    });
  }

  let currentParsed: URL;
  let nextParsed: URL;
  try {
    currentParsed = new URL(currentUrl);
    nextParsed = new URL(location, currentParsed);
  } catch {
    return err({ kind: 'invalid_request', message: `Invalid redirect Location: "${location}"` });
  }

  const validatedNext = validateParsedUrl(nextParsed);
  if (!validatedNext.ok) return validatedNext;

  const nextHeaders = nextParsed.origin !== currentParsed.origin ? stripCrossOriginHeaders(headers) : headers;

  return ok({
    nextUrl: validatedNext.value,
    headers: nextHeaders,
  });
};

/**
 * Evaluates a Raw Response for a Fetch Request and produces Rendered Output (D14, D16, D17).
 */
export const evaluateResponse = (request: FetchRequest, response: RawResponse): Result<RenderedOutput, FetchError> => {
  if (response.status < 200 || response.status >= 300) {
    return err({
      kind: 'http_error',
      message: `HTTP error ${response.status} fetching ${request.url}`,
    });
  }

  switch (request.format) {
    case 'html':
      return ok(RenderedOutput(response.body));
    default:
      return request.format satisfies never;
  }
};
