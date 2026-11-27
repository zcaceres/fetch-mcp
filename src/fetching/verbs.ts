import zlib from 'node:zlib';
import { Readability } from '@mozilla/readability';
import { JSDOM } from 'jsdom';
import TurndownService from 'turndown';
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
import {
  isBinaryContentType,
  isIpLiteral,
  isReservedIp,
  normalizeHostname,
  stripCrossOriginHeaders,
} from './queries.ts';

export const DEFAULT_LIMIT = 5000;
export const MAX_REDIRECTS = 10;
export const MAX_RESPONSE_BYTES = 10 * 1024 * 1024;
export const REQUEST_TIMEOUT_MS = 30_000;
export const DEFAULT_USER_AGENT =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
const DEFAULT_ACCEPT_ENCODING = 'gzip, deflate, br';
const CRLF_REGEX = /[\r\n]/;
const HTTP_HEADER_NAME_REGEX = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;

const hasInvalidHeaderValueChar = (value: string): boolean => {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if ((code < 0x20 && code !== 0x09) || code === 0x7f || code > 0xff) {
      return true;
    }
  }
  return false;
};

const sanitizeAndDefaultHeaders = (rawHeaders: Headers | undefined): Result<Headers, FetchError> => {
  const deduped = new Map<string, readonly [string, string]>();

  for (const [key, value] of Object.entries(rawHeaders ?? {})) {
    if (CRLF_REGEX.test(key) || CRLF_REGEX.test(value)) {
      return err({
        kind: 'invalid_request',
        message: `Invalid header ${JSON.stringify(key)}: CR/LF control characters are not allowed`,
      });
    }
    if (!HTTP_HEADER_NAME_REGEX.test(key)) {
      return err({
        kind: 'invalid_request',
        message: `Invalid header ${JSON.stringify(key)}: header name must be a valid HTTP token`,
      });
    }
    if (hasInvalidHeaderValueChar(value)) {
      return err({
        kind: 'invalid_request',
        message: `Invalid header ${JSON.stringify(key)}: invalid character in header value`,
      });
    }
    deduped.set(key.toLowerCase(), [key, value]);
  }

  const result: Record<string, string> = {};
  if (!deduped.has('user-agent')) {
    result['User-Agent'] = DEFAULT_USER_AGENT;
  }
  if (!deduped.has('accept-encoding')) {
    result['Accept-Encoding'] = DEFAULT_ACCEPT_ENCODING;
  }
  for (const [key, value] of deduped.values()) {
    result[key] = value;
  }
  return ok(result);
};

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

  const normalizedHeaders = sanitizeAndDefaultHeaders(input.headers);
  if (!normalizedHeaders.ok) return normalizedHeaders;

  return ok({
    url: validatedUrl.value,
    format: input.format,
    headers: normalizedHeaders.value,
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

const findHeaderCaseInsensitive = (headers: Headers, name: string): string | undefined => {
  const lower = name.toLowerCase();
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === lower) return value;
  }
  return undefined;
};

const stripScriptAndStyle = (document: Document): void => {
  for (const tag of ['script', 'style']) {
    for (const el of Array.from(document.getElementsByTagName(tag))) {
      el.remove();
    }
  }
};

const isBufferTooLargeError = (error: unknown): boolean => {
  if (!(error instanceof Error)) return false;
  if ('code' in error && error.code === 'ERR_BUFFER_TOO_LARGE') return true;
  return error.message.includes('Cannot create a Buffer larger than');
};

/**
 * Enforces MAX_RESPONSE_BYTES on declared Content-Length, raw wire bytes, and decompressed output,
 * decompressing gzip/x-gzip/deflate/br and passing unknown encodings through unchanged (D9, D14, D17, I5).
 */
export const decodeResponseBody = (
  url: TargetUrl,
  headers: Headers,
  rawBytes: Uint8Array,
  maxBytes: number = MAX_RESPONSE_BYTES,
): Result<string, FetchError> => {
  const contentLength = findHeaderCaseInsensitive(headers, 'content-length');
  if (contentLength !== undefined) {
    const declared = Number.parseInt(contentLength, 10);
    if (!Number.isNaN(declared) && declared > maxBytes) {
      return err({
        kind: 'response_too_large',
        message: `Response too large: ${contentLength.trim()} bytes exceeds ${maxBytes} byte limit`,
      });
    }
  }

  if (rawBytes.byteLength > maxBytes) {
    return err({
      kind: 'response_too_large',
      message: `Response too large: exceeded ${maxBytes} byte limit`,
    });
  }

  const encoding = (findHeaderCaseInsensitive(headers, 'content-encoding') ?? '').trim().toLowerCase();
  let decoded: Uint8Array = rawBytes;

  if (encoding === 'gzip' || encoding === 'x-gzip' || encoding === 'deflate' || encoding === 'br') {
    try {
      const opts = { maxOutputLength: maxBytes };
      if (encoding === 'gzip' || encoding === 'x-gzip') {
        decoded = zlib.gunzipSync(rawBytes, opts);
      } else if (encoding === 'deflate') {
        decoded = zlib.inflateSync(rawBytes, opts);
      } else {
        decoded = zlib.brotliDecompressSync(rawBytes, opts);
      }
    } catch (error: unknown) {
      if (isBufferTooLargeError(error)) {
        return err({
          kind: 'response_too_large',
          message: `Response too large: exceeded ${maxBytes} byte limit`,
        });
      }
      return err({
        kind: 'decode_error',
        message: `Failed to decompress ${encoding} response from ${url}`,
      });
    }
  }

  if (decoded.byteLength > maxBytes) {
    return err({
      kind: 'response_too_large',
      message: `Response too large: exceeded ${maxBytes} byte limit`,
    });
  }

  return ok(new TextDecoder('utf-8').decode(decoded));
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

  const contentType = findHeaderCaseInsensitive(response.headers, 'content-type');
  if (isBinaryContentType(contentType)) {
    const mediaType = (contentType?.split(';')[0] ?? '').trim().toLowerCase();
    return err({
      kind: 'unsupported_content_type',
      message: `Unsupported binary Content-Type "${mediaType}" fetching ${request.url}`,
    });
  }

  switch (request.format) {
    case 'html':
      return ok(RenderedOutput(response.body));

    case 'json': {
      try {
        const parsed: unknown = JSON.parse(response.body);
        return ok(RenderedOutput(JSON.stringify(parsed)));
      } catch {
        return err({
          kind: 'parse_error',
          message: `Invalid JSON response from ${request.url}`,
        });
      }
    }

    case 'text': {
      const dom = new JSDOM(response.body);
      stripScriptAndStyle(dom.window.document);
      const rawText = dom.window.document.body?.textContent ?? '';
      return ok(RenderedOutput(rawText.replace(/\s+/g, ' ').trim()));
    }

    case 'markdown': {
      const dom = new JSDOM(response.body);
      stripScriptAndStyle(dom.window.document);
      const turndown = new TurndownService();
      const bodyHtml = dom.window.document.body?.innerHTML ?? '';
      return ok(RenderedOutput(turndown.turndown(bodyHtml)));
    }

    case 'readable': {
      const dom = new JSDOM(response.body, { url: request.url });
      const reader = new Readability(dom.window.document);
      const article = reader.parse();
      if (!article) {
        return err({
          kind: 'parse_error',
          message: `Failed to parse readable content from ${request.url}`,
        });
      }
      const turndown = new TurndownService();
      const bodyMarkdown = turndown.turndown(article.content ?? '');
      const title = (article.title ?? '').trim();
      const combined =
        title.length > 0 ? (bodyMarkdown.length > 0 ? `# ${title}\n\n${bodyMarkdown}` : `# ${title}`) : bodyMarkdown;
      return ok(RenderedOutput(combined));
    }

    default:
      return request.format satisfies never;
  }
};
