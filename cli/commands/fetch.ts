import type { Headers } from '../../src/fetching/nouns.ts';
import { isIpLiteral, normalizeHostname, windowedExcerpt } from '../../src/fetching/queries.ts';
import { evaluateResponse, prepareFetch, validateRedirectHop, validateResolvedIps } from '../../src/fetching/verbs.ts';
import { err, ok, type Result } from '../../src/shared/result.ts';
import type { Command } from '../command.ts';

const REDIRECT_STATUS_CODES = new Set([301, 302, 303, 307, 308]);

const parseNumberArg = (flag: string, raw: string | undefined): Result<number, string> => {
  if (raw === undefined) {
    return err(`Missing value for ${flag}`);
  }
  const n = Number(raw);
  if (raw.trim() === '' || Number.isNaN(n)) {
    return err(`Invalid ${flag === '--start-index' ? 'startIndex' : 'maxLength'}: must be a non-negative integer`);
  }
  return ok(n);
};

const parseHeaderArg = (raw: string | undefined): Result<readonly [string, string], string> => {
  if (raw === undefined) {
    return err('Missing value for --header');
  }
  const idx = raw.indexOf(':');
  if (idx <= 0) {
    return err(`Invalid header "${raw}": expected Key:Value`);
  }
  return ok([raw.slice(0, idx).trim(), raw.slice(idx + 1).trim()]);
};

const findHeaderCaseInsensitive = (headers: Headers, target: string): string | undefined => {
  const lower = target.toLowerCase();
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === lower) return value;
  }
  return undefined;
};

export const fetchCommand: Command = {
  kind: 'domain',
  usage: 'fetch <format> <url> [--start-index <N>] [--max-length <N>] [--header <Key:Value>]...',
  summary: 'fetch a Target URL in Format and return a Windowed Excerpt',
  run: async (args, world) => {
    const [format, url, ...rest] = args;
    if (!format || !url) {
      return err('usage: fetch <format> <url> [--start-index <N>] [--max-length <N>] [--header <Key:Value>]...');
    }

    let startIndex: number | undefined;
    let maxLength: number | undefined;
    const headers: Record<string, string> = {};

    for (let i = 0; i < rest.length; i++) {
      const flag = rest[i];
      if (flag === '--start-index') {
        const parsed = parseNumberArg(flag, rest[i + 1]);
        if (!parsed.ok) return parsed;
        startIndex = parsed.value;
        i++;
      } else if (flag === '--max-length') {
        const parsed = parseNumberArg(flag, rest[i + 1]);
        if (!parsed.ok) return parsed;
        maxLength = parsed.value;
        i++;
      } else if (flag === '--header') {
        const parsed = parseHeaderArg(rest[i + 1]);
        if (!parsed.ok) return parsed;
        const [k, v] = parsed.value;
        headers[k] = v;
        i++;
      } else {
        return err(`Unknown flag: ${flag}`);
      }
    }

    const prepared = prepareFetch({
      url,
      format,
      headers,
      ...(startIndex !== undefined ? { startIndex } : {}),
      ...(maxLength !== undefined ? { maxLength } : {}),
    });
    if (!prepared.ok) return err(prepared.error.message);

    let currentUrl = prepared.value.url;
    let currentHeaders = prepared.value.headers;

    for (let hop = 0; ; hop++) {
      const host = normalizeHostname(new URL(currentUrl).hostname);
      if (!isIpLiteral(host)) {
        const lookup = await world.dns.lookup(host);
        if (!lookup.ok) return err(lookup.error.message);
        const validatedIps = validateResolvedIps(host, lookup.value);
        if (!validatedIps.ok) return err(validatedIps.error.message);
      }

      const response = await world.origin.get(currentUrl, currentHeaders);
      if (!response.ok) return err(response.error.message);

      const location = findHeaderCaseInsensitive(response.value.headers, 'location');
      if (REDIRECT_STATUS_CODES.has(response.value.status) && location !== undefined && location.length > 0) {
        const nextHop = validateRedirectHop(currentUrl, location, currentHeaders, hop);
        if (!nextHop.ok) return err(nextHop.error.message);
        currentUrl = nextHop.value.nextUrl;
        currentHeaders = nextHop.value.headers;
        continue;
      }

      const rendered = evaluateResponse(
        { ...prepared.value, url: currentUrl, headers: currentHeaders },
        response.value,
      );
      if (!rendered.ok) return err(rendered.error.message);

      const excerpt = windowedExcerpt(rendered.value, prepared.value.window);
      if (excerpt.length === 0) {
        return ok(['(empty)']);
      }
      const lines = excerpt.split('\n').map((line) => (line.length > 0 ? `| ${line}` : '|'));
      return ok(lines);
    }
  },
};
