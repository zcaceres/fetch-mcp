import { executeFetch } from '../../src/fetching/execute.ts';
import type { ResolveProxyPort } from '../../src/fetching/ports.ts';
import { normalizeHostname } from '../../src/fetching/queries.ts';
import { validateResolvedIps } from '../../src/fetching/verbs.ts';
import { parseOperatorLimits, resolveProxyPolicy } from '../../src/policy/verbs.ts';
import { err, ok, type Result } from '../../src/shared/result.ts';
import { executeFetchTranscript } from '../../src/transcript/execute.ts';
import type { CheckHostPort, FetchPagePort, ResolveTranscriptProxyPort } from '../../src/transcript/ports.ts';
import type { Command } from '../command.ts';

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

const unescapeControlChars = (value: string): string => value.replace(/\\r/g, '\r').replace(/\\n/g, '\n');

const parseHeaderArg = (raw: string | undefined): Result<readonly [string, string], string> => {
  if (raw === undefined) {
    return err('Missing value for --header');
  }
  const decoded = unescapeControlChars(raw);
  const idx = decoded.indexOf(':');
  if (idx <= 0) {
    return err(`Invalid header "${raw}": expected Key:Value`);
  }
  return ok([decoded.slice(0, idx).trim(), decoded.slice(idx + 1).trim()]);
};

export const fetchTranscriptCommand: Command = {
  kind: 'domain',
  usage:
    'fetch-transcript <url> [--lang <code>] [--start-index <N>] [--max-length <N>] [--header <Key:Value>]... [--proxy <url>]',
  summary: 'fetch a YouTube video transcript and return a Windowed Excerpt',
  run: async (args, world) => {
    const [url, ...rest] = args;
    if (!url) {
      return err(
        'usage: fetch-transcript <url> [--lang <code>] [--start-index <N>] [--max-length <N>] [--header <Key:Value>]... [--proxy <url>]',
      );
    }

    let lang: string | undefined;
    let startIndex: number | undefined;
    let maxLength: number | undefined;
    let proxy: string | undefined;
    const headers: Record<string, string> = {};

    for (let i = 0; i < rest.length; i++) {
      const flag = rest[i];
      if (flag === '--lang') {
        const value = rest[i + 1];
        if (value === undefined) return err('Missing value for --lang');
        lang = value;
        i++;
      } else if (flag === '--start-index') {
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
        if (!(k in headers) || !/[\r\n]/.test(headers[k] ?? '')) {
          headers[k] = v;
        }
        i++;
      } else if (flag === '--proxy') {
        const value = rest[i + 1];
        if (value === undefined) return err('Missing value for --proxy');
        proxy = value;
        i++;
      } else {
        return err(`Unknown flag: ${flag}`);
      }
    }

    const envMap = Object.fromEntries(world.env.entries());
    const limits = parseOperatorLimits(envMap);
    if (!limits.ok) return err(limits.error.message);

    const resolveFetchProxy: ResolveProxyPort = (targetUrl) => {
      const resolved = resolveProxyPolicy(targetUrl, envMap, proxy);
      if (!resolved.ok) {
        return err({ kind: 'invalid_request', message: resolved.error.message });
      }
      return ok(resolved.value.kind === 'proxy' ? String(resolved.value.url) : undefined);
    };

    const resolveTranscriptProxy: ResolveTranscriptProxyPort = (targetUrl) => {
      const resolved = resolveProxyPolicy(targetUrl, envMap, proxy);
      if (!resolved.ok) {
        return err({ kind: 'invalid_request', message: resolved.error.message });
      }
      return ok(resolved.value.kind === 'proxy' ? String(resolved.value.url) : undefined);
    };

    const fetchPage: FetchPagePort = async (targetUrl, reqHeaders) => {
      const res = await executeFetch(
        { url: targetUrl, format: 'html', headers: reqHeaders, maxLength: 0 },
        { httpGet: world.origin.get, dnsLookup: world.dns.lookup, resolveProxy: resolveFetchProxy },
        { maxResponseBytes: limits.value.maxResponseBytes },
      );
      if (!res.ok) {
        const kind = res.error.kind === 'blocked_url' ? 'blocked_url' : 'fetch_error';
        return err({ kind, message: res.error.message });
      }
      return ok(String(res.value));
    };

    const checkHost: CheckHostPort = async (hostname) => {
      const host = normalizeHostname(hostname);
      const lookup = await world.dns.lookup(host);
      if (!lookup.ok) {
        return err({ kind: 'blocked_url', message: lookup.error.message });
      }
      const validated = validateResolvedIps(host, lookup.value);
      if (!validated.ok) {
        return err({ kind: 'blocked_url', message: validated.error.message });
      }
      return ok(undefined);
    };

    const result = await executeFetchTranscript(
      {
        url,
        headers,
        ...(lang !== undefined ? { lang } : {}),
        ...(startIndex !== undefined ? { startIndex } : {}),
        ...(maxLength !== undefined ? { maxLength } : {}),
      },
      { fetchPage, checkHost, resolveProxy: resolveTranscriptProxy, ytDlp: world.ytdlp },
      { defaultLimit: limits.value.defaultLimit },
    );

    if (!result.ok) return err(result.error.message);
    if (result.value.length === 0) return ok(['(empty)']);
    return ok(result.value.split('\n').map((line) => (line.length > 0 ? `| ${line}` : '|')));
  },
};
