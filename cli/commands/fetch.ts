import { executeFetch } from '../../src/fetching/execute.ts';
import type { ResolveProxyPort } from '../../src/fetching/ports.ts';
import { parseOperatorLimits, resolveProxyPolicy } from '../../src/policy/verbs.ts';
import { err, ok, type Result } from '../../src/shared/result.ts';
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

export const fetchCommand: Command = {
  kind: 'domain',
  usage: 'fetch <format> <url> [--start-index <N>] [--max-length <N>] [--header <Key:Value>]... [--proxy <url>]',
  summary: 'fetch a Target URL in Format and return a Windowed Excerpt',
  run: async (args, world) => {
    const [format, url, ...rest] = args;
    if (!format || !url) {
      return err(
        'usage: fetch <format> <url> [--start-index <N>] [--max-length <N>] [--header <Key:Value>]... [--proxy <url>]',
      );
    }

    let startIndex: number | undefined;
    let maxLength: number | undefined;
    let proxy: string | undefined;
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

    const resolveProxy: ResolveProxyPort = (targetUrl) => {
      const resolved = resolveProxyPolicy(targetUrl, envMap, proxy);
      if (!resolved.ok) {
        return err({ kind: 'invalid_request', message: resolved.error.message });
      }
      return ok(resolved.value.kind === 'proxy' ? String(resolved.value.url) : undefined);
    };

    const result = await executeFetch(
      {
        url,
        format,
        headers,
        ...(startIndex !== undefined ? { startIndex } : {}),
        ...(maxLength !== undefined ? { maxLength } : {}),
      },
      {
        httpGet: world.origin.get,
        dnsLookup: world.dns.lookup,
        resolveProxy,
      },
      {
        defaultLimit: limits.value.defaultLimit,
        maxResponseBytes: limits.value.maxResponseBytes,
      },
    );

    if (!result.ok) return err(result.error.message);
    if (result.value.length === 0) return ok(['(empty)']);
    return ok(result.value.split('\n').map((line) => (line.length > 0 ? `| ${line}` : '|')));
  },
};
