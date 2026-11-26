import { executeFetch } from '../../src/fetching/execute.ts';
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
      },
    );

    if (!result.ok) return err(result.error.message);
    if (result.value.length === 0) return ok(['(empty)']);
    return ok(result.value.split('\n').map((line) => (line.length > 0 ? `| ${line}` : '|')));
  },
};
