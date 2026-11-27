#!/usr/bin/env node

import { realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import pkg from '../package.json' with { type: 'json' };
import { executeFetch } from './fetching/execute.ts';
import { type Headers, WEB_FORMATS, type WebFormat } from './fetching/nouns.ts';
import type { FetchPorts, ResolveProxyPort } from './fetching/ports.ts';
import { normalizeHostname } from './fetching/queries.ts';
import { validateResolvedIps } from './fetching/verbs.ts';
import { createRealDnsLookup } from './integrations/dns/client.ts';
import { createRealHttpGet } from './integrations/origin/client.ts';
import { createRealYtDlp } from './integrations/ytdlp/client.ts';
import { parseOperatorLimits, resolveProxyPolicy } from './policy/verbs.ts';
import { err, ok, type Result } from './shared/result.ts';
import { executeFetchTranscript } from './transcript/execute.ts';
import type { CheckHostPort, FetchPagePort, ResolveTranscriptProxyPort, YtDlpPort } from './transcript/ports.ts';

const USAGE = `mcp-fetch v${pkg.version}

Usage: mcp-fetch <command> <url> [flags]

Commands:
  html        Fetch a URL and return raw HTML
  markdown    Fetch a URL and return Markdown
  readable    Fetch a URL and return article content as Markdown (via Readability)
  text        Fetch a URL and return plain text
  json        Fetch a URL and return JSON
  transcript  Fetch a YouTube video transcript

Flags:
  --header <Key:Value>  Custom request header (repeatable)
  --max-length <N>      Maximum characters to return
  --start-index <N>     Start from this character index
  --proxy <URL>         Proxy URL
  --lang <code>         Language code for YouTube transcripts (default: en)
  --help                Show this help message
  --version             Show version
`;

export type CliAction =
  | { readonly kind: 'help' }
  | { readonly kind: 'version' }
  | {
      readonly kind: 'fetch';
      readonly format: WebFormat;
      readonly url: string;
      readonly headers: Headers;
      readonly maxLength?: number;
      readonly startIndex?: number;
      readonly proxy?: string;
    }
  | {
      readonly kind: 'transcript';
      readonly url: string;
      readonly headers: Headers;
      readonly maxLength?: number;
      readonly startIndex?: number;
      readonly proxy?: string;
      readonly lang?: string;
    };

export type CliDeps = {
  readonly ports?: FetchPorts;
  readonly ytDlp?: YtDlpPort;
  readonly env?: NodeJS.ProcessEnv;
  readonly stdout?: (text: string) => void;
  readonly stderr?: (text: string) => void;
};

const isWebFormat = (value: string): value is WebFormat => (WEB_FORMATS as readonly string[]).includes(value);

const parseNonNegativeInt = (flag: string, value: string | undefined): Result<number, string> => {
  if (value === undefined || !/^\d+$/.test(value)) {
    return err(`${flag} requires a non-negative integer`);
  }
  return ok(Number.parseInt(value, 10));
};

const parseHeaderFlag = (value: string | undefined): Result<readonly [string, string], string> => {
  if (value === undefined || value.startsWith('--')) {
    return err('--header requires a Key:Value argument');
  }
  const idx = value.indexOf(':');
  if (idx <= 0) {
    return err(`Invalid --header "${value}": expected Key:Value`);
  }
  const key = value.slice(0, idx).trim();
  if (key.length === 0) {
    return err(`Invalid --header "${value}": expected Key:Value`);
  }
  return ok([key, value.slice(idx + 1).trim()]);
};

export const parseCliArgs = (argv: readonly string[]): Result<CliAction, string> => {
  if (argv.length === 0 || argv.includes('--help')) {
    return ok({ kind: 'help' });
  }
  if (argv.includes('--version')) {
    return ok({ kind: 'version' });
  }

  const subcommand = argv[0];
  if (subcommand === undefined || (!isWebFormat(subcommand) && subcommand !== 'transcript')) {
    return err(`Unknown command: ${subcommand ?? ''}\n\n${USAGE}`);
  }

  const url = argv[1];
  if (url === undefined || url.startsWith('--')) {
    return err(`Missing URL for "${subcommand}" command`);
  }

  const headers: Record<string, string> = {};
  let maxLength: number | undefined;
  let startIndex: number | undefined;
  let proxy: string | undefined;
  let lang: string | undefined;

  for (let i = 2; i < argv.length; i++) {
    const flag = argv[i];
    const value = argv[i + 1];
    switch (flag) {
      case '--header': {
        const parsed = parseHeaderFlag(value);
        if (!parsed.ok) return parsed;
        const [k, v] = parsed.value;
        headers[k] = v;
        i++;
        break;
      }
      case '--max-length': {
        const parsed = parseNonNegativeInt(flag, value);
        if (!parsed.ok) return parsed;
        maxLength = parsed.value;
        i++;
        break;
      }
      case '--start-index': {
        const parsed = parseNonNegativeInt(flag, value);
        if (!parsed.ok) return parsed;
        startIndex = parsed.value;
        i++;
        break;
      }
      case '--proxy':
        if (value === undefined || value.startsWith('--')) {
          return err('--proxy requires a value');
        }
        proxy = value;
        i++;
        break;
      case '--lang':
        if (value === undefined || value.startsWith('--')) {
          return err('--lang requires a value');
        }
        lang = value;
        i++;
        break;
      default:
        return err(`Unknown flag: ${flag ?? ''}`);
    }
  }

  if (subcommand === 'transcript') {
    return ok({
      kind: 'transcript',
      url,
      headers,
      ...(maxLength !== undefined ? { maxLength } : {}),
      ...(startIndex !== undefined ? { startIndex } : {}),
      ...(proxy !== undefined ? { proxy } : {}),
      ...(lang !== undefined ? { lang } : {}),
    });
  }

  return ok({
    kind: 'fetch',
    format: subcommand,
    url,
    headers,
    ...(maxLength !== undefined ? { maxLength } : {}),
    ...(startIndex !== undefined ? { startIndex } : {}),
    ...(proxy !== undefined ? { proxy } : {}),
  });
};

export const runCli = async (argv: readonly string[], deps: CliDeps = {}): Promise<number> => {
  const stdout = deps.stdout ?? ((text: string) => process.stdout.write(text));
  const stderr = deps.stderr ?? ((text: string) => process.stderr.write(text));
  const env = deps.env ?? process.env;

  const parsed = parseCliArgs(argv);
  if (!parsed.ok) {
    stderr(`${parsed.error}\n`);
    return 1;
  }

  const action = parsed.value;
  switch (action.kind) {
    case 'help':
      stdout(USAGE);
      return 0;

    case 'version':
      stdout(`${pkg.version}\n`);
      return 0;

    case 'transcript': {
      const limits = parseOperatorLimits(env);
      if (!limits.ok) {
        stderr(`${limits.error.message}\n`);
        return 1;
      }

      const { defaultLimit, maxResponseBytes } = limits.value;
      const resolveFetchProxy: ResolveProxyPort = (targetUrl) => {
        const resolved = resolveProxyPolicy(targetUrl, env, action.proxy);
        if (!resolved.ok) {
          return err({ kind: 'invalid_request', message: resolved.error.message });
        }
        return ok(resolved.value.kind === 'proxy' ? String(resolved.value.url) : undefined);
      };

      const resolveTranscriptProxy: ResolveTranscriptProxyPort = (targetUrl) => {
        const resolved = resolveProxyPolicy(targetUrl, env, action.proxy);
        if (!resolved.ok) {
          return err({ kind: 'invalid_request', message: resolved.error.message });
        }
        return ok(resolved.value.kind === 'proxy' ? String(resolved.value.url) : undefined);
      };

      const basePorts: FetchPorts = deps.ports ?? {
        httpGet: createRealHttpGet({ maxBytes: maxResponseBytes }),
        dnsLookup: createRealDnsLookup(),
      };
      const fetchPorts: FetchPorts = {
        ...basePorts,
        resolveProxy: basePorts.resolveProxy ?? resolveFetchProxy,
      };

      const fetchPage: FetchPagePort = async (targetUrl, reqHeaders) => {
        const res = await executeFetch(
          { url: targetUrl, format: 'html', headers: reqHeaders, maxLength: 0 },
          fetchPorts,
          { maxResponseBytes },
        );
        if (!res.ok) {
          const kind = res.error.kind === 'blocked_url' ? 'blocked_url' : 'fetch_error';
          return err({ kind, message: res.error.message });
        }
        return ok(String(res.value));
      };

      const checkHost: CheckHostPort = async (hostname) => {
        const host = normalizeHostname(hostname);
        const lookup = await fetchPorts.dnsLookup(host);
        if (!lookup.ok) {
          return err({ kind: 'blocked_url', message: lookup.error.message });
        }
        const validated = validateResolvedIps(host, lookup.value);
        if (!validated.ok) {
          return err({ kind: 'blocked_url', message: validated.error.message });
        }
        return ok(undefined);
      };

      const ytDlp = deps.ytDlp ?? createRealYtDlp({ maxBytes: maxResponseBytes });
      const result = await executeFetchTranscript(
        {
          url: action.url,
          headers: action.headers,
          ...(action.lang !== undefined ? { lang: action.lang } : {}),
          ...(action.startIndex !== undefined ? { startIndex: action.startIndex } : {}),
          ...(action.maxLength !== undefined ? { maxLength: action.maxLength } : {}),
        },
        { fetchPage, checkHost, resolveProxy: resolveTranscriptProxy, ytDlp },
        { defaultLimit },
      );

      if (!result.ok) {
        stderr(`${result.error.message}\n`);
        return 1;
      }
      stdout(result.value);
      return 0;
    }

    case 'fetch': {
      const limits = parseOperatorLimits(env);
      if (!limits.ok) {
        stderr(`${limits.error.message}\n`);
        return 1;
      }

      const { defaultLimit, maxResponseBytes } = limits.value;
      const resolveFetchProxy: ResolveProxyPort = (targetUrl) => {
        const resolved = resolveProxyPolicy(targetUrl, env, action.proxy);
        if (!resolved.ok) {
          return err({ kind: 'invalid_request', message: resolved.error.message });
        }
        return ok(resolved.value.kind === 'proxy' ? String(resolved.value.url) : undefined);
      };

      const basePorts: FetchPorts = deps.ports ?? {
        httpGet: createRealHttpGet({ maxBytes: maxResponseBytes }),
        dnsLookup: createRealDnsLookup(),
      };
      const ports: FetchPorts = {
        ...basePorts,
        resolveProxy: basePorts.resolveProxy ?? resolveFetchProxy,
      };

      const result = await executeFetch(
        {
          url: action.url,
          format: action.format,
          headers: action.headers,
          ...(action.maxLength !== undefined ? { maxLength: action.maxLength } : {}),
          ...(action.startIndex !== undefined ? { startIndex: action.startIndex } : {}),
        },
        ports,
        { defaultLimit, maxResponseBytes },
      );

      if (!result.ok) {
        stderr(`${result.error.message}\n`);
        return 1;
      }
      stdout(result.value);
      return 0;
    }

    default:
      return action satisfies never;
  }
};

const isMainModule = (): boolean => {
  try {
    const scriptPath = fileURLToPath(import.meta.url);
    const arg = process.argv[1];
    if (!arg) return false;
    return scriptPath === realpathSync(arg);
  } catch {
    return process.argv[1]?.endsWith('/cli.js') || process.argv[1]?.endsWith('/mcp-fetch') || false;
  }
};

if (isMainModule()) {
  runCli(process.argv.slice(2))
    .then((code) => process.exit(code))
    .catch((error: unknown) => {
      const message = error instanceof Error ? error.message : String(error);
      process.stderr.write(`${message}\n`);
      process.exit(1);
    });
}
