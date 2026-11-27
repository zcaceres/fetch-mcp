# Slice 01: Operator Limits & Proxy Policy Resolution

Part of the [Proxy & Limits plan](../../plan.md). Decisions referenced as D# / U# / I# are in
[`REQUIREMENTS.md`](../../../../../REQUIREMENTS.md). Tracer bullet — first slice of the journey.

Covers [acceptance criteria](../../acceptance-criteria.md) PL-1, PL-2, PL-3, PL-4, PL-5, PL-6, PL-7, and PL-8.

## Goal

Create the pure bounded context `src/policy/` (isolated from `src/fetching/` and `src/transcript/`) to parse Operator
limits (`DEFAULT_LIMIT`, `MAX_RESPONSE_BYTES`, failing explicitly per `D25`), match `NO_PROXY`, redact proxy
credentials for error output, and resolve per-URL **Proxy Policy** (`D5`, `D23`, `D24`, `D25`). Extend `FetchPorts`
and `TranscriptPorts` with `ResolveProxyPort` and `proxyUrl` handoff so `executeFetch` re-evaluates Proxy Policy on
every redirect hop and skips local DNS when proxied (`D8`, `D23`, `D24`), and `executeFetchTranscript` skips local DNS
`checkHost` when proxied while passing `--proxy` to `yt-dlp` and delegating direct fallback hops (`D21`, `D26`). Wire
`env` world commands, `origin last-proxy`, and `--proxy` into the harness.

**Done when:** `bun run lint`, `bun run typecheck`, `bun test`, and
`bun run harness run scenarios` (all `fetch-web-content`, `fetch-transcript`, and `proxy-and-limits` Slice 01
scenarios) pass cleanly.

## Scope

**In:**
- Bounded context `src/policy/`:
  - `nouns.ts`: `ProxyProtocol`, `ProxyUrl`, `ProxyPolicy`, `OperatorLimits`, `EnvMap`, `PolicyError`.
  - `queries.ts`: `isNoProxyMatch`, `redactProxyUrl`.
  - `verbs.ts`: `parseOperatorLimits`, `resolveProxyPolicy`.
  - `policy.test.ts`: pure given/when/then unit tests covering `PL-1`–`PL-5`.
- Port & orchestration extensions (no cross-context imports):
  - `src/fetching/ports.ts`: add `ResolveProxyPort`, optional `resolveProxy` on `FetchPorts`, and optional `proxyUrl?: string` on `HttpGetPort`.
  - `src/fetching/execute.ts`: resolve Proxy Policy per hop (`D24`); when proxied, skip local `dnsLookup` (`D8`, `D23`) and pass `pinnedIps = []` + `proxyUrl` to `httpGet`; when direct, preserve `I2` DNS validation & pinning.
  - `src/transcript/ports.ts`: add `ResolveTranscriptProxyPort`, optional `resolveProxy` on `TranscriptPorts`, and optional `proxyUrl?: string` on `YtDlpPort.downloadSubtitles`.
  - `src/transcript/execute.ts`: resolve Proxy Policy after `prepareFetchTranscript`; skip `checkHost` when proxied (`D8`, `D26`); pass `proxyUrl` into `ytDlp.downloadSubtitles`.
- Mocks & harness:
  - `src/integrations/origin/mock.ts`: record `lastProxy(url)` (`string | null | undefined` — `null` = direct, `string` = proxy URL, `undefined` = not requested).
  - `src/integrations/ytdlp/mock.ts`: forward `proxyUrl` to `buildYtDlpArgs(url, lang, '<tmp>/sub', proxyUrl)`.
  - `cli/world.ts`: add `env: Map<string, string>` (reset on `reset`).
  - `cli/commands/env.ts` & `cli/commands/index.ts`: add `env set`, `env unset`, `env clear` world commands.
  - `cli/commands/origin.ts`: add `origin last-proxy <url>` world command.
  - `cli/commands/fetch.ts` & `cli/commands/fetch-transcript.ts`: add `--proxy <url>`, apply `parseOperatorLimits`, and wire `resolveProxyPolicy` into `executeFetch` / `executeFetchTranscript`.
- `biome.json`: include `src/policy/**`.

**Out:**
- Real HTTP/HTTPS `CONNECT` and SOCKS4/4a/5/5h proxy socket transport in `src/integrations/origin/client.ts` (waits on Slice 02: `02-real-proxy-transport`).
- Wiring `src/cli.ts` (`mcp-fetch`) to `src/policy/` and removing legacy `Fetcher` proxy fallback (waits on Slice 03: `03-cli-proxy-and-limits-wiring`).
- MCP server (`src/index.ts`) Operator env wiring and `I6` schema enforcement (waits on `mcp-interface` journey).

## Vocabulary

The Terminology this slice uses.

- **Operator**, **CLI User**, **Target URL**, **Window**, **Fetch Request**, **Raw Response**, **Operator Limits**, **Proxy Policy**, **Windowed Excerpt** *(derived)*, **parse operator limits**, **resolve proxy policy**, **fetch**, **fetch transcript**.

## What it reads and writes

| Payload | Shape |
|---|---|
| `ProxyProtocol` | `'http:' \| 'https:' \| 'socks4:' \| 'socks4a:' \| 'socks5:' \| 'socks5h:'` |
| `ProxyUrl` | `Brand<string, 'ProxyUrl'>` |
| `ProxyPolicy` | `{ readonly kind: 'direct' } \| { readonly kind: 'proxy'; readonly url: ProxyUrl; readonly protocol: ProxyProtocol }` |
| `OperatorLimits` | `{ readonly defaultLimit: number; readonly maxResponseBytes: number }` |
| `EnvMap` | `Readonly<Record<string, string | undefined>>` |
| `PolicyError` | `{ readonly kind: 'invalid_limit' \| 'invalid_proxy'; readonly message: string }` |

## Verbs (`src/policy/verbs.ts`)

| Function | Rule | Error |
|---|---|---|
| `parseOperatorLimits(env: EnvMap): Result<OperatorLimits, PolicyError>` | Reads `DEFAULT_LIMIT` (unset/blank → `5000`; must match `/^\d+$/`, `0` allowed for unlimited) and `MAX_RESPONSE_BYTES` (unset/blank → `10485760`; must match `/^\d+$/` and `> 0`) (D9, D25, I5). | `Invalid DEFAULT_LIMIT "<raw>": must be a non-negative integer`<br>`Invalid MAX_RESPONSE_BYTES "<raw>": must be a positive integer` |
| `resolveProxyPolicy(targetUrl: string, env: EnvMap, explicitProxy?: string): Result<ProxyPolicy, PolicyError>` | Uses `explicitProxy` first when defined (rejecting empty/blank values per D25 and bypassing `NO_PROXY`); otherwise checks `NO_PROXY`/`no_proxy` via `isNoProxyMatch` (non-empty `NO_PROXY` shadows `no_proxy`), then env precedence (`https:` → `HTTPS_PROXY`/`https_proxy`/`HTTP_PROXY`/`http_proxy`/`ALL_PROXY`/`all_proxy`; `http:` → `HTTP_PROXY`/`http_proxy`/`ALL_PROXY`/`all_proxy`). Normalizes bare `host:port` (or `[ipv6]:port`) with explicit `:<port>` to `http://<raw>`; requires scheme in `ProxyProtocol` and non-empty hostname (D5, D23, D24, D25, D31, I7). | `Invalid proxy URL: "<redacted>"`<br>`Unsupported proxy protocol "<protocol>" (supported: http, https, socks4, socks4a, socks5, socks5h)` |

## Queries (`src/policy/queries.ts`)

The derived checks this slice computes. Never stored, never refused.

| Function | Definition |
|---|---|
| `isNoProxyMatch(targetUrl: URL, noProxy: string | undefined): boolean` | Splits `noProxy` on `,`; matches `*`, exact hostname, `.domain`/subdomain suffix, optional `:port`, and `[ipv6]:port` (canonicalizing IPv6 literals and rejecting malformed port/bracket syntax) against normalized target hostname and effective port (`443` for `https:`, `80` for `http:`) (D24). |
| `redactProxyUrl(proxyUrl: string): string` | Strips username/password credentials from valid and malformed proxy URLs (including passwords containing `@`, `/`, `?`, `#`, or `%`) so secrets never leak into logs or error messages (D31, I7). |

## Harness

| Command | Kind | What it does |
|---|---|---|
| `env set <KEY> <VALUE>` | world | Sets Operator environment variable `<KEY>` in world state; prints `env: <KEY>=<VALUE>`. |
| `env unset <KEY>` | world | Removes `<KEY>` from world environment; prints `env: unset <KEY>`. |
| `env clear` | world | Clears all Operator environment variables; prints `env: cleared`. |
| `origin last-proxy <url>` | world | Prints `(not requested)`, `proxy: direct`, or `proxy: <redactedProxyUrl>` for the last request to `<url>`. |
| `fetch <format> <url> ... [--proxy <url>]` | domain | Parses Operator limits (`D25`), resolves Proxy Policy per hop (`D24`), and runs `executeFetch`. |
| `fetch-transcript <url> ... [--proxy <url>]` | domain | Parses Operator limits (`D25`), resolves Proxy Policy (`D26`), and runs `executeFetchTranscript`. |

## Placeholders

*(None — all rules in Slice 01 are settled by D2, D5, D6, D7, D8, D9, D14, D15, D21, D23, D24, D25, D26, I1, I2, I3, I4, I5.)*

## Tests

- **Domain tests** (`src/policy/policy.test.ts`): pure given/when/then tests for `parseOperatorLimits` (defaults, `DEFAULT_LIMIT=0`, custom limits, invalid/negative/float/zero-max-bytes failures), `isNoProxyMatch` (`*`, exact host, `.domain`, subdomain, `:port`, `[ipv6]:port`), `redactProxyUrl` (removes `user:pass@` in valid and malformed URLs), and `resolveProxyPolicy` (precedence, lowercase fallbacks, `NO_PROXY`, CLI `--proxy` overriding `NO_PROXY`, bare `host:port`, `socks4`/`socks4a`/`socks5`/`socks5h`, malformed/unsupported schemes).
- **Orchestration tests** (`src/fetching/fetching.test.ts` & `src/transcript/transcript.test.ts`): `executeFetch` per-hop Proxy Policy re-evaluation & delegated DNS, and `executeFetchTranscript` proxied `yt-dlp` `--proxy` + skipped `checkHost` + local allowlist enforcement.
- **Scenario:** `scenarios/proxy-and-limits/01-operator-limits-and-proxy-policy.txt`.
