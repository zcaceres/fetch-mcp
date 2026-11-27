# Slice 05: Real Transport & CLI Wiring

Part of the [Fetch Web Content plan](../../plan.md). Decisions referenced as D# / U# / I# are in
[`REQUIREMENTS.md`](../../../../../REQUIREMENTS.md). Builds on [slice 04](../04-limits-compression-and-timeouts/spec.md).

Covers [acceptance criteria](../../acceptance-criteria.md) FW-4 (socket IP pinning) and FW-15 (CLI wiring), closing
Gap #1 from [2026-11-25-fetch-web-content-verify.md](../../../../../notes/2026-11-25-fetch-web-content-verify.md).

## Goal

Extract the shared port-injected fetch pipeline (`executeFetch`) so every caller — the harness, the real `mcp-fetch`
CLI, and later the MCP server — runs identical SSRF, DNS-pinning, redirect, decode, render, and windowing logic. Wire
validated `ResolvedIp[]` directly into `HttpGetPort` (closing `FW-4` DNS-rebinding TOCTOU), implement the real
IP-pinned HTTP(S) client (`src/integrations/origin/client.ts`) and DNS client (`src/integrations/dns/client.ts`), and
migrate `src/cli.ts` (`mcp-fetch`) to Terminology's breaking subcommands (`html`, `markdown`, `readable`, `text`,
`json`, `transcript`) with repeatable `--header <Key:Value>` support (`D1`, `D6`, `D10`, `D12`, `D13`, `D14`).

**Done when:** `bun run lint`, `bun run typecheck`, `bun run build`, `bun test` (including real-transport and CLI
integration tests), and `bun run harness run scenarios/fetch-web-content` (Slices 01–05) all pass cleanly.

## Scope

**In:**
- `src/fetching/ports.ts`: pass `pinnedIps: readonly ResolvedIp[]` into `HttpGetPort` (`I2`).
- `src/fetching/execute.ts`: pure port-injected orchestration (`executeFetch(input, ports, options?)`) used identically by the harness (`cli/commands/fetch.ts`) and the real CLI (`src/cli.ts`).
- `src/integrations/origin/mock.ts` & `cli/commands/origin.ts`: record `pinnedIps` per URL and add `origin last-pinned <url>` world command to verify `FW-4` IP pinning in scenarios.
- `src/integrations/origin/client.ts`: real IP-pinned HTTP(S) `HttpGetPort` implementation using `node:http`/`node:https` with a custom `lookup` pinned strictly to `pinnedIps`, streaming raw byte cap enforcement (`MAX_RESPONSE_BYTES`), and `30s` single-attempt timeout (`D8`, `D9`, `D18`, `I2`, `I5`).
- `src/integrations/dns/client.ts`: real `DnsLookupPort` implementation wrapping `node:dns` (`dns.promises.lookup(hostname, { all: true })`), returning typed `Result` errors on failure (`I2`).
- `src/cli.ts` & `src/cli.test.ts`: breaking CLI redesign (`html`, `markdown`, `readable`, `text`, `json`, `transcript`), repeatable `--header <Key:Value>`, `--max-length`, `--start-index`, routing web subcommands through `executeFetch` + real ports (printing Windowed Excerpt to `stdout` / exit `0`, or typed error message to `stderr` / exit `1`).
- `package.json` & `biome.json`: update `engines.node` to `>=20` (`D13`) and include `src/cli.ts` and `src/cli.test.ts` in Biome linting.

**Out:**
- Operator proxy routing (`HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`/`NO_PROXY`, SOCKS, `--proxy`) and Operator env limit scenarios (waits on `proxy-and-limits` journey; `--proxy` continues to be parsed in `src/cli.ts` and falls back cleanly until `proxy-and-limits` replaces legacy transport).
- `transcript` YouTube redesign (`yt-dlp` / direct scrape ports & domain core; waits on `fetch-transcript` journey — `src/cli.ts` delegates `transcript` to existing `Fetcher.youtubeTranscript` meanwhile).
- MCP stdio server (`src/index.ts`) tool renames and wiring (waits on `mcp-interface` journey).

## Vocabulary

The Terminology this slice uses.

- **CLI User**, **Target URL**, **Format** (`WebFormat`: `html`, `markdown`, `readable`, `text`, `json`), **Window**, **Fetch Request**, **WireResponse**, **Raw Response**, **Rendered Output** *(derived)*, **Windowed Excerpt** *(derived)*, **fetch**.

## What it reads and writes

| Payload | Shape |
|---|---|
| `HttpGetPort` | `(url: TargetUrl, headers: Headers, pinnedIps: readonly ResolvedIp[]) => Promise<Result<WireResponse, FetchError>>` |
| `FetchPorts` | `{ readonly httpGet: HttpGetPort; readonly dnsLookup: DnsLookupPort }` |
| `ExecuteFetchOptions` | `{ readonly defaultLimit?: number; readonly maxResponseBytes?: number; readonly maxRedirects?: number }` |

## Verbs & Workflow

| Function | Rule | Error |
|---|---|---|
| `executeFetch(input: RawFetchInput, ports: FetchPorts, options?: ExecuteFetchOptions): Promise<Result<WindowedExcerpt, FetchError>>` | Runs `prepareFetch`, then per-hop DNS lookup + `validateResolvedIps` (or `[ResolvedIp(host)]` for public IP literals), calls `ports.httpGet(currentUrl, currentHeaders, pinnedIps)`, follows redirects via `validateRedirectHop`, decodes via `decodeResponseBody`, renders via `evaluateResponse`, and slices via `windowedExcerpt` (D4, D8, D9, D14, D15, D16, D17, D18, I1, I2, I4, I5). | Same exact typed `FetchError` messages from Slices 01–04 |

## Queries (`src/fetching/queries.ts`)

Unchanged from Slice 04 (`normalizeHostname`, `isIpLiteral`, `isReservedIp`, `isBinaryContentType`, `stripCrossOriginHeaders`, `windowedExcerpt`).

## Harness

| Command | Kind | What it does |
|---|---|---|
| `fetch <format> <url> [--start-index <N>] [--max-length <N>] [--header <Key:Value>]...` | domain | Now delegates directly to `executeFetch` using `world.origin.get` and `world.dns.lookup`. |
| `origin last-pinned <url>` | world | Prints `(not requested)` if `<url>` was never contacted, or `pinned: <ip1>, <ip2>, ...` showing the exact `ResolvedIp[]` passed to `HttpGetPort` (FW-4, I2). |

## CLI (`src/cli.ts`, `mcp-fetch`)

- Subcommands (`D12`): `html`, `markdown`, `readable`, `text`, `json`, `transcript`.
- Flags (`D6`, `D12`): `--header <Key:Value>` (repeatable), `--max-length <N>`, `--start-index <N>`, `--proxy <URL>`, `--lang <code>`, `--help`, `--version`.
- Output (`D14`): writes Windowed Excerpt to `stdout` and exits `0`; on error, writes `<message>\n` to `stderr` and exits `1`.

## Placeholders

*(None — all rules in Slice 05 are settled by D1, D6, D8, D9, D10, D12, D13, D14, D18, I1, I2, I4, I5.)*

## Tests

- **Real transport integration tests** (`src/integrations/origin/client.test.ts`): tests `createRealHttpGet` + `executeFetch` against local HTTP servers — verifying pinned IP socket connection (no second DNS lookup), streaming raw byte limit abortion, gzip/deflate/br decompression, `30s`/custom timeout abortion, single-attempt delivery, cross-origin header stripping, and binary Content-Type rejection.
- **CLI tests** (`src/cli.test.ts`): unit tests for `parseArgs` (`html`, `markdown`, `readable`, `text`, `json`, `transcript`, repeatable `--header`, invalid flags/URLs) and `runCli` end-to-end tests asserting `stdout` + exit `0` and `stderr` + exit `1`.
- **Scenario:** `scenarios/fetch-web-content/05-real-transport-and-cli-wiring.txt` (proving `FW-4` pinned IP handoff across direct hosts, redirects, and public IP literals, plus full `executeFetch` format pipeline).
