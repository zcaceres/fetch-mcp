# Slice 01: Basic HTML Fetch

Part of the [Fetch Web Content plan](../../plan.md). Decisions referenced as D# / U# / I# are in
[`REQUIREMENTS.md`](../../../../../REQUIREMENTS.md). Tracer bullet — first slice of the journey.

Covers [acceptance criteria](../../acceptance-criteria.md) FW-1, FW-3 (basic scheme/localhost/private IPv4), FW-5, FW-10, and FW-14.

## Goal

Establish the Bun-runnable DD harness, scenario runner, TypeScript typecheck, and Biome linter (D11), alongside the
pure `src/shared/` and `src/fetching/` core and in-memory `origin` + `dns` mocks. Proves the narrowest end-to-end
`fetch` path: validating a Fetch Request, rejecting malformed input and basic SSRF targets (`file:`, `localhost`,
private IPv4), retrieving a single-attempt HTML Raw Response from the mocked Remote Origin Server, handling non-2xx
and network errors explicitly, and slicing Rendered Output into a Windowed Excerpt.

**Done when:** `bun run lint`, `bun run typecheck`, `bun test`, and
`bun run harness run scenarios/fetch-web-content/01-basic-html-fetch.txt` all pass cleanly.

## Scope

**In:**
- Tooling & harness foundation (D11): `typescript` (`bun run typecheck`), Biome (`bun run lint`, `bun run lint:fix`), `cli/` harness (`main.ts`, `session.ts`, `scenario.ts`, `command.ts`, `world.ts`, `commands/`), and a Bun test running all `scenarios/**/*.txt`.
- Shared kernel: `src/shared/result.ts` (`Result<T, E>`, `ok`, `err`) and `src/shared/brand.ts` (`Brand<T, B>`).
- Bounded context `src/fetching/`: `nouns.ts`, `verbs.ts` (`prepareFetch`, `evaluateResponse`), `queries.ts` (`windowedExcerpt`), `ports.ts` (`HttpGetPort`, `DnsLookupPort`).
- In-memory mocks: `src/integrations/origin/mock.ts` and `src/integrations/dns/mock.ts`.
- Harness commands: `fetch` (domain), `origin` and `dns` (world).

**Out:**
- Full IPv6 / IPv4-mapped IPv6 / multicast / malformed IP SSRF rules, DNS rebinding validation, and HTTP redirect handling (waits on Slice 02: `02-ssrf-and-redirects`).
- `markdown`, `readable`, `text`, `json` rendering and binary `Content-Type` guard (waits on Slice 03: `03-formats-and-content-guards`).
- Compression (`gzip`/`deflate`/`br`), `MAX_RESPONSE_BYTES` streaming enforcement, `30s` timeouts, and custom request header hygiene (waits on Slice 04: `04-limits-compression-and-timeouts`).
- Real IP-pinned HTTP(S) client and `mcp-fetch` CLI rewiring (waits on Slice 05: `05-real-transport-and-cli-wiring`).
- Operator proxy routing and env var limit overrides (waits on `proxy-and-limits` journey).
- MCP stdio server wiring (waits on `mcp-interface` journey).

## Vocabulary

The Terminology this slice uses.

- **Target URL**, **Format** (`html`), **Fetch Request**, **Raw Response**, **Rendered Output** *(derived)*, **Windowed Excerpt** *(derived)*, **fetch**.

## What it reads and writes

| Payload | Shape |
|---|---|
| `TargetUrl` | `Brand<string, 'TargetUrl'>` (validated `http:` / `https:` URL string) |
| `WebFormat` | `'html'` (union expands to `'html' \| 'markdown' \| 'readable' \| 'text' \| 'json'` in Slice 03) |
| `Window` | `{ readonly startIndex: number; readonly maxLength: number }` |
| `FetchRequest` | `{ readonly url: TargetUrl; readonly format: WebFormat; readonly window: Window }` |
| `RawResponse` | `{ readonly status: number; readonly url: TargetUrl; readonly headers: Readonly<Record<string, string>>; readonly body: string }` |
| `RenderedOutput` | `Brand<string, 'RenderedOutput'>` |
| `WindowedExcerpt` | `Brand<string, 'WindowedExcerpt'>` |
| `FetchError` | Discriminated union `{ readonly kind: 'invalid_request' \| 'blocked_url' \| 'http_error' \| 'network_error'; readonly message: string }` |

## Verbs (`src/fetching/verbs.ts`)

| Function | Rule | Error |
|---|---|---|
| `prepareFetch(input: RawFetchInput, defaultLimit?: number): Result<FetchRequest, FetchError>` | Parses and validates `url`, `format`, `startIndex` (default `0`), and `maxLength` (default `defaultLimit ?? 5000`); enforces `http:`/`https:` and blocks `localhost`, `*.localhost`, and private IPv4 literals (`127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, `0.0.0.0/8`) (D4, D8, D9, D14, I1). | `Invalid Target URL: "<url>"`<br>`Unsupported Format: "<format>"`<br>`Invalid startIndex: must be a non-negative integer`<br>`Invalid maxLength: must be a non-negative integer`<br>`Blocked Target URL: disallowed scheme "<protocol>" (only http: and https: are allowed)`<br>`Blocked Target URL: private address "<host>"` |
| `evaluateResponse(request: FetchRequest, response: RawResponse): Result<RenderedOutput, FetchError>` | Requires HTTP status `200..299` (D14); renders `html` as unmodified response body (D16). | `HTTP error <status> fetching <url>` |

## Queries (`src/fetching/queries.ts`)

The derived nouns this slice computes. Never stored, never refused.

| Function | Definition |
|---|---|
| `windowedExcerpt(output: RenderedOutput, window: Window): WindowedExcerpt` | Returns `""` if `startIndex >= output.length`; if `maxLength === 0`, returns `output.slice(startIndex)`; otherwise returns `output.slice(startIndex, startIndex + maxLength)`. Sliced text only, no appended footer (D4, D9, D14, D15). |

## Harness

| Command | Kind | What it does |
|---|---|---|
| `fetch <format> <url> [--start-index <N>] [--max-length <N>]` | domain | Calls `prepareFetch`, fetches `RawResponse` via `origin` port, calls `evaluateResponse` and `windowedExcerpt`. Prints each line prefixed with `\| ` (or `(empty)` if `""`), or `error: <message>`. |
| `origin serve <url> <status> <body...>` | world | Registers a mock HTTP response for `<url>` in the in-memory origin mock and prints `origin: <status> <url>`. |
| `origin fail <url> <reason...>` | world | Registers a mock network failure for `<url>` (returning `err({ kind: 'network_error', message: 'Network error fetching <url>: <reason>' })`) and prints `origin: fail <url>`. |
| `dns set <host> <ip...>` | world | Registers mock DNS records for `<host>` in the in-memory DNS mock and prints `dns: <host> -> <ips>`. |

## Placeholders

*(None — all rules in Slice 01 are settled by D4, D8, D9, D11, D14, D15, D16, D18, I1.)*

## Tests

- **Domain tests** (`src/fetching/fetching.test.ts`): pure given/when/then tests for `prepareFetch` (valid URL, defaults, malformed URL, unsupported format, negative/non-integer window bounds, disallowed schemes, `localhost`, `*.localhost`, private IPv4), `evaluateResponse` (200 HTML unmodified, 404/500 error), and `windowedExcerpt` (default limit, custom window, `maxLength = 0` unlimited, `startIndex >= length` empty).
- **Scenario:** `scenarios/fetch-web-content/01-basic-html-fetch.txt` (replayed automatically by `bun test` and `bun run harness run scenarios`).
