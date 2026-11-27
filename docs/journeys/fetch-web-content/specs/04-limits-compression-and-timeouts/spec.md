# Slice 04: Limits, Compression & Timeouts

Part of the [Fetch Web Content plan](../../plan.md). Decisions referenced as D# / U# / I# are in
[`REQUIREMENTS.md`](../../../../../REQUIREMENTS.md). Builds on [slice 03](../03-formats-and-content-guards/spec.md).

Covers [acceptance criteria](../../acceptance-criteria.md) FW-2, FW-7, and FW-8.

## Goal

Add request header hygiene, response decompression, byte-cap enforcement, and timeout handling to `src/fetching/` and
the harness. `prepareFetch` rejects CR/LF control characters in custom headers, deduplicates duplicate
case-insensitive caller headers, and applies default `User-Agent` and `Accept-Encoding` (`gzip, deflate, br`) only
when not supplied by the caller (`D18`). `decodeResponseBody` enforces `MAX_RESPONSE_BYTES` (`10 MB`) on declared
`Content-Length`, raw wire bytes, and decompressed streams (`I5`), decompresses `gzip`/`x-gzip`/`deflate`/`br` while
passing unknown encodings through unchanged (`D17`), and fails explicitly on corrupted compressed payloads. Slow
origins exceeding `30s` fail with a typed timeout error without retrying (`D9`, `D18`).

**Done when:** `bun run lint`, `bun run typecheck`, `bun test`, and
`bun run harness run scenarios/fetch-web-content` (Slices 01–04) all pass cleanly.

> **Note on existing scenarios:** Because `D18` adds default `User-Agent` and `Accept-Encoding` headers to every
> outbound request, `origin last-headers` assertions in `scenarios/fetch-web-content/02-ssrf-and-redirects.txt` will
> be updated in this slice to include those two default headers (citing `D18`).

## Scope

**In:**
- `src/fetching/nouns.ts`: add `WireResponse` (`status`, `url`, `headers`, `rawBytes: Uint8Array`) and three `FetchError` variants (`response_too_large`, `decode_error`, `timeout`).
- `src/fetching/verbs.ts`:
  - Update `prepareFetch` with CR/LF rejection, case-insensitive duplicate caller header deduplication (last value wins), and case-insensitive default `User-Agent` / `Accept-Encoding` (`D18`).
  - Add `decodeResponseBody(url, headers, rawBytes, maxBytes?)` enforcing `MAX_RESPONSE_BYTES` (`10_485_760`) on `Content-Length`, raw bytes, and decompressed output (`gzip`, `x-gzip`, `deflate`, `br`) with unknown encoding passthrough (`D9`, `D14`, `D17`, `I5`).
- `src/fetching/ports.ts`: update `HttpGetPort` to return `Result<WireResponse, FetchError>` (carrying `rawBytes: Uint8Array`).
- `src/integrations/origin/mock.ts` & `cli/commands/origin.ts`: record per-URL attempt counts (`origin attempts <url>`), add `compress`, `repeat`, `corrupt`, and `timeout` world controls.
- `cli/commands/fetch.ts`: wire `decodeResponseBody` after receiving `WireResponse` (and support `\r`/`\n` escape decoding in harness `--header` arguments so CR/LF rejection can be exercised in scenarios).

**Out:**
- Real IP-pinned HTTP(S) client and `mcp-fetch` CLI rewiring (waits on Slice 05: `05-real-transport-and-cli-wiring`).
- Operator env var configuration of `DEFAULT_LIMIT` and `MAX_RESPONSE_BYTES` and proxy routing (waits on `proxy-and-limits` journey).

## Vocabulary

The Terminology this slice uses.

- **Target URL**, **Format** (`WebFormat`), **Window**, **Fetch Request**, **Wire Response**, **Raw Response**, **Rendered Output**, **Windowed Excerpt** *(derived)*, **fetch**.

## What it reads and writes

| Payload | Shape |
|---|---|
| `WireResponse` | `{ readonly status: number; readonly url: TargetUrl; readonly headers: Headers; readonly rawBytes: Uint8Array }` |
| `FetchError` | Adds `{ readonly kind: 'response_too_large'; readonly message: string }`, `{ readonly kind: 'decode_error'; readonly message: string }`, and `{ readonly kind: 'timeout'; readonly message: string }` |

## Verbs (`src/fetching/verbs.ts`)

| Function | Rule | Error |
|---|---|---|
| `prepareFetch(input: RawFetchInput, defaultLimit?: number): Result<FetchRequest, FetchError>` | Same as Slice 03, plus rejects any header name or value containing `\r` or `\n`, deduplicates duplicate caller headers case-insensitively (last value wins), and applies default `User-Agent` (`DEFAULT_USER_AGENT`) and `Accept-Encoding: gzip, deflate, br` only when not supplied case-insensitively (D14, D18). | Same as Slice 03, plus:<br>`Invalid header <JSON.stringify(key)>: CR/LF control characters are not allowed` |
| `decodeResponseBody(url: TargetUrl, headers: Headers, rawBytes: Uint8Array, maxBytes?: number): Result<string, FetchError>` | Rejects declared `Content-Length > maxBytes` and `rawBytes.byteLength > maxBytes` (`maxBytes` defaults to `MAX_RESPONSE_BYTES = 10_485_760`, D9, I5); decompresses `gzip`/`x-gzip`, `deflate`, and `br` under `maxOutputLength: maxBytes` (I5); passes missing, `identity`, or unknown `Content-Encoding` through unchanged as UTF-8 (D17). | `Response too large: <contentLength> bytes exceeds <maxBytes> byte limit`<br>`Response too large: exceeded <maxBytes> byte limit`<br>`Failed to decompress <encoding> response from <url>` |
| `validateResolvedIps`, `validateRedirectHop`, `evaluateResponse` | Unchanged from Slice 03. | Unchanged from Slice 03 |

## Queries (`src/fetching/queries.ts`)

Unchanged from Slice 03 (`normalizeHostname`, `isIpLiteral`, `isReservedIp`, `isBinaryContentType`, `stripCrossOriginHeaders`, `windowedExcerpt`).

## Harness

| Command | Kind | What it does |
|---|---|---|
| `fetch <format> <url> [--start-index <N>] [--max-length <N>] [--header <Key:Value>]...` | domain | Decodes `\r`/`\n` escapes in `--header` args, runs `prepareFetch`, DNS/redirect loop via `origin.get` (`WireResponse`), `decodeResponseBody`, `evaluateResponse`, and `windowedExcerpt`. |
| `origin compress <url> <encoding> <body...>` | world | Serves HTTP 200 with `Content-Encoding: <encoding>` and compressed bytes (`gzip`, `x-gzip`, `deflate`, `br`, or raw UTF-8 for unknown encodings) and prints `origin: compress <encoding> <url>`. |
| `origin repeat <url> <count> [encoding]` | world | Serves HTTP 200 containing `<count>` copies of `'a'` (optionally compressed with `gzip`/`deflate`/`br`) for testing `MAX_RESPONSE_BYTES` on raw and decompressed streams; prints `origin: repeat <count> <url>`. |
| `origin corrupt <url> <encoding>` | world | Serves HTTP 200 with `Content-Encoding: <encoding>` and invalid compressed bytes; prints `origin: corrupt <encoding> <url>`. |
| `origin timeout <url>` | world | Configures `<url>` to fail with `{ kind: 'timeout', message: 'Request timed out after 30000ms fetching <url>' }` (single attempt); prints `origin: timeout <url>`. |
| `origin attempts <url>` | world | Prints `attempts: <count>` for `<url>` to prove single-attempt delivery (D18). |

## Placeholders

*(None — all rules in Slice 04 are settled by D9, D14, D17, D18, I5.)*

## Tests

- **Domain tests** (`src/fetching/fetching.test.ts`): pure given/when/then tests for `prepareFetch` (default `User-Agent` and `Accept-Encoding` applied when absent, case-insensitive caller override prevents duplication, duplicate case-insensitive caller headers deduplicated last-value-wins, CR/LF in header name or value rejected) and `decodeResponseBody` (`gzip`, `x-gzip`, `deflate`, `br` decompression, unknown encoding passthrough, `Content-Length` over limit, raw wire bytes over limit, decompressed zip-bomb over limit, corrupted compressed stream error).
- **Scenario:** `scenarios/fetch-web-content/04-limits-compression-and-timeouts.txt` (plus Slices 01–03 scenarios pass).
