# Slice 03: Formats & Content Guards

Part of the [Fetch Web Content plan](../../plan.md). Decisions referenced as D# / U# / I# are in
[`REQUIREMENTS.md`](../../../../../REQUIREMENTS.md). Builds on [slice 02](../02-ssrf-and-redirects/spec.md).

Covers [acceptance criteria](../../acceptance-criteria.md) FW-9, FW-11, FW-12, and FW-13.

## Goal

Expand `src/fetching/` to support all five web **Formats** (`html`, `json`, `text`, `markdown`, `readable`) with
explicit parse errors and a binary `Content-Type` guard. `json` validates and compactly re-serializes JSON; `text`
removes `<script>` and `<style>` elements and normalizes whitespace; `markdown` removes `<script>` and `<style>`
elements before Turndown conversion; `readable` extracts the main article via Mozilla Readability + Turndown and
prepends `# <article.title>` when present; and clearly binary `Content-Type` responses are rejected before rendering.

**Done when:** `bun run lint`, `bun run typecheck`, `bun test`, and
`bun run harness run scenarios/fetch-web-content` (Slices 01–03) all pass cleanly.

## Scope

**In:**
- `src/fetching/nouns.ts`: expand `WEB_FORMATS` to `['html', 'markdown', 'readable', 'text', 'json']`; add `unsupported_content_type` and `parse_error` variants to `FetchError`.
- `src/fetching/queries.ts`: add `isBinaryContentType(contentType: string | undefined): boolean` (D17).
- `src/fetching/verbs.ts`: update `evaluateResponse` with binary `Content-Type` rejection (D17) and exhaustive `WebFormat` rendering for `json`, `text`, `markdown`, and `readable` (D14, D16).
- `src/integrations/origin/mock.ts` & `cli/commands/origin.ts`: add `header(url, name, value)` / `origin header <url> <name> <value...>` world command to attach response headers (such as `Content-Type`) to served routes.

**Out:**
- Compression (`gzip`/`deflate`/`br`), `MAX_RESPONSE_BYTES` streaming enforcement, `30s` timeout, default `User-Agent`/`Accept-Encoding` deduplication, duplicate case-insensitive caller headers, and CR/LF header rejection (waits on Slice 04: `04-limits-compression-and-timeouts`).
- Real IP-pinned HTTP(S) client and `mcp-fetch` CLI rewiring (waits on Slice 05: `05-real-transport-and-cli-wiring`).
- Non-UTF-8 charset transcoding (Deferred in `plan.md`).

## Vocabulary

The Terminology this slice uses.

- **Target URL**, **Format** (`WebFormat`: `html`, `markdown`, `readable`, `text`, `json`), **Window**, **Fetch Request**, **Raw Response**, **Rendered Output** *(derived)*, **Windowed Excerpt** *(derived)*, **fetch**.

## What it reads and writes

| Payload | Shape |
|---|---|
| `WebFormat` | `'html' \| 'markdown' \| 'readable' \| 'text' \| 'json'` |
| `FetchError` | Adds `{ readonly kind: 'unsupported_content_type'; readonly message: string }` and `{ readonly kind: 'parse_error'; readonly message: string }` |

## Verbs (`src/fetching/verbs.ts`)

| Function | Rule | Error |
|---|---|---|
| `prepareFetch(input: RawFetchInput, defaultLimit?: number): Result<FetchRequest, FetchError>` | Now accepts all five `WebFormat` values (`html`, `markdown`, `readable`, `text`, `json`) (D4, D16, D19). | Same as Slice 02 (`Unsupported Format: "<format>"` for anything else) |
| `evaluateResponse(request: FetchRequest, response: RawResponse): Result<RenderedOutput, FetchError>` | Requires `200..299` (D14); rejects binary `Content-Type` via `isBinaryContentType` (D17); renders `html` (unmodified), `json` (`JSON.parse` + compact `JSON.stringify`), `text` (JSDOM minus `<script>`/`<style>`, collapsed/trimmed `body.textContent`), `markdown` (JSDOM minus `<script>`/`<style>`, Turndown), `readable` (Mozilla Readability + Turndown, prepending `# <article.title>\n\n` when title is non-empty) (D14, D16). | `HTTP error <status> fetching <url>`<br>`Unsupported binary Content-Type "<mediaType>" fetching <url>`<br>`Invalid JSON response from <url>`<br>`Failed to parse readable content from <url>` |

## Queries (`src/fetching/queries.ts`)

The derived nouns and pure checks this slice computes. Never stored, never refused.

| Function | Definition |
|---|---|
| `isBinaryContentType(contentType: string \| undefined): boolean` | Strips parameters after `;`, lowercases and trims the media type, and returns `true` for `image/*` (excluding `image/svg+xml`), `audio/*`, `video/*`, `font/*`, `application/octet-stream`, `application/pdf`, and `application/zip`; returns `false` for missing, empty, `image/svg+xml`, or text-based media types (D17). |
| `normalizeHostname`, `isIpLiteral`, `isReservedIp`, `stripCrossOriginHeaders`, `windowedExcerpt` | Unchanged from Slice 02. |

## Harness

| Command | Kind | What it does |
|---|---|---|
| `fetch <format> <url> [--start-index <N>] [--max-length <N>] [--header <Key:Value>]...` | domain | Now accepts `html`, `markdown`, `readable`, `text`, and `json`. |
| `origin header <url> <name> <value...>` | world | Sets response header `<name>` to `<value>` on an existing mocked route for `<url>` and prints `origin: header <url> <name>: <value>`. |

## Placeholders

*(None — all rules in Slice 03 are settled by D4, D14, D16, D17, D19.)*

## Tests

- **Domain tests** (`src/fetching/fetching.test.ts`): pure given/when/then tests for `isBinaryContentType` (all binary media types with and without `; charset=...` params, text/JSON/HTML/XML/missing allowed), `evaluateResponse` for `json` (valid compact serialization + invalid JSON error), `text` (strips `<script>`/`<style>`, collapses whitespace, body-less HTML -> `""`), `markdown` (strips `<script>`/`<style>`, converts headings/links/lists), `readable` (extracts article with `# <title>`, strips nav/footer boilerplate, title-less article omits heading, unparseable page fails explicitly), and binary `Content-Type` rejection across formats.
- **Scenario:** `scenarios/fetch-web-content/03-formats-and-content-guards.txt` (plus Slices 01–02 scenarios continue to pass).
