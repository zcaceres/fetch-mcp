# Fetch MCP Requirements

What is true however Fetch MCP is used: terminology, rules, invariants (I#), decisions (D#) and open questions (U#).
One numbering covers every journey; a new decision, question or invariant takes the next number, whichever journey
raised it. Everything here says what's true now; git keeps how it got there (`git log --grep D7`). Ids never move: a
number is never reused, a resolved question points to its decision under [Resolved questions](#resolved-questions),
and a withdrawn decision keeps its heading as one line.

What each journey's users can do and see is in its acceptance criteria, which cite these rules:

- **Fetch Web Content:** an Agent or CLI User fetches a public web Target URL in a Format and receives a Windowed Excerpt ([acceptance criteria](docs/journeys/fetch-web-content/acceptance-criteria.md)).

## Sources

Where the context came from: briefs, documents, designs, tickets, code, people. Re-read them before deciding
something they cover.

- [README.md](README.md): project overview, MCP tools, CLI usage, environment variables, and security features (v1.2.0).
- [package.json](package.json): package metadata (`mcp-fetch-server` v1.2.0), binaries, scripts, and runtime dependencies.
- [src/](src/): existing implementation (`index.ts`, `cli.ts`, `Fetcher.ts`, `httpClient.ts`, `ssrf.ts`, `YouTubeTranscript.ts`, `types.ts`).
- [docs/github/README.md](docs/github/README.md): exported GitHub issues and pull requests (as of 2026-09-27).

## Terminology

The vocabulary. Documents, code and harness commands use these words and no others; a new word, or a change to one,
is a decision. Each entry cites the decisions behind it. An entry marked *(proposed)* was inferred, not confirmed. A
noun marked *(derived)* is computed from others, never stored, and its entry says how.

### Actors

- **Agent:** an untrusted MCP client or AI model invoking tools over stdio (D1, D2).
- **CLI User:** a local human or script invoking `mcp-fetch` directly from the terminal (D1, D2).
- **Operator:** the person or runtime configuring process-level limits and proxy policy via environment variables (D2).

### Nouns

- **Target URL:** an `http:` or `https:` URL identifying a public web resource or YouTube video (D3, D4, D8).
- **Format:** the requested output representation — one of the five web formats (`html`, `markdown`, `readable`, `text`, `json`, modeled as `WebFormat`) or `youtube-transcript` (D3, D4, D19).
- **Window:** the non-negative integer character bounds (`startIndex`, `maxLength`) selecting a Windowed Excerpt from Rendered Output or Transcript (D4, D9, D19).
- **Fetch Request:** an actor's request carrying a Target URL, desired Format, optional custom request headers, optional Window (`startIndex`, `maxLength`), and (for `youtube-transcript`) an optional caption language code (D4, D6, D19).
- **Raw Response:** the bounded HTTP response status, headers, final URL, and decoded UTF-8 body retrieved from an origin server (D4, D9).
- **Proxy Policy:** the effective proxy routing rule (direct or HTTP/HTTPS/SOCKS proxy URL) resolved from Operator environment variables (`HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY`, `NO_PROXY`) or a CLI User's explicit `--proxy` override (D2, D4, D5, D6).
- **Rendered Output** *(derived)*: the string produced by transforming a Raw Response into the requested Format (`html`, `markdown`, `readable`, `text`, or `json`); never stored (D4).
- **Transcript** *(derived)*: formatted timestamped caption lines prefixed with a language header, extracted from a YouTube video via `yt-dlp` or direct page/caption-XML parsing; never stored (D4, D7).
- **Windowed Excerpt** *(derived)*: the character substring of Rendered Output or Transcript selected by `startIndex` and `maxLength` (with `maxLength = 0` meaning no limit); never stored (D4, D9).

### Verbs

- **fetch:** retrieve a public web resource for a Fetch Request, transform its Raw Response into Rendered Output for the requested Format, and return a Windowed Excerpt (D4).
- **fetch transcript:** retrieve a YouTube video's captions (trying `yt-dlp` first, then direct extraction), build a Transcript, and return a Windowed Excerpt (D4, D7).

## External Systems

Everything outside the system that it talks to, time included. Each is mocked in `src/integrations/<system>/`. When a
system computes a value for us, its rule for it is recorded here, as that system's, not as a D#.

| System | What we need from it | Source |
|---|---|---|
| Remote Origin Server | HTTP/HTTPS `GET` responses (status, headers, redirects, raw/compressed body) | D3, D4, D9 |
| DNS Resolver | IPv4/IPv6 address lookup for hostnames prior to direct connections | D8 |
| Proxy Server | HTTP/HTTPS/SOCKS proxied request forwarding or `CONNECT` tunneling (and remote DNS resolution when proxied) | D5, D8 |
| YouTube | Video watch pages (`ytInitialPlayerResponse`) and timed-text caption XML (`srv1`) | D3, D7, D8 |
| `yt-dlp` CLI | Optional local subprocess for downloading YouTube `.srv1` subtitles | D7 |
| OS Environment | Operator configuration (`DEFAULT_LIMIT`, `MAX_RESPONSE_BYTES`, proxy env vars) | D2, D5, D9 |
| Clock | Request and subprocess timeouts (`30s`) | D9 |

## Functional Requirements

### Web Content Fetching
- An Agent or CLI User can `fetch` a public `http:` or `https:` Target URL and receive its Rendered Output as `html`, `markdown`, `readable`, `text`, or `json`, with single-attempt delivery, case-insensitive `User-Agent`/`Accept-Encoding` defaulting, and header CR/LF rejection (D1, D3, D4, D12, D16, D18).
- `fetch` follows up to 10 HTTP redirects, validating every redirect hop against SSRF rules, stripping `Authorization`, `Cookie`, and `Proxy-Authorization` headers across origin boundaries, and treating redirect statuses without a `Location` header as non-2xx HTTP errors (D8, D9, D14, D17, I1, I4).
- `fetch` rejects clearly binary `Content-Type` responses with a typed error, decodes text-based responses as UTF-8, decompresses `gzip`/`deflate`/`br` responses, and passes unknown `Content-Encoding` values through unchanged (D17, I5).
- `fetch` returns a Windowed Excerpt (sliced text only) selected by `startIndex` (default `0`) and `maxLength` (default `DEFAULT_LIMIT` = `5000`; `0` = unlimited), returning `""` when `startIndex` is at or beyond the output length (D4, D9, D14, D15).
- Non-2xx HTTP responses, invalid JSON payloads for `json` format, and pages unparseable by Readability for `readable` format fail explicitly with typed domain errors (D14, D16).

### YouTube Transcript Fetching
- An Agent or CLI User can `fetch transcript` for an allowlisted YouTube Target URL with an optional caption language code (default `"en"`) and Window bounds (D3, D4, D7, D12, I3, U1).
- `fetch transcript` tries local `yt-dlp` first when present on `PATH` and falls back to direct YouTube watch-page and caption-XML extraction if `yt-dlp` is unavailable or fails, without swallowing validation or SSRF errors (D7, I3).
- `fetch transcript` returns a Windowed Excerpt of the Transcript, formatted as a language header followed by timestamped caption lines (D4, D9, D15, U1).

### Interfaces & Proxy Routing
- The MCP stdio server (`mcp-fetch-server`) exposes six tools aligned to Terminology: `fetch_html`, `fetch_markdown`, `fetch_readable`, `fetch_text`, `fetch_json`, and `fetch_transcript`, accepting custom request headers and never accepting a caller-supplied `proxy` parameter (D1, D6, D10, D12, I6).
- The local CLI (`mcp-fetch`) exposes six matching subcommands (`html`, `markdown`, `readable`, `text`, `json`, `transcript`) and supports `--header`, `--proxy`, `--max-length`, `--start-index`, and `--lang` (D1, D6, D10, D12).
- Operator proxy configuration (`HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY`, honoring `NO_PROXY`) and CLI `--proxy` overrides support HTTP, HTTPS, and SOCKS (`socks4`/`socks5`) proxies (D2, D5, D6, U3).
- Typed domain errors map to `isError: true` text results in MCP responses and `stderr` output with exit code `1` in the CLI (D14).

## Non-Functional Requirements

- **Security (SSRF & Isolation):** Every Target URL and redirect hop is restricted to `http:`/`https:` and blocked from `localhost`, `*.localhost`, and all IANA-reserved IPv4/IPv6 ranges (including IPv4-mapped IPv6 and multicast), failing closed on malformed IPs or DNS failures; direct connections pin validated DNS records to sockets while proxied connections delegate hostname DNS resolution to the proxy (D8, I1, I2, I3, I4, I6, U3).
- **Resource Safety:** Raw Response bodies are capped at `MAX_RESPONSE_BYTES` (default `10 MB`) across both raw wire bytes and decompressed streams, and network requests and `yt-dlp` subprocesses time out after `30s` (D9, I5).
- **Runtime & Distribution:** Supports Node.js `>= 20` LTS and Bun, uses Bun (`bun test`, `bun build`, committed `bun.lock`) with `tsc --noEmit`, Biome linting, and a Bun-runnable DD harness + `scenarios/` runner, and upgrades dependencies to latest stable versions for the breaking major release (D10, D11, D13).
- **Protocol Conformance:** Conforms to the latest MCP specification supported by `@modelcontextprotocol/sdk` (`2025-11-25`), advertising only implemented capabilities (D13, U4).
- **Privacy & Statelessness:** No fetched content, credentials, or request history is persisted across calls (D3).

## Invariants

Statements that must always be true, however the system is used, in whatever order things happen, and whatever data
the outside world sends.

**Status:** *Decided* invariants follow from a decision or requirement (the source column), or were confirmed
directly. *Proposed* ones were inferred while building and need confirming. *Placeholder* ones describe a stand-in
for an undecided rule and will change with it.

| # | Invariant | Source | Status |
|---|---|---|---|
| I1 | Every Target URL (initial request and every redirect hop) uses `http:` or `https:` and never targets `localhost`, `*.localhost`, or any IANA-reserved IPv4/IPv6 literal (including IPv4-mapped IPv6 and multicast); malformed IP inputs fail closed. | D8 | Decided |
| I2 | On direct (non-proxied) connections, every DNS record resolved for a hostname must be a public IP and validated addresses are pinned directly to the socket; DNS errors or empty answers fail closed. | D8 | Decided |
| I3 | `fetch transcript` accepts only allowlisted YouTube hosts (`youtube.com`, `www.youtube.com`, `m.youtube.com`, `music.youtube.com`, `youtu.be`), and input/SSRF validation failures (including invalid language codes) are never swallowed into fallback. | D7, D8 | Decided |
| I4 | Sensitive headers (`Authorization`, `Cookie`, `Proxy-Authorization`) are never forwarded across an origin boundary during HTTP redirects. | D9 | Decided |
| I5 | No Raw Response may exceed `MAX_RESPONSE_BYTES` in either raw wire bytes or decompressed bytes. | D9 | Decided |
| I6 | An Agent calling an MCP tool can never supply or override proxy routing. | D2, D6 | Decided |

## Not Yet in Scope

- Headless browser / JavaScript-rendered SPA execution (D3).
- Non-GET HTTP methods (POST, PUT, DELETE, etc.) and persistent cookie jars or sessions (D3).
- Multi-tenant authentication and per-user access scoping (D3; see [issue #47](docs/github/issues/047-question-about-auth-approach.md)).
- Persistent caching or local storage of fetched pages (D3).
- Remote MCP transports over HTTP or SSE (D3).

## Decision Log

### D1. Dual interface over a shared domain core

- **Decided (2026-11-25):** Fetch MCP exposes both an MCP stdio server (`mcp-fetch-server`) and a local CLI (`mcp-fetch`), both delegating to one shared pure domain core.

### D2. Canonical actors and trust boundary

- **Decided (2026-11-25):** The system recognizes three actors: **Agent** (untrusted MCP tool caller), **CLI User** (local human or script invoking `mcp-fetch`), and **Operator** (configures runtime limits and proxy policy via environment variables). The distinction exists because an Agent is untrusted with host network routing, whereas an Operator (and local CLI User) is trusted.

### D3. Core scope and explicit non-goals

- **Decided (2026-11-25):** Fetch MCP is a lightweight, SSRF-hardened web fetcher that retrieves public HTTP(S) content and YouTube video transcripts and returns them in agent-ready text formats. Headless browser rendering, non-GET HTTP methods/cookie jars, multi-tenant auth, persistent response caching, and remote MCP HTTP/SSE transports are out of scope for now.

### D4. Canonical domain vocabulary

- **Decided (2026-11-25):** The domain speaks a unified vocabulary: Nouns are **Target URL**, **Format** (`html`, `markdown`, `readable`, `text`, `json`, `youtube-transcript`), **Fetch Request**, **Raw Response**, and **Proxy Policy**; Derived Nouns are **Rendered Output**, **Transcript**, and **Windowed Excerpt**; Verbs are **fetch** (general web content) and **fetch transcript** (YouTube transcripts).

### D5. Supported proxy protocols

- **Decided (2026-11-25):** Operator proxies (`HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY`, honoring `NO_PROXY`) and CLI `--proxy` overrides support HTTP, HTTPS, and SOCKS (`socks4`/`socks5`) proxy protocols.

### D6. Interface parameter parity and proxy trust boundary

- **Decided (2026-11-25):** MCP tools never accept a caller-supplied `proxy` parameter because an **Agent** is untrusted; proxy routing for MCP comes exclusively from **Operator** environment variables. Both MCP tools and the CLI (`--header`) accept custom request headers; only the CLI accepts `--proxy` because the **CLI User** is the local operator.

### D7. YouTube transcript retrieval strategy

- **Decided (2026-11-25):** `fetch transcript` invokes local `yt-dlp` first when available on `PATH`, falling back to direct YouTube page + caption XML extraction if `yt-dlp` is unavailable or fails. Input validation / SSRF errors must never be swallowed into fallback.

### D8. SSRF protection and proxy DNS delegation

- **Decided (2026-11-25):** Every Target URL and redirect hop is validated locally to allow only `http:`/`https:` and block `localhost`/`*.localhost` and all IANA-reserved IPv4/IPv6 ranges (including IPv4-mapped IPv6 and multicast), failing closed on malformed IPs. Direct connections resolve and validate all DNS records and pin them to the socket to prevent DNS rebinding. When an Operator or CLI proxy is active, URL/IP literal validation still runs locally while hostname DNS resolution is delegated to the proxy consistently across both `fetch` and `fetch transcript`.

### D9. Response limits, timeouts, redirects, and cross-origin header stripping

- **Decided (2026-11-25):** Default Windowed Excerpt length is `5000` characters (`DEFAULT_LIMIT`, with `0` meaning unlimited), max Raw Response body size is `10 MB` (`MAX_RESPONSE_BYTES`, enforced on both raw and decompressed streams), request and subprocess timeout is `30s`, maximum redirect hops is `10`, and sensitive headers (`Authorization`, `Cookie`, `Proxy-Authorization`) are stripped on any cross-origin redirect.

### D10. Breaking next major release

- **Decided (2026-11-25):** The decision-driven redesign is a breaking major release; MCP tool names, CLI subcommands/flags, and runtime dependencies may be renamed or upgraded to match Terminology and current standards.

### D11. Bun toolchain with typecheck, Biome lint, and DD harness

- **Decided (2026-11-25):** Keep Bun (`bun test`, `bun build`, `bun.lock`) as the build and test toolchain, adding `tsc --noEmit` typechecking, Biome linting, and a Bun-runnable DD harness + `scenarios/` runner.

### D12. Breaking MCP tool and CLI subcommand names

- **Decided (2026-11-25):** Align MCP tool names and CLI subcommands directly to Terminology (per D4, D10): six MCP tools (`fetch_html`, `fetch_markdown`, `fetch_readable`, `fetch_text`, `fetch_json`, `fetch_transcript`) and six matching CLI subcommands (`html`, `markdown`, `readable`, `text`, `json`, `transcript`).

### D13. Runtime floor and MCP conformance target

- **Decided (2026-11-25):** Support Node.js `>= 20` LTS and Bun, upgrade runtime dependencies to latest stable versions with a committed `bun.lock`, and conform to the latest MCP specification supported by `@modelcontextprotocol/sdk` (`2025-11-25`, deferring `2026-07-28` `server/discover` until SDK support lands).

### D14. Explicit failure semantics and typed domain errors

- **Decided (2026-11-25):** Non-2xx HTTP responses, invalid JSON in `json` format, unparseable Readability documents in `readable` format, and SSRF/limit/timeout violations all return typed domain errors (`Result`), mapped to `isError: true` in MCP responses and `stderr` + exit code `1` in the CLI. A `startIndex` at or beyond output length returns an empty Windowed Excerpt (`""`).

### D15. Windowed Excerpt returns sliced text only

- **Decided (2026-11-25):** `Windowed Excerpt` returns only the sliced character substring with no appended truncation footer or inline metadata, keeping machine-parseable formats (such as JSON and HTML) unmodified. Resolves U2.

### D16. Web Format rendering rules

- **Decided (2026-11-25):** Rendering rules for web formats are: `html` returns the unmodified response text; `json` parses via `JSON.parse` and re-serializes compactly via `JSON.stringify` (failing on invalid JSON); `text` removes `<script>` and `<style>` elements, extracts `body.textContent`, and collapses/trims whitespace; `markdown` strips `<script>` and `<style>` elements before Turndown conversion; `readable` extracts the main article with Mozilla Readability, converts `article.content` with Turndown, and prepends `# <article.title>\n\n` when a non-empty title is present (failing if Readability returns `null`).

### D17. Binary Content-Type guard and HTTP response decoding

- **Decided (2026-11-25):** `fetch` rejects clearly binary `Content-Type` responses (`image/*`, `audio/*`, `video/*`, `application/octet-stream`, `application/pdf`, `application/zip`, `font/*`) with a typed error. Text-based or missing `Content-Type` responses are decoded as UTF-8. Redirect statuses (`301`, `302`, `303`, `307`, `308`) with no `Location` header are treated as non-2xx HTTP errors. Supported `Content-Encoding` values (`gzip`, `x-gzip`, `deflate`, `br`) are decompressed under `MAX_RESPONSE_BYTES` (I5); unknown encodings are passed through unchanged.

### D18. Single-attempt delivery and request header hygiene

- **Decided (2026-11-25):** `fetch` is strictly single-attempt (never auto-retries 5xx, connection, or timeout errors). Default `User-Agent` and `Accept-Encoding` (`gzip, deflate, br`) headers are applied only when the caller has not supplied them (checked case-insensitively). Custom header names or values containing CR (`\r`) or LF (`\n`) control characters are rejected with a typed validation error.

### D19. Window noun and WebFormat subset

- **Decided (2026-11-25):** Formalize **Window** (`startIndex`, `maxLength`) as a Terminology noun, and define `WebFormat` as the five non-transcript web variants of **Format** (`html`, `markdown`, `readable`, `text`, `json`) used by `fetch`.

## Undecided Questions

| # | Question | Meanwhile |
|---|---|---|
| U1 | (`fetch-transcript`) When a requested `lang` caption track does not exist on a YouTube video, should `fetch transcript` fall back to the first available track or return a typed error? | Fall back to the first available track and report the actual language in the Transcript header. |
| U3 | (`proxy-and-limits`) For SOCKS proxies, should `socks5://` and `socks5h://` both delegate hostname DNS to the proxy per D8, or distinguish local vs. proxy DNS by scheme? | Delegate hostname DNS to the proxy for all SOCKS schemes (matching HTTP/HTTPS proxies under D8). |
| U4 | (`mcp-interface`) Should `tools/list` reject unrecognized pagination cursors with `-32602` (issue #49 SHOULD item), and when should MCP `2026-07-28` `server/discover` (issue #50) be adopted? | Follow `@modelcontextprotocol/sdk` defaults on `2025-11-25`. |

### Resolved questions

Pointers only, so an old reference to a U# still leads somewhere. The decision says what was decided.

| # | Resolved by |
|---|---|
| U2 | D15 |
