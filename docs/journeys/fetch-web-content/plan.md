# Fetch Web Content: Plan

How the journey is built, slice by slice. What it must do is in its [acceptance criteria](acceptance-criteria.md);
decisions (D#) and questions (U#) are in [`REQUIREMENTS.md`](../../../REQUIREMENTS.md).

## Sources

The designs, flows, tickets and documents behind this journey, from its design session.

- [`REQUIREMENTS.md`](../../../REQUIREMENTS.md): system terminology, D1–D18, I1–I6.
- [src/fetching/](../../../src/fetching/), [src/integrations/origin/](../../../src/integrations/origin/), [src/integrations/dns/](../../../src/integrations/dns/), [src/cli.ts](../../../src/cli.ts): Functional DDD web-fetching implementation and real CLI wiring.

## Shape

An **Agent** or **CLI User** submits a **Fetch Request** naming a **Target URL**, a web **Format** (`html`, `markdown`,
`readable`, `text`, or `json`), optional custom headers, and optional Window bounds (`startIndex`, `maxLength`). The
domain core parses and validates the request (blocking disallowed schemes, local/reserved hosts, and CR/LF headers),
resolves and validates public DNS records on direct connections, retrieves a single-attempt **Raw Response** through
the origin port (following up to 10 validated redirects, stripping sensitive headers across origins, decompressing
supported encodings, and enforcing byte caps and timeouts), transforms the response into **Rendered Output** (rejecting
binary Content-Types and non-2xx statuses), and computes a **Windowed Excerpt** (sliced text only) to return to the
actor.

## Contexts, verbs and queries

Where this journey lives in the code. Each noun is a type in the context's `nouns.ts`. Each verb is a function in its
`verbs.ts`, and each derived noun a function in its `queries.ts`, each with a harness command of the same name.

| Context | Nouns | Verbs | Queries | Harness commands |
|---|---|---|---|---|
| `src/fetching/` | `TargetUrl`, `WebFormat`, `Window`, `FetchRequest`, `WireResponse`, `RawResponse`, `RenderedOutput`, `WindowedExcerpt`, `FetchError` | `prepareFetch`, `validateResolvedIps`, `validateRedirectHop`, `validateWireResponseSize`, `decodeResponseBody`, `evaluateResponse` | `normalizeHostname`, `isIpLiteral`, `isReservedIp`, `isBinaryContentType`, `stripCrossOriginHeaders`, `windowedExcerpt` | `fetch <format> <url> [--start-index N] [--max-length N] [--header K:V]` |

## External systems

Every system outside ours is mocked in `src/integrations/<system>/`; world commands make it do what the journey needs.

| System | What we need from it | World commands |
|---|---|---|
| origin (`src/integrations/origin/`) | HTTP(S) `GET` responses (status, headers, redirects, compressed/oversized/corrupted bodies, network errors, `30s` timeouts) | `origin serve`, `origin header`, `origin compress`, `origin repeat`, `origin corrupt`, `origin redirect`, `origin fail`, `origin timeout`, `origin last-headers`, `origin last-pinned`, `origin attempts` |
| dns (`src/integrations/dns/`) | Hostname-to-IP resolution for direct connections | `dns set <host> <ip...>`, `dns empty <host>`, `dns fail <host> <reason...>` |

## Slices

Each slice is one capability, wired through every part of the system (harness commands, verbs, ports, mocks) with
a scenario that runs it. The first is the **tracer bullet**: the narrowest path a user would recognize, and nothing
else. Each later slice adds one capability, chosen from the criteria not yet met or from what running the journey
turned up. Each has a [spec](specs/) and a scenario in `scenarios/fetch-web-content/`.

### Done

1. **01 — Basic HTML Fetch (Tracer Bullet).** Sets up the DD harness, `scenarios/` runner, `typescript` + Biome lint (D11), `src/shared/result.ts`, `src/fetching/` core, and `origin`/`dns` mocks; proves happy-path `fetch html`, Windowed Excerpt slicing, non-2xx HTTP error, request validation, and basic SSRF rejection (`file:`, `localhost`, private IPv4). Covers FW-1, FW-3 (basic), FW-5, FW-10, FW-14, D11.
   ([spec](specs/01-basic-html-fetch/spec.md), `scenarios/fetch-web-content/01-basic-html-fetch.txt`)
2. **02 — SSRF & Redirects.** Full IANA-reserved IPv4/IPv6 + IPv4-mapped IPv6 + multicast + malformed IP blocking, DNS lookup validation & rebinding refusal, redirect following up to 10 hops with relative `Location`, per-hop SSRF checks, cross-origin sensitive header stripping, and missing-`Location` refusal. Covers FW-3, FW-4 (harness validation), FW-6.
   ([spec](specs/02-ssrf-and-redirects/spec.md), `scenarios/fetch-web-content/02-ssrf-and-redirects.txt`)
3. **03 — Formats & Content Guards.** Adds `json` (parse/stringify + invalid JSON error), `text` (DOM script/style stripping + whitespace collapse), `markdown` (script/style stripping + Turndown), `readable` (Readability + Turndown with `# <title>` + parse error), and binary `Content-Type` rejection. Covers FW-9, FW-11, FW-12, FW-13.
   ([spec](specs/03-formats-and-content-guards/spec.md), `scenarios/fetch-web-content/03-formats-and-content-guards.txt`)
4. **04 — Limits, Compression & Timeouts.** Adds `gzip`/`deflate`/`br` decompression, unknown encoding passthrough, `MAX_RESPONSE_BYTES` enforcement on `Content-Length`, raw wire bytes, and decoded streams, `30s` timeout handling, and custom header hygiene (case-insensitive `User-Agent`/`Accept-Encoding` defaults, duplicate case-insensitive caller header handling, and CR/LF rejection). Covers FW-2, FW-7, FW-8.
   ([spec](specs/04-limits-compression-and-timeouts/spec.md), `scenarios/fetch-web-content/04-limits-compression-and-timeouts.txt`)
5. **05 — Real Transport & CLI Wiring.** Implements the real IP-pinned HTTP(S) client in `src/integrations/origin/client.ts` (wiring validated `ResolvedIp` records directly to sockets to complete FW-4 pinning) + real DNS port in `src/integrations/dns/client.ts`, shared `executeFetch`, and rewires `mcp-fetch` CLI (`html`, `markdown`, `readable`, `text`, `json`, `transcript`, `--header`, `--max-length`, `--start-index`). Covers FW-4, FW-15.
   ([spec](specs/05-real-transport-and-cli-wiring/spec.md), `scenarios/fetch-web-content/05-real-transport-and-cli-wiring.txt`)
6. **06 — Scenario Coverage & Doc Polish.** Added `attempts: 1` assertions on HTTP 200/500 in `scenarios/fetch-web-content/04-limits-compression-and-timeouts.txt`, default `5000`-char Windowed Excerpt truncation test in `src/fetching/fetching.test.ts`, `validateWireResponseSize` enforcement before non-2xx checks (`D17`, `I5`), and aligned `plan.md` + `specs/04`–`05`. Covers FW-5, FW-14.

### Next

*(All planned slices for `fetch-web-content` are complete.)*

## Deferred

- Non-UTF-8 charset transcoding (e.g. `ISO-8859-1`, `Shift_JIS` via `Content-Type` charset parameter): out of scope for this journey; responses are decoded as UTF-8 (D17).
- Content-Type negotiation / automatic Format inference: actors explicitly select Format (D4, D12).
- Custom Markdown/Turndown options (e.g. LaTeX preservation, link style flags): deferred until user demand warrants additional request options.
- Proxy routing (`HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`/`NO_PROXY`, SOCKS, `--proxy`) and Operator env limit configuration (`DEFAULT_LIMIT`, `MAX_RESPONSE_BYTES`): owned by the `proxy-and-limits` journey.
- MCP stdio tool schemas and server dispatch (`fetch_html`, `fetch_text`, etc.): owned by the `mcp-interface` journey.
