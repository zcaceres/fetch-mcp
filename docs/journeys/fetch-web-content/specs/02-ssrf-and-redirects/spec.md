# Slice 02: SSRF & Redirects

Part of the [Fetch Web Content plan](../../plan.md). Decisions referenced as D# / U# / I# are in
[`REQUIREMENTS.md`](../../../../../REQUIREMENTS.md). Builds on [slice 01](../01-basic-html-fetch/spec.md).

Covers [acceptance criteria](../../acceptance-criteria.md) FW-3 (full IPv4/IPv6), FW-4, and FW-6.

## Goal

Harden `src/fetching/` with full IANA-reserved IPv4/IPv6 SSRF protection (including IPv4-mapped IPv6, CGNAT, cloud
IMDS, multicast, and fail-closed malformed IP checks), direct-connection DNS lookup validation (blocking private IPs,
empty answers, and lookup failures), and manual HTTP redirect handling up to 10 hops with relative `Location`
resolution, per-hop SSRF + DNS validation, cross-origin sensitive header stripping, and missing-`Location` refusal.

**Done when:** `bun run lint`, `bun run typecheck`, `bun test`, and
`bun run harness run scenarios/fetch-web-content` (both Slice 01 and Slice 02 scenarios) all pass cleanly.

## Scope

**In:**
- `src/fetching/queries.ts`: full `isReservedIp` (IPv4 + IPv6 + IPv4-mapped IPv6 + multicast + fail-closed) and `stripCrossOriginHeaders` (`Authorization`, `Cookie`, `Proxy-Authorization`, case-insensitive).
- `src/fetching/verbs.ts`: upgrade `prepareFetch` to use `isReservedIp` and accept `headers`; add `validateResolvedIps` and `validateRedirectHop`.
- `src/fetching/nouns.ts` & `src/fetching/ports.ts`: add `Headers`, `ResolvedIp`, `RedirectStep`, `too_many_redirects` error kind, and pass request `headers` to `HttpGetPort`.
- `src/integrations/dns/mock.ts`: default public fixtures (`example.com`, `origin-a.example.com`, `origin-b.example.com`) plus `empty(host)` and `fail(host, reason)` controls.
- `src/integrations/origin/mock.ts`: record received request headers per URL, add `redirect(url, status, location)` and `lastHeaders(url)` controls.
- Harness commands: `--header <Key:Value>` on `fetch`, redirect loop + DNS check in `fetch`, `origin redirect` / `origin last-headers`, and `dns empty` / `dns fail`.

**Out:**
- `markdown`, `readable`, `text`, `json` rendering and binary `Content-Type` rejection (waits on Slice 03: `03-formats-and-content-guards`).
- Compression (`gzip`/`deflate`/`br`), `MAX_RESPONSE_BYTES`, `30s` timeout, default `User-Agent`/`Accept-Encoding` deduplication, and CR/LF header rejection (waits on Slice 04: `04-limits-compression-and-timeouts`).
- Real IP-pinned HTTP(S) client and `mcp-fetch` CLI wiring (waits on Slice 05: `05-real-transport-and-cli-wiring`).
- Proxy DNS delegation (waits on `proxy-and-limits` journey).

## Vocabulary

The Terminology this slice uses.

- **Target URL**, **Format** (`WebFormat`: `html`), **Window**, **Fetch Request**, **Raw Response**, **Rendered Output** *(derived)*, **Windowed Excerpt** *(derived)*, **fetch**.

## What it reads and writes

| Payload | Shape |
|---|---|
| `Headers` | `Readonly<Record<string, string>>` |
| `ResolvedIp` | `Brand<string, 'ResolvedIp'>` |
| `FetchRequest` | `{ readonly url: TargetUrl; readonly format: WebFormat; readonly headers: Headers; readonly window: Window }` |
| `RedirectStep` | `{ readonly nextUrl: TargetUrl; readonly headers: Headers }` |
| `FetchError` | Adds `{ readonly kind: 'too_many_redirects'; readonly message: string }` to Slice 01's discriminated union |

## Verbs (`src/fetching/verbs.ts`)

| Function | Rule | Error |
|---|---|---|
| `prepareFetch(input: RawFetchInput, defaultLimit?: number): Result<FetchRequest, FetchError>` | Same as Slice 01, upgraded to check all IPv4/IPv6 reserved ranges via `isReservedIp` and carry `headers` (D4, D8, D9, D14, I1). | Same as Slice 01 (`Blocked Target URL: private address "<host>"` now covers all reserved IPv4/IPv6 and IPv4-mapped IPv6 literals) |
| `validateResolvedIps(hostname: string, addresses: readonly string[]): Result<readonly ResolvedIp[], FetchError>` | Requires at least one address and every resolved IP to be public (`!isReservedIp(ip)`); fails closed on empty answers or any reserved/malformed IP (D8, I2). | `Blocked Target URL: DNS lookup returned no addresses for "<hostname>"`<br>`Blocked Target URL: hostname "<hostname>" resolved to private IP "<ip>"` |
| `validateRedirectHop(currentUrl: TargetUrl, location: string, headers: Headers, hop: number, maxRedirects?: number): Result<RedirectStep, FetchError>` | Requires `hop < maxRedirects` (default `10`, D9), resolves `location` against `currentUrl`, enforces `I1` on the resolved URL, and strips sensitive headers via `stripCrossOriginHeaders` when `nextUrl.origin !== currentUrl.origin` (D8, D9, I1, I4). | `Too many redirects (exceeded <maxRedirects>)`<br>`Invalid redirect Location: "<location>"`<br>`Blocked Target URL: disallowed scheme "<protocol>" (only http: and https: are allowed)`<br>`Blocked Target URL: private address "<host>"` |
| `evaluateResponse(request: FetchRequest, response: RawResponse): Result<RenderedOutput, FetchError>` | Unchanged from Slice 01 — requires `200..299`, so a redirect status (`301`/`302`/`303`/`307`/`308`) with no `Location` header is refused here (D14, D17). | `HTTP error <status> fetching <url>` |

## Queries (`src/fetching/queries.ts`)

The derived nouns and pure checks this slice computes. Never stored, never refused.

| Function | Definition |
|---|---|
| `normalizeHostname(hostname: string): string` | Strips enclosing IPv6 brackets, lowercases, and trims trailing dots (D8, I1). |
| `isIpLiteral(host: string): boolean` | Returns `true` if `host` is a syntactically valid IPv4 or IPv6 literal (D8, I1). |
| `isReservedIp(ip: string): boolean` | Returns `true` for all IANA-reserved IPv4 ranges (`0.0.0.0/8`, `10.0.0.0/8`, `100.64.0.0/10`, `127.0.0.0/8`, `169.254.0.0/16`, `172.16.0.0/12`, `192.0.0.0/24`, `192.0.2.0/24`, `192.88.99.0/24`, `192.168.0.0/16`, `198.18.0.0/15`, `198.51.100.0/24`, `203.0.113.0/24`, `224.0.0.0/4`, `240.0.0.0/4`), all IANA-reserved IPv6 ranges (`::/96`, `::ffff:0:0/96` mapped IPv4 check, `::ffff:0:0:0/96`, `64:ff9b::/96`, `64:ff9b:1::/48`, `100::/64`, `2001::/32`, `2001:2::/48`, `2001:10::/28`, `2001:20::/28`, `2001:db8::/32`, `2002::/16`, `fc00::/7`, `fe80::/10`, `fec0::/10`, `ff00::/8`), and fails closed (`true`) on malformed, zone-scoped (`%`), or unrecognized inputs (D8, I1). |
| `stripCrossOriginHeaders(headers: Headers): Headers` | Returns a new header map excluding `authorization`, `cookie`, and `proxy-authorization` (matched case-insensitively) (D9, I4). |
| `windowedExcerpt(output: RenderedOutput, window: Window): WindowedExcerpt` | Unchanged from Slice 01 (D4, D9, D14, D15, D19). |

## Harness

| Command | Kind | What it does |
|---|---|---|
| `fetch <format> <url> [--start-index <N>] [--max-length <N>] [--header <Key:Value>]...` | domain | Calls `prepareFetch`, then runs the redirect loop (validating DNS via `dns.lookup` + `validateResolvedIps` for non-IP hostnames, fetching via `origin.get`, validating redirects via `validateRedirectHop`), then `evaluateResponse` and `windowedExcerpt`. |
| `origin redirect <url> <status> <location>` | world | Registers a mock redirect response with `Location: <location>` and prints `origin: redirect <status> <url> -> <location>`. |
| `origin last-headers <url>` | world | Prints `(not requested)` if `<url>` was never contacted, `(no headers)` if contacted with empty headers, or sorted `header: <Key>: <Value>` lines from the most recent request to `<url>`. |
| `dns empty <host>` | world | Registers an empty IP list for `<host>` and prints `dns: <host> -> (empty)`. |
| `dns fail <host> <reason...>` | world | Registers a DNS failure (`Blocked Target URL: DNS lookup failed for "<host>": <reason>`) and prints `dns: fail <host>`. |

## Placeholders

*(None — all rules in Slice 02 are settled by D8, D9, D14, D17, I1, I2, I4.)*

## Tests

- **Domain tests** (`src/fetching/fetching.test.ts`): pure given/when/then tests for `isReservedIp` (all IPv4 reserved ranges, public IPv4s, IPv6 loopback/ULA/link-local/multicast/NAT64/Teredo/documentation/6to4, IPv4-mapped IPv6 both dotted and WHATWG hex for private and public IPs, zone-scoped & malformed fail-closed), `stripCrossOriginHeaders` (mixed-case stripping + preserving custom headers), `validateResolvedIps` (all public, mixed public+private rebinding, empty list, malformed IP), and `validateRedirectHop` (same-origin preserves headers, cross-origin strips sensitive headers, relative `Location` resolution, redirect limit at 10, disallowed scheme, private IP/host).
- **Scenario:** `scenarios/fetch-web-content/02-ssrf-and-redirects.txt` (plus Slice 01 scenario continues to pass).
