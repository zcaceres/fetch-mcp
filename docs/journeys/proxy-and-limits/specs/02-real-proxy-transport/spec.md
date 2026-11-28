# Slice 02: Real HTTP, HTTPS CONNECT & SOCKS Proxy Transport

Part of the [Proxy & Limits plan](../../plan.md). Decisions referenced as D# / U# / I# are in
[`REQUIREMENTS.md`](../../../../../REQUIREMENTS.md). Builds on [slice 01](../01-operator-limits-and-proxy-policy/spec.md).

Covers [acceptance criteria](../../acceptance-criteria.md) PL-9 (real HTTP, HTTPS `CONNECT`, and SOCKS4/4a/5/5h proxy
forwarding with auth, timeout, byte caps, and credential redaction).

## Goal

Extend `src/integrations/origin/client.ts` (backed by a zero-dependency `src/integrations/origin/proxy.ts` tunnel
module) so `createRealHttpGet` fulfills the 4th `proxyUrl?: string` parameter of `HttpGetPort` across all six
supported proxy protocols (`http:`, `https:`, `socks4:`, `socks4a:`, `socks5:`, `socks5h:`) (`D5`, `D23`). Preserve
local IP-pinning when direct (`I2`), delegate hostname DNS to the proxy when proxied (`D8`, `D23`), enforce
`MAX_RESPONSE_BYTES` (`I5`) and `30s` timeout (`D9`), never auto-retry (`D18`), and redact proxy credentials in every
error message. Add `origin proxy-fail` in the harness so proxy failure & credential-redaction behavior is scripted.

**Done when:** `bun run lint`, `bun run typecheck`, `bun run build`, `bun test` (including real local HTTP, CONNECT,
SOCKS4a, and SOCKS5 proxy integration tests), and `bun run harness run scenarios` pass cleanly.

## Scope

**In:**
- `src/integrations/origin/proxy.ts`: zero-dependency proxy tunnel & auth helpers:
  - `buildProxyAuthHeader(proxyUrl: URL): string | undefined`
  - `openHttpConnectTunnel(proxyUrl: URL, targetUrl: URL, timeoutMs: number): Promise<Result<net.Socket, TunnelError>>`
  - `openSocks4Tunnel(proxyUrl: URL, targetUrl: URL, timeoutMs: number): Promise<Result<net.Socket, TunnelError>>` (SOCKS4 IPv4 + SOCKS4a domain extension per `D23`)
  - `openSocks5Tunnel(proxyUrl: URL, targetUrl: URL, timeoutMs: number): Promise<Result<net.Socket, TunnelError>>` (RFC 1928 + RFC 1929 username/password auth, ATYP `0x03` domain name per `D23`)
  - `wrapTlsOverTunnel(socket: net.Socket, targetUrl: URL, timeoutMs: number): Promise<Result<tls.TLSSocket, TunnelError>>` (`TunnelError = { readonly kind: 'timeout' | 'proxy_error'; readonly message: string }`)
- `src/integrations/origin/client.ts`: route `createRealHttpGet` through direct IP-pinned sockets (`proxyUrl === undefined`), HTTP absolute-URI forwarding (`http:` target via `http:`/`https:` proxy), HTTPS `CONNECT` tunnel (`https:` target via `http:`/`https:` proxy), or SOCKS4/4a/5/5h tunnel (`http:` or `https:` target), preserving streaming `maxBytes`, `timeoutMs`, single-attempt delivery, and credential-redacted error messages.
- `src/integrations/origin/proxy.test.ts`: real local TCP/HTTP/CONNECT/SOCKS4a/SOCKS5 server integration tests proving auth, remote hostname delegation (`ATYP 0x03` / SOCKS4a), non-200 CONNECT / SOCKS refusal + credential redaction, `maxBytes` streaming cap, timeout abortion, and `executeFetch` end-to-end SSRF blocking when proxied.
- `src/integrations/origin/mock.ts` & `cli/commands/origin.ts`: add `proxyFail(url, reason)` mock control and `origin proxy-fail <url> <reason...>` world command returning `Network error fetching <url> via proxy <redactedProxyUrl>: <reason>` when a request to `<url>` uses a proxy.

**Out:**
- Wiring `src/cli.ts` (`mcp-fetch`) to `src/policy/` and removing legacy `Fetcher` proxy fallback (waits on Slice 03: `03-cli-proxy-and-limits-wiring`).
- MCP server (`src/index.ts`) Operator proxy/limit wiring (waits on `mcp-interface` journey).

## Vocabulary

The Terminology this slice uses.

- **Target URL**, **Proxy Policy**, **Wire Response**, **Raw Response**, **fetch**.

## What it reads and writes

| Module | Contract | Error |
|---|---|---|
| `createRealHttpGet` (`src/integrations/origin/client.ts`) | Implements `HttpGetPort(url, headers, pinnedIps, proxyUrl?)`. Uses `pinnedIps` when direct; uses `proxyUrl` via HTTP forwarding, HTTPS `CONNECT`, or SOCKS4/4a/5/5h when proxied (`D5`, `D8`, `D9`, `D23`, `I2`, `I5`). | `Network error fetching <url> via proxy <redactedProxyUrl>: <reason>`<br>`Request timed out after <timeoutMs>ms fetching <url>`<br>`Response too large: <declared> bytes exceeds <maxBytes> byte limit`<br>`Response too large: exceeded <maxBytes> byte limit` |

## Harness

| Command | Kind | What it does |
|---|---|---|
| `origin proxy-fail <url> <reason...>` | world | Configures mocked origin/proxy to fail proxied requests to `<url>` with `Network error fetching <url> via proxy <redactedProxyUrl>: <reason>`; prints `origin: proxy-fail <url>`. |

## Placeholders

*(None — all rules in Slice 02 are settled by D5, D8, D9, D14, D18, D23, D24, I1, I2, I5.)*

## Tests

- **Real local proxy integration tests** (`src/integrations/origin/proxy.test.ts`):
  - HTTP proxy forwarding with `Proxy-Authorization: Basic ...` header verification
  - HTTPS proxy `CONNECT` tunnel + `CONNECT` auth + non-200 `CONNECT` failure redacting `user:pass`
  - SOCKS5 (`socks5:` and `socks5h:`) no-auth and RFC 1929 username/password auth, asserting ATYP `0x03` hostname delegation (unresolvable `.invalid` host succeeds via proxy!)
  - SOCKS4 (`socks4:` and `socks4a:`) asserting `0.0.0.1` + hostname SOCKS4a domain delegation and userid auth
  - Streaming `maxBytes` cap (`I5`), proxy timeout (`D9`), and `executeFetch` blocking `http://127.0.0.1` locally even with active SOCKS5 proxy (`I1`, `D8`)
- **Scenario:** `scenarios/proxy-and-limits/02-real-proxy-transport.txt`.
