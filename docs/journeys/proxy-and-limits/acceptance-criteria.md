# Proxy & Limits: Acceptance Criteria

An **Operator** configures process-level proxy routing (`HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY`, `NO_PROXY`) and
resource limits (`DEFAULT_LIMIT`, `MAX_RESPONSE_BYTES`) via OS environment variables, or a **CLI User** passes an
explicit `--proxy` override, and the system enforces the resulting **Proxy Policy** and limits consistently across
`fetch` and `fetch transcript` ([plan](plan.md)).

Rules that hold whichever journey is involved, and the decisions (D#), questions (U#) and invariants (I#) cited here,
are in [`REQUIREMENTS.md`](../../../REQUIREMENTS.md). These criteria say what **Operator** and **CLI User** can do and
see; they cite rules rather than restate them. Each slice's [spec](specs/) names the criteria it covers.

Each criterion is one or more Gherkin scenarios tagged with its id (`@PL-1`) and the decisions, questions and
invariants it cites. Scenarios that share an id make up one criterion.

## Steps

1. **Parse Operator Limits.** System reads `DEFAULT_LIMIT` and `MAX_RESPONSE_BYTES` from OS Environment and fails explicitly on invalid values.
2. **Resolve Proxy Policy.** System resolves effective Proxy Policy per Target URL (and per redirect hop) from CLI `--proxy` or Operator env vars honoring `NO_PROXY`, normalizing bare `host:port` and rejecting malformed or unsupported proxy URLs.
3. **Enforce Local SSRF & Delegate DNS.** System validates Target URLs and YouTube host allowlists locally, pinning local DNS when direct and delegating hostname DNS to the proxy when proxied.
4. **Forward Through Proxy Server.** System routes HTTP, HTTPS (`CONNECT`), SOCKS (`socks4`/`socks4a`/`socks5`/`socks5h`), and `yt-dlp` (`--proxy`) traffic through the active Proxy Server under `30s` timeout and `MAX_RESPONSE_BYTES` caps, redacting credentials from error messages.
5. **Deliver Result or Typed Error.** System returns a Windowed Excerpt (bounded by `DEFAULT_LIMIT` when caller omits `maxLength`) or a typed error on CLI `stderr` (exit `1`).

## 1. Parse Operator Limits

```gherkin
@PL-1 @D2 @D9 @D15 @I5
Scenario: Valid DEFAULT_LIMIT and MAX_RESPONSE_BYTES env vars govern default Window length and Raw Response cap
  Given the Operator sets DEFAULT_LIMIT (including 0 for unlimited) and MAX_RESPONSE_BYTES
  When an actor runs fetch or fetch transcript without explicit maxLength
  Then the default Window uses DEFAULT_LIMIT and Raw Response bodies exceeding MAX_RESPONSE_BYTES are refused (D9, D15, I5)

@PL-2 @D2 @D14 @D25
Scenario: Invalid non-empty DEFAULT_LIMIT or MAX_RESPONSE_BYTES env vars fail explicitly
  Given the Operator sets DEFAULT_LIMIT to a negative or non-integer value, or MAX_RESPONSE_BYTES to 0, negative, or non-integer
  When an actor runs fetch or fetch transcript
  Then the request fails explicitly with a typed configuration error before any network or subprocess I/O (D14, D25)
```

## 2. Resolve Proxy Policy

```gherkin
@PL-3 @D2 @D5 @D24
Scenario: Operator env proxy precedence and bare host:port normalization
  Given the Operator sets HTTPS_PROXY, HTTP_PROXY, or ALL_PROXY (uppercase or lowercase, or bare host:port)
  When an actor fetches an https: or http: Target URL
  Then effective Proxy Policy follows D24 precedence and normalizes bare host:port to http:// (D5, D24)

@PL-4 @D2 @D6 @D24
Scenario: NO_PROXY bypasses Operator env proxies, while explicit CLI --proxy overrides both env proxies and NO_PROXY
  Given the Operator sets HTTP_PROXY/HTTPS_PROXY and NO_PROXY matching a host, subdomain suffix, port, IPv6 host, or "*"
  When an actor fetches a matching Target URL without --proxy
  Then the request uses a direct connection (D24)
  When a CLI User fetches the same Target URL with explicit --proxy
  Then the request routes through the explicit CLI proxy, bypassing NO_PROXY (D6, D24)

@PL-5 @D5 @D14 @D23 @D24 @D25 @D31 @I7
Scenario: Malformed, empty, bare-without-port, or unsupported proxy URLs fail explicitly without falling back or leaking credentials
  Given an Operator env var or CLI --proxy contains a malformed URL, bare host without :port, blank CLI --proxy, or unsupported scheme (such as ftp://)
  When an actor runs fetch or fetch transcript
  Then the request fails explicitly with a typed proxy configuration error with any credentials redacted and never contacts the origin directly (D14, D23, D24, D25, D31, I7)

@PL-6 @D8 @D24 @I1 @I4
Scenario: Proxy Policy is re-evaluated on every HTTP redirect hop
  Given an initial Target URL routes through a proxy (or direct via NO_PROXY) and redirects to a host with a different Proxy Policy
  When the actor fetches the Target URL
  Then each redirect hop is SSRF-validated locally (I1), strips sensitive headers cross-origin (I4), and re-evaluates Proxy Policy for the destination hop (D24)
```

## 3. Enforce Local SSRF & Delegate DNS

```gherkin
@PL-7 @D8 @D23 @I1 @I2
Scenario: Proxied fetch still blocks private Target URLs locally while delegating public hostname DNS to the proxy
  Given an active HTTP, HTTPS, or SOCKS Proxy Policy
  When an actor fetches "http://127.0.0.1/secret" or "http://localhost/admin"
  Then the request is refused locally as a blocked Target URL before contacting the proxy (D8, I1)
  When an actor fetches a public hostname whose local DNS would fail or be unavailable
  Then local DNS lookup is skipped and hostname resolution is delegated to the proxy (D8, D23)

@PL-8 @D7 @D8 @D21 @D26 @I1 @I3
Scenario: Proxied fetch transcript validates YouTube host locally, skips local DNS checkHost, and passes --proxy to yt-dlp and direct fallback
  Given an active Proxy Policy for a YouTube Target URL
  When an actor runs fetch transcript for a non-YouTube host
  Then the request is refused locally without invoking yt-dlp or contacting the proxy (I3, D26)
  When an actor runs fetch transcript for an allowlisted YouTube host whose local DNS is unavailable
  Then local DNS checkHost is skipped, yt-dlp receives --proxy before --, and direct fallback re-evaluates Proxy Policy across watch page and caption track URLs (D8, D21, D26)
```

## 4. Forward Through Proxy Server

```gherkin
@PL-9 @D5 @D9 @D14 @D23 @D31 @I5 @I7
Scenario: Real HTTP, HTTPS CONNECT, and SOCKS4/4a/5/5h proxies forward traffic with auth, timeout, byte caps, and credential redaction
  Given a reachable HTTP, HTTPS, SOCKS4/4a, or SOCKS5/5h Proxy Server (with or without credentials)
  When the real HTTP transport fetches a public HTTP or HTTPS Target URL through that proxy
  Then HTTP requests use absolute-URI with Proxy-Authorization, HTTPS requests use CONNECT tunneling, SOCKS proxies connect with remote hostname resolution, MAX_RESPONSE_BYTES and 30s timeout are enforced, and proxy errors redact credentials (D5, D9, D14, D23, D31, I5, I7)
```

## 5. Deliver Result or Typed Error

```gherkin
@PL-10 @D1 @D2 @D6 @D12 @D14 @D24 @D25 @D26
Scenario: CLI mcp-fetch applies Operator limits and Proxy Policy across web and transcript subcommands without legacy fallback
  Given Operator env vars or CLI --proxy on `mcp-fetch <subcommand>`
  When the CLI User runs a web or transcript subcommand
  Then both subcommands route through the shared domain core (`executeFetch` / `executeFetchTranscript`) honoring Operator limits and Proxy Policy, writing output to stdout (exit 0) or typed errors to stderr (exit 1) (D1, D6, D14, D24, D25, D26)
```
