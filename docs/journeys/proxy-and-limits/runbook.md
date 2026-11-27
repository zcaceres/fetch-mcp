# Runbook: Proxy & Limits

How a person, or an agent, walks the journey by hand: what needs eyes, a browser, a real sandbox or a judgment
call. Everything that can be scripted is a scenario, listed below; the [acceptance criteria](acceptance-criteria.md)
each step shows are in brackets.

## Before you start

```bash
bun install
bun run harness        # interactive; type help
```

Every external system is mocked in memory and starts from its fixtures; `reset` starts again.

## Scenarios

| Scenario | Shows |
|---|---|
| `scenarios/proxy-and-limits/01-operator-limits-and-proxy-policy.txt` | Tracer bullet: `DEFAULT_LIMIT`/`MAX_RESPONSE_BYTES` valid & invalid env vars, env proxy precedence & bare `host:port`, `NO_PROXY` vs CLI `--proxy`, malformed/unsupported proxy refusal, per-hop redirect Proxy Policy re-evaluation, local SSRF + delegated DNS for both `fetch` and `fetch transcript` (`--proxy` to `yt-dlp` and direct fallback) [PL-1, PL-2, PL-3, PL-4, PL-5, PL-6, PL-7, PL-8] |
| `scenarios/proxy-and-limits/02-real-proxy-transport.txt` | SOCKS4/4a/5/5h DNS delegation and proxied failure reporting with credential redaction [PL-9] |
| `scenarios/proxy-and-limits/03-cli-proxy-and-limits-wiring.txt` | Operator `DEFAULT_LIMIT` & `MAX_RESPONSE_BYTES` on `fetch-transcript`, `NO_PROXY` port matching, and `--proxy` overriding `NO_PROXY` on `fetch-transcript` [PL-1, PL-2, PL-4, PL-8] |

```bash
bun run harness run scenarios/proxy-and-limits
```

## By hand

### 1. CLI invalid env & proxy smoke check (after Slice 03)

1. Run `bun run build && DEFAULT_LIMIT=bad node dist/cli.js html https://example.com`.
   - Writes `Invalid DEFAULT_LIMIT "bad": must be a non-negative integer` to `stderr` and exits `1`. [PL-2, PL-10]
2. Run `HTTP_PROXY=ftp://proxy:21 node dist/cli.js html http://example.com`.
   - Writes `Unsupported proxy protocol "ftp:" (supported: http, https, socks4, socks4a, socks5, socks5h)` to `stderr` and exits `1`. [PL-5, PL-10]
3. Run `node dist/cli.js html http://127.0.0.1/secret --proxy http://127.0.0.1:8080`.
   - Writes `Blocked Target URL: private address "127.0.0.1"` to `stderr` and exits `1`. [PL-7, PL-10]
