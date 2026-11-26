# Runbook: Fetch Web Content

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
| `scenarios/fetch-web-content/01-basic-html-fetch.txt` | Tracer bullet: `fetch html`, Windowed Excerpt slicing, non-2xx/network error, malformed input & basic SSRF refusal [FW-1, FW-3, FW-5, FW-10, FW-14] |
| `scenarios/fetch-web-content/02-ssrf-and-redirects.txt` | Full IPv4/IPv6 SSRF blocking, direct DNS validation & rebinding refusal, redirect loop, per-hop SSRF, cross-origin header stripping, missing Location [FW-3, FW-4, FW-6] |
| `scenarios/fetch-web-content/03-formats-and-content-guards.txt` | Binary Content-Type guard, `json`/`text`/`markdown`/`readable` rendering, invalid JSON & Readability parse errors [FW-9, FW-11, FW-12, FW-13] |
| `scenarios/fetch-web-content/04-limits-compression-and-timeouts.txt` | Default header deduplication & CR/LF rejection, `gzip`/`deflate`/`br` decompression & unknown encoding passthrough, `MAX_RESPONSE_BYTES` on headers/wire/decompressed streams, `30s` single-attempt timeout [FW-2, FW-7, FW-8] |

```bash
bun run harness run scenarios/fetch-web-content
```

## By hand

### 1. Live network CLI smoke check (after Slice 05)

1. Run `bun run build && node dist/cli.js readable https://example.com --max-length 500`.
   - Prints readable Markdown (beginning with `# Example Domain` if present) to `stdout` and exits `0`. [FW-13, FW-15]
2. Run `node dist/cli.js html http://127.0.0.1/`.
   - Writes the blocked Target URL error to `stderr` and exits `1` without making a network request. [FW-3, FW-15]
