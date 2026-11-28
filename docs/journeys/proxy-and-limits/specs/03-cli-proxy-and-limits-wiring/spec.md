# Slice 03: CLI Proxy & Limits Wiring

Part of the [Proxy & Limits plan](../../plan.md). Decisions referenced as D# / U# / I# are in
[`REQUIREMENTS.md`](../../../../../REQUIREMENTS.md). Builds on [slice 02](../02-real-proxy-transport/spec.md).

Covers [acceptance criteria](../../acceptance-criteria.md) PL-10 (wiring `mcp-fetch` CLI web and transcript
subcommands onto `src/policy/`, `executeFetch`, and `executeFetchTranscript`, and removing legacy `Fetcher` proxy
fallback completely).

## Goal

Rewire `src/cli.ts` (`mcp-fetch`) so every subcommand (`html`, `markdown`, `readable`, `text`, `json`, `transcript`)
uses `parseOperatorLimits` (fail-fast per `D25`) and `resolveProxyPolicy` (`D5`, `D6`, `D23`, `D24`, `D26`) over
`executeFetch` / `executeFetchTranscript` + real proxied `createRealHttpGet` / `createRealYtDlp`. Remove the legacy
`Fetcher` import and proxy fallback branches from `src/cli.ts` completely (`D1`, `D12`, `D14`).

**Done when:** `bun run lint`, `bun run typecheck`, `bun run build`, `bun test` (including CLI proxy & limits tests),
offline CLI smoke checks from [runbook.md](../../runbook.md), and `bun run harness run scenarios` (all journeys) pass
cleanly.

## Scope

**In:**
- `src/cli.ts`:
  - Remove `Fetcher` import, `parsePositiveEnvInt`, `hasEnvProxy`, and both legacy proxy fallback branches (`case 'fetch'` and `case 'transcript'`).
  - Parse Operator limits via `parseOperatorLimits(env)` before invoking domain orchestration, writing `<error.message>\n` to `stderr` with exit `1` on invalid `DEFAULT_LIMIT` or `MAX_RESPONSE_BYTES` (`D25`).
  - Wire `resolveProxy` callbacks backed by `resolveProxyPolicy(targetUrl, env, action.proxy)` into both `executeFetch` and `executeFetchTranscript` (`D23`, `D24`, `D26`).
- `src/cli.test.ts`:
  - Tests for `runCli` Operator limits (`DEFAULT_LIMIT`, `DEFAULT_LIMIT=0`, `MAX_RESPONSE_BYTES`, and fail-fast invalid env values on both web and transcript subcommands).
  - Tests for `runCli` web subcommands with env proxies (`HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`), `NO_PROXY`, explicit `--proxy` overriding `NO_PROXY`, unsupported proxy refusal, delegated DNS, and local SSRF blocking.
  - Tests for `runCli transcript` with env proxy / `--proxy` (skipping local DNS `checkHost`, passing `--proxy` to `ytDlp`, and proxied direct fallback).
- `scenarios/proxy-and-limits/03-cli-proxy-and-limits-wiring.txt`: scripts `DEFAULT_LIMIT` & `MAX_RESPONSE_BYTES` on `fetch-transcript`, `NO_PROXY` host/port/canonical-IPv6 matching, per-hop redirect proxy-switch and proxied-to-direct SSRF refusal, and explicit `--proxy` overriding `NO_PROXY` on `fetch-transcript`.

**Out:**
- MCP server (`src/index.ts`) Operator env proxy/limit wiring, tool renames, and legacy retirement (covered in `mcp-interface`, `D27`–`D29`).

## Vocabulary

The Terminology this slice uses.

- **Operator**, **CLI User**, **Target URL**, **Format**, **Window**, **Fetch Request**, **Operator Limits**, **Proxy Policy**, **Windowed Excerpt** *(derived)*, **parse operator limits**, **resolve proxy policy**, **fetch**, **fetch transcript**.

## What it reads and writes

| Caller | Rule | Error |
|---|---|---|
| `runCli(argv, deps)` (`src/cli.ts`) | Parses CLI args, calls `parseOperatorLimits(env)` (`D25`), builds `resolveProxy` via `resolveProxyPolicy(targetUrl, env, action.proxy)` (`D23`, `D24`, `D26`), and dispatches all six subcommands exclusively through `executeFetch` / `executeFetchTranscript` + real or injected ports (zero `Fetcher` fallback). | Exact `PolicyError`, `FetchError`, or `TranscriptError` message to `stderr` with exit code `1` (`D14`) |

## Harness

No new harness commands; reuses `env`, `origin`, `dns`, `ytdlp`, `fetch`, and `fetch-transcript` from Slices 01–02.

## Placeholders

*(None — all rules in Slice 03 are settled by D1, D2, D5, D6, D8, D9, D12, D14, D15, D21, D23, D24, D25, D26, I1–I5.)*

## Tests

- **CLI integration tests** (`src/cli.test.ts`): Operator limits (valid & fail-fast invalid), env proxy precedence + `NO_PROXY` + `--proxy` override, unsupported proxy refusal, proxied `fetch` and `fetch-transcript` (both `yt-dlp` `--proxy` and direct fallback) with `stdout`/exit `0` and `stderr`/exit `1` (`PL-10`).
- **Built binary smoke checks** (`node dist/cli.js`): all three checks in [runbook.md](../../runbook.md) (`DEFAULT_LIMIT=bad`, `HTTP_PROXY=ftp://proxy:21`, and `http://127.0.0.1/secret --proxy http://127.0.0.1:8080`).
- **Scenario:** `scenarios/proxy-and-limits/03-cli-proxy-and-limits-wiring.txt`.
