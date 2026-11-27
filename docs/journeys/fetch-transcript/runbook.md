# Runbook: Fetch Transcript

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
| `scenarios/fetch-transcript/01-direct-transcript-extraction.txt` | Tracer bullet: YouTube host allowlist & `lang`/CR-LF validation, direct watch-page + caption XML extraction, exact/prefix `lang` selection & available-language error, `srv1`/`srv3` parsing + entity decoding, empty-XML refusal, and Windowed Excerpt slicing [FT-1, FT-2, FT-5, FT-6, FT-7, FT-8, FT-9] |
| `scenarios/fetch-transcript/02-ytdlp-primary-and-fallback.txt` | `yt-dlp` primary invocation (`--write-sub`, `--write-auto-sub`, `--` sentinel), direct extraction fallback on failure/empty output, and strict non-swallowing of validation and DNS SSRF errors [FT-3, FT-4] |
| `scenarios/fetch-transcript/03-real-ytdlp-and-cli-wiring.txt` | `yt-dlp` timeout fallback (`30s`), regional prefix + Window slicing on `yt-dlp` path, and `dns fail` / `dns empty` / mixed IPv4-mapped IPv6 blocking before `yt-dlp` [FT-2, FT-3, FT-4, FT-6, FT-9] |

```bash
bun run harness run scenarios/fetch-transcript
```

## By hand

### 1. Live YouTube CLI smoke check (after Slice 03)

1. Run `bun run build && node dist/cli.js transcript https://www.youtube.com/watch?v=jNQXAC9IVRw --max-length 300`.
   - Prints `[Transcript language: en — ...]` followed by timestamped lines to `stdout` and exits `0`. [FT-3, FT-7, FT-9, FT-10]
2. Run `node dist/cli.js transcript https://example.com/not-youtube`.
   - Writes `Blocked Target URL: host "example.com" is not an allowlisted YouTube domain` to `stderr` and exits `1`. [FT-2, FT-10]
