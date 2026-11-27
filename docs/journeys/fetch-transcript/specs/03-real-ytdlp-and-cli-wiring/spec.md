# Slice 03: Real yt-dlp Client & CLI Wiring

Part of the [Fetch Transcript plan](../../plan.md). Decisions referenced as D# / U# / I# are in
[`REQUIREMENTS.md`](../../../../../REQUIREMENTS.md). Builds on [slice 02](../02-ytdlp-primary-and-fallback/spec.md).

Covers [acceptance criteria](../../acceptance-criteria.md) FT-3 (real `30s` subprocess timeout), FT-2 (scripted
`dns fail` / `dns empty` blocking before `yt-dlp`), and FT-10 (`mcp-fetch transcript` CLI wiring).

## Goal

Implement the real async `yt-dlp` subprocess adapter (`src/integrations/ytdlp/client.ts`) using `node:child_process`
`execFile` (never a shell), `buildYtDlpArgs` with the `--` end-of-options sentinel (`D21`), a `30s` timeout (`D9`),
`MAX_RESPONSE_BYTES` cap on downloaded subtitle files (`I5`), and guaranteed temp-directory cleanup. Rewire
`mcp-fetch transcript` in `src/cli.ts` off legacy `Fetcher.youtubeTranscript` onto `executeFetchTranscript` linked to
real `executeFetch`, DNS `checkHost`, and `createRealYtDlp` (`D1`, `D6`, `D12`, `D14`), and add `ytdlp timeout` to the
harness to cover `yt-dlp` timeout fallback alongside `dns fail` / `dns empty` SSRF checks.

**Done when:** `bun run lint`, `bun run typecheck`, `bun run build`, `bun test` (including real `yt-dlp` subprocess and
CLI `transcript` tests), and `bun run harness run scenarios` (all `fetch-web-content` + `fetch-transcript` Slices
01–03) pass cleanly.

## Scope

**In:**
- `src/integrations/ytdlp/client.ts`: real async `YtDlpPort` (`createRealYtDlp(options?)`) with `isAvailable()` (cached `--version` probe returning `boolean`, never throwing) and `downloadSubtitles(url, lang)` (`mkdtemp`, `execFile` with `buildYtDlpArgs`, default `30000ms` timeout per `D9`, `MAX_RESPONSE_BYTES` file-size guard per `I5`, `.srv1` discovery, guaranteed `rm` cleanup in `finally`).
- `src/integrations/ytdlp/client.test.ts`: real subprocess integration tests using tiny temporary executable scripts to prove argv/sentinel passing, `.srv1` discovery + `matchedLang` extraction, non-zero exit handling, missing `.srv1` handling, timeout termination, `maxBytes` refusal, `isAvailable()` caching/missing-binary handling, and temp-dir cleanup in both success and failure paths.
- `src/cli.ts` & `src/cli.test.ts`: rewire `mcp-fetch transcript` onto `executeFetchTranscript` (wired with `FetchPagePort` → `executeFetch`, `CheckHostPort` → `dnsLookup` + `validateResolvedIps`, and `YtDlpPort` → `createRealYtDlp()`), preserving the proxy fallback seam to legacy `Fetcher.youtubeTranscript` only when `--proxy` or Operator proxy env vars are set (until `proxy-and-limits` replaces proxy routing). Add `ytDlp?: YtDlpPort` to `CliDeps` and unit/integration tests for `mcp-fetch transcript` in `src/cli.test.ts` (`FT-10`).
- `src/integrations/ytdlp/mock.ts` & `cli/commands/ytdlp.ts`: add `timeout(url)` mock control and `ytdlp timeout <url>` world command.

**Out:**
- Proxy routing for `yt-dlp` (`--proxy` / `HTTPS_PROXY`/`HTTP_PROXY`/`ALL_PROXY`/`NO_PROXY`) and removal of the legacy proxy fallback seam in `src/cli.ts` (waits on `proxy-and-limits` journey, `U3`).
- MCP `fetch_transcript` server tool schema and dispatch in `src/index.ts` (waits on `mcp-interface` journey, `U4`).

## Vocabulary

The Terminology this slice uses.

- **CLI User**, **Target URL**, **Format** (`youtube-transcript`), **Window**, **Fetch Request**, **Transcript** *(derived)*, **Windowed Excerpt** *(derived)*, **fetch transcript**.

## What it reads and writes

| Payload | Shape |
|---|---|
| `RealYtDlpOptions` | `{ readonly binary?: string; readonly timeoutMs?: number; readonly maxBytes?: number; readonly proxy?: string }` |
| `CliDeps` | `{ readonly ports?: FetchPorts; readonly ytDlp?: YtDlpPort; readonly env?: NodeJS.ProcessEnv; readonly stdout?: (text: string) => void; readonly stderr?: (text: string) => void }` |

## Verbs & Workflow

No new domain verbs; `src/transcript/` remains pure and isolated from `src/fetching/`.

| Adapter / Caller | Rule | Error |
|---|---|---|
| `createRealYtDlp(options?).isAvailable()` | Runs `execFile(binary, ['--version'], { timeout: 5000 })` once and caches the boolean result; catches `ENOENT` or any spawn error and returns `false` (never throws) (`D7`). | *(never fails; returns `boolean`)* |
| `createRealYtDlp(options?).downloadSubtitles(url, lang)` | Creates a temp dir (`mkdtemp`), executes `execFile(binary, buildYtDlpArgs(url, lang, path.join(tmpDir, 'sub'), proxy), { timeout: timeoutMs ?? 30000 })`, rejects `.srv1` files exceeding `maxBytes ?? MAX_RESPONSE_BYTES` (`I5`), extracts `matchedLang` from `/\.([^.]+)\.srv1$/` (defaulting to `lang`), and always removes `tmpDir` in `finally` (`D7`, `D9`, `D21`). | `yt-dlp timed out after <timeoutMs>ms`<br>`yt-dlp failed: <message>`<br>`yt-dlp did not produce subtitle files`<br>`yt-dlp subtitle file exceeded <maxBytes> byte limit` |
| `runCli(['transcript', ...])` | Links `executeFetchTranscript` to `FetchPagePort` (backed by `executeFetch` with `maxLength: 0`), `CheckHostPort` (backed by `dnsLookup` + `validateResolvedIps`), and `ytDlp` (`deps.ytDlp ?? createRealYtDlp({ maxBytes: maxResponseBytes })`), passing `DEFAULT_LIMIT` from `env.DEFAULT_LIMIT`. Writes Windowed Excerpt to `stdout` (exit `0`) or `<error.message>\n` to `stderr` (exit `1`) (`D1`, `D6`, `D12`, `D14`). | Exact `TranscriptError.message` on `stderr` with exit code `1` |

## Queries (`src/transcript/queries.ts`)

Unchanged from Slice 02 (`isAllowedYouTubeHost`, `decodeHtmlEntities`, `parseCaptionXml`, `buildYtDlpArgs`, `windowedTranscript`).

## Harness

| Command | Kind | What it does |
|---|---|---|
| `ytdlp timeout <url>` | world | Configures mocked `yt-dlp` to time out after `30000ms` for `<url>` (triggering direct fallback); prints `ytdlp: timeout <url>`. |

## Placeholders

*(None — all rules in Slice 03 are settled by D1, D6, D7, D8, D9, D12, D14, D15, D20, D21, D22, I1, I2, I3, I5.)*

## Tests

- **Real `yt-dlp` subprocess tests** (`src/integrations/ytdlp/client.test.ts`): tests `createRealYtDlp` with temporary stub scripts — verifying `isAvailable()` true/false + caching, exact argv (including `--write-sub`, `--write-auto-sub`, `--`), `.srv1` discovery + `matchedLang`, non-zero exit, missing `.srv1`, timeout killing a slow child process, `maxBytes` cap, and temp-dir cleanup in every case.
- **CLI tests** (`src/cli.test.ts`): tests `runCli(['transcript', ...])` for `yt-dlp` primary (`stdout` + exit `0`), direct fallback when `yt-dlp` is unavailable/failing, `--lang`, `--start-index`, `--max-length`, `--header`, and typed validation/SSRF errors on `stderr` with exit `1` (`FT-10`).
- **Scenario:** `scenarios/fetch-transcript/03-real-ytdlp-and-cli-wiring.txt` (proving `yt-dlp` timeout fallback, `yt-dlp` regional prefix + Window slicing, and `dns fail` / `dns empty` / mixed IPv4-mapped IPv6 blocking before `yt-dlp`).
