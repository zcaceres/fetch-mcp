# Slice 02: yt-dlp Primary & Fallback

Part of the [Fetch Transcript plan](../../plan.md). Decisions referenced as D# / U# / I# are in
[`REQUIREMENTS.md`](../../../../../REQUIREMENTS.md). Builds on [slice 01](../01-direct-transcript-extraction/spec.md).

Covers [acceptance criteria](../../acceptance-criteria.md) FT-3 and FT-4.

## Goal

Wire `yt-dlp` as the primary caption retriever in `src/transcript/execute.ts` with automatic fallback to Slice 01's
direct watch-page extraction when `yt-dlp` is unavailable, exits with an error, produces no `.srv1` file, or returns
empty caption XML (`D7`). Add a pure `buildYtDlpArgs` query guaranteeing `--write-sub`, `--write-auto-sub`,
`--sub-format srv1`, `--skip-download`, and the `--` end-of-options sentinel (`D21`), enforce host DNS SSRF checks
before invoking `yt-dlp`, and prove that validation and SSRF errors are never swallowed into fallback (`I2`, `I3`).

**Done when:** `bun run lint`, `bun run typecheck`, `bun test`, and
`bun run harness run scenarios` (all `fetch-web-content` + `fetch-transcript` Slices 01–02) pass cleanly.

## Scope

**In:**
- `src/transcript/queries.ts`: add `buildYtDlpArgs(url, lang, outputTemplate, proxy?)` (`D21`).
- `src/transcript/ports.ts`: add `YtDlpResult`, `YtDlpPort` (`isAvailable`, `downloadSubtitles`), and `CheckHostPort` (`checkHost`) to `TranscriptPorts`.
- `src/transcript/execute.ts`: check `checkHost` before invoking `ytDlp`; if `ytDlp.isAvailable()` is true, try `ytDlp.downloadSubtitles` -> `buildTranscript` first, falling back to direct watch-page extraction on `yt-dlp` failure or empty XML without ever swallowing `invalid_request` or `blocked_url` errors (`D7`, `I2`, `I3`).
- `src/integrations/ytdlp/mock.ts`: in-memory `YtDlpMock` (default fixture `available = false` so Slice 01's direct-extraction scenario stays green) with `setAvailable`, `serve`, `empty`, `fail`, and `lastArgs` controls.
- `cli/world.ts`, `cli/commands/ytdlp.ts`, `cli/commands/index.ts`, `cli/commands/fetch-transcript.ts`: add `ytdlp` world command and wire `world.ytdlp` + DNS `checkHost` into `fetch-transcript`.

**Out:**
- Real `yt-dlp` subprocess client (`execFile`, temp dir lifecycle, `30s` timeout) and `mcp-fetch transcript` CLI rewiring (waits on Slice 03: `03-real-ytdlp-and-cli-wiring`).
- Proxy routing for `yt-dlp` and direct YouTube fetches (waits on `proxy-and-limits` journey).
- MCP `fetch_transcript` server tool wiring (waits on `mcp-interface` journey).

## Vocabulary

The Terminology this slice uses.

- **Target URL**, **Format** (`youtube-transcript`), **Window**, **Fetch Request**, **Caption Track**, **Transcript**, **Windowed Excerpt** *(derived)*, **fetch transcript**.

## What it reads and writes

| Payload | Shape |
|---|---|
| `YtDlpResult` | `{ readonly xml: string; readonly lang: string; readonly langName: string }` |
| `YtDlpPort` | `{ readonly isAvailable: () => Promise<boolean>; readonly downloadSubtitles: (url: TargetUrl, lang: LanguageCode) => Promise<Result<YtDlpResult, string>> }` |
| `CheckHostPort` | `(hostname: string) => Promise<Result<void, TranscriptError>>` |
| `TranscriptPorts` | `{ readonly fetchPage: FetchPagePort; readonly checkHost?: CheckHostPort; readonly ytDlp?: YtDlpPort }` |

## Verbs & Workflow (`src/transcript/execute.ts`)

| Function | Rule | Error |
|---|---|---|
| `executeFetchTranscript(input, ports, options?)` | Runs `prepareTranscriptRequest` first (`I3`), then `ports.checkHost(hostname)` if provided (`I2`, `I3`). Never invokes `ytDlp` or falls back if either fails. When `ports.ytDlp` is provided and `isAvailable()` is true, tries `downloadSubtitles(url, lang)` -> `buildTranscript(...)`; if `downloadSubtitles` or `buildTranscript` fails, falls back to direct watch-page extraction (D7, D21, D22). | Validation/SSRF errors from `prepareTranscriptRequest` / `checkHost`, or direct-extraction error if `yt-dlp` fails/falls back |

## Queries (`src/transcript/queries.ts`)

| Function | Definition |
|---|---|
| `buildYtDlpArgs(url: TargetUrl, lang: LanguageCode, outputTemplate: string, proxy?: string): readonly string[]` | Builds `['--write-sub', '--write-auto-sub', '--sub-lang', lang, '--sub-format', 'srv1', '--skip-download', '-o', outputTemplate, ...(proxy ? ['--proxy', proxy] : []), '--', url]` (D21). |
| `isAllowedYouTubeHost`, `decodeHtmlEntities`, `parseCaptionXml`, `windowedExcerpt` | Unchanged from Slice 01. |

## Harness

| Command | Kind | What it does |
|---|---|---|
| `ytdlp available <true\|false>` | world | Toggles whether mocked `yt-dlp` is available on `PATH`; prints `ytdlp: available <true\|false>`. |
| `ytdlp serve <url> <lang> <xml...>` | world | Registers mocked `.srv1` XML output for `(<url>, <lang>)`; prints `ytdlp: serve <lang> <url>`. |
| `ytdlp empty <url>` | world | Configures `yt-dlp` to produce no subtitle files for `<url>` (triggering fallback); prints `ytdlp: empty <url>`. |
| `ytdlp fail <url> <reason...>` | world | Configures `yt-dlp` to exit with `<reason>` for `<url>` (triggering fallback); prints `ytdlp: fail <url>`. |
| `ytdlp last-args` | world | Prints `(not invoked)` if `yt-dlp` was never called, or `args: <argv>` showing the exact flags built by `buildYtDlpArgs`. |

## Placeholders

*(None — all rules in Slice 02 are settled by D7, D8, D9, D14, D20, D21, D22, I2, I3.)*

## Tests

- **Domain tests** (`src/transcript/transcript.test.ts`): pure given/when/then tests for `buildYtDlpArgs` (verifying `--write-sub`, `--write-auto-sub`, `--sub-format srv1`, `--skip-download`, `--` sentinel before URL, optional `--proxy`) and `executeFetchTranscript` (yt-dlp primary skips `fetchPage`, yt-dlp unavailable/failing/empty-XML falls back to direct `fetchPage`, validation & `checkHost` SSRF failures never invoke `ytDlp` or `fetchPage`).
- **Scenario:** `scenarios/fetch-transcript/02-ytdlp-primary-and-fallback.txt` (plus Slice 01 scenario continues to pass).
