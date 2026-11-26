# Fetch Transcript: Plan

How the journey is built, slice by slice. What it must do is in its [acceptance criteria](acceptance-criteria.md);
decisions (D#) and questions (U#) are in [`REQUIREMENTS.md`](../../../REQUIREMENTS.md).

## Sources

The designs, flows, tickets and documents behind this journey, from its design session.

- [`REQUIREMENTS.md`](../../../REQUIREMENTS.md): system terminology, D3, D4, D7–D9, D12, D14, D15, D18–D22, I1–I3, I5.
- [src/YouTubeTranscript.ts](../../../src/YouTubeTranscript.ts), [src/Fetcher.ts](../../../src/Fetcher.ts), [src/YouTubeTranscript.fixture.test.ts](../../../src/YouTubeTranscript.fixture.test.ts): v1.2.0 reference implementation and real caption XML fixtures.
- [PR #48](../../github/pull-requests/048-fix-fetcher-prevent-argv-injection-into-yt-dlp-via-videourl.md): `yt-dlp` `--` end-of-options sentinel defense-in-depth context.

## Shape

An **Agent** or **CLI User** submits a **Fetch Request** for a YouTube video **Target URL** with an optional caption
language code (`lang`, default `"en"`), optional custom headers, and optional **Window** bounds. The `src/transcript/`
context validates the URL scheme, YouTube host allowlist (`I3`), safe `lang` pattern, Window bounds, and header
hygiene before any I/O. It invokes `yt-dlp` first when available (`--write-sub`, `--write-auto-sub`, `--sub-format srv1`,
`--skip-download`, `--`, `30s` timeout); if `yt-dlp` is unavailable or fails, it falls back to direct extraction by
fetching the watch page HTML and selected caption track XML through a `FetchPagePort` (wired by callers to
`src/fetching/execute.ts` so full SSRF, DNS pinning, and `MAX_RESPONSE_BYTES` rules hold without contexts importing
each other). Caption tracks match `lang` case-insensitively by exact code then regional prefix, failing explicitly
with available codes if absent (`D20`). `srv1`/`srv3` XML is parsed with entity decoding (`D21`), failing on empty
XML (`D22`), formatted into a **Transcript**, and sliced into a **Windowed Excerpt** (`D15`).

## Contexts, verbs and queries

Where this journey lives in the code. Contexts never import each other; callers (harness, CLI, MCP server) link
`src/transcript/` to `src/fetching/` via `FetchPagePort`.

| Context | Nouns | Verbs | Queries | Harness commands |
|---|---|---|---|---|
| `src/transcript/` | `YouTubeUrl`, `LanguageCode`, `Window`, `CaptionTrack`, `TranscriptRequest`, `Transcript`, `WindowedExcerpt`, `TranscriptError` | `prepareTranscriptRequest`, `extractCaptionTracks`, `selectCaptionTrack`, `buildTranscript` | `isAllowedYouTubeHost`, `decodeHtmlEntities`, `parseCaptionXml`, `windowedTranscript` | `fetch-transcript <url> [--lang <code>] [--start-index N] [--max-length N] [--header K:V]` |

## External systems

Every system outside ours is mocked in `src/integrations/<system>/`; world commands make it do what the journey needs.

| System | What we need from it | World commands |
|---|---|---|
| ytdlp (`src/integrations/ytdlp/`) | Optional local `yt-dlp` subprocess (`isAvailable`, `downloadSubtitles`) | `ytdlp available <true\|false>`, `ytdlp serve <url> <lang> <xml...>`, `ytdlp empty <url>`, `ytdlp fail <url> <reason...>`, `ytdlp last-args` |
| origin (`src/integrations/origin/`) | YouTube watch page HTML and caption track XML (via `FetchPagePort` → `executeFetch`) | Reuses `origin serve`, `origin header`, `origin fail`, etc. from `fetch-web-content` |
| dns (`src/integrations/dns/`) | Hostname resolution for YouTube hosts in direct extraction | Reuses `dns set`, `dns empty`, `dns fail` from `fetch-web-content` |

## Slices

Each slice is one capability, wired through every part of the system (harness commands, verbs, ports, mocks) with
a scenario that runs it.

### Done

1. **01 — Direct Transcript Extraction (Tracer Bullet).** Adds `src/transcript/` core (`prepareTranscriptRequest`, `extractCaptionTracks`, `selectCaptionTrack`, `buildTranscript`, `parseCaptionXml`, `decodeHtmlEntities`, `windowedTranscript`, `executeFetchTranscript`) and `fetch-transcript` harness command linked to `executeFetch` over existing `origin`/`dns` mocks. Covers FT-1, FT-2, FT-5, FT-6, FT-7, FT-8, FT-9.
   ([spec](specs/01-direct-transcript-extraction/spec.md), `scenarios/fetch-transcript/01-direct-transcript-extraction.txt`)

### Next

In the order we expect to build them; reorder freely. Each says where it came from: criteria, a finding (a
`/dd-verify` note) or a decision.

1. **02 — yt-dlp Primary & Fallback.** Adds `src/integrations/ytdlp/mock.ts`, `ytdlp` world commands (`available`, `serve`, `empty`, `fail`, `last-args`), and `yt-dlp`-primary with direct fallback in `executeFetchTranscript`, proving validation/SSRF errors are never swallowed (`I3`) and `--write-sub`/`--write-auto-sub`/`--` flags are enforced (`D7`, `D21`). From FT-3, FT-4.
2. **03 — Real yt-dlp Client & CLI Wiring.** Implements async `src/integrations/ytdlp/client.ts` (`execFile`, `--` sentinel, temp dir cleanup, `30s` timeout) and rewires `mcp-fetch transcript` in `src/cli.ts` off legacy `Fetcher.youtubeTranscript` onto `executeFetchTranscript`. From FT-10.

## Deferred

- Auto-translated captions via YouTube `tlang` parameter: out of scope for now.
- Alternative transcript output formats (plain text without timestamps, SRT/VTT): Transcript always uses `[Transcript language: ...]` + `[m:ss] ...`.
- Non-YouTube video platforms (Vimeo, Twitch, etc.): allowlisted YouTube hosts only (`I3`).
- Proxy routing for `yt-dlp` and direct YouTube fetches: owned by the `proxy-and-limits` journey.
- MCP `fetch_transcript` tool schema and server dispatch: owned by the `mcp-interface` journey.
