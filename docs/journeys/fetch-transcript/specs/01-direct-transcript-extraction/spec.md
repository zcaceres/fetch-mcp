# Slice 01: Direct Transcript Extraction

Part of the [Fetch Transcript plan](../../plan.md). Decisions referenced as D# / U# / I# are in
[`REQUIREMENTS.md`](../../../../../REQUIREMENTS.md). Tracer bullet — first slice of the journey.

Covers [acceptance criteria](../../acceptance-criteria.md) FT-1, FT-2, FT-5, FT-6, FT-7, FT-8, and FT-9.

## Goal

Create the bounded context `src/transcript/` (isolated from `src/fetching/` and linked only by callers through
`FetchPagePort`) and wire the `fetch-transcript` harness command. Proves the complete direct-extraction path:
validating YouTube Target URLs against the host allowlist (`I3`), validating `lang` and Window bounds and CR/LF
headers, fetching watch page HTML and caption track XML via `FetchPagePort` (backed by `executeFetch` so full SSRF,
DNS pinning, and `MAX_RESPONSE_BYTES` rules hold), selecting caption tracks by exact case-insensitive match then
regional prefix (or failing with available language codes per `D20`), parsing `srv1`/`srv3` XML with named, numeric,
and double-encoded HTML entity decoding (`D21`), rejecting empty caption XML (`D22`), and slicing the Transcript into
a Windowed Excerpt (`D15`).

**Done when:** `bun run lint`, `bun run typecheck`, `bun test`, and
`bun run harness run scenarios` (all `fetch-web-content` + `fetch-transcript` Slice 01 scenarios) pass cleanly.

## Scope

**In:**
- Bounded context `src/transcript/`:
  - `nouns.ts`: `TargetUrl`, `LanguageCode`, `Window`, `Headers`, `CaptionTrack`, `FetchRequest`, `RawTranscriptInput`, `Transcript`, `WindowedExcerpt`, `TranscriptError`.
  - `queries.ts`: `isAllowedYouTubeHost`, `decodeHtmlEntities`, `parseCaptionXml`, `windowedExcerpt`.
  - `verbs.ts`: `prepareFetchTranscript`, `extractCaptionTracks`, `selectCaptionTrack`, `buildTranscript`.
  - `ports.ts`: `FetchPagePort`, `TranscriptPorts`.
  - `execute.ts`: `executeFetchTranscript(input, ports, options?)` (direct extraction path; `yt-dlp` port added in Slice 02).
- Harness command: `cli/commands/fetch-transcript.ts` (domain command linking `executeFetchTranscript` to `executeFetch` over `world.origin` and `world.dns`).
- `biome.json`: include `src/transcript/**`.

**Out:**
- `yt-dlp` primary invocation, mock, world commands, and fallback orchestration (waits on Slice 02: `02-ytdlp-primary-and-fallback`).
- Real `yt-dlp` subprocess client and `mcp-fetch transcript` CLI rewiring (waits on Slice 03: `03-real-ytdlp-and-cli-wiring`).
- Proxy routing (waits on `proxy-and-limits` journey).
- MCP `fetch_transcript` server tool wiring (waits on `mcp-interface` journey).

## Vocabulary

The Terminology this slice uses.

- **Target URL**, **Format** (`youtube-transcript`), **Window**, **Fetch Request**, **Caption Track**, **Transcript**, **Windowed Excerpt** *(derived)*, **fetch transcript**.

## What it reads and writes

| Payload | Shape |
|---|---|
| `TargetUrl` | `Brand<string, 'TargetUrl'>` |
| `LanguageCode` | `Brand<string, 'LanguageCode'>` (matches `/^[a-zA-Z0-9][a-zA-Z0-9-]*$/`, default `'en'`) |
| `CaptionTrack` | `{ readonly languageCode: string; readonly name: string; readonly baseUrl: string }` |
| `FetchRequest` | `{ readonly url: TargetUrl; readonly lang: LanguageCode; readonly headers: Headers; readonly window: Window }` |
| `Transcript` | `Brand<string, 'Transcript'>` |
| `WindowedExcerpt` | `Brand<string, 'WindowedExcerpt'>` |
| `TranscriptError` | Discriminated union `{ readonly kind: 'invalid_request' \| 'blocked_url' \| 'fetch_error' \| 'not_found' \| 'language_not_found' \| 'parse_error'; readonly message: string }` |

## Verbs (`src/transcript/verbs.ts`)

| Function | Rule | Error |
|---|---|---|
| `prepareFetchTranscript(input: RawTranscriptInput, defaultLimit?: number): Result<FetchRequest, TranscriptError>` | Validates URL syntax, requires `http:`/`https:`, requires hostname in `ALLOWED_YOUTUBE_HOSTS` (`youtube.com`, `www.youtube.com`, `m.youtube.com`, `music.youtube.com`, `youtu.be`), validates `lang` (default `'en'`, matches `/^[a-zA-Z0-9][a-zA-Z0-9-]*$/`), validates `startIndex` (`0`) and `maxLength` (`defaultLimit ?? 5000`), and rejects CR/LF, non-token header names, and invalid header value characters (escaping rejected header names with `JSON.stringify`) (D4, D8, D9, D14, D18, D19, D28, I1, I3). | `Invalid Target URL: "<url>"`<br>`Blocked Target URL: disallowed scheme "<protocol>" (only http: and https: are allowed)`<br>`Blocked Target URL: host "<host>" is not an allowlisted YouTube domain`<br>`Invalid language code "<lang>": only letters, digits, and hyphens are allowed`<br>`Invalid startIndex: must be a non-negative integer`<br>`Invalid maxLength: must be a non-negative integer`<br>`Invalid header <JSON.stringify(key)>: CR/LF control characters are not allowed`<br>`Invalid header <JSON.stringify(key)>: header name must be a valid HTTP token`<br>`Invalid header <JSON.stringify(key)>: invalid character in header value` |
| `extractCaptionTracks(html: string): Result<readonly CaptionTrack[], TranscriptError>` | Scans `ytInitialPlayerResponse = {` matches resiliently in watch page HTML (skipping non-JSON matches and individual malformed `captionTracks` entries per D21) and reads `captions.playerCaptionsTracklistRenderer.captionTracks`; requires at least one valid track with `languageCode` and `baseUrl` (D14, D21). | `Could not find ytInitialPlayerResponse in page HTML`<br>`No caption tracks found for this video` |
| `selectCaptionTrack(tracks: readonly CaptionTrack[], lang: LanguageCode): Result<CaptionTrack, TranscriptError>` | Case-insensitive exact match on `languageCode` first, then case-insensitive regional prefix match (`track.languageCode.toLowerCase().startsWith(lang.toLowerCase() + '-')`); fails listing unique available language codes in order when absent (D14, D20). | `No captions available in language "<lang>" (available: <codes>)` |
| `buildTranscript(xml: string, lang: string, langName: string): Result<Transcript, TranscriptError>` | Parses `srv1`/`srv3` XML via `parseCaptionXml`; requires at least one non-empty caption line (D22); formats `[Transcript language: <lang> — <langName>]\n\n<lines joined by \n>` (D4, D21, D22). | `No caption lines found in transcript XML` |

## Queries (`src/transcript/queries.ts`)

The derived nouns and pure checks this slice computes. Never stored, never refused.

| Function | Definition |
|---|---|
| `isAllowedYouTubeHost(hostname: string): boolean` | Normalizes hostname (lowercased, trailing dots stripped) and checks membership in `ALLOWED_YOUTUBE_HOSTS` (`youtube.com`, `www.youtube.com`, `m.youtube.com`, `music.youtube.com`, `youtu.be`) (I3). |
| `decodeHtmlEntities(text: string): string` | Decodes `&amp;` (enabling double-encoded YouTube entities like `&amp;#39;`), named entities (`&lt;`, `&gt;`, `&quot;`, `&apos;`, `&nbsp;`), decimal numeric entities (`&#39;`, `&#160;`), and hex numeric entities (`&#x27;`) (D21). |
| `parseCaptionXml(xml: string): readonly string[]` | Parses `srv1` (`<text start="...">`) or `srv3` (`<p t="...">`) XML, strips inline HTML tags, decodes entities via `decodeHtmlEntities`, skips empty/whitespace-only entries, and formats each line as `[m:ss] <content>` (D21). |
| `stripCrossOriginHeaders(watchUrl: TargetUrl, captionUrl: string, headers: Headers): Headers` | Strips `Authorization`, `Cookie`, and `Proxy-Authorization` case-insensitively whenever `captionUrl` has a different origin from `watchUrl` (or fails URL parsing) (D7, I4). |
| `windowedExcerpt(transcript: Transcript, window: Window): WindowedExcerpt` | Returns `""` if `startIndex >= transcript.length`; full remainder if `maxLength === 0`; otherwise `transcript.slice(startIndex, startIndex + maxLength)` with no appended footer (D9, D14, D15, D19). |

## Harness

| Command | Kind | What it does |
|---|---|---|
| `fetch-transcript <url> [--lang <code>] [--start-index <N>] [--max-length <N>] [--header <Key:Value>]...` | domain | Calls `executeFetchTranscript` with a `FetchPagePort` backed by `executeFetch` (`format: 'html'`, `maxLength: 0`) over `world.origin` and `world.dns`. Prints each line prefixed with `\| ` (or `(empty)` if `""`), or `error: <message>`. |

## Placeholders

*(None — all rules in Slice 01 are settled by D4, D8, D9, D14, D15, D18, D19, D20, D21, D22, I1, I2, I3, I5.)*

## Tests

- **Domain tests** (`src/transcript/transcript.test.ts`): pure given/when/then tests for `prepareFetchTranscript` (allowlisted hosts, non-YouTube host blocked, disallowed scheme, invalid `lang` with shell/flag metacharacters, invalid Window bounds, CR/LF header rejection), `extractCaptionTracks` (valid player response, missing `ytInitialPlayerResponse`, empty/missing tracks), `selectCaptionTrack` (exact match, case-insensitive match, regional prefix `en` → `en-US`, missing language lists available codes), `decodeHtmlEntities` (named, decimal, hex, double-encoded `&amp;#39;`), `parseCaptionXml` (`srv1`, `srv3`, inline tags stripped, empty skipped), `buildTranscript` (header + timestamps, empty XML fails), and `windowedExcerpt`.
- **Scenario:** `scenarios/fetch-transcript/01-direct-transcript-extraction.txt`.
