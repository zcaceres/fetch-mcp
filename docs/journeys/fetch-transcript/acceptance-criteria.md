# Fetch Transcript: Acceptance Criteria

An **Agent** or **CLI User** submits a **Fetch Request** (`format: youtube-transcript`) for a YouTube video
**Target URL** with an optional caption language code (`lang`, default `"en"`), optional custom headers, and optional
**Window**, and receives a **Windowed Excerpt** of the **Transcript** or a typed domain error. Built slice by slice,
starting in the harness and wiring into real `yt-dlp` and the CLI ([plan](plan.md)).

Rules that hold whichever journey is involved, and the decisions (D#), questions (U#) and invariants (I#) cited here,
are in [`REQUIREMENTS.md`](../../../REQUIREMENTS.md). These criteria say what **Agent** and **CLI User** can do and
see; they cite rules rather than restate them. Each slice's [spec](specs/) names the criteria it covers.

Each criterion is one or more Gherkin scenarios tagged with its id (`@FT-1`) and the decisions, questions and
invariants it cites. Scenarios that share an id make up one criterion.

## Steps

1. **Submit Fetch Request.** Actor supplies a YouTube Target URL, optional `lang`, optional custom headers, and optional Window.
2. **Validate YouTube Target URL & `lang`.** System enforces YouTube host allowlisting, SSRF rules, and safe language code validation before any subprocess or network call.
3. **Retrieve Caption XML.** System tries local `yt-dlp` first when available on `PATH`, falling back to direct YouTube watch-page and caption-track XML extraction without swallowing validation or SSRF errors.
4. **Parse & Format Transcript.** System parses `srv1`/`srv3` XML, decodes HTML entities, and formats the Transcript with its language header and timestamps.
5. **Slice Windowed Excerpt.** System slices the Transcript into a Windowed Excerpt and delivers it (or a typed error) to the actor.

## 1. Submit Fetch Request

```gherkin
@FT-1 @D4 @D14 @D18 @D19 @I3
Scenario: Malformed Target URL, invalid Window bounds, invalid lang, or CR/LF headers are refused before any I/O
  Given an Agent or CLI User submits a Fetch Request with a malformed URL, negative startIndex/maxLength, invalid lang code, or CR/LF header
  When they fetch transcript
  Then the request is refused with a typed validation error before invoking yt-dlp or making any network call (D14, D18, I3)
```

## 2. Validate YouTube Target URL & `lang`

```gherkin
@FT-2 @D8 @I1 @I2 @I3
Scenario: Non-YouTube hosts and disallowed schemes are blocked before connecting
  Given an Agent or CLI User submits a Fetch Request for "https://example.com/video" or "file:///tmp/video"
  When they fetch transcript
  Then the request is refused as a blocked Target URL without falling back (D8, I1, I3)

@FT-2 @D8 @I2 @I3
Scenario: Allowlisted YouTube hosts are accepted and validated against DNS SSRF rules
  Given an Agent or CLI User submits a Fetch Request for an allowlisted YouTube host (I3)
  When DNS resolves to a reserved IP or fails
  Then the request is refused as a blocked Target URL before connecting (D8, I2, I3)
```

## 3. Retrieve Caption XML

```gherkin
@FT-3 @D7 @D9 @D21 @I3
Scenario: Available yt-dlp subprocess is used first with manual and auto-generated subtitles enabled
  Given yt-dlp is available on PATH and produces an srv1 subtitle file for the requested video and lang
  When the actor runs fetch transcript
  Then yt-dlp is invoked with --write-sub, --write-auto-sub, --sub-format srv1, --skip-download, and the -- end-of-options sentinel within the 30s timeout (D7, D9, D21)
  And the actor receives the formatted Transcript without scraping the watch page

@FT-4 @D7 @D14 @I3
Scenario: Unavailable or failing yt-dlp falls back cleanly to direct extraction without swallowing validation errors
  Given yt-dlp is unavailable on PATH, exits with an error, or produces no subtitle file
  When the actor runs fetch transcript for a valid YouTube Target URL
  Then the system falls back to direct watch-page and caption-XML extraction (D7)
  And input validation or SSRF errors are never swallowed into fallback (I3)

@FT-5 @D7 @D8 @D9 @D14 @I1 @I2 @I5
Scenario: Direct extraction fetches watch page and caption track under full SSRF and byte-cap guards
  Given yt-dlp is unavailable and YouTube serves a watch page containing ytInitialPlayerResponse and a public caption track baseUrl
  When the actor runs fetch transcript
  Then both the watch page and caption track URL (with fmt=srv1 appended if missing) are fetched through full SSRF, DNS pinning, and MAX_RESPONSE_BYTES enforcement (D8, D9, I1, I2, I5)

@FT-5 @D14
Scenario: Missing ytInitialPlayerResponse or missing caption tracks fails explicitly
  Given the watch page omits ytInitialPlayerResponse or lists zero caption tracks
  When the actor runs fetch transcript via direct extraction
  Then the actor receives a typed error (D14)

@FT-6 @D14 @D20
Scenario: Caption track selection prefers exact case-insensitive match, then regional prefix, and fails listing available codes when absent
  Given a video has caption tracks "en-US" and "de"
  When the actor runs fetch transcript with lang "en"
  Then the "en-US" track is selected via regional prefix match (D20)
  When the actor runs fetch transcript with lang "fr"
  Then the actor receives a typed error listing available language codes "en-US, de" (D14, D20)
```

## 4. Parse & Format Transcript

```gherkin
@FT-7 @D4 @D21
Scenario: srv1 and srv3 XML captions are parsed with timestamps, inline tags stripped, and entities decoded
  Given caption XML in srv1 (<text start>) or srv3 (<p t>) format containing inline tags, blank lines, named entities, numeric entities, and double-encoded &amp;#39;
  When the Transcript is formatted
  Then the Transcript starts with "[Transcript language: <code> — <name>]\n\n" followed by "[m:ss] <text>" lines with tags stripped, blank captions skipped, and entities decoded (D21)

@FT-8 @D14 @D22
Scenario: Empty or unrecognized caption XML fails explicitly
  Given fetched caption XML produces zero non-empty caption lines
  When the Transcript is formatted
  Then the actor receives a typed parse error (D14, D22)
```

## 5. Slice Windowed Excerpt

```gherkin
@FT-9 @D4 @D9 @D14 @D15 @D19
Scenario: Transcript is sliced into a Windowed Excerpt with sliced text only
  Given a formatted Transcript
  When the actor runs fetch transcript with startIndex and maxLength (or maxLength 0 for unlimited, or startIndex beyond length)
  Then the actor receives the exact sliced text with no appended footer, or "" when startIndex is at or beyond length (D9, D14, D15, D19)

@FT-10 @D1 @D6 @D12 @D14
Scenario: CLI User fetches a YouTube transcript via mcp-fetch transcript
  Given a valid YouTube Target URL
  When the CLI User runs `mcp-fetch transcript <url> --lang en --start-index 0 --max-length 200`
  Then the Windowed Excerpt is written to stdout with exit code 0, or a typed error message is written to stderr with exit code 1 (D1, D6, D12, D14)
```
