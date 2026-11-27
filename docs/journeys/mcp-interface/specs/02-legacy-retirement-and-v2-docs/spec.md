# Slice 02: Legacy Retirement, Lint Expansion & v2.0.0 Docs

Part of the [MCP Interface plan](../../plan.md). Decisions referenced as D# / U# / I# are in
[`REQUIREMENTS.md`](../../../../../REQUIREMENTS.md). Builds on [slice 01](../01-mcp-server-core-wiring/spec.md).

Covers [acceptance criteria](../../acceptance-criteria.md) MI-7 (retiring legacy v1.2.0 modules, expanding Biome to
all of `src/**`, updating `README.md`, and bumping `package.json` to `2.0.0`).

## Goal

Preserve the real YouTube caption fixtures from `src/YouTubeTranscript.fixture.test.ts` by porting them onto
`src/transcript/` (`src/transcript/fixtures.test.ts`), remove all retired v1.2.0 legacy modules and legacy tests
(`Fetcher`, `httpClient`, `ssrf`, `YouTubeTranscript`, `types`), expand `biome.json` to lint all of `src/**`, update
`README.md` for the breaking v2.0.0 MCP tool names, CLI subcommands, proxy/limit rules, and Node.js `>=20` floor
(`D10`, `D12`, `D13`), and bump `package.json` to `2.0.0`.

**Done when:** `bun run lint` (covering all of `src/**`), `bun run typecheck`, `bun run build`, `bun test` (including
ported YouTube fixture tests), and `bun run harness run scenarios` (all 12 scenarios across all 4 journeys) pass
cleanly, and `node dist/cli.js --version` prints `2.0.0`.

## Scope

**In:**
- `src/transcript/fixtures.test.ts`: port real `jNQXAC9IVRw` ("Me at the zoo") `srv1` / `srv3` / `ytInitialPlayerResponse` fixtures onto `parseCaptionXml`, `extractCaptionTracks`, and `executeFetchTranscript` (asserting `D20` missing-language error and `D21` double-encoded `&amp;#39;` → `'`).
- Delete retired legacy files:
  - `src/Fetcher.ts`, `src/Fetcher.test.ts`, `src/Fetcher.fixture.test.ts`
  - `src/httpClient.ts`, `src/httpClient.test.ts`
  - `src/ssrf.ts`, `src/ssrf.test.ts`
  - `src/YouTubeTranscript.ts`, `src/YouTubeTranscript.test.ts`, `src/YouTubeTranscript.fixture.test.ts`
  - `src/types.ts`
- `biome.json`: simplify `files.includes` to `["src/**", "cli/**", "biome.json"]`.
- `README.md`: update MCP tool names (`fetch_text`, `fetch_transcript`), CLI subcommands (`text`, `transcript`, `--header`), HTTP/HTTPS/SOCKS4/4a/5/5h proxy & fail-fast Operator limit docs, MCP `2025-11-25` conformance, Node.js `>=20` / Bun support, and v2.0.0 breaking changes note.
- `package.json`: bump `version` to `2.0.0` (`D10`).

**Out:**
- `docs/github/` (untracked historical issue/PR export — remains untouched and unstaged).
- MCP `2026-07-28` `server/discover` (deferred per `D13`, `D27`).

## Vocabulary

The Terminology this slice uses.

- **Agent**, **CLI User**, **Operator**, **Target URL**, **Format**, **Window**, **Proxy Policy**, **Transcript** *(derived)*, **Windowed Excerpt** *(derived)*, **fetch**, **fetch transcript**.

## Placeholders

*(None — all decisions D1–D29 and invariants I1–I6 are settled; 0 open U#s remain.)*

## Tests

- **Ported fixture tests** (`src/transcript/fixtures.test.ts`): real YouTube `srv1`/`srv3` caption parsing, double-encoded `&amp;#39;` decoding (`D21`), realistic `ytInitialPlayerResponse` extraction, and end-to-end `executeFetchTranscript` for `en`, `de`, and missing `fr` (`D20`).
- **Full repository checks:** `bun run lint` (`src/**` + `cli/**`), `bun run typecheck`, `bun run build`, `bun test`, `bun run harness run scenarios`, and `node dist/cli.js --version` (`2.0.0`).
