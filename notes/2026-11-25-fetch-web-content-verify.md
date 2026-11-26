# Verify: `fetch-web-content` (2026-11-25)

**Status:** 4 of 5 slices (`01`–`04`) are done and pass all automated checks (`286/286` tests, `4/4` scenarios); adversarial exploration uncovered 1 minor bug (unescaped newline in `Invalid header` error message when the header *name* contains CR/LF), 2 minor `plan.md` drift items, 0 undecided questions, and 1 remaining gap (`FW-4` socket IP pinning, queued in Slice 05).

## Checks

| Check | Result |
|---|---|
| `bun run lint` (`biome ci .`) | Pass (20 files, 0 errors, 0 warnings) |
| `bun run typecheck` (`tsc --noEmit`) | Pass (0 errors) |
| `bun run build` | Pass (`dist/index.js`, `dist/cli.js`) |
| `bun test` | Pass (286 pass, 0 fail, 535 assertions across 10 files) |
| `bun run harness run scenarios/fetch-web-content` | Pass (4/4 scenarios: `01`–`04`) |
| Adversarial harness exploration (piped `bun run harness`) | Found 1 bug (`X-Bad\nName:val` injects a raw newline into the error string); all other probes passed (exact `10485760` byte boundaries raw/gzip/`Content-Length`, `x-gzip` + `json`, corrupted `deflate`/`br`, full `User-Agent`+`Accept-Encoding` override, LF-only and CR-only values, cross-origin redirect with duplicate `Authorization`/`authorization`) |

## Criteria

| ID | Status | Evidence |
|---|---|---|
| `FW-1` | **Holds** | `scenarios/fetch-web-content/01-basic-html-fetch.txt` L38–50; `src/fetching/fetching.test.ts` (`prepareFetch`) |
| `FW-2` | **Holds** *(minor bug on header-name error formatting)* | `scenarios/fetch-web-content/04-limits-compression-and-timeouts.txt` L4–22; `src/fetching/fetching.test.ts` (`prepareFetch` defaults, deduplication, CR/LF); see Bug #1 |
| `FW-3` | **Holds** | `scenarios/fetch-web-content/01-basic-html-fetch.txt` L52–63; `scenarios/fetch-web-content/02-ssrf-and-redirects.txt` L4–25; `src/fetching/fetching.test.ts` (`isReservedIp`) |
| `FW-4` | **Not covered** *(partially holds)* | DNS validation & rebinding/empty/error fail-closed hold in `scenarios/fetch-web-content/02-ssrf-and-redirects.txt` L27–50 and `src/fetching/fetching.test.ts` (`validateResolvedIps`); real socket IP pinning waits on Slice 05 |
| `FW-5` | **Holds** | `scenarios/fetch-web-content/01-basic-html-fetch.txt` L4–36; `src/fetching/fetching.test.ts` (`evaluateResponse`) |
| `FW-6` | **Holds** | `scenarios/fetch-web-content/02-ssrf-and-redirects.txt` L52–126; `src/fetching/fetching.test.ts` (`validateRedirectHop`, `stripCrossOriginHeaders`) |
| `FW-7` | **Holds** | `scenarios/fetch-web-content/04-limits-compression-and-timeouts.txt` L24–78; `src/fetching/fetching.test.ts` (`decodeResponseBody`); adversarial exact-boundary probes (`10485760` bytes raw/gzip/`Content-Length`) |
| `FW-8` | **Holds** | `scenarios/fetch-web-content/04-limits-compression-and-timeouts.txt` L80–89 (`origin timeout` + `origin attempts` = 1) |
| `FW-9` | **Holds** | `scenarios/fetch-web-content/03-formats-and-content-guards.txt` L4–41; `src/fetching/fetching.test.ts` (`isBinaryContentType`, `evaluateResponse`) |
| `FW-10` | **Holds** | `scenarios/fetch-web-content/01-basic-html-fetch.txt` L4–9; `src/fetching/fetching.test.ts` (`evaluateResponse`) |
| `FW-11` | **Holds** | `scenarios/fetch-web-content/03-formats-and-content-guards.txt` L43–56; `src/fetching/fetching.test.ts` (`evaluateResponse` json) |
| `FW-12` | **Holds** | `scenarios/fetch-web-content/03-formats-and-content-guards.txt` L58–69; `src/fetching/fetching.test.ts` (`evaluateResponse` text & markdown) |
| `FW-13` | **Holds** | `scenarios/fetch-web-content/03-formats-and-content-guards.txt` L71–86; `src/fetching/fetching.test.ts` (`evaluateResponse` readable) |
| `FW-14` | **Holds** | `scenarios/fetch-web-content/01-basic-html-fetch.txt` L11–22; `src/fetching/fetching.test.ts` (`windowedExcerpt`) |
| `FW-15` | **Not built** | Queued in Slice 05 (`05-real-transport-and-cli-wiring`) |

## Findings

### Bugs

1. **Unescaped CR/LF in `Invalid header` error message (`src/fetching/verbs.ts:43`):**
   - When a header *name* contains `\r` or `\n`, `prepareFetch` returns `` `Invalid header "${key}": CR/LF control characters are not allowed` `` without escaping control characters.
   - **Evidence:** Running `fetch html https://example.com/override --header X-Bad\nName:val` in `bun run harness` printed a two-line error:
     ```text
     error: Invalid header "X-Bad
     Name": CR/LF control characters are not allowed
     ```
   - **Fix:** Escape control characters in `key` (e.g., `JSON.stringify(key)` -> `Invalid header "X-Bad\nName": ...` with literal `\n` escape) so rejected header names cannot break single-line error/log/scenario output.

### Drift

1. **`plan.md` Contexts table (`docs/journeys/fetch-web-content/plan.md:31`):**
   - Missing `WireResponse` in `Nouns` and `decodeResponseBody` in `Verbs`.
2. **`plan.md` External systems table (`docs/journeys/fetch-web-content/plan.md:39-41`):**
   - `origin` world commands omit `origin compress`, `origin repeat`, `origin corrupt`, `origin attempts`; `clock` row lists `clock advance <duration>` while timeout simulation lives on `origin timeout <url>`.

### Needs a decision

*(None.)*

### Gaps

1. **`FW-4` socket IP pinning (`cli/commands/fetch.ts:87`):**
   - Queued in Slice 05 (`05-real-transport-and-cli-wiring`). *(Previous Gap #2 — duplicate case-insensitive custom headers — is now closed by Slice 04.)*

## By-hand checklist (for the user)

- [ ] *(After Slice 05)* Run `bun run build && node dist/cli.js readable https://example.com --max-length 500` and verify readable Markdown output (`stdout`, exit `0`). [`FW-13`, `FW-15`]
- [ ] *(After Slice 05)* Run `node dist/cli.js html http://127.0.0.1/` and verify blocked Target URL message on `stderr` with exit `1`. [`FW-3`, `FW-15`]

## Proposed `/dd-decide` items

*(None.)*
