# Verify: `fetch-web-content` (2026-11-25)

**Status:** 2 of 5 slices (`01-basic-html-fetch`, `02-ssrf-and-redirects`) are done and pass all automated checks and adversarial harness probes; 0 bugs found, 3 minor drift items, 2 coverage gaps (tracked into Slices 04–05), and 1 terminology decision proposed.

## Checks

| Check | Result |
|---|---|
| `bun run lint` (`biome ci .`) | Pass (20 files, 0 errors) |
| `bun run typecheck` (`tsc --noEmit`) | Pass (0 errors) |
| `bun run build` | Pass (`dist/index.js`, `dist/cli.js`) |
| `bun test` | Pass (271 pass, 0 fail, 486 assertions across 10 files) |
| `bun run harness run scenarios/fetch-web-content` | Pass (2/2 scenarios: `01-basic-html-fetch.txt`, `02-ssrf-and-redirects.txt`) |
| Adversarial harness exploration (piped `bun run harness`) | Pass (obfuscated decimal/hex/octal IPv4 `127.0.0.1`, `sub.localhost.`, `LOCALHOST`, `example.com.`, public IPv4 & IPv4-mapped public IPv6 literals, HTTP `204` empty body, invalid redirect `Location`, port-change cross-origin header stripping with mixed-case headers, colons in header values, exact 10-hop vs 11-hop redirect boundary, `reset`) |

## Criteria

| ID | Status | Evidence |
|---|---|---|
| `FW-1` | **Holds** | `scenarios/fetch-web-content/01-basic-html-fetch.txt` L38–50; `src/fetching/fetching.test.ts` (`prepareFetch` malformed URL, unsupported format, negative/non-integer bounds) |
| `FW-2` | **Not built** | Queued in Slice 04 (`04-limits-compression-and-timeouts`) |
| `FW-3` | **Holds** | `scenarios/fetch-web-content/01-basic-html-fetch.txt` L52–63; `scenarios/fetch-web-content/02-ssrf-and-redirects.txt` L4–25; `src/fetching/fetching.test.ts` (`isReservedIp` all IPv4/IPv6 ranges + fail-closed); adversarial harness run (decimal/hex/octal IPv4, `sub.localhost.`, `LOCALHOST`) |
| `FW-4` | **Not covered** *(partially holds)* | DNS validation & rebinding/empty/error fail-closed hold in `scenarios/fetch-web-content/02-ssrf-and-redirects.txt` L27–50 and `src/fetching/fetching.test.ts` (`validateResolvedIps`); actual socket pinning of `ResolvedIp[]` is not wired yet (waits on Slice 05) |
| `FW-5` | **Holds** | `scenarios/fetch-web-content/01-basic-html-fetch.txt` L4–36; `src/fetching/fetching.test.ts` (`evaluateResponse`) |
| `FW-6` | **Holds** | `scenarios/fetch-web-content/02-ssrf-and-redirects.txt` L52–120; `src/fetching/fetching.test.ts` (`validateRedirectHop`, `stripCrossOriginHeaders`); adversarial harness run (exact 10 vs 11 hops, port-change cross-origin, invalid `Location`) |
| `FW-7` | **Not built** | Queued in Slice 04 (`04-limits-compression-and-timeouts`) |
| `FW-8` | **Not built** | Queued in Slice 04 (`04-limits-compression-and-timeouts`) |
| `FW-9` | **Not built** | Queued in Slice 03 (`03-formats-and-content-guards`) |
| `FW-10` | **Holds** | `scenarios/fetch-web-content/01-basic-html-fetch.txt` L4–9; `src/fetching/fetching.test.ts` (`evaluateResponse` unmodified HTML) |
| `FW-11` | **Not built** | Queued in Slice 03 (`03-formats-and-content-guards`) |
| `FW-12` | **Not built** | Queued in Slice 03 (`03-formats-and-content-guards`) |
| `FW-13` | **Not built** | Queued in Slice 03 (`03-formats-and-content-guards`) |
| `FW-14` | **Holds** | `scenarios/fetch-web-content/01-basic-html-fetch.txt` L11–22; `src/fetching/fetching.test.ts` (`windowedExcerpt`) |
| `FW-15` | **Not built** | Queued in Slice 05 (`05-real-transport-and-cli-wiring`) |

## Findings

### Bugs

*(None.)*

### Drift

1. **Helper exported from `verbs.ts` and undocumented helper in `queries.ts`:**
   - `src/fetching/verbs.ts:22` exports `normalizeHostname(hostname: string): string`, which is a pure string helper rather than a verb returning `Result` and does not appear in `specs/02-ssrf-and-redirects/spec.md` → Verbs.
   - `src/fetching/queries.ts:138` exports `isIpLiteral(host: string): boolean`, which is not listed in `specs/02-ssrf-and-redirects/spec.md` → Queries or `plan.md` → Contexts.
   - **Suggested fix:** move `normalizeHostname` to `queries.ts` (or a non-verb internal helper) and document both helpers if kept as public queries, or keep `verbs.ts` strictly to exported verbs.
2. **Stale comment in `runbook.md`:**
   - `docs/journeys/fetch-web-content/runbook.md:11` still reads `bun run harness # interactive; type help (wired in slice 01)` even though Slice 01 is now built and verified.
3. **Minor naming split between Terminology and `nouns.ts`:**
   - `REQUIREMENTS.md` Terminology defines **Format** (and uses "Window bounds" in prose without a dedicated **Window** entry), whereas `src/fetching/nouns.ts:9,14` defines `WebFormat` and `Window`.

### Needs a decision

1. **Canonicalize `Window` in Terminology (and clarify `WebFormat` vs `Format`):**
   - `REQUIREMENTS.md` already refers to "optional Window bounds (`startIndex`, `maxLength`)" in **Fetch Request**, and `src/fetching/nouns.ts` models `Window` as a first-class noun alongside `WebFormat` (the 5 non-YouTube variants of `Format`). Deciding whether **Window** becomes a formal Terminology noun keeps docs and `nouns.ts` in strict 1:1 alignment.

### Gaps

1. **`FW-4` socket IP pinning not exercised in harness (`cli/commands/fetch.ts:87`):**
   - `validateResolvedIps` returns `Result<readonly ResolvedIp[], FetchError>`, and `cli/commands/fetch.ts` validates it but does not pass the resolved IPs into `world.origin.get` (mocked origin matches by URL only). Real socket-level IP pinning is queued in Slice 05 (`05-real-transport-and-cli-wiring`).
2. **Duplicate case-insensitive custom request header keys (`cli/commands/fetch.ts:68`):**
   - Passing `--header Authorization:first --header authorization:second` stores both keys on the object rather than deduplicating case-insensitively. Queued into Slice 04 (`04-limits-compression-and-timeouts`) alongside `D18` header hygiene (`User-Agent`/`Accept-Encoding` deduplication and CR/LF rejection).

## By-hand checklist (for the user)

- [ ] *(After Slice 05)* Run `bun run build && node dist/cli.js readable https://example.com --max-length 500` and verify readable Markdown output (`stdout`, exit `0`). [`FW-13`, `FW-15`]
- [ ] *(After Slice 05)* Run `node dist/cli.js html http://127.0.0.1/` and verify blocked Target URL message on `stderr` with exit `1`. [`FW-3`, `FW-15`]

## Proposed `/dd-decide` items

Ready to run if you want to formalize the Terminology addition:

```text
/dd-decide Add Window to Terminology as a Noun: the character slice bounds (`startIndex`, `maxLength`) used to compute a Windowed Excerpt from Rendered Output or Transcript; clarify WebFormat as the non-transcript subset of Format (`html`, `markdown`, `readable`, `text`, `json`).
```
