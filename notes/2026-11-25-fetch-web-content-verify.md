# Verify: `fetch-web-content` (2026-11-25)

**Status:** 3 of 5 slices (`01-basic-html-fetch`, `02-ssrf-and-redirects`, `03-formats-and-content-guards`) are done and pass all automated checks and adversarial harness probes; 0 bugs found, 1 minor drift item, 1 edge-case decision proposed (`image/svg+xml`), and 2 coverage gaps already queued into Slices 04–05.

## Checks

| Check | Result |
|---|---|
| `bun run lint` (`biome ci .`) | Pass (20 files, 0 errors, 0 warnings) |
| `bun run typecheck` (`tsc --noEmit`) | Pass (0 errors) |
| `bun run build` | Pass (`dist/index.js`, `dist/cli.js`) |
| `bun test` | Pass (279 pass, 0 fail, 516 assertions across 10 files) |
| `bun run harness run scenarios/fetch-web-content` | Pass (3/3 scenarios: `01-basic-html-fetch.txt`, `02-ssrf-and-redirects.txt`, `03-formats-and-content-guards.txt`) |
| Adversarial harness exploration (piped `bun run harness`) | Pass (Slice 01–02 probes plus Slice 03 probes: `origin header` on unserved URL, `image/svg+xml`, `404` + `image/png` status-first precedence, `application/zip`, `Font/Woff2`, `null` JSON, empty body JSON, plain text in `markdown`/`text`, body-less HTML, Readability duplicate `<h1>` + relative link resolution + title-less article + window slicing) |

## Criteria

| ID | Status | Evidence |
|---|---|---|
| `FW-1` | **Holds** | `scenarios/fetch-web-content/01-basic-html-fetch.txt` L38–50; `src/fetching/fetching.test.ts` (`prepareFetch`) |
| `FW-2` | **Not built** | Queued in Slice 04 (`04-limits-compression-and-timeouts`) |
| `FW-3` | **Holds** | `scenarios/fetch-web-content/01-basic-html-fetch.txt` L52–63; `scenarios/fetch-web-content/02-ssrf-and-redirects.txt` L4–25; `src/fetching/fetching.test.ts` (`isReservedIp`) |
| `FW-4` | **Not covered** *(partially holds)* | DNS validation & rebinding/empty/error fail-closed hold in `scenarios/fetch-web-content/02-ssrf-and-redirects.txt` L27–50 and `src/fetching/fetching.test.ts` (`validateResolvedIps`); socket-level IP pinning waits on Slice 05 |
| `FW-5` | **Holds** | `scenarios/fetch-web-content/01-basic-html-fetch.txt` L4–36; `src/fetching/fetching.test.ts` (`evaluateResponse`) |
| `FW-6` | **Holds** | `scenarios/fetch-web-content/02-ssrf-and-redirects.txt` L52–120; `src/fetching/fetching.test.ts` (`validateRedirectHop`, `stripCrossOriginHeaders`) |
| `FW-7` | **Not built** | Queued in Slice 04 (`04-limits-compression-and-timeouts`) |
| `FW-8` | **Not built** | Queued in Slice 04 (`04-limits-compression-and-timeouts`) |
| `FW-9` | **Holds** | `scenarios/fetch-web-content/03-formats-and-content-guards.txt` L4–32; `src/fetching/fetching.test.ts` (`isBinaryContentType`, `evaluateResponse`) |
| `FW-10` | **Holds** | `scenarios/fetch-web-content/01-basic-html-fetch.txt` L4–9; `src/fetching/fetching.test.ts` (`evaluateResponse`) |
| `FW-11` | **Holds** | `scenarios/fetch-web-content/03-formats-and-content-guards.txt` L34–47; `src/fetching/fetching.test.ts` (`evaluateResponse` json) |
| `FW-12` | **Holds** | `scenarios/fetch-web-content/03-formats-and-content-guards.txt` L49–60; `src/fetching/fetching.test.ts` (`evaluateResponse` text & markdown) |
| `FW-13` | **Holds** | `scenarios/fetch-web-content/03-formats-and-content-guards.txt` L62–77; `src/fetching/fetching.test.ts` (`evaluateResponse` readable) |
| `FW-14` | **Holds** | `scenarios/fetch-web-content/01-basic-html-fetch.txt` L11–22; `src/fetching/fetching.test.ts` (`windowedExcerpt`) |
| `FW-15` | **Not built** | Queued in Slice 05 (`05-real-transport-and-cli-wiring`) |

## Findings

### Bugs

*(None.)*

### Drift

1. **Missing `isBinaryContentType` in `plan.md` Contexts table:**
   - `docs/journeys/fetch-web-content/plan.md:31` lists `normalizeHostname, isIpLiteral, isReservedIp, stripCrossOriginHeaders, windowedExcerpt` under `Queries`, omitting `isBinaryContentType` added in Slice 03 (`src/fetching/queries.ts:182`).

### Needs a decision

1. **`image/svg+xml` handling under `D17`:**
   - Exploring `origin header https://example.com/svg Content-Type image/svg+xml` + `fetch html https://example.com/svg` printed `error: Unsupported binary Content-Type "image/svg+xml" fetching https://example.com/svg`, because `D17` blocks all `image/*`. Since SVG is UTF-8 XML text (and sometimes useful to inspect as `html`/`text`), confirm whether `image/svg+xml` should stay blocked under `image/*` or be explicitly excluded from the binary Content-Type guard.

### Gaps

1. **`FW-4` socket IP pinning not exercised in harness (`cli/commands/fetch.ts:81`):**
   - Already queued in Slice 05 (`05-real-transport-and-cli-wiring`).
2. **Duplicate case-insensitive custom request header keys (`cli/commands/fetch.ts:62`):**
   - Already queued in Slice 04 (`04-limits-compression-and-timeouts`).

## By-hand checklist (for the user)

- [ ] *(After Slice 05)* Run `bun run build && node dist/cli.js readable https://example.com --max-length 500` and verify readable Markdown output (`stdout`, exit `0`). [`FW-13`, `FW-15`]
- [ ] *(After Slice 05)* Run `node dist/cli.js html http://127.0.0.1/` and verify blocked Target URL message on `stderr` with exit `1`. [`FW-3`, `FW-15`]

## Proposed `/dd-decide` items

Ready to run if you want to allow SVG text responses (otherwise leave `D17` as-is to keep blocking all `image/*`):

```text
/dd-decide Update D17: exclude image/svg+xml from the binary Content-Type guard because SVG is UTF-8 XML text; continue rejecting all other image/* types.
```
