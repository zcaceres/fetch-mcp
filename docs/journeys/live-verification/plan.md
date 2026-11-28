# Live Verification: Plan

How the journey is built, slice by slice. What it must do is in its [acceptance criteria](acceptance-criteria.md);
decisions (D#) and questions (U#) are in [`REQUIREMENTS.md`](../../../REQUIREMENTS.md).

## Sources

The designs, flows, tickets and documents behind this journey, from its design session.

- [`REQUIREMENTS.md`](../../../REQUIREMENTS.md): system terminology, D1, D3, D12–D14, D27, D28, D30–D35, I1–I7.
- Anthropic / MCP `2025-11-25` server specification & `@modelcontextprotocol/inspector` docs, Google Gemini CLI MCP docs, and OpenAI Responses API / Agents SDK MCP docs (reviewed 2026-11-27).
- GitHub repository issues & PRs (`zcaceres/fetch-mcp`): real-world user failure reports (international pages, Readability/Markdown edge cases, live YouTube transcripts, Node/jsdom bundling, MCP client capability probing).
- [src/transcript/fixtures.test.ts](../../../src/transcript/fixtures.test.ts): existing real YouTube `jNQXAC9IVRw` caption fixtures.

## Shape

An **Agent** or **Operator** verifies `fetch-mcp` end to end without brittle mocks or flaky CI:
1. A pure bounded context `src/verification/` defines **Cassette**, **Form Factor**, **Live Sample**, **Output Check**,
   and **Verification Report** *(derived)* (`D35`), cross-vendor MCP conformance checks (Anthropic, Gemini, OpenAI rules
   per `D28`, `D33`), secret redaction (`D31`, `I7`), resilient **Output Checks**, and report summarization
   (`pass` / `fail` / `skipped_env` per **Live Sample** × **Form Factor**).
2. A local HTTPS `CONNECT` replay proxy (`src/integrations/replay/`) generates an ephemeral CA (`NODE_EXTRA_CA_CERTS`)
   and replays wire-level **Cassettes** from `fixtures/cassettes/` through unmodified built `dist/` binaries via
   Operator `HTTP_PROXY`/`HTTPS_PROXY` — keeping `I1`–`I7` 100% unmodified with zero SSRF backdoors (`D34`).
3. An on-demand runner (`bun run verify:replay` for offline cassette replay; `bun run verify:live` / `--record` for live
   internet checks & safe cassette refreshes) drives all three **Form Factors** (`dist/cli.js`, `dist/index.js` stdio,
   `dist/index.js --http` Streamable HTTP), never overwrites valid **Cassettes** on live failure, and prints the
   structured **Verification Report** JSON plus a human-readable summary (`D34`, `D35`).

## Contexts, verbs and queries

Where this journey lives in the code. Contexts never import each other; callers (harness, verification runner, tests)
link `src/verification/` to `src/mcp/` and `src/integrations/replay/`.

| Context | Nouns | Verbs | Queries | Harness commands |
|---|---|---|---|---|
| `src/verification/` | `FormFactor`, `Cassette`, `LiveSample`, `OutputCheck`, `VerificationReport` *(derived)* | `parseCassette`, `updateCassette` | `validateVendorSchemas`, `redactCassette`, `evaluateOutputChecks`, `classifyCellStatus`, `checkFormFactorParity`, `summarizeReport`, `formatReportSummary` | `verify-mcp check-schemas`, `verify-mcp check-strict <tool> <jsonArgs...>` |

## External systems

| System | What we need from it | World commands / Adapter |
|---|---|---|
| Local Replay Proxy (`src/integrations/replay/`) | Ephemeral TLS CA + HTTP/HTTPS `CONNECT` server replaying `fixtures/cassettes/` offline and recording live wire hops on demand | Real local proxy in `src/integrations/replay/proxy.ts` + in-memory cassette store in tests |
| Built `dist/` Binaries (`dist/cli.js`, `dist/index.js`) | Unmodified Node subprocesses for `cli`, `mcp-stdio`, and `mcp-http` | Subprocess drivers in `src/integrations/replay/drivers.ts` |
| Live Internet Targets | Real public web pages, JSON endpoints, refusal URLs, and public YouTube videos (on-demand live mode only) | Real network only under `bun run verify:live` (never in default `bun test` / PR CI) |

## Slices

Each slice is one capability, wired through every part of the system with a scenario or test suite that runs it.

### Done

1. **01 — Cross-Vendor MCP Schema & Strict Conformance (Tracer Bullet).** Upgraded `src/mcp/server.ts` with root `additionalProperties: false`, typed `headers` (`additionalProperties: { type: 'string' }`), MCP `2025-11-25` read-only tool annotations (`D33`), and strict `z.strictObject` runtime rejection of unexpected keys including smuggled `proxy` (`D28`, `I6`); updated `MI-5`/`MI-6`, `scenarios/mcp-interface/01-mcp-server-core-wiring.txt`, and `src/index.test.ts`; added pure `src/verification/` (`validateVendorSchemas`) and `verify-mcp` harness command + scenario. Covers LV-1.
   ([spec](specs/01-cross-vendor-mcp-conformance/spec.md), `scenarios/live-verification/01-cross-vendor-mcp-conformance.txt`)
2. **02 — Wire-Level Cassette Core & Output Checks.** Added `FormFactor`, `Cassette`, `LiveSample`, `OutputCheck`, `VerificationReport` *(derived)* nouns (`D35`), `parseCassette`, `updateCassette` (never overwriting valid cassettes on failure), `redactCassette` (`D31`/`I7`), `evaluateOutputChecks`, `classifyCellStatus`, `checkFormFactorParity`, and `summarizeReport`/`formatReportSummary` in `src/verification/` with unit tests. Covers LV-2, LV-6 (report & safe-update rules).
3. **03 — Local HTTPS CONNECT Replay Proxy & Initial Real-Internet Live Samples.** Implemented ephemeral CA + local HTTPS `CONNECT` replay proxy (`src/integrations/replay/proxy.ts`), curated **Live Samples** (`src/verification/samples.ts`) across all 4 real-world categories, and versioned wire-level **Cassettes** in `fixtures/cassettes/`. Covers LV-3, LV-4.
4. **04 — Multi-Form-Factor Matrix & On-Demand Live Refresh Runner.** Wired `src/integrations/replay/{drivers,runner,replay.test}.ts` plus `bun run verify:replay` and `bun run verify:live` (`--record`), exercising unmodified `dist/cli.js`, `dist/index.js` (`mcp-stdio`), and `dist/index.js --http` (`mcp-http`) across all 8 **Live Samples** (24 matrix cells) with cross-vendor schema checks, byte-for-byte 3-way parity, and zero SSRF backdoors. Covers LV-5, LV-6.

### Next

*(All planned slices for `live-verification` are complete.)*

## Deferred

- Invoking paid Anthropic / Gemini / OpenAI LLM APIs directly with API keys inside automated runs: schema, annotation, wire-protocol, and `@modelcontextprotocol/sdk` client conformance cover cross-vendor server correctness without requiring API billing.
- Automated scheduled nightly live runs in GitHub Actions: can be added later once the on-demand local/agent runner (`bun run verify:live`) is proven stable.
