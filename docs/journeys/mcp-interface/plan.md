# MCP Interface: Plan

How the journey is built, slice by slice. What it must do is in its [acceptance criteria](acceptance-criteria.md);
decisions (D#) and questions (U#) are in [`REQUIREMENTS.md`](../../../REQUIREMENTS.md).

## Sources

The designs, flows, tickets and documents behind this journey, from its design session.

- [`REQUIREMENTS.md`](../../../REQUIREMENTS.md): system terminology, D1, D2, D6, D10–D14, D24–D29, I1–I6.
- [src/index.ts](../../../src/index.ts) & [src/index.test.ts](../../../src/index.test.ts): v1.2.0 stdio MCP server and tests.
- [Issue #49](../../github/issues/049-mcp-spec-conformance-2-requirements-violated-via-hasmcp-mcp-spec-test-spec.md) & [Issue #50](../../github/issues/050-mcp-spec-conformance-6-requirements-violated-via-hasmcp-mcp-spec-test-spec.md): MCP `2025-11-25` conformance findings (capabilities + `-32602` invalid cursor) and `2026-07-28` deferral.
- [README.md](../../../README.md) & [package.json](../../../package.json): distribution metadata and public documentation.

## Shape

`mcp-fetch-server` is the MCP stdio edge adapter (`src/mcp/server.ts` + `src/index.ts`) linking the three pure bounded
contexts (`src/policy/`, `src/fetching/`, `src/transcript/`) and real integrations (`src/integrations/`) without
introducing new domain rules. At startup, `src/index.ts` validates Operator limits (`DEFAULT_LIMIT`,
`MAX_RESPONSE_BYTES`) via `parseOperatorLimits`, failing fast to `stderr` with exit `1` if invalid (`D25`, `D29`).
`createMcpServer` advertises only `capabilities: { tools: {} }` on MCP `2025-11-25` (`D13`, `D27`), exposes the six
breaking Terminology-aligned tools (`fetch_html`, `fetch_markdown`, `fetch_readable`, `fetch_text`, `fetch_json`,
`fetch_transcript`) with zero `proxy` schema properties (`D6`, `D12`, `I6`), rejects unrecognized `tools/list` cursors
and unknown `tools/call` tool names with JSON-RPC `-32602` (`D27`, `D28`), silently strips any smuggled `proxy`
argument (`D28`, `I6`), and maps domain/validation errors to `CallToolResult` `{ isError: true }` (`D14`, `D28`). Once
wired, legacy v1.2.0 modules (`Fetcher.ts`, `httpClient.ts`, `ssrf.ts`, `YouTubeTranscript.ts`, `types.ts`) are
retired, Biome expands to all of `src/**`, `README.md` is updated, and `package.json` bumps to `2.0.0`.

## Contexts, verbs and queries

This journey adds no new bounded context; it wires an MCP edge adapter (`src/mcp/server.ts`) and stdio entrypoint
(`src/index.ts`) over the existing bounded contexts (`src/policy/`, `src/fetching/`, `src/transcript/`).

| Adapter | Functions | Harness commands |
|---|---|---|
| `src/mcp/server.ts` | `listTools`, `dispatchToolCall`, `createMcpServer` | `mcp list-tools [--cursor <val>]`, `mcp call <tool> <jsonArgs...>` |

## External systems

Reuses `origin`, `dns`, `ytdlp`, and `env` mocks in the harness, plus real `@modelcontextprotocol/sdk` stdio JSON-RPC
integration tests in `src/index.test.ts`.

## Slices

Each slice is one capability, wired through every part of the system (harness commands, adapter, tests) with a
scenario that runs it.

### Done

1. **01 — MCP Server Core Wiring & Conformance (Tracer Bullet).** Adds `src/mcp/server.ts` (`listTools`, `dispatchToolCall`, `createMcpServer`), rewires `src/index.ts` onto the shared domain core with fail-fast startup limits (`D29`), updates `src/index.test.ts` for MCP `2025-11-25` conformance (`-32602` invalid cursor & unknown tool, 6 D12 tool names, `I6` proxy stripping, startup env validation, `isError: true` domain errors), and adds `mcp` harness command + scenario. Covers MI-1, MI-2, MI-3, MI-4, MI-5, MI-6.
   ([spec](specs/01-mcp-server-core-wiring/spec.md), `scenarios/mcp-interface/01-mcp-server-core-wiring.txt`)
2. **02 — Legacy Retirement, Lint Expansion & v2.0.0 Docs.** Ports unique real-caption fixture tests from `src/YouTubeTranscript.fixture.test.ts` into `src/transcript/fixtures.test.ts`, removes retired legacy files (`Fetcher.ts`, `httpClient.ts`, `ssrf.ts`, `YouTubeTranscript.ts`, `types.ts` and their legacy tests), expands `biome.json` to `src/**`, updates `README.md` for v2.0.0 (`D10`, `D12`), and bumps `package.json` to `2.0.0`. Covers MI-7.
   ([spec](specs/02-legacy-retirement-and-v2-docs/spec.md))

### Next

*(None — all planned slices are complete.)*

## Deferred

- MCP `2026-07-28` `server/discover` (issue #50): deferred until `@modelcontextprotocol/sdk` adds support (`D13`, `D27`).
- Remote MCP transports over HTTP / SSE (`D3`).
