# Slice 01: Cross-Vendor MCP Schema & Strict Conformance

## Criteria covered

- `LV-1` (Anthropic, Gemini, and OpenAI MCP tool schema, `2025-11-25` annotation, `stdout` hygiene, and strict `D28` unknown-key refusal; `D12`, `D28`, `D33`, `I6`)

## Goal

Upgrade `src/mcp/server.ts` so all six MCP tool definitions conform strictly to Anthropic (Claude), Google (Gemini), and
OpenAI MCP server requirements (`additionalProperties: false`, typed `headers`, `2025-11-25` read-only annotations, and
strict runtime unknown-key refusal per `D28`), create the pure `src/verification/` bounded context with
`validateVendorSchemas`, and wire the `verify-mcp` harness command + scenario.

## Scope

### In
- `src/mcp/server.ts`:
  - Add `additionalProperties: false` to every tool `inputSchema`.
  - Add `additionalProperties: { type: 'string' }` to `headers` property schema (for Gemini/OpenAI strict object typing).
  - Add MCP `2025-11-25` `annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true }` to every tool definition (`D33`).
  - Switch `WebToolArgsSchema` and `TranscriptToolArgsSchema` to `z.strictObject(...)` so unexpected keys — including a smuggled `proxy` — return `CallToolResult` `{ isError: true }` with `Invalid arguments: Unrecognized key: "<key>"` before touching the network (`D28`, `I6`).
- Propagate `D28` to `docs/journeys/mcp-interface/acceptance-criteria.md` (`MI-5`, `MI-6`), `scenarios/mcp-interface/01-mcp-server-core-wiring.txt`, and `src/index.test.ts` (including `stdout` pure-JSON-RPC hygiene assertions on `dist/index.js`).
- New bounded context `src/verification/`:
  - `nouns.ts`: `VendorName` (`'anthropic' | 'gemini' | 'openai'`), `VendorToolSchemaInput`, `VendorCheckIssue`.
  - `queries.ts`: `validateVendorSchemas(tools: readonly VendorToolSchemaInput[]): readonly VendorCheckIssue[]`.
- Harness command `cli/commands/verify-mcp.ts` registered in `cli/commands/index.ts`.
- Unit tests in `src/verification/verification.test.ts` and scenario `scenarios/live-verification/01-cross-vendor-mcp-conformance.txt`.

### Out
- Wire-level Cassette recording/redaction and structural assertion evaluation (Slice 02; `LV-2`).
- Local HTTPS `CONNECT` replay proxy and real-internet corpus (Slice 03; `LV-3`, `LV-4`).
- Multi-form-factor matrix runner across CLI + stdio + Streamable HTTP (Slice 04; `LV-5`, `LV-6`).

## Vocabulary

- **Agent**, **Operator**, **Fetch Request**, **Target URL**, **Format**, **Windowed Excerpt** *(derived)*.

## Queries (`src/verification/queries.ts`)

Pure checks; never stored, never refused.

| Function | Definition |
|---|---|
| `validateVendorSchemas(tools)` | Audits every tool definition against Anthropic, Gemini, and OpenAI MCP rules (`D12`, `D33`, `I6`): requires `snake_case` name, non-empty description, `inputSchema.type === 'object'`, root `additionalProperties === false` (OpenAI strict), no `oneOf`/`anyOf`/`allOf` or unsupported `format` keywords (OpenAI/Gemini), typed `headers.additionalProperties.type === 'string'` (Gemini/OpenAI), no `proxy` property anywhere (`I6`), and explicit `annotations` (`readOnlyHint: true`, `destructiveHint: false`, `idempotentHint: true`, `openWorldHint: true`) (`D33`). Returns an empty array when all checks pass, or typed `VendorCheckIssue[]`. |

## Harness

| Command | Kind | What it does |
|---|---|---|
| `verify-mcp check-schemas` | domain | Runs `listTools(defaultLimit)` and feeds the definitions into `validateVendorSchemas`; prints `conformance: ok (6 tools: anthropic, gemini, openai)` or one `issue: <vendor> <tool>: <message>` line per finding. |
| `verify-mcp check-strict <tool> <jsonArgs...>` | domain | Runs `dispatchToolCall` with `<jsonArgs>` and prints `isError: <true\|false>` + text (confirming strict `D28` refusal of unexpected keys like `proxy`). |

## Placeholders

*(None — all rules settled by D12, D28, D33, I6.)*

## Tests

- **Domain tests** (`src/verification/verification.test.ts`): pure given/when/then tests proving `validateVendorSchemas` passes on valid schemas and catches missing `additionalProperties: false`, untyped `headers`, missing `annotations`, `oneOf`/`anyOf`, and forbidden `proxy` property.
- **MCP server tests** (`src/index.test.ts`): asserts `annotations`, `additionalProperties: false`, typed `headers`, strict `isError: true` refusal of smuggled `proxy` / unknown keys (`D28`), and clean `stdout` JSON-RPC framing (`D33`).
- **Scenario:** `scenarios/live-verification/01-cross-vendor-mcp-conformance.txt`.

## Done when

- `src/mcp/server.ts`, `src/verification/{nouns,queries,verification.test}.ts`, `cli/commands/verify-mcp.ts`, and updated `src/index.test.ts` + `mcp-interface` scenario pass `bun run lint`, `bun run typecheck`, `bun test`, and `bun run harness run scenarios`.
