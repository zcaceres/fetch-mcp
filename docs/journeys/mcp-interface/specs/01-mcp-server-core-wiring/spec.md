# Slice 01: MCP Server Core Wiring & Conformance

Part of the [MCP Interface plan](../../plan.md). Decisions referenced as D# / U# / I# are in
[`REQUIREMENTS.md`](../../../../../REQUIREMENTS.md). Tracer bullet — first slice of the journey.

Covers [acceptance criteria](../../acceptance-criteria.md) MI-1, MI-2, MI-3, MI-4, MI-5, and MI-6.

## Goal

Extract the testable MCP server wiring into `src/mcp/server.ts` (`listTools`, `dispatchToolCall`, `createMcpServer`),
rewire `src/index.ts` off legacy `Fetcher` onto the shared domain core (`src/policy/`, `src/fetching/`,
`src/transcript/`, and real integrations) with fail-fast Operator startup limits (`D25`, `D29`), conform cleanly to
MCP `2025-11-25` (`tools` capability only, `-32602` on unrecognized `tools/list` cursors and unknown `tools/call` tool
names per `D27`, `D28`), strictly reject unexpected arguments including smuggled `proxy` (`I6`, `D28`, `D33`), and wire
the `mcp` harness command plus stdio JSON-RPC integration tests in `src/index.test.ts`.

**Done when:** `bun run lint`, `bun run typecheck`, `bun run build`, `bun test` (including updated stdio MCP tests in
`src/index.test.ts`), and `bun run harness run scenarios` (all journeys) pass cleanly.

## Scope

**In:**
- `src/mcp/server.ts`:
  - `MCP_TOOL_NAMES`: `['fetch_html', 'fetch_markdown', 'fetch_readable', 'fetch_text', 'fetch_json', 'fetch_transcript']` (`D12`).
  - `listTools(defaultLimit: number, cursor?: string)`: returns the 6 tool definitions (zero `proxy` schema properties per `I6`) or `err({ code: -32602, message: 'Invalid pagination cursor' })` when `cursor !== undefined` (`D27`).
  - `dispatchToolCall(name: string, rawArgs: unknown, deps: McpDispatchDeps)`:
    - Rejects unknown or removed legacy tool names (`fetch_txt`, `fetch_youtube_transcript`, etc.) with `err({ code: -32602, message: 'Unknown tool: <name>' })` (`D28`).
    - Parses arguments via strict Zod (`z.strictObject` with `url: z.string()`, optional `headers`, `max_length`, `start_index`, `lang`), rejecting any unknown keys including `proxy` with `isError: true` (`D28`, `D33`, `I6`).
    - Returns `{ content: [{ type: 'text', text }], isError: true }` on structural argument validation errors or domain/transport/proxy errors (`D14`, `D28`).
    - Dispatches web tools via `executeFetch` and `fetch_transcript` via `executeFetchTranscript`, applying Operator env `resolveProxyPolicy(targetUrl, env)` (never caller proxy per `I6`) and `defaultLimit`/`maxResponseBytes` (`D1`, `D24`, `D26`).
  - `createMcpServer(deps: McpServerDeps)`: wires `@modelcontextprotocol/sdk` `Server` (`capabilities: { tools: {} }`, `ListToolsRequestSchema`, `CallToolRequestSchema` mapping `-32602` errors to `McpError(ErrorCode.InvalidParams, ...)`).
- `src/index.ts`:
  - Validates Operator limits at startup via `parseOperatorLimits(process.env)` — writes `<error.message>\n` to `stderr` and exits `1` on failure (`D25`, `D29`).
  - Connects `createMcpServer` to `StdioServerTransport` using `createRealHttpGet`, `createRealDnsLookup`, and `createRealYtDlp`.
- `src/index.test.ts`:
  - Real stdio JSON-RPC session tests against `src/index.ts` / `dist/index.js`: startup failure on invalid `DEFAULT_LIMIT`/`MAX_RESPONSE_BYTES` (`MI-1`), `initialize` capabilities (`MI-2`), `tools/list` 6 D12 names, `D33` strict schema/annotations, & no `proxy` property (`MI-3`), `tools/list` invalid cursor `-32602` (`MI-4`), unknown/legacy tool `-32602` (`MI-6`), SSRF/validation `isError: true` (`MI-6`), plus unit/integration tests for `dispatchToolCall` across all 6 tools & strict smuggled `proxy` rejection (`MI-5`).
- Harness: `cli/commands/mcp.ts` + `cli/commands/index.ts` (`mcp list-tools [--cursor <val>]`, `mcp call <tool> <jsonArgs...>`).
- `biome.json`: include `src/mcp/**`, `src/index.ts`, `src/index.test.ts`.

**Out:**
- Porting `src/YouTubeTranscript.fixture.test.ts`, deleting legacy `Fetcher.ts`/`httpClient.ts`/`ssrf.ts`/`YouTubeTranscript.ts`/`types.ts`, expanding `biome.json` to all of `src/**`, updating `README.md`, and bumping `package.json` to `2.0.0` (waits on Slice 02: `02-legacy-retirement-and-v2-docs`).

## Vocabulary

The Terminology this slice uses.

- **Agent**, **Operator**, **Target URL**, **Format**, **Window**, **Fetch Request**, **Operator Limits**, **Proxy Policy**, **Rendered Output**, **Transcript**, **Windowed Excerpt** *(derived)*, **parse operator limits**, **resolve proxy policy**, **fetch**, **fetch transcript**.

## What it reads and writes

| Type | Shape |
|---|---|
| `McpToolCallResult` | `{ readonly content: readonly [{ readonly type: 'text'; readonly text: string }]; readonly isError: boolean }` |
| `McpProtocolError` | `{ readonly code: -32602; readonly message: string }` |
| `McpDispatchDeps` | `{ readonly fetchPorts: FetchPorts; readonly ytDlp: YtDlpPort; readonly env: EnvMap; readonly limits: OperatorLimits }` |

## Adapter Contract (`src/mcp/server.ts`)

| Function | Rule | Error |
|---|---|---|
| `listTools(defaultLimit, cursor?)` | Rejects any defined `cursor` with `-32602` (`D27`); otherwise returns the 6 D12 tool schemas without `proxy` (`D6`, `D12`, `I6`). | `-32602`: `Invalid pagination cursor` |
| `dispatchToolCall(name, rawArgs, deps)` | Rejects unknown/legacy tool names with `-32602` (`D28`). Parses args via `z.strictObject` (rejecting unknown fields including `proxy` per `D28`, `D33`, `I6`). Runs `executeFetch` or `executeFetchTranscript` with Operator `resolveProxyPolicy(url, deps.env)` (never caller proxy). Returns `isError: false` on success or `isError: true` on argument/domain errors (`D14`, `D28`). | `-32602`: `Unknown tool: <name>`<br>`isError: true`: `Invalid arguments: <detail>` or exact `FetchError`/`TranscriptError` message |

## Harness

| Command | Kind | What it does |
|---|---|---|
| `mcp list-tools [--cursor <val>]` | domain | Parses Operator limits from `world.env` (`D29`), calls `listTools(limits.defaultLimit, cursor)`. Prints `tool: <name> (<props>)` lines or `error (-32602): <message>`. |
| `mcp call <tool> <jsonArgs...>` | domain | Parses Operator limits from `world.env`, parses `<jsonArgs>` JSON, calls `dispatchToolCall` over `world.origin`, `world.dns`, `world.ytdlp`, `world.env`. Prints `isError: <true\|false>` followed by `\| <line>` (or `(empty)`), or `error (-32602): <message>`. |

## Placeholders

*(None — all rules in Slice 01 are settled by D1, D2, D4, D6, D9, D12, D13, D14, D15, D24–D29, I1–I6.)*

## Tests

- **MCP adapter & stdio tests** (`src/index.test.ts`): real stdio JSON-RPC tests for `MI-1`–`MI-6`, plus in-process `dispatchToolCall` tests for all 6 D12 tools, strict smuggled `proxy` rejection, Operator env proxy delegation, and `isError: true` argument/domain errors.
- **Scenario:** `scenarios/mcp-interface/01-mcp-server-core-wiring.txt`.
