# MCP Interface: Acceptance Criteria

An **Agent** connects to `mcp-fetch-server` over MCP stdio (`2025-11-25`), inspects advertised capabilities and tools,
and invokes `fetch_html`, `fetch_markdown`, `fetch_readable`, `fetch_text`, `fetch_json`, or `fetch_transcript` over
the shared domain core under **Operator** limits and proxy policy ([plan](plan.md)).

Rules that hold whichever journey is involved, and the decisions (D#), questions (U#) and invariants (I#) cited here,
are in [`REQUIREMENTS.md`](../../../REQUIREMENTS.md). These criteria say what **Agent** and **Operator** can do and
see; they cite rules rather than restate them. Each slice's [spec](specs/) names the criteria it covers.

Each criterion is one or more Gherkin scenarios tagged with its id (`@MI-1`) and the decisions, questions and
invariants it cites. Scenarios that share an id make up one criterion.

## Steps

1. **Start & Validate Operator Limits.** Server validates `DEFAULT_LIMIT` and `MAX_RESPONSE_BYTES` at startup, failing fast to `stderr` with exit `1` if invalid.
2. **Initialize & Advertise Capabilities.** Server completes the MCP `2025-11-25` handshake advertising only `tools` (never unimplemented `resources` or `prompts`).
3. **List Tools.** Server lists the six Terminology-aligned tools with no `proxy` property in any schema and rejects unrecognized pagination cursors with `-32602`.
4. **Dispatch Tool Calls.** Server rejects unknown tool names with `-32602`, rejects unexpected arguments (including any smuggled `proxy`) with `isError: true`, and routes valid calls through the shared domain core under Operator Proxy Policy and limits.
5. **Return Tool Result.** Server returns `CallToolResult` with `isError: false` on success and `isError: true` with the typed error text on validation or domain failures.
6. **Clean v2.0.0 Distribution.** Legacy v1.2.0 modules are retired, Biome covers all of `src/**`, and `README.md`/`package.json` reflect v2.0.0.

## 1. Start & Validate Operator Limits

```gherkin
@MI-1 @D2 @D9 @D14 @D25 @D29
Scenario: Invalid DEFAULT_LIMIT or MAX_RESPONSE_BYTES fails fast at MCP server startup
  Given the Operator starts mcp-fetch-server with an invalid DEFAULT_LIMIT or MAX_RESPONSE_BYTES env var
  When the process initializes
  Then it writes the typed configuration error to stderr and exits with code 1 before accepting MCP requests (D25, D29)
```

## 2. Initialize & Advertise Capabilities

```gherkin
@MI-2 @D13 @D27
Scenario: Handshake conforms to MCP 2025-11-25 and advertises only implemented capabilities
  Given an Agent sends initialize for protocolVersion "2025-11-25"
  When mcp-fetch-server responds
  Then capabilities includes tools and omits unimplemented resources and prompts capabilities (D13, D27)
```

## 3. List Tools

```gherkin
@MI-3 @D6 @D10 @D12 @I6
Scenario: tools/list returns the six Terminology-aligned tools with no proxy parameter
  Given an initialized MCP session
  When the Agent calls tools/list with no cursor
  Then the server returns exactly fetch_html, fetch_markdown, fetch_readable, fetch_text, fetch_json, and fetch_transcript (D12)
  And no tool inputSchema includes a proxy property (D6, I6)

@MI-4 @D13 @D27
Scenario: tools/list rejects any unrecognized pagination cursor with JSON-RPC -32602
  Given an initialized MCP session
  When the Agent calls tools/list with a cursor parameter
  Then the server responds with JSON-RPC error code -32602 (InvalidParams) (D27)
```

## 4. Dispatch Tool Calls & 5. Return Tool Result

```gherkin
@MI-5 @D1 @D4 @D6 @D12 @D14 @D24 @D26 @D28 @I6
Scenario: tools/call routes all six tools through the shared domain core under Operator Proxy Policy and rejects smuggled proxy arguments
  Given an Agent calls fetch_html, fetch_markdown, fetch_readable, fetch_text, fetch_json, or fetch_transcript with optional headers, start_index, max_length, and lang
  Then the server applies Operator env Proxy Policy and returns CallToolResult with isError: false and the Windowed Excerpt text (D1, D24, D26)
  When the Agent smuggles a proxy or other unexpected argument into the call
  Then the server rejects the call with CallToolResult isError: true without touching the network (D28, I6)

@MI-6 @D14 @D28
Scenario: Unknown tool names return JSON-RPC -32602 while argument validation and domain errors return isError: true
  Given an Agent invokes an unknown or removed legacy tool name (such as fetch_txt or fetch_youtube_transcript)
  When mcp-fetch-server handles tools/call
  Then it responds with JSON-RPC error code -32602 (InvalidParams) (D28)
  When an Agent invokes a valid tool with invalid arguments, a blocked SSRF Target URL, or a failing origin/transcript
  Then mcp-fetch-server returns CallToolResult with isError: true and the typed error text (D14, D28)
```

## 6. Clean v2.0.0 Distribution

```gherkin
@MI-7 @D10 @D11 @D12 @D13
Scenario: Legacy implementation is retired, all of src/ is linted and typechecked, and docs/package reflect v2.0.0
  Given the MCP server and CLI both run exclusively on the shared domain core
  When the repository is linted, typechecked, built, and tested
  Then no retired legacy modules remain, Biome covers all of src/**, README.md documents the v2.0.0 tools/subcommands/env vars, and package.json reports version 2.0.0 (D10, D11, D12, D13)
```
