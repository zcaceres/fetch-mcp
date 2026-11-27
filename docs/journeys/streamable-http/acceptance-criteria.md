# Streamable HTTP: Acceptance Criteria

An **Operator** launches `mcp-fetch-server --http` and an **Agent** connects over MCP `2025-11-25` **Streamable HTTP**
(`/mcp`), discovers the six Terminology-aligned tools, and invokes them statelessly over the shared domain core under
**Operator Limits**, **Proxy Policy**, and localhost `Origin`/`Host` DNS-rebinding guards ([plan](plan.md)).

Rules that hold whichever journey is involved, and the decisions (D#), questions (U#) and invariants (I#) cited here,
are in [`REQUIREMENTS.md`](../../../REQUIREMENTS.md). These criteria say what **Agent** and **Operator** can do and
see; they cite rules rather than restate them. Each slice's [spec](specs/) names the criteria it covers.

Each criterion is one or more Gherkin scenarios tagged with its id (`@SH-1`) and the decisions, questions and
invariants it cites. Scenarios that share an id make up one criterion.

## Steps

1. **Start & Validate Operator Limits.** Operator launches `mcp-fetch-server --http [--host <addr>] [--port <n>]`; server validates flags and Operator Limits before binding.
2. **Enforce Host & Origin Guards.** Server validates `Host` and `Origin` headers on every `/mcp` request to block localhost DNS rebinding.
3. **Initialize & List Tools Over HTTP.** Agent completes MCP `2025-11-25` `initialize` and `tools/list` statelessly via `POST /mcp`.
4. **Invoke Tools Over Shared Core.** Agent invokes all six tools via `POST /mcp` under Operator Limits, Proxy Policy, SSRF, and strict `D28` argument rules.
5. **Reject Unsupported Routes & Legacy SSE.** Unknown paths, unsupported HTTP methods, legacy SSE routes, and malformed JSON fail explicitly.
6. **Verify Built Binary SDK Interop.** Built `dist/index.js --http` interoperates end-to-end with `@modelcontextprotocol/sdk` `StreamableHTTPClientTransport`.

## 1. Start & Validate Operator Limits

```gherkin
@SH-1 @D25 @D29 @D32
Scenario: --http flag parses host/port with 127.0.0.1:3000 defaults and rejects invalid flags or Operator Limits at startup
  Given an Operator launches `mcp-fetch-server --http` with default or explicit `--host` / `--port` flags
  When flags or `DEFAULT_LIMIT` / `MAX_RESPONSE_BYTES` are invalid
  Then the process writes a typed error to stderr and exits with code 1 before binding any listening socket (D25, D29, D32)
```

## 2. Enforce Host & Origin Guards

```gherkin
@SH-2 @D32
Scenario: Non-allowlisted Host or untrusted cross-origin Origin headers are rejected with HTTP 403
  Given `mcp-fetch-server --http` is bound to `127.0.0.1:3000`
  When an HTTP request arrives on `/mcp` with `Host: attacker.example` or `Origin: https://evil.example`
  Then the server rejects the request with HTTP 403 before parsing MCP JSON-RPC (D32)
  When an HTTP request arrives with a matching localhost `Host` and either no `Origin` or a matching localhost `Origin`
  Then the request passes origin/host validation (D32)
```

## 3. Initialize & List Tools Over HTTP

```gherkin
@SH-3 @D12 @D13 @D27 @D32 @D33
Scenario: Stateless POST /mcp serves MCP 2025-11-25 initialize, 6-tool tools/list, and -32602 invalid cursor
  Given a running `mcp-fetch-server --http` endpoint at `/mcp`
  When an Agent sends `initialize` (`2025-11-25`) and `tools/list` via `POST /mcp`
  Then the server advertises only `tools` capability and lists the six D12 tools with D33 schemas and annotations (D12, D13, D27, D32, D33)
  And `tools/list` with any defined `cursor` returns JSON-RPC `-32602` (D27)
```

## 4. Invoke Tools Over Shared Core

```gherkin
@SH-4 @D1 @D14 @D24 @D26 @D28 @D31 @D32 @I1 @I2 @I3 @I4 @I5 @I6 @I7
Scenario: POST /mcp tools/call routes all six tools through the shared domain core under Operator Proxy Policy and strict D28 rules
  Given `mcp-fetch-server --http` is configured with Operator Limits and Proxy Policy
  When an Agent calls any of the six D12 tools via `POST /mcp`
  Then valid calls return `CallToolResult` (`isError: false`) with the Windowed Excerpt using Operator Proxy Policy (D1, D24, D26, D32)
  And unknown tools return JSON-RPC `-32602` while unexpected keys (including smuggled `proxy`) and SSRF/domain errors return `isError: true` with credentials redacted (D14, D28, D31, I1, I6, I7)
```

## 5. Reject Unsupported Routes & Legacy SSE

```gherkin
@SH-5 @D3 @D14 @D32
Scenario: Unknown paths, legacy SSE endpoints, unsupported methods, and malformed JSON fail explicitly
  Given a running `mcp-fetch-server --http` server
  When a client requests `/sse` or `/unknown`
  Then the server responds with HTTP 404 (D3, D32)
  When a client sends an unsupported method (such as `PUT /mcp`) or invalid JSON body on `POST /mcp`
  Then the server responds cleanly with HTTP 405 or 400 without crashing or leaking stack traces (D14, D32)
```

## 6. Verify Built Binary SDK Interop

```gherkin
@SH-6 @D13 @D32 @D33
Scenario: Built dist/index.js --http interoperates with stock @modelcontextprotocol/sdk StreamableHTTPClientTransport
  Given `dist/index.js --http --port <ephemeral>` is spawned under Node.js
  When a stock `@modelcontextprotocol/sdk` `Client` connects via `StreamableHTTPClientTransport`
  Then `listTools`, `callTool`, and protocol error handling succeed cleanly across multiple stateless requests (D13, D32, D33)
```
