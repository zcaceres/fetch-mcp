# Slice 01: Streamable HTTP Guards & Core Wiring

## Criteria covered

- `SH-1` (flag parsing & validation; `D25`, `D29`, `D32`)
- `SH-2` (`Host` and `Origin` header DNS-rebinding guards; `D32`)
- `SH-3` (stateless `initialize`, `tools/list`, and `-32602` invalid cursor over `POST /mcp`; `D12`, `D13`, `D27`, `D32`, `D33`)
- `SH-4` (`tools/call` over shared domain core under Operator Proxy Policy and strict `D28`; `D1`, `D14`, `D24`, `D26`, `D28`, `D31`, `D32`, `I1`–`I7`)
- `SH-5` (404 on unknown/legacy `/sse` paths, 405 on unsupported methods, 400 on malformed JSON; `D3`, `D14`, `D32`)

## Goal

Build the pure HTTP argument parser, `Host`/`Origin` DNS-rebinding guard, and stateless Streamable HTTP request handler
in `src/mcp/http.ts`, wired through a new `mcp-http` harness command so every Streamable HTTP rule is testable
deterministically before wiring the live TCP listener in Slice 02.

## Scope

### In
- `src/mcp/http.ts`:
  - `parseServerArgs(argv: readonly string[]): Result<ServerMode, string>` (`stdio` default vs `{ kind: 'http', host: string, port: number }` with defaults `127.0.0.1` and `3000`).
  - `validateHttpOriginAndHost(headers, boundHost, boundPort): Result<void, { readonly status: 403; readonly message: string }>`.
  - `handleStreamableHttpRequest(request, deps)` routing `/mcp` (`POST`), returning `404` on other paths (including `/sse`), `405` on non-`POST` methods, `403` on failed `Host`/`Origin` guard, `400` on invalid JSON body, and stateless MCP JSON-RPC responses for `initialize`, `tools/list`, and `tools/call`.
- Harness command `cli/commands/mcp-http.ts` registered in `cli/commands/index.ts`.
- Unit tests in `src/mcp/http.test.ts` and scenario `scenarios/streamable-http/01-http-guards-and-core-wiring.txt`.

### Out
- Live Node `http.createServer` socket binding and `src/index.ts --http` process entrypoint (Slice 02; `SH-6`).
- Real `StreamableHTTPClientTransport` subprocess test (Slice 02; `SH-6`).
- Updating `src/mcp/server.ts` with `D33` annotations and strict `D28` unknown-key rejection (covered by `live-verification` Slice 01; `handleStreamableHttpRequest` delegates directly to `listTools` / `dispatchToolCall` / `createMcpServer` so it inherits those automatically).

## Vocabulary

- **Agent**, **Operator**, **Operator Limits**, **Proxy Policy**, **Target URL**, **Windowed Excerpt**, **fetch**, **fetch transcript**.

## Adapter Contract (`src/mcp/http.ts`)

| Function | Rule | Error |
|---|---|---|
| `parseServerArgs(argv)` | Empty argv → `{ kind: 'stdio' }`; `--http` enables `{ kind: 'http', host: '127.0.0.1', port: 3000 }`; accepts `--host <addr>` and `--port <1..65535>`; rejects `--host`/`--port` without `--http`, unknown flags, missing values, or invalid ports (`D32`). | `Unknown flag: <flag>`<br>`--host requires --http`<br>`--port requires --http`<br>`--host requires a value`<br>`Invalid --port "<val>": must be an integer between 1 and 65535` |
| `validateHttpOriginAndHost(headers, boundHost, boundPort)` | When bound to localhost (`127.0.0.1`, `localhost`, `::1`), requires `Host` header to match a loopback hostname (`127.0.0.1`, `localhost`, `[::1]`) on `boundPort` (or matching `boundHost:boundPort` when bound to a non-loopback address). If `Origin` header is present, requires `Origin` to parse as `http:`/`https:` with a matching loopback (or `boundHost`) hostname (`D32`). | `{ status: 403, message: 'Forbidden Host header: "<host>"' }`<br>`{ status: 403, message: 'Forbidden Origin header: "<origin>"' }` |
| `handleStreamableHttpRequest(req, deps)` | Checks path === `/mcp` (`404` otherwise, including `/sse`); runs `validateHttpOriginAndHost` (`403`); requires `POST` (`405` otherwise); parses JSON body (`400` on invalid JSON); delegates MCP `2025-11-25` JSON-RPC (`initialize`, `tools/list`, `tools/call`) to `src/mcp/server.ts` statelessly (`D3`, `D12`, `D27`, `D28`, `D32`). | HTTP `404` (`Not Found`), `403`, `405` (`Method Not Allowed`), `400` (`Invalid JSON body`), or MCP JSON-RPC `-32602` / `isError: true` |

## Harness

| Command | Kind | What it does |
|---|---|---|
| `mcp-http check-args [args...]` | domain | Runs `parseServerArgs` and prints `mode: stdio`, `mode: http <host>:<port>`, or `error: <msg>`. |
| `mcp-http request <method> <path> [--host <hdr>] [--origin <hdr>] [--body <json>]` | domain | Parses Operator Limits (`D25`, `D29`), invokes `handleStreamableHttpRequest` over harness mocks (`world.origin`, `world.dns`, `world.ytdlp`, `world.env`) bound to `127.0.0.1:3000`, and prints `status: <code>` + body summary. |

## Placeholders

*(None — all rules settled by D3, D12–D14, D24–D29, D31–D33, I1–I7.)*

## Tests

- **Unit tests** (`src/mcp/http.test.ts`): `parseServerArgs` (defaults, custom host/port, invalid flags/ports), `validateHttpOriginAndHost` (localhost Host/Origin allowed, attacker Host/Origin blocked `403`, non-loopback bind matching), `handleStreamableHttpRequest` (`initialize`, `tools/list`, `-32602` cursor, `tools/call` web & transcript with Operator proxy, `404` `/sse`, `405` `GET`/`PUT`, `400` invalid JSON).
- **Scenario:** `scenarios/streamable-http/01-http-guards-and-core-wiring.txt`.

## Done when

- `src/mcp/http.ts`, `cli/commands/mcp-http.ts`, and `src/mcp/http.test.ts` pass `bun run lint`, `bun run typecheck`, `bun test`, and `bun run harness run scenarios/streamable-http/01-http-guards-and-core-wiring.txt`.
