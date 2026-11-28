# Streamable HTTP: Plan

How the journey is built, slice by slice. What it must do is in its [acceptance criteria](acceptance-criteria.md);
decisions (D#) and questions (U#) are in [`REQUIREMENTS.md`](../../../REQUIREMENTS.md).

## Sources

The designs, flows, tickets and documents behind this journey, from its design session.

- [`REQUIREMENTS.md`](../../../REQUIREMENTS.md): system terminology, D1, D3, D12–D14, D24–D29, D31–D33, I1–I7.
- [src/mcp/server.ts](../../../src/mcp/server.ts) & [src/index.ts](../../../src/index.ts): shared MCP tool definitions, dispatch logic, and `stdio` entrypoint.
- Anthropic MCP `2025-11-25` Streamable HTTP spec, Google Gemini CLI MCP docs, and OpenAI Agents SDK (`MCPServerStreamableHttp`) docs (reviewed 2026-11-27).

## Shape

An **Operator** launches `mcp-fetch-server --http [--host 127.0.0.1] [--port 3000]` to serve MCP `2025-11-25`
**Streamable HTTP** statelessly on `/mcp` (`D32`). Pure edge helpers parse startup flags (`--http`, `--host`,
`--port`), fail fast on invalid flags or **Operator Limits** (`D25`, `D29`), and validate `Host` and `Origin` headers
on every incoming request to block localhost DNS rebinding (`D32`). Valid `POST /mcp` requests spin up a fresh
stateless `StreamableHTTPServerTransport` wired to `createMcpServer`, delegating every tool call to the exact same
bounded contexts (`src/policy/`, `src/fetching/`, `src/transcript/`) under Operator-only **Proxy Policy** (`I6`) and
strict `D28` validation. Unknown paths (including legacy `/sse`) return `404` (`D3`), and unsupported methods return
`405`.

## Contexts, verbs and queries

This journey adds no new bounded context; it extends the MCP edge adapter (`src/mcp/http.ts`) and entrypoint
(`src/index.ts`) over the existing bounded contexts (`src/policy/`, `src/fetching/`, `src/transcript/`).

| Adapter | Functions | Harness commands |
|---|---|---|
| `src/mcp/http.ts` | `parseServerArgs`, `validateHttpOriginAndHost`, `handleStreamableHttpRequest`, `startStreamableHttpServer` | `mcp-http check-args [args...]`, `mcp-http request <method> <path> [--host <hdr>] [--origin <hdr>] [--body <json...>]` |

## External systems

Reuses `origin`, `dns`, `ytdlp`, and `env` mocks in the harness, plus real Node `http.createServer` and stock
`@modelcontextprotocol/sdk` `StreamableHTTPClientTransport` integration tests in `src/mcp/http.test.ts` / `src/index.test.ts`.

## Slices

Each slice is one capability, wired through every part of the system (harness commands, adapter functions, tests) with
a scenario that runs it.

### Done

1. **01 — Streamable HTTP Guards & Core Wiring (Tracer Bullet).** Added pure `src/mcp/http.ts` (`parseServerArgs`, `validateHttpOriginAndHost`, stateless `handleStreamableHttpRequest` over `createMcpServer`), `mcp-http` harness command, unit tests, and scenario. Covers SH-1 (flag parsing), SH-2, SH-3, SH-4, SH-5.
   ([spec](specs/01-http-guards-and-core-wiring/spec.md), `scenarios/streamable-http/01-http-guards-and-core-wiring.txt`)
2. **02 — Node HTTP Entrypoint & SDK Client Interop.** Added `startStreamableHttpServer` in `src/mcp/http.ts` using `@modelcontextprotocol/sdk`'s stateless `StreamableHTTPServerTransport`, wired `--http` / `--host` / `--port` in `src/index.ts` (with fail-fast `D29` limits and SIGINT/SIGTERM cleanup), and added real `StreamableHTTPClientTransport` + `Client` interop tests in `src/mcp/http.test.ts`. Covers SH-1 (process exit), SH-6.

### Next

*(All planned slices for `streamable-http` are complete.)*

## Deferred

- Stateful `Mcp-Session-Id` session management & `DELETE /mcp` teardown: stateless per-request handling satisfies current fetch tools (`D32`).
- Built-in OAuth 2.1 / multi-tenant authentication for public cloud hosting (`D3`).
- Legacy HTTP+SSE (`/sse`) transport (`D3`, `D32`).
