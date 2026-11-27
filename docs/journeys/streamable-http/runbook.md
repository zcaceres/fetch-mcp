# Streamable HTTP: Runbook

How to verify the `streamable-http` journey. Everything that can be scripted runs in `scenarios/` and `bun test`; the
by-hand checklist covers real external Streamable HTTP MCP clients.

## Scenarios

| Slice | Scenario | Criteria |
|---|---|---|
| 01 — Streamable HTTP Guards & Core Wiring | `scenarios/streamable-http/01-http-guards-and-core-wiring.txt` | SH-1, SH-2, SH-3, SH-4, SH-5 |

Run all scenarios for this journey:

```bash
bun run harness run scenarios/streamable-http
```

## By hand

1. **External Streamable HTTP MCP client check:**
   - Start `bun run build && node dist/index.js --http --port 3000`.
   - Connect via `npx @modelcontextprotocol/inspector --url http://127.0.0.1:3000/mcp` (or Claude Code / Gemini CLI / OpenAI Agents SDK `MCPServerStreamableHttp`) and verify tool discovery and live `fetch_readable` + `fetch_transcript` execution `[SH-3, SH-4, SH-6]`.
