# Live Verification: Runbook

How to verify the `live-verification` journey. Offline conformance scenarios and cassette replay run deterministically
without network access; live-internet verification and real host checks run on demand.

## Scenarios

| Slice | Scenario | Criteria |
|---|---|---|
| 01 — Cross-Vendor MCP Schema & Strict Conformance | `scenarios/live-verification/01-cross-vendor-mcp-conformance.txt` | LV-1 |

Run all scenarios for this journey:

```bash
bun run harness run scenarios/live-verification
```

## By hand

1. **On-demand live-internet verification & Cassette refresh:**
   - Run `bun run build && bun run verify:live` against the real internet and inspect the **Verification Report** JSON + human summary across `cli`, `mcp-stdio`, and `mcp-http` `[LV-4, LV-5, LV-6]`.
   - To refresh **Cassettes** after confirming all live checks pass, run `bun run verify:live -- --record` and review `git diff fixtures/cassettes/` to verify zero leaked credentials `[LV-2, LV-6, I7]`.
2. **External MCP host spot-check (Claude Code / Claude Desktop, Gemini CLI, OpenAI Agents SDK / MCP Inspector):**
   - Connect each host to `node dist/index.js` (`stdio`) and `node dist/index.js --http` (`http://127.0.0.1:3000/mcp`) and verify clean tool listing, read-only annotations, and live tool execution `[LV-1, LV-5]`.
