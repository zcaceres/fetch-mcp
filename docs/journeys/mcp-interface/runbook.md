# Runbook: MCP Interface

How a person, or an agent, walks the journey by hand: what needs eyes, a browser, a real sandbox or a judgment
call. Everything that can be scripted is a scenario, listed below; the [acceptance criteria](acceptance-criteria.md)
each step shows are in brackets.

## Before you start

```bash
bun install
bun run harness        # interactive; type help
```

Every external system is mocked in memory and starts from its fixtures; `reset` starts again.

## Scenarios

| Scenario | Shows |
|---|---|
| `scenarios/mcp-interface/01-mcp-server-core-wiring.txt` | Tracer bullet: `tools/list` D12 tool names & no `proxy` schema property, `-32602` invalid cursor & unknown/legacy tool rejection, `tools/call` across web & transcript tools, silent `proxy` smuggling strip (`I6`), Operator env proxy & limits enforcement, and `isError: true` domain/argument errors [MI-1, MI-3, MI-4, MI-5, MI-6] |

```bash
bun run harness run scenarios/mcp-interface
```

## By hand

### 1. Live MCP stdio conformance smoke check (after Slice 01)

1. Run `bun run build && DEFAULT_LIMIT=bad node dist/index.js`.
   - Writes `Invalid DEFAULT_LIMIT "bad": must be a non-negative integer` to `stderr` and exits `1`. [MI-1]
2. Pipe an `initialize` + `tools/list` JSON-RPC session into `node dist/index.js`.
   - Advertises only `tools` capability (no `resources`), lists `fetch_html`, `fetch_markdown`, `fetch_readable`, `fetch_text`, `fetch_json`, `fetch_transcript`, and rejects `{ "cursor": "bad" }` with `-32602`. [MI-2, MI-3, MI-4]
3. Optional (with network/npx): run `npx @hasmcp/mcp-spec-test@latest -c "node dist/index.js" --spec-version 2025-11-25` to verify 0 conformance failures and 0 unmet SHOULD recommendations. [MI-2, MI-3, MI-4]
