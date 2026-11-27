# Live Verification: Acceptance Criteria

An **Agent** or **Operator** verifies `fetch-mcp` against Anthropic (Claude), Google (Gemini), and OpenAI MCP server
requirements and against real-world internet **Live Samples** captured in wire-level **Cassettes**, replayed offline
across all three supported **Form Factors** (`cli`, `mcp-stdio`, `mcp-http`) and refreshed on demand against the live
internet ([plan](plan.md)).

Rules that hold whichever journey is involved, and the decisions (D#), questions (U#) and invariants (I#) cited here,
are in [`REQUIREMENTS.md`](../../../REQUIREMENTS.md). These criteria say what **Agent** and **Operator** can do and
see; they cite rules rather than restate them. Each slice's [spec](specs/) names the criteria it covers.

Each criterion is one or more Gherkin scenarios tagged with its id (`@LV-1`) and the decisions, questions and
invariants it cites. Scenarios that share an id make up one criterion.

## Steps

1. **Validate Cross-Vendor MCP Conformance.** Runner checks all six MCP tool schemas, `2025-11-25` annotations, strict `D28` unknown-key refusal, and `stdio` `stdout` hygiene against Anthropic, Gemini, and OpenAI rules.
2. **Parse, Redact & Evaluate Cassettes.** Domain core parses wire-level **Cassettes**, redacts secrets, and evaluates resilient **Output Checks** without brittle exact-body diffs.
3. **Replay Cassettes Offline Across Real Binaries.** Local HTTPS `CONNECT` replay proxy replays versioned `fixtures/cassettes/` offline against unmodified built `dist/` binaries while keeping `I1`–`I7` intact.
4. **Cover Real-World Internet Material.** Curated **Live Samples** span HTML article/Readability & Markdown/docs, public JSON & compressed/redirected/non-ASCII UTF-8, real refusal cases (404, binary, SSRF), and public YouTube transcripts.
5. **Verify Parity Across All Three Form Factors.** Matrix runner executes every **Live Sample** through `dist/cli.js` (`cli`), `dist/index.js` (`mcp-stdio`), and `dist/index.js --http` (`mcp-http`).
6. **Refresh & Report On Demand Against Live Internet.** Live mode hits real public URLs (separate from default `bun test` / PR CI), never overwrites a valid **Cassette** on failure, prints a **Verification Report** (JSON + human summary), and exits `1` on any failure.

## 1. Validate Cross-Vendor MCP Conformance

```gherkin
@LV-1 @D12 @D28 @D33 @I6
Scenario: All six MCP tools pass Anthropic, Gemini, and OpenAI schema, annotation, and strict unknown-key rules
  Given `listTools` returns the six D12 tool definitions
  When the cross-vendor conformance validator inspects every tool definition
  Then every tool declares root `additionalProperties: false`, typed `headers` (`additionalProperties: { type: "string" }`), no unsupported composition keywords, no `proxy` property, and MCP `2025-11-25` read-only annotations (D12, D33, I6)
  And calling any tool with an unexpected key (including a smuggled `proxy`) returns `CallToolResult` with `isError: true` before touching the network (D28, I6)
  And `dist/index.js` over `stdio` writes strictly valid JSON-RPC frames to `stdout` with zero diagnostic log pollution (D33)
```

## 2. Parse, Redact & Evaluate Cassettes

```gherkin
@LV-2 @D31 @D34 @D35 @I7
Scenario: Wire-level Cassettes redact secrets before persistence and evaluate resilient Output Checks
  Given a captured wire-level HTTP/YouTube exchange containing `Authorization`, `Cookie`, `Set-Cookie`, or proxy credentials
  When the Cassette is redacted and serialized
  Then all sensitive request/response headers and URL credentials are stripped or redacted without corrupting relative `Location` paths (D31, D34, D35, I7)
  And Output Checks verify status/error kind, non-empty output, required substrings/headings, and valid JSON without brittle exact-body matching (D34, D35)
```

## 3. Replay Cassettes Offline Across Real Binaries

```gherkin
@LV-3 @D34 @I1 @I2 @I3 @I4 @I5 @I6 @I7
Scenario: Local HTTPS CONNECT replay proxy drives unmodified dist/ binaries offline with zero SSRF backdoors
  Given versioned Cassettes in `fixtures/cassettes/` and a local HTTPS CONNECT replay proxy with an ephemeral CA (`NODE_EXTRA_CA_CERTS`)
  When unmodified `dist/cli.js`, `dist/index.js`, and `dist/index.js --http` run with Operator `HTTP_PROXY`/`HTTPS_PROXY` pointing at the replay proxy
  Then public `http:` and `https:` Target URLs replay real wire bytes, redirects, compression, and YouTube captions completely offline (D34)
  And SSRF checks (`127.0.0.1`, `localhost`), YouTube host allowlisting, byte caps, and Operator-only proxy rules remain 100% enforced (I1, I2, I3, I4, I5, I6, I7)
```

## 4. Cover Real-World Internet Material

```gherkin
@LV-4 @D34 @D35
Scenario: Curated Live Samples exercise all four web and YouTube categories
  Given the versioned Live Samples manifest and `fixtures/cassettes/`
  Then the Live Samples include real-world targets across (1) HTML article/Readability & Markdown/docs, (2) public JSON & compressed/redirected/non-ASCII UTF-8, (3) real refusal cases (404, binary, SSRF), and (4) public YouTube transcripts (D34, D35)
```

## 5. Verify Parity Across All Three Form Factors

```gherkin
@LV-5 @D1 @D32 @D34 @D35
Scenario: Matrix runner executes every Live Sample across cli, mcp-stdio, and mcp-http
  Given built `dist/cli.js` and `dist/index.js` binaries and the offline replay proxy (or live internet)
  When the Agent or Operator runs the matrix verification runner
  Then every Live Sample runs across `cli`, `mcp-stdio`, and `mcp-http`, verifying Output Checks and exact success/refusal output parity across all three Form Factors (D1, D32, D34, D35)
```

## 6. Refresh & Report On Demand Against Live Internet

```gherkin
@LV-6 @D34 @D35 @I7
Scenario: On-demand live verification never overwrites valid Cassettes on failure and emits structured Verification Reports
  Given an Agent or Operator invokes the on-demand live verification runner (kept separate from default offline `bun test` / PR CI)
  When a Live Sample succeeds in record mode
  Then its redacted Cassette is updated cleanly in `fixtures/cassettes/` via `update cassette` (D34, D35, I7)
  When a required Live Sample fails, or an optional Live Sample succeeds at fetching but fails an Output Check
  Then any existing valid Cassette on disk is left untouched, the runner prints the full Verification Report JSON and human summary (`pass` / `fail` / `skipped_env` per Live Sample × Form Factor), and the process exits with code 1 (D34, D35)
  When an optional Live Sample fails to fetch in live mode due to environment/rate-limit unavailability (`!outcome.ok`)
  Then that cell is classified as `skipped_env` (exit 0 if no other cell failed) while existing valid Cassettes remain untouched (D34)
```
