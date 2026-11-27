# Proxy & Limits: Plan

How the journey is built, slice by slice. What it must do is in its [acceptance criteria](acceptance-criteria.md);
decisions (D#) and questions (U#) are in [`REQUIREMENTS.md`](../../../REQUIREMENTS.md).

## Sources

The designs, flows, tickets and documents behind this journey, from its design session.

- [`REQUIREMENTS.md`](../../../REQUIREMENTS.md): system terminology, D2, D5, D6, D8, D9, D14, D15, D21, D23–D26, I1–I6.
- [src/httpClient.ts](../../../src/httpClient.ts) & [src/types.ts](../../../src/types.ts): v1.2.0 proxy precedence, `NO_PROXY`, HTTP/CONNECT proxy logic, and env limit defaults.
- [PR #44](../../github/pull-requests/044-fix-remove-user-controlled-proxy-parameter-to-prevent-ssrf-bypass-cwe-918.md) & [PR #46](../../github/pull-requests/046-add-support-for-environment-proxies-http-https-socks-and-improve-node-js-pr.md): proxy trust boundary (`I6`) and HTTP/HTTPS/SOCKS + bare `host:port` requirements.

## Shape

An **Operator** configures process-level proxy routing (`HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY`, `NO_PROXY`) and
limits (`DEFAULT_LIMIT`, `MAX_RESPONSE_BYTES`) via OS Environment, or a **CLI User** supplies `--proxy`. A new pure
bounded context `src/policy/` parses Operator limits (failing explicitly on invalid values per `D25`), evaluates
`NO_PROXY`, and resolves the effective **Proxy Policy** (`direct` or validated `http:`/`https:`/`socks4:`/`socks4a:`/
`socks5:`/`socks5h:` `ProxyUrl`, normalizing bare `host:port` to `http://` per `D23`–`D25`). Callers (harness, CLI,
and later MCP server) link `src/policy/` into `src/fetching/` and `src/transcript/` through port callbacks without
contexts importing each other. On every hop, local SSRF / YouTube host checks still run (`I1`, `I3`), while active
proxies skip local DNS resolution and delegate hostname DNS to the proxy (`D8`, `D23`, `D26`). The real HTTP client
(`src/integrations/origin/client.ts`) implements zero-dependency HTTP forwarding, HTTPS `CONNECT` tunneling, and
SOCKS4/4a/5/5h tunneling with credential redaction, `30s` timeouts, and `MAX_RESPONSE_BYTES` caps (`D5`, `D9`, `I5`),
allowing `src/cli.ts` to drop its legacy `Fetcher` proxy fallback completely.

## Contexts, verbs and queries

Where this journey lives in the code. Contexts never import each other; callers (harness, CLI, MCP server) link
`src/policy/` to `src/fetching/` and `src/transcript/` via port functions (`ResolveProxyPort`).

| Context | Nouns | Verbs | Queries | Harness commands |
|---|---|---|---|---|
| `src/policy/` | `ProxyProtocol`, `ProxyUrl`, `ProxyPolicy`, `OperatorLimits`, `EnvMap`, `PolicyError` | `parseOperatorLimits`, `resolveProxyPolicy` | `isNoProxyMatch`, `redactProxyUrl` | `fetch ... [--proxy <url>]`, `fetch-transcript ... [--proxy <url>]` |

## External systems

Every system outside ours is mocked in `src/integrations/<system>/`; world commands make it do what the journey needs.

| System | What we need from it | World commands |
|---|---|---|
| OS Environment (`cli/world.ts`) | In-memory Operator environment variables (`HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY`, `NO_PROXY`, `DEFAULT_LIMIT`, `MAX_RESPONSE_BYTES`) | `env set <KEY> <VALUE>`, `env unset <KEY>`, `env clear` |
| Proxy Server (`src/integrations/origin/`, `src/integrations/ytdlp/`) | Records effective proxy URL per request in mocks; real HTTP/CONNECT/SOCKS proxy forwarding in `src/integrations/origin/client.ts` | `origin last-proxy <url>`, `origin proxy-fail <url> <reason...>`, `ytdlp last-args` |

## Slices

Each slice is one capability, wired through every part of the system (harness commands, verbs, ports, mocks) with
a scenario that runs it.

### Done

1. **01 — Operator Limits & Proxy Policy Resolution (Tracer Bullet).** Adds pure `src/policy/` bounded context (`parseOperatorLimits`, `resolveProxyPolicy`, `isNoProxyMatch`, `redactProxyUrl`), extends `FetchPorts` and `TranscriptPorts` with `ResolveProxyPort` + `proxyUrl` handoff (skipping local DNS when proxied per `D8`/`D23`/`D26` and re-evaluating per redirect hop per `D24`), adds `env` world commands, `origin last-proxy`, and `--proxy` on `fetch` / `fetch-transcript`. Covers PL-1, PL-2, PL-3, PL-4, PL-5, PL-6, PL-7, PL-8.
   ([spec](specs/01-operator-limits-and-proxy-policy/spec.md), `scenarios/proxy-and-limits/01-operator-limits-and-proxy-policy.txt`)
2. **02 — Real HTTP, HTTPS CONNECT & SOCKS Proxy Transport.** Extends `src/integrations/origin/client.ts` with zero-dependency HTTP proxy forwarding (`Proxy-Authorization`), HTTPS `CONNECT` tunneling, and RFC 1928 SOCKS5/5h + SOCKS4/4a tunneling with credential redaction, `30s` timeout, and `MAX_RESPONSE_BYTES` caps, backed by real local proxy integration tests and `origin proxy-fail`. Covers PL-9.
   ([spec](specs/02-real-proxy-transport/spec.md), `scenarios/proxy-and-limits/02-real-proxy-transport.txt`)

### Next

In the order we expect to build them; reorder freely. Each says where it came from: criteria, a finding (a
`/dd-verify` note) or a decision.

1. **03 — CLI Proxy & Limits Wiring.** Wires `src/cli.ts` (`fetch` and `transcript`) to `src/policy/` + real proxied `createRealHttpGet` and `createRealYtDlp`, enforces fail-fast Operator limits (`D25`), and removes the legacy `Fetcher` import and proxy fallback from `src/cli.ts`. From PL-10.

## Deferred

- PAC files / WPAD auto-discovery and OS system proxy registries: out of scope for now.
- Custom CA bundles / TLS `rejectUnauthorized: false` for corporate MITM proxies: out of scope for now.
- MCP stdio server (`src/index.ts`) Operator proxy/limit wiring and `I6` schema enforcement: owned by the `mcp-interface` journey.
