# Fetch MCP Server

![fetch mcp logo](logo.jpg)

[![npm version](https://img.shields.io/npm/v/mcp-fetch-server.svg)](https://www.npmjs.com/package/mcp-fetch-server)

A lightweight, SSRF-hardened MCP stdio server (`mcp-fetch-server`) and local CLI (`mcp-fetch`) for fetching public web content as HTML, Markdown, readable article Markdown, plain text, JSON, or YouTube transcripts. Supports Node.js `>= 20` LTS and Bun.

<a href="https://glama.ai/mcp/servers/nu09wf23ao">
  <img width="380" height="200" src="https://glama.ai/mcp/servers/nu09wf23ao/badge" alt="Fetch Server MCP server" />
</a>

## Breaking Changes in v2.0.0

- **Aligned MCP tool names:** `fetch_txt` → `fetch_text`, `fetch_youtube_transcript` → `fetch_transcript`.
- **Aligned CLI subcommands:** `txt` → `text`, `youtube` → `transcript`, plus repeatable `--header <Key:Value>`.
- **Fail-fast configuration:** invalid `DEFAULT_LIMIT`, `MAX_RESPONSE_BYTES`, or proxy URLs now fail explicitly instead of silently falling back to defaults or direct connections.
- **Explicit missing caption language:** requesting an unavailable YouTube transcript language now fails explicitly and lists the available language codes.
- **Runtime floor:** requires Node.js `>= 20` LTS or Bun.

## MCP Tools

All tools conform to MCP `2025-11-25` and accept the following common parameters (proxy routing for MCP is strictly Operator-configured via environment variables and can never be supplied by a tool caller):

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `url` | string | Yes | Public `http:` or `https:` URL to fetch |
| `headers` | object | No | Optional custom request headers |
| `max_length` | number | No | Maximum characters to return (default: `DEFAULT_LIMIT` / `5000`; `0` = unlimited) |
| `start_index` | number | No | Start content from this character index (default: `0`) |

- **`fetch_html`** — Fetch a URL and return its unmodified HTML content.
- **`fetch_markdown`** — Fetch a URL, strip `<script>` and `<style>`, and convert to Markdown.
- **`fetch_readable`** — Extract the main article content using [Mozilla Readability](https://github.com/mozilla/readability), convert to Markdown, and prepend `# <title>` when present.
- **`fetch_text`** — Fetch a URL, strip `<script>` and `<style>`, and return normalized plain text.
- **`fetch_json`** — Fetch a JSON resource, validate via `JSON.parse`, and return compact JSON.
- **`fetch_transcript`** — Fetch a YouTube video's captions (tries local `yt-dlp` first with manual and auto-generated subtitles enabled, falling back to direct watch-page + caption XML extraction). Accepts an optional `lang` parameter (default: `"en"`).

## Installation

### As an MCP server

Add to your MCP client configuration:

```json
{
  "mcpServers": {
    "fetch": {
      "command": "npx",
      "args": ["mcp-fetch-server"]
    }
  }
}
```

### As a CLI

```bash
npx mcp-fetch <command> <url> [flags]
```

Or install globally:

```bash
npm install -g mcp-fetch-server
mcp-fetch <command> <url> [flags]
```

## CLI Usage

```text
mcp-fetch <command> <url> [flags]
```

### Commands

| Command | Description |
|---------|-------------|
| `html` | Fetch a URL and return raw HTML |
| `markdown` | Fetch a URL and return Markdown |
| `readable` | Fetch a URL and return article content as Markdown (via Readability) |
| `text` | Fetch a URL and return plain text |
| `json` | Fetch a URL and return JSON |
| `transcript` | Fetch a YouTube video transcript |

### Flags

| Flag | Description |
|------|-------------|
| `--header <Key:Value>` | Custom request header (repeatable) |
| `--max-length <N>` | Maximum characters to return (`0` = unlimited) |
| `--start-index <N>` | Start from this character index |
| `--proxy <URL>` | Proxy URL (`http`, `https`, `socks4`, `socks4a`, `socks5`, `socks5h`, or bare `host:port`; bypasses `NO_PROXY`) |
| `--lang <code>` | Language code for YouTube transcripts (default: `en`) |
| `--help` | Show help message |
| `--version` | Show version |

### Examples

```bash
# Fetch a page as markdown
mcp-fetch markdown https://example.com

# Extract article content without boilerplate
mcp-fetch readable https://example.com/blog/post

# Get a YouTube transcript in Spanish
mcp-fetch transcript https://www.youtube.com/watch?v=jNQXAC9IVRw --lang es

# Fetch with custom headers and a length limit
mcp-fetch html https://example.com --header "Accept-Language: en-US" --max-length 10000

# Fetch through an HTTP or SOCKS5 proxy
mcp-fetch json https://api.example.com/data --proxy socks5://127.0.0.1:1080
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `DEFAULT_LIMIT` | Default character limit for responses (default: `5000`; `0` = unlimited; fails explicitly if invalid) |
| `MAX_RESPONSE_BYTES` | Maximum raw and decompressed response body size in bytes (default: `10485760` / 10 MB; fails explicitly if invalid) |
| `HTTPS_PROXY` / `https_proxy` | Proxy URL for `https://` requests (`http`, `https`, `socks4`, `socks4a`, `socks5`, `socks5h`, or bare `host:port`) |
| `HTTP_PROXY` / `http_proxy` | Proxy URL for `http://` requests (fallback for `https://`) |
| `ALL_PROXY` / `all_proxy` | Fallback proxy URL for HTTP/HTTPS requests |
| `NO_PROXY` / `no_proxy` | Comma-separated hostnames, `.domain` suffixes, `:port` entries, `[ipv6]:port`, or `*` bypassing Operator env proxies |

Example with custom limits and an Operator proxy:

```json
{
  "mcpServers": {
    "fetch": {
      "command": "npx",
      "args": ["mcp-fetch-server"],
      "env": {
        "DEFAULT_LIMIT": "50000",
        "HTTPS_PROXY": "socks5://127.0.0.1:1080"
      }
    }
  }
}
```

## Security & Reliability

- **SSRF Protection:** Restricts all requests and redirect hops to `http:`/`https:`, blocks `localhost`/`*.localhost` and all IANA-reserved IPv4/IPv6 ranges (including IPv4-mapped IPv6 and multicast), fails closed on malformed IPs or DNS failures, pins validated DNS records directly to sockets on direct connections to prevent DNS rebinding, and delegates public hostname DNS to the proxy when proxied.
- **Header & Redirect Hygiene:** Strips `Authorization`, `Cookie`, and `Proxy-Authorization` across cross-origin redirects, caps redirects at 10 hops, rejects CR/LF header injection, and redacts proxy credentials from error output.
- **Resource Safety:** Enforces `MAX_RESPONSE_BYTES` across declared `Content-Length`, streaming wire bytes, decompressed `gzip`/`deflate`/`br` streams, and `yt-dlp` subtitle files; rejects clearly binary `Content-Type` responses; enforces a `30s` single-attempt timeout.
- **YouTube Isolation:** Restricts `fetch_transcript` / `mcp-fetch transcript` to allowlisted YouTube hosts, validates `lang` codes strictly, passes `--` end-of-options sentinel to `yt-dlp`, and never swallows validation or SSRF errors into fallback.

## Development

```bash
bun install
bun run lint                       # Biome lint & formatting check
bun run typecheck                  # TypeScript typecheck
bun test                           # Unit, integration, and scenario tests
bun run harness run scenarios      # Replay all DD harness scenarios
bun run build                      # Build dist/index.js and dist/cli.js
```

## License

This project is licensed under the MIT License.
