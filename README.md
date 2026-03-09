# Fetch MCP Server

![fetch mcp logo](logo.jpg)

[![npm version](https://img.shields.io/npm/v/mcp-fetch-server.svg)](https://www.npmjs.com/package/mcp-fetch-server)

An MCP server for fetching web content in multiple formats — HTML, JSON, plain text, Markdown, readable article content, and YouTube transcripts.

<a href="https://glama.ai/mcp/servers/nu09wf23ao">
  <img width="380" height="200" src="https://glama.ai/mcp/servers/nu09wf23ao/badge" alt="Fetch Server MCP server" />
</a>

## Tools

All tools accept the following common parameters:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `url` | string | Yes | URL to fetch |
| `headers` | object | No | Custom headers to include in the request |
| `max_length` | number | No | Maximum characters to return (default: 5000) |
| `start_index` | number | No | Start from this character index (default: 0) |
| `proxy` | string | No | Proxy URL (e.g. `http://proxy:8080`) |

- **fetch_html** — Fetch a website and return its raw HTML content.

- **fetch_markdown** — Fetch a website and return its content converted to Markdown.

- **fetch_txt** — Fetch a website and return plain text with HTML tags, scripts, and styles removed.

- **fetch_json** — Fetch a URL and return the JSON response.

- **fetch_readable** — Fetch a website and extract the main article content using [Mozilla Readability](https://github.com/mozilla/readability), returned as Markdown. Strips navigation, ads, and boilerplate. Ideal for articles and blog posts.

- **fetch_youtube_transcript** — Fetch a YouTube video's captions/transcript. Uses `yt-dlp` if available, otherwise extracts directly from the page. Accepts an additional `lang` parameter (default: `"en"`) to select the caption language.

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

```
mcp-fetch <command> <url> [flags]
```

### Commands

| Command | Description |
|---------|-------------|
| `html` | Fetch a URL and return raw HTML |
| `markdown` | Fetch a URL and return Markdown |
| `readable` | Fetch a URL and return article content as Markdown (via Readability) |
| `txt` | Fetch a URL and return plain text |
| `json` | Fetch a URL and return JSON |
| `youtube` | Fetch a YouTube video transcript |

### Flags

| Flag | Description |
|------|-------------|
| `--max-length <N>` | Maximum characters to return |
| `--start-index <N>` | Start from this character index |
| `--proxy <URL>` | Proxy URL |
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
mcp-fetch youtube https://www.youtube.com/watch?v=dQw4w9WgXcQ --lang es

# Fetch with a length limit
mcp-fetch html https://example.com --max-length 10000

# Fetch through a proxy
mcp-fetch json https://api.example.com/data --proxy http://proxy:8080
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `DEFAULT_LIMIT` | Default character limit for responses (default: `5000`, set to `0` for no limit) |

Example with a custom limit:

```json
{
  "mcpServers": {
    "fetch": {
      "command": "npx",
      "args": ["mcp-fetch-server"],
      "env": {
        "DEFAULT_LIMIT": "50000"
      }
    }
  }
}
```

## Features

- Fetch web content as HTML, JSON, plain text, or Markdown
- Extract article content with Mozilla Readability (strips ads, nav, boilerplate)
- Extract YouTube video transcripts (via `yt-dlp` or direct extraction)
- Proxy support for requests behind firewalls
- Pagination with `max_length` and `start_index`
- Custom request headers
- SSRF protection (blocks private/localhost addresses)

## Development

```bash
bun install
bun run dev     # start with watch mode
bun test        # run tests
bun run build   # build for production
```

## License

This project is licensed under the MIT License.
