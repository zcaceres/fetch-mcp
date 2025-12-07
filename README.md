# Fetch MCP Server

![fetch mcp logo](logo.jpg)

This MCP server provides functionality to fetch web content in various formats, including HTML, JSON, plain text, and Markdown.

[Available on NPM](https://www.npmjs.com/package/mcp-fetch-server)

<a href="https://glama.ai/mcp/servers/nu09wf23ao">
  <img width="380" height="200" src="https://glama.ai/mcp/servers/nu09wf23ao/badge" alt="Fetch Server MCP server" />
</a>

## Components

### Tools

- **fetch_html**

  - Fetch a website and return the content as HTML
  - Input:
    - `url` (string, required): URL of the website to fetch
    - `headers` (object, optional): Custom headers to include in the request
    - `max_length` (number, optional): Maximum length to fetch (default 5000, can change via environment variable)
    - `start_index` (number, optional): Used together with max_length to retrieve contents piece by piece, 0 by default
  - Returns the raw HTML content of the webpage

- **fetch_json**

  - Fetch a JSON file from a URL
  - Input:
    - `url` (string, required): URL of the JSON to fetch
    - `headers` (object, optional): Custom headers to include in the request
    - `max_length` (number, optional): Maximum length to fetch (default 5000, can change via environment variable)
    - `start_index` (number, optional): Used together with max_length to retrieve contents piece by piece, 0 by default
  - Returns the parsed JSON content

- **fetch_txt**

  - Fetch a website and return the content as plain text (no HTML)
  - Input:
    - `url` (string, required): URL of the website to fetch
    - `headers` (object, optional): Custom headers to include in the request
    - `max_length` (number, optional): Maximum length to fetch (default 5000, can change via environment variable)
    - `start_index` (number, optional): Used together with max_length to retrieve contents piece by piece, 0 by default
  - Returns the text content of the webpage with HTML tags, scripts, and styles removed

- **fetch_markdown**

  - Fetch a website and return the content as Markdown
  - Input:
    - `url` (string, required): URL of the website to fetch
    - `headers` (object, optional): Custom headers to include in the request
    - `max_length` (number, optional): Maximum length to fetch (default 5000, can change via environment variable)
    - `start_index` (number, optional): Used together with max_length to retrieve contents piece by piece, 0 by default
  - Returns the content of the webpage converted to Markdown format

- **fetch_safe**

  - Fetch a website with maximum security restrictions (hardened mode)
  - Input:
    - `url` (string, required): URL of the website to fetch
    - `headers` (object, optional): Custom headers to include in the request
  - Security features:
    - Strict character limit (default 2000, configurable via `SAFE_FETCH_LIMIT`)
    - Returns plain text only (all HTML stripped)
    - Uses "high" risk profile by default
    - Best for fetching untrusted content
  - Returns plain text content with strict size limits

- **health_check**
  - Check the health status of the fetch server
  - Input: none
  - Returns server status, version, uptime, and enabled features

### Resources

This server does not provide any persistent resources. It's designed to fetch and transform web content on demand.

## Getting started

1. Clone the repository
2. Install dependencies: `npm install`
3. Build the server: `npm run build`

### Usage

To use the server, you can run it directly:

```bash
npm start
```

This will start the Fetch MCP Server running on stdio.

### Environment variables

- **DEFAULT_LIMIT** - sets the default size limit for the fetch (0 = no limit, default: `5000`)
- **SAFE_FETCH_LIMIT** - maximum content length for fetch_safe tool (default: `2000`, max: `10000`)
- **SSRF_DNS_CHECK** - enable DNS resolution checking for hostnames (default: `true`)
- **SSRF_DNS_FAIL_CLOSED** - block requests if DNS resolution fails (default: `true` for security)
- **REQUEST_TIMEOUT** - request timeout in milliseconds (default: `30000`)
- **MAX_REDIRECTS** - maximum number of redirects to follow (default: `5`)
- **SANITIZE_ERRORS** - hide sensitive URL parameters in error messages (default: `true`)
- **VALIDATE_CONTENT_TYPE** - validate response content-type matches expected type (default: `true`)
- **ALLOW_AUTH_HEADERS** - allow `Authorization` and `Cookie` headers in requests (default: `false`). When enabled, auth headers are still stripped on cross-origin redirects to prevent credential leakage.
- **INCLUDE_RESPONSE_METADATA** - include the `<security_context>` and `<metadata>` blocks in responses (default: `true`). Set to `false` to omit these blocks for constrained LLMs; content remains wrapped in delimiters but without security context.
- **MAX_REQUESTS_PER_MINUTE** - rate limit for requests (default: `60`, set to `0` to disable)
- **ENABLE_METRICS** - emit structured metrics to stderr (default: `false`)
- **LOG_LEVEL** - logging verbosity: error, warn, info, debug (default: `error`)
- **LOG_FORMAT** - log output format: json (for production) or pretty (for local development) (default: `json`)
- **ENABLE_CACHE** - cache responses in memory to avoid redundant fetches (default: `false`)
- **CACHE_TTL** - cache time-to-live in milliseconds (default: `300000` = 5 minutes)
- **ENABLE_HTML_SANDBOX** - process HTML in isolated worker thread for security (default: `true`)
- **ALLOW_UNSAFE_HTML** - explicitly disable the HTML sandbox (overrides ENABLE_HTML_SANDBOX) (default: `false`)
- **HTML_WORKER_TIMEOUT** - timeout for sandboxed HTML processing in milliseconds (default: `10000`)
- **HTML_WORKER_MAX_MB** - max V8 old-generation heap size for HTML worker in MB (default: `128`)
- **HTML_WORKER_YOUNG_MB** - V8 young-generation heap size in MB (default: `32`)
- **HTML_WORKER_CODE_MB** - V8 code range size in MB (default: `64`)

### Usage with Desktop App

To integrate this server with a desktop app, add the following to your app's server configuration:

```json
{
  "mcpServers": {
    "fetch": {
      "command": "npx",
      "args": ["mcp-fetch-server"],
      "env": {
        "DEFAULT_LIMIT": "50000",
        "SAFE_FETCH_LIMIT": "2000",
        "MAX_REQUESTS_PER_MINUTE": "60",
        "SSRF_DNS_CHECK": "true",
        "SSRF_DNS_FAIL_CLOSED": "true",
        "REQUEST_TIMEOUT": "30000",
        "MAX_REDIRECTS": "5",
        "SANITIZE_ERRORS": "true",
        "VALIDATE_CONTENT_TYPE": "true",
        "ALLOW_AUTH_HEADERS": "false",
        "ALLOW_UNSAFE_HTML": "false",
        "ENABLE_HTML_SANDBOX": "true",
        "HTML_WORKER_TIMEOUT": "10000",
        "HTML_WORKER_MAX_MB": "128",
        "HTML_WORKER_YOUNG_MB": "32",
        "HTML_WORKER_CODE_MB": "64"
      }
    }
  }
}
```

## Security

This server includes comprehensive security protections including SSRF prevention,
header injection protection, and content validation.

**Important:** When using with LLMs, fetched web content should be treated as
untrusted input. See [docs/SECURITY.md](docs/SECURITY.md) for detailed guidance
on prompt injection risks and mitigation strategies.

## Features

- Fetches web content using modern fetch API
- Supports custom headers for requests
- Provides content in multiple formats: HTML, JSON, plain text, and Markdown
- Uses JSDOM for HTML parsing and text extraction
- Uses TurndownService for HTML to Markdown conversion

## Development

- Run `npm run dev` to start the TypeScript compiler in watch mode
- Use `npm test` to run the test suite

## License

This project is licensed under the MIT License.
