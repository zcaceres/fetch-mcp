import type { LiveSample } from './nouns.ts';

/**
 * Curated real-internet Live Samples spanning all four categories (D34, D35, LV-4):
 * 1. HTML article / Readability & Markdown/docs
 * 2. Public JSON & compressed/redirected/non-ASCII UTF-8
 * 3. Real refusal cases (HTTP 404, binary image/png, SSRF private IP)
 * 4. Public YouTube video transcript
 */
export const LIVE_SAMPLES: readonly LiveSample[] = [
  {
    id: 'iana-readable',
    category: 'html-article',
    description: 'HTTP->HTTPS redirect + Brotli HTML article extracted via Readability into Markdown',
    tool: 'fetch_readable',
    cliSubcommand: 'readable',
    url: 'http://iana.org/help/example-domains',
    maxLength: 2000,
    cassetteFile: 'iana-readable.json',
    checks: [
      { kind: 'expect_ok' },
      { kind: 'starts_with', prefix: '# ' },
      { kind: 'contains', text: 'Example' },
      { kind: 'min_length', value: 100 },
    ],
  },
  {
    id: 'iana-markdown',
    category: 'markdown-docs',
    description: 'Rich documentation HTML page converted cleanly to Markdown with headings and links',
    tool: 'fetch_markdown',
    cliSubcommand: 'markdown',
    url: 'https://www.iana.org/domains/reserved',
    maxLength: 2000,
    cassetteFile: 'iana-markdown.json',
    checks: [
      { kind: 'expect_ok' },
      { kind: 'contains', text: 'IANA-managed Reserved Domains' },
      { kind: 'not_contains', text: '<script' },
      { kind: 'min_length', value: 100 },
    ],
  },
  {
    id: 'npm-registry-json',
    category: 'json-and-encoding',
    description: 'Gzipped public JSON API endpoint re-serialized compactly',
    tool: 'fetch_json',
    cliSubcommand: 'json',
    url: 'https://registry.npmjs.org/mcp-fetch-server/latest',
    maxLength: 0,
    cassetteFile: 'npm-registry-json.json',
    checks: [{ kind: 'expect_ok' }, { kind: 'valid_json' }, { kind: 'contains', text: '"mcp-fetch-server"' }],
  },
  {
    id: 'httpbin-utf8-text',
    category: 'json-and-encoding',
    description: 'Multi-script non-ASCII UTF-8 page decoded cleanly to plain text',
    tool: 'fetch_text',
    cliSubcommand: 'text',
    url: 'https://httpbin.org/encoding/utf8',
    maxLength: 500,
    cassetteFile: 'httpbin-utf8-text.json',
    checks: [
      { kind: 'expect_ok' },
      { kind: 'contains', text: 'UTF-8' },
      { kind: 'contains', text: 'Markus Kuhn' },
      { kind: 'min_length', value: 100 },
    ],
  },
  {
    id: 'refusal-404',
    category: 'refusal',
    description: 'Non-2xx HTTP 404 response fails explicitly across all Form Factors',
    tool: 'fetch_html',
    cliSubcommand: 'html',
    url: 'https://www.iana.org/fetch-mcp-missing-404',
    cassetteFile: 'refusal-404.json',
    checks: [{ kind: 'expect_error', contains: 'HTTP error 404' }],
  },
  {
    id: 'refusal-binary-png',
    category: 'refusal',
    description: 'Redirected binary image/png Content-Type is rejected explicitly',
    tool: 'fetch_html',
    cliSubcommand: 'html',
    url: 'https://www.w3.org/Icons/WWW/w3c_home.png',
    cassetteFile: 'refusal-binary-png.json',
    checks: [{ kind: 'expect_error', contains: 'Unsupported binary Content-Type' }],
  },
  {
    id: 'refusal-ssrf-loopback',
    category: 'refusal',
    description: 'Private 127.0.0.1 Target URL stays blocked locally even when replaying via local proxy (I1)',
    tool: 'fetch_html',
    cliSubcommand: 'html',
    url: 'http://127.0.0.1/secret',
    checks: [{ kind: 'expect_error', contains: 'Blocked Target URL: private address "127.0.0.1"' }],
  },
  {
    id: 'youtube-me-at-the-zoo',
    category: 'youtube-transcript',
    description: 'Public YouTube video transcript extraction (jNQXAC9IVRw)',
    tool: 'fetch_transcript',
    cliSubcommand: 'transcript',
    url: 'https://www.youtube.com/watch?v=jNQXAC9IVRw',
    lang: 'en',
    maxLength: 500,
    cassetteFile: 'youtube-me-at-the-zoo.json',
    liveOptional: true,
    checks: [
      { kind: 'expect_ok' },
      { kind: 'starts_with', prefix: '[Transcript language: en' },
      { kind: 'contains', text: 'elephants' },
    ],
  },
];
