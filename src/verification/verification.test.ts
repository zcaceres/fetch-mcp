import { describe, expect, it } from 'bun:test';
import type { Cassette, VendorToolSchemaInput } from './nouns.ts';
import {
  checkFormFactorParity,
  classifyCellStatus,
  evaluateOutputChecks,
  formatReportSummary,
  redactCassette,
  summarizeReport,
  validateVendorSchemas,
} from './queries.ts';
import { parseCassette, updateCassette } from './verbs.ts';

const makeValidTool = (overrides: Partial<VendorToolSchemaInput> = {}): VendorToolSchemaInput => ({
  name: 'fetch_html',
  description: 'Fetch a website and return unmodified HTML',
  inputSchema: {
    type: 'object',
    properties: {
      url: { type: 'string', description: 'URL to fetch' },
      headers: {
        type: 'object',
        description: 'Optional request headers',
        additionalProperties: { type: 'string' },
      },
      max_length: { type: 'number', description: 'Max characters' },
      start_index: { type: 'number', description: 'Start index' },
    },
    required: ['url'],
    additionalProperties: false,
  },
  annotations: {
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: true,
  },
  ...overrides,
});

describe('verification domain — Slice 01 (LV-1, D33, I6)', () => {
  it('passes valid Anthropic/Gemini/OpenAI tool definitions with zero issues', () => {
    expect(validateVendorSchemas([makeValidTool()])).toEqual([]);
  });

  it('flags missing root additionalProperties: false, untyped object properties, missing annotations, composition keywords, and forbidden proxy property', () => {
    const broken: VendorToolSchemaInput = {
      name: 'fetchHtml',
      description: '',
      inputSchema: {
        type: 'object',
        properties: {
          url: { type: 'string', format: 'uri' },
          headers: { type: 'object' },
          proxy: { type: 'string' },
        },
        anyOf: [{ required: ['url'] }],
      },
    };

    const issues = validateVendorSchemas([broken]);
    const messages = issues.map((i) => `${i.vendor}:${i.message}`);
    expect(messages).toContain('anthropic:tool name must be snake_case');
    expect(messages).toContain('openai:tool description must be non-empty');
    expect(messages).toContain('openai:inputSchema must declare additionalProperties: false for strict mode');
    expect(messages).toContain('openai:inputSchema must not use oneOf/anyOf/allOf composition keywords');
    expect(messages).toContain('anthropic:inputSchema must never expose a caller-controlled proxy property (I6)');
    expect(messages).toContain('openai:property "url" must omit non-portable JSON Schema format "uri"');
    expect(messages).toContain(
      'gemini:object property "headers" must declare typed additionalProperties (e.g. { type: "string" })',
    );
    expect(messages).toContain(
      'anthropic:tool must declare MCP 2025-11-25 annotations { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true }',
    );
  });
});

describe('verification domain — Slice 02 (LV-2, LV-6, D31, D34, D35, I7)', () => {
  const sampleCassette: Cassette = {
    version: 1,
    targetId: 'example-article',
    recordedAt: '2026-11-27T00:00:00Z',
    exchanges: [
      {
        url: 'https://user:s3cr3t@example.com/article',
        method: 'GET',
        status: 200,
        headers: {
          'Content-Type': 'text/html; charset=utf-8',
          Authorization: 'Bearer secret-token',
          Cookie: 'session=abc',
          'Set-Cookie': 'sid=xyz; HttpOnly',
          'Proxy-Authorization': 'Basic dXNlcjpwYXNz',
          Location: 'https://alice:pw@example.com/next',
        },
        bodyBase64: Buffer.from('<h1>Hello</h1>').toString('base64'),
      },
    ],
  };

  it('parses valid cassettes and rejects malformed cassette payloads', () => {
    expect(parseCassette(sampleCassette).ok).toBe(true);
    expect(parseCassette({ version: 2, targetId: '', exchanges: [] }).ok).toBe(false);
  });

  it('redacts sensitive headers and URL credentials while preserving relative Location paths containing @ (D31, I7)', () => {
    const clean = redactCassette(sampleCassette);
    expect(clean.exchanges[0]?.url).toBe('https://example.com/article');
    expect(clean.exchanges[0]?.headers).toEqual({
      'content-type': 'text/html; charset=utf-8',
      location: 'https://example.com/next',
    });

    const withRelativeLoc = redactCassette({
      ...sampleCassette,
      exchanges: [
        {
          url: 'https://example.com/pkg',
          method: 'GET',
          status: 302,
          headers: { Location: '/relative/path?email=alice@example.com' },
          bodyBase64: '',
        },
        {
          url: 'https://example.com/proto-rel',
          method: 'GET',
          status: 302,
          headers: { Location: '//bob:secret@cdn.example.com/path' },
          bodyBase64: '',
        },
      ],
    });
    expect(withRelativeLoc.exchanges[0]?.headers.location).toBe('/relative/path?email=alice@example.com');
    expect(withRelativeLoc.exchanges[1]?.headers.location).toBe('//cdn.example.com/path');
  });

  it('refuses to overwrite an existing valid cassette on live failure and redacts on success (D34, D35, I7)', () => {
    const refused = updateCassette(sampleCassette, sampleCassette, false);
    expect(refused).toEqual({
      ok: false,
      error: 'Refusing to overwrite existing cassette "example-article" because live verification failed',
    });

    const accepted = updateCassette(sampleCassette, sampleCassette, true);
    expect(accepted.ok).toBe(true);
    if (accepted.ok) {
      expect(accepted.value.exchanges[0]?.url).toBe('https://example.com/article');
      expect(accepted.value.exchanges[0]?.headers).not.toHaveProperty('set-cookie');
    }
  });

  it('evaluates resilient Output Checks across success and refusal outcomes (D34, D35)', () => {
    expect(
      evaluateOutputChecks({ ok: true, output: '{"ok":true,"title":"Hello"}' }, [
        { kind: 'expect_ok' },
        { kind: 'valid_json' },
        { kind: 'min_length', value: 10 },
        { kind: 'contains', text: 'Hello' },
        { kind: 'not_contains', text: '<script>' },
        { kind: 'starts_with', prefix: '{' },
      ]),
    ).toEqual([]);

    expect(
      evaluateOutputChecks({ ok: false, output: 'HTTP error 404 fetching https://example.com/missing' }, [
        { kind: 'expect_error', contains: 'HTTP error 404' },
      ]),
    ).toEqual([]);

    const failures = evaluateOutputChecks({ ok: true, output: 'not-json' }, [
      { kind: 'valid_json' },
      { kind: 'min_length', value: 50 },
      { kind: 'contains', text: 'missing' },
    ]);
    expect(failures).toHaveLength(3);
  });

  it('classifies liveOptional failures as skipped_env only when the fetch itself fails in live mode (D34)', () => {
    expect(classifyCellStatus('live', true, true, [])).toBe('pass');
    expect(classifyCellStatus('live', true, false, ['expected success, got error: HTTP 429'])).toBe('skipped_env');
    expect(classifyCellStatus('live', true, true, ['expected output to contain "elephants"'])).toBe('fail');
    expect(classifyCellStatus('live', false, false, ['expected success'])).toBe('fail');
    expect(classifyCellStatus('replay', true, false, ['expected success'])).toBe('fail');
  });

  it('summarizes pass, fail, and skipped_env counts into a Verification Report (D34, D35)', () => {
    const report = summarizeReport(
      'live',
      [
        { targetId: 'a', category: 'html-article', formFactor: 'cli', status: 'pass', durationMs: 12 },
        {
          targetId: 'b',
          category: 'youtube-transcript',
          formFactor: 'mcp-stdio',
          status: 'skipped_env',
          durationMs: 1,
          details: 'yt-dlp unavailable',
        },
        {
          targetId: 'c',
          category: 'refusal',
          formFactor: 'mcp-http',
          status: 'fail',
          durationMs: 20,
          details: 'expected error',
        },
      ],
      '2026-11-27T12:00:00Z',
    );
    expect(report.totals).toEqual({ pass: 1, fail: 1, skippedEnv: 1 });
    expect(report.ok).toBe(false);
    expect(formatReportSummary(report)).toContain('[FAIL] c (mcp-http, 20ms)');
    expect(formatReportSummary(report)).toContain('[SKIP] b (mcp-stdio, 1ms)');
  });

  it('checks exact 3-way parity across CLI, MCP stdio, and MCP Streamable HTTP including equal-length diffs (LV-5)', () => {
    const same = { ok: true, output: 'hello' };
    expect(checkFormFactorParity({ cli: same, 'mcp-stdio': same, 'mcp-http': same })).toEqual([]);

    const mismatch = checkFormFactorParity({
      cli: { ok: true, output: 'hello' },
      'mcp-stdio': { ok: false, output: 'err' },
      'mcp-http': { ok: true, output: 'hello!' },
    });
    expect(mismatch).toEqual([
      'parity mismatch (mcp-stdio vs cli): ok=false !== true',
      'parity mismatch (mcp-http vs cli): output length 6 !== 5',
    ]);

    const sameLenDiff = checkFormFactorParity({
      cli: { ok: true, output: 'hello' },
      'mcp-stdio': { ok: true, output: 'world' },
      'mcp-http': { ok: true, output: 'hello' },
    });
    expect(sameLenDiff).toEqual(['parity mismatch (mcp-stdio vs cli): output content differs (same length 5)']);
  });
});
