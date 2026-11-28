import { describe, expect, it } from 'bun:test';
import { spawn } from 'node:child_process';
import path from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { ErrorCode, McpError } from '@modelcontextprotocol/sdk/types.js';
import pkg from '../package.json' with { type: 'json' };
import { createDnsMock } from './integrations/dns/mock.ts';
import { createOriginMock } from './integrations/origin/mock.ts';
import { createYtDlpMock } from './integrations/ytdlp/mock.ts';
import { dispatchToolCall, listTools } from './mcp/server.ts';

type JsonRpcResponse = {
  readonly id?: number;
  readonly result?: {
    readonly protocolVersion?: string;
    readonly capabilities?: Record<string, unknown>;
    readonly tools?: readonly {
      readonly name: string;
      readonly inputSchema: { readonly properties?: Record<string, unknown> };
    }[];
    readonly content?: readonly { readonly type: string; readonly text: string }[];
    readonly isError?: boolean;
  };
  readonly error?: {
    readonly code: number;
    readonly message: string;
  };
};

const runMcpSession = (
  messages: readonly object[],
  envOverrides: Readonly<Record<string, string | undefined>> = {},
): Promise<readonly JsonRpcResponse[]> =>
  new Promise((resolve, reject) => {
    const serverPath = path.resolve(import.meta.dir, 'index.ts');
    const proc = spawn(process.execPath, ['run', serverPath], {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: { ...process.env, ...envOverrides },
    });

    const responses: JsonRpcResponse[] = [];
    const expectedResponses = messages.filter((m) => 'id' in m).length;
    let buffer = '';
    let stderr = '';

    const timeout = setTimeout(() => {
      proc.kill();
      reject(new Error(`Timed out waiting for MCP responses. stderr: ${stderr}`));
    }, 5000);

    proc.stderr.on('data', (chunk: Buffer) => {
      stderr += chunk.toString('utf-8');
    });

    proc.stdout.on('data', (chunk: Buffer) => {
      buffer += chunk.toString('utf-8');
      const lines = buffer.split('\n');
      buffer = lines.pop() ?? '';
      for (const line of lines) {
        if (!line.trim()) continue;
        try {
          responses.push(JSON.parse(line));
          if (responses.length >= expectedResponses) {
            clearTimeout(timeout);
            proc.kill();
            resolve(responses);
          }
        } catch (error) {
          clearTimeout(timeout);
          proc.kill();
          reject(new Error(`Failed to parse JSON-RPC line: ${line} (${String(error)})`));
        }
      }
    });

    proc.on('error', (error) => {
      clearTimeout(timeout);
      reject(error);
    });

    for (const msg of messages) {
      proc.stdin.write(`${JSON.stringify(msg)}\n`);
    }
    proc.stdin.end();
  });

const runMcpStartupExpectExit = (
  envOverrides: Readonly<Record<string, string | undefined>>,
): Promise<{ readonly code: number | null; readonly stderr: string }> =>
  new Promise((resolve, reject) => {
    const serverPath = path.resolve(import.meta.dir, 'index.ts');
    const proc = spawn(process.execPath, ['run', serverPath], {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: { ...process.env, ...envOverrides },
    });
    let stderr = '';
    proc.stderr.on('data', (chunk: Buffer) => {
      stderr += chunk.toString('utf-8');
    });
    proc.on('error', reject);
    proc.on('close', (code) => resolve({ code, stderr }));
    proc.stdin.end();
  });

describe('MCP stdio server conformance (MI-1, MI-2, MI-3, MI-4, MI-6)', () => {
  it('fails fast at startup on invalid DEFAULT_LIMIT or MAX_RESPONSE_BYTES (MI-1, D25, D29)', async () => {
    const badLimit = await runMcpStartupExpectExit({ DEFAULT_LIMIT: 'bad' });
    expect(badLimit.code).toBe(1);
    expect(badLimit.stderr).toBe('Invalid DEFAULT_LIMIT "bad": must be a non-negative integer\n');

    const badMax = await runMcpStartupExpectExit({ MAX_RESPONSE_BYTES: '0' });
    expect(badMax.code).toBe(1);
    expect(badMax.stderr).toBe('Invalid MAX_RESPONSE_BYTES "0": must be a positive integer\n');
  });

  it('advertises only tools capability, lists the 6 D12 tools without proxy, and rejects invalid cursor & unknown tools with -32602 (MI-2, MI-3, MI-4, MI-6)', async () => {
    const responses = await runMcpSession([
      {
        jsonrpc: '2.0',
        id: 1,
        method: 'initialize',
        params: {
          protocolVersion: '2025-11-25',
          capabilities: {},
          clientInfo: { name: 'test-client', version: '1.0.0' },
        },
      },
      { jsonrpc: '2.0', method: 'notifications/initialized' },
      { jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} },
      { jsonrpc: '2.0', id: 3, method: 'tools/list', params: { cursor: 'unknown-cursor' } },
      {
        jsonrpc: '2.0',
        id: 4,
        method: 'tools/call',
        params: { name: 'fetch_txt', arguments: { url: 'https://a.com' } },
      },
      {
        jsonrpc: '2.0',
        id: 5,
        method: 'tools/call',
        params: { name: 'fetch_html', arguments: { url: 'http://127.0.0.1/secret' } },
      },
    ]);

    const initResp = responses.find((r) => r.id === 1);
    expect(initResp?.error).toBeUndefined();
    expect(initResp?.result?.protocolVersion).toBe('2025-11-25');
    expect(initResp?.result?.capabilities?.tools).toBeDefined();
    expect(initResp?.result?.capabilities?.resources).toBeUndefined();
    expect(initResp?.result?.capabilities?.prompts).toBeUndefined();

    const listResp = responses.find((r) => r.id === 2);
    expect(listResp?.error).toBeUndefined();
    const tools = listResp?.result?.tools ?? [];
    expect(tools.map((t) => t.name)).toEqual([
      'fetch_html',
      'fetch_markdown',
      'fetch_readable',
      'fetch_text',
      'fetch_json',
      'fetch_transcript',
    ]);
    for (const tool of tools) {
      expect(tool.inputSchema.properties).not.toHaveProperty('proxy');
    }

    const badCursor = responses.find((r) => r.id === 3);
    expect(badCursor?.error?.code).toBe(-32602);

    const unknownTool = responses.find((r) => r.id === 4);
    expect(unknownTool?.error?.code).toBe(-32602);

    const ssrfResp = responses.find((r) => r.id === 5);
    expect(ssrfResp?.error).toBeUndefined();
    expect(ssrfResp?.result?.isError).toBe(true);
    expect(ssrfResp?.result?.content?.[0]?.text).toBe('Blocked Target URL: private address "127.0.0.1"');
  });

  it('interoperates cleanly with the stock @modelcontextprotocol/sdk Client over StdioClientTransport (MI-2, MI-3, MI-4, MI-6)', async () => {
    const serverPath = path.resolve(import.meta.dir, 'index.ts');
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: ['run', serverPath],
      stderr: 'pipe',
    });
    const client = new Client({ name: 'sdk-interop-test', version: '1.0.0' });

    await client.connect(transport);
    try {
      expect(client.getServerVersion()).toEqual({ name: 'zcaceres/fetch', version: pkg.version });
      const caps = client.getServerCapabilities();
      expect(caps?.tools).toBeDefined();
      expect(caps?.resources).toBeUndefined();
      expect(caps?.prompts).toBeUndefined();

      const listed = await client.listTools();
      expect(listed.tools.map((t) => t.name)).toEqual([
        'fetch_html',
        'fetch_markdown',
        'fetch_readable',
        'fetch_text',
        'fetch_json',
        'fetch_transcript',
      ]);
      for (const tool of listed.tools) {
        expect(tool.inputSchema.properties).not.toHaveProperty('proxy');
        expect(tool.inputSchema.additionalProperties).toBe(false);
        expect(tool.annotations).toEqual({
          readOnlyHint: true,
          destructiveHint: false,
          idempotentHint: true,
          openWorldHint: true,
        });
      }

      let cursorError: unknown;
      try {
        await client.listTools({ cursor: 'invalid-cursor' });
      } catch (error) {
        cursorError = error;
      }
      expect(cursorError).toBeInstanceOf(McpError);
      if (cursorError instanceof McpError) {
        expect(cursorError.code).toBe(ErrorCode.InvalidParams);
      }

      let unknownToolError: unknown;
      try {
        await client.callTool({ name: 'fetch_txt', arguments: { url: 'https://example.com' } });
      } catch (error) {
        unknownToolError = error;
      }
      expect(unknownToolError).toBeInstanceOf(McpError);
      if (unknownToolError instanceof McpError) {
        expect(unknownToolError.code).toBe(ErrorCode.InvalidParams);
      }

      const ssrfRes = await client.callTool({
        name: 'fetch_html',
        arguments: { url: 'http://127.0.0.1/secret' },
      });
      expect(ssrfRes.isError).toBe(true);
      expect(ssrfRes.content).toEqual([{ type: 'text', text: 'Blocked Target URL: private address "127.0.0.1"' }]);

      const badHeaderRes = await client.callTool({
        name: 'fetch_html',
        arguments: { url: 'http://93.184.216.34/', headers: { 'Bad Header': 'v' } },
      });
      expect(badHeaderRes.isError).toBe(true);
    } finally {
      await client.close();
    }
  });
});

describe('MCP dispatchToolCall & listTools (MI-3, MI-4, MI-5, MI-6)', () => {
  it('rejects any defined cursor in listTools with -32602 (D27)', () => {
    expect(listTools(5000).ok).toBe(true);
    expect(listTools(5000, 'abc')).toEqual({
      ok: false,
      error: { code: -32602, message: 'Invalid pagination cursor' },
    });
    expect(listTools(5000, '')).toEqual({
      ok: false,
      error: { code: -32602, message: 'Invalid pagination cursor' },
    });
  });

  it('dispatches all six D12 tools over shared core, rejects smuggled proxy, and honors Operator env proxy (MI-5, D28, I6)', async () => {
    const origin = createOriginMock();
    const dns = createDnsMock();
    const ytDlp = createYtDlpMock();
    dns.fail('remote.invalid', 'ENOTFOUND');
    dns.fail('www.youtube.com', 'ENOTFOUND');
    origin.serve(
      'https://remote.invalid/page',
      200,
      '<html><head><title>Article Title</title></head><body><article><h1>Article Title</h1><p>This is a full article paragraph with enough text for Mozilla Readability to parse cleanly and reliably across runs.</p><p>Second paragraph of meaningful article body content so Readability extracts the main body.</p></article></body></html>',
    );
    origin.serve('https://remote.invalid/data', 200, '{"hello": "world"}');
    ytDlp.setAvailable(true);
    ytDlp.serve(
      'https://www.youtube.com/watch?v=m1',
      'en',
      '<transcript><text start="0" dur="1">Hello MCP</text></transcript>',
    );

    const deps = {
      fetchPorts: { httpGet: origin.get, dnsLookup: dns.lookup },
      ytDlp,
      env: { HTTPS_PROXY: 'socks5://127.0.0.1:1080' },
      limits: { defaultLimit: 5000, maxResponseBytes: 10 * 1024 * 1024 },
    };

    const smuggledRes = await dispatchToolCall(
      'fetch_html',
      { url: 'https://remote.invalid/page', proxy: 'http://attacker:80' },
      deps,
    );
    expect(smuggledRes).toEqual({
      ok: true,
      value: { content: [{ type: 'text', text: 'Invalid arguments: Unrecognized key: "proxy"' }], isError: true },
    });
    expect(origin.lastProxy('https://remote.invalid/page')).toBeUndefined();

    const htmlRes = await dispatchToolCall('fetch_html', { url: 'https://remote.invalid/page' }, deps);
    expect(htmlRes.ok && !htmlRes.value.isError).toBe(true);
    expect(origin.lastProxy('https://remote.invalid/page')).toBe('socks5://127.0.0.1:1080');

    const mdRes = await dispatchToolCall('fetch_markdown', { url: 'https://remote.invalid/page' }, deps);
    expect(mdRes.ok && !mdRes.value.isError && mdRes.value.content[0].text.includes('Article Title')).toBe(true);

    const readRes = await dispatchToolCall('fetch_readable', { url: 'https://remote.invalid/page' }, deps);
    expect(readRes.ok && !readRes.value.isError && readRes.value.content[0].text.startsWith('# Article Title')).toBe(
      true,
    );

    const textRes = await dispatchToolCall(
      'fetch_text',
      { url: 'https://remote.invalid/page', headers: { 'X-Mcp-Test': 'forwarded' }, start_index: 8, max_length: 5 },
      deps,
    );
    expect(textRes).toEqual({
      ok: true,
      value: { content: [{ type: 'text', text: 'Title' }], isError: false },
    });
    expect(origin.lastHeaders('https://remote.invalid/page')).toMatchObject({ 'X-Mcp-Test': 'forwarded' });

    const jsonRes = await dispatchToolCall('fetch_json', { url: 'https://remote.invalid/data' }, deps);
    expect(jsonRes).toEqual({
      ok: true,
      value: { content: [{ type: 'text', text: '{"hello":"world"}' }], isError: false },
    });

    const smuggledTr = await dispatchToolCall(
      'fetch_transcript',
      { url: 'https://www.youtube.com/watch?v=m1', lang: 'en', proxy: 'http://evil:80' },
      deps,
    );
    expect(smuggledTr).toEqual({
      ok: true,
      value: { content: [{ type: 'text', text: 'Invalid arguments: Unrecognized key: "proxy"' }], isError: true },
    });

    const trRes = await dispatchToolCall(
      'fetch_transcript',
      { url: 'https://www.youtube.com/watch?v=m1', lang: 'en' },
      deps,
    );
    expect(trRes).toEqual({
      ok: true,
      value: {
        content: [{ type: 'text', text: '[Transcript language: en — en]\n\n[0:00] Hello MCP' }],
        isError: false,
      },
    });
    expect(ytDlp.lastArgs()).toContain('socks5://127.0.0.1:1080');
  });

  it('returns -32602 for unknown tools and isError: true for invalid arguments (MI-6, D28)', async () => {
    const deps = {
      fetchPorts: { httpGet: createOriginMock().get, dnsLookup: createDnsMock().lookup },
      ytDlp: createYtDlpMock(),
      env: {},
      limits: { defaultLimit: 5000, maxResponseBytes: 10 * 1024 * 1024 },
    };

    expect(await dispatchToolCall('fetch_youtube_transcript', { url: 'https://youtube.com/watch?v=1' }, deps)).toEqual({
      ok: false,
      error: { code: -32602, message: 'Unknown tool: fetch_youtube_transcript' },
    });

    const badArg = await dispatchToolCall('fetch_html', { url: 123 }, deps);
    expect(badArg.ok).toBe(true);
    if (badArg.ok) {
      expect(badArg.value.isError).toBe(true);
      expect(badArg.value.content[0].text).toContain('Invalid arguments:');
    }

    const origin500 = createOriginMock();
    const dnsOk = createDnsMock();
    dnsOk.set('example.com', ['93.184.216.34']);
    origin500.serve('https://example.com/boom', 500, 'fail');
    const failOriginRes = await dispatchToolCall(
      'fetch_html',
      { url: 'https://example.com/boom' },
      { ...deps, fetchPorts: { httpGet: origin500.get, dnsLookup: dnsOk.lookup } },
    );
    expect(failOriginRes).toEqual({
      ok: true,
      value: { content: [{ type: 'text', text: 'HTTP error 500 fetching https://example.com/boom' }], isError: true },
    });

    const failTrRes = await dispatchToolCall('fetch_transcript', { url: 'https://example.com/not-youtube' }, deps);
    expect(failTrRes).toEqual({
      ok: true,
      value: {
        content: [
          { type: 'text', text: 'Blocked Target URL: host "example.com" is not an allowlisted YouTube domain' },
        ],
        isError: true,
      },
    });
  });
});
