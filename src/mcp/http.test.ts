import { describe, expect, it } from 'bun:test';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { ErrorCode, McpError } from '@modelcontextprotocol/sdk/types.js';
import { createDnsMock } from '../integrations/dns/mock.ts';
import { createOriginMock } from '../integrations/origin/mock.ts';
import { createYtDlpMock } from '../integrations/ytdlp/mock.ts';
import {
  handleStreamableHttpRequest,
  parseServerArgs,
  startStreamableHttpServer,
  validateHttpOriginAndHost,
} from './http.ts';

describe('Streamable HTTP guards & handler — Slice 01 (SH-1..SH-5, D32)', () => {
  describe('parseServerArgs', () => {
    it('defaults to stdio and parses --http with host/port defaults or overrides', () => {
      expect(parseServerArgs([])).toEqual({ ok: true, value: { kind: 'stdio' } });
      expect(parseServerArgs(['--http'])).toEqual({
        ok: true,
        value: { kind: 'http', host: '127.0.0.1', port: 3000 },
      });
      expect(parseServerArgs(['--http', '--host', '::1', '--port', '8080'])).toEqual({
        ok: true,
        value: { kind: 'http', host: '::1', port: 8080 },
      });
      expect(parseServerArgs(['--http', '--host', '[::1]', '--port', '8080'])).toEqual({
        ok: true,
        value: { kind: 'http', host: '::1', port: 8080 },
      });
    });

    it('rejects --host/--port without --http, empty bracket host, invalid ports, and unknown flags', () => {
      expect(parseServerArgs(['--port', '8080'])).toEqual({ ok: false, error: '--port requires --http' });
      expect(parseServerArgs(['--host', '127.0.0.1'])).toEqual({ ok: false, error: '--host requires --http' });
      expect(parseServerArgs(['--http', '--host', '[]'])).toEqual({ ok: false, error: '--host requires a value' });
      expect(parseServerArgs(['--http', '--port', '0'])).toEqual({
        ok: false,
        error: 'Invalid --port "0": must be an integer between 1 and 65535',
      });
      expect(parseServerArgs(['--http', '--port', '70000'])).toEqual({
        ok: false,
        error: 'Invalid --port "70000": must be an integer between 1 and 65535',
      });
      expect(parseServerArgs(['--unknown'])).toEqual({ ok: false, error: 'Unknown flag: --unknown' });
    });
  });

  describe('validateHttpOriginAndHost (SH-2, D32)', () => {
    it('accepts matching localhost Host and optional localhost Origin', () => {
      expect(validateHttpOriginAndHost({ host: '127.0.0.1:3000' }, '127.0.0.1', 3000)).toEqual({
        ok: true,
        value: undefined,
      });
      expect(
        validateHttpOriginAndHost({ Host: 'localhost:3000', Origin: 'http://localhost:5173' }, '127.0.0.1', 3000),
      ).toEqual({ ok: true, value: undefined });
      expect(validateHttpOriginAndHost({ host: '[::1]:3000' }, '127.0.0.1', 3000)).toEqual({
        ok: true,
        value: undefined,
      });
      expect(validateHttpOriginAndHost({ host: '[2001:db8::1]:3000' }, '2001:0db8::1', 3000)).toEqual({
        ok: true,
        value: undefined,
      });
    });

    it('rejects untrusted Host, mismatched port, userinfo/path/query smuggling, whitespace Origin, or cross-origin Origin with HTTP 403', () => {
      expect(validateHttpOriginAndHost({ host: 'attacker.example' }, '127.0.0.1', 3000)).toEqual({
        ok: false,
        error: { status: 403, message: 'Forbidden Host header: "attacker.example"' },
      });
      expect(validateHttpOriginAndHost({ host: '127.0.0.1:9999' }, '127.0.0.1', 3000)).toEqual({
        ok: false,
        error: { status: 403, message: 'Forbidden Host header: "127.0.0.1:9999"' },
      });
      expect(validateHttpOriginAndHost({ host: 'evil@127.0.0.1:3000' }, '127.0.0.1', 3000)).toEqual({
        ok: false,
        error: { status: 403, message: 'Forbidden Host header: "evil@127.0.0.1:3000"' },
      });
      expect(validateHttpOriginAndHost({ host: '127.0.0.1:3000/evil' }, '127.0.0.1', 3000)).toEqual({
        ok: false,
        error: { status: 403, message: 'Forbidden Host header: "127.0.0.1:3000/evil"' },
      });
      expect(
        validateHttpOriginAndHost({ host: '127.0.0.1:3000', origin: 'https://evil.example' }, '127.0.0.1', 3000),
      ).toEqual({
        ok: false,
        error: { status: 403, message: 'Forbidden Origin header: "https://evil.example"' },
      });
      expect(
        validateHttpOriginAndHost({ host: '127.0.0.1:3000', origin: 'http://127.0.0.1:3000/foo' }, '127.0.0.1', 3000),
      ).toEqual({
        ok: false,
        error: { status: 403, message: 'Forbidden Origin header: "http://127.0.0.1:3000/foo"' },
      });
      expect(validateHttpOriginAndHost({ host: '127.0.0.1:3000', origin: '   ' }, '127.0.0.1', 3000)).toEqual({
        ok: false,
        error: { status: 403, message: 'Forbidden Origin header: ""' },
      });
    });
  });

  describe('handleStreamableHttpRequest (SH-3, SH-4, SH-5)', () => {
    const makeDeps = () => {
      const origin = createOriginMock();
      const dns = createDnsMock();
      const ytDlp = createYtDlpMock();
      return {
        origin,
        dns,
        ytDlp,
        deps: {
          version: '2.0.0',
          boundHost: '127.0.0.1',
          boundPort: 3000,
          fetchPorts: { httpGet: origin.get, dnsLookup: dns.lookup },
          ytDlp,
          env: {},
          limits: { defaultLimit: 5000, maxResponseBytes: 10 * 1024 * 1024 },
        },
      };
    };

    it('returns 404 for /sse and unknown paths, 405 for non-POST, 400 for bad JSON', async () => {
      const { deps } = makeDeps();
      expect(
        await handleStreamableHttpRequest({ method: 'GET', path: '/sse', headers: { host: '127.0.0.1:3000' } }, deps),
      ).toEqual({ status: 404, contentType: 'text/plain', body: 'Not Found' });

      expect(
        await handleStreamableHttpRequest({ method: 'PUT', path: '/mcp', headers: { host: '127.0.0.1:3000' } }, deps),
      ).toEqual({ status: 405, contentType: 'text/plain', body: 'Method Not Allowed' });

      expect(
        await handleStreamableHttpRequest(
          { method: 'POST', path: '/mcp', headers: { host: '127.0.0.1:3000' }, body: '{bad' },
          deps,
        ),
      ).toEqual({ status: 400, contentType: 'text/plain', body: 'Invalid JSON body' });
    });

    it('handles initialize, tools/list, and tools/call statelessly over shared core', async () => {
      const { origin, deps } = makeDeps();
      origin.serve('https://example.com/p', 200, '<p>Streamable OK</p>');

      const listRes = await handleStreamableHttpRequest(
        {
          method: 'POST',
          path: '/mcp',
          headers: { host: '127.0.0.1:3000' },
          body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }),
        },
        deps,
      );
      expect(listRes.status).toBe(200);
      const listJson = JSON.parse(listRes.body);
      expect(listJson.result.tools).toHaveLength(6);

      const callRes = await handleStreamableHttpRequest(
        {
          method: 'POST',
          path: '/mcp',
          headers: { host: '127.0.0.1:3000' },
          body: JSON.stringify({
            jsonrpc: '2.0',
            id: 2,
            method: 'tools/call',
            params: { name: 'fetch_text', arguments: { url: 'https://example.com/p' } },
          }),
        },
        deps,
      );
      expect(callRes.status).toBe(200);
      expect(JSON.parse(callRes.body).result).toEqual({
        content: [{ type: 'text', text: 'Streamable OK' }],
        isError: false,
      });

      const smuggledRes = await handleStreamableHttpRequest(
        {
          method: 'POST',
          path: '/mcp',
          headers: { host: '127.0.0.1:3000' },
          body: JSON.stringify({
            jsonrpc: '2.0',
            id: 3,
            method: 'tools/call',
            params: { name: 'fetch_text', arguments: { url: 'https://example.com/p', proxy: 'http://evil:80' } },
          }),
        },
        deps,
      );
      expect(JSON.parse(smuggledRes.body).result).toEqual({
        content: [{ type: 'text', text: 'Invalid arguments: Unrecognized key: "proxy"' }],
        isError: true,
      });

      for (const badArgs of [null, [], 'not-an-object']) {
        const nonObjRes = await handleStreamableHttpRequest(
          {
            method: 'POST',
            path: '/mcp',
            headers: { host: '127.0.0.1:3000' },
            body: JSON.stringify({
              jsonrpc: '2.0',
              id: 4,
              method: 'tools/call',
              params: { name: 'fetch_text', arguments: badArgs },
            }),
          },
          deps,
        );
        expect(JSON.parse(nonObjRes.body).error).toEqual({ code: -32603, message: 'Invalid arguments type' });
      }
    });
  });

  describe('startStreamableHttpServer — real Node HTTP & SDK Client interop (SH-2, SH-5, SH-6)', () => {
    it('interoperates end-to-end with stock @modelcontextprotocol/sdk StreamableHTTPClientTransport and enforces HTTP guards', async () => {
      const origin = createOriginMock();
      const dns = createDnsMock();
      const ytDlp = createYtDlpMock();
      origin.serve('https://example.com/live-http', 200, '<h1>Streamable Real</h1>');

      const running = await startStreamableHttpServer(
        {
          version: '2.0.0',
          fetchPorts: { httpGet: origin.get, dnsLookup: dns.lookup },
          ytDlp,
          env: {},
          limits: { defaultLimit: 5000, maxResponseBytes: 10 * 1024 * 1024 },
        },
        '127.0.0.1',
        0,
      );

      try {
        // HTTP route & Origin guards
        const sseRes = await fetch(`http://127.0.0.1:${running.port}/sse`);
        expect(sseRes.status).toBe(404);

        const getMcp = await fetch(running.url);
        expect(getMcp.status).toBe(405);

        const badOrigin = await fetch(running.url, {
          method: 'POST',
          headers: { origin: 'https://evil.example', 'content-type': 'application/json' },
          body: '{}',
        });
        expect(badOrigin.status).toBe(403);

        // Stock SDK StreamableHTTPClientTransport interop
        const transport = new StreamableHTTPClientTransport(new URL(running.url));
        const client = new Client({ name: 'streamable-http-test', version: '1.0.0' });
        await client.connect(transport);
        try {
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
            expect(tool.inputSchema.additionalProperties).toBe(false);
            expect(tool.annotations?.readOnlyHint).toBe(true);
          }

          const okCall = await client.callTool({
            name: 'fetch_text',
            arguments: { url: 'https://example.com/live-http' },
          });
          expect(okCall).toEqual({
            content: [{ type: 'text', text: 'Streamable Real' }],
            isError: false,
          });

          const smuggled = await client.callTool({
            name: 'fetch_html',
            arguments: { url: 'https://example.com/live-http', proxy: 'http://evil:80' },
          });
          expect(smuggled.isError).toBe(true);

          const ssrf = await client.callTool({
            name: 'fetch_html',
            arguments: { url: 'http://127.0.0.1/secret' },
          });
          expect(ssrf).toEqual({
            content: [{ type: 'text', text: 'Blocked Target URL: private address "127.0.0.1"' }],
            isError: true,
          });

          let unknownErr: unknown;
          try {
            await client.callTool({ name: 'fetch_txt', arguments: { url: 'https://example.com/' } });
          } catch (error) {
            unknownErr = error;
          }
          expect(unknownErr).toBeInstanceOf(McpError);
          if (unknownErr instanceof McpError) {
            expect(unknownErr.code).toBe(ErrorCode.InvalidParams);
          }
        } finally {
          await client.close();
        }
      } finally {
        await running.close();
      }
    });
  });
});
