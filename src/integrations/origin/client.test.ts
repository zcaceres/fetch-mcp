import { afterAll, beforeAll, describe, expect, it } from 'bun:test';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import zlib from 'node:zlib';
import { executeFetch } from '../../fetching/execute.ts';
import { ResolvedIp, TargetUrl } from '../../fetching/nouns.ts';
import type { DnsLookupPort } from '../../fetching/ports.ts';
import { ok } from '../../shared/result.ts';
import { createPinnedLookup, createRealHttpGet } from './client.ts';

describe('real HTTP transport (Slice 05)', () => {
  let server: http.Server;
  let port: number;
  let requestCounts: Map<string, number>;
  let recordedHeaders: Map<string, http.IncomingHttpHeaders>;

  beforeAll(async () => {
    requestCounts = new Map();
    recordedHeaders = new Map();

    server = http.createServer((req, res) => {
      const path = req.url ?? '/';
      requestCounts.set(path, (requestCounts.get(path) ?? 0) + 1);
      recordedHeaders.set(path, req.headers);

      if (path === '/html') {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end('<h3>Hello</h3> <p>From real server</p>');
        return;
      }

      if (path === '/gzip') {
        const gz = zlib.gzipSync('{"ok": true}');
        res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Encoding': 'gzip' });
        res.end(gz);
        return;
      }

      if (path === '/binary') {
        res.writeHead(200, { 'Content-Type': 'image/png' });
        res.end(Buffer.from([0x89, 0x50, 0x4e, 0x47]));
        return;
      }

      if (path === '/big-raw') {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('a'.repeat(500));
        return;
      }

      if (path === '/slow') {
        setTimeout(() => {
          if (!res.destroyed) {
            res.writeHead(200, { 'Content-Type': 'text/plain' });
            res.end('too late');
          }
        }, 400);
        return;
      }

      if (path === '/redirect-private') {
        res.writeHead(302, { Location: 'http://127.0.0.1/secret' });
        res.end();
        return;
      }

      if (path === '/redirect-relative') {
        res.writeHead(302, { Location: '/html' });
        res.end();
        return;
      }

      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not Found');
    });

    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const addr = server.address() as AddressInfo;
    port = addr.port;
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it('connects strictly via pinnedIps without issuing a second DNS lookup (FW-4, I2)', async () => {
    const httpGet = createRealHttpGet({ maxBytes: 1024 * 1024, timeoutMs: 2000 });
    // Hostname "unresolvable.invalid" does not exist in real DNS, proving the socket used pinnedIps (127.0.0.1)
    const result = await httpGet(
      TargetUrl(`http://unresolvable.invalid:${port}/html`),
      { 'User-Agent': 'TestAgent/1.0', 'Accept-Encoding': 'gzip, deflate, br' },
      [ResolvedIp('127.0.0.1')],
    );

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.status).toBe(200);
      expect(new TextDecoder().decode(result.value.rawBytes)).toBe('<h3>Hello</h3> <p>From real server</p>');
    }
    expect(recordedHeaders.get('/html')?.['user-agent']).toBe('TestAgent/1.0');
  });

  it('invokes pinned lookup callbacks asynchronously across all lookup modes (D13, D14, FW-4, FW-5)', async () => {
    const withIp = createPinnedLookup([ResolvedIp('93.184.216.34')]);
    const empty = createPinnedLookup([]);
    const cases = [
      [withIp, { all: true }],
      [withIp, {}],
      [withIp, { family: 6 }],
      [empty, { all: true }],
      [empty, {}],
    ] as const;

    for (const [lookup, opts] of cases) {
      let calledSync = false;
      let called = false;
      await new Promise<void>((resolve) => {
        lookup('example.com', opts, () => {
          called = true;
          resolve();
        });
        calledSync = called;
      });
      expect(calledSync).toBe(false);
    }
  });

  it('aborts streaming reads when raw bytes exceed maxBytes (I5)', async () => {
    const httpGet = createRealHttpGet({ maxBytes: 100, timeoutMs: 2000 });
    const result = await httpGet(TargetUrl(`http://unresolvable.invalid:${port}/big-raw`), {}, [
      ResolvedIp('127.0.0.1'),
    ]);

    expect(result).toEqual({
      ok: false,
      error: { kind: 'response_too_large', message: 'Response too large: exceeded 100 byte limit' },
    });
  });

  it('aborts slow origin on timeout in a single attempt (D9, D18)', async () => {
    const before = requestCounts.get('/slow') ?? 0;
    const httpGet = createRealHttpGet({ maxBytes: 1024, timeoutMs: 80 });
    const result = await httpGet(TargetUrl(`http://unresolvable.invalid:${port}/slow`), {}, [ResolvedIp('127.0.0.1')]);

    expect(result).toEqual({
      ok: false,
      error: {
        kind: 'timeout',
        message: `Request timed out after 80ms fetching http://unresolvable.invalid:${port}/slow`,
      },
    });
    expect((requestCounts.get('/slow') ?? 0) - before).toBe(1);
  });

  it('wires executeFetch end-to-end with real HTTP transport for gzip JSON, relative redirects, and binary/SSRF guards', async () => {
    // Wrap createRealHttpGet so public-validated DNS IP maps to our local test socket in integration tests
    const rawHttpGet = createRealHttpGet({ maxBytes: 1024 * 1024, timeoutMs: 2000 });
    const localPinnedHttpGet: typeof rawHttpGet = (url, headers, _pinned) =>
      rawHttpGet(url, headers, [ResolvedIp('127.0.0.1')]);
    const fakePublicDns: DnsLookupPort = async () => ok(['93.184.216.34']);

    const jsonRes = await executeFetch(
      { url: `http://test.example.com:${port}/gzip`, format: 'json' },
      { httpGet: localPinnedHttpGet, dnsLookup: fakePublicDns },
    );
    expect(jsonRes.ok).toBe(true);
    if (jsonRes.ok) {
      expect(String(jsonRes.value)).toBe('{"ok":true}');
    }

    const redirectRes = await executeFetch(
      { url: `http://test.example.com:${port}/redirect-relative`, format: 'text' },
      { httpGet: localPinnedHttpGet, dnsLookup: fakePublicDns },
    );
    expect(redirectRes.ok).toBe(true);
    if (redirectRes.ok) {
      expect(String(redirectRes.value)).toBe('Hello From real server');
    }

    const binaryRes = await executeFetch(
      { url: `http://test.example.com:${port}/binary`, format: 'html' },
      { httpGet: localPinnedHttpGet, dnsLookup: fakePublicDns },
    );
    expect(binaryRes).toEqual({
      ok: false,
      error: {
        kind: 'unsupported_content_type',
        message: `Unsupported binary Content-Type "image/png" fetching http://test.example.com:${port}/binary`,
      },
    });

    const ssrfRes = await executeFetch(
      { url: `http://test.example.com:${port}/redirect-private`, format: 'html' },
      { httpGet: localPinnedHttpGet, dnsLookup: fakePublicDns },
    );
    expect(ssrfRes).toEqual({
      ok: false,
      error: {
        kind: 'blocked_url',
        message: 'Blocked Target URL: private address "127.0.0.1"',
      },
    });
  });

  it('returns a typed Result error instead of rejecting when transport.request throws on invalid headers (D14, D28)', async () => {
    const httpGet = createRealHttpGet({ maxBytes: 1024, timeoutMs: 2000 });
    const cases: readonly Record<string, string>[] = [{ '': 'v' }, { 'Bad Header': 'v' }, { 'X-Test': 'bad\u0000val' }];
    for (const badHeaders of cases) {
      const result = await httpGet(TargetUrl(`http://unresolvable.invalid:${port}/html`), badHeaders, [
        ResolvedIp('127.0.0.1'),
      ]);
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error.kind).toBe('invalid_request');
      }
    }
  });
});
