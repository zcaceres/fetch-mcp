import { describe, expect, it } from 'bun:test';
import zlib from 'node:zlib';
import { ok } from '../shared/result.ts';
import { executeFetch } from './execute.ts';
import { RenderedOutput, ResolvedIp, TargetUrl } from './nouns.ts';
import { isBinaryContentType, isReservedIp, stripCrossOriginHeaders, windowedExcerpt } from './queries.ts';
import {
  DEFAULT_USER_AGENT,
  decodeResponseBody,
  evaluateResponse,
  prepareFetch,
  validateRedirectHop,
  validateResolvedIps,
} from './verbs.ts';

describe('fetching domain', () => {
  describe('prepareFetch', () => {
    it('accepts a valid public http/https URL with default window bounds and default headers (D18)', () => {
      const result = prepareFetch({ url: 'https://example.com/page', format: 'html' });
      expect(result).toEqual({
        ok: true,
        value: {
          url: TargetUrl('https://example.com/page'),
          format: 'html',
          headers: {
            'User-Agent': DEFAULT_USER_AGENT,
            'Accept-Encoding': 'gzip, deflate, br',
          },
          window: { startIndex: 0, maxLength: 5000 },
        },
      });
    });

    it('accepts custom defaultLimit, headers, and explicit window bounds including maxLength 0', () => {
      const withDefault = prepareFetch(
        { url: 'https://example.com/', format: 'html', headers: { 'X-Trace': '1' } },
        1200,
      );
      expect(withDefault.ok).toBe(true);
      if (withDefault.ok) {
        expect(withDefault.value.window).toEqual({ startIndex: 0, maxLength: 1200 });
        expect(withDefault.value.headers).toEqual({
          'User-Agent': DEFAULT_USER_AGENT,
          'Accept-Encoding': 'gzip, deflate, br',
          'X-Trace': '1',
        });
      }

      const unlimited = prepareFetch({
        url: 'https://example.com/',
        format: 'html',
        startIndex: 10,
        maxLength: 0,
      });
      expect(unlimited.ok).toBe(true);
      if (unlimited.ok) {
        expect(unlimited.value.window).toEqual({ startIndex: 10, maxLength: 0 });
      }
    });

    it('deduplicates default and duplicate caller headers case-insensitively (D18)', () => {
      const result = prepareFetch({
        url: 'https://example.com/',
        format: 'html',
        headers: {
          'user-agent': 'CustomBot/1.0',
          'ACCEPT-ENCODING': 'identity',
          'X-Dup': 'first',
          'x-dup': 'second',
        },
      });
      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.value.headers).toEqual({
          'user-agent': 'CustomBot/1.0',
          'ACCEPT-ENCODING': 'identity',
          'x-dup': 'second',
        });
      }
    });

    it('rejects custom header names or values containing CR/LF control characters (D14, D18)', () => {
      expect(
        prepareFetch({
          url: 'https://example.com/',
          format: 'html',
          headers: { 'X-Bad': 'ok\r\nInjected: evil' },
        }),
      ).toEqual({
        ok: false,
        error: {
          kind: 'invalid_request',
          message: 'Invalid header "X-Bad": CR/LF control characters are not allowed',
        },
      });
      expect(
        prepareFetch({
          url: 'https://example.com/',
          format: 'html',
          headers: { 'X-Bad\nName': 'value' },
        }),
      ).toEqual({
        ok: false,
        error: {
          kind: 'invalid_request',
          message: 'Invalid header "X-Bad\\nName": CR/LF control characters are not allowed',
        },
      });
    });

    it('rejects empty, non-token, or control-character custom headers before connecting (D14, D18)', () => {
      const cases: readonly Record<string, string>[] = [
        { '': 'v' },
        { 'Bad Header': 'v' },
        { 'X-Test': 'bad\u0000val' },
      ];
      for (const headers of cases) {
        const result = prepareFetch({ url: 'https://example.com/', format: 'html', headers });
        expect(result.ok).toBe(false);
        if (!result.ok) {
          expect(result.error.kind).toBe('invalid_request');
        }
      }
    });

    it('rejects malformed URLs', () => {
      const result = prepareFetch({ url: 'not-a-url', format: 'html' });
      expect(result).toEqual({
        ok: false,
        error: { kind: 'invalid_request', message: 'Invalid Target URL: "not-a-url"' },
      });
    });

    it('rejects unsupported formats', () => {
      const result = prepareFetch({ url: 'https://example.com/', format: 'pdf' });
      expect(result).toEqual({
        ok: false,
        error: { kind: 'invalid_request', message: 'Unsupported Format: "pdf"' },
      });
    });

    it('rejects negative or non-integer window bounds', () => {
      expect(prepareFetch({ url: 'https://example.com/', format: 'html', startIndex: -1 })).toEqual({
        ok: false,
        error: { kind: 'invalid_request', message: 'Invalid startIndex: must be a non-negative integer' },
      });
      expect(prepareFetch({ url: 'https://example.com/', format: 'html', startIndex: 1.5 })).toEqual({
        ok: false,
        error: { kind: 'invalid_request', message: 'Invalid startIndex: must be a non-negative integer' },
      });
      expect(prepareFetch({ url: 'https://example.com/', format: 'html', maxLength: -5 })).toEqual({
        ok: false,
        error: { kind: 'invalid_request', message: 'Invalid maxLength: must be a non-negative integer' },
      });
      expect(prepareFetch({ url: 'https://example.com/', format: 'html', maxLength: Number.NaN })).toEqual({
        ok: false,
        error: { kind: 'invalid_request', message: 'Invalid maxLength: must be a non-negative integer' },
      });
    });

    it('blocks disallowed URL schemes (I1)', () => {
      expect(prepareFetch({ url: 'file:///etc/passwd', format: 'html' })).toEqual({
        ok: false,
        error: {
          kind: 'blocked_url',
          message: 'Blocked Target URL: disallowed scheme "file:" (only http: and https: are allowed)',
        },
      });
      expect(prepareFetch({ url: 'ftp://example.com/file', format: 'html' })).toEqual({
        ok: false,
        error: {
          kind: 'blocked_url',
          message: 'Blocked Target URL: disallowed scheme "ftp:" (only http: and https: are allowed)',
        },
      });
    });

    it('blocks localhost, *.localhost, and reserved IPv4/IPv6 literals (I1)', () => {
      for (const [url, host] of [
        ['http://localhost/admin', 'localhost'],
        ['http://api.localhost:8080/', 'api.localhost'],
        ['http://localhost./', 'localhost'],
        ['http://127.0.0.1/secret', '127.0.0.1'],
        ['http://10.0.0.1/internal', '10.0.0.1'],
        ['http://100.64.0.1/cgnat', '100.64.0.1'],
        ['http://172.16.0.1/', '172.16.0.1'],
        ['http://192.168.1.1/', '192.168.1.1'],
        ['http://169.254.169.254/latest/meta-data/', '169.254.169.254'],
        ['http://0.0.0.0/', '0.0.0.0'],
        ['http://224.0.0.1/multicast', '224.0.0.1'],
        ['http://[::1]/loopback', '::1'],
        ['http://[::ffff:127.0.0.1]/mapped', '::ffff:7f00:1'],
        ['http://[fc00::1]/ula', 'fc00::1'],
        ['http://[fe80::1]/link-local', 'fe80::1'],
      ] as const) {
        expect(prepareFetch({ url, format: 'html' })).toEqual({
          ok: false,
          error: { kind: 'blocked_url', message: `Blocked Target URL: private address "${host}"` },
        });
      }
    });

    it('allows public IPv4 and IPv6 literals (I1)', () => {
      expect(prepareFetch({ url: 'http://93.184.216.34/', format: 'html' }).ok).toBe(true);
      expect(prepareFetch({ url: 'http://[2606:2800:220:1:248:1893:25c8:1946]/', format: 'html' }).ok).toBe(true);
    });
  });

  describe('isReservedIp', () => {
    it('blocks all IANA-reserved IPv4 ranges', () => {
      for (const ip of [
        '0.0.0.0',
        '10.255.255.255',
        '100.64.0.1',
        '100.127.255.255',
        '127.0.0.1',
        '169.254.169.254',
        '172.16.0.1',
        '172.31.255.255',
        '192.0.0.1',
        '192.0.2.1',
        '192.88.99.1',
        '192.168.0.1',
        '198.18.0.1',
        '198.19.255.255',
        '198.51.100.1',
        '203.0.113.1',
        '224.0.0.1',
        '239.255.255.255',
        '240.0.0.1',
        '255.255.255.255',
      ]) {
        expect(isReservedIp(ip)).toBe(true);
      }
    });

    it('allows public IPv4 addresses', () => {
      for (const ip of ['1.1.1.1', '8.8.8.8', '93.184.216.34', '100.63.255.255', '172.32.0.1']) {
        expect(isReservedIp(ip)).toBe(false);
      }
    });

    it('blocks reserved IPv6 ranges and IPv4-mapped reserved addresses', () => {
      for (const ip of [
        '::',
        '::1',
        '::ffff:127.0.0.1',
        '::ffff:7f00:1',
        '::ffff:10.0.0.1',
        '::ffff:169.254.169.254',
        '::ffff:0:127.0.0.1',
        '64:ff9b::1',
        '64:ff9b:1::1',
        '100::1',
        '2001::1',
        '2001:2::1',
        '2001:10::1',
        '2001:20::1',
        '2001:db8::1',
        '2002::1',
        'fc00::1',
        'fd12:3456::1',
        'fe80::1',
        'fec0::1',
        'ff02::1',
      ]) {
        expect(isReservedIp(ip)).toBe(true);
      }
    });

    it('allows public IPv6 and IPv4-mapped public addresses', () => {
      for (const ip of ['2606:2800:220:1:248:1893:25c8:1946', '2606:4700:4700::1111', '::ffff:93.184.216.34']) {
        expect(isReservedIp(ip)).toBe(false);
      }
    });

    it('fails closed on zone-scoped, malformed, or non-IP inputs', () => {
      for (const bad of ['', 'not-an-ip', 'fe80::1%eth0', '2606::1%en0', '1::2::3', '999.0.0.1']) {
        expect(isReservedIp(bad)).toBe(true);
      }
    });
  });

  describe('stripCrossOriginHeaders', () => {
    it('strips Authorization, Cookie, and Proxy-Authorization case-insensitively', () => {
      expect(
        stripCrossOriginHeaders({
          Authorization: 'Bearer secret',
          cookie: 'sid=123',
          'Proxy-Authorization': 'Basic xyz',
          'X-Trace': 'abc',
          Accept: 'text/html',
        }),
      ).toEqual({
        'X-Trace': 'abc',
        Accept: 'text/html',
      });
    });
  });

  describe('validateResolvedIps', () => {
    it('accepts a list of public IPs (I2)', () => {
      expect(validateResolvedIps('example.com', ['93.184.216.34', '2606:2800:220:1:248:1893:25c8:1946'])).toEqual({
        ok: true,
        value: [ResolvedIp('93.184.216.34'), ResolvedIp('2606:2800:220:1:248:1893:25c8:1946')],
      });
    });

    it('fails closed on empty address list (I2)', () => {
      expect(validateResolvedIps('empty.example.com', [])).toEqual({
        ok: false,
        error: {
          kind: 'blocked_url',
          message: 'Blocked Target URL: DNS lookup returned no addresses for "empty.example.com"',
        },
      });
    });

    it('rejects when any resolved IP is reserved or malformed (DNS rebinding, I2)', () => {
      expect(validateResolvedIps('rebind.example.com', ['93.184.216.34', '10.0.0.5'])).toEqual({
        ok: false,
        error: {
          kind: 'blocked_url',
          message: 'Blocked Target URL: hostname "rebind.example.com" resolved to private IP "10.0.0.5"',
        },
      });
    });
  });

  describe('validateRedirectHop', () => {
    const startUrl = TargetUrl('https://origin-a.example.com/old');
    const headers = { Authorization: 'Bearer secret', Cookie: 'a=1', 'X-Trace': 'abc' };

    it('resolves relative Location on same origin and preserves sensitive headers', () => {
      const result = validateRedirectHop(startUrl, '/new', headers, 0);
      expect(result).toEqual({
        ok: true,
        value: {
          nextUrl: TargetUrl('https://origin-a.example.com/new'),
          headers,
        },
      });
    });

    it('strips sensitive headers when crossing origins (I4)', () => {
      const result = validateRedirectHop(startUrl, 'https://origin-b.example.com/final', headers, 0);
      expect(result).toEqual({
        ok: true,
        value: {
          nextUrl: TargetUrl('https://origin-b.example.com/final'),
          headers: { 'X-Trace': 'abc' },
        },
      });
    });

    it('refuses redirects at or beyond maxRedirects (D9)', () => {
      expect(validateRedirectHop(startUrl, '/next', headers, 10)).toEqual({
        ok: false,
        error: { kind: 'too_many_redirects', message: 'Too many redirects (exceeded 10)' },
      });
    });

    it('blocks redirects to private IPs and disallowed schemes (I1)', () => {
      expect(validateRedirectHop(startUrl, 'http://127.0.0.1/secret', headers, 0)).toEqual({
        ok: false,
        error: { kind: 'blocked_url', message: 'Blocked Target URL: private address "127.0.0.1"' },
      });
      expect(validateRedirectHop(startUrl, 'file:///etc/passwd', headers, 0)).toEqual({
        ok: false,
        error: {
          kind: 'blocked_url',
          message: 'Blocked Target URL: disallowed scheme "file:" (only http: and https: are allowed)',
        },
      });
    });
  });

  describe('isBinaryContentType', () => {
    it('flags binary media types with or without parameters (D17)', () => {
      for (const ct of [
        'image/png',
        'IMAGE/JPEG; charset=binary',
        'audio/mpeg',
        'video/mp4',
        'font/woff2',
        'application/octet-stream',
        'application/pdf',
        'application/pdf; charset=utf-8',
        'application/zip',
      ]) {
        expect(isBinaryContentType(ct)).toBe(true);
      }
    });

    it('allows text-based, JSON, XML, and missing Content-Type (D17)', () => {
      for (const ct of [
        undefined,
        '',
        'text/html',
        'text/html; charset=utf-8',
        'text/plain',
        'application/json',
        'application/ld+json',
        'application/xml',
        'application/xhtml+xml',
        'image/svg+xml',
        'image/svg+xml; charset=utf-8',
      ]) {
        expect(isBinaryContentType(ct)).toBe(false);
      }
    });
  });

  describe('evaluateResponse', () => {
    const reqFor = (format: string) => {
      const r = prepareFetch({ url: 'https://example.com/', format });
      if (!r.ok) throw new Error(`expected valid request for format ${format}`);
      return r.value;
    };

    it('returns unmodified HTML for 2xx responses (D16)', () => {
      const request = reqFor('html');
      const body = '<h1>Hello</h1><script>alert(1)</script>';
      const result = evaluateResponse(request, {
        status: 200,
        url: request.url,
        headers: { 'content-type': 'text/html' },
        body,
      });
      expect(result).toEqual({ ok: true, value: RenderedOutput(body) });
    });

    it('returns typed HTTP error for non-2xx responses including 302 without Location (D14, D17)', () => {
      const request = reqFor('html');
      expect(evaluateResponse(request, { status: 404, url: request.url, headers: {}, body: 'Not Found' })).toEqual({
        ok: false,
        error: { kind: 'http_error', message: 'HTTP error 404 fetching https://example.com/' },
      });
      expect(evaluateResponse(request, { status: 302, url: request.url, headers: {}, body: 'Moved' })).toEqual({
        ok: false,
        error: { kind: 'http_error', message: 'HTTP error 302 fetching https://example.com/' },
      });
    });

    it('rejects binary Content-Type before rendering (D14, D17)', () => {
      const request = reqFor('html');
      expect(
        evaluateResponse(request, {
          status: 200,
          url: request.url,
          headers: { 'Content-Type': 'image/png; charset=binary' },
          body: 'PNGDATA',
        }),
      ).toEqual({
        ok: false,
        error: {
          kind: 'unsupported_content_type',
          message: 'Unsupported binary Content-Type "image/png" fetching https://example.com/',
        },
      });
    });

    it('renders json compactly and fails explicitly on invalid JSON (D14, D16)', () => {
      const request = reqFor('json');
      expect(
        evaluateResponse(request, {
          status: 200,
          url: request.url,
          headers: { 'content-type': 'application/json' },
          body: '{ "a": 1, "b": [2, 3] }',
        }),
      ).toEqual({ ok: true, value: RenderedOutput('{"a":1,"b":[2,3]}') });

      expect(
        evaluateResponse(request, {
          status: 200,
          url: request.url,
          headers: { 'content-type': 'text/html' },
          body: '<html>not json</html>',
        }),
      ).toEqual({
        ok: false,
        error: { kind: 'parse_error', message: 'Invalid JSON response from https://example.com/' },
      });
    });

    it('renders text stripping script and style and collapsing whitespace (D16)', () => {
      const request = reqFor('text');
      const res = evaluateResponse(request, {
        status: 200,
        url: request.url,
        headers: { 'content-type': 'text/html' },
        body: '<html><head><style>body{color:red}</style><script>var a=1;</script></head><body><h1>Hi</h1>  <p>World</p><script>bad()</script></body></html>',
      });
      expect(res).toEqual({ ok: true, value: RenderedOutput('Hi World') });

      const emptyRes = evaluateResponse(request, {
        status: 200,
        url: request.url,
        headers: {},
        body: '<html><head><title>No body</title></head></html>',
      });
      expect(emptyRes).toEqual({ ok: true, value: RenderedOutput('') });
    });

    it('renders markdown stripping script and style before Turndown conversion (D16)', () => {
      const request = reqFor('markdown');
      const res = evaluateResponse(request, {
        status: 200,
        url: request.url,
        headers: { 'content-type': 'text/html' },
        body: '<html><head><style>p{color:red}</style><script>bad()</script></head><body><h3>Guide</h3><p>Visit <a href="https://example.com">home</a>.</p><script>inline()</script></body></html>',
      });
      expect(res).toEqual({ ok: true, value: RenderedOutput('### Guide\n\nVisit [home](https://example.com).') });
    });

    it('renders readable with # title heading, strips boilerplate, and fails on unparseable pages (D14, D16)', () => {
      const request = reqFor('readable');
      const articleHtml =
        '<!DOCTYPE html><html><head><title>Test Article</title></head><body>' +
        '<nav><a href="/">Home</a></nav>' +
        '<article><p>This is the first paragraph of the article and contains plenty of meaningful text so Mozilla Readability identifies it as the primary article content cleanly.</p>' +
        '<p>This is the second paragraph with additional substantial prose so Readability keeps the article body and strips away navigation boilerplate.</p></article>' +
        '<footer><p>Copyright 2026</p></footer></body></html>';
      const res = evaluateResponse(request, {
        status: 200,
        url: request.url,
        headers: { 'content-type': 'text/html' },
        body: articleHtml,
      });
      expect(res.ok).toBe(true);
      if (res.ok) {
        expect(res.value.startsWith('# Test Article\n\n')).toBe(true);
        expect(res.value).toContain('first paragraph');
        expect(res.value).not.toContain('Copyright 2026');
      }

      const failRes = evaluateResponse(request, {
        status: 200,
        url: request.url,
        headers: { 'content-type': 'text/html' },
        body: '<html><body></body></html>',
      });
      expect(failRes).toEqual({
        ok: false,
        error: { kind: 'parse_error', message: 'Failed to parse readable content from https://example.com/' },
      });
    });
  });

  describe('decodeResponseBody', () => {
    const url = TargetUrl('https://example.com/data');

    it('decompresses gzip, x-gzip, deflate, and br payloads (D17)', () => {
      const plain = 'hello compressed world';
      expect(decodeResponseBody(url, { 'content-encoding': 'gzip' }, zlib.gzipSync(plain))).toEqual({
        ok: true,
        value: plain,
      });
      expect(decodeResponseBody(url, { 'Content-Encoding': 'X-GZIP' }, zlib.gzipSync(plain))).toEqual({
        ok: true,
        value: plain,
      });
      expect(decodeResponseBody(url, { 'content-encoding': 'deflate' }, zlib.deflateSync(plain))).toEqual({
        ok: true,
        value: plain,
      });
      expect(decodeResponseBody(url, { 'content-encoding': 'br' }, zlib.brotliCompressSync(plain))).toEqual({
        ok: true,
        value: plain,
      });
    });

    it('passes missing, identity, and unknown Content-Encoding through unchanged (D17)', () => {
      const bytes = new TextEncoder().encode('raw-utf8');
      expect(decodeResponseBody(url, {}, bytes)).toEqual({ ok: true, value: 'raw-utf8' });
      expect(decodeResponseBody(url, { 'content-encoding': 'identity' }, bytes)).toEqual({
        ok: true,
        value: 'raw-utf8',
      });
      expect(decodeResponseBody(url, { 'content-encoding': 'custom-enc' }, bytes)).toEqual({
        ok: true,
        value: 'raw-utf8',
      });
    });

    it('enforces maxBytes on declared Content-Length, raw bytes, and decompressed output (I5)', () => {
      const small = new TextEncoder().encode('ok');
      expect(decodeResponseBody(url, { 'Content-Length': '500' }, small, 100)).toEqual({
        ok: false,
        error: { kind: 'response_too_large', message: 'Response too large: 500 bytes exceeds 100 byte limit' },
      });

      const bigRaw = new Uint8Array(101);
      expect(decodeResponseBody(url, {}, bigRaw, 100)).toEqual({
        ok: false,
        error: { kind: 'response_too_large', message: 'Response too large: exceeded 100 byte limit' },
      });

      const bomb = zlib.gzipSync('a'.repeat(500));
      expect(bomb.byteLength).toBeLessThan(100);
      expect(decodeResponseBody(url, { 'content-encoding': 'gzip' }, bomb, 100)).toEqual({
        ok: false,
        error: { kind: 'response_too_large', message: 'Response too large: exceeded 100 byte limit' },
      });
    });

    it('returns typed decode error on corrupted compressed stream (D14, D17)', () => {
      const badBytes = new TextEncoder().encode('not-valid-gzip');
      expect(decodeResponseBody(url, { 'content-encoding': 'gzip' }, badBytes)).toEqual({
        ok: false,
        error: { kind: 'decode_error', message: 'Failed to decompress gzip response from https://example.com/data' },
      });
    });

    it('skips decompression for 0-byte bodies and passes multi-value Content-Encoding through unchanged (D17)', () => {
      expect(decodeResponseBody(url, { 'content-encoding': 'gzip' }, new Uint8Array(0))).toEqual({
        ok: true,
        value: '',
      });
      const bytes = new TextEncoder().encode('raw-multi');
      expect(decodeResponseBody(url, { 'content-encoding': 'gzip, br' }, bytes)).toEqual({
        ok: true,
        value: 'raw-multi',
      });
    });
  });

  describe('executeFetch edge hardening (D17, FW-5, FW-6, FW-9)', () => {
    it('returns HTTP error before decompressing non-2xx gzip responses and treats blank Location as absent (D17)', async () => {
      const dnsLookup = async () => ok([ResolvedIp('93.184.216.34')]);

      const res500 = await executeFetch(
        { url: 'https://example.com/500-gz', format: 'html' },
        {
          dnsLookup,
          httpGet: async (reqUrl) =>
            ok({
              status: 500,
              url: reqUrl,
              headers: { 'Content-Encoding': 'gzip' },
              rawBytes: new Uint8Array(0),
            }),
        },
      );
      expect(res500).toEqual({
        ok: false,
        error: { kind: 'http_error', message: 'HTTP error 500 fetching https://example.com/500-gz' },
      });

      const resWsLoc = await executeFetch(
        { url: 'https://example.com/ws-loc', format: 'html' },
        {
          dnsLookup,
          httpGet: async (reqUrl) =>
            ok({
              status: 302,
              url: reqUrl,
              headers: { location: '   ' },
              rawBytes: new Uint8Array(0),
            }),
        },
      );
      expect(resWsLoc).toEqual({
        ok: false,
        error: { kind: 'http_error', message: 'HTTP error 302 fetching https://example.com/ws-loc' },
      });
    });

    it('enforces MAX_RESPONSE_BYTES raw wire-byte cap even on non-2xx responses (D17, I5)', async () => {
      const res = await executeFetch(
        { url: 'https://example.com/big-500', format: 'html' },
        {
          dnsLookup: async () => ok([ResolvedIp('93.184.216.34')]),
          httpGet: async (reqUrl) =>
            ok({
              status: 500,
              url: reqUrl,
              headers: { 'content-type': 'text/plain' },
              rawBytes: new TextEncoder().encode('x'.repeat(200)),
            }),
        },
        { maxResponseBytes: 100 },
      );
      expect(res).toEqual({
        ok: false,
        error: { kind: 'response_too_large', message: 'Response too large: exceeded 100 byte limit' },
      });
    });

    it('uses last-value-wins for case-duplicate response headers (FW-9)', async () => {
      const res = await executeFetch(
        { url: 'https://example.com/dup-ct', format: 'html' },
        {
          dnsLookup: async () => ok([ResolvedIp('93.184.216.34')]),
          httpGet: async (reqUrl) =>
            ok({
              status: 200,
              url: reqUrl,
              headers: { 'Content-Type': 'text/html', 'content-type': 'image/png' },
              rawBytes: new TextEncoder().encode('<p>hi</p>'),
            }),
        },
      );
      expect(res.ok).toBe(false);
      if (!res.ok) {
        expect(res.error.kind).toBe('unsupported_content_type');
      }
    });
  });

  describe('windowedExcerpt', () => {
    const output = RenderedOutput('0123456789abcdefghij');

    it('slices by startIndex and maxLength without adding metadata (D15)', () => {
      expect(String(windowedExcerpt(output, { startIndex: 5, maxLength: 6 }))).toBe('56789a');
    });

    it('returns full remainder when maxLength is 0 (D9, D15)', () => {
      expect(String(windowedExcerpt(output, { startIndex: 0, maxLength: 0 }))).toBe('0123456789abcdefghij');
      expect(String(windowedExcerpt(output, { startIndex: 10, maxLength: 0 }))).toBe('abcdefghij');
    });

    it('returns empty string when startIndex is at or beyond output length (D14, D15)', () => {
      expect(String(windowedExcerpt(output, { startIndex: 20, maxLength: 10 }))).toBe('');
      expect(String(windowedExcerpt(output, { startIndex: 99, maxLength: 10 }))).toBe('');
    });
  });
});
