import { describe, expect, it } from 'bun:test';
import { RenderedOutput, ResolvedIp, TargetUrl } from './nouns.ts';
import { isReservedIp, stripCrossOriginHeaders, windowedExcerpt } from './queries.ts';
import { evaluateResponse, prepareFetch, validateRedirectHop, validateResolvedIps } from './verbs.ts';

describe('fetching domain', () => {
  describe('prepareFetch', () => {
    it('accepts a valid public http/https URL with default window bounds and headers', () => {
      const result = prepareFetch({ url: 'https://example.com/page', format: 'html' });
      expect(result).toEqual({
        ok: true,
        value: {
          url: TargetUrl('https://example.com/page'),
          format: 'html',
          headers: {},
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
        expect(withDefault.value.headers).toEqual({ 'X-Trace': '1' });
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

  describe('evaluateResponse', () => {
    const reqResult = prepareFetch({ url: 'https://example.com/', format: 'html' });
    if (!reqResult.ok) throw new Error('expected valid request');
    const request = reqResult.value;

    it('returns unmodified HTML for 2xx responses (D16)', () => {
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
      expect(evaluateResponse(request, { status: 404, url: request.url, headers: {}, body: 'Not Found' })).toEqual({
        ok: false,
        error: { kind: 'http_error', message: 'HTTP error 404 fetching https://example.com/' },
      });
      expect(evaluateResponse(request, { status: 302, url: request.url, headers: {}, body: 'Moved' })).toEqual({
        ok: false,
        error: { kind: 'http_error', message: 'HTTP error 302 fetching https://example.com/' },
      });
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
