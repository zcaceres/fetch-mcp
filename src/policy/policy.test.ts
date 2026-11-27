import { describe, expect, it } from 'bun:test';
import { ProxyUrl } from './nouns.ts';
import { isNoProxyMatch, redactProxyUrl } from './queries.ts';
import { parseOperatorLimits, resolveProxyPolicy } from './verbs.ts';

describe('policy domain (Slice 01)', () => {
  describe('parseOperatorLimits (PL-1, PL-2, D9, D25)', () => {
    it('returns default limits when env vars are unset or blank', () => {
      expect(parseOperatorLimits({})).toEqual({
        ok: true,
        value: { defaultLimit: 5000, maxResponseBytes: 10 * 1024 * 1024 },
      });
      expect(parseOperatorLimits({ DEFAULT_LIMIT: '   ', MAX_RESPONSE_BYTES: '' })).toEqual({
        ok: true,
        value: { defaultLimit: 5000, maxResponseBytes: 10 * 1024 * 1024 },
      });
    });

    it('accepts valid integer limits including DEFAULT_LIMIT=0 for unlimited', () => {
      expect(parseOperatorLimits({ DEFAULT_LIMIT: '0', MAX_RESPONSE_BYTES: '1024' })).toEqual({
        ok: true,
        value: { defaultLimit: 0, maxResponseBytes: 1024 },
      });
      expect(parseOperatorLimits({ DEFAULT_LIMIT: '2500' })).toEqual({
        ok: true,
        value: { defaultLimit: 2500, maxResponseBytes: 10 * 1024 * 1024 },
      });
    });

    it('fails explicitly on invalid DEFAULT_LIMIT or MAX_RESPONSE_BYTES values (D25)', () => {
      expect(parseOperatorLimits({ DEFAULT_LIMIT: '-1' })).toEqual({
        ok: false,
        error: { kind: 'invalid_limit', message: 'Invalid DEFAULT_LIMIT "-1": must be a non-negative integer' },
      });
      expect(parseOperatorLimits({ DEFAULT_LIMIT: 'abc' })).toEqual({
        ok: false,
        error: { kind: 'invalid_limit', message: 'Invalid DEFAULT_LIMIT "abc": must be a non-negative integer' },
      });
      expect(parseOperatorLimits({ DEFAULT_LIMIT: '12.5' })).toEqual({
        ok: false,
        error: { kind: 'invalid_limit', message: 'Invalid DEFAULT_LIMIT "12.5": must be a non-negative integer' },
      });
      expect(parseOperatorLimits({ MAX_RESPONSE_BYTES: '0' })).toEqual({
        ok: false,
        error: { kind: 'invalid_limit', message: 'Invalid MAX_RESPONSE_BYTES "0": must be a positive integer' },
      });
      expect(parseOperatorLimits({ MAX_RESPONSE_BYTES: '-100' })).toEqual({
        ok: false,
        error: { kind: 'invalid_limit', message: 'Invalid MAX_RESPONSE_BYTES "-100": must be a positive integer' },
      });
      expect(parseOperatorLimits({ MAX_RESPONSE_BYTES: '10mb' })).toEqual({
        ok: false,
        error: { kind: 'invalid_limit', message: 'Invalid MAX_RESPONSE_BYTES "10mb": must be a positive integer' },
      });
      expect(parseOperatorLimits({ DEFAULT_LIMIT: '99999999999999999999' })).toEqual({
        ok: false,
        error: {
          kind: 'invalid_limit',
          message: 'Invalid DEFAULT_LIMIT "99999999999999999999": must be a non-negative integer',
        },
      });
      expect(parseOperatorLimits({ MAX_RESPONSE_BYTES: '99999999999999999999' })).toEqual({
        ok: false,
        error: {
          kind: 'invalid_limit',
          message: 'Invalid MAX_RESPONSE_BYTES "99999999999999999999": must be a positive integer',
        },
      });
    });
  });

  describe('isNoProxyMatch (PL-4, D24)', () => {
    it('matches wildcard, exact host, subdomain suffix, optional port, and IPv6 host/port', () => {
      expect(isNoProxyMatch(new URL('https://anything.example.com'), '*')).toBe(true);
      expect(isNoProxyMatch(new URL('https://example.com'), 'example.com')).toBe(true);
      expect(isNoProxyMatch(new URL('https://api.example.com'), '.example.com')).toBe(true);
      expect(isNoProxyMatch(new URL('https://example.com'), '.example.com')).toBe(true);
      expect(isNoProxyMatch(new URL('https://notexample.com'), 'example.com')).toBe(false);
      expect(isNoProxyMatch(new URL('https://example.com:8443'), 'example.com:8443')).toBe(true);
      expect(isNoProxyMatch(new URL('https://example.com'), 'example.com:8443')).toBe(false);
      expect(isNoProxyMatch(new URL('https://example.com'), 'example.com:443')).toBe(true);
      expect(isNoProxyMatch(new URL('http://[2001:db8::1]:8080/'), '[2001:db8::1]:8080')).toBe(true);
      expect(isNoProxyMatch(new URL('http://[2001:db8::1]:9090/'), '[2001:db8::1]:8080')).toBe(false);
      expect(isNoProxyMatch(new URL('http://[2001:0db8::1]:8080/'), '[2001:0db8::1]:8080')).toBe(true);
      expect(isNoProxyMatch(new URL('http://[2001:db8::1]:8080/'), '[2001:0db8::1]:8080')).toBe(true);
      expect(isNoProxyMatch(new URL('http://[2001:db8::1]/'), '2001:0db8::1')).toBe(true);
      expect(isNoProxyMatch(new URL('https://example.com:9999/'), 'example.com:')).toBe(false);
      expect(isNoProxyMatch(new URL('https://example.com/'), '[example.com]garbage')).toBe(false);
    });
  });

  describe('redactProxyUrl (D31, I7)', () => {
    it('strips credentials from valid and malformed proxy URLs', () => {
      expect(redactProxyUrl('https://user:secret@proxy.internal:8443/')).toBe('https://proxy.internal:8443/');
      expect(redactProxyUrl('socks5://alice:p%40ss@127.0.0.1:1080')).toBe('socks5://127.0.0.1:1080');
      expect(redactProxyUrl('http://127.0.0.1:8080/')).toBe('http://127.0.0.1:8080/');
      expect(redactProxyUrl('http://user:secret@bad host')).toBe('http://<redacted>@bad host');
      expect(redactProxyUrl('user:topsecret@bad host:8080')).toBe('<redacted>@bad host:8080');
      expect(redactProxyUrl('user:topsecret@proxy.internal:8080')).toBe('<redacted>@proxy.internal:8080');
      expect(redactProxyUrl('http://user:p@ss@bad host:8080')).toBe('http://<redacted>@bad host:8080');
      expect(redactProxyUrl('http://user:p/ss@bad host:8080')).toBe('http://<redacted>@bad host:8080');
      expect(redactProxyUrl('http://user:p?ss@bad host:8080')).toBe('http://<redacted>@bad host:8080');
      expect(redactProxyUrl('http://user:p#ss@bad host:8080')).toBe('http://<redacted>@bad host:8080');
      expect(redactProxyUrl('http://proxy.internal:8080/path?email=a@b.com')).toBe(
        'http://proxy.internal:8080/path?email=a@b.com',
      );
    });
  });

  describe('resolveProxyPolicy (PL-3, PL-4, PL-5, D5, D23, D24, D25)', () => {
    it('returns direct when no proxy is configured', () => {
      expect(resolveProxyPolicy('https://example.com', {})).toEqual({
        ok: true,
        value: { kind: 'direct' },
      });
    });

    it('follows env precedence for https and http targets and normalizes bare host:port', () => {
      const env = {
        HTTP_PROXY: '127.0.0.1:8080',
        HTTPS_PROXY: 'https://proxy.internal:8443',
        ALL_PROXY: 'socks5://127.0.0.1:1080',
      };

      expect(resolveProxyPolicy('http://example.com', env)).toEqual({
        ok: true,
        value: { kind: 'proxy', url: ProxyUrl('http://127.0.0.1:8080/'), protocol: 'http:' },
      });
      expect(resolveProxyPolicy('https://example.com', env)).toEqual({
        ok: true,
        value: { kind: 'proxy', url: ProxyUrl('https://proxy.internal:8443/'), protocol: 'https:' },
      });
      expect(resolveProxyPolicy('https://example.com', { all_proxy: 'socks5h://127.0.0.1:1080' })).toEqual({
        ok: true,
        value: { kind: 'proxy', url: ProxyUrl('socks5h://127.0.0.1:1080'), protocol: 'socks5h:' },
      });
      expect(
        resolveProxyPolicy('https://example.com', { HTTPS_PROXY: '   ', ALL_PROXY: 'socks5://127.0.0.1:1080' }),
      ).toEqual({
        ok: true,
        value: { kind: 'proxy', url: ProxyUrl('socks5://127.0.0.1:1080'), protocol: 'socks5:' },
      });
      expect(
        resolveProxyPolicy('https://example.com', {
          HTTPS_PROXY: 'http://proxy:8080',
          NO_PROXY: '   ',
          no_proxy: 'example.com',
        }),
      ).toEqual({
        ok: true,
        value: { kind: 'direct' },
      });
    });

    it('supports all SOCKS4/4a/5/5h schemes (D23)', () => {
      for (const proto of ['socks4:', 'socks4a:', 'socks5:', 'socks5h:'] as const) {
        const res = resolveProxyPolicy('https://example.com', {}, `${proto}//127.0.0.1:1080`);
        expect(res).toEqual({
          ok: true,
          value: { kind: 'proxy', url: ProxyUrl(`${proto}//127.0.0.1:1080`), protocol: proto },
        });
      }
    });

    it('honors NO_PROXY for env proxies while letting explicit CLI --proxy bypass NO_PROXY (PL-4, D24)', () => {
      const env = { HTTPS_PROXY: 'http://proxy:8080', NO_PROXY: '.example.com' };
      expect(resolveProxyPolicy('https://sub.example.com', env)).toEqual({
        ok: true,
        value: { kind: 'direct' },
      });
      expect(resolveProxyPolicy('https://sub.example.com', env, 'socks5://127.0.0.1:1080')).toEqual({
        ok: true,
        value: { kind: 'proxy', url: ProxyUrl('socks5://127.0.0.1:1080'), protocol: 'socks5:' },
      });
    });

    it('fails explicitly on unsupported protocols or malformed proxy URLs without leaking credentials (PL-5, D25)', () => {
      expect(resolveProxyPolicy('http://example.com', { HTTP_PROXY: 'ftp://proxy:21' })).toEqual({
        ok: false,
        error: {
          kind: 'invalid_proxy',
          message: 'Unsupported proxy protocol "ftp:" (supported: http, https, socks4, socks4a, socks5, socks5h)',
        },
      });
      expect(resolveProxyPolicy('http://example.com', {}, 'http://user:topsecret@bad host:80')).toEqual({
        ok: false,
        error: {
          kind: 'invalid_proxy',
          message: 'Invalid proxy URL: "http://<redacted>@bad host:80"',
        },
      });
      expect(resolveProxyPolicy('http://example.com', {}, 'user:topsecret@bad host:8080')).toEqual({
        ok: false,
        error: {
          kind: 'invalid_proxy',
          message: 'Invalid proxy URL: "<redacted>@bad host:8080"',
        },
      });
      expect(resolveProxyPolicy('http://example.com', { HTTP_PROXY: 'garbage' })).toEqual({
        ok: false,
        error: {
          kind: 'invalid_proxy',
          message: 'Invalid proxy URL: "garbage"',
        },
      });
      expect(resolveProxyPolicy('http://example.com', { HTTP_PROXY: 'http://envproxy:8080' }, '')).toEqual({
        ok: false,
        error: {
          kind: 'invalid_proxy',
          message: 'Invalid proxy URL: ""',
        },
      });
      expect(resolveProxyPolicy('http://example.com', {}, '   ')).toEqual({
        ok: false,
        error: {
          kind: 'invalid_proxy',
          message: 'Invalid proxy URL: "   "',
        },
      });
    });
  });
});
