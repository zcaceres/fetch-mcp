import { describe, expect, it } from 'bun:test';
import { parseCliArgs, runCli } from './cli.ts';
import { createDnsMock } from './integrations/dns/mock.ts';
import { createOriginMock } from './integrations/origin/mock.ts';
import { createYtDlpMock } from './integrations/ytdlp/mock.ts';

describe('parseCliArgs (D12)', () => {
  it('parses all six aligned subcommands', () => {
    for (const cmd of ['html', 'markdown', 'readable', 'text', 'json'] as const) {
      const result = parseCliArgs([cmd, 'https://example.com']);
      expect(result.ok).toBe(true);
      if (result.ok && result.value.kind === 'fetch') {
        expect(result.value.format).toBe(cmd);
        expect(result.value.url).toBe('https://example.com');
      }
    }

    const transcript = parseCliArgs(['transcript', 'https://www.youtube.com/watch?v=abc', '--lang', 'es']);
    expect(transcript).toEqual({
      ok: true,
      value: {
        kind: 'transcript',
        url: 'https://www.youtube.com/watch?v=abc',
        headers: {},
        lang: 'es',
      },
    });
  });

  it('parses repeatable --header flags alongside --max-length, --start-index, and --proxy', () => {
    const result = parseCliArgs([
      'markdown',
      'https://example.com',
      '--header',
      'Accept: text/html',
      '--header',
      'X-Custom: val:with:colons',
      '--max-length',
      '1000',
      '--start-index',
      '50',
      '--proxy',
      'http://proxy:8080',
    ]);
    expect(result).toEqual({
      ok: true,
      value: {
        kind: 'fetch',
        format: 'markdown',
        url: 'https://example.com',
        headers: {
          Accept: 'text/html',
          'X-Custom': 'val:with:colons',
        },
        maxLength: 1000,
        startIndex: 50,
        proxy: 'http://proxy:8080',
      },
    });
  });

  it('handles --help, empty args, and --version', () => {
    expect(parseCliArgs(['--help'])).toEqual({ ok: true, value: { kind: 'help' } });
    expect(parseCliArgs([])).toEqual({ ok: true, value: { kind: 'help' } });
    expect(parseCliArgs(['--version'])).toEqual({ ok: true, value: { kind: 'version' } });
  });

  it('rejects unknown subcommands (including removed legacy names txt/youtube), missing URL, and invalid flags', () => {
    expect(parseCliArgs(['txt', 'https://example.com']).ok).toBe(false);
    expect(parseCliArgs(['youtube', 'https://youtube.com']).ok).toBe(false);
    expect(parseCliArgs(['foobar', 'https://example.com']).ok).toBe(false);
    expect(parseCliArgs(['html']).ok).toBe(false);
    expect(parseCliArgs(['html', 'https://example.com', '--unknown']).ok).toBe(false);
    expect(parseCliArgs(['html', 'https://example.com', '--max-length']).ok).toBe(false);
    expect(parseCliArgs(['html', 'https://example.com', '--max-length', 'abc']).ok).toBe(false);
    expect(parseCliArgs(['html', 'https://example.com', '--max-length', '-1']).ok).toBe(false);
    expect(parseCliArgs(['html', 'https://example.com', '--start-index', '-5']).ok).toBe(false);
    expect(parseCliArgs(['html', 'https://example.com', '--header']).ok).toBe(false);
    expect(parseCliArgs(['html', 'https://example.com', '--header', 'no-colon']).ok).toBe(false);
    expect(parseCliArgs(['html', 'https://example.com', '--header', ' : v']).ok).toBe(false);
    expect(parseCliArgs(['html', 'https://example.com', '--proxy']).ok).toBe(false);
    expect(parseCliArgs(['html', 'https://example.com', '--proxy', '--max-length', '10']).ok).toBe(false);
    expect(parseCliArgs(['html', 'https://example.com', '--lang']).ok).toBe(false);
    expect(parseCliArgs(['html', 'https://example.com', '--lang', 'fr'])).toEqual({
      ok: false,
      error: '--lang is only valid with the "transcript" command',
    });
  });

  it('preserves CR/LF, control, and non-Latin-1 header violations across trimming and duplicate exact-case flags (D18)', () => {
    const trailingCrlf = parseCliArgs(['html', 'https://example.com', '--header', 'X-Bad: val\r\n']);
    expect(trailingCrlf.ok).toBe(true);
    if (trailingCrlf.ok && trailingCrlf.value.kind === 'fetch') {
      expect(trailingCrlf.value.headers['X-Bad']).toBe('val\r\n');
    }

    const leadingCrlf = parseCliArgs(['html', 'https://example.com', '--header', '\r\nX-Bad: val']);
    expect(leadingCrlf.ok).toBe(true);
    if (leadingCrlf.ok && leadingCrlf.value.kind === 'fetch') {
      expect(Object.keys(leadingCrlf.value.headers)).toEqual(['\r\nX-Bad']);
    }

    const dupCrlf = parseCliArgs([
      'html',
      'https://example.com',
      '--header',
      'X-A: bad\r\nEvil: 1',
      '--header',
      'X-A: good',
    ]);
    expect(dupCrlf.ok).toBe(true);
    if (dupCrlf.ok && dupCrlf.value.kind === 'fetch') {
      expect(dupCrlf.value.headers['X-A']).toContain('\r\n');
    }

    const dupNul = parseCliArgs([
      'html',
      'https://example.com',
      '--header',
      'X-A: bad\u0000val',
      '--header',
      'X-A: good',
    ]);
    expect(dupNul.ok).toBe(true);
    if (dupNul.ok && dupNul.value.kind === 'fetch') {
      expect(dupNul.value.headers['X-A']).toBe('bad\u0000val');
    }
  });
});

describe('runCli (FW-15)', () => {
  it('writes Windowed Excerpt to stdout and returns exit code 0 on success', async () => {
    const origin = createOriginMock();
    const dns = createDnsMock();
    origin.serve('https://example.com/', 200, '<h3>Hello</h3> <p>World</p>');

    let out = '';
    let errOut = '';
    const code = await runCli(
      ['text', 'https://example.com/', '--header', 'Accept: text/html', '--start-index', '0', '--max-length', '5'],
      {
        ports: { httpGet: origin.get, dnsLookup: dns.lookup },
        stdout: (s) => {
          out += s;
        },
        stderr: (s) => {
          errOut += s;
        },
      },
    );

    expect(code).toBe(0);
    expect(out).toBe('Hello');
    expect(errOut).toBe('');
    expect(origin.lastHeaders('https://example.com/')?.Accept).toBe('text/html');
  });

  it('writes typed error message to stderr and returns exit code 1 on SSRF or HTTP failure', async () => {
    const origin = createOriginMock();
    const dns = createDnsMock();

    let out = '';
    let errOut = '';
    const code = await runCli(['html', 'http://127.0.0.1/secret'], {
      ports: { httpGet: origin.get, dnsLookup: dns.lookup },
      stdout: (s) => {
        out += s;
      },
      stderr: (s) => {
        errOut += s;
      },
    });

    expect(code).toBe(1);
    expect(out).toBe('');
    expect(errOut).toBe('Blocked Target URL: private address "127.0.0.1"\n');
  });

  it('prints usage on --help and version on --version with exit code 0', async () => {
    let helpOut = '';
    const helpCode = await runCli(['--help'], {
      stdout: (s) => {
        helpOut += s;
      },
      stderr: () => {},
    });
    expect(helpCode).toBe(0);
    expect(helpOut).toContain('Usage: mcp-fetch <command> <url> [flags]');
    expect(helpOut).toContain('--header <Key:Value>');

    let versionOut = '';
    const versionCode = await runCli(['--version'], {
      stdout: (s) => {
        versionOut += s;
      },
      stderr: () => {},
    });
    expect(versionCode).toBe(0);
    expect(versionOut).toMatch(/^\d+\.\d+\.\d+\n$/);
  });
});

describe('runCli transcript (FT-10)', () => {
  it('uses yt-dlp primary via executeFetchTranscript and writes Windowed Excerpt to stdout with exit 0', async () => {
    const origin = createOriginMock();
    const dns = createDnsMock();
    dns.set('www.youtube.com', ['142.250.190.78']);
    const ytDlp = createYtDlpMock();
    ytDlp.setAvailable(true);
    ytDlp.serve(
      'https://www.youtube.com/watch?v=cli1',
      'en-US',
      '<transcript><text start="1.0" dur="2.0">Hello CLI</text></transcript>',
    );

    let out = '';
    let errOut = '';
    const code = await runCli(
      [
        'transcript',
        'https://www.youtube.com/watch?v=cli1',
        '--lang',
        'en',
        '--start-index',
        '0',
        '--max-length',
        '54',
      ],
      {
        ports: { httpGet: origin.get, dnsLookup: dns.lookup },
        ytDlp,
        stdout: (s) => {
          out += s;
        },
        stderr: (s) => {
          errOut += s;
        },
      },
    );

    expect(code).toBe(0);
    expect(out).toBe('[Transcript language: en-US — en-US]\n\n[0:01] Hello CLI');
    expect(errOut).toBe('');
    expect(origin.lastHeaders('https://www.youtube.com/watch?v=cli1')).toBeUndefined();
  });

  it('falls back to direct extraction when yt-dlp fails and honors --lang and --header', async () => {
    const origin = createOriginMock();
    const dns = createDnsMock();
    dns.set('www.youtube.com', ['142.250.190.78']);
    origin.serve(
      'https://www.youtube.com/watch?v=cli2',
      200,
      '<html><script>var ytInitialPlayerResponse = {"captions":{"playerCaptionsTracklistRenderer":{"captionTracks":[{"baseUrl":"https://www.youtube.com/api/timedtext?v=cli2&lang=de","name":{"simpleText":"German"},"languageCode":"de"}]}}};</script></html>',
    );
    origin.serve(
      'https://www.youtube.com/api/timedtext?v=cli2&lang=de&fmt=srv1',
      200,
      '<transcript><text start="0" dur="2">Hallo CLI</text></transcript>',
    );
    const ytDlp = createYtDlpMock();
    ytDlp.setAvailable(true);
    ytDlp.fail('https://www.youtube.com/watch?v=cli2', 'exit 1');

    let out = '';
    let errOut = '';
    const code = await runCli(
      ['transcript', 'https://www.youtube.com/watch?v=cli2', '--lang', 'de', '--header', 'Accept-Language: de'],
      {
        ports: { httpGet: origin.get, dnsLookup: dns.lookup },
        ytDlp,
        stdout: (s) => {
          out += s;
        },
        stderr: (s) => {
          errOut += s;
        },
      },
    );

    expect(code).toBe(0);
    expect(out).toBe('[Transcript language: de — German]\n\n[0:00] Hallo CLI');
    expect(errOut).toBe('');
    expect(origin.lastHeaders('https://www.youtube.com/watch?v=cli2')?.['Accept-Language']).toBe('de');
  });

  it('writes typed error to stderr with exit 1 on non-YouTube host, DNS SSRF, or missing language', async () => {
    const origin = createOriginMock();
    const dns = createDnsMock();
    dns.set('www.youtube.com', ['10.0.0.1']);
    const ytDlp = createYtDlpMock();
    ytDlp.setAvailable(true);

    let errHost = '';
    const hostCode = await runCli(['transcript', 'https://example.com/not-youtube'], {
      ports: { httpGet: origin.get, dnsLookup: dns.lookup },
      ytDlp,
      stdout: () => {},
      stderr: (s) => {
        errHost += s;
      },
    });
    expect(hostCode).toBe(1);
    expect(errHost).toBe('Blocked Target URL: host "example.com" is not an allowlisted YouTube domain\n');
    expect(ytDlp.lastArgs()).toBeUndefined();

    let errDns = '';
    const dnsCode = await runCli(['transcript', 'https://www.youtube.com/watch?v=rebind'], {
      ports: { httpGet: origin.get, dnsLookup: dns.lookup },
      ytDlp,
      stdout: () => {},
      stderr: (s) => {
        errDns += s;
      },
    });
    expect(dnsCode).toBe(1);
    expect(errDns).toBe('Blocked Target URL: hostname "www.youtube.com" resolved to private IP "10.0.0.1"\n');
    expect(ytDlp.lastArgs()).toBeUndefined();
  });
});

describe('runCli proxy & Operator limits (PL-10)', () => {
  it('enforces valid DEFAULT_LIMIT and MAX_RESPONSE_BYTES and fails fast on invalid env values (D25)', async () => {
    const origin = createOriginMock();
    const dns = createDnsMock();
    origin.serve('https://example.com/data', 200, '<p>0123456789</p>');

    let out = '';
    const okCode = await runCli(['html', 'https://example.com/data'], {
      ports: { httpGet: origin.get, dnsLookup: dns.lookup },
      env: { DEFAULT_LIMIT: '6', MAX_RESPONSE_BYTES: '100' },
      stdout: (s) => {
        out += s;
      },
      stderr: () => {},
    });
    expect(okCode).toBe(0);
    expect(out).toBe('<p>012');

    let errLimit = '';
    const badLimitCode = await runCli(['html', 'https://example.com/data'], {
      ports: { httpGet: origin.get, dnsLookup: dns.lookup },
      env: { DEFAULT_LIMIT: 'bad' },
      stdout: () => {},
      stderr: (s) => {
        errLimit += s;
      },
    });
    expect(badLimitCode).toBe(1);
    expect(errLimit).toBe('Invalid DEFAULT_LIMIT "bad": must be a non-negative integer\n');

    let errMax = '';
    const badMaxCode = await runCli(['transcript', 'https://www.youtube.com/watch?v=abc'], {
      ports: { httpGet: origin.get, dnsLookup: dns.lookup },
      ytDlp: createYtDlpMock(),
      env: { MAX_RESPONSE_BYTES: '0' },
      stdout: () => {},
      stderr: (s) => {
        errMax += s;
      },
    });
    expect(badMaxCode).toBe(1);
    expect(errMax).toBe('Invalid MAX_RESPONSE_BYTES "0": must be a positive integer\n');
  });

  it('applies Operator env proxies, NO_PROXY, and explicit --proxy override across web subcommands (D24, D25)', async () => {
    const origin = createOriginMock();
    const dns = createDnsMock();
    dns.fail('remote.invalid', 'ENOTFOUND');
    origin.serve('https://remote.invalid/page', 200, '<p>proxied-cli</p>');

    let out = '';
    const envCode = await runCli(['html', 'https://remote.invalid/page'], {
      ports: { httpGet: origin.get, dnsLookup: dns.lookup },
      env: { HTTPS_PROXY: 'socks5://127.0.0.1:1080' },
      stdout: (s) => {
        out += s;
      },
      stderr: () => {},
    });
    expect(envCode).toBe(0);
    expect(out).toBe('<p>proxied-cli</p>');
    expect(origin.lastProxy('https://remote.invalid/page')).toBe('socks5://127.0.0.1:1080');

    let overrideOut = '';
    const overrideCode = await runCli(['html', 'https://remote.invalid/page', '--proxy', 'socks5h://127.0.0.1:1081'], {
      ports: { httpGet: origin.get, dnsLookup: dns.lookup },
      env: { HTTPS_PROXY: 'http://ignored:8080', NO_PROXY: 'remote.invalid' },
      stdout: (s) => {
        overrideOut += s;
      },
      stderr: () => {},
    });
    expect(overrideCode).toBe(0);
    expect(overrideOut).toBe('<p>proxied-cli</p>');
    expect(origin.lastProxy('https://remote.invalid/page')).toBe('socks5h://127.0.0.1:1081');

    let errProxy = '';
    const badProxyCode = await runCli(['html', 'http://example.com/nope'], {
      ports: { httpGet: origin.get, dnsLookup: dns.lookup },
      env: { HTTP_PROXY: 'ftp://proxy:21' },
      stdout: () => {},
      stderr: (s) => {
        errProxy += s;
      },
    });
    expect(badProxyCode).toBe(1);
    expect(errProxy).toBe(
      'Unsupported proxy protocol "ftp:" (supported: http, https, socks4, socks4a, socks5, socks5h)\n',
    );
    expect(origin.lastProxy('http://example.com/nope')).toBeUndefined();
  });

  it('delegates DNS and forwards --proxy to yt-dlp and direct fallback for mcp-fetch transcript (D26)', async () => {
    const origin = createOriginMock();
    const dns = createDnsMock();
    dns.fail('www.youtube.com', 'ENOTFOUND');
    const ytDlp = createYtDlpMock();
    ytDlp.setAvailable(true);
    ytDlp.serve(
      'https://www.youtube.com/watch?v=proxcli',
      'en',
      '<transcript><text start="0" dur="1">Proxied transcript</text></transcript>',
    );

    let out = '';
    const code = await runCli(
      ['transcript', 'https://www.youtube.com/watch?v=proxcli', '--proxy', 'socks5://127.0.0.1:1080'],
      {
        ports: { httpGet: origin.get, dnsLookup: dns.lookup },
        ytDlp,
        env: { NO_PROXY: 'www.youtube.com' },
        stdout: (s) => {
          out += s;
        },
        stderr: () => {},
      },
    );
    expect(code).toBe(0);
    expect(out).toBe('[Transcript language: en — en]\n\n[0:00] Proxied transcript');
    expect(ytDlp.lastArgs()).toContain('--proxy');
    expect(ytDlp.lastArgs()).toContain('socks5://127.0.0.1:1080');
  });
});
