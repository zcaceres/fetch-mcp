import { describe, expect, it } from 'bun:test';
import { parseCliArgs, runCli } from './cli.ts';
import { createDnsMock } from './integrations/dns/mock.ts';
import { createOriginMock } from './integrations/origin/mock.ts';

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
    expect(parseCliArgs(['html', 'https://example.com', '--proxy']).ok).toBe(false);
    expect(parseCliArgs(['html', 'https://example.com', '--proxy', '--max-length', '10']).ok).toBe(false);
    expect(parseCliArgs(['html', 'https://example.com', '--lang']).ok).toBe(false);
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
