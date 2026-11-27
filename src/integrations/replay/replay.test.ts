import { describe, expect, it } from 'bun:test';
import { LIVE_SAMPLES } from '../../verification/samples.ts';
import { createDnsMock } from '../dns/mock.ts';
import { createOriginMock } from '../origin/mock.ts';
import { recordLiveExchangeChain, recordLiveSampleExchanges, runVerificationMatrix } from './runner.ts';

describe('offline multi-form-factor cassette replay matrix (LV-3, LV-4, LV-5, D32, D33, D34, D35)', () => {
  it('replays all 8 curated real-world Live Samples across cli, mcp-stdio, and mcp-http with zero SSRF backdoors', async () => {
    const report = await runVerificationMatrix({ mode: 'replay' });

    expect(report.mode).toBe('replay');
    expect(report.totals.fail).toBe(0);
    expect(report.totals.skippedEnv).toBe(0);
    expect(report.totals.pass).toBe(LIVE_SAMPLES.length * 3);
    expect(report.ok).toBe(true);
  }, 30_000);

  it('recordLiveExchangeChain enforces SSRF guards and strips sensitive headers across cross-origin redirects (I1, I4, D8, D9)', async () => {
    const origin = createOriginMock();
    const dns = createDnsMock();
    dns.set('a.example.com', ['93.184.216.34']);
    dns.set('b.example.com', ['93.184.216.35']);
    origin.serve('https://a.example.com/start', 302, '', { Location: 'https://b.example.com/dest' });
    origin.serve('https://b.example.com/dest', 200, 'ok');
    origin.serve('https://a.example.com/to-loopback', 302, '', { Location: 'http://127.0.0.1/secret' });

    const ports = { httpGet: origin.get, dnsLookup: dns.lookup };

    await expect(recordLiveExchangeChain('http://127.0.0.1/secret', undefined, ports)).rejects.toThrow(
      'Blocked Target URL: private address "127.0.0.1"',
    );

    await expect(recordLiveExchangeChain('https://a.example.com/to-loopback', undefined, ports)).rejects.toThrow(
      'Blocked Target URL: private address "127.0.0.1"',
    );

    const exchanges = await recordLiveExchangeChain(
      'https://a.example.com/start',
      { Authorization: 'Bearer secret', Cookie: 'sid=1', 'X-Trace': 'keep' },
      ports,
    );
    expect(exchanges).toHaveLength(2);
    expect(origin.lastHeaders('https://a.example.com/start')).toMatchObject({
      Authorization: 'Bearer secret',
      Cookie: 'sid=1',
      'X-Trace': 'keep',
    });
    expect(origin.lastHeaders('https://b.example.com/dest')).not.toHaveProperty('Authorization');
    expect(origin.lastHeaders('https://b.example.com/dest')).not.toHaveProperty('Cookie');
    expect(origin.lastHeaders('https://b.example.com/dest')).toMatchObject({ 'X-Trace': 'keep' });
  });

  it('recordLiveSampleExchanges captures both watch page and srv1 caption XML for fetch_transcript samples (LV-6, D34, I4)', async () => {
    const origin = createOriginMock();
    const dns = createDnsMock();
    dns.set('www.youtube.com', ['142.250.190.78']);
    dns.set('captions.example.com', ['93.184.216.34']);

    const watchUrl = 'https://www.youtube.com/watch?v=demo';
    const trackBase = 'https://captions.example.com/api/timedtext?v=demo&lang=en';
    origin.serve(
      watchUrl,
      200,
      `<html><script>var ytInitialPlayerResponse = ${JSON.stringify({
        captions: {
          playerCaptionsTracklistRenderer: {
            captionTracks: [{ baseUrl: trackBase, languageCode: 'en', name: { simpleText: 'English' } }],
          },
        },
      })};</script></html>`,
    );
    origin.serve(`${trackBase}&fmt=srv1`, 200, '<transcript><text start="0" dur="1">Hello</text></transcript>');

    const exchanges = await recordLiveSampleExchanges(
      {
        id: 'yt-demo',
        category: 'youtube-transcript',
        description: 'Demo transcript',
        tool: 'fetch_transcript',
        cliSubcommand: 'transcript',
        url: watchUrl,
        lang: 'en',
        headers: { Authorization: 'Bearer yt-secret' },
        checks: [{ kind: 'expect_ok' }],
      },
      { httpGet: origin.get, dnsLookup: dns.lookup },
    );

    expect(exchanges.map((e) => e.url)).toEqual([watchUrl, `${trackBase}&fmt=srv1`]);
    expect(origin.lastHeaders(`${trackBase}&fmt=srv1`)).not.toHaveProperty('Authorization');
  });
});
