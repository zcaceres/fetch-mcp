import { describe, expect, it } from 'bun:test';
import { executeFetch } from '../fetching/execute.ts';
import { createDnsMock } from '../integrations/dns/mock.ts';
import { createOriginMock } from '../integrations/origin/mock.ts';
import { err, ok } from '../shared/result.ts';
import { executeFetchTranscript } from './execute.ts';
import type { FetchPagePort } from './ports.ts';
import { parseCaptionXml } from './queries.ts';
import { extractCaptionTracks } from './verbs.ts';

// Real caption XML from YouTube video jNQXAC9IVRw ("Me at the zoo")
// Downloaded via yt-dlp --sub-format srv1
const realSrv1Xml = `<?xml version="1.0" encoding="utf-8" ?><transcript><text start="1.2" dur="2.16">All right, so here we are, in front of the
elephants</text><text start="5.318" dur="2.656">the cool thing about these guys is that they
have really...</text><text start="7.974" dur="4.642">really really long trunks</text><text start="12.616" dur="1.751">and that&amp;#39;s cool</text><text start="14.421" dur="1.312">(baaaaaaaaaaahhh!!)</text><text start="16.881" dur="2">and that&amp;#39;s pretty much all there is to
say</text></transcript>`;

// Same video, srv3 format (uses <p t="ms" d="ms"> tags)
const realSrv3Xml = `<?xml version="1.0" encoding="utf-8" ?><timedtext format="3">
<body>
<p t="1200" d="2160">All right, so here we are, in front of the
elephants</p>
<p t="5318" d="2656">the cool thing about these guys is that they
have really...</p>
<p t="7974" d="4642">really really long trunks</p>
<p t="12616" d="1751">and that&#39;s cool</p>
<p t="14421" d="1312">(baaaaaaaaaaahhh!!)</p>
<p t="16881" d="2000">and that&#39;s pretty much all there is to
say</p>
</body>
</timedtext>`;

const realPlayerResponse = {
  captions: {
    playerCaptionsTracklistRenderer: {
      captionTracks: [
        {
          baseUrl: 'https://www.youtube.com/api/timedtext?v=jNQXAC9IVRw&lang=en',
          name: { simpleText: 'English' },
          vssId: '.en',
          languageCode: 'en',
          isTranslatable: true,
        },
        {
          baseUrl: 'https://www.youtube.com/api/timedtext?v=jNQXAC9IVRw&lang=de',
          name: { simpleText: 'German' },
          vssId: '.de',
          languageCode: 'de',
          isTranslatable: true,
        },
      ],
    },
  },
};

const realPageHtml = `<!DOCTYPE html><html><head><title>Me at the zoo - YouTube</title></head><body><script>var ytInitialPlayerResponse = ${JSON.stringify(realPlayerResponse)};</script></body></html>`;

describe('transcript domain — real YouTube fixtures (D20, D21)', () => {
  it('parses real srv1 and srv3 XML with matching timestamps and decodes double-encoded &amp;#39;', () => {
    const srv1Lines = parseCaptionXml(realSrv1Xml);
    const srv3Lines = parseCaptionXml(realSrv3Xml);

    expect(srv1Lines).toHaveLength(6);
    expect(srv3Lines).toHaveLength(6);
    expect(srv1Lines[0]).toBe('[0:01] All right, so here we are, in front of the\nelephants');
    expect(srv1Lines[2]).toBe('[0:07] really really long trunks');
    expect(srv1Lines[3]).toBe("[0:12] and that's cool");
    expect(srv1Lines[4]).toBe('[0:14] (baaaaaaaaaaahhh!!)');
    expect(srv1Lines).toEqual(srv3Lines);
  });

  it('extracts caption tracks from realistic ytInitialPlayerResponse HTML', () => {
    const tracks = extractCaptionTracks(realPageHtml);
    expect(tracks.ok).toBe(true);
    if (tracks.ok) {
      expect(tracks.value).toHaveLength(2);
      expect(tracks.value[0]?.languageCode).toBe('en');
      expect(tracks.value[1]?.languageCode).toBe('de');
    }
  });

  it('executes end-to-end direct extraction for en, de, and fails listing available languages for fr (D20)', async () => {
    const origin = createOriginMock();
    const dns = createDnsMock();
    dns.set('www.youtube.com', ['142.250.190.78']);
    origin.serve('https://www.youtube.com/watch?v=jNQXAC9IVRw', 200, realPageHtml);
    origin.serve('https://www.youtube.com/api/timedtext?v=jNQXAC9IVRw&lang=en&fmt=srv1', 200, realSrv1Xml);
    origin.serve('https://www.youtube.com/api/timedtext?v=jNQXAC9IVRw&lang=de&fmt=srv1', 200, realSrv3Xml);

    const fetchPage: FetchPagePort = async (targetUrl, reqHeaders) => {
      const res = await executeFetch(
        { url: targetUrl, format: 'html', headers: reqHeaders, maxLength: 0 },
        { httpGet: origin.get, dnsLookup: dns.lookup },
      );
      if (!res.ok) {
        return err({
          kind: res.error.kind === 'blocked_url' ? 'blocked_url' : 'fetch_error',
          message: res.error.message,
        });
      }
      return ok(String(res.value));
    };

    const enRes = await executeFetchTranscript({ url: 'https://www.youtube.com/watch?v=jNQXAC9IVRw' }, { fetchPage });
    expect(enRes.ok).toBe(true);
    if (enRes.ok) {
      expect(String(enRes.value)).toContain('[Transcript language: en — English]');
      expect(String(enRes.value)).toContain("[0:12] and that's cool");
    }

    const deRes = await executeFetchTranscript(
      { url: 'https://www.youtube.com/watch?v=jNQXAC9IVRw', lang: 'de' },
      { fetchPage },
    );
    expect(deRes.ok).toBe(true);
    if (deRes.ok) {
      expect(String(deRes.value)).toContain('[Transcript language: de — German]');
    }

    const frRes = await executeFetchTranscript(
      { url: 'https://www.youtube.com/watch?v=jNQXAC9IVRw', lang: 'fr' },
      { fetchPage },
    );
    expect(frRes).toEqual({
      ok: false,
      error: {
        kind: 'language_not_found',
        message: 'No captions available in language "fr" (available: en, de)',
      },
    });
  });
});
