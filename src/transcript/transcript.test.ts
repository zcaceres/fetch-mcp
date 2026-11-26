import { describe, expect, it } from 'bun:test';
import { err, ok } from '../shared/result.ts';
import { executeFetchTranscript } from './execute.ts';
import { LanguageCode, Transcript, YouTubeUrl } from './nouns.ts';
import {
  buildYtDlpArgs,
  decodeHtmlEntities,
  isAllowedYouTubeHost,
  parseCaptionXml,
  windowedTranscript,
} from './queries.ts';
import { buildTranscript, extractCaptionTracks, prepareTranscriptRequest, selectCaptionTrack } from './verbs.ts';

describe('transcript domain (Slice 01)', () => {
  describe('isAllowedYouTubeHost', () => {
    it('allows canonical YouTube hosts regardless of case or trailing dot (I3)', () => {
      for (const host of [
        'youtube.com',
        'www.youtube.com',
        'WWW.YOUTUBE.COM.',
        'm.youtube.com',
        'music.youtube.com',
        'youtu.be',
      ]) {
        expect(isAllowedYouTubeHost(host)).toBe(true);
      }
    });

    it('rejects non-YouTube and spoofed hosts (I3)', () => {
      for (const host of ['example.com', 'evil-youtube.com', 'youtube.com.evil.com', 'localhost', '127.0.0.1']) {
        expect(isAllowedYouTubeHost(host)).toBe(false);
      }
    });
  });

  describe('prepareTranscriptRequest', () => {
    it('accepts a valid YouTube URL with defaults (D4, D9, I3)', () => {
      const result = prepareTranscriptRequest({ url: 'https://www.youtube.com/watch?v=abc123' });
      expect(result).toEqual({
        ok: true,
        value: {
          url: YouTubeUrl('https://www.youtube.com/watch?v=abc123'),
          lang: LanguageCode('en'),
          headers: {},
          window: { startIndex: 0, maxLength: 5000 },
        },
      });
    });

    it('rejects malformed URLs, disallowed schemes, and non-YouTube hosts (I1, I3)', () => {
      expect(prepareTranscriptRequest({ url: 'not-a-url' })).toEqual({
        ok: false,
        error: { kind: 'invalid_request', message: 'Invalid Target URL: "not-a-url"' },
      });
      expect(prepareTranscriptRequest({ url: 'file:///tmp/video' })).toEqual({
        ok: false,
        error: {
          kind: 'blocked_url',
          message: 'Blocked Target URL: disallowed scheme "file:" (only http: and https: are allowed)',
        },
      });
      expect(prepareTranscriptRequest({ url: 'https://example.com/watch?v=123' })).toEqual({
        ok: false,
        error: {
          kind: 'blocked_url',
          message: 'Blocked Target URL: host "example.com" is not an allowlisted YouTube domain',
        },
      });
    });

    it('rejects unsafe lang codes and invalid Window bounds (I3, D14)', () => {
      expect(prepareTranscriptRequest({ url: 'https://youtu.be/abc', lang: 'en;rm' })).toEqual({
        ok: false,
        error: {
          kind: 'invalid_request',
          message: 'Invalid language code "en;rm": only letters, digits, and hyphens are allowed',
        },
      });
      expect(prepareTranscriptRequest({ url: 'https://youtu.be/abc', lang: '--exec' })).toEqual({
        ok: false,
        error: {
          kind: 'invalid_request',
          message: 'Invalid language code "--exec": only letters, digits, and hyphens are allowed',
        },
      });
      expect(prepareTranscriptRequest({ url: 'https://youtu.be/abc', lang: '-o' })).toEqual({
        ok: false,
        error: {
          kind: 'invalid_request',
          message: 'Invalid language code "-o": only letters, digits, and hyphens are allowed',
        },
      });
      expect(prepareTranscriptRequest({ url: 'https://youtu.be/abc', lang: '' })).toEqual({
        ok: false,
        error: {
          kind: 'invalid_request',
          message: 'Invalid language code "": only letters, digits, and hyphens are allowed',
        },
      });
      expect(prepareTranscriptRequest({ url: 'https://youtu.be/abc', startIndex: -1 })).toEqual({
        ok: false,
        error: { kind: 'invalid_request', message: 'Invalid startIndex: must be a non-negative integer' },
      });
      expect(prepareTranscriptRequest({ url: 'https://youtu.be/abc', maxLength: -5 })).toEqual({
        ok: false,
        error: { kind: 'invalid_request', message: 'Invalid maxLength: must be a non-negative integer' },
      });
    });

    it('accepts regional language codes with digits and rejects CR/LF headers (D18)', () => {
      const valid = prepareTranscriptRequest({ url: 'https://youtu.be/abc', lang: 'es-419' });
      expect(valid.ok).toBe(true);

      expect(
        prepareTranscriptRequest({
          url: 'https://youtu.be/abc',
          headers: { 'X-Bad': 'ok\r\nEvil: 1' },
        }),
      ).toEqual({
        ok: false,
        error: {
          kind: 'invalid_request',
          message: 'Invalid header "X-Bad": CR/LF control characters are not allowed',
        },
      });
      expect(
        prepareTranscriptRequest({
          url: 'https://youtu.be/abc',
          headers: { 'X-Bad\nName': 'ok' },
        }),
      ).toEqual({
        ok: false,
        error: {
          kind: 'invalid_request',
          message: 'Invalid header "X-Bad\\nName": CR/LF control characters are not allowed',
        },
      });
    });
  });

  describe('extractCaptionTracks', () => {
    it('extracts valid caption tracks from ytInitialPlayerResponse HTML', () => {
      const html =
        '<html><script>var ytInitialPlayerResponse = {"captions":{"playerCaptionsTracklistRenderer":{"captionTracks":[{"baseUrl":"https://www.youtube.com/api/timedtext?v=1&lang=en","name":{"simpleText":"English"},"languageCode":"en"}]}}};</script></html>';
      expect(extractCaptionTracks(html)).toEqual({
        ok: true,
        value: [{ languageCode: 'en', name: 'English', baseUrl: 'https://www.youtube.com/api/timedtext?v=1&lang=en' }],
      });
    });

    it('fails explicitly when ytInitialPlayerResponse or captionTracks are missing (D14)', () => {
      expect(extractCaptionTracks('<html><body>No player</body></html>')).toEqual({
        ok: false,
        error: { kind: 'not_found', message: 'Could not find ytInitialPlayerResponse in page HTML' },
      });
      expect(
        extractCaptionTracks(
          '<html><script>var ytInitialPlayerResponse = {"captions":{"playerCaptionsTracklistRenderer":{"captionTracks":[]}}};</script></html>',
        ),
      ).toEqual({
        ok: false,
        error: { kind: 'not_found', message: 'No caption tracks found for this video' },
      });
    });
  });

  describe('selectCaptionTrack', () => {
    const tracks = [
      { languageCode: 'en-US', name: 'English (US)', baseUrl: 'https://www.youtube.com/api/timedtext?lang=en-US' },
      { languageCode: 'de', name: 'German', baseUrl: 'https://www.youtube.com/api/timedtext?lang=de' },
    ] as const;

    it('prefers case-insensitive exact match, then regional prefix match (D20)', () => {
      expect(selectCaptionTrack(tracks, LanguageCode('DE'))).toEqual({ ok: true, value: tracks[1] });
      expect(selectCaptionTrack(tracks, LanguageCode('en'))).toEqual({ ok: true, value: tracks[0] });
    });

    it('fails listing available language codes when requested lang is absent (D20)', () => {
      expect(selectCaptionTrack(tracks, LanguageCode('fr'))).toEqual({
        ok: false,
        error: {
          kind: 'language_not_found',
          message: 'No captions available in language "fr" (available: en-US, de)',
        },
      });
    });
  });

  describe('decodeHtmlEntities & parseCaptionXml', () => {
    it('decodes named, numeric decimal/hex, and double-encoded YouTube entities (D21)', () => {
      expect(decodeHtmlEntities('Tom &amp; Jerry &lt;3 &quot;hi&quot; &apos;a&apos;')).toBe(
        'Tom & Jerry <3 "hi" \'a\'',
      );
      expect(decodeHtmlEntities('that&amp;#39;s &#160;cool &#x26; &#x27;ok&#x27;')).toBe("that's \u00a0cool & 'ok'");
    });

    it('parses srv1 and srv3 XML, strips inline tags, and skips empty lines (D21)', () => {
      const srv1 =
        '<transcript><text start="1.2" dur="2.0">Hello &amp;#39;world&amp;#39;</text><text start="3.0" dur="1.0">  </text><text start="65.5" dur="1.0"><font color="#ccc">Minute</font> mark</text></transcript>';
      expect(parseCaptionXml(srv1)).toEqual(["[0:01] Hello 'world'", '[1:05] Minute mark']);

      const srv3 =
        '<timedtext format="3"><body><p t="0" d="2000">Hallo &#x26; Welt</p><p t="5200" d="1000">Zweite Zeile</p></body></timedtext>';
      expect(parseCaptionXml(srv3)).toEqual(['[0:00] Hallo & Welt', '[0:05] Zweite Zeile']);
    });
  });

  describe('buildTranscript & windowedTranscript', () => {
    it('formats Transcript with language header and timestamps (D4, D21)', () => {
      const res = buildTranscript('<transcript><text start="0" dur="2">Hi</text></transcript>', 'en', 'English');
      expect(res).toEqual({
        ok: true,
        value: Transcript('[Transcript language: en — English]\n\n[0:00] Hi'),
      });
    });

    it('fails explicitly when caption XML yields zero caption lines (D22)', () => {
      expect(buildTranscript('<transcript></transcript>', 'en', 'English')).toEqual({
        ok: false,
        error: { kind: 'parse_error', message: 'No caption lines found in transcript XML' },
      });
      expect(buildTranscript('<other>nope</other>', 'en', 'English')).toEqual({
        ok: false,
        error: { kind: 'parse_error', message: 'No caption lines found in transcript XML' },
      });
    });

    it('slices Transcript into a Windowed Excerpt cleanly (D9, D15)', () => {
      const t = Transcript('[Transcript language: de — German]\n\n[0:00] Hallo');
      expect(String(windowedTranscript(t, { startIndex: 0, maxLength: 34 }))).toBe(
        '[Transcript language: de — German]',
      );
      expect(String(windowedTranscript(t, { startIndex: 0, maxLength: 0 }))).toBe(String(t));
      expect(String(windowedTranscript(t, { startIndex: 500, maxLength: 10 }))).toBe('');
    });
  });

  describe('buildYtDlpArgs (D21)', () => {
    it('builds safe argv with --write-sub, --write-auto-sub, and -- end-of-options sentinel', () => {
      expect(buildYtDlpArgs(YouTubeUrl('https://www.youtube.com/watch?v=abc'), LanguageCode('en'), '/tmp/sub')).toEqual(
        [
          '--write-sub',
          '--write-auto-sub',
          '--sub-lang',
          'en',
          '--sub-format',
          'srv1',
          '--skip-download',
          '-o',
          '/tmp/sub',
          '--',
          'https://www.youtube.com/watch?v=abc',
        ],
      );
    });

    it('includes --proxy before the -- sentinel when provided', () => {
      expect(
        buildYtDlpArgs(
          YouTubeUrl('https://www.youtube.com/watch?v=abc'),
          LanguageCode('es'),
          '/tmp/sub',
          'http://proxy:8080',
        ),
      ).toEqual([
        '--write-sub',
        '--write-auto-sub',
        '--sub-lang',
        'es',
        '--sub-format',
        'srv1',
        '--skip-download',
        '-o',
        '/tmp/sub',
        '--proxy',
        'http://proxy:8080',
        '--',
        'https://www.youtube.com/watch?v=abc',
      ]);
    });
  });

  describe('executeFetchTranscript primary & fallback (FT-3, FT-4, D7, I3)', () => {
    it('uses yt-dlp first when available and skips watch-page scraping', async () => {
      let fetchPageCalls = 0;
      const result = await executeFetchTranscript(
        { url: 'https://www.youtube.com/watch?v=yt1', lang: 'en' },
        {
          fetchPage: async () => {
            fetchPageCalls++;
            return err({ kind: 'fetch_error', message: 'should not be called' });
          },
          ytDlp: {
            isAvailable: async () => true,
            downloadSubtitles: async () =>
              ok({
                xml: '<transcript><text start="2.0" dur="1.0">From yt-dlp</text></transcript>',
                lang: 'en',
                langName: 'en',
              }),
          },
        },
      );

      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(String(result.value)).toBe('[Transcript language: en — en]\n\n[0:02] From yt-dlp');
      }
      expect(fetchPageCalls).toBe(0);
    });

    it('falls back to direct extraction when yt-dlp fails or returns empty XML', async () => {
      const watchHtml =
        '<html><script>var ytInitialPlayerResponse = {"captions":{"playerCaptionsTracklistRenderer":{"captionTracks":[{"baseUrl":"https://www.youtube.com/api/timedtext?v=fb&lang=en","name":{"simpleText":"English"},"languageCode":"en"}]}}};</script></html>';
      const captionXml = '<transcript><text start="0" dur="2">Direct fallback</text></transcript>';

      const fetchPage = async (url: string) => ok(url.includes('timedtext') ? captionXml : watchHtml);

      const afterFail = await executeFetchTranscript(
        { url: 'https://www.youtube.com/watch?v=fb' },
        {
          fetchPage,
          ytDlp: {
            isAvailable: async () => true,
            downloadSubtitles: async () => err('yt-dlp exited with 1'),
          },
        },
      );
      expect(afterFail.ok).toBe(true);
      if (afterFail.ok) {
        expect(String(afterFail.value)).toBe('[Transcript language: en — English]\n\n[0:00] Direct fallback');
      }

      const afterEmptyXml = await executeFetchTranscript(
        { url: 'https://www.youtube.com/watch?v=fb' },
        {
          fetchPage,
          ytDlp: {
            isAvailable: async () => true,
            downloadSubtitles: async () => ok({ xml: '<transcript></transcript>', lang: 'en', langName: 'en' }),
          },
        },
      );
      expect(afterEmptyXml.ok).toBe(true);
      if (afterEmptyXml.ok) {
        expect(String(afterEmptyXml.value)).toBe('[Transcript language: en — English]\n\n[0:00] Direct fallback');
      }
    });

    it('never invokes yt-dlp or falls back on validation or checkHost SSRF errors (I2, I3)', async () => {
      let ytDlpCalls = 0;
      let fetchPageCalls = 0;
      const ports = {
        fetchPage: async () => {
          fetchPageCalls++;
          return ok('');
        },
        checkHost: async (hostname: string) =>
          err({
            kind: 'blocked_url' as const,
            message: `Blocked Target URL: hostname "${hostname}" resolved to private IP "10.0.0.1"`,
          }),
        ytDlp: {
          isAvailable: async () => true,
          downloadSubtitles: async () => {
            ytDlpCalls++;
            return ok({ xml: '', lang: 'en', langName: 'en' });
          },
        },
      };

      const badLang = await executeFetchTranscript(
        { url: 'https://www.youtube.com/watch?v=abc', lang: '--exec' },
        ports,
      );
      expect(badLang.ok).toBe(false);

      const badHost = await executeFetchTranscript({ url: 'https://example.com/watch?v=abc' }, ports);
      expect(badHost.ok).toBe(false);

      const rebind = await executeFetchTranscript({ url: 'https://www.youtube.com/watch?v=rebind' }, ports);
      expect(rebind).toEqual({
        ok: false,
        error: {
          kind: 'blocked_url',
          message: 'Blocked Target URL: hostname "www.youtube.com" resolved to private IP "10.0.0.1"',
        },
      });

      expect(ytDlpCalls).toBe(0);
      expect(fetchPageCalls).toBe(0);
    });
  });
});
