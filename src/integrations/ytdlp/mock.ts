import { err, ok, type Result } from '../../shared/result.ts';
import type { LanguageCode, YouTubeUrl } from '../../transcript/nouns.ts';
import type { YtDlpPort, YtDlpResult } from '../../transcript/ports.ts';
import { buildYtDlpArgs } from '../../transcript/queries.ts';

type YtDlpEntry =
  | { readonly kind: 'xml'; readonly lang: string; readonly xml: string }
  | { readonly kind: 'empty' }
  | { readonly kind: 'fail'; readonly reason: string }
  | { readonly kind: 'timeout' };

export type YtDlpMock = YtDlpPort & {
  readonly setAvailable: (available: boolean) => void;
  readonly serve: (url: string, lang: string, xml: string) => void;
  readonly empty: (url: string) => void;
  readonly fail: (url: string, reason: string) => void;
  readonly timeout: (url: string) => void;
  readonly lastArgs: () => readonly string[] | undefined;
};

export const createYtDlpMock = (): YtDlpMock => {
  let available = false;
  let recordedArgs: readonly string[] | undefined;
  const routes = new Map<string, YtDlpEntry>();

  const normalizeKey = (url: string): string => {
    try {
      return new URL(url).href;
    } catch {
      return url;
    }
  };

  const downloadSubtitles = async (
    url: YouTubeUrl,
    lang: LanguageCode,
    proxyUrl?: string,
  ): Promise<Result<YtDlpResult, string>> => {
    recordedArgs = buildYtDlpArgs(url, lang, '<tmp>/sub', proxyUrl);
    const entry = routes.get(normalizeKey(url));
    if (!entry || entry.kind === 'empty') {
      return err('yt-dlp did not produce subtitle files');
    }
    if (entry.kind === 'fail') {
      return err(entry.reason);
    }
    if (entry.kind === 'timeout') {
      return err('yt-dlp timed out after 30000ms');
    }
    const target = lang.toLowerCase();
    const entryLang = entry.lang.toLowerCase();
    if (entryLang !== target && !entryLang.startsWith(`${target}-`)) {
      return err(`yt-dlp did not produce subtitles for language "${lang}"`);
    }
    return ok({ xml: entry.xml, lang: entry.lang, langName: entry.lang });
  };

  return {
    isAvailable: async () => available,
    downloadSubtitles,
    setAvailable: (flag) => {
      available = flag;
    },
    serve: (url, lang, xml) => {
      routes.set(normalizeKey(url), { kind: 'xml', lang, xml });
    },
    empty: (url) => {
      routes.set(normalizeKey(url), { kind: 'empty' });
    },
    fail: (url, reason) => {
      routes.set(normalizeKey(url), { kind: 'fail', reason });
    },
    timeout: (url) => {
      routes.set(normalizeKey(url), { kind: 'timeout' });
    },
    lastArgs: () => recordedArgs,
  };
};
