import {
  type Headers,
  type LanguageCode,
  type TargetUrl,
  type Transcript,
  type Window,
  WindowedExcerpt,
} from './nouns.ts';

const SENSITIVE_CROSS_ORIGIN_HEADERS: ReadonlySet<string> = new Set(['authorization', 'cookie', 'proxy-authorization']);

export const ALLOWED_YOUTUBE_HOSTS: ReadonlySet<string> = new Set([
  'youtube.com',
  'www.youtube.com',
  'm.youtube.com',
  'music.youtube.com',
  'youtu.be',
]);

const normalizeHostname = (hostname: string): string => {
  const bare = hostname.startsWith('[') && hostname.endsWith(']') ? hostname.slice(1, -1) : hostname;
  return bare.toLowerCase().replace(/\.+$/, '');
};

/**
 * Returns true if `hostname` belongs to the allowlisted YouTube domains (I3).
 */
export const isAllowedYouTubeHost = (hostname: string): boolean =>
  ALLOWED_YOUTUBE_HOSTS.has(normalizeHostname(hostname));

/**
 * Decodes named, numeric decimal/hex, and YouTube's double-encoded HTML entities (D21).
 */
export const decodeHtmlEntities = (text: string): string =>
  text
    .replace(/&amp;/g, '&')
    .replace(/&#(\d+);/g, (match, dec: string) => {
      const code = Number.parseInt(dec, 10);
      return code >= 0 && code <= 0x10ffff ? String.fromCodePoint(code) : match;
    })
    .replace(/&#[xX]([0-9a-fA-F]+);/g, (match, hex: string) => {
      const code = Number.parseInt(hex, 16);
      return code >= 0 && code <= 0x10ffff ? String.fromCodePoint(code) : match;
    })
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&nbsp;/g, '\u00a0');

const formatTimestamp = (totalSeconds: number): string => {
  const safe = Number.isFinite(totalSeconds) && totalSeconds >= 0 ? totalSeconds : 0;
  const minutes = Math.floor(safe / 60);
  const seconds = Math.floor(safe % 60);
  return `${minutes}:${seconds.toString().padStart(2, '0')}`;
};

/**
 * Parses YouTube `srv1` (`<text start="...">`) or `srv3` (`<p t="...">`) XML into timestamped lines (D21).
 */
export const parseCaptionXml = (xml: string): readonly string[] => {
  const lines: string[] = [];
  const textRegex = /<text\s+[^>]*start="([^"]+)"[^>]*>([\s\S]*?)<\/text>/g;
  const pRegex = /<p\s+[^>]*t="(\d+)"[^>]*>([\s\S]*?)<\/p>/g;

  const firstText = textRegex.exec(xml);
  if (firstText !== null) {
    textRegex.lastIndex = 0;
    for (let match = textRegex.exec(xml); match !== null; match = textRegex.exec(xml)) {
      const seconds = Number.parseFloat(match[1] ?? '0');
      const raw = (match[2] ?? '').replace(/<[^>]+>/g, '');
      const content = decodeHtmlEntities(raw).trim();
      if (content.length > 0) {
        lines.push(`[${formatTimestamp(seconds)}] ${content}`);
      }
    }
    return lines;
  }

  for (let match = pRegex.exec(xml); match !== null; match = pRegex.exec(xml)) {
    const ms = Number.parseInt(match[1] ?? '0', 10);
    const raw = (match[2] ?? '').replace(/<[^>]+>/g, '');
    const content = decodeHtmlEntities(raw).trim();
    if (content.length > 0) {
      lines.push(`[${formatTimestamp(ms / 1000)}] ${content}`);
    }
  }

  return lines;
};

/**
 * Builds the `yt-dlp` argv array with manual + auto-generated subtitles enabled and the `--` end-of-options
 * sentinel immediately before the Target URL (D21).
 */
export const buildYtDlpArgs = (
  url: TargetUrl,
  lang: LanguageCode,
  outputTemplate: string,
  proxy?: string,
): readonly string[] => [
  '--write-sub',
  '--write-auto-sub',
  '--sub-lang',
  lang,
  '--sub-format',
  'srv1',
  '--skip-download',
  '-o',
  outputTemplate,
  ...(proxy ? ['--proxy', proxy] : []),
  '--',
  url,
];

/**
 * Strips Authorization, Cookie, and Proxy-Authorization when moving across origins (D7, I4).
 */
export const stripCrossOriginHeaders = (fromUrl: string, toUrl: string, headers: Headers): Headers => {
  try {
    if (new URL(fromUrl).origin === new URL(toUrl).origin) {
      return headers;
    }
  } catch {
    // Fail closed and strip sensitive headers when either URL cannot be parsed
  }

  const filtered: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    if (!SENSITIVE_CROSS_ORIGIN_HEADERS.has(key.toLowerCase())) {
      filtered[key] = value;
    }
  }
  return filtered;
};

/**
 * Slices a Transcript into a Windowed Excerpt (D9, D14, D15, D19).
 * Returns sliced text only, with no appended footer or metadata.
 */
export const windowedExcerpt = (transcript: Transcript, window: Window): WindowedExcerpt => {
  if (window.startIndex >= transcript.length) {
    return WindowedExcerpt('');
  }
  if (window.maxLength === 0) {
    return WindowedExcerpt(transcript.slice(window.startIndex));
  }
  return WindowedExcerpt(transcript.slice(window.startIndex, window.startIndex + window.maxLength));
};
