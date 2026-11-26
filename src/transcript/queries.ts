import { type Transcript, type Window, WindowedExcerpt } from './nouns.ts';

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
    .replace(/&#x([0-9a-fA-F]+);/g, (match, hex: string) => {
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
 * Slices a Transcript into a Windowed Excerpt (D9, D14, D15, D19).
 * Returns sliced text only, with no appended footer or metadata.
 */
export const windowedTranscript = (transcript: Transcript, window: Window): WindowedExcerpt => {
  if (window.startIndex >= transcript.length) {
    return WindowedExcerpt('');
  }
  if (window.maxLength === 0) {
    return WindowedExcerpt(transcript.slice(window.startIndex));
  }
  return WindowedExcerpt(transcript.slice(window.startIndex, window.startIndex + window.maxLength));
};
