import { z } from 'zod';
import { err, ok, type Result } from '../shared/result.ts';
import {
  type CaptionTrack,
  type FetchRequest,
  type Headers,
  LanguageCode,
  type RawTranscriptInput,
  TargetUrl,
  Transcript,
  type TranscriptError,
} from './nouns.ts';
import { isAllowedYouTubeHost, parseCaptionXml } from './queries.ts';

export const DEFAULT_TRANSCRIPT_LIMIT = 5000;
const SAFE_LANG_REGEX = /^[a-zA-Z0-9][a-zA-Z0-9-]*$/;
const CRLF_REGEX = /[\r\n]/;
const HTTP_HEADER_NAME_REGEX = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;

const hasInvalidHeaderValueChar = (value: string): boolean => {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if ((code < 0x20 && code !== 0x09) || code === 0x7f || code > 0xff) {
      return true;
    }
  }
  return false;
};

const normalizeHostDisplay = (hostname: string): string => {
  const bare = hostname.startsWith('[') && hostname.endsWith(']') ? hostname.slice(1, -1) : hostname;
  return bare.toLowerCase().replace(/\.+$/, '');
};

const isNonNegativeInt = (n: number): boolean => Number.isInteger(n) && n >= 0;

const validateHeaders = (rawHeaders: Headers | undefined): Result<Headers, TranscriptError> => {
  const deduped = new Map<string, readonly [string, string]>();
  for (const [key, value] of Object.entries(rawHeaders ?? {})) {
    if (CRLF_REGEX.test(key) || CRLF_REGEX.test(value)) {
      return err({
        kind: 'invalid_request',
        message: `Invalid header ${JSON.stringify(key)}: CR/LF control characters are not allowed`,
      });
    }
    if (!HTTP_HEADER_NAME_REGEX.test(key)) {
      return err({
        kind: 'invalid_request',
        message: `Invalid header ${JSON.stringify(key)}: header name must be a valid HTTP token`,
      });
    }
    if (hasInvalidHeaderValueChar(value)) {
      return err({
        kind: 'invalid_request',
        message: `Invalid header ${JSON.stringify(key)}: invalid character in header value`,
      });
    }
    deduped.set(key.toLowerCase(), [key, value]);
  }
  const result: Record<string, string> = {};
  for (const [key, value] of deduped.values()) {
    result[key] = value;
  }
  return ok(result);
};

/**
 * Validates a YouTube transcript Fetch Request against URL allowlist, lang code, Window bounds,
 * and CR/LF header rules before any subprocess or network I/O (D4, D8, D9, D14, D18, D19, I1, I3).
 */
export const prepareFetchTranscript = (
  input: RawTranscriptInput,
  defaultLimit: number = DEFAULT_TRANSCRIPT_LIMIT,
): Result<FetchRequest, TranscriptError> => {
  let parsed: URL;
  try {
    parsed = new URL(input.url);
  } catch {
    return err({ kind: 'invalid_request', message: `Invalid Target URL: "${input.url}"` });
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return err({
      kind: 'blocked_url',
      message: `Blocked Target URL: disallowed scheme "${parsed.protocol}" (only http: and https: are allowed)`,
    });
  }

  const host = normalizeHostDisplay(parsed.hostname);
  if (!isAllowedYouTubeHost(host)) {
    return err({
      kind: 'blocked_url',
      message: `Blocked Target URL: host "${host}" is not an allowlisted YouTube domain`,
    });
  }

  const lang = input.lang ?? 'en';
  if (!SAFE_LANG_REGEX.test(lang)) {
    return err({
      kind: 'invalid_request',
      message: `Invalid language code "${lang}": only letters, digits, and hyphens are allowed`,
    });
  }

  const startIndex = input.startIndex ?? 0;
  if (!isNonNegativeInt(startIndex)) {
    return err({ kind: 'invalid_request', message: 'Invalid startIndex: must be a non-negative integer' });
  }

  const maxLength = input.maxLength ?? defaultLimit;
  if (!isNonNegativeInt(maxLength)) {
    return err({ kind: 'invalid_request', message: 'Invalid maxLength: must be a non-negative integer' });
  }

  const headers = validateHeaders(input.headers);
  if (!headers.ok) return headers;

  return ok({
    url: TargetUrl(parsed.href),
    lang: LanguageCode(lang),
    headers: headers.value,
    window: { startIndex, maxLength },
  });
};

const extractJsonObjectStartingAt = (text: string, startBraceIndex: number): string | null => {
  let depth = 0;
  let inString = false;
  let escaped = false;

  for (let i = startBraceIndex; i < text.length; i++) {
    const ch = text[i];
    if (inString) {
      if (escaped) {
        escaped = false;
      } else if (ch === '\\') {
        escaped = true;
      } else if (ch === '"') {
        inString = false;
      }
      continue;
    }

    if (ch === '"') {
      inString = true;
    } else if (ch === '{') {
      depth++;
    } else if (ch === '}') {
      depth--;
      if (depth === 0) {
        return text.slice(startBraceIndex, i + 1);
      }
    }
  }
  return null;
};

const CaptionTrackSchema = z.object({
  languageCode: z.string().min(1),
  baseUrl: z.string().min(1),
  name: z
    .object({
      simpleText: z.string().optional(),
      runs: z.array(z.object({ text: z.string() })).optional(),
    })
    .optional(),
});

const PlayerResponseSchema = z.object({
  captions: z
    .object({
      playerCaptionsTracklistRenderer: z
        .object({
          captionTracks: z.array(CaptionTrackSchema).optional(),
        })
        .optional(),
    })
    .optional(),
});

/**
 * Extracts CaptionTrack records from YouTube watch page HTML (`ytInitialPlayerResponse`) (D14).
 */
export const extractCaptionTracks = (html: string): Result<readonly CaptionTrack[], TranscriptError> => {
  const marker = /ytInitialPlayerResponse\s*=\s*\{/.exec(html);
  if (!marker) {
    return err({ kind: 'not_found', message: 'Could not find ytInitialPlayerResponse in page HTML' });
  }

  const braceStart = marker.index + marker[0].length - 1;
  const jsonText = extractJsonObjectStartingAt(html, braceStart);
  if (jsonText === null) {
    return err({ kind: 'not_found', message: 'Could not find ytInitialPlayerResponse in page HTML' });
  }

  let rawJson: unknown;
  try {
    rawJson = JSON.parse(jsonText);
  } catch {
    return err({ kind: 'not_found', message: 'Could not find ytInitialPlayerResponse in page HTML' });
  }

  const parsed = PlayerResponseSchema.safeParse(rawJson);
  const rawTracks = parsed.success ? parsed.data.captions?.playerCaptionsTracklistRenderer?.captionTracks : undefined;
  if (!rawTracks || rawTracks.length === 0) {
    return err({ kind: 'not_found', message: 'No caption tracks found for this video' });
  }

  const tracks: CaptionTrack[] = rawTracks.map((track) => ({
    languageCode: track.languageCode,
    baseUrl: track.baseUrl,
    name: track.name?.simpleText ?? track.name?.runs?.map((r) => r.text).join('') ?? track.languageCode,
  }));

  return ok(tracks);
};

/**
 * Selects a CaptionTrack matching `lang` case-insensitively by exact code first, then regional prefix;
 * fails explicitly listing available language codes when absent (D14, D20).
 */
export const selectCaptionTrack = (
  tracks: readonly CaptionTrack[],
  lang: LanguageCode,
): Result<CaptionTrack, TranscriptError> => {
  const target = lang.toLowerCase();

  const exact = tracks.find((track) => track.languageCode.toLowerCase() === target);
  if (exact) return ok(exact);

  const prefix = tracks.find((track) => track.languageCode.toLowerCase().startsWith(`${target}-`));
  if (prefix) return ok(prefix);

  const available = Array.from(new Set(tracks.map((track) => track.languageCode))).join(', ');
  return err({
    kind: 'language_not_found',
    message: `No captions available in language "${lang}" (available: ${available})`,
  });
};

/**
 * Parses `srv1`/`srv3` caption XML and formats a Transcript with language header and timestamps (D4, D21, D22).
 */
export const buildTranscript = (xml: string, lang: string, langName: string): Result<Transcript, TranscriptError> => {
  const lines = parseCaptionXml(xml);
  if (lines.length === 0) {
    return err({ kind: 'parse_error', message: 'No caption lines found in transcript XML' });
  }
  return ok(Transcript(`[Transcript language: ${lang} — ${langName}]\n\n${lines.join('\n')}`));
};
