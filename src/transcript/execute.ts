import { ok, type Result } from '../shared/result.ts';
import type { RawTranscriptInput, TranscriptError, WindowedExcerpt } from './nouns.ts';
import type { TranscriptPorts } from './ports.ts';
import { windowedTranscript } from './queries.ts';
import {
  buildTranscript,
  DEFAULT_TRANSCRIPT_LIMIT,
  extractCaptionTracks,
  prepareTranscriptRequest,
  selectCaptionTrack,
} from './verbs.ts';

export type ExecuteTranscriptOptions = {
  readonly defaultLimit?: number;
};

/**
 * Shared port-injected orchestration for `fetch transcript` (direct extraction in Slice 01;
 * yt-dlp primary + fallback added in Slice 02). Performs no direct I/O and imports no other context.
 */
export const executeFetchTranscript = async (
  input: RawTranscriptInput,
  ports: TranscriptPorts,
  options: ExecuteTranscriptOptions = {},
): Promise<Result<WindowedExcerpt, TranscriptError>> => {
  const prepared = prepareTranscriptRequest(input, options.defaultLimit ?? DEFAULT_TRANSCRIPT_LIMIT);
  if (!prepared.ok) return prepared;

  const page = await ports.fetchPage(prepared.value.url, prepared.value.headers);
  if (!page.ok) return page;

  const tracks = extractCaptionTracks(page.value);
  if (!tracks.ok) return tracks;

  const selected = selectCaptionTrack(tracks.value, prepared.value.lang);
  if (!selected.ok) return selected;

  const captionUrl = selected.value.baseUrl.includes('fmt=')
    ? selected.value.baseUrl
    : `${selected.value.baseUrl}${selected.value.baseUrl.includes('?') ? '&' : '?'}fmt=srv1`;

  const xml = await ports.fetchPage(captionUrl, prepared.value.headers);
  if (!xml.ok) return xml;

  const transcript = buildTranscript(xml.value, selected.value.languageCode, selected.value.name);
  if (!transcript.ok) return transcript;

  return ok(windowedTranscript(transcript.value, prepared.value.window));
};
