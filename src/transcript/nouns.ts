import type { Brand } from '../shared/brand.ts';

export type TargetUrl = Brand<string, 'TargetUrl'>;
export const TargetUrl = (value: string): TargetUrl => value as TargetUrl;

export type LanguageCode = Brand<string, 'LanguageCode'>;
export const LanguageCode = (value: string): LanguageCode => value as LanguageCode;

export type Headers = Readonly<Record<string, string>>;

export type Window = {
  readonly startIndex: number;
  readonly maxLength: number;
};

export type CaptionTrack = {
  readonly languageCode: string;
  readonly name: string;
  readonly baseUrl: string;
};

export type RawTranscriptInput = {
  readonly url: string;
  readonly lang?: string;
  readonly headers?: Headers;
  readonly startIndex?: number;
  readonly maxLength?: number;
};

export type FetchRequest = {
  readonly url: TargetUrl;
  readonly lang: LanguageCode;
  readonly headers: Headers;
  readonly window: Window;
};

export type Transcript = Brand<string, 'Transcript'>;
export const Transcript = (value: string): Transcript => value as Transcript;

export type WindowedExcerpt = Brand<string, 'WindowedExcerpt'>;
export const WindowedExcerpt = (value: string): WindowedExcerpt => value as WindowedExcerpt;

export type TranscriptError =
  | { readonly kind: 'invalid_request'; readonly message: string }
  | { readonly kind: 'blocked_url'; readonly message: string }
  | { readonly kind: 'fetch_error'; readonly message: string }
  | { readonly kind: 'not_found'; readonly message: string }
  | { readonly kind: 'language_not_found'; readonly message: string }
  | { readonly kind: 'parse_error'; readonly message: string };
