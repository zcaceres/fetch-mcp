import type { Result } from '../shared/result.ts';
import type { Headers, LanguageCode, TargetUrl, TranscriptError } from './nouns.ts';

export type FetchPagePort = (url: string, headers: Headers) => Promise<Result<string, TranscriptError>>;

export type CheckHostPort = (hostname: string) => Promise<Result<void, TranscriptError>>;

export type ResolveTranscriptProxyPort = (targetUrl: TargetUrl) => Result<string | undefined, TranscriptError>;

export type YtDlpResult = {
  readonly xml: string;
  readonly lang: string;
  readonly langName: string;
};

export type YtDlpPort = {
  readonly isAvailable: () => Promise<boolean>;
  readonly downloadSubtitles: (
    url: TargetUrl,
    lang: LanguageCode,
    proxyUrl?: string,
  ) => Promise<Result<YtDlpResult, string>>;
};

export type TranscriptPorts = {
  readonly fetchPage: FetchPagePort;
  readonly checkHost?: CheckHostPort;
  readonly resolveProxy?: ResolveTranscriptProxyPort;
  readonly ytDlp?: YtDlpPort;
};
