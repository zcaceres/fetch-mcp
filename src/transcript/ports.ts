import type { Result } from '../shared/result.ts';
import type { Headers, TranscriptError } from './nouns.ts';

export type FetchPagePort = (url: string, headers: Headers) => Promise<Result<string, TranscriptError>>;

export type TranscriptPorts = {
  readonly fetchPage: FetchPagePort;
};
