import type { Result } from '../shared/result.ts';
import type { FetchError, Headers, RawResponse, TargetUrl } from './nouns.ts';

export type HttpGetPort = (url: TargetUrl, headers: Headers) => Promise<Result<RawResponse, FetchError>>;

export type DnsLookupPort = (hostname: string) => Promise<Result<readonly string[], FetchError>>;
