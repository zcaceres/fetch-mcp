import type { Result } from '../shared/result.ts';
import type { FetchError, Headers, TargetUrl, WireResponse } from './nouns.ts';

export type HttpGetPort = (url: TargetUrl, headers: Headers) => Promise<Result<WireResponse, FetchError>>;

export type DnsLookupPort = (hostname: string) => Promise<Result<readonly string[], FetchError>>;
