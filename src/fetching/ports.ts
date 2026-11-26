import type { Result } from '../shared/result.ts';
import type { FetchError, Headers, ResolvedIp, TargetUrl, WireResponse } from './nouns.ts';

export type HttpGetPort = (
  url: TargetUrl,
  headers: Headers,
  pinnedIps: readonly ResolvedIp[],
) => Promise<Result<WireResponse, FetchError>>;

export type DnsLookupPort = (hostname: string) => Promise<Result<readonly string[], FetchError>>;

export type FetchPorts = {
  readonly httpGet: HttpGetPort;
  readonly dnsLookup: DnsLookupPort;
};
