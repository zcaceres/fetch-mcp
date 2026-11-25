import type { FetchError } from '../../fetching/nouns.ts';
import type { DnsLookupPort } from '../../fetching/ports.ts';
import { err, ok, type Result } from '../../shared/result.ts';

type DnsEntry =
  | { readonly kind: 'ips'; readonly ips: readonly string[] }
  | { readonly kind: 'fail'; readonly reason: string };

const FIXTURE_RECORDS: readonly (readonly [string, readonly string[]])[] = [
  ['example.com', ['93.184.216.34']],
  ['origin-a.example.com', ['93.184.216.34']],
  ['origin-b.example.com', ['93.184.216.35']],
];

export type DnsMock = {
  readonly lookup: DnsLookupPort;
  readonly set: (host: string, ips: readonly string[]) => void;
  readonly empty: (host: string) => void;
  readonly fail: (host: string, reason: string) => void;
};

export const createDnsMock = (): DnsMock => {
  const records = new Map<string, DnsEntry>(FIXTURE_RECORDS.map(([host, ips]) => [host, { kind: 'ips', ips }]));

  const lookup: DnsLookupPort = async (hostname: string): Promise<Result<readonly string[], FetchError>> => {
    const entry = records.get(hostname.toLowerCase());
    if (!entry) {
      return err({
        kind: 'blocked_url',
        message: `Blocked Target URL: DNS lookup failed for "${hostname}": ENOTFOUND`,
      });
    }
    if (entry.kind === 'fail') {
      return err({
        kind: 'blocked_url',
        message: `Blocked Target URL: DNS lookup failed for "${hostname}": ${entry.reason}`,
      });
    }
    return ok(entry.ips);
  };

  return {
    lookup,
    set: (host, ips) => {
      records.set(host.toLowerCase(), { kind: 'ips', ips });
    },
    empty: (host) => {
      records.set(host.toLowerCase(), { kind: 'ips', ips: [] });
    },
    fail: (host, reason) => {
      records.set(host.toLowerCase(), { kind: 'fail', reason });
    },
  };
};
