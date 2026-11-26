import dns from 'node:dns';
import type { DnsLookupPort } from '../../fetching/ports.ts';
import { err, ok } from '../../shared/result.ts';

/**
 * Real DNS Resolver port wrapping `dns.promises.lookup(..., { all: true })` (D8, I2).
 */
export const createRealDnsLookup = (): DnsLookupPort => async (hostname) => {
  try {
    const raw = await dns.promises.lookup(hostname, { all: true });
    const records = Array.isArray(raw) ? raw : [raw];
    return ok(records.map((record) => record.address));
  } catch (error: unknown) {
    const reason = error instanceof Error ? error.message : String(error);
    return err({
      kind: 'blocked_url',
      message: `Blocked Target URL: DNS lookup failed for "${hostname}": ${reason}`,
    });
  }
};
