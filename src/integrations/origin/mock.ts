import type { FetchError, Headers, RawResponse, TargetUrl } from '../../fetching/nouns.ts';
import type { HttpGetPort } from '../../fetching/ports.ts';
import { err, ok, type Result } from '../../shared/result.ts';

type OriginEntry =
  | { readonly kind: 'response'; readonly status: number; readonly headers: Headers; readonly body: string }
  | { readonly kind: 'fail'; readonly reason: string };

export type OriginMock = {
  readonly get: HttpGetPort;
  readonly serve: (url: string, status: number, body: string, headers?: Headers) => void;
  readonly redirect: (url: string, status: number, location: string) => void;
  readonly fail: (url: string, reason: string) => void;
  readonly lastHeaders: (url: string) => Headers | undefined;
};

export const createOriginMock = (): OriginMock => {
  const routes = new Map<string, OriginEntry>();
  const recordedHeaders = new Map<string, Headers>();

  const normalizeKey = (url: string): string => {
    try {
      return new URL(url).href;
    } catch {
      return url;
    }
  };

  const get: HttpGetPort = async (url: TargetUrl, headers: Headers): Promise<Result<RawResponse, FetchError>> => {
    const key = normalizeKey(url);
    recordedHeaders.set(key, { ...headers });

    const entry = routes.get(key);
    if (!entry) {
      return err({ kind: 'network_error', message: `Network error fetching ${url}: no mock response registered` });
    }
    if (entry.kind === 'fail') {
      return err({ kind: 'network_error', message: `Network error fetching ${url}: ${entry.reason}` });
    }
    return ok({
      status: entry.status,
      url,
      headers: entry.headers,
      body: entry.body,
    });
  };

  return {
    get,
    serve: (url, status, body, headers = {}) => {
      routes.set(normalizeKey(url), { kind: 'response', status, headers, body });
    },
    redirect: (url, status, location) => {
      routes.set(normalizeKey(url), { kind: 'response', status, headers: { location }, body: '' });
    },
    fail: (url, reason) => {
      routes.set(normalizeKey(url), { kind: 'fail', reason });
    },
    lastHeaders: (url) => recordedHeaders.get(normalizeKey(url)),
  };
};
