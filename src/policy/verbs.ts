import { err, ok, type Result } from '../shared/result.ts';
import {
  type EnvMap,
  type OperatorLimits,
  type PolicyError,
  type ProxyPolicy,
  type ProxyProtocol,
  ProxyUrl,
  SUPPORTED_PROXY_PROTOCOLS,
} from './nouns.ts';
import { isNoProxyMatch, redactProxyUrl } from './queries.ts';

export const DEFAULT_OPERATOR_LIMIT = 5000;
export const DEFAULT_OPERATOR_MAX_RESPONSE_BYTES = 10 * 1024 * 1024;
const UNSIGNED_INT_REGEX = /^\d+$/;
const SCHEME_PREFIX_REGEX = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//;

const isSupportedProxyProtocol = (protocol: string): protocol is ProxyProtocol =>
  (SUPPORTED_PROXY_PROTOCOLS as readonly string[]).includes(protocol);

const firstNonEmpty = (...values: readonly (string | undefined)[]): string | undefined => {
  for (const value of values) {
    const trimmed = value?.trim();
    if (trimmed && trimmed.length > 0) return trimmed;
  }
  return undefined;
};

/**
 * Parses `DEFAULT_LIMIT` (non-negative integer, `0` = unlimited) and `MAX_RESPONSE_BYTES`
 * (positive integer) from Operator environment variables, failing explicitly on invalid values (D9, D25, I5).
 */
export const parseOperatorLimits = (env: EnvMap): Result<OperatorLimits, PolicyError> => {
  let defaultLimit = DEFAULT_OPERATOR_LIMIT;
  const rawLimit = env.DEFAULT_LIMIT?.trim();
  if (rawLimit !== undefined && rawLimit.length > 0) {
    const parsedLimit = UNSIGNED_INT_REGEX.test(rawLimit) ? Number.parseInt(rawLimit, 10) : Number.NaN;
    if (!Number.isSafeInteger(parsedLimit)) {
      return err({
        kind: 'invalid_limit',
        message: `Invalid DEFAULT_LIMIT "${rawLimit}": must be a non-negative integer`,
      });
    }
    defaultLimit = parsedLimit;
  }

  let maxResponseBytes = DEFAULT_OPERATOR_MAX_RESPONSE_BYTES;
  const rawMaxBytes = env.MAX_RESPONSE_BYTES?.trim();
  if (rawMaxBytes !== undefined && rawMaxBytes.length > 0) {
    const parsedMax = UNSIGNED_INT_REGEX.test(rawMaxBytes) ? Number.parseInt(rawMaxBytes, 10) : Number.NaN;
    if (!Number.isSafeInteger(parsedMax) || parsedMax <= 0) {
      return err({
        kind: 'invalid_limit',
        message: `Invalid MAX_RESPONSE_BYTES "${rawMaxBytes}": must be a positive integer`,
      });
    }
    maxResponseBytes = parsedMax;
  }

  return ok({ defaultLimit, maxResponseBytes });
};

/**
 * Resolves effective Proxy Policy for `targetUrl` from optional CLI `--proxy` (bypassing `NO_PROXY`)
 * or Operator environment variables honoring `NO_PROXY`/`no_proxy` (D5, D23, D24, D25).
 */
export const resolveProxyPolicy = (
  targetUrl: string,
  env: EnvMap,
  explicitProxy?: string,
): Result<ProxyPolicy, PolicyError> => {
  let rawProxy: string | undefined;
  if (explicitProxy !== undefined) {
    const trimmedExplicit = explicitProxy.trim();
    if (trimmedExplicit.length === 0) {
      return err({ kind: 'invalid_proxy', message: `Invalid proxy URL: "${explicitProxy}"` });
    }
    rawProxy = trimmedExplicit;
  }

  if (!rawProxy) {
    let parsedTarget: URL;
    try {
      parsedTarget = new URL(targetUrl);
    } catch {
      return ok({ kind: 'direct' });
    }

    const noProxy = firstNonEmpty(env.NO_PROXY, env.no_proxy);
    if (isNoProxyMatch(parsedTarget, noProxy)) {
      return ok({ kind: 'direct' });
    }

    if (parsedTarget.protocol === 'https:') {
      rawProxy = firstNonEmpty(
        env.HTTPS_PROXY,
        env.https_proxy,
        env.HTTP_PROXY,
        env.http_proxy,
        env.ALL_PROXY,
        env.all_proxy,
      );
    } else if (parsedTarget.protocol === 'http:') {
      rawProxy = firstNonEmpty(env.HTTP_PROXY, env.http_proxy, env.ALL_PROXY, env.all_proxy);
    }
  }

  if (!rawProxy) {
    return ok({ kind: 'direct' });
  }

  const hasScheme = SCHEME_PREFIX_REGEX.test(rawProxy);
  if (!hasScheme) {
    const authority = rawProxy.split(/[/?#]/, 1)[0] ?? '';
    const lastAt = authority.lastIndexOf('@');
    const hostPort = lastAt === -1 ? authority : authority.slice(lastAt + 1);
    if (!/:\d+$/.test(hostPort)) {
      return err({ kind: 'invalid_proxy', message: `Invalid proxy URL: "${redactProxyUrl(rawProxy)}"` });
    }
  }

  const normalized = hasScheme ? rawProxy : `http://${rawProxy}`;
  let parsedProxy: URL;
  try {
    parsedProxy = new URL(normalized);
  } catch {
    return err({ kind: 'invalid_proxy', message: `Invalid proxy URL: "${redactProxyUrl(rawProxy)}"` });
  }

  if (!isSupportedProxyProtocol(parsedProxy.protocol)) {
    return err({
      kind: 'invalid_proxy',
      message: `Unsupported proxy protocol "${parsedProxy.protocol}" (supported: http, https, socks4, socks4a, socks5, socks5h)`,
    });
  }

  if (!parsedProxy.hostname) {
    return err({ kind: 'invalid_proxy', message: `Invalid proxy URL: "${redactProxyUrl(rawProxy)}"` });
  }

  return ok({
    kind: 'proxy',
    url: ProxyUrl(parsedProxy.href),
    protocol: parsedProxy.protocol,
  });
};
