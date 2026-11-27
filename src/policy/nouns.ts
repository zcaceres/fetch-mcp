import type { Brand } from '../shared/brand.ts';

export const SUPPORTED_PROXY_PROTOCOLS = ['http:', 'https:', 'socks4:', 'socks4a:', 'socks5:', 'socks5h:'] as const;
export type ProxyProtocol = (typeof SUPPORTED_PROXY_PROTOCOLS)[number];

export type ProxyUrl = Brand<string, 'ProxyUrl'>;
export const ProxyUrl = (value: string): ProxyUrl => value as ProxyUrl;

export type ProxyPolicy =
  | { readonly kind: 'direct' }
  | { readonly kind: 'proxy'; readonly url: ProxyUrl; readonly protocol: ProxyProtocol };

export type OperatorLimits = {
  readonly defaultLimit: number;
  readonly maxResponseBytes: number;
};

export type EnvMap = Readonly<Record<string, string | undefined>>;

export type PolicyError =
  | { readonly kind: 'invalid_limit'; readonly message: string }
  | { readonly kind: 'invalid_proxy'; readonly message: string };
