import type { Brand } from '../shared/brand.ts';

export type TargetUrl = Brand<string, 'TargetUrl'>;
export const TargetUrl = (value: string): TargetUrl => value as TargetUrl;

export type ResolvedIp = Brand<string, 'ResolvedIp'>;
export const ResolvedIp = (value: string): ResolvedIp => value as ResolvedIp;

export const WEB_FORMATS = ['html'] as const;
export type WebFormat = (typeof WEB_FORMATS)[number];

export type Headers = Readonly<Record<string, string>>;

export type Window = {
  readonly startIndex: number;
  readonly maxLength: number;
};

export type FetchRequest = {
  readonly url: TargetUrl;
  readonly format: WebFormat;
  readonly headers: Headers;
  readonly window: Window;
};

export type RawFetchInput = {
  readonly url: string;
  readonly format: string;
  readonly headers?: Headers;
  readonly startIndex?: number;
  readonly maxLength?: number;
};

export type RawResponse = {
  readonly status: number;
  readonly url: TargetUrl;
  readonly headers: Headers;
  readonly body: string;
};

export type RedirectStep = {
  readonly nextUrl: TargetUrl;
  readonly headers: Headers;
};

export type RenderedOutput = Brand<string, 'RenderedOutput'>;
export const RenderedOutput = (value: string): RenderedOutput => value as RenderedOutput;

export type WindowedExcerpt = Brand<string, 'WindowedExcerpt'>;
export const WindowedExcerpt = (value: string): WindowedExcerpt => value as WindowedExcerpt;

export type FetchError =
  | { readonly kind: 'invalid_request'; readonly message: string }
  | { readonly kind: 'blocked_url'; readonly message: string }
  | { readonly kind: 'too_many_redirects'; readonly message: string }
  | { readonly kind: 'http_error'; readonly message: string }
  | { readonly kind: 'network_error'; readonly message: string };
