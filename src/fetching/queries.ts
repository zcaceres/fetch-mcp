import { type Headers, type RenderedOutput, type Window, WindowedExcerpt } from './nouns.ts';

const SENSITIVE_CROSS_ORIGIN_HEADERS = new Set(['authorization', 'cookie', 'proxy-authorization']);
const BINARY_MEDIA_TYPE_PREFIXES = ['image/', 'audio/', 'video/', 'font/'] as const;
const BINARY_MEDIA_TYPES = new Set(['application/octet-stream', 'application/pdf', 'application/zip']);

const parseIPv4Octets = (ip: string): readonly [number, number, number, number] | null => {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  const nums: number[] = [];
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    if (part.length > 1 && part.startsWith('0')) return null;
    const n = Number(part);
    if (n < 0 || n > 255) return null;
    nums.push(n);
  }
  const [a, b, c, d] = nums;
  if (a === undefined || b === undefined || c === undefined || d === undefined) return null;
  return [a, b, c, d];
};

const isReservedIPv4Octets = (a: number, b: number, c: number): boolean =>
  a === 0 ||
  a === 10 ||
  (a === 100 && b >= 64 && b <= 127) ||
  a === 127 ||
  (a === 169 && b === 254) ||
  (a === 172 && b >= 16 && b <= 31) ||
  (a === 192 && b === 0 && c === 0) ||
  (a === 192 && b === 0 && c === 2) ||
  (a === 192 && b === 88 && c === 99) ||
  (a === 192 && b === 168) ||
  (a === 198 && (b === 18 || b === 19)) ||
  (a === 198 && b === 51 && c === 100) ||
  (a === 203 && b === 0 && c === 113) ||
  (a >= 224 && a <= 239) ||
  a >= 240;

const parseIPv6Side = (side: string, allowTrailingIPv4: boolean): number[] | null => {
  if (side === '') return [];
  const parts = side.split(':');
  const groups: number[] = [];
  for (let i = 0; i < parts.length; i++) {
    const part = parts[i];
    if (part === undefined || part === '') return null;
    if (part.includes('.')) {
      if (!allowTrailingIPv4 || i !== parts.length - 1) return null;
      const octets = parseIPv4Octets(part);
      if (octets === null) return null;
      const [a, b, c, d] = octets;
      groups.push((a << 8) | b, (c << 8) | d);
    } else {
      if (!/^[0-9a-f]{1,4}$/.test(part)) return null;
      groups.push(Number.parseInt(part, 16));
    }
  }
  return groups;
};

const parseIPv6ToGroups = (ip: string): readonly number[] | null => {
  if (!ip || ip.includes('%') || !ip.includes(':')) return null;
  const lower = ip.toLowerCase();
  const halves = lower.split('::');
  if (halves.length > 2) return null;

  if (halves.length === 1) {
    const groups = parseIPv6Side(halves[0] ?? '', true);
    return groups !== null && groups.length === 8 ? groups : null;
  }

  const leftHalf = halves[0] ?? '';
  const rightHalf = halves[1] ?? '';
  const left = parseIPv6Side(leftHalf, rightHalf === '');
  const right = parseIPv6Side(rightHalf, true);
  if (left === null || right === null) return null;

  const missing = 8 - (left.length + right.length);
  if (missing < 1) return null;

  return [...left, ...new Array<number>(missing).fill(0), ...right];
};

const isReservedIPv6Groups = (g: readonly number[]): boolean => {
  const g0 = g[0] ?? 0;
  const g1 = g[1] ?? 0;
  const g2 = g[2] ?? 0;
  const g3 = g[3] ?? 0;
  const g4 = g[4] ?? 0;
  const g5 = g[5] ?? 0;
  const g6 = g[6] ?? 0;
  const g7 = g[7] ?? 0;

  // ::/96 — unspecified, loopback ::1, deprecated IPv4-compatible
  if (g0 === 0 && g1 === 0 && g2 === 0 && g3 === 0 && g4 === 0 && g5 === 0) return true;

  // ::ffff:0:0/96 — IPv4-mapped IPv6
  if (g0 === 0 && g1 === 0 && g2 === 0 && g3 === 0 && g4 === 0 && g5 === 0xffff) {
    const a = (g6 >> 8) & 0xff;
    const b = g6 & 0xff;
    const c = (g7 >> 8) & 0xff;
    return isReservedIPv4Octets(a, b, c);
  }

  // ::ffff:0:0:0/96 — IPv4-translated
  if (g0 === 0 && g1 === 0 && g2 === 0 && g3 === 0 && g4 === 0xffff && g5 === 0) return true;

  // 64:ff9b::/96 — NAT64 well-known prefix
  if (g0 === 0x0064 && g1 === 0xff9b && g2 === 0 && g3 === 0 && g4 === 0 && g5 === 0) return true;

  // 64:ff9b:1::/48 — NAT64 local-use
  if (g0 === 0x0064 && g1 === 0xff9b && g2 === 0x0001) return true;

  // 100::/64 — Discard-Only
  if (g0 === 0x0100 && g1 === 0 && g2 === 0 && g3 === 0) return true;

  // 2001::/32 — Teredo
  if (g0 === 0x2001 && g1 === 0x0000) return true;

  // 2001:2::/48 — Benchmarking
  if (g0 === 0x2001 && g1 === 0x0002 && g2 === 0x0000) return true;

  // 2001:10::/28 (ORCHID) and 2001:20::/28 (ORCHIDv2)
  if (g0 === 0x2001 && ((g1 & 0xfff0) === 0x0010 || (g1 & 0xfff0) === 0x0020)) return true;

  // 2001:db8::/32 — Documentation
  if (g0 === 0x2001 && g1 === 0x0db8) return true;

  // 2002::/16 — 6to4
  if (g0 === 0x2002) return true;

  // fc00::/7 — Unique Local Address
  if ((g0 & 0xfe00) === 0xfc00) return true;

  // fe80::/10 — Link-Local Unicast
  if ((g0 & 0xffc0) === 0xfe80) return true;

  // fec0::/10 — Deprecated Site-Local
  if ((g0 & 0xffc0) === 0xfec0) return true;

  // ff00::/8 — Multicast
  if ((g0 & 0xff00) === 0xff00) return true;

  return false;
};

/**
 * Normalizes a URL hostname by stripping IPv6 brackets, lowercasing, and removing trailing dots (D8, I1).
 */
export const normalizeHostname = (hostname: string): string => {
  const bare = hostname.startsWith('[') && hostname.endsWith(']') ? hostname.slice(1, -1) : hostname;
  return bare.toLowerCase().replace(/\.+$/, '');
};

/**
 * Returns true if `host` is a syntactically valid IPv4 or IPv6 literal.
 */
export const isIpLiteral = (host: string): boolean =>
  parseIPv4Octets(host) !== null || parseIPv6ToGroups(host) !== null;

/**
 * Returns true if `ip` falls in any IANA-reserved IPv4 or IPv6 range.
 * Fails closed (returns true) for malformed, zone-scoped, or unrecognized strings (D8, I1).
 */
export const isReservedIp = (ip: string): boolean => {
  const ipv4 = parseIPv4Octets(ip);
  if (ipv4 !== null) {
    return isReservedIPv4Octets(ipv4[0], ipv4[1], ipv4[2]);
  }
  const ipv6 = parseIPv6ToGroups(ip);
  if (ipv6 !== null) {
    return isReservedIPv6Groups(ipv6);
  }
  return true;
};

/**
 * Returns true if `contentType` identifies a clearly binary media type that should not be decoded as text (D17).
 */
export const isBinaryContentType = (contentType: string | undefined): boolean => {
  if (!contentType) return false;
  const mediaType = (contentType.split(';')[0] ?? '').trim().toLowerCase();
  if (!mediaType || mediaType === 'image/svg+xml') return false;
  if (BINARY_MEDIA_TYPES.has(mediaType)) return true;
  return BINARY_MEDIA_TYPE_PREFIXES.some((prefix) => mediaType.startsWith(prefix));
};

/**
 * Strips Authorization, Cookie, and Proxy-Authorization headers case-insensitively (D9, I4).
 */
export const stripCrossOriginHeaders = (headers: Headers): Headers => {
  const filtered: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    if (!SENSITIVE_CROSS_ORIGIN_HEADERS.has(key.toLowerCase())) {
      filtered[key] = value;
    }
  }
  return filtered;
};

/**
 * Slices Rendered Output into a Windowed Excerpt (D4, D9, D14, D15).
 * Returns sliced text only, with no appended footer or metadata.
 */
export const windowedExcerpt = (output: RenderedOutput, window: Window): WindowedExcerpt => {
  if (window.startIndex >= output.length) {
    return WindowedExcerpt('');
  }
  if (window.maxLength === 0) {
    return WindowedExcerpt(output.slice(window.startIndex));
  }
  return WindowedExcerpt(output.slice(window.startIndex, window.startIndex + window.maxLength));
};
