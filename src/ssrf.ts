import dns from "node:dns";
import net from "node:net";

export const ALLOWED_YOUTUBE_HOSTS = new Set([
  "youtube.com",
  "www.youtube.com",
  "m.youtube.com",
  "music.youtube.com",
  "youtu.be",
]);

function isReservedIPv4Octets(a: number, b: number, c: number, _d: number): boolean {
  return (
    a === 0 || // 0.0.0.0/8         - "This" network (RFC 1122)
    a === 10 || // 10.0.0.0/8        - Private-Use (RFC 1918)
    (a === 100 && b >= 64 && b <= 127) || // 100.64.0.0/10     - Shared / CGNAT (RFC 6598)
    a === 127 || // 127.0.0.0/8       - Loopback (RFC 1122)
    (a === 169 && b === 254) || // 169.254.0.0/16    - Link-Local / Cloud IMDS (RFC 3927)
    (a === 172 && b >= 16 && b <= 31) || // 172.16.0.0/12     - Private-Use (RFC 1918)
    (a === 192 && b === 0 && c === 0) || // 192.0.0.0/24      - IETF Protocol Assignments (RFC 6890)
    (a === 192 && b === 0 && c === 2) || // 192.0.2.0/24      - TEST-NET-1 (RFC 5737)
    (a === 192 && b === 88 && c === 99) || // 192.88.99.0/24    - 6to4 Relay Anycast (RFC 3068)
    (a === 192 && b === 168) || // 192.168.0.0/16    - Private-Use (RFC 1918)
    (a === 198 && (b === 18 || b === 19)) || // 198.18.0.0/15     - Benchmarking (RFC 2544)
    (a === 198 && b === 51 && c === 100) || // 198.51.100.0/24   - TEST-NET-2 (RFC 5737)
    (a === 203 && b === 0 && c === 113) || // 203.0.113.0/24    - TEST-NET-3 (RFC 5737)
    (a >= 224 && a <= 239) || // 224.0.0.0/4       - Multicast (RFC 5771 / CVE-2025-8020)
    a >= 240 // 240.0.0.0/4       - Reserved + 255.255.255.255 broadcast
  );
}

/**
 * Parse a valid IPv6 address into its 8 16-bit numeric groups.
 * Handles compressed (`::`), expanded, mixed dotted-IPv4 (`::ffff:127.0.0.1`),
 * and WHATWG-normalized hex (`::ffff:7f00:1`) forms.
 * Returns null for any invalid or zone-scoped input.
 */
export function parseIPv6ToGroups(ip: string): number[] | null {
  if (!ip || ip.includes("%") || !net.isIPv6(ip)) {
    return null;
  }

  const lower = ip.toLowerCase();
  const halves = lower.split("::");
  if (halves.length > 2) {
    return null;
  }

  const parseSide = (side: string): number[] | null => {
    if (side === "") return [];
    const parts = side.split(":");
    const groups: number[] = [];
    for (let i = 0; i < parts.length; i++) {
      const part = parts[i];
      if (part.includes(".")) {
        // Dotted-quad IPv4 suffix is only valid as the very last segment
        if (i !== parts.length - 1 || !net.isIPv4(part)) {
          return null;
        }
        const [a, b, c, d] = part.split(".").map(Number);
        groups.push((a << 8) | b, (c << 8) | d);
      } else {
        if (!/^[0-9a-f]{1,4}$/.test(part)) {
          return null;
        }
        groups.push(parseInt(part, 16));
      }
    }
    return groups;
  };

  if (halves.length === 1) {
    const groups = parseSide(halves[0]);
    return groups && groups.length === 8 ? groups : null;
  }

  const left = parseSide(halves[0]);
  const right = parseSide(halves[1]);
  if (!left || !right) {
    return null;
  }

  const missing = 8 - (left.length + right.length);
  if (missing < 1) {
    return null;
  }

  return [...left, ...new Array<number>(missing).fill(0), ...right];
}

function isReservedIPv6Groups(g: number[]): boolean {
  // ::/96 — covers :: (unspecified), ::1 (loopback), and deprecated IPv4-compatible (::x.x.x.x)
  if (g[0] === 0 && g[1] === 0 && g[2] === 0 && g[3] === 0 && g[4] === 0 && g[5] === 0) {
    return true;
  }

  // ::ffff:0:0/96 — IPv4-mapped IPv6 (both ::ffff:127.0.0.1 and WHATWG hex ::ffff:7f00:1)
  if (g[0] === 0 && g[1] === 0 && g[2] === 0 && g[3] === 0 && g[4] === 0 && g[5] === 0xffff) {
    const a = (g[6] >> 8) & 0xff;
    const b = g[6] & 0xff;
    const c = (g[7] >> 8) & 0xff;
    const d = g[7] & 0xff;
    return isReservedIPv4Octets(a, b, c, d);
  }

  // ::ffff:0:0:0/96 — IPv4-translated (RFC 2765)
  if (g[0] === 0 && g[1] === 0 && g[2] === 0 && g[3] === 0 && g[4] === 0xffff && g[5] === 0) {
    return true;
  }

  // 64:ff9b::/96 — NAT64 well-known prefix (RFC 6052)
  if (g[0] === 0x0064 && g[1] === 0xff9b && g[2] === 0 && g[3] === 0 && g[4] === 0 && g[5] === 0) {
    return true;
  }

  // 64:ff9b:1::/48 — NAT64 local-use (RFC 8215)
  if (g[0] === 0x0064 && g[1] === 0xff9b && g[2] === 0x0001) {
    return true;
  }

  // 100::/64 — Discard-Only (RFC 6666)
  if (g[0] === 0x0100 && g[1] === 0 && g[2] === 0 && g[3] === 0) {
    return true;
  }

  // 2001::/32 — Teredo (RFC 4380)
  if (g[0] === 0x2001 && g[1] === 0x0000) {
    return true;
  }

  // 2001:2::/48 — Benchmarking (RFC 5180)
  if (g[0] === 0x2001 && g[1] === 0x0002 && g[2] === 0x0000) {
    return true;
  }

  // 2001:10::/28 (ORCHID) and 2001:20::/28 (ORCHIDv2)
  if (g[0] === 0x2001 && ((g[1] & 0xfff0) === 0x0010 || (g[1] & 0xfff0) === 0x0020)) {
    return true;
  }

  // 2001:db8::/32 — Documentation (RFC 3849)
  if (g[0] === 0x2001 && g[1] === 0x0db8) {
    return true;
  }

  // 2002::/16 — 6to4 (RFC 3056)
  if (g[0] === 0x2002) {
    return true;
  }

  // fc00::/7 — Unique Local Address (RFC 4193)
  if ((g[0] & 0xfe00) === 0xfc00) {
    return true;
  }

  // fe80::/10 — Link-Local Unicast (RFC 4291)
  if ((g[0] & 0xffc0) === 0xfe80) {
    return true;
  }

  // fec0::/10 — Deprecated Site-Local
  if ((g[0] & 0xffc0) === 0xfec0) {
    return true;
  }

  // ff00::/8 — Multicast (RFC 4291)
  if ((g[0] & 0xff00) === 0xff00) {
    return true;
  }

  return false;
}

/**
 * Returns true if the IP address belongs to any IANA reserved / non-public range.
 * Fails closed (returns true) for invalid or unrecognized IP strings.
 */
export function isReservedIP(ip: string): boolean {
  if (net.isIPv4(ip)) {
    const [a, b, c, d] = ip.split(".").map(Number);
    return isReservedIPv4Octets(a, b, c, d);
  }

  const groups = parseIPv6ToGroups(ip);
  if (groups) {
    return isReservedIPv6Groups(groups);
  }

  // Fail closed on non-IP / malformed input
  return true;
}

export function normalizeHostname(hostname: string): string {
  const bare =
    hostname.startsWith("[") && hostname.endsWith("]")
      ? hostname.slice(1, -1)
      : hostname;
  return bare.toLowerCase().replace(/\.+$/, "");
}

export function isLocalHostname(normalizedHostname: string): boolean {
  return (
    normalizedHostname === "" ||
    normalizedHostname === "localhost" ||
    normalizedHostname.endsWith(".localhost")
  );
}

/**
 * Validates that a URL uses HTTP/HTTPS and does not target localhost or a reserved IP literal.
 */
export function validateUrl(url: string): URL {
  const parsedUrl = new URL(url);
  if (parsedUrl.protocol !== "http:" && parsedUrl.protocol !== "https:") {
    throw new Error(
      `Fetcher blocked URL with disallowed protocol "${parsedUrl.protocol}". Only HTTP and HTTPS are allowed.`,
    );
  }

  const bareHostname = normalizeHostname(parsedUrl.hostname);
  if (
    isLocalHostname(bareHostname) ||
    (net.isIP(bareHostname) !== 0 && isReservedIP(bareHostname))
  ) {
    throw new Error(
      `Fetcher blocked request to private address "${bareHostname}". This prevents SSRF attacks where a local MCP server could access privileged internal services.`,
    );
  }

  return parsedUrl;
}

/**
 * Validates that a URL is a valid public YouTube URL for transcript extraction.
 */
export function validateYouTubeUrl(url: string): URL {
  const parsedUrl = validateUrl(url);
  const host = normalizeHostname(parsedUrl.hostname);
  if (!ALLOWED_YOUTUBE_HOSTS.has(host)) {
    throw new Error(
      `Fetcher blocked URL "${url}": fetch_youtube_transcript only allows YouTube URLs (youtube.com, youtu.be).`,
    );
  }
  return parsedUrl;
}

/**
 * Resolves all DNS records for a hostname and ensures every resolved IP is public.
 * Fails closed on DNS resolution errors or empty answers.
 */
export async function resolveAndValidateHost(
  hostname: string,
): Promise<dns.LookupAddress[]> {
  const bareHostname = normalizeHostname(hostname);

  if (isLocalHostname(bareHostname)) {
    throw new Error(
      `Fetcher blocked request to private address "${bareHostname}". This prevents SSRF attacks where a local MCP server could access privileged internal services.`,
    );
  }

  const ipVersion = net.isIP(bareHostname);
  if (ipVersion !== 0) {
    if (isReservedIP(bareHostname)) {
      throw new Error(
        `Fetcher blocked request to private address "${bareHostname}". This prevents SSRF attacks where a local MCP server could access privileged internal services.`,
      );
    }
    return [{ address: bareHostname, family: ipVersion }];
  }

  let raw: dns.LookupAddress | dns.LookupAddress[];
  try {
    raw = await dns.promises.lookup(bareHostname, { all: true });
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    throw new Error(
      `Fetcher blocked request: DNS lookup failed for "${bareHostname}": ${msg}`,
    );
  }

  const records = Array.isArray(raw) ? raw : raw ? [raw] : [];
  if (records.length === 0) {
    throw new Error(
      `Fetcher blocked request: DNS lookup returned no addresses for "${bareHostname}".`,
    );
  }

  for (const record of records) {
    if (isReservedIP(record.address)) {
      throw new Error(
        `Fetcher blocked request: hostname "${bareHostname}" resolved to private IP "${record.address}". This prevents DNS rebinding SSRF attacks.`,
      );
    }
  }

  return records;
}

/**
 * Creates a Node/Bun `net.LookupFunction` that validates all resolved IPs and returns
 * the validated records directly to the socket, eliminating DNS rebinding TOCTOU.
 */
export function createSafeLookup(): net.LookupFunction {
  return (hostname, options, callback) => {
    resolveAndValidateHost(hostname)
      .then((records) => {
        if (options && typeof options === "object" && options.all) {
          (callback as (err: NodeJS.ErrnoException | null, addresses: dns.LookupAddress[]) => void)(
            null,
            records,
          );
        } else {
          const familyFilter =
            typeof options === "number"
              ? options
              : options && typeof options === "object" && typeof options.family === "number"
                ? options.family
                : 0;
          const match =
            familyFilter === 4 || familyFilter === 6
              ? records.find((r) => r.family === familyFilter)
              : records[0];
          if (!match) {
            callback(
              new Error(
                `Fetcher blocked request: no IPv${familyFilter} address found for "${hostname}".`,
              ) as NodeJS.ErrnoException,
              "",
              0,
            );
            return;
          }
          callback(null, match.address, match.family);
        }
      })
      .catch((err) => {
        if (options && typeof options === "object" && options.all) {
          (callback as (err: NodeJS.ErrnoException | null, addresses: dns.LookupAddress[]) => void)(
            err as NodeJS.ErrnoException,
            [],
          );
        } else {
          callback(err as NodeJS.ErrnoException, "", 0);
        }
      });
  };
}
