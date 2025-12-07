// src/security/ssrf.ts
import ipaddr from "ipaddr.js";
import { enableDnsCheck, dnsFailClosed, dependencies } from "../types.js";

// Blocked IP ranges for SSRF protection
export const BLOCKED_RANGES = [
  "unspecified",
  "broadcast",
  "multicast",
  "linkLocal",
  "loopback",
  "carrierGradeNat",
  "private",
  "reserved",
  "uniqueLocal", // IPv6 equivalent of private (fc00::/7)
  "ipv4Mapped", // Block all IPv4-mapped IPv6 by default, check underlying IP
];

// Allowed URL schemes
export const ALLOWED_SCHEMES = ["http:", "https:"];

/**
 * Check if an IP address should be blocked
 * Handles IPv4, IPv6, and IPv4-mapped IPv6 addresses
 */
export function isBlockedIP(ip: string): boolean {
  if (!ipaddr.isValid(ip)) return false;

  const addr = ipaddr.parse(ip);
  const range = addr.range();

  // Fix #1: Handle IPv4-mapped IPv6 addresses (e.g., ::ffff:127.0.0.1)
  if (range === "ipv4Mapped" && addr.kind() === "ipv6") {
    try {
      const ipv6Addr = addr as ipaddr.IPv6;
      const ipv4Addr = ipv6Addr.toIPv4Address();
      const ipv4Range = ipv4Addr.range();
      // Check if the underlying IPv4 is in a blocked range
      return BLOCKED_RANGES.includes(ipv4Range);
    } catch {
      // If conversion fails, block it to be safe
      return true;
    }
  }

  return BLOCKED_RANGES.includes(range);
}

/**
 * Validate URL scheme
 * Fix #4: Only allow http/https
 */
export function validateScheme(urlString: string): void {
  const url = new URL(urlString);
  if (!ALLOWED_SCHEMES.includes(url.protocol)) {
    throw new Error(
      `Blocked URL scheme: ${url.protocol}. Only http: and https: are allowed.`,
    );
  }
}

/**
 * Validate URL security (SSRF protection)
 * Fix #2: Returns resolved IPs to prevent DNS rebinding
 */
export async function validateUrlSecurity(
  urlString: string,
): Promise<string[]> {
  const url = new URL(urlString);
  // Strip brackets from IPv6 addresses (URL gives us [::1], ipaddr.js expects ::1)
  const hostname = url.hostname.replace(/^\[|\]$/g, "");

  const ssrfExplanation =
    "This is to prevent a security vulnerability where a local MCP could fetch privileged local IPs and exfiltrate data.";

  // Direct IP check (always performed)
  if (ipaddr.isValid(hostname)) {
    if (isBlockedIP(hostname)) {
      throw new Error(
        `Blocked private/reserved IP: ${hostname}. ${ssrfExplanation}`,
      );
    }
    return [hostname];
  }

  // DNS resolution check (configurable)
  if (!enableDnsCheck) return [];

  try {
    const deps = dependencies.get();
    const [ipv4s, ipv6s] = await Promise.all([
      deps.dnsResolve4(hostname).catch(() => []),
      deps.dnsResolve6(hostname).catch(() => []),
    ]);

    const allIPs = [...ipv4s, ...ipv6s];

    // If both fail and fail-closed is enabled, block
    if (allIPs.length === 0 && dnsFailClosed) {
      throw new Error(
        `DNS resolution failed for ${hostname} (fail-closed mode). Set SSRF_DNS_FAIL_CLOSED=false to allow.`,
      );
    }

    // Check all resolved IPs
    for (const ip of allIPs) {
      if (isBlockedIP(ip)) {
        throw new Error(
          `Hostname ${hostname} resolves to blocked IP ${ip}. ${ssrfExplanation}`,
        );
      }
    }

    return allIPs;
  } catch (err) {
    if (dnsFailClosed) throw err;
    // fail-open: allow the request to proceed
    return [];
  }
}

/**
 * Check if two URLs have the same origin
 */
export function isSameOrigin(url1: string, url2: string): boolean {
  try {
    const u1 = new URL(url1);
    const u2 = new URL(url2);
    return u1.origin === u2.origin;
  } catch {
    return false;
  }
}
