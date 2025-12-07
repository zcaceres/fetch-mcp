// src/security/fetch.ts
// Secure fetch with SSRF protection, DNS pinning, and redirect handling

import { requestTimeout, maxRedirects, dependencies } from "../types.js";
import { validateScheme, validateUrlSecurity, isSameOrigin } from "./ssrf.js";
import { sanitizeHeaders } from "./headers.js";

/**
 * Perform a secure fetch with timeout, redirect validation, and SSRF protection
 * Implements DNS connection pinning to prevent DNS rebinding attacks
 *
 * Security features:
 * - URL scheme validation (http/https only)
 * - SSRF protection via IP blocking and DNS resolution checks
 * - DNS connection pinning to prevent TOCTOU/rebinding attacks
 * - Manual redirect handling with security validation
 * - Cross-origin auth header stripping on redirects
 * - Request timeout with AbortController
 */
export async function secureFetch(
  url: string,
  headers: Record<string, string>,
  redirectCount = 0,
  originalUrl?: string,
): Promise<Response> {
  // Validate scheme (http/https only)
  validateScheme(url);

  // Validate URL security and get resolved IPs
  const resolvedIPs = await validateUrlSecurity(url);

  // Track original URL for cross-origin redirect detection
  const origin = originalUrl ?? url;

  // Implement DNS connection pinning (Fix #13: prevent TOCTOU DNS rebinding)
  // Only for HTTP - HTTPS already has TLS cert validation which prevents rebinding
  let fetchUrl = url;
  const fetchHeaders = { ...headers };
  const parsedUrl = new URL(url);

  if (resolvedIPs.length > 0 && parsedUrl.protocol === "http:") {
    const originalHostname = parsedUrl.hostname;

    // Pin to first resolved IP
    parsedUrl.hostname = resolvedIPs[0];
    fetchUrl = parsedUrl.toString();

    // Set Host header to original hostname for HTTP/1.1 virtual hosting
    fetchHeaders["Host"] = originalHostname;
  }
  // For HTTPS: DNS validation is performed but we don't pin the connection
  // because TLS certificate validation provides rebinding protection

  // Add timeout using AbortController
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), requestTimeout);

  try {
    const deps = dependencies.get();
    const response = await deps.fetch(fetchUrl, {
      headers: {
        "User-Agent":
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        ...fetchHeaders,
      },
      redirect: "manual", // Don't auto-follow redirects
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    // Handle redirects manually with security validation
    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get("location");

      if (!location) {
        throw new Error(`Redirect response missing Location header`);
      }

      if (redirectCount >= maxRedirects) {
        throw new Error(`Too many redirects (max: ${maxRedirects})`);
      }

      // Resolve relative URLs
      const redirectUrl = new URL(location, url).toString();

      // Strip auth headers if redirecting to a different origin (prevent credential leakage)
      let redirectHeaders = headers;
      if (!isSameOrigin(origin, redirectUrl)) {
        redirectHeaders = sanitizeHeaders(headers, true); // stripAuth = true
      }

      // Recursively fetch with redirect validation
      return secureFetch(
        redirectUrl,
        redirectHeaders,
        redirectCount + 1,
        origin,
      );
    }

    if (!response.ok) {
      throw new Error(`HTTP error: ${response.status}`);
    }

    return response;
  } catch (e: unknown) {
    clearTimeout(timeoutId);

    if (e instanceof Error) {
      if (e.name === "AbortError") {
        throw new Error(`Request timeout after ${requestTimeout}ms`);
      }
      throw e;
    }
    throw new Error("Unknown fetch error");
  }
}
