// src/security/headers.ts
import {
  BLOCKED_HEADERS,
  AUTH_HEADERS,
  allowAuthHeaders,
  sanitizeErrors,
} from "../types.js";

/**
 * Sanitize URL for error messages (remove sensitive query params)
 * Fix #9: Configurable info disclosure
 */
export function sanitizeUrlForError(urlString: string): string {
  if (!sanitizeErrors) return urlString;

  try {
    const url = new URL(urlString);
    // Remove query string and hash which may contain tokens
    return `${url.protocol}//${url.host}${url.pathname}`;
  } catch {
    return "[invalid URL]";
  }
}

/**
 * Sanitize headers to prevent injection attacks
 * @param headers - Headers to sanitize
 * @param stripAuth - Force strip auth headers (used for cross-origin redirects)
 */
export function sanitizeHeaders(
  headers?: Record<string, string>,
  stripAuth = false,
): Record<string, string> {
  if (!headers) return {};

  const sanitized: Record<string, string> = {};

  for (const [key, value] of Object.entries(headers)) {
    const lowerKey = key.toLowerCase();

    // Block dangerous headers (always blocked)
    if (BLOCKED_HEADERS.includes(lowerKey)) {
      continue;
    }

    // Block auth headers unless explicitly allowed, or if stripAuth is set (cross-origin redirect)
    if (AUTH_HEADERS.includes(lowerKey)) {
      if (stripAuth || !allowAuthHeaders) {
        continue;
      }
    }

    // Block headers with CRLF characters (header injection)
    if (
      key.includes("\r") ||
      key.includes("\n") ||
      value.includes("\r") ||
      value.includes("\n")
    ) {
      continue;
    }

    sanitized[key] = value;
  }

  return sanitized;
}
