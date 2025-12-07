// src/security/content-type.ts
// Content-type validation to prevent content-type confusion attacks

import { validateContentType } from "../types.js";

/**
 * Validate response content type matches expected types
 *
 * Fix #10: Content type validation to prevent content type confusion attacks
 *
 * This prevents attacks where a malicious server returns content with
 * an unexpected content-type (e.g., returning HTML when JSON was expected)
 * which could lead to parsing vulnerabilities or injection attacks.
 *
 * @param response - The HTTP response to validate
 * @param expectedTypes - Array of acceptable content types (e.g., ['text/html', 'application/xhtml+xml'])
 * @param methodName - The name of the fetch method (for error messages)
 * @throws Error if content type doesn't match expected types
 */
export function checkContentType(
  response: Response,
  expectedTypes: string[],
  methodName: string,
): void {
  // Skip validation if disabled via environment variable
  if (!validateContentType) return;

  const contentType = response.headers.get("content-type");

  // If no content-type header, allow the request (some servers don't set it)
  if (!contentType) return;

  // Extract the media type (ignore charset and other parameters)
  const mediaType = contentType.split(";")[0].trim().toLowerCase();

  // Check if the media type matches any expected type
  const isValid = expectedTypes.some(
    (expected) => mediaType === expected.toLowerCase(),
  );

  if (!isValid) {
    throw new Error(
      `Unexpected content type for ${methodName}: got "${mediaType}", ` +
        `expected one of: ${expectedTypes.join(", ")}. ` +
        `Set VALIDATE_CONTENT_TYPE=false to disable this check.`,
    );
  }
}
