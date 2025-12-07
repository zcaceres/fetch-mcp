// src/config/validation.ts
// Configuration validation logic

import {
  requestTimeout,
  maxRedirects,
  downloadLimit,
  htmlWorkerMaxMemoryMb,
  safeFetchLimit,
} from "./constants.js";

// Configuration validation error type
export interface ConfigValidationError {
  variable: string;
  value: string | undefined;
  message: string;
  severity: "error" | "warning";
}

/**
 * Validate all configuration values at startup
 * Returns an array of validation errors (empty if all valid)
 */
export function validateConfiguration(): ConfigValidationError[] {
  const errors: ConfigValidationError[] = [];

  // Validate REQUEST_TIMEOUT
  if (isNaN(requestTimeout) || requestTimeout <= 0) {
    errors.push({
      variable: "REQUEST_TIMEOUT",
      value: process.env.REQUEST_TIMEOUT,
      message: "Must be a positive integer (milliseconds)",
      severity: "error",
    });
  }

  // Validate MAX_REDIRECTS
  if (isNaN(maxRedirects) || maxRedirects < 0) {
    errors.push({
      variable: "MAX_REDIRECTS",
      value: process.env.MAX_REDIRECTS,
      message: "Must be a non-negative integer",
      severity: "error",
    });
  }

  // Validate DEFAULT_LIMIT
  if (isNaN(downloadLimit) || downloadLimit < 0) {
    errors.push({
      variable: "DEFAULT_LIMIT",
      value: process.env.DEFAULT_LIMIT,
      message: "Must be a non-negative integer (0 = unlimited)",
      severity: "error",
    });
  }

  // Validate CACHE_TTL (if caching is enabled)
  const cacheEnabled = process.env.ENABLE_CACHE === "true";
  const cacheTTLValue = Number.parseInt(process.env.CACHE_TTL ?? "300000");
  if (cacheEnabled) {
    if (isNaN(cacheTTLValue) || cacheTTLValue <= 0) {
      errors.push({
        variable: "CACHE_TTL",
        value: process.env.CACHE_TTL,
        message: "Must be a positive integer (milliseconds)",
        severity: "error",
      });
    }
    // Warn about long cache TTLs (security risk)
    if (cacheTTLValue > 3600000) {
      // > 1 hour
      errors.push({
        variable: "CACHE_TTL",
        value: process.env.CACHE_TTL,
        message: "Long cache TTL (>1 hour) increases cache poisoning risk",
        severity: "warning",
      });
    }
  }

  // Validate MAX_REQUESTS_PER_MINUTE
  const maxReqPerMin = Number.parseInt(
    process.env.MAX_REQUESTS_PER_MINUTE ?? "0",
  );
  if (isNaN(maxReqPerMin) || maxReqPerMin < 0) {
    errors.push({
      variable: "MAX_REQUESTS_PER_MINUTE",
      value: process.env.MAX_REQUESTS_PER_MINUTE,
      message: "Must be a non-negative integer (0 = disabled)",
      severity: "error",
    });
  }

  // Validate HTML_WORKER_TIMEOUT
  const workerTimeout = Number.parseInt(
    process.env.HTML_WORKER_TIMEOUT ?? "10000",
  );
  if (isNaN(workerTimeout) || workerTimeout <= 0) {
    errors.push({
      variable: "HTML_WORKER_TIMEOUT",
      value: process.env.HTML_WORKER_TIMEOUT,
      message: "Must be a positive integer (milliseconds)",
      severity: "error",
    });
  }

  // Validate worker memory limits
  if (isNaN(htmlWorkerMaxMemoryMb) || htmlWorkerMaxMemoryMb <= 0) {
    errors.push({
      variable: "HTML_WORKER_MAX_MB",
      value: process.env.HTML_WORKER_MAX_MB,
      message: "Must be a positive integer (megabytes)",
      severity: "error",
    });
  }

  // Warn about high SAFE_FETCH_LIMIT (increased attack surface)
  if (safeFetchLimit > 5000) {
    errors.push({
      variable: "SAFE_FETCH_LIMIT",
      value: process.env.SAFE_FETCH_LIMIT,
      message: `High safe fetch limit (${safeFetchLimit} chars) increases attack surface. Consider using default (2000) for untrusted content.`,
      severity: "warning",
    });
  }

  return errors;
}
