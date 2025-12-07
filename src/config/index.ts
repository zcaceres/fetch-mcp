// src/config/index.ts
// Configuration module - exports all configuration values and utilities

// Re-export all constants
export {
  downloadLimit,
  safeFetchLimit,
  enableDnsCheck,
  dnsFailClosed,
  requestTimeout,
  maxRedirects,
  sanitizeErrors,
  BLOCKED_HEADERS,
  AUTH_HEADERS,
  allowAuthHeaders,
  validateContentType,
  EXPECTED_CONTENT_TYPES,
  includeMetadata,
  MAX_METADATA_SIZE,
  htmlWorkerMaxMemoryMb,
  htmlWorkerYoungMemoryMb,
  htmlWorkerCodeRangeMb,
  enableHtmlSandbox,
  allowUnsafeHtml,
  htmlWorkerTimeout,
  enableMetrics,
  logLevel,
  logFormat,
  maxRequestsPerMinute,
  enableCache,
  cacheTTL,
  RequestPayloadSchema,
  type RequestPayload,
} from "./constants.js";

// Re-export validation
export {
  validateConfiguration,
  type ConfigValidationError,
} from "./validation.js";
