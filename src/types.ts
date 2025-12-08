// src/types.ts
// Re-export all types and utilities from their respective modules
// This maintains backward compatibility with existing imports

import { z } from "zod";

// Re-export configuration
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
  validateConfiguration,
  type ConfigValidationError,
} from "./config/index.js";

// Re-export risk detection
export {
  type ResponseMetadata,
  type SecurityContext,
  type RiskProfile,
  getRiskProfile,
  mapRiskLevelToScore,
  decodeHtmlEntities,
  normalizeHomoglyphs,
  detectBase64Injection,
  detectKnownRisks,
  decodeUrlEncoding,
  decodeHtmlEntitiesRecursive,
  decodePunycode,
  normalizeForDetection,
} from "./risk/index.js";

// Re-export cache
export { ResponseCache, responseCache } from "./cache/index.js";

// Re-export rate limiting
export { RateLimiter, rateLimiter } from "./rate-limit/index.js";

// Re-export logging
export { type FetchMetrics, emitMetric, log } from "./logging/index.js";

// Re-export dependency injection
export { type FetcherDependencies, dependencies } from "./deps/index.js";
