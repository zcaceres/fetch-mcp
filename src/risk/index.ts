// src/risk/index.ts
// Risk detection module - exports all risk-related functionality

// Re-export types
export type { ResponseMetadata, SecurityContext } from "./types.js";
export type { RiskProfile } from "./profiles.js";

// Re-export profiles
export { getRiskProfile, mapRiskLevelToScore } from "./profiles.js";

// Re-export encoding utilities
export {
  decodeHtmlEntities,
  normalizeHomoglyphs,
  detectBase64Injection,
  decodeUrlEncoding,
  decodeHtmlEntitiesRecursive,
  decodePunycode,
  normalizeForDetection,
} from "./encoding.js";

// Re-export detection patterns (for testing)
export {
  INJECTION_PATTERNS,
  DELIMITER_ESCAPE_PATTERNS,
  SOCIAL_ENGINEERING_PATTERNS,
  MULTI_TOOL_PATTERNS,
  CONTEXT_OVERFLOW_PATTERNS,
} from "./patterns.js";

// Re-export detection function
export { detectKnownRisks } from "./detection.js";
