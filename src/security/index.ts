// src/security/index.ts

// Export all SSRF protection functions
export {
  BLOCKED_RANGES,
  ALLOWED_SCHEMES,
  isBlockedIP,
  validateScheme,
  validateUrlSecurity,
  isSameOrigin,
} from "./ssrf.js";

// Export all header security functions
export { sanitizeUrlForError, sanitizeHeaders } from "./headers.js";

// Export secure fetch function
export { secureFetch } from "./fetch.js";

// Export content type validation
export { checkContentType } from "./content-type.js";

// Export prompt injection test suite
export {
  INJECTION_TEST_CASES,
  getTestCasesByType,
  getTestCasesBySeverity,
  getCriticalTestCases,
  validateRiskDetection,
  generateTestPage,
  type InjectionTestCase,
  type InjectionType,
} from "./injection-cases.js";
