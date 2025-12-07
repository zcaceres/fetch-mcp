// src/config/constants.ts
// Configuration constants and environment variable parsing

import { z } from "zod";

// Download limit
export const downloadLimit =
  Number.parseInt(process.env.DEFAULT_LIMIT ?? "5000") ?? 5000;

// Safe fetch limit (stricter default for security-conscious mode)
// Capped at 10000 to prevent extreme context window usage
const SAFE_FETCH_MAX = 10000;
const SAFE_FETCH_DEFAULT = 2000;
export const safeFetchLimit = Math.min(
  Number.parseInt(process.env.SAFE_FETCH_LIMIT ?? String(SAFE_FETCH_DEFAULT)) ||
    SAFE_FETCH_DEFAULT,
  SAFE_FETCH_MAX,
);

// SSRF protection config - secure defaults
export const enableDnsCheck = process.env.SSRF_DNS_CHECK !== "false"; // default: true
export const dnsFailClosed = process.env.SSRF_DNS_FAIL_CLOSED !== "false"; // default: true (fail closed = secure)

// Request security config
export const requestTimeout = Number.parseInt(
  process.env.REQUEST_TIMEOUT ?? "30000",
); // default: 30 seconds
export const maxRedirects = Number.parseInt(process.env.MAX_REDIRECTS ?? "5"); // default: 5 redirects
export const sanitizeErrors = process.env.SANITIZE_ERRORS !== "false"; // default: true (hide sensitive URL params)

// Blocked headers that could be used for attacks
export const BLOCKED_HEADERS = [
  "host",
  "set-cookie",
  "x-forwarded-for",
  "x-forwarded-host",
  "x-real-ip",
  "proxy-authorization",
  "www-authenticate",
];

// Auth headers - blocked by default, can be allowed via ALLOW_AUTH_HEADERS=true
export const AUTH_HEADERS = ["authorization", "cookie"];
export const allowAuthHeaders = process.env.ALLOW_AUTH_HEADERS === "true"; // default: false (secure)

// Content type validation (default: true for security)
export const validateContentType =
  process.env.VALIDATE_CONTENT_TYPE !== "false";

// Expected content types for each fetch method
export const EXPECTED_CONTENT_TYPES = {
  html: ["text/html", "application/xhtml+xml"],
  json: [
    "application/json",
    "text/json",
    "application/ld+json",
    "application/feed+json",
  ],
  text: ["text/html", "text/plain", "application/xhtml+xml"],
  markdown: [
    "text/html",
    "application/xhtml+xml",
    "text/markdown",
    "text/x-markdown",
    "text/plain",
  ],
};

// Response metadata configuration
export const includeMetadata =
  process.env.INCLUDE_RESPONSE_METADATA !== "false"; // default: true

// Limit metadata size to prevent context flooding
export const MAX_METADATA_SIZE = 8 * 1024; // 8KB

// HTML Worker resource limits
export const htmlWorkerMaxMemoryMb = Number.parseInt(
  process.env.HTML_WORKER_MAX_MB ?? "128",
); // default 128MB old-space limit

export const htmlWorkerYoungMemoryMb = Number.parseInt(
  process.env.HTML_WORKER_YOUNG_MB ?? "32",
); // V8 young gen default

export const htmlWorkerCodeRangeMb = Number.parseInt(
  process.env.HTML_WORKER_CODE_MB ?? "64",
);

// HTML sandboxing configuration - secure by default
export const enableHtmlSandbox = process.env.ENABLE_HTML_SANDBOX !== "false"; // default: true (secure)
export const allowUnsafeHtml = process.env.ALLOW_UNSAFE_HTML === "true"; // explicit opt-out
export const htmlWorkerTimeout = Number.parseInt(
  process.env.HTML_WORKER_TIMEOUT ?? "10000",
); // 10 seconds

// Observability configuration
export const enableMetrics = process.env.ENABLE_METRICS === "true"; // default: false
export const logLevel = process.env.LOG_LEVEL ?? "error"; // error, warn, info, debug
export const logFormat = process.env.LOG_FORMAT ?? "json"; // json (for production) | pretty (for local dev)

// Rate limiting configuration (default: 60 for production security)
export const maxRequestsPerMinute = Number.parseInt(
  process.env.MAX_REQUESTS_PER_MINUTE ?? "60",
); // 60 requests/minute default, 0 = disabled

// Response caching configuration
export const enableCache = process.env.ENABLE_CACHE === "true"; // default: false
export const cacheTTL = Number.parseInt(process.env.CACHE_TTL ?? "300000"); // 5 minutes

// Request payload schema
export const RequestPayloadSchema = z.object({
  url: z.string().url(),
  headers: z.record(z.string()).optional(),
  max_length: z.number().int().min(0).optional().default(downloadLimit),
  start_index: z.number().int().min(0).optional().default(0),
});

// Make sure TypeScript treats the fields as optional with defaults
export type RequestPayload = {
  url: string;
  headers?: Record<string, string>;
  max_length?: number;
  start_index?: number;
};
