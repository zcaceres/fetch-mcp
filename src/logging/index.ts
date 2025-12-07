// src/logging/index.ts
// Logging and metrics utilities

import { logLevel, logFormat, enableMetrics } from "../config/constants.js";

// Fetch metrics interface
export interface FetchMetrics {
  timestamp: string;
  type: "fetch_request";
  url: string; // sanitized
  tool: string;
  duration: number;
  status: "success" | "error";
  errorType?: string;
  contentLength?: number;
  redirectCount?: number;
  cached?: boolean;
}

/**
 * Emit a fetch metric to stderr (for collection by external systems)
 */
export function emitMetric(metric: FetchMetrics): void {
  if (!enableMetrics) return;

  if (logFormat === "pretty") {
    const { timestamp, type, url, tool, duration, status, ...rest } = metric;
    const extras =
      Object.keys(rest).length > 0 ? ` ${JSON.stringify(rest)}` : "";
    console.error(
      `[${timestamp}] METRIC ${tool} ${status} ${duration}ms ${url}${extras}`,
    );
  } else {
    console.error(JSON.stringify(metric));
  }
}

/**
 * Log a message at the specified level
 */
export function log(
  level: "error" | "warn" | "info" | "debug",
  message: string,
  data?: object,
): void {
  const levels = { error: 0, warn: 1, info: 2, debug: 3 };
  const currentLevel = levels[logLevel as keyof typeof levels] ?? 0;

  if (levels[level] > currentLevel) return;

  if (logFormat === "pretty") {
    const timestamp = new Date().toISOString();
    const levelUpper = level.toUpperCase().padEnd(5);
    const dataStr = data ? ` | ${JSON.stringify(data)}` : "";
    console.error(`[${timestamp}] ${levelUpper} ${message}${dataStr}`);
  } else {
    console.error(
      JSON.stringify({
        timestamp: new Date().toISOString(),
        level,
        message,
        ...data,
      }),
    );
  }
}
