// src/processors/worker-utils.ts
// Utilities for sandboxed worker processing

import { runInWorker } from "../workers/index.js";
import type { WorkerInput, WorkerOutput } from "../workers/html-processor.js";

/**
 * Sanitize worker output to remove potentially dangerous content
 * that might have leaked through HTML processing
 */
export function sanitiseWorkerOutput(output: string): string {
  let sanitized = output;

  // Remove any script tags that might have leaked through
  sanitized = sanitized.replace(
    /<script[\s\S]*?<\/script>/gi,
    "[SCRIPT REMOVED]",
  );
  sanitized = sanitized.replace(/<script[^>]*>/gi, "[SCRIPT REMOVED]");

  // Remove iframe tags
  sanitized = sanitized.replace(
    /<iframe[\s\S]*?<\/iframe>/gi,
    "[IFRAME REMOVED]",
  );
  sanitized = sanitized.replace(/<iframe[^>]*\/?>/gi, "[IFRAME REMOVED]");

  // Remove object/embed tags (potential XSS vectors)
  sanitized = sanitized.replace(
    /<object[\s\S]*?<\/object>/gi,
    "[OBJECT REMOVED]",
  );
  sanitized = sanitized.replace(/<embed[^>]*\/?>/gi, "[EMBED REMOVED]");

  // Remove event handlers (onclick, onerror, etc.)
  sanitized = sanitized.replace(/\s+on\w+\s*=\s*["'][^"']*["']/gi, "");
  sanitized = sanitized.replace(/\s+on\w+\s*=\s*[^\s>]+/gi, "");

  // Remove javascript: URLs
  sanitized = sanitized.replace(/javascript:/gi, "blocked:");

  // Remove data: URLs in href/src attributes (potential XSS)
  sanitized = sanitized.replace(
    /\s+(href|src)\s*=\s*["']?\s*data:/gi,
    ' $1="blocked:',
  );

  // Remove vbscript: URLs
  sanitized = sanitized.replace(/vbscript:/gi, "blocked:");

  return sanitized;
}

/**
 * Process HTML in a sandboxed worker thread
 */
export async function processHtmlSandboxed(
  html: string,
  mode: "text" | "markdown",
): Promise<string> {
  const workerResult = await runInWorker<WorkerInput, WorkerOutput>(
    "html-processor.js",
    { html, mode },
  );

  // Workers post a single WorkerOutput object. Older mocks may wrap it in a
  // { success, result: WorkerOutput } envelope, so unwrap defensively.
  const output: WorkerOutput | undefined = (() => {
    // Wrapped shape: { success: true, result: WorkerOutput }
    if (
      workerResult &&
      typeof workerResult === "object" &&
      "result" in workerResult &&
      workerResult.result &&
      typeof workerResult.result === "object" &&
      "success" in (workerResult as { result: WorkerOutput }).result
    ) {
      return (workerResult as { result: WorkerOutput }).result;
    }

    // Direct WorkerOutput shape
    if (
      workerResult &&
      typeof workerResult === "object" &&
      "success" in workerResult
    ) {
      const candidate = workerResult as WorkerOutput;
      const resultIsString = typeof candidate.result === "string";
      const resultIsUndefined = typeof candidate.result === "undefined";
      if (
        typeof candidate.success === "boolean" &&
        (resultIsString || resultIsUndefined || "error" in candidate)
      ) {
        return candidate;
      }
    }

    return undefined;
  })();

  if (!output || !output.success || !output.result) {
    const errorMessage =
      (output && output.error) ||
      (workerResult as { error?: string })?.error ||
      "Worker processing failed";
    throw new Error(errorMessage);
  }

  // Sanitize the worker output before returning
  return sanitiseWorkerOutput(output.result);
}
