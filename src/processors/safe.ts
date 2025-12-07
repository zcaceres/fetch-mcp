// src/processors/safe.ts
import type { ContentProcessor, ProcessorOptions } from "./index.js";
import { JSDOM } from "jsdom";
import { EXPECTED_CONTENT_TYPES, safeFetchLimit } from "../types.js";
import { log } from "../logging/index.js";
import { processHtmlSandboxed } from "./worker-utils.js";

/**
 * Safe content processor - ultra-hardened text extraction
 *
 * Features:
 * - Strips to plain text only (no HTML structure)
 * - Removes scripts, styles, and comments
 * - Sanitizes Unicode control characters
 * - Strips any remaining HTML-like patterns
 * - Enforces configurable max length (default 2000 characters)
 */
export class SafeProcessor implements ContentProcessor {
  name = "safe";
  toolName = "fetch_safe";
  description = "Ultra-hardened text extraction with maximum safety";
  expectedContentTypes = [
    ...EXPECTED_CONTENT_TYPES.text,
    ...EXPECTED_CONTENT_TYPES.html,
  ];
  defaultContentType = "text/plain";
  contentTypeOverride = "text/plain"; // Always report as plain text
  maxLengthOverride = safeFetchLimit; // Configurable limit via SAFE_FETCH_LIMIT env var

  async process(content: string, options: ProcessorOptions): Promise<string> {
    let text: string;

    // Always prefer sandbox for safe mode
    if (options.useSandbox) {
      log("debug", "Using sandboxed HTML processing", {
        url: options.url,
        tool: this.toolName,
      });
      text = await processHtmlSandboxed(content, "text");
    } else {
      // Fallback non-sandboxed processing
      const dom = new JSDOM(content);
      const document = dom.window.document;

      // Remove scripts and styles
      const scripts = document.getElementsByTagName("script");
      const styles = document.getElementsByTagName("style");
      Array.from(scripts).forEach((script) => script.remove());
      Array.from(styles).forEach((style) => style.remove());

      const rawText = document.body.textContent || "";
      text = rawText.replace(/\s+/g, " ").trim();
    }

    // Additional sanitization for safe mode
    text = this.sanitize(text);

    return text;
  }

  /**
   * Apply additional sanitization for maximum safety
   */
  private sanitize(text: string): string {
    // Strip Unicode control characters (except common whitespace)
    // Includes: NULL to BACKSPACE, vertical tab, form feed, shift chars, DEL, C1 controls
    // Also zero-width chars and special spaces
    let sanitized = text.replace(
      /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F\u200B-\u200F\u2028-\u202F\uFEFF]/g,
      "",
    );

    // Normalize whitespace aggressively
    sanitized = sanitized.replace(/\s+/g, " ").trim();

    // Strip any remaining HTML-like patterns that might have leaked through
    sanitized = sanitized.replace(/<[^>]*>/g, "");

    return sanitized;
  }
}
