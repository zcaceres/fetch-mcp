// src/processors/text.ts
import type { ContentProcessor, ProcessorOptions } from "./index.js";
import { JSDOM } from "jsdom";
import { EXPECTED_CONTENT_TYPES } from "../types.js";
import { log } from "../logging/index.js";
import { processHtmlSandboxed, sanitiseWorkerOutput } from "./worker-utils.js";

/**
 * Text content processor - extracts plain text from HTML
 * Removes scripts, styles, and normalizes whitespace
 */
export class TextProcessor implements ContentProcessor {
  name = "text";
  toolName = "fetch_txt";
  description = "Extracts plain text from HTML content";
  expectedContentTypes = EXPECTED_CONTENT_TYPES.text;
  defaultContentType = "text/plain";

  async process(content: string, options: ProcessorOptions): Promise<string> {
    if (options.useSandbox) {
      log("debug", "Using sandboxed HTML processing", {
        url: options.url,
        tool: this.toolName,
      });
      return processHtmlSandboxed(content, "text");
    }

    // Non-sandboxed processing using JSDOM
    const dom = new JSDOM(content);
    const document = dom.window.document;

    // Remove scripts and styles
    const scripts = document.getElementsByTagName("script");
    const styles = document.getElementsByTagName("style");
    Array.from(scripts).forEach((script) => script.remove());
    Array.from(styles).forEach((style) => style.remove());

    // Extract text and normalize whitespace
    const text = document.body.textContent || "";
    return text.replace(/\s+/g, " ").trim();
  }
}
