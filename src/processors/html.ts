// src/processors/html.ts
import type { ContentProcessor, ProcessorOptions } from "./index.js";
import { EXPECTED_CONTENT_TYPES } from "../types.js";

/**
 * HTML content processor - returns raw HTML as-is
 */
export class HtmlProcessor implements ContentProcessor {
  name = "html";
  toolName = "fetch_html";
  description = "Returns raw HTML content";
  expectedContentTypes = EXPECTED_CONTENT_TYPES.html;
  defaultContentType = "text/html";

  async process(content: string, _options: ProcessorOptions): Promise<string> {
    // HTML is returned as-is, no processing needed
    return content;
  }
}
