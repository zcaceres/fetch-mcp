// src/processors/markdown.ts
import type { ContentProcessor, ProcessorOptions } from "./index.js";
import TurndownService from "turndown";
import { EXPECTED_CONTENT_TYPES } from "../types.js";
import { log } from "../logging/index.js";
import { processHtmlSandboxed } from "./worker-utils.js";

// Max LaTeX content length to process (prevent ReDoS)
const MAX_LATEX_PROCESS_LENGTH = 1000000;

/**
 * Fix double-escaped backslashes in LaTeX contexts only
 * Prevents ReDoS by limiting input length
 * See: https://github.com/zcaceres/fetch-mcp/issues/4
 */
function fixLatexEscaping(markdown: string): string {
  // Limit input length to prevent ReDoS
  if (markdown.length > MAX_LATEX_PROCESS_LENGTH) {
    return markdown;
  }

  // Fix inline math: $...$  (but not $$)
  // Fix display math: $$...$$
  return markdown.replace(
    /(\$\$?)([^$]{1,10000}?)(\1)/g,
    (match, open, content, close) => {
      const fixed = content.replace(/\\\\/g, "\\");
      return open + fixed + close;
    },
  );
}

/**
 * Markdown content processor - converts HTML to Markdown
 * Includes LaTeX backslash escape fixing
 */
export class MarkdownProcessor implements ContentProcessor {
  name = "markdown";
  toolName = "fetch_markdown";
  description = "Converts HTML to Markdown format";
  expectedContentTypes = EXPECTED_CONTENT_TYPES.markdown;
  defaultContentType = "text/markdown";

  async process(content: string, options: ProcessorOptions): Promise<string> {
    let markdown: string;

    if (options.useSandbox) {
      log("debug", "Using sandboxed HTML processing", {
        url: options.url,
        tool: this.toolName,
      });
      markdown = await processHtmlSandboxed(content, "markdown");
    } else {
      // Non-sandboxed processing using Turndown
      const turndownService = new TurndownService();
      markdown = turndownService.turndown(content);
    }

    // Fix LaTeX backslash escaping
    return fixLatexEscaping(markdown);
  }
}

// Export for testing
export { fixLatexEscaping };
