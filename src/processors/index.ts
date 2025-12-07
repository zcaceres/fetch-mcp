// src/processors/index.ts

/**
 * Options passed to content processors
 */
export interface ProcessorOptions {
  /** Whether to use sandboxed processing (worker thread) */
  useSandbox: boolean;
  /** URL being processed (for logging) */
  url?: string;
}

/**
 * Interface for content processors
 * Each processor handles a specific content type (HTML, JSON, text, markdown)
 */
export interface ContentProcessor {
  /** Processor identifier */
  name: string;
  /** MCP tool name this processor is used for */
  toolName: string;
  /** Human-readable description */
  description: string;
  /** Expected content types this processor can handle */
  expectedContentTypes: string[];
  /** Default content type for caching/metadata */
  defaultContentType: string;
  /** Override content type in metadata (e.g., safe mode always reports text/plain) */
  contentTypeOverride?: string;
  /** Maximum length override (e.g., safe mode caps at 2000) */
  maxLengthOverride?: number;
  /** Process raw content and return processed output */
  process(content: string, options: ProcessorOptions): Promise<string>;
}

/**
 * Registry for content processors
 */
class ProcessorRegistry {
  private processors = new Map<string, ContentProcessor>();

  register(processor: ContentProcessor): void {
    this.processors.set(processor.name, processor);
  }

  get(name: string): ContentProcessor | undefined {
    return this.processors.get(name);
  }

  getByToolName(toolName: string): ContentProcessor | undefined {
    for (const processor of this.processors.values()) {
      if (processor.toolName === toolName) {
        return processor;
      }
    }
    return undefined;
  }

  getAll(): ContentProcessor[] {
    return Array.from(this.processors.values());
  }

  has(name: string): boolean {
    return this.processors.has(name);
  }
}

export const processorRegistry = new ProcessorRegistry();

// Import and register processors
import { HtmlProcessor } from "./html.js";
import { JsonProcessor } from "./json.js";
import { TextProcessor } from "./text.js";
import { MarkdownProcessor } from "./markdown.js";
import { SafeProcessor } from "./safe.js";

// Auto-register all processors
processorRegistry.register(new HtmlProcessor());
processorRegistry.register(new JsonProcessor());
processorRegistry.register(new TextProcessor());
processorRegistry.register(new MarkdownProcessor());
processorRegistry.register(new SafeProcessor());

// Export processor classes for external use
export { HtmlProcessor } from "./html.js";
export { JsonProcessor } from "./json.js";
export { TextProcessor } from "./text.js";
export { MarkdownProcessor } from "./markdown.js";
export { SafeProcessor } from "./safe.js";
