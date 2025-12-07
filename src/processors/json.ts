// src/processors/json.ts
import type { ContentProcessor, ProcessorOptions } from "./index.js";
import { EXPECTED_CONTENT_TYPES } from "../types.js";

/**
 * JSON content processor - parses and re-stringifies JSON
 * This validates the JSON and normalizes its formatting
 */
export class JsonProcessor implements ContentProcessor {
  name = "json";
  toolName = "fetch_json";
  description = "Parses and returns JSON content";
  expectedContentTypes = EXPECTED_CONTENT_TYPES.json;
  defaultContentType = "application/json";

  async process(content: string, _options: ProcessorOptions): Promise<string> {
    // Parse to validate JSON and then re-stringify
    const json = JSON.parse(content);
    return JSON.stringify(json);
  }
}
