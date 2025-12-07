// src/Fetcher.ts
// Fetch orchestration - coordinates processors, security, caching, and metrics

import {
  RequestPayload,
  rateLimiter,
  maxRequestsPerMinute,
  enableCache,
  cacheTTL,
  responseCache,
  enableHtmlSandbox,
} from "./types.js";
import { ResponseMetadata } from "./risk/index.js";
import { emitMetric, log } from "./logging/index.js";
import { ResponseBuilder, readResponseWithLimit } from "./response/index.js";
import {
  sanitizeUrlForError,
  sanitizeHeaders,
  secureFetch,
  checkContentType,
} from "./security/index.js";
import {
  processorRegistry,
  type ContentProcessor,
} from "./processors/index.js";

/**
 * Apply start_index and max_length limits to content
 */
function applyLengthLimits(
  text: string,
  maxLength: number,
  startIndex: number,
): string {
  if (startIndex >= text.length) {
    return "";
  }

  const end =
    maxLength > 0 ? Math.min(startIndex + maxLength, text.length) : text.length;
  return text.substring(startIndex, end);
}

/**
 * Execute a fetch using a content processor
 * Orchestrates: caching, rate limiting, security, processing, and metrics
 */
async function fetchWithProcessor(
  requestPayload: RequestPayload,
  processor: ContentProcessor,
) {
  const startTime = Date.now();
  const safeUrl = sanitizeUrlForError(requestPayload.url);

  // Apply max length (use processor override if available)
  const maxLength =
    processor.maxLengthOverride !== undefined
      ? Math.min(
          requestPayload.max_length ?? processor.maxLengthOverride,
          processor.maxLengthOverride,
        )
      : (requestPayload.max_length ?? 5000);
  const startIndex = requestPayload.start_index ?? 0;

  // Generate cache key
  const cacheKey = `${processor.toolName}:${requestPayload.url}:${JSON.stringify(requestPayload.headers ?? {})}`;

  const emitSuccessMetric = (contentLength: number, cached: boolean) => {
    emitMetric({
      timestamp: new Date().toISOString(),
      type: "fetch_request",
      url: safeUrl,
      tool: processor.toolName,
      duration: Date.now() - startTime,
      status: "success",
      contentLength,
      cached,
    });
  };

  const emitErrorMetric = (error: Error) => {
    emitMetric({
      timestamp: new Date().toISOString(),
      type: "fetch_request",
      url: safeUrl,
      tool: processor.toolName,
      duration: Date.now() - startTime,
      status: "error",
      errorType: error.name,
    });
  };

  try {
    // Check cache first
    if (enableCache) {
      const cached = responseCache.get(cacheKey);
      if (cached) {
        log("debug", "Cache hit", { url: safeUrl, tool: processor.toolName });

        const totalLength = cached.data.length;
        const content = applyLengthLimits(cached.data, maxLength, startIndex);

        const metadataContentType =
          processor.contentTypeOverride ?? cached.contentType;

        const metadata: ResponseMetadata = {
          truncated: startIndex + content.length < totalLength,
          totalLength,
          startIndex,
          fetchedLength: content.length,
          contentType: metadataContentType,
        };

        emitSuccessMetric(content.length, true);

        return new ResponseBuilder()
          .setContent(content)
          .setMetadata(metadata)
          .build();
      }
    }

    // Rate limiting check
    if (!rateLimiter.canProceed(maxRequestsPerMinute)) {
      const retryAfter = rateLimiter.getRetryAfter(maxRequestsPerMinute);
      throw new Error(
        `Rate limit exceeded (${maxRequestsPerMinute} requests/minute). ` +
          `Retry after ${retryAfter} seconds.`,
      );
    }

    // Fetch with security protections
    const sanitizedHeaders = sanitizeHeaders(requestPayload.headers);
    const response = await secureFetch(requestPayload.url, sanitizedHeaders);

    // Validate content type
    checkContentType(
      response,
      processor.expectedContentTypes,
      processor.toolName,
    );

    // Read response with memory limit
    const rawContent = await readResponseWithLimit(response);

    // Process content using the processor
    const fullContent = await processor.process(rawContent, {
      useSandbox: enableHtmlSandbox,
      url: safeUrl,
    });
    const totalLength = fullContent.length;

    // Cache the processed content
    if (enableCache) {
      const contentType =
        response.headers.get("content-type") ?? processor.defaultContentType;
      responseCache.set(cacheKey, fullContent, contentType, cacheTTL);
      log("debug", "Cached response", {
        url: safeUrl,
        tool: processor.toolName,
      });
    }

    // Apply length limits
    const content = applyLengthLimits(fullContent, maxLength, startIndex);

    // Use content type override if specified
    const metadataContentType =
      processor.contentTypeOverride ??
      response.headers.get("content-type") ??
      undefined;

    const metadata: ResponseMetadata = {
      truncated: startIndex + content.length < totalLength,
      totalLength,
      startIndex,
      fetchedLength: content.length,
      contentType: metadataContentType,
    };

    emitSuccessMetric(content.length, false);

    return new ResponseBuilder()
      .setContent(content)
      .setMetadata(metadata)
      .build();
  } catch (error) {
    emitErrorMetric(error as Error);
    const errorMessage = (error as Error).message;
    const fullErrorMessage = errorMessage.includes(safeUrl)
      ? errorMessage
      : `Failed to fetch ${safeUrl}: ${errorMessage}`;
    return ResponseBuilder.errorResponse(fullErrorMessage);
  }
}

/**
 * Fetcher class - provides methods for fetching and processing web content
 * Uses the processor registry for content processing
 */
export class Fetcher {
  /**
   * Fetch raw HTML content
   */
  static async html(requestPayload: RequestPayload) {
    const processor = processorRegistry.get("html");
    if (!processor) throw new Error("HTML processor not registered");
    return fetchWithProcessor(requestPayload, processor);
  }

  /**
   * Fetch and parse JSON content
   */
  static async json(requestPayload: RequestPayload) {
    const processor = processorRegistry.get("json");
    if (!processor) throw new Error("JSON processor not registered");
    return fetchWithProcessor(requestPayload, processor);
  }

  /**
   * Fetch and extract plain text from HTML
   */
  static async txt(requestPayload: RequestPayload) {
    const processor = processorRegistry.get("text");
    if (!processor) throw new Error("Text processor not registered");
    return fetchWithProcessor(requestPayload, processor);
  }

  /**
   * Fetch and convert HTML to Markdown
   */
  static async markdown(requestPayload: RequestPayload) {
    const processor = processorRegistry.get("markdown");
    if (!processor) throw new Error("Markdown processor not registered");
    return fetchWithProcessor(requestPayload, processor);
  }

  /**
   * Ultra-hardened fetch with maximum safety processing
   */
  static async safe(requestPayload: RequestPayload) {
    const processor = processorRegistry.get("safe");
    if (!processor) throw new Error("Safe processor not registered");
    return fetchWithProcessor(requestPayload, processor);
  }
}

// Export for testing
export { fetchWithProcessor, applyLengthLimits };
