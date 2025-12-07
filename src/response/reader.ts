// src/response/reader.ts
// Memory-safe response reading with size limits

// Max content size to read into memory (10MB)
const MAX_MEMORY_SIZE = 10 * 1024 * 1024;

/**
 * Read response body with memory limit protection
 *
 * Fix #7: Prevent memory exhaustion attacks by limiting response size
 *
 * This function streams the response body in chunks and enforces a maximum
 * size limit to prevent malicious or oversized responses from exhausting
 * server memory.
 *
 * @param response - The HTTP response to read
 * @param maxSize - Maximum allowed size in bytes (default: 10MB)
 * @returns The response body as a string
 * @throws Error if response exceeds maxSize
 */
export async function readResponseWithLimit(
  response: Response,
  maxSize = MAX_MEMORY_SIZE,
): Promise<string> {
  const contentLength = response.headers.get("content-length");

  // If content-length is known and exceeds limit, throw early
  if (contentLength && parseInt(contentLength) > maxSize) {
    throw new Error(
      `Response too large: ${contentLength} bytes (max: ${maxSize})`,
    );
  }

  // Read in chunks to limit memory usage
  const reader = response.body?.getReader();
  if (!reader) {
    return "";
  }

  const chunks: Uint8Array[] = [];
  let totalSize = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();

      if (done) break;

      totalSize += value.length;
      if (totalSize > maxSize) {
        reader.cancel();
        throw new Error(`Response too large: exceeded ${maxSize} bytes`);
      }

      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  // Combine chunks and decode
  const combined = new Uint8Array(totalSize);
  let offset = 0;
  for (const chunk of chunks) {
    combined.set(chunk, offset);
    offset += chunk.length;
  }

  return new TextDecoder().decode(combined);
}

// Export the default max size for reference
export { MAX_MEMORY_SIZE };
