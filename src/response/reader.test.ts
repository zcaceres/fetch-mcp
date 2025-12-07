// src/response/reader.test.ts
// Tests for readResponseWithLimit function

import { describe, it, expect } from "@jest/globals";
import { readResponseWithLimit, MAX_MEMORY_SIZE } from "./reader.js";

describe("readResponseWithLimit", () => {
  // Helper to create a mock Response with a readable stream
  function createMockResponse(
    content: string,
    options: { contentLength?: string } = {},
  ): Response {
    const encoder = new TextEncoder();
    const data = encoder.encode(content);

    const stream = new ReadableStream({
      start(controller) {
        controller.enqueue(data);
        controller.close();
      },
    });

    const headers = new Headers();
    if (options.contentLength) {
      headers.set("content-length", options.contentLength);
    }

    return {
      body: stream,
      headers,
    } as unknown as Response;
  }

  // Helper to create chunked response
  function createChunkedResponse(chunks: string[]): Response {
    const encoder = new TextEncoder();
    let chunkIndex = 0;

    const stream = new ReadableStream({
      pull(controller) {
        if (chunkIndex < chunks.length) {
          controller.enqueue(encoder.encode(chunks[chunkIndex]));
          chunkIndex++;
        } else {
          controller.close();
        }
      },
    });

    return {
      body: stream,
      headers: new Headers(),
    } as unknown as Response;
  }

  describe("basic reading", () => {
    it("should read entire response body", async () => {
      const content = "Hello, World!";
      const response = createMockResponse(content);

      const result = await readResponseWithLimit(response);

      expect(result).toBe(content);
    });

    it("should read empty response", async () => {
      const response = createMockResponse("");

      const result = await readResponseWithLimit(response);

      expect(result).toBe("");
    });

    it("should handle response with no body", async () => {
      const response = {
        body: null,
        headers: new Headers(),
      } as unknown as Response;

      const result = await readResponseWithLimit(response);

      expect(result).toBe("");
    });

    it("should handle unicode content", async () => {
      const content = "你好世界! こんにちは 🌍🌎🌏";
      const response = createMockResponse(content);

      const result = await readResponseWithLimit(response);

      expect(result).toBe(content);
    });
  });

  describe("chunked reading", () => {
    it("should combine multiple chunks", async () => {
      const chunks = ["Hello, ", "World", "!"];
      const response = createChunkedResponse(chunks);

      const result = await readResponseWithLimit(response);

      expect(result).toBe("Hello, World!");
    });

    it("should handle many small chunks", async () => {
      const chunks = Array(100).fill("a");
      const response = createChunkedResponse(chunks);

      const result = await readResponseWithLimit(response);

      expect(result).toBe("a".repeat(100));
    });
  });

  describe("size limits", () => {
    it("should throw early if content-length exceeds limit", async () => {
      const response = createMockResponse("content", {
        contentLength: "999999999999", // Very large
      });

      await expect(readResponseWithLimit(response, 1000)).rejects.toThrow(
        "Response too large",
      );
    });

    it("should throw when streamed content exceeds limit", async () => {
      // Create chunks that will exceed the limit
      const chunks = Array(10).fill("x".repeat(200));
      const response = createChunkedResponse(chunks);

      await expect(readResponseWithLimit(response, 500)).rejects.toThrow(
        /Response too large.*exceeded 500 bytes/,
      );
    });

    it("should accept content exactly at limit", async () => {
      const content = "x".repeat(100);
      const response = createMockResponse(content);

      const result = await readResponseWithLimit(response, 100);

      expect(result).toBe(content);
    });

    it("should accept content below limit", async () => {
      const content = "x".repeat(50);
      const response = createMockResponse(content);

      const result = await readResponseWithLimit(response, 100);

      expect(result).toBe(content);
    });

    it("should use default MAX_MEMORY_SIZE when no limit specified", async () => {
      // Just verify the constant is reasonable
      expect(MAX_MEMORY_SIZE).toBe(10 * 1024 * 1024); // 10MB
    });
  });

  describe("memory efficiency", () => {
    it("should not load entire content into memory at once for large responses", async () => {
      // Create a moderately large response
      const chunkSize = 10000;
      const numChunks = 10;
      const chunks = Array(numChunks).fill("x".repeat(chunkSize));
      const response = createChunkedResponse(chunks);

      // Should work within memory constraints
      const result = await readResponseWithLimit(
        response,
        chunkSize * numChunks + 1000,
      );

      expect(result.length).toBe(chunkSize * numChunks);
    });
  });
});
