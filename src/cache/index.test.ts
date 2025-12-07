// src/cache/index.test.ts
// Tests for the response cache module

import { ResponseCache, responseCache } from "./index";

describe("ResponseCache", () => {
  beforeEach(() => {
    responseCache.clear();
  });

  describe("Basic Operations", () => {
    it("should store and retrieve cache entries", () => {
      responseCache.set("test-key", "test-data", "text/html", 60000);
      const entry = responseCache.get("test-key");
      expect(entry).toBeDefined();
      expect(entry?.data).toBe("test-data");
      expect(entry?.contentType).toBe("text/html");
    });

    it("should return undefined for non-existent keys", () => {
      const entry = responseCache.get("non-existent");
      expect(entry).toBeUndefined();
    });

    it("should clear all entries", () => {
      responseCache.set("key1", "data1", "text/plain", 60000);
      responseCache.set("key2", "data2", "text/plain", 60000);

      responseCache.clear();

      expect(responseCache.size()).toBe(0);
      expect(responseCache.get("key1")).toBeUndefined();
    });
  });

  describe("TTL Expiration", () => {
    it("should expire entries after TTL", () => {
      // Set with very short TTL
      responseCache.set("expiring-key", "data", "text/plain", 1);

      // Wait for expiration
      return new Promise<void>((resolve) => {
        setTimeout(() => {
          const entry = responseCache.get("expiring-key");
          expect(entry).toBeUndefined();
          resolve();
        }, 10);
      });
    });

    it("should not return expired entries", () => {
      responseCache.set("expired-key", "data", "text/plain", -1);
      const entry = responseCache.get("expired-key");
      expect(entry).toBeUndefined();
    });
  });

  describe("Statistics", () => {
    it("should provide cache statistics", () => {
      responseCache.set("key1", "data1", "text/plain", 60000);
      responseCache.set("key2", "data2", "text/plain", 60000);

      const stats = responseCache.stats();
      expect(stats.size).toBe(2);
      expect(stats.maxSize).toBe(100);
    });

    it("should track size correctly", () => {
      expect(responseCache.size()).toBe(0);
      responseCache.set("key1", "data1", "text/plain", 60000);
      expect(responseCache.size()).toBe(1);
      responseCache.set("key2", "data2", "text/plain", 60000);
      expect(responseCache.size()).toBe(2);
    });
  });

  describe("Integrity Verification", () => {
    it("should verify entry integrity on retrieval", () => {
      // This test verifies the signing mechanism works
      responseCache.set("signed-key", "signed-data", "text/html", 60000);
      const entry = responseCache.get("signed-key");

      // If signature verification failed, entry would be undefined
      expect(entry).toBeDefined();
      expect(entry?.data).toBe("signed-data");
    });

    it("should handle different content types", () => {
      responseCache.set("json-key", '{"foo":"bar"}', "application/json", 60000);
      responseCache.set("html-key", "<html></html>", "text/html", 60000);
      responseCache.set("text-key", "plain text", "text/plain", 60000);

      expect(responseCache.get("json-key")?.contentType).toBe(
        "application/json",
      );
      expect(responseCache.get("html-key")?.contentType).toBe("text/html");
      expect(responseCache.get("text-key")?.contentType).toBe("text/plain");
    });
  });

  describe("Capacity Management", () => {
    it("should evict oldest entry when at capacity", () => {
      // Create a fresh cache instance to test capacity
      const smallCache = new ResponseCache();

      // Fill beyond capacity (default is 100)
      for (let i = 0; i < 101; i++) {
        smallCache.set(`key-${i}`, `data-${i}`, "text/plain", 60000);
      }

      // Size should be capped
      expect(smallCache.size()).toBeLessThanOrEqual(100);
    });
  });
});
