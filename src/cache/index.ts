// src/cache/index.ts
// Response caching with HMAC-based integrity verification

import { createHmac, randomBytes } from "crypto";
import { log } from "../logging/index.js";

// Generate a unique signing key for this server instance
// This ensures cache entries can't be tampered with
const cacheSigningKey = randomBytes(32).toString("hex");

interface CacheEntry {
  data: string;
  contentType: string;
  expires: number;
  signature: string; // HMAC signature for integrity verification
}

/**
 * Secure response cache with HMAC-based integrity verification
 * Prevents cache poisoning by signing all entries
 */
export class ResponseCache {
  private cache = new Map<string, CacheEntry>();
  private maxSize = 100; // Max entries

  /**
   * Generate HMAC signature for cache entry
   */
  private sign(
    key: string,
    data: string,
    contentType: string,
    expires: number,
  ): string {
    const payload = `${key}:${data}:${contentType}:${expires}`;
    return createHmac("sha256", cacheSigningKey).update(payload).digest("hex");
  }

  /**
   * Verify HMAC signature of cache entry
   */
  private verify(key: string, entry: CacheEntry): boolean {
    const expectedSignature = this.sign(
      key,
      entry.data,
      entry.contentType,
      entry.expires,
    );
    return entry.signature === expectedSignature;
  }

  get(key: string): CacheEntry | undefined {
    const entry = this.cache.get(key);
    if (!entry) return undefined;

    // Check expiration
    if (Date.now() > entry.expires) {
      this.cache.delete(key);
      return undefined;
    }

    // Verify integrity
    if (!this.verify(key, entry)) {
      // Signature mismatch - potential tampering, delete entry
      this.cache.delete(key);
      log("warn", "Cache entry signature verification failed", { key });
      return undefined;
    }

    return entry;
  }

  set(key: string, data: string, contentType: string, ttl: number): void {
    // Evict oldest if at capacity
    if (this.cache.size >= this.maxSize) {
      const oldestKey = this.cache.keys().next().value;
      if (oldestKey) this.cache.delete(oldestKey);
    }

    const expires = Date.now() + ttl;
    const signature = this.sign(key, data, contentType, expires);

    this.cache.set(key, {
      data,
      contentType,
      expires,
      signature,
    });
  }

  clear(): void {
    this.cache.clear();
  }

  size(): number {
    return this.cache.size;
  }

  /**
   * Get cache statistics for monitoring
   */
  stats(): { size: number; maxSize: number } {
    return {
      size: this.cache.size,
      maxSize: this.maxSize,
    };
  }
}

// Singleton instance
export const responseCache = new ResponseCache();
