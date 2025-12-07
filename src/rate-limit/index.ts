// src/rate-limit/index.ts
// Simple in-memory rate limiter

/**
 * Simple in-memory rate limiter with sliding window
 */
export class RateLimiter {
  private requests: number[] = [];
  private readonly windowMs = 60000; // 1 minute

  /**
   * Check if a request can proceed given the rate limit
   * @param limit - Maximum requests per minute (0 = disabled)
   * @returns true if the request can proceed
   */
  canProceed(limit: number): boolean {
    if (limit <= 0) return true; // disabled

    const now = Date.now();
    this.requests = this.requests.filter((t) => now - t < this.windowMs);

    if (this.requests.length >= limit) {
      return false;
    }

    this.requests.push(now);
    return true;
  }

  /**
   * Get the number of seconds until the rate limit resets
   * @param limit - Maximum requests per minute
   * @returns Number of seconds to wait before retrying
   */
  getRetryAfter(limit: number): number {
    if (limit <= 0 || this.requests.length === 0) return 0;
    const oldestRequest = Math.min(...this.requests);
    return Math.ceil((this.windowMs - (Date.now() - oldestRequest)) / 1000);
  }

  /**
   * Reset the rate limiter (for testing)
   */
  reset(): void {
    this.requests = [];
  }
}

// Singleton instance
export const rateLimiter = new RateLimiter();
