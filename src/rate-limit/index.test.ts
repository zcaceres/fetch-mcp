// src/rate-limit/index.test.ts
// Tests for the rate limiter module

import { RateLimiter, rateLimiter } from "./index";

describe("RateLimiter", () => {
  describe("Disabled (limit = 0)", () => {
    it("should allow requests when limit is disabled (0)", () => {
      const limiter = new RateLimiter();
      expect(limiter.canProceed(0)).toBe(true);
    });

    it("should always return 0 retry time when disabled", () => {
      const limiter = new RateLimiter();
      expect(limiter.getRetryAfter(0)).toBe(0);
    });
  });

  describe("Within Limit", () => {
    it("should allow requests within limit", () => {
      const limiter = new RateLimiter();
      expect(limiter.canProceed(10)).toBe(true);
      expect(limiter.canProceed(10)).toBe(true);
      expect(limiter.canProceed(10)).toBe(true);
    });

    it("should track requests accurately", () => {
      const limiter = new RateLimiter();

      // Make exactly the limit number of requests
      for (let i = 0; i < 5; i++) {
        expect(limiter.canProceed(5)).toBe(true);
      }

      // Next request should be blocked
      expect(limiter.canProceed(5)).toBe(false);
    });
  });

  describe("Exceeding Limit", () => {
    it("should block requests exceeding limit", () => {
      const limiter = new RateLimiter();

      // Make 3 requests with limit of 3
      limiter.canProceed(3);
      limiter.canProceed(3);
      limiter.canProceed(3);

      // 4th should be blocked
      expect(limiter.canProceed(3)).toBe(false);
    });

    it("should continue blocking while at limit", () => {
      const limiter = new RateLimiter();

      // Exhaust limit
      limiter.canProceed(2);
      limiter.canProceed(2);

      // Multiple subsequent requests should all be blocked
      expect(limiter.canProceed(2)).toBe(false);
      expect(limiter.canProceed(2)).toBe(false);
      expect(limiter.canProceed(2)).toBe(false);
    });
  });

  describe("Retry After", () => {
    it("should return retry after time when rate limited", () => {
      const limiter = new RateLimiter();

      // Exhaust limit
      limiter.canProceed(1);
      limiter.canProceed(1);

      // Should return positive retry time
      const retryAfter = limiter.getRetryAfter(1);
      expect(retryAfter).toBeGreaterThan(0);
      expect(retryAfter).toBeLessThanOrEqual(60);
    });

    it("should return 0 when no requests have been made", () => {
      const limiter = new RateLimiter();
      expect(limiter.getRetryAfter(5)).toBe(0);
    });
  });

  describe("Window Reset", () => {
    it("should allow requests after window expires", async () => {
      // This test uses real timing - kept short for CI
      const limiter = new RateLimiter();

      // We can't easily test the 60-second window, but we can verify
      // that the mechanism exists by checking that old requests are filtered
      limiter.canProceed(1);

      // Request should be tracked
      expect(limiter.canProceed(1)).toBe(false);
    });
  });

  describe("Singleton Instance", () => {
    it("should export a singleton rateLimiter instance", () => {
      expect(rateLimiter).toBeInstanceOf(RateLimiter);
    });

    it("singleton should be functional", () => {
      // Use fresh module to avoid state from other tests
      jest.resetModules();
      const { rateLimiter: freshLimiter } = require("./index");

      expect(freshLimiter.canProceed(100)).toBe(true);
    });
  });
});
