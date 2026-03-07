import { describe, it, expect, beforeEach, afterAll, jest } from "bun:test";
import { Fetcher } from "./Fetcher";

const originalFetch = globalThis.fetch;
const mockFetch = jest.fn();

afterAll(() => {
  globalThis.fetch = originalFetch;
});

describe("Fetcher", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    globalThis.fetch = mockFetch as any;
  });

  const mockRequest = {
    url: "https://example.com",
    headers: { "Custom-Header": "Value" },
  };

  const mockHtml = `
    <html>
      <head>
        <title>Test Page</title>
        <script>console.log('This should be removed');</script>
        <style>body { color: red; }</style>
      </head>
      <body>
        <h1>Hello World</h1>
        <p>This is a test paragraph.</p>
      </body>
    </html>
  `;

  describe("html", () => {
    it("should return the raw HTML content", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        text: jest.fn().mockResolvedValueOnce(mockHtml),
      });

      const result = await Fetcher.html(mockRequest);
      expect(result).toEqual({
        content: [{ type: "text", text: mockHtml }],
        isError: false,
      });
    });

    it("should handle errors", async () => {
      mockFetch.mockRejectedValueOnce(new Error("Network error"));

      const result = await Fetcher.html(mockRequest);
      expect(result).toEqual({
        content: [
          {
            type: "text",
            text: "Failed to fetch https://example.com: Network error",
          },
        ],
        isError: true,
      });
    });
  });

  describe("json", () => {
    it("should parse and return JSON content", async () => {
      const mockJson = { key: "value" };
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: jest.fn().mockResolvedValueOnce(mockJson),
      });

      const result = await Fetcher.json(mockRequest);
      expect(result).toEqual({
        content: [{ type: "text", text: JSON.stringify(mockJson) }],
        isError: false,
      });
    });

    it("should handle errors", async () => {
      mockFetch.mockRejectedValueOnce(new Error("Invalid JSON"));

      const result = await Fetcher.json(mockRequest);
      expect(result).toEqual({
        content: [
          {
            type: "text",
            text: "Failed to fetch https://example.com: Invalid JSON",
          },
        ],
        isError: true,
      });
    });
  });

  describe("txt", () => {
    it("should handle errors", async () => {
      mockFetch.mockRejectedValueOnce(new Error("Parsing error"));

      const result = await Fetcher.txt(mockRequest);
      expect(result).toEqual({
        content: [
          {
            type: "text",
            text: "Failed to fetch https://example.com: Parsing error",
          },
        ],
        isError: true,
      });
    });
  });

  describe("markdown", () => {
    it("should handle errors", async () => {
      mockFetch.mockRejectedValueOnce(new Error("Conversion error"));

      const result = await Fetcher.markdown(mockRequest);
      expect(result).toEqual({
        content: [
          {
            type: "text",
            text: "Failed to fetch https://example.com: Conversion error",
          },
        ],
        isError: true,
      });
    });
  });

  describe("SSRF protection", () => {
    it("should block file:// URLs", async () => {
      const result = await Fetcher.html({ url: "file:///etc/passwd" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain('disallowed protocol "file:"');
    });

    it("should block data: URLs", async () => {
      const result = await Fetcher.html({ url: "data:text/html,<h1>hi</h1>" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain('disallowed protocol "data:"');
    });

    it("should block ftp: URLs", async () => {
      const result = await Fetcher.html({ url: "ftp://example.com/file" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain('disallowed protocol "ftp:"');
    });

    it("should block IPv6 loopback http://[::1]/", async () => {
      const result = await Fetcher.html({ url: "http://[::1]/" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("private address");
    });

    it("should block redirects to private IPs", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        url: "http://127.0.0.1/internal",
        text: jest.fn().mockResolvedValueOnce("secret"),
      });

      const result = await Fetcher.html({ url: "https://example.com" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("private address");
    });

    it("should allow redirects to public URLs", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        url: "https://cdn.example.com/page",
        text: jest.fn().mockResolvedValueOnce("<html>ok</html>"),
      });

      const result = await Fetcher.html({ url: "https://example.com" });
      expect(result.isError).toBe(false);
      expect(result.content[0].text).toBe("<html>ok</html>");
    });
  });

  describe("error handling", () => {
    it("should handle non-OK responses", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 404,
      });

      const result = await Fetcher.html(mockRequest);
      expect(result).toEqual({
        content: [
          {
            type: "text",
            text: "Failed to fetch https://example.com: HTTP error: 404",
          },
        ],
        isError: true,
      });
    });

    it("should handle unknown errors", async () => {
      mockFetch.mockRejectedValueOnce("Unknown error");

      const result = await Fetcher.html(mockRequest);
      expect(result).toEqual({
        content: [
          {
            type: "text",
            text: "Failed to fetch https://example.com: Unknown error",
          },
        ],
        isError: true,
      });
    });
  });
});
