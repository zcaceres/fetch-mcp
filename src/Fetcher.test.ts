import { describe, it, expect, beforeEach, afterAll, jest, spyOn } from "bun:test";
import dns from "node:dns";
import { Fetcher } from "./Fetcher";

const originalFetch = globalThis.fetch;
const mockFetch = jest.fn();
const originalLookup = dns.promises.lookup;

afterAll(() => {
  globalThis.fetch = originalFetch;
  dns.promises.lookup = originalLookup;
});

describe("Fetcher", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    globalThis.fetch = mockFetch as any;
    Fetcher.hasYtDlp = false;
    // Default: resolve all hostnames to a public IP so existing tests aren't affected
    dns.promises.lookup = (async () => ({ address: "93.184.216.34", family: 4 })) as any;
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

  describe("readable", () => {
    const articleHtml = `
      <html>
        <head><title>Test Article</title></head>
        <body>
          <nav>Navigation</nav>
          <article>
            <h1>Hello World</h1>
            <p>This is the main article content that should be extracted by Readability. It needs to be long enough for Readability to consider it real content, so here is some additional text to pad it out a bit more.</p>
          </article>
          <footer>Footer stuff</footer>
        </body>
      </html>
    `;

    it("should return readable content as markdown", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        text: jest.fn().mockResolvedValueOnce(articleHtml),
      });

      const result = await Fetcher.readable(mockRequest);
      expect(result.isError).toBe(false);
      expect(result.content[0].text).toContain("Hello World");
    });

    it("should return error when Readability cannot parse", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        text: jest.fn().mockResolvedValueOnce("<html><body></body></html>"),
      });

      const result = await Fetcher.readable(mockRequest);
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Failed to parse readable content");
    });

    it("should handle fetch errors", async () => {
      mockFetch.mockRejectedValueOnce(new Error("Network error"));

      const result = await Fetcher.readable(mockRequest);
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Failed to fetch https://example.com: Network error");
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
      // Should NOT be double-wrapped with "Failed to fetch" prefix
      expect(result.content[0].text).not.toContain("Failed to fetch");
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

  describe("proxy", () => {
    it("should pass proxy option to fetch when provided", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        text: jest.fn().mockResolvedValueOnce("<html>ok</html>"),
      });

      await Fetcher.html({ url: "https://example.com", proxy: "http://proxy:8080" });
      expect(mockFetch).toHaveBeenCalledTimes(1);
      const callArgs = mockFetch.mock.calls[0];
      expect(callArgs[1]).toHaveProperty("proxy", "http://proxy:8080");
    });

    it("should not include proxy option when not provided", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        text: jest.fn().mockResolvedValueOnce("<html>ok</html>"),
      });

      await Fetcher.html({ url: "https://example.com" });
      expect(mockFetch).toHaveBeenCalledTimes(1);
      const callArgs = mockFetch.mock.calls[0];
      expect(callArgs[1]).not.toHaveProperty("proxy");
    });
  });

  describe("youtubeTranscript", () => {
    it("should fetch and parse YouTube transcript", async () => {
      const playerResponse = {
        captions: {
          playerCaptionsTracklistRenderer: {
            captionTracks: [
              {
                languageCode: "en",
                baseUrl: "https://www.youtube.com/api/timedtext?lang=en",
                name: { simpleText: "English" },
              },
            ],
          },
        },
      };
      const pageHtml = `<html><script>var ytInitialPlayerResponse = ${JSON.stringify(playerResponse)};</script></html>`;
      const captionXml = `<transcript><text start="0" dur="2">Hello</text><text start="2" dur="3">World</text></transcript>`;

      // First call: page HTML. Second call: caption XML.
      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          text: jest.fn().mockResolvedValueOnce(pageHtml),
        })
        .mockResolvedValueOnce({
          ok: true,
          text: jest.fn().mockResolvedValueOnce(captionXml),
        });

      const result = await Fetcher.youtubeTranscript({
        url: "https://www.youtube.com/watch?v=test",
      });

      expect(result.isError).toBe(false);
      expect(result.content[0].text).toContain("[Transcript language: en");
      expect(result.content[0].text).toContain("[0:00] Hello");
      expect(result.content[0].text).toContain("[0:02] World");
    });

    it("should pass proxy when fetching captions", async () => {
      const playerResponse = {
        captions: {
          playerCaptionsTracklistRenderer: {
            captionTracks: [
              {
                languageCode: "en",
                baseUrl: "https://www.youtube.com/api/timedtext?lang=en",
                name: { simpleText: "English" },
              },
            ],
          },
        },
      };
      const pageHtml = `<html><script>var ytInitialPlayerResponse = ${JSON.stringify(playerResponse)};</script></html>`;
      const captionXml = `<transcript><text start="0" dur="2">Hi</text></transcript>`;

      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          text: jest.fn().mockResolvedValueOnce(pageHtml),
        })
        .mockResolvedValueOnce({
          ok: true,
          text: jest.fn().mockResolvedValueOnce(captionXml),
        });

      await Fetcher.youtubeTranscript({
        url: "https://www.youtube.com/watch?v=test",
        proxy: "http://proxy:8080",
      });

      // Both calls should include proxy
      for (const call of mockFetch.mock.calls) {
        expect(call[1]).toHaveProperty("proxy", "http://proxy:8080");
      }
    });

    it("should return error when no captions found", async () => {
      const pageHtml = `<html><script>var ytInitialPlayerResponse = {"videoDetails":{"videoId":"test"}};</script></html>`;

      mockFetch.mockResolvedValueOnce({
        ok: true,
        text: jest.fn().mockResolvedValueOnce(pageHtml),
      });

      const result = await Fetcher.youtubeTranscript({
        url: "https://www.youtube.com/watch?v=test",
      });

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("No caption tracks found");
    });
  });

  describe("DNS rebinding SSRF protection", () => {
    it("should block hostnames that resolve to private IPs", async () => {
      const lookupSpy = spyOn(dns.promises, "lookup").mockResolvedValueOnce({
        address: "127.0.0.1",
        family: 4,
      } as any);

      const result = await Fetcher.html({ url: "https://evil.example.com" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("resolved to private IP");
      expect(result.content[0].text).toContain("DNS rebinding");
      lookupSpy.mockRestore();
    });

    it("should block post-redirect hostnames that resolve to private IPs", async () => {
      const lookupSpy = spyOn(dns.promises, "lookup")
        .mockResolvedValueOnce({ address: "93.184.216.34", family: 4 } as any) // pre-fetch: public
        .mockResolvedValueOnce({ address: "10.0.0.1", family: 4 } as any); // post-redirect: private

      mockFetch.mockResolvedValueOnce({
        ok: true,
        url: "https://internal.evil.com/secret",
        text: jest.fn().mockResolvedValueOnce("secret data"),
      });

      const result = await Fetcher.html({ url: "https://example.com" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("resolved to private IP");
      lookupSpy.mockRestore();
    });

    it("should allow hostnames that resolve to public IPs", async () => {
      const lookupSpy = spyOn(dns.promises, "lookup").mockResolvedValueOnce({
        address: "93.184.216.34",
        family: 4,
      } as any);

      mockFetch.mockResolvedValueOnce({
        ok: true,
        text: jest.fn().mockResolvedValueOnce("<html>ok</html>"),
      });

      const result = await Fetcher.html({ url: "https://example.com" });
      expect(result.isError).toBe(false);
      lookupSpy.mockRestore();
    });
  });

  describe("yt-dlp lang sanitization", () => {
    it("should reject lang with shell metacharacters", async () => {
      Fetcher.hasYtDlp = true;

      const result = await Fetcher.youtubeTranscript({
        url: "https://www.youtube.com/watch?v=test",
        lang: "en; rm -rf /",
      });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Invalid language code");
    });

    it("should reject lang with command substitution", async () => {
      Fetcher.hasYtDlp = true;

      const result = await Fetcher.youtubeTranscript({
        url: "https://www.youtube.com/watch?v=test",
        lang: "$(whoami)",
      });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Invalid language code");
    });

    it("should accept valid language codes", async () => {
      Fetcher.hasYtDlp = true;
      // This will fail at yt-dlp execution (not installed in test), falling back to direct fetch
      // which will also fail since we haven't mocked fetch — but it should NOT fail at lang validation
      const lookupSpy = spyOn(dns.promises, "lookup").mockResolvedValue({
        address: "93.184.216.34",
        family: 4,
      } as any);

      const playerResponse = {
        captions: {
          playerCaptionsTracklistRenderer: {
            captionTracks: [{ languageCode: "pt-BR", baseUrl: "https://youtube.com/api/timedtext?lang=pt-BR", name: { simpleText: "Portuguese" } }],
          },
        },
      };
      const pageHtml = `<html><script>var ytInitialPlayerResponse = ${JSON.stringify(playerResponse)};</script></html>`;
      const captionXml = `<transcript><text start="0" dur="2">Olá</text></transcript>`;

      mockFetch
        .mockResolvedValueOnce({ ok: true, text: jest.fn().mockResolvedValueOnce(pageHtml) })
        .mockResolvedValueOnce({ ok: true, text: jest.fn().mockResolvedValueOnce(captionXml) });

      const result = await Fetcher.youtubeTranscript({
        url: "https://www.youtube.com/watch?v=test",
        lang: "pt-BR",
      });
      expect(result.isError).toBe(false);
      lookupSpy.mockRestore();
    });

    it("should accept language codes with digits like es-419", async () => {
      Fetcher.hasYtDlp = true;
      const lookupSpy = spyOn(dns.promises, "lookup").mockResolvedValue({
        address: "93.184.216.34",
        family: 4,
      } as any);

      const playerResponse = {
        captions: {
          playerCaptionsTracklistRenderer: {
            captionTracks: [{ languageCode: "es-419", baseUrl: "https://youtube.com/api/timedtext?lang=es-419", name: { simpleText: "Spanish (Latin America)" } }],
          },
        },
      };
      const pageHtml = `<html><script>var ytInitialPlayerResponse = ${JSON.stringify(playerResponse)};</script></html>`;
      const captionXml = `<transcript><text start="0" dur="2">Hola</text></transcript>`;

      mockFetch
        .mockResolvedValueOnce({ ok: true, text: jest.fn().mockResolvedValueOnce(pageHtml) })
        .mockResolvedValueOnce({ ok: true, text: jest.fn().mockResolvedValueOnce(captionXml) });

      const result = await Fetcher.youtubeTranscript({
        url: "https://www.youtube.com/watch?v=test",
        lang: "es-419",
      });
      expect(result.isError).toBe(false);
      lookupSpy.mockRestore();
    });
  });

  describe("checkYtDlp", () => {
    it("should return a promise (async)", () => {
      Fetcher.hasYtDlp = null;
      const result = Fetcher.checkYtDlp();
      expect(result).toBeInstanceOf(Promise);
    });

    it("should return cached value when already checked", async () => {
      Fetcher.hasYtDlp = true;
      const result = await Fetcher.checkYtDlp();
      expect(result).toBe(true);
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

    it("should produce a string text field when response processing throws a non-Error", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        text: jest.fn().mockRejectedValueOnce("string error"),
      });

      const result = await Fetcher.html(mockRequest);
      expect(result.isError).toBe(true);
      expect(typeof result.content[0].text).toBe("string");
      expect(result.content[0].text).toBe("string error");
    });
  });
});
