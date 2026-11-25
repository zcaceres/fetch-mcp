import { describe, it, expect, beforeEach, afterAll, jest, spyOn } from "bun:test";
import dns from "node:dns";
import { Fetcher } from "./Fetcher";
import { safeHttpGet, type HttpResponse } from "./httpClient";

const originalTransport = Fetcher.transport;
const mockTransport = jest.fn();
const originalLookup = dns.promises.lookup;

function okResponse(text: string, url = "https://example.com"): HttpResponse {
  return { status: 200, ok: true, url, headers: {}, text };
}

afterAll(() => {
  Fetcher.transport = originalTransport;
  dns.promises.lookup = originalLookup;
});

describe("Fetcher", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    Fetcher.transport = mockTransport as any;
    Fetcher.hasYtDlp = false;
    dns.promises.lookup = (async () => [{ address: "93.184.216.34", family: 4 }]) as any;
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
      mockTransport.mockResolvedValueOnce(okResponse(mockHtml));

      const result = await Fetcher.html(mockRequest);
      expect(result).toEqual({
        content: [{ type: "text", text: mockHtml }],
        isError: false,
      });
    });

    it("should handle errors", async () => {
      mockTransport.mockRejectedValueOnce(new Error("Network error"));

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
      mockTransport.mockResolvedValueOnce(okResponse(JSON.stringify(mockJson)));

      const result = await Fetcher.json(mockRequest);
      expect(result).toEqual({
        content: [{ type: "text", text: JSON.stringify(mockJson) }],
        isError: false,
      });
    });

    it("should handle errors", async () => {
      mockTransport.mockRejectedValueOnce(new Error("Invalid JSON"));

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
      mockTransport.mockRejectedValueOnce(new Error("Parsing error"));

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
      mockTransport.mockResolvedValueOnce(okResponse(articleHtml));

      const result = await Fetcher.readable(mockRequest);
      expect(result.isError).toBe(false);
      expect(result.content[0].text).toContain("Hello World");
    });

    it("should return error when Readability cannot parse", async () => {
      mockTransport.mockResolvedValueOnce(okResponse("<html><body></body></html>"));

      const result = await Fetcher.readable(mockRequest);
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Failed to parse readable content");
    });

    it("should handle fetch errors", async () => {
      mockTransport.mockRejectedValueOnce(new Error("Network error"));

      const result = await Fetcher.readable(mockRequest);
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Failed to fetch https://example.com: Network error");
    });
  });

  describe("markdown", () => {
    it("should handle errors", async () => {
      mockTransport.mockRejectedValueOnce(new Error("Conversion error"));

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
      expect(mockTransport).not.toHaveBeenCalled();
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

    it("should block IPv4-mapped IPv6 loopback http://[::ffff:127.0.0.1]/", async () => {
      const result = await Fetcher.html({ url: "http://[::ffff:127.0.0.1]/" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("private address");
    });

    it("should block IPv4-mapped IPv6 IMDS http://[::ffff:169.254.169.254]/", async () => {
      const result = await Fetcher.html({ url: "http://[::ffff:169.254.169.254]/latest/meta-data/" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("private address");
    });

    it("should propagate SSRF errors from transport without double-wrapping", async () => {
      mockTransport.mockRejectedValueOnce(
        new Error('Fetcher blocked request to private address "127.0.0.1".'),
      );

      const result = await Fetcher.html({ url: "https://example.com" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("private address");
      expect(result.content[0].text).not.toContain("Failed to fetch");
    });
  });

  describe("proxy (CLI / operator env)", () => {
    it("should forward explicit proxy option to transport when provided", async () => {
      mockTransport.mockResolvedValueOnce(okResponse("<html>ok</html>"));

      await Fetcher.html({ url: "https://example.com", proxy: "http://proxy:8080" });
      expect(mockTransport).toHaveBeenCalledTimes(1);
      expect(mockTransport.mock.calls[0][0]).toHaveProperty("proxy", "http://proxy:8080");
    });

    it("should leave proxy undefined when not provided", async () => {
      mockTransport.mockResolvedValueOnce(okResponse("<html>ok</html>"));

      await Fetcher.html({ url: "https://example.com" });
      expect(mockTransport).toHaveBeenCalledTimes(1);
      expect(mockTransport.mock.calls[0][0].proxy).toBeUndefined();
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

      mockTransport
        .mockResolvedValueOnce(okResponse(pageHtml))
        .mockResolvedValueOnce(okResponse(captionXml));

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

      mockTransport
        .mockResolvedValueOnce(okResponse(pageHtml))
        .mockResolvedValueOnce(okResponse(captionXml));

      await Fetcher.youtubeTranscript({
        url: "https://www.youtube.com/watch?v=test",
        proxy: "http://proxy:8080",
      });

      for (const call of mockTransport.mock.calls) {
        expect(call[0]).toHaveProperty("proxy", "http://proxy:8080");
      }
    });

    it("should return error when no captions found", async () => {
      const pageHtml = `<html><script>var ytInitialPlayerResponse = {"videoDetails":{"videoId":"test"}};</script></html>`;

      mockTransport.mockResolvedValueOnce(okResponse(pageHtml));

      const result = await Fetcher.youtubeTranscript({
        url: "https://www.youtube.com/watch?v=test",
      });

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("No caption tracks found");
    });
  });

  describe("DNS rebinding SSRF protection via real transport", () => {
    it("should block hostnames that resolve to private IPs", async () => {
      Fetcher.transport = safeHttpGet;
      const lookupSpy = spyOn(dns.promises, "lookup").mockResolvedValueOnce([
        { address: "127.0.0.1", family: 4 },
      ] as any);

      const result = await Fetcher.html({ url: "https://evil.example.com" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("resolved to private IP");
      expect(result.content[0].text).toContain("DNS rebinding");
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

      const playerResponse = {
        captions: {
          playerCaptionsTracklistRenderer: {
            captionTracks: [{ languageCode: "pt-BR", baseUrl: "https://youtube.com/api/timedtext?lang=pt-BR", name: { simpleText: "Portuguese" } }],
          },
        },
      };
      const pageHtml = `<html><script>var ytInitialPlayerResponse = ${JSON.stringify(playerResponse)};</script></html>`;
      const captionXml = `<transcript><text start="0" dur="2">Olá</text></transcript>`;

      mockTransport
        .mockResolvedValueOnce(okResponse(pageHtml))
        .mockResolvedValueOnce(okResponse(captionXml));

      const result = await Fetcher.youtubeTranscript({
        url: "https://www.youtube.com/watch?v=test",
        lang: "pt-BR",
      });
      expect(result.isError).toBe(false);
    });

    it("should accept language codes with digits like es-419", async () => {
      Fetcher.hasYtDlp = true;

      const playerResponse = {
        captions: {
          playerCaptionsTracklistRenderer: {
            captionTracks: [{ languageCode: "es-419", baseUrl: "https://youtube.com/api/timedtext?lang=es-419", name: { simpleText: "Spanish (Latin America)" } }],
          },
        },
      };
      const pageHtml = `<html><script>var ytInitialPlayerResponse = ${JSON.stringify(playerResponse)};</script></html>`;
      const captionXml = `<transcript><text start="0" dur="2">Hola</text></transcript>`;

      mockTransport
        .mockResolvedValueOnce(okResponse(pageHtml))
        .mockResolvedValueOnce(okResponse(captionXml));

      const result = await Fetcher.youtubeTranscript({
        url: "https://www.youtube.com/watch?v=test",
        lang: "es-419",
      });
      expect(result.isError).toBe(false);
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

  describe("response size limit", () => {
    it("should propagate Response too large errors without double-wrapping", async () => {
      mockTransport.mockRejectedValueOnce(
        new Error("Response too large: 999999999999 bytes exceeds 10485760 byte limit"),
      );

      const result = await Fetcher.html(mockRequest);
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Response too large");
      expect(result.content[0].text).not.toContain("Failed to fetch");
    });
  });

  describe("error handling", () => {
    it("should handle non-OK responses", async () => {
      mockTransport.mockResolvedValueOnce({
        status: 404,
        ok: false,
        url: "https://example.com",
        headers: {},
        text: "",
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
      mockTransport.mockRejectedValueOnce("Unknown error");

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
