import { describe, it, expect, afterEach, jest } from "bun:test";
import { Fetcher } from "./Fetcher";

const sampleHtml = `<!DOCTYPE html>
<html>
  <head>
    <title>Test Page</title>
    <script>var x = 1;</script>
    <script src="app.js"></script>
    <style>body { color: red; }</style>
    <style>.hidden { display: none; }</style>
  </head>
  <body>
    <h1>Main Title</h1>
    <p>First paragraph with <a href="/link">a link</a>.</p>
    <ul>
      <li>Item one</li>
      <li>Item two</li>
    </ul>
    <div>
      <p>Nested paragraph.</p>
      <script>alert('inline script')</script>
    </div>
  </body>
</html>`;

function mockFetchWith(content: string, contentType = "text/html") {
  globalThis.fetch = jest.fn().mockResolvedValue({
    ok: true,
    text: () => Promise.resolve(content),
    json: () => Promise.resolve(JSON.parse(content)),
    headers: new Headers({ "content-type": contentType }),
  }) as any;
}

const originalFetch = globalThis.fetch;

describe("Fetcher — fixture tests", () => {
  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  const req = (overrides?: Partial<{ max_length: number; start_index: number }>) => ({
    url: "https://example.com",
    ...overrides,
  });

  describe("txt — real JSDOM parsing", () => {
    it("strips scripts, styles, and normalizes whitespace", async () => {
      mockFetchWith(sampleHtml);
      const result = await Fetcher.txt(req({ max_length: 0 }));
      const text = result.content[0].text;

      expect(text).not.toContain("var x = 1");
      expect(text).not.toContain("alert(");
      expect(text).not.toContain("color: red");
      expect(text).not.toContain("display: none");
      expect(text).toContain("Main Title");
      expect(text).toContain("First paragraph");
      expect(text).toContain("a link");
      expect(text).toContain("Item one");
      expect(text).toContain("Item two");
      expect(text).toContain("Nested paragraph");
      // whitespace normalized — no runs of multiple spaces
      expect(text).not.toMatch(/  /);
    });

    it("returns empty string for body-less HTML", async () => {
      mockFetchWith("<html><head><title>No body</title></head></html>");
      const result = await Fetcher.txt(req({ max_length: 0 }));
      expect(result.content[0].text).toBe("");
    });
  });

  describe("markdown — real Turndown conversion", () => {
    it("converts headings, links, and lists to markdown", async () => {
      mockFetchWith(sampleHtml);
      const result = await Fetcher.markdown(req({ max_length: 0 }));
      const md = result.content[0].text;

      // Turndown uses underline-style h1 by default
      expect(md).toContain("Main Title");
      expect(md).toMatch(/={3,}/); // underline heading
      expect(md).toContain("[a link](/link)");
      expect(md).toMatch(/\*\s+Item one/);
      expect(md).toMatch(/\*\s+Item two/);
      expect(md).toContain("Nested paragraph");
    });

    it("handles plain text input gracefully", async () => {
      mockFetchWith("Just plain text, no HTML.");
      const result = await Fetcher.markdown(req({ max_length: 0 }));
      expect(result.content[0].text).toContain("Just plain text");
      expect(result.isError).toBe(false);
    });
  });

  describe("applyLengthLimits", () => {
    const longContent = "A".repeat(200);

    it("truncates to max_length", async () => {
      mockFetchWith(longContent);
      const result = await Fetcher.html(req({ max_length: 50 }));
      expect(result.content[0].text).toHaveLength(50);
    });

    it("skips start_index characters", async () => {
      mockFetchWith("abcdefghij");
      const result = await Fetcher.html(req({ max_length: 5, start_index: 3 }));
      expect(result.content[0].text).toBe("defgh");
    });

    it("returns empty when start_index exceeds length", async () => {
      mockFetchWith("short");
      const result = await Fetcher.html(req({ max_length: 10, start_index: 100 }));
      expect(result.content[0].text).toBe("");
    });

    it("returns full content when max_length is 0 (unlimited)", async () => {
      mockFetchWith(longContent);
      const result = await Fetcher.html(req({ max_length: 0 }));
      expect(result.content[0].text).toBe(longContent);
    });

    it("applies defaults (max_length=5000) when not specified", async () => {
      const bigContent = "B".repeat(10000);
      mockFetchWith(bigContent);
      const result = await Fetcher.html(req());
      expect(result.content[0].text).toHaveLength(5000);
    });
  });
});
