// src/processors/index.test.ts
// Tests for content processors

import {
  processorRegistry,
  HtmlProcessor,
  JsonProcessor,
  TextProcessor,
  MarkdownProcessor,
  SafeProcessor,
  type ProcessorOptions,
} from "./index";

// Mock the workers module
jest.mock("../workers/index.js", () => ({
  runInWorker: jest.fn(),
}));

import { runInWorker } from "../workers/index.js";
const mockRunInWorker = runInWorker as jest.MockedFunction<typeof runInWorker>;

describe("ProcessorRegistry", () => {
  it("should have all processors registered", () => {
    expect(processorRegistry.has("html")).toBe(true);
    expect(processorRegistry.has("json")).toBe(true);
    expect(processorRegistry.has("text")).toBe(true);
    expect(processorRegistry.has("markdown")).toBe(true);
    expect(processorRegistry.has("safe")).toBe(true);
  });

  it("should get processor by name", () => {
    const htmlProcessor = processorRegistry.get("html");
    expect(htmlProcessor).toBeInstanceOf(HtmlProcessor);
  });

  it("should get processor by tool name", () => {
    const processor = processorRegistry.getByToolName("fetch_html");
    expect(processor).toBeInstanceOf(HtmlProcessor);
  });

  it("should return undefined for unknown processor", () => {
    expect(processorRegistry.get("unknown")).toBeUndefined();
  });

  it("should return all processors", () => {
    const all = processorRegistry.getAll();
    expect(all.length).toBe(5);
  });
});

describe("HtmlProcessor", () => {
  const processor = new HtmlProcessor();
  const defaultOptions: ProcessorOptions = { useSandbox: false };

  it("should have correct metadata", () => {
    expect(processor.name).toBe("html");
    expect(processor.toolName).toBe("fetch_html");
    expect(processor.defaultContentType).toBe("text/html");
    expect(processor.expectedContentTypes).toContain("text/html");
  });

  it("should return HTML content as-is", async () => {
    const html = "<html><body><h1>Test</h1></body></html>";
    const result = await processor.process(html, defaultOptions);
    expect(result).toBe(html);
  });

  it("should preserve all HTML content including scripts", async () => {
    const html = "<html><script>alert('test')</script></html>";
    const result = await processor.process(html, defaultOptions);
    expect(result).toBe(html);
  });
});

describe("JsonProcessor", () => {
  const processor = new JsonProcessor();
  const defaultOptions: ProcessorOptions = { useSandbox: false };

  it("should have correct metadata", () => {
    expect(processor.name).toBe("json");
    expect(processor.toolName).toBe("fetch_json");
    expect(processor.defaultContentType).toBe("application/json");
    expect(processor.expectedContentTypes).toContain("application/json");
  });

  it("should parse and re-stringify valid JSON", async () => {
    const json = '{"key": "value", "num": 123}';
    const result = await processor.process(json, defaultOptions);
    expect(result).toBe('{"key":"value","num":123}');
  });

  it("should normalize JSON formatting", async () => {
    const json = '{\n  "key":\n    "value"\n}';
    const result = await processor.process(json, defaultOptions);
    expect(result).toBe('{"key":"value"}');
  });

  it("should throw on invalid JSON", async () => {
    await expect(
      processor.process("not json", defaultOptions),
    ).rejects.toThrow();
  });

  it("should handle arrays", async () => {
    const json = "[1, 2, 3]";
    const result = await processor.process(json, defaultOptions);
    expect(result).toBe("[1,2,3]");
  });

  it("should handle nested objects", async () => {
    const json = '{"outer": {"inner": "value"}}';
    const result = await processor.process(json, defaultOptions);
    expect(JSON.parse(result)).toEqual({ outer: { inner: "value" } });
  });
});

describe("TextProcessor", () => {
  const processor = new TextProcessor();

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("should have correct metadata", () => {
    expect(processor.name).toBe("text");
    expect(processor.toolName).toBe("fetch_txt");
    expect(processor.defaultContentType).toBe("text/plain");
  });

  describe("Non-sandboxed mode", () => {
    const options: ProcessorOptions = { useSandbox: false };

    it("should extract text from HTML", async () => {
      const html = "<html><body><h1>Title</h1><p>Paragraph</p></body></html>";
      const result = await processor.process(html, options);
      expect(result).toContain("Title");
      expect(result).toContain("Paragraph");
    });

    it("should remove script tags", async () => {
      const html =
        "<html><body><script>alert('xss')</script>Content</body></html>";
      const result = await processor.process(html, options);
      expect(result).not.toContain("alert");
      expect(result).toContain("Content");
    });

    it("should remove style tags", async () => {
      const html =
        "<html><head><style>body { color: red; }</style></head><body>Content</body></html>";
      const result = await processor.process(html, options);
      expect(result).not.toContain("color");
      expect(result).toContain("Content");
    });

    it("should normalize whitespace", async () => {
      const html = "<html><body>  Multiple   spaces  </body></html>";
      const result = await processor.process(html, options);
      expect(result).toBe("Multiple spaces");
    });
  });

  describe("Sandboxed mode", () => {
    it("should use worker for sandboxed processing", async () => {
      mockRunInWorker.mockResolvedValueOnce({
        success: true,
        result: { success: true, result: "Sandboxed text" },
      });

      const options: ProcessorOptions = {
        useSandbox: true,
        url: "https://example.com",
      };
      const result = await processor.process(
        "<html><body>Content</body></html>",
        options,
      );

      expect(mockRunInWorker).toHaveBeenCalledWith(
        "html-processor.js",
        expect.any(Object),
      );
      expect(result).toBe("Sandboxed text");
    });
  });
});

describe("MarkdownProcessor", () => {
  const processor = new MarkdownProcessor();

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("should have correct metadata", () => {
    expect(processor.name).toBe("markdown");
    expect(processor.toolName).toBe("fetch_markdown");
    expect(processor.defaultContentType).toBe("text/markdown");
  });

  describe("Non-sandboxed mode", () => {
    const options: ProcessorOptions = { useSandbox: false };

    it("should convert HTML headings to markdown", async () => {
      const html = "<h1>Title</h1>";
      const result = await processor.process(html, options);
      // Turndown uses setext-style (===) or atx-style (#) for h1
      expect(result).toMatch(/Title/);
      expect(result).toMatch(/(=+|# )/);
    });

    it("should convert HTML paragraphs", async () => {
      const html = "<p>Paragraph text</p>";
      const result = await processor.process(html, options);
      expect(result).toContain("Paragraph text");
    });

    it("should convert HTML links", async () => {
      const html = '<a href="https://example.com">Link</a>';
      const result = await processor.process(html, options);
      expect(result).toContain("[Link]");
      expect(result).toContain("https://example.com");
    });
  });

  describe("LaTeX escaping", () => {
    const options: ProcessorOptions = { useSandbox: false };

    it("should fix double-escaped backslashes in inline math", async () => {
      // Mock the Turndown output that has double-escaped backslashes
      mockRunInWorker.mockResolvedValueOnce({
        success: true,
        result: { success: true, result: "Formula: $\\\\kappa$" },
      });

      const sandboxOptions: ProcessorOptions = { useSandbox: true };
      const result = await processor.process("<p>LaTeX</p>", sandboxOptions);
      expect(result).toContain("$\\kappa$");
    });

    it("should fix double-escaped backslashes in display math", async () => {
      mockRunInWorker.mockResolvedValueOnce({
        success: true,
        result: { success: true, result: "$$\\\\alpha + \\\\beta$$" },
      });

      const sandboxOptions: ProcessorOptions = { useSandbox: true };
      const result = await processor.process("<p>Math</p>", sandboxOptions);
      expect(result).toContain("$$\\alpha + \\beta$$");
    });

    it("should NOT fix backslashes outside LaTeX delimiters", async () => {
      mockRunInWorker.mockResolvedValueOnce({
        success: true,
        result: { success: true, result: "Path C:\\\\Users $\\\\kappa$" },
      });

      const sandboxOptions: ProcessorOptions = { useSandbox: true };
      const result = await processor.process("<p>Mixed</p>", sandboxOptions);
      expect(result).toContain("C:\\\\Users");
      expect(result).toContain("$\\kappa$");
    });
  });
});

describe("SafeProcessor", () => {
  const processor = new SafeProcessor();

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("should have correct metadata", () => {
    expect(processor.name).toBe("safe");
    expect(processor.toolName).toBe("fetch_safe");
    expect(processor.defaultContentType).toBe("text/plain");
    expect(processor.contentTypeOverride).toBe("text/plain");
    expect(processor.maxLengthOverride).toBe(2000);
  });

  describe("Non-sandboxed mode", () => {
    const options: ProcessorOptions = { useSandbox: false };

    it("should extract plain text", async () => {
      const html = "<html><body><h1>Title</h1><p>Content</p></body></html>";
      const result = await processor.process(html, options);
      expect(result).toContain("Title");
      expect(result).toContain("Content");
    });

    it("should remove script tags", async () => {
      const html =
        "<html><body><script>evil()</script>Safe content</body></html>";
      const result = await processor.process(html, options);
      expect(result).not.toContain("evil");
      expect(result).toContain("Safe content");
    });
  });

  describe("Sanitization", () => {
    const options: ProcessorOptions = { useSandbox: false };

    it("should strip Unicode control characters", async () => {
      mockRunInWorker.mockResolvedValueOnce({
        success: true,
        result: {
          success: true,
          result: "Hello\x00\x0B\x1F World\u200B\uFEFF test",
        },
      });

      const sandboxOptions: ProcessorOptions = { useSandbox: true };
      const result = await processor.process("<html></html>", sandboxOptions);

      expect(result).not.toMatch(/[\x00-\x08\x0B\x0C\x0E-\x1F\u200B\uFEFF]/);
      expect(result).toBe("Hello World test");
    });

    it("should normalize whitespace", async () => {
      const html =
        "<html><body>  Multiple   spaces\n\nand lines  </body></html>";
      const result = await processor.process(html, options);
      expect(result).not.toMatch(/\s{2,}/);
    });

    it("should strip remaining HTML-like patterns", async () => {
      mockRunInWorker.mockResolvedValueOnce({
        success: true,
        result: { success: true, result: "Text <b>bold</b> more" },
      });

      const sandboxOptions: ProcessorOptions = { useSandbox: true };
      const result = await processor.process("<html></html>", sandboxOptions);
      expect(result).not.toContain("<b>");
      expect(result).not.toContain("</b>");
    });
  });

  describe("Sandboxed mode", () => {
    it("should prefer sandbox for safe mode", async () => {
      mockRunInWorker.mockResolvedValueOnce({
        success: true,
        result: { success: true, result: "Safe sandboxed output" },
      });

      const options: ProcessorOptions = {
        useSandbox: true,
        url: "https://example.com",
      };
      await processor.process("<html></html>", options);

      expect(mockRunInWorker).toHaveBeenCalled();
    });
  });
});

describe("Worker Output Sanitization", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("should sanitize script tags from worker output", async () => {
    const processor = new TextProcessor();

    mockRunInWorker.mockResolvedValueOnce({
      success: true,
      result: {
        success: true,
        result: "Text <script>alert('xss')</script> more",
      },
    });

    const result = await processor.process("<html></html>", {
      useSandbox: true,
    });
    expect(result).toContain("[SCRIPT REMOVED]");
    expect(result).not.toContain("<script>");
  });

  it("should sanitize iframe tags from worker output", async () => {
    const processor = new MarkdownProcessor();

    mockRunInWorker.mockResolvedValueOnce({
      success: true,
      result: {
        success: true,
        result: "Text <iframe src='evil.com'></iframe> more",
      },
    });

    const result = await processor.process("<html></html>", {
      useSandbox: true,
    });
    expect(result).toContain("[IFRAME REMOVED]");
    expect(result).not.toContain("<iframe");
  });

  it("should block javascript: URLs", async () => {
    const processor = new TextProcessor();

    mockRunInWorker.mockResolvedValueOnce({
      success: true,
      result: { success: true, result: "Link: javascript:alert(1)" },
    });

    const result = await processor.process("<html></html>", {
      useSandbox: true,
    });
    expect(result).toContain("blocked:");
    expect(result).not.toContain("javascript:");
  });

  it("should remove event handlers", async () => {
    const processor = new TextProcessor();

    mockRunInWorker.mockResolvedValueOnce({
      success: true,
      result: { success: true, result: '<img onerror="alert(1)">' },
    });

    const result = await processor.process("<html></html>", {
      useSandbox: true,
    });
    expect(result).not.toContain("onerror");
  });
});
