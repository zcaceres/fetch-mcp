import { describe, it, expect, jest, beforeEach, afterAll } from "bun:test";
import { parseArgs, type ParsedArgs } from "./cli";
import { Fetcher } from "./Fetcher";

// Save originals
const originalExit = process.exit;
const originalStdoutWrite = process.stdout.write;
const originalStderrWrite = process.stderr.write;

afterAll(() => {
  process.exit = originalExit;
  process.stdout.write = originalStdoutWrite;
  process.stderr.write = originalStderrWrite;
});

function captureExit(): { code: number | undefined; stdout: string; stderr: string } {
  const result = { code: undefined as number | undefined, stdout: "", stderr: "" };
  process.exit = ((c: number) => {
    result.code = c;
    throw new Error("EXIT");
  }) as any;
  process.stdout.write = ((s: string) => {
    result.stdout += s;
    return true;
  }) as any;
  process.stderr.write = ((s: string) => {
    result.stderr += s;
    return true;
  }) as any;
  return result;
}

function restoreIO() {
  process.exit = originalExit;
  process.stdout.write = originalStdoutWrite;
  process.stderr.write = originalStderrWrite;
}

describe("parseArgs", () => {
  it("parses a basic subcommand and URL", () => {
    // Temporarily override exit/write to prevent test from exiting
    const orig = process.exit;
    const result = parseArgs(["html", "https://example.com"]);
    expect(result.subcommand).toBe("html");
    expect(result.url).toBe("https://example.com");
  });

  it("parses all flags", () => {
    const result = parseArgs([
      "markdown",
      "https://example.com",
      "--max-length", "1000",
      "--start-index", "50",
      "--proxy", "http://proxy:8080",
    ]);
    expect(result.subcommand).toBe("markdown");
    expect(result.url).toBe("https://example.com");
    expect(result.maxLength).toBe(1000);
    expect(result.startIndex).toBe(50);
    expect(result.proxy).toBe("http://proxy:8080");
  });

  it("parses youtube with --lang flag", () => {
    const result = parseArgs([
      "youtube",
      "https://www.youtube.com/watch?v=abc",
      "--lang", "es",
    ]);
    expect(result.subcommand).toBe("youtube");
    expect(result.lang).toBe("es");
  });

  it("exits with help on --help", () => {
    const cap = captureExit();
    try {
      parseArgs(["--help"]);
    } catch {}
    restoreIO();
    expect(cap.code).toBe(0);
    expect(cap.stdout).toContain("Usage:");
  });

  it("exits with help on empty args", () => {
    const cap = captureExit();
    try {
      parseArgs([]);
    } catch {}
    restoreIO();
    expect(cap.code).toBe(0);
    expect(cap.stdout).toContain("Usage:");
  });

  it("exits with version on --version", () => {
    const cap = captureExit();
    try {
      parseArgs(["--version"]);
    } catch {}
    restoreIO();
    expect(cap.code).toBe(0);
    expect(cap.stdout).toMatch(/^\d+\.\d+\.\d+\n$/);
  });

  it("exits with error on unknown subcommand", () => {
    const cap = captureExit();
    try {
      parseArgs(["foobar", "https://example.com"]);
    } catch {}
    restoreIO();
    expect(cap.code).toBe(1);
    expect(cap.stderr).toContain("Unknown command: foobar");
  });

  it("exits with error on missing URL", () => {
    const cap = captureExit();
    try {
      parseArgs(["html"]);
    } catch {}
    restoreIO();
    expect(cap.code).toBe(1);
    expect(cap.stderr).toContain("Missing URL");
  });

  it("exits with error on unknown flag", () => {
    const cap = captureExit();
    try {
      parseArgs(["html", "https://example.com", "--unknown"]);
    } catch {}
    restoreIO();
    expect(cap.code).toBe(1);
    expect(cap.stderr).toContain("Unknown flag: --unknown");
  });

  it("parses all subcommands", () => {
    for (const cmd of ["html", "markdown", "txt", "json", "youtube"] as const) {
      const result = parseArgs([cmd, "https://example.com"]);
      expect(result.subcommand).toBe(cmd);
    }
  });
});
