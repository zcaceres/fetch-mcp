import { JSDOM } from "jsdom";
import TurndownService from "turndown";
import { Readability } from "@mozilla/readability";
import { mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { RequestPayload, YouTubeTranscriptPayload, downloadLimit, maxResponseBytes } from "./types.js";
import { YouTubeTranscript } from "./YouTubeTranscript.js";
import { resolveAndValidateHost, validateUrl, validateYouTubeUrl } from "./ssrf.js";
import { resolveProxyUrl, safeHttpGet, type HttpRequestOptions, type HttpResponse } from "./httpClient.js";

export class Fetcher {
  static transport: (options: HttpRequestOptions) => Promise<HttpResponse> = safeHttpGet;

  private static applyLengthLimits(text: string, maxLength: number, startIndex: number): string {
    if (startIndex >= text.length) {
      return "";
    }

    const end = maxLength > 0 ? Math.min(startIndex + maxLength, text.length) : text.length;
    return text.substring(startIndex, end);
  }

  private static async _fetch({
    url,
    headers,
    proxy,
  }: RequestPayload): Promise<string> {
    validateUrl(url);
    let response: HttpResponse;
    try {
      response = await this.transport({
        url,
        headers,
        proxy,
        maxBytes: maxResponseBytes,
      });
    } catch (e: unknown) {
      if (e instanceof Error) {
        if (
          e.message.startsWith("Fetcher blocked") ||
          e.message.startsWith("Response too large") ||
          e.message.startsWith("Unsupported proxy protocol") ||
          e.message.startsWith("Failed to fetch ")
        ) {
          throw e;
        }
        throw new Error(`Failed to fetch ${url}: ${e.message}`);
      }
      throw new Error(`Failed to fetch ${url}: Unknown error`);
    }

    if (!response.ok) {
      throw new Error(`Failed to fetch ${url}: HTTP error: ${response.status}`);
    }

    return response.text;
  }

  static async html(requestPayload: RequestPayload) {
    try {
      let html = await this._fetch(requestPayload);

      // Apply length limits
      html = this.applyLengthLimits(
        html,
        requestPayload.max_length ?? downloadLimit,
        requestPayload.start_index ?? 0,
      );

      return { content: [{ type: "text", text: html }], isError: false };
    } catch (error) {
      return {
        content: [{ type: "text", text: error instanceof Error ? error.message : String(error) }],
        isError: true,
      };
    }
  }

  static async json(requestPayload: RequestPayload) {
    try {
      const text = await this._fetch(requestPayload);
      const json = JSON.parse(text);
      let jsonString = JSON.stringify(json);

      // Apply length limits
      jsonString = this.applyLengthLimits(
        jsonString,
        requestPayload.max_length ?? downloadLimit,
        requestPayload.start_index ?? 0,
      );

      return {
        content: [{ type: "text", text: jsonString }],
        isError: false,
      };
    } catch (error) {
      return {
        content: [{ type: "text", text: error instanceof Error ? error.message : String(error) }],
        isError: true,
      };
    }
  }

  static async txt(requestPayload: RequestPayload) {
    try {
      const html = await this._fetch(requestPayload);

      const dom = new JSDOM(html);
      const document = dom.window.document;

      const scripts = document.getElementsByTagName("script");
      const styles = document.getElementsByTagName("style");
      Array.from(scripts).forEach((script) => script.remove());
      Array.from(styles).forEach((style) => style.remove());

      const text = document.body.textContent || "";
      let normalizedText = text.replace(/\s+/g, " ").trim();

      // Apply length limits
      normalizedText = this.applyLengthLimits(
        normalizedText,
        requestPayload.max_length ?? downloadLimit,
        requestPayload.start_index ?? 0,
      );

      return {
        content: [{ type: "text", text: normalizedText }],
        isError: false,
      };
    } catch (error) {
      return {
        content: [{ type: "text", text: error instanceof Error ? error.message : String(error) }],
        isError: true,
      };
    }
  }

  private static async fetchTranscriptViaYtDlp(
    videoUrl: string,
    lang: string,
    proxy?: string,
  ): Promise<{ xml: string; lang: string; langName: string }> {
    if (!/^[a-zA-Z0-9-]+$/.test(lang)) {
      throw new Error(`Invalid language code: "${lang}". Only letters, digits, and hyphens are allowed.`);
    }
    const { execFileSync } = await import("child_process");
    const tmpDir = mkdtempSync(path.join(tmpdir(), "mcp-fetch-"));
    try {
      const args = [
        "--write-sub", "--sub-lang", lang,
        "--sub-format", "srv1",
        "--skip-download",
        "-o", path.join(tmpDir, "sub"),
      ];
      if (proxy) {
        args.push("--proxy", proxy);
      }
      args.push("--", videoUrl);
      execFileSync(
        "yt-dlp",
        args,
        { encoding: "utf-8", timeout: 30000, stdio: ["pipe", "pipe", "pipe"] },
      );
      const files = readdirSync(tmpDir).filter((f: string) => f.endsWith(".srv1"));
      if (files.length === 0) {
        throw new Error("yt-dlp did not produce subtitle files");
      }
      const file = files[0];
      const xml = readFileSync(path.join(tmpDir, file), "utf-8");
      const matchedLang = file.match(/\.([^.]+)\.srv1$/)?.[1] ?? lang;
      return { xml, lang: matchedLang, langName: matchedLang };
    } finally {
      rmSync(tmpDir, { recursive: true, force: true });
    }
  }

  private static async fetchTranscriptDirect(
    requestPayload: YouTubeTranscriptPayload,
  ): Promise<{ xml: string; lang: string; langName: string }> {
    const html = await this._fetch(requestPayload);

    const playerResponse = YouTubeTranscript.extractPlayerResponse(html);
    const tracks = YouTubeTranscript.getCaptionTracks(playerResponse);

    const lang = requestPayload.lang ?? "en";
    const track =
      tracks.find((t: any) => t.languageCode === lang) ?? tracks[0];

    const captionUrl = track.baseUrl + (track.baseUrl.includes("fmt=") ? "" : "&fmt=srv1");
    const xml = await this._fetch({
      url: captionUrl,
      headers: requestPayload.headers,
      proxy: requestPayload.proxy,
    });

    return {
      xml,
      lang: track.languageCode,
      langName: track.name?.simpleText ?? "Unknown",
    };
  }

  static hasYtDlp: boolean | null = null;

  static async checkYtDlp(): Promise<boolean> {
    if (this.hasYtDlp !== null) return this.hasYtDlp;
    try {
      const { execSync } = await import("child_process");
      execSync("which yt-dlp", { encoding: "utf-8", stdio: "pipe" });
      this.hasYtDlp = true;
    } catch {
      this.hasYtDlp = false;
    }
    return this.hasYtDlp;
  }

  static async youtubeTranscript(requestPayload: YouTubeTranscriptPayload) {
    try {
      const parsedUrl = validateYouTubeUrl(requestPayload.url);
      await resolveAndValidateHost(parsedUrl.hostname);

      const resolvedProxy = requestPayload.proxy
        ? resolveProxyUrl(parsedUrl, requestPayload.proxy)?.href
        : undefined;

      const lang = requestPayload.lang ?? "en";
      let result: { xml: string; lang: string; langName: string };

      if (await this.checkYtDlp()) {
        // Validate lang before attempting yt-dlp — this is a security check that must not be swallowed
        if (!/^[a-zA-Z0-9-]+$/.test(lang)) {
          throw new Error(`Invalid language code: "${lang}". Only letters, digits, and hyphens are allowed.`);
        }
        try {
          result = await this.fetchTranscriptViaYtDlp(
            requestPayload.url,
            lang,
            resolvedProxy,
          );
        } catch {
          result = await this.fetchTranscriptDirect(requestPayload);
        }
      } else {
        result = await this.fetchTranscriptDirect(requestPayload);
      }

      const lines = YouTubeTranscript.parseTranscriptXml(result.xml);
      const header = `[Transcript language: ${result.lang} — ${result.langName}]\n\n`;
      let transcript = header + lines.join("\n");

      transcript = this.applyLengthLimits(
        transcript,
        requestPayload.max_length ?? downloadLimit,
        requestPayload.start_index ?? 0,
      );

      return { content: [{ type: "text", text: transcript }], isError: false };
    } catch (error) {
      return {
        content: [{ type: "text", text: error instanceof Error ? error.message : String(error) }],
        isError: true,
      };
    }
  }

  static async readable(requestPayload: RequestPayload) {
    try {
      const html = await this._fetch(requestPayload);

      const dom = new JSDOM(html, { url: requestPayload.url });
      const reader = new Readability(dom.window.document);
      const article = reader.parse();

      if (!article) {
        throw new Error("Failed to parse readable content from the page");
      }

      const turndownService = new TurndownService();
      let content = turndownService.turndown(article.content ?? "");

      content = this.applyLengthLimits(
        content,
        requestPayload.max_length ?? downloadLimit,
        requestPayload.start_index ?? 0,
      );

      return { content: [{ type: "text", text: content }], isError: false };
    } catch (error) {
      return {
        content: [{ type: "text", text: error instanceof Error ? error.message : String(error) }],
        isError: true,
      };
    }
  }

  static async markdown(requestPayload: RequestPayload) {
    try {
      const html = await this._fetch(requestPayload);
      const turndownService = new TurndownService();
      let markdown = turndownService.turndown(html);

      // Apply length limits
      markdown = this.applyLengthLimits(
        markdown,
        requestPayload.max_length ?? downloadLimit,
        requestPayload.start_index ?? 0,
      );

      return { content: [{ type: "text", text: markdown }], isError: false };
    } catch (error) {
      return {
        content: [{ type: "text", text: error instanceof Error ? error.message : String(error) }],
        isError: true,
      };
    }
  }
}
