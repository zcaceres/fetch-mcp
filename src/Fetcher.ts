import { JSDOM } from "jsdom";
import { readdown } from "readdown";
import is_ip_private from "private-ip";
import dns from "node:dns";
import { RequestPayload, YouTubeTranscriptPayload, downloadLimit, maxResponseBytes } from "./types.js";
import { YouTubeTranscript } from "./YouTubeTranscript.js";

export class Fetcher {
  private static applyLengthLimits(text: string, maxLength: number, startIndex: number): string {
    if (startIndex >= text.length) {
      return "";
    }

    const end = maxLength > 0 ? Math.min(startIndex + maxLength, text.length) : text.length;
    return text.substring(startIndex, end);
  }

  private static validateUrl(url: string): void {
    const parsedUrl = new URL(url);
    if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
      throw new Error(
        `Fetcher blocked URL with disallowed protocol "${parsedUrl.protocol}". Only HTTP and HTTPS are allowed.`,
      );
    }
    const hostname = parsedUrl.hostname;
    const bareHostname = hostname.startsWith('[') && hostname.endsWith(']')
      ? hostname.slice(1, -1)
      : hostname;
    if (bareHostname === 'localhost' || is_ip_private(bareHostname)) {
      throw new Error(
        `Fetcher blocked request to private address "${bareHostname}". This prevents SSRF attacks where a local MCP server could access privileged internal services.`,
      );
    }
  }

  private static async validateResolvedIp(url: string): Promise<void> {
    const hostname = new URL(url).hostname;
    const bareHostname = hostname.startsWith('[') && hostname.endsWith(']')
      ? hostname.slice(1, -1)
      : hostname;
    try {
      const { address } = await dns.promises.lookup(bareHostname);
      if (is_ip_private(address)) {
        throw new Error(
          `Fetcher blocked request: hostname "${bareHostname}" resolved to private IP "${address}". This prevents DNS rebinding SSRF attacks.`,
        );
      }
    } catch (e) {
      if (e instanceof Error && e.message.includes('Fetcher blocked')) throw e;
      // DNS lookup failures (e.g. non-resolvable hostnames) are not SSRF — let fetch handle them
    }
  }

  private static async _fetch({
    url,
    headers,
    proxy,
  }: RequestPayload): Promise<Response> {
    this.validateUrl(url);
    await this.validateResolvedIp(url);
    let response: Response;
    try {
      response = await fetch(url, {
        headers: {
          "User-Agent":
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
          ...headers,
        },
        // Note: proxy is a Bun-specific fetch option. On Node.js, this option is silently ignored.
        // To use a proxy on Node.js, you would need an HTTP agent library like http-proxy-agent.
        ...(proxy ? { proxy } : {}),
      } as RequestInit);
    } catch (e: unknown) {
      if (e instanceof Error) {
        throw new Error(`Failed to fetch ${url}: ${e.message}`);
      }
      throw new Error(`Failed to fetch ${url}: Unknown error`);
    }

    if (response.url && response.url !== url) {
      this.validateUrl(response.url);
      await this.validateResolvedIp(response.url);
    }

    if (!response.ok) {
      throw new Error(`Failed to fetch ${url}: HTTP error: ${response.status}`);
    }

    const contentLength = response.headers?.get?.("content-length");
    if (contentLength && parseInt(contentLength, 10) > maxResponseBytes) {
      throw new Error(`Response too large: ${contentLength} bytes exceeds ${maxResponseBytes} byte limit`);
    }

    return response;
  }

  private static async readResponseText(response: Response): Promise<string> {
    if (!response.body) return response.text();
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let result = "";
    let bytesRead = 0;
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        bytesRead += value.byteLength;
        if (bytesRead > maxResponseBytes) {
          throw new Error(`Response too large: exceeded ${maxResponseBytes} byte limit while reading`);
        }
        result += decoder.decode(value, { stream: true });
      }
      result += decoder.decode();
      return result;
    } finally {
      reader.cancel();
    }
  }

  static async html(requestPayload: RequestPayload) {
    try {
      const response = await this._fetch(requestPayload);
      let html = await this.readResponseText(response);
      
      // Apply length limits
      html = this.applyLengthLimits(
        html, 
        requestPayload.max_length ?? downloadLimit,
        requestPayload.start_index ?? 0
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
      const response = await this._fetch(requestPayload);
      const text = await this.readResponseText(response);
      const json = JSON.parse(text);
      let jsonString = JSON.stringify(json);
      
      // Apply length limits
      jsonString = this.applyLengthLimits(
        jsonString,
        requestPayload.max_length ?? downloadLimit,
        requestPayload.start_index ?? 0
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
      const response = await this._fetch(requestPayload);
      const html = await this.readResponseText(response);

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
        requestPayload.start_index ?? 0
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
  ): Promise<{ xml: string; lang: string; langName: string }> {
    if (!/^[a-zA-Z0-9-]+$/.test(lang)) {
      throw new Error(`Invalid language code: "${lang}". Only letters, digits, and hyphens are allowed.`);
    }
    const { execFileSync, execSync } = await import("child_process");
    const tmpDir = execSync("mktemp -d", { encoding: "utf-8" }).trim();
    try {
      execFileSync(
        "yt-dlp",
        [
          "--write-sub", "--sub-lang", lang,
          "--sub-format", "srv1",
          "--skip-download",
          "-o", `${tmpDir}/sub`,
          videoUrl,
        ],
        { encoding: "utf-8", timeout: 30000, stdio: ["pipe", "pipe", "pipe"] },
      );
      const { readdirSync, readFileSync } = await import("fs");
      const files = readdirSync(tmpDir).filter((f: string) => f.endsWith(".srv1"));
      if (files.length === 0) {
        throw new Error("yt-dlp did not produce subtitle files");
      }
      const file = files[0];
      const xml = readFileSync(`${tmpDir}/${file}`, "utf-8");
      const matchedLang = file.match(/\.([^.]+)\.srv1$/)?.[1] ?? lang;
      return { xml, lang: matchedLang, langName: matchedLang };
    } finally {
      const { rmSync } = await import("fs");
      rmSync(tmpDir, { recursive: true, force: true });
    }
  }

  private static async fetchTranscriptDirect(
    requestPayload: YouTubeTranscriptPayload,
  ): Promise<{ xml: string; lang: string; langName: string }> {
    const response = await this._fetch(requestPayload);
    const html = await this.readResponseText(response);

    const playerResponse = YouTubeTranscript.extractPlayerResponse(html);
    const tracks = YouTubeTranscript.getCaptionTracks(playerResponse);

    const lang = requestPayload.lang ?? "en";
    const track =
      tracks.find((t: any) => t.languageCode === lang) ?? tracks[0];

    const captionUrl = track.baseUrl + (track.baseUrl.includes("fmt=") ? "" : "&fmt=srv1");
    const captionResponse = await this._fetch({
      url: captionUrl,
      headers: requestPayload.headers,
      proxy: requestPayload.proxy,
    });

    const xml = await this.readResponseText(captionResponse);
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
      const lang = requestPayload.lang ?? "en";
      let result: { xml: string; lang: string; langName: string };

      if (await this.checkYtDlp()) {
        // Validate lang before attempting yt-dlp — this is a security check that must not be swallowed
        if (!/^[a-zA-Z0-9-]+$/.test(lang)) {
          throw new Error(`Invalid language code: "${lang}". Only letters, digits, and hyphens are allowed.`);
        }
        try {
          result = await this.fetchTranscriptViaYtDlp(requestPayload.url, lang);
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
      const response = await this._fetch(requestPayload);
      const html = await this.readResponseText(response);

      const result = readdown(html, { url: requestPayload.url, includeHeader: false });
      let content = result.markdown;

      content = this.applyLengthLimits(
        content,
        requestPayload.max_length ?? downloadLimit,
        requestPayload.start_index ?? 0
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
      const response = await this._fetch(requestPayload);
      const html = await this.readResponseText(response);
      const result = readdown(html, { url: requestPayload.url, includeHeader: false, raw: true });
      let markdown = result.markdown;

      // Apply length limits
      markdown = this.applyLengthLimits(
        markdown,
        requestPayload.max_length ?? downloadLimit,
        requestPayload.start_index ?? 0
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
