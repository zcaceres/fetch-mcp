import { JSDOM } from "jsdom";
import TurndownService from "turndown";
import is_ip_private from "private-ip";
import { RequestPayload } from "./types.js";

export class Fetcher {
  private static applyLengthLimits(text: string, maxLength: number, startIndex: number): string {
    if (startIndex >= text.length) {
      return "";
    }
    
    const end = Math.min(startIndex + maxLength, text.length);
    return text.substring(startIndex, end);
  }
  private static async _fetch({
    url,
    headers,
  }: RequestPayload): Promise<Response> {
    try {
      if (is_ip_private(url)) {
        throw new Error(
          `Fetcher blocked an attempt to fetch a private IP ${url}. This is to prevent a security vulnerability where a local MCP could fetch privileged local IPs and exfiltrate data.`,
        );
      }
      const response = await fetch(url, {
        headers: {
          "User-Agent":
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
          ...headers,
        },
      });

      if (!response.ok) {
        throw new Error(`HTTP error: ${response.status}`);
      }
      return response;
    } catch (e: unknown) {
      if (e instanceof Error) {
        throw new Error(`Failed to fetch ${url}: ${e.message}`);
      } else {
        throw new Error(`Failed to fetch ${url}: Unknown error`);
      }
    }
  }

  static async html(requestPayload: RequestPayload) {
    try {
      const response = await this._fetch(requestPayload);
      let html = await response.text();
      
      // Apply length limits
      html = this.applyLengthLimits(
        html, 
        requestPayload.max_length ?? 5000, 
        requestPayload.start_index ?? 0
      );
      
      return { content: [{ type: "text", text: html }], isError: false };
    } catch (error) {
      return {
        content: [{ type: "text", text: (error as Error).message }],
        isError: true,
      };
    }
  }

  static async json(requestPayload: RequestPayload) {
    try {
      const response = await this._fetch(requestPayload);
      const json = await response.json();
      let jsonString = JSON.stringify(json);
      
      // Apply length limits
      jsonString = this.applyLengthLimits(
        jsonString,
        requestPayload.max_length ?? 5000,
        requestPayload.start_index ?? 0
      );
      
      return {
        content: [{ type: "text", text: jsonString }],
        isError: false,
      };
    } catch (error) {
      return {
        content: [{ type: "text", text: (error as Error).message }],
        isError: true,
      };
    }
  }

  static async txt(requestPayload: RequestPayload) {
    try {
      const response = await this._fetch(requestPayload);
      const html = await response.text();

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
        requestPayload.max_length ?? 5000,
        requestPayload.start_index ?? 0
      );

      return {
        content: [{ type: "text", text: normalizedText }],
        isError: false,
      };
    } catch (error) {
      return {
        content: [{ type: "text", text: (error as Error).message }],
        isError: true,
      };
    }
  }

  static async markdown(requestPayload: RequestPayload) {
    try {
      const response = await this._fetch(requestPayload);
      const html = await response.text();
      const turndownService = new TurndownService();
      let markdown = turndownService.turndown(html);
      
      // Apply length limits
      markdown = this.applyLengthLimits(
        markdown,
        requestPayload.max_length ?? 5000,
        requestPayload.start_index ?? 0
      );
      
      return { content: [{ type: "text", text: markdown }], isError: false };
    } catch (error) {
      return {
        content: [{ type: "text", text: (error as Error).message }],
        isError: true,
      };
    }
  }
}
