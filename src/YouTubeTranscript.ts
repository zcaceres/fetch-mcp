export class YouTubeTranscript {
  static extractPlayerResponse(html: string): unknown {
    const marker = /ytInitialPlayerResponse\s*=\s*(?=\{)/.exec(html);
    if (!marker) {
      throw new Error("Could not find ytInitialPlayerResponse in page HTML");
    }
    const start = marker.index + marker[0].length;
    const end = this.findJsonObjectEnd(html, start);
    if (end === -1) {
      throw new Error("Could not find ytInitialPlayerResponse in page HTML");
    }
    return JSON.parse(html.slice(start, end));
  }

  /**
   * Returns the index just past the JSON object that starts at `start`, or -1
   * when it is unterminated. Braces inside string values (for example a video
   * description containing "};") do not end the object.
   */
  private static findJsonObjectEnd(text: string, start: number): number {
    let depth = 0;
    let inString = false;
    for (let i = start; i < text.length; i++) {
      const ch = text[i];
      if (inString) {
        if (ch === "\\") {
          i++;
        } else if (ch === '"') {
          inString = false;
        }
      } else if (ch === '"') {
        inString = true;
      } else if (ch === "{") {
        depth++;
      } else if (ch === "}") {
        depth--;
        if (depth === 0) {
          return i + 1;
        }
      }
    }
    return -1;
  }

  static getCaptionTracks(playerResponse: any): any[] {
    const tracks =
      playerResponse?.captions?.playerCaptionsTracklistRenderer?.captionTracks;
    if (!Array.isArray(tracks) || tracks.length === 0) {
      throw new Error("No caption tracks found for this video");
    }
    return tracks;
  }

  static decodeHtmlEntities(text: string): string {
    return text
      .replace(/&amp;/g, "&")
      .replace(/&lt;/g, "<")
      .replace(/&gt;/g, ">")
      .replace(/&quot;/g, '"')
      .replace(/&#39;/g, "'");
  }

  static parseTranscriptXml(xml: string): string[] {
    const lines: string[] = [];

    // Format 1: <text start="X" dur="Y">content</text>
    const textRegex = /<text\s+start="([^"]+)"[^>]*>([\s\S]*?)<\/text>/g;
    // Format 2: <p t="X" d="Y">content</p>
    const pRegex = /<p\s+t="(\d+)"[^>]*>([\s\S]*?)<\/p>/g;

    let match: RegExpExecArray | null;

    match = textRegex.exec(xml);
    if (match) {
      // Reset and use format 1
      textRegex.lastIndex = 0;
      while ((match = textRegex.exec(xml)) !== null) {
        const seconds = parseFloat(match[1]);
        const content = this.decodeHtmlEntities(match[2].replace(/<[^>]+>/g, "").trim());
        if (content) {
          lines.push(`[${this.formatTimestamp(seconds)}] ${content}`);
        }
      }
    } else {
      // Try format 2
      while ((match = pRegex.exec(xml)) !== null) {
        const ms = parseInt(match[1], 10);
        const seconds = ms / 1000;
        const content = this.decodeHtmlEntities(match[2].replace(/<[^>]+>/g, "").trim());
        if (content) {
          lines.push(`[${this.formatTimestamp(seconds)}] ${content}`);
        }
      }
    }

    return lines;
  }

  private static formatTimestamp(totalSeconds: number): string {
    const minutes = Math.floor(totalSeconds / 60);
    const seconds = Math.floor(totalSeconds % 60);
    return `${minutes}:${seconds.toString().padStart(2, "0")}`;
  }
}
