import { describe, it, expect } from "bun:test";
import { YouTubeTranscript } from "./YouTubeTranscript";

describe("YouTubeTranscript", () => {
  describe("extractPlayerResponse", () => {
    it("extracts ytInitialPlayerResponse from HTML", () => {
      const html = `<html><script>var ytInitialPlayerResponse = {"captions":{"test":true}};</script></html>`;
      const result = YouTubeTranscript.extractPlayerResponse(html);
      expect(result).toEqual({ captions: { test: true } });
    });

    it("throws when ytInitialPlayerResponse is not found", () => {
      expect(() => YouTubeTranscript.extractPlayerResponse("<html></html>")).toThrow(
        "Could not find ytInitialPlayerResponse",
      );
    });
  });

  describe("getCaptionTracks", () => {
    it("returns caption tracks from player response", () => {
      const playerResponse = {
        captions: {
          playerCaptionsTracklistRenderer: {
            captionTracks: [
              { languageCode: "en", baseUrl: "https://example.com/captions" },
            ],
          },
        },
      };
      const tracks = YouTubeTranscript.getCaptionTracks(playerResponse);
      expect(tracks).toHaveLength(1);
      expect(tracks[0].languageCode).toBe("en");
    });

    it("throws when no caption tracks exist", () => {
      expect(() => YouTubeTranscript.getCaptionTracks({})).toThrow(
        "No caption tracks found",
      );
    });

    it("throws when captionTracks is empty", () => {
      const playerResponse = {
        captions: {
          playerCaptionsTracklistRenderer: {
            captionTracks: [],
          },
        },
      };
      expect(() => YouTubeTranscript.getCaptionTracks(playerResponse)).toThrow(
        "No caption tracks found",
      );
    });
  });

  describe("decodeHtmlEntities", () => {
    it("decodes all supported entities", () => {
      expect(YouTubeTranscript.decodeHtmlEntities("&amp; &lt; &gt; &quot; &#39;")).toBe(
        '& < > " \'',
      );
    });

    it("leaves plain text unchanged", () => {
      expect(YouTubeTranscript.decodeHtmlEntities("hello world")).toBe("hello world");
    });
  });

  describe("parseTranscriptXml", () => {
    it("parses <text> format", () => {
      const xml = `<?xml version="1.0" encoding="utf-8"?>
<transcript>
<text start="0" dur="5.2">Hello world</text>
<text start="5.2" dur="3.1">Second line</text>
<text start="65" dur="2.0">After a minute</text>
</transcript>`;
      const lines = YouTubeTranscript.parseTranscriptXml(xml);
      expect(lines).toEqual([
        "[0:00] Hello world",
        "[0:05] Second line",
        "[1:05] After a minute",
      ]);
    });

    it("parses <p> format with milliseconds", () => {
      const xml = `<timedtext>
<p t="0" d="5200">Hello world</p>
<p t="5200" d="3100">Second line</p>
<p t="65000" d="2000">After a minute</p>
</timedtext>`;
      const lines = YouTubeTranscript.parseTranscriptXml(xml);
      expect(lines).toEqual([
        "[0:00] Hello world",
        "[0:05] Second line",
        "[1:05] After a minute",
      ]);
    });

    it("decodes HTML entities in captions", () => {
      const xml = `<transcript><text start="0" dur="2">Tom &amp; Jerry &lt;3</text></transcript>`;
      const lines = YouTubeTranscript.parseTranscriptXml(xml);
      expect(lines).toEqual(["[0:00] Tom & Jerry <3"]);
    });

    it("strips inline HTML tags from caption text", () => {
      const xml = `<transcript><text start="0" dur="2"><font color="#CCCCCC">styled</font> text</text></transcript>`;
      const lines = YouTubeTranscript.parseTranscriptXml(xml);
      expect(lines).toEqual(["[0:00] styled text"]);
    });

    it("skips empty captions", () => {
      const xml = `<transcript><text start="0" dur="2">Hello</text><text start="2" dur="1">  </text><text start="3" dur="2">World</text></transcript>`;
      const lines = YouTubeTranscript.parseTranscriptXml(xml);
      expect(lines).toEqual(["[0:00] Hello", "[0:03] World"]);
    });

    it("returns empty array for unrecognized format", () => {
      const lines = YouTubeTranscript.parseTranscriptXml("<something>no match</something>");
      expect(lines).toEqual([]);
    });
  });
});
