#!/usr/bin/env node

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { RequestPayloadSchema, YouTubeTranscriptPayloadSchema } from "./types.js";
import { Fetcher } from "./Fetcher.js";
import process from "process";
import { downloadLimit } from "./types.js";
import pkg from "../package.json" with { type: "json" };

const server = new Server(
  {
    name: "zcaceres/fetch",
    version: pkg.version,
  },
  {
    capabilities: {
      resources: {},
      tools: {},
    },
  },
);

server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: "fetch_html",
        description: "Fetch a website and return its unmodified contents as HTML",
        inputSchema: {
          type: "object",
          properties: {
            url: {
              type: "string",
              description: "URL of the website to fetch",
            },
            headers: {
              type: "object",
              description: "Optional headers to include in the request",
            },
            max_length: {
              type: "number",
              description: `Maximum number of characters to return (default: ${downloadLimit})`,
            },
            start_index: {
              type: "number",
              description: "Start content from this character index (default: 0)",
            },
            proxy: {
              type: "string",
              description: "Optional proxy URL (e.g. 'http://proxy:8080')",
            },
          },
          required: ["url"],
        },
      },
      {
        name: "fetch_markdown",
        description: "Fetch a website and return its contents converted to Markdown",
        inputSchema: {
          type: "object",
          properties: {
            url: {
              type: "string",
              description: "URL of the website to fetch",
            },
            headers: {
              type: "object",
              description: "Optional headers to include in the request",
            },
            max_length: {
              type: "number",
              description: `Maximum number of characters to return (default: ${downloadLimit})`,
            },
            start_index: {
              type: "number",
              description: "Start content from this character index (default: 0)",
            },
            proxy: {
              type: "string",
              description: "Optional proxy URL (e.g. 'http://proxy:8080')",
            },
          },
          required: ["url"],
        },
      },
      {
        name: "fetch_txt",
        description:
          "Fetch a website, convert the content to plain text (no HTML)",
        inputSchema: {
          type: "object",
          properties: {
            url: {
              type: "string",
              description: "URL of the website to fetch",
            },
            headers: {
              type: "object",
              description: "Optional headers to include in the request",
            },
            max_length: {
              type: "number",
              description: `Maximum number of characters to return (default: ${downloadLimit})`,
            },
            start_index: {
              type: "number",
              description: "Start content from this character index (default: 0)",
            },
            proxy: {
              type: "string",
              description: "Optional proxy URL (e.g. 'http://proxy:8080')",
            },
          },
          required: ["url"],
        },
      },
      {
        name: "fetch_json",
        description: "Fetch a JSON file from a URL",
        inputSchema: {
          type: "object",
          properties: {
            url: {
              type: "string",
              description: "URL of the JSON to fetch",
            },
            headers: {
              type: "object",
              description: "Optional headers to include in the request",
            },
            max_length: {
              type: "number",
              description: `Maximum number of characters to return (default: ${downloadLimit})`,
            },
            start_index: {
              type: "number",
              description: "Start content from this character index (default: 0)",
            },
            proxy: {
              type: "string",
              description: "Optional proxy URL (e.g. 'http://proxy:8080')",
            },
          },
          required: ["url"],
        },
      },
      {
        name: "fetch_youtube_transcript",
        description:
          "Fetch a YouTube video page and extract its captions/transcript",
        inputSchema: {
          type: "object",
          properties: {
            url: {
              type: "string",
              description: "URL of the YouTube video",
            },
            headers: {
              type: "object",
              description: "Optional headers to include in the request",
            },
            max_length: {
              type: "number",
              description: `Maximum number of characters to return (default: ${downloadLimit})`,
            },
            start_index: {
              type: "number",
              description: "Start content from this character index (default: 0)",
            },
            proxy: {
              type: "string",
              description: "Optional proxy URL (e.g. 'http://proxy:8080')",
            },
            lang: {
              type: "string",
              description: "Language code for captions (default: 'en')",
            },
          },
          required: ["url"],
        },
      },
    ],
  };
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  if (name === "fetch_youtube_transcript") {
    const validatedArgs = YouTubeTranscriptPayloadSchema.parse(args);
    return Fetcher.youtubeTranscript(validatedArgs);
  }

  const validatedArgs = RequestPayloadSchema.parse(args);

  if (name === "fetch_html") return Fetcher.html(validatedArgs);
  if (name === "fetch_json") return Fetcher.json(validatedArgs);
  if (name === "fetch_txt") return Fetcher.txt(validatedArgs);
  if (name === "fetch_markdown") return Fetcher.markdown(validatedArgs);
  throw new Error("Tool not found");
});

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((error) => {
  console.error("Fatal error in main():", error);
  process.exit(1);
});
