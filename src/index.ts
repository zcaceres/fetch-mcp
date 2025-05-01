#!/usr/bin/env node

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { RequestPayloadSchema } from "./types.js";
import { Fetcher } from "./Fetcher.js";

const server = new Server(
  {
    name: "zcaceres/fetch",
    version: "0.1.0",
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
        description: "Fetch a website and return the content as HTML",
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
              description: "Maximum number of characters to return (default: 5000)",
            },
            start_index: {
              type: "number",
              description: "Start content from this character index (default: 0)",
            },
          },
          required: ["url"],
        },
      },
      {
        name: "fetch_markdown",
        description: "Fetch a website and return the content as Markdown",
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
              description: "Maximum number of characters to return (default: 5000)",
            },
            start_index: {
              type: "number",
              description: "Start content from this character index (default: 0)",
            },
          },
          required: ["url"],
        },
      },
      {
        name: "fetch_txt",
        description:
          "Fetch a website, return the content as plain text (no HTML)",
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
              description: "Maximum number of characters to return (default: 5000)",
            },
            start_index: {
              type: "number",
              description: "Start content from this character index (default: 0)",
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
              description: "Maximum number of characters to return (default: 5000)",
            },
            start_index: {
              type: "number",
              description: "Start content from this character index (default: 0)",
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

  const validatedArgs = RequestPayloadSchema.parse(args);

  if (request.params.name === "fetch_html") {
    const fetchResult = await Fetcher.html(validatedArgs);
    return fetchResult;
  }
  if (request.params.name === "fetch_json") {
    const fetchResult = await Fetcher.json(validatedArgs);
    return fetchResult;
  }
  if (request.params.name === "fetch_txt") {
    const fetchResult = await Fetcher.txt(validatedArgs);
    return fetchResult;
  }
  if (request.params.name === "fetch_markdown") {
    const fetchResult = await Fetcher.markdown(validatedArgs);
    return fetchResult;
  }
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
