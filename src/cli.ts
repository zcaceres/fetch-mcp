#!/usr/bin/env node

import { Fetcher } from "./Fetcher.js";
import type { RequestPayload, YouTubeTranscriptPayload } from "./types.js";
import pkg from "../package.json" with { type: "json" };

const USAGE = `mcp-fetch v${pkg.version}

Usage: mcp-fetch <command> <url> [flags]

Commands:
  html      Fetch a URL and return raw HTML
  markdown  Fetch a URL and return Markdown
  readable  Fetch a URL and return article content as Markdown (via Readability)
  txt       Fetch a URL and return plain text
  json      Fetch a URL and return JSON
  youtube   Fetch a YouTube video transcript

Flags:
  --max-length <N>   Maximum characters to return
  --start-index <N>  Start from this character index
  --proxy <URL>      Proxy URL
  --lang <code>      Language code for YouTube transcripts (default: en)
  --help             Show this help message
  --version          Show version
`;

const SUBCOMMANDS = ["html", "markdown", "readable", "txt", "json", "youtube"] as const;
type Subcommand = (typeof SUBCOMMANDS)[number];

export interface ParsedArgs {
  subcommand: Subcommand;
  url: string;
  maxLength?: number;
  startIndex?: number;
  proxy?: string;
  lang?: string;
}

export function parseArgs(argv: string[]): ParsedArgs {
  if (argv.length === 0 || argv.includes("--help")) {
    process.stdout.write(USAGE);
    process.exit(0);
  }

  if (argv.includes("--version")) {
    process.stdout.write(pkg.version + "\n");
    process.exit(0);
  }

  const subcommand = argv[0] as string;
  if (!SUBCOMMANDS.includes(subcommand as Subcommand)) {
    process.stderr.write(`Unknown command: ${subcommand}\n\n${USAGE}`);
    process.exit(1);
  }

  const url = argv[1];
  if (!url || url.startsWith("--")) {
    process.stderr.write(`Missing URL for "${subcommand}" command\n`);
    process.exit(1);
  }

  const result: ParsedArgs = { subcommand: subcommand as Subcommand, url };

  for (let i = 2; i < argv.length; i++) {
    const flag = argv[i];
    const value = argv[i + 1];
    switch (flag) {
      case "--max-length": {
        const parsed = parseInt(value, 10);
        if (isNaN(parsed)) {
          process.stderr.write(`${flag} requires a numeric value\n`);
          process.exit(1);
        }
        result.maxLength = parsed;
        i++;
        break;
      }
      case "--start-index": {
        const parsed = parseInt(value, 10);
        if (isNaN(parsed)) {
          process.stderr.write(`${flag} requires a numeric value\n`);
          process.exit(1);
        }
        result.startIndex = parsed;
        i++;
        break;
      }
      case "--proxy":
        result.proxy = value;
        i++;
        break;
      case "--lang":
        result.lang = value;
        i++;
        break;
      default:
        process.stderr.write(`Unknown flag: ${flag}\n`);
        process.exit(1);
    }
  }

  return result;
}

async function run(args: ParsedArgs): Promise<void> {
  const fetchers: Record<string, (p: any) => Promise<any>> = {
    html: Fetcher.html.bind(Fetcher),
    markdown: Fetcher.markdown.bind(Fetcher),
    readable: Fetcher.readable.bind(Fetcher),
    txt: Fetcher.txt.bind(Fetcher),
    json: Fetcher.json.bind(Fetcher),
    youtube: Fetcher.youtubeTranscript.bind(Fetcher),
  };

  const payload: RequestPayload & { lang?: string } = { url: args.url };
  if (args.maxLength !== undefined) payload.max_length = args.maxLength;
  if (args.startIndex !== undefined) payload.start_index = args.startIndex;
  if (args.proxy) payload.proxy = args.proxy;
  if (args.lang) payload.lang = args.lang;

  const result = await fetchers[args.subcommand](payload);
  const text = result.content[0].text;

  if (result.isError) {
    process.stderr.write(text + "\n");
    process.exit(1);
  }

  process.stdout.write(text);
}

import { realpathSync } from "fs";
import { fileURLToPath } from "url";

function isMainModule(): boolean {
  try {
    const scriptPath = fileURLToPath(import.meta.url);
    const argPath = realpathSync(process.argv[1]);
    return scriptPath === argPath;
  } catch {
    return process.argv[1]?.endsWith("/cli.js") || process.argv[1]?.endsWith("/mcp-fetch") || false;
  }
}

if (isMainModule()) {
  const args = parseArgs(process.argv.slice(2));
  run(args).catch((err) => {
    process.stderr.write(String(err?.message ?? err) + "\n");
    process.exit(1);
  });
}
