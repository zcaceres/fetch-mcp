import type { Command } from '../command.ts';
import { dnsCommand } from './dns.ts';
import { envCommand } from './env.ts';
import { fetchCommand } from './fetch.ts';
import { fetchTranscriptCommand } from './fetch-transcript.ts';
import { mcpCommand } from './mcp.ts';
import { mcpHttpCommand } from './mcp-http.ts';
import { originCommand } from './origin.ts';
import { verifyMcpCommand } from './verify-mcp.ts';
import { ytdlpCommand } from './ytdlp.ts';

export const commands: Readonly<Record<string, Command>> = {
  fetch: fetchCommand,
  'fetch-transcript': fetchTranscriptCommand,
  mcp: mcpCommand,
  'mcp-http': mcpHttpCommand,
  'verify-mcp': verifyMcpCommand,
  origin: originCommand,
  dns: dnsCommand,
  ytdlp: ytdlpCommand,
  env: envCommand,
};
