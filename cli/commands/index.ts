import type { Command } from '../command.ts';
import { dnsCommand } from './dns.ts';
import { fetchCommand } from './fetch.ts';
import { fetchTranscriptCommand } from './fetch-transcript.ts';
import { originCommand } from './origin.ts';
import { ytdlpCommand } from './ytdlp.ts';

export const commands: Readonly<Record<string, Command>> = {
  fetch: fetchCommand,
  'fetch-transcript': fetchTranscriptCommand,
  origin: originCommand,
  dns: dnsCommand,
  ytdlp: ytdlpCommand,
};
