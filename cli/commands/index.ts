import type { Command } from '../command.ts';
import { dnsCommand } from './dns.ts';
import { fetchCommand } from './fetch.ts';
import { originCommand } from './origin.ts';

export const commands: Readonly<Record<string, Command>> = {
  fetch: fetchCommand,
  origin: originCommand,
  dns: dnsCommand,
};
