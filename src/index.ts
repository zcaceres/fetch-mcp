#!/usr/bin/env node

import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import pkg from '../package.json' with { type: 'json' };
import { createRealDnsLookup } from './integrations/dns/client.ts';
import { createRealHttpGet } from './integrations/origin/client.ts';
import { createRealYtDlp } from './integrations/ytdlp/client.ts';
import { createMcpServer } from './mcp/server.ts';
import { parseOperatorLimits } from './policy/verbs.ts';

async function main(): Promise<void> {
  const limits = parseOperatorLimits(process.env);
  if (!limits.ok) {
    process.stderr.write(`${limits.error.message}\n`);
    process.exit(1);
  }

  const server = createMcpServer({
    version: pkg.version,
    env: process.env,
    limits: limits.value,
    fetchPorts: {
      httpGet: createRealHttpGet({ maxBytes: limits.value.maxResponseBytes }),
      dnsLookup: createRealDnsLookup(),
    },
    ytDlp: createRealYtDlp({ maxBytes: limits.value.maxResponseBytes }),
  });

  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`Fatal error in main(): ${message}\n`);
  process.exit(1);
});
