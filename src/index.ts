#!/usr/bin/env node

import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import pkg from '../package.json' with { type: 'json' };
import { createRealDnsLookup } from './integrations/dns/client.ts';
import { createRealHttpGet } from './integrations/origin/client.ts';
import { createRealYtDlp } from './integrations/ytdlp/client.ts';
import { parseServerArgs, startStreamableHttpServer } from './mcp/http.ts';
import { createMcpServer, type McpServerDeps } from './mcp/server.ts';
import { parseOperatorLimits } from './policy/verbs.ts';

async function main(): Promise<void> {
  const mode = parseServerArgs(process.argv.slice(2));
  if (!mode.ok) {
    process.stderr.write(`${mode.error}\n`);
    process.exit(1);
  }

  const limits = parseOperatorLimits(process.env);
  if (!limits.ok) {
    process.stderr.write(`${limits.error.message}\n`);
    process.exit(1);
  }

  const deps: McpServerDeps = {
    version: pkg.version,
    env: process.env,
    limits: limits.value,
    fetchPorts: {
      httpGet: createRealHttpGet({ maxBytes: limits.value.maxResponseBytes }),
      dnsLookup: createRealDnsLookup(),
    },
    ytDlp: createRealYtDlp({ maxBytes: limits.value.maxResponseBytes }),
  };

  if (mode.value.kind === 'http') {
    const running = await startStreamableHttpServer(deps, mode.value.host, mode.value.port);
    process.stderr.write(`mcp-fetch-server Streamable HTTP listening on ${running.url}\n`);
    const shutdown = (): void => {
      void running.close().finally(() => process.exit(0));
    };
    process.on('SIGINT', shutdown);
    process.on('SIGTERM', shutdown);
    return;
  }

  const server = createMcpServer(deps);
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`Fatal error in main(): ${message}\n`);
  process.exit(1);
});
