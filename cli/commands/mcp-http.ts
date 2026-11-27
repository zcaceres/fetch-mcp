import { z } from 'zod';
import pkg from '../../package.json' with { type: 'json' };
import { handleStreamableHttpRequest, parseServerArgs } from '../../src/mcp/http.ts';
import { parseOperatorLimits } from '../../src/policy/verbs.ts';
import { err, ok } from '../../src/shared/result.ts';
import type { Command } from '../command.ts';

const USAGE =
  'usage: mcp-http check-args [args...] | mcp-http request <method> <path> [--host <hdr>] [--origin <hdr>] [--body <json...>]';

const RpcSummarySchema = z.object({
  error: z.object({ code: z.number(), message: z.string() }).optional(),
  result: z
    .object({
      protocolVersion: z.string().optional(),
      capabilities: z.record(z.string(), z.unknown()).optional(),
      tools: z.array(z.object({ name: z.string() })).optional(),
      isError: z.boolean().optional(),
      content: z.array(z.object({ text: z.string() })).optional(),
    })
    .optional(),
});

const formatRpcSummary = (body: string): string => {
  try {
    const parsed = RpcSummarySchema.safeParse(JSON.parse(body));
    if (!parsed.success) return body;
    const { error, result } = parsed.data;

    if (error) {
      return `error (${error.code}): ${error.message}`;
    }
    if (result?.protocolVersion && result.capabilities) {
      const caps = Object.keys(result.capabilities).join(',');
      return `initialize ${result.protocolVersion} capabilities=${caps}`;
    }
    if (result?.tools) {
      return `tools=${result.tools.map((t) => t.name).join(',')}`;
    }
    if (typeof result?.isError === 'boolean') {
      const text = result.content?.[0]?.text ?? '';
      return `isError=${result.isError} text=${text}`;
    }
  } catch {
    // Plain text response
  }
  return body;
};

export const mcpHttpCommand: Command = {
  kind: 'domain',
  usage: USAGE,
  summary: 'exercise Streamable HTTP startup flags, Host/Origin guards, and stateless /mcp dispatch',
  run: async (args, world) => {
    const [action, ...rest] = args;

    if (action === 'check-args') {
      const parsed = parseServerArgs(rest);
      if (!parsed.ok) return err(parsed.error);
      if (parsed.value.kind === 'stdio') return ok(['mode: stdio']);
      return ok([`mode: http ${parsed.value.host}:${parsed.value.port}`]);
    }

    if (action === 'request') {
      const [method, path, ...flags] = rest;
      if (!method || !path) {
        return err('usage: mcp-http request <method> <path> [--host <hdr>] [--origin <hdr>] [--body <json...>]');
      }

      const headers: Record<string, string> = {};
      let body: string | undefined;

      for (let i = 0; i < flags.length; i++) {
        const flag = flags[i];
        if (flag === '--host') {
          const val = flags[i + 1];
          if (val === undefined) return err('Missing value for --host');
          headers.host = val;
          i++;
        } else if (flag === '--origin') {
          const val = flags[i + 1];
          if (val === undefined) return err('Missing value for --origin');
          headers.origin = val;
          i++;
        } else if (flag === '--body') {
          body = flags.slice(i + 1).join(' ');
          break;
        } else {
          return err(`Unknown flag: ${flag}`);
        }
      }

      const envMap = Object.fromEntries(world.env.entries());
      const limits = parseOperatorLimits(envMap);
      if (!limits.ok) return err(limits.error.message);

      const response = await handleStreamableHttpRequest(
        { method, path, headers, ...(body !== undefined ? { body } : {}) },
        {
          version: pkg.version,
          boundHost: '127.0.0.1',
          boundPort: 3000,
          fetchPorts: { httpGet: world.origin.get, dnsLookup: world.dns.lookup },
          ytDlp: world.ytdlp,
          env: envMap,
          limits: limits.value,
        },
      );

      return ok([`status: ${response.status}`, `body: ${formatRpcSummary(response.body)}`]);
    }

    return err(USAGE);
  },
};
