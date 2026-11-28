import { dispatchToolCall, listTools } from '../../src/mcp/server.ts';
import { parseOperatorLimits } from '../../src/policy/verbs.ts';
import { err, ok } from '../../src/shared/result.ts';
import type { Command } from '../command.ts';

const USAGE = 'usage: mcp list-tools [--cursor <val>] | mcp call <tool> <jsonArgs...>';

export const mcpCommand: Command = {
  kind: 'domain',
  usage: USAGE,
  summary: 'invoke MCP tools/list and tools/call against the shared domain core',
  run: async (args, world) => {
    const [action, ...rest] = args;
    const envMap = Object.fromEntries(world.env.entries());
    const limits = parseOperatorLimits(envMap);
    if (!limits.ok) {
      return err(limits.error.message);
    }

    if (action === 'list-tools') {
      let cursor: string | undefined;
      for (let i = 0; i < rest.length; i++) {
        if (rest[i] === '--cursor') {
          const val = rest[i + 1];
          if (val === undefined) return err('Missing value for --cursor');
          cursor = val;
          i++;
        } else {
          return err(`Unknown flag: ${rest[i]}`);
        }
      }

      const listed = listTools(limits.value.defaultLimit, cursor);
      if (!listed.ok) {
        return ok([`error (${listed.error.code}): ${listed.error.message}`]);
      }
      return ok(
        listed.value.tools.map((tool) => `tool: ${tool.name} (${Object.keys(tool.inputSchema.properties).join(', ')})`),
      );
    }

    if (action === 'call') {
      const [toolName, ...jsonParts] = rest;
      if (!toolName || jsonParts.length === 0) {
        return err('usage: mcp call <tool> <jsonArgs...>');
      }
      let parsedArgs: unknown;
      try {
        parsedArgs = JSON.parse(jsonParts.join(' '));
      } catch {
        return err('Invalid JSON arguments');
      }

      const result = await dispatchToolCall(toolName, parsedArgs, {
        fetchPorts: { httpGet: world.origin.get, dnsLookup: world.dns.lookup },
        ytDlp: world.ytdlp,
        env: envMap,
        limits: limits.value,
      });

      if (!result.ok) {
        return ok([`error (${result.error.code}): ${result.error.message}`]);
      }

      const text = result.value.content[0].text;
      const bodyLines =
        text.length === 0 ? ['(empty)'] : text.split('\n').map((line) => (line.length > 0 ? `| ${line}` : '|'));
      return ok([`isError: ${result.value.isError}`, ...bodyLines]);
    }

    return err(USAGE);
  },
};
