import { dispatchToolCall, listTools } from '../../src/mcp/server.ts';
import { parseOperatorLimits } from '../../src/policy/verbs.ts';
import { err, ok } from '../../src/shared/result.ts';
import { validateVendorSchemas } from '../../src/verification/queries.ts';
import type { Command } from '../command.ts';

const USAGE = 'usage: verify-mcp check-schemas | verify-mcp check-strict <tool> <jsonArgs...>';

export const verifyMcpCommand: Command = {
  kind: 'domain',
  usage: USAGE,
  summary: 'validate cross-vendor MCP tool schemas and strict unknown-key refusal',
  run: async (args, world) => {
    const [action, ...rest] = args;
    const envMap = Object.fromEntries(world.env.entries());
    const limits = parseOperatorLimits(envMap);
    if (!limits.ok) {
      return err(limits.error.message);
    }

    if (action === 'check-schemas') {
      const listed = listTools(limits.value.defaultLimit);
      if (!listed.ok) {
        return err(listed.error.message);
      }
      const issues = validateVendorSchemas(listed.value.tools);
      if (issues.length === 0) {
        return ok([`conformance: ok (${listed.value.tools.length} tools: anthropic, gemini, openai)`]);
      }
      return ok(issues.map((i) => `issue: ${i.vendor} ${i.tool}: ${i.message}`));
    }

    if (action === 'check-strict') {
      const [toolName, ...jsonParts] = rest;
      if (!toolName || jsonParts.length === 0) {
        return err('usage: verify-mcp check-strict <tool> <jsonArgs...>');
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
