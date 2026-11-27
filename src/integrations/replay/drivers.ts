import { execFileSync, spawn } from 'node:child_process';
import net from 'node:net';
import path from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { z } from 'zod';
import type { CellOutcome, LiveSample, VendorToolSchemaInput } from '../../verification/nouns.ts';
import { validateVendorSchemas } from '../../verification/queries.ts';

const REPO_ROOT = path.resolve(import.meta.dir, '../../..');
const DIST_CLI_PATH = path.join(REPO_ROOT, 'dist/cli.js');
const DIST_SERVER_PATH = path.join(REPO_ROOT, 'dist/index.js');
const EXPECTED_TOOL_COUNT = 6;

export const resolveNodeBinary = (): string => {
  try {
    return execFileSync('which', ['node'], { encoding: 'utf-8' }).trim();
  } catch {
    return 'node';
  }
};

const findFreePort = (): Promise<number> =>
  new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.on('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const addr = srv.address();
      const port = typeof addr === 'object' && addr !== null ? addr.port : 0;
      srv.close(() => resolve(port));
    });
  });

const buildToolArguments = (sample: LiveSample): Record<string, unknown> => ({
  url: sample.url,
  ...(sample.lang !== undefined ? { lang: sample.lang } : {}),
  ...(sample.maxLength !== undefined ? { max_length: sample.maxLength } : {}),
  ...(sample.startIndex !== undefined ? { start_index: sample.startIndex } : {}),
  ...(sample.headers !== undefined ? { headers: sample.headers } : {}),
});

const extractToolOutcome = (result: unknown): CellOutcome => {
  if (typeof result !== 'object' || result === null) {
    return { ok: false, output: 'Invalid MCP tool response' };
  }
  const isError = 'isError' in result && result.isError === true;
  let text = '';
  if ('content' in result && Array.isArray(result.content)) {
    const first: unknown = result.content[0];
    if (typeof first === 'object' && first !== null && 'text' in first && typeof first.text === 'string') {
      text = first.text;
    }
  }
  return { ok: !isError, output: text };
};

const VendorPropertySchema = z.object({
  type: z.string().optional(),
  description: z.string().optional(),
  additionalProperties: z.union([z.boolean(), z.object({ type: z.string().optional() })]).optional(),
  oneOf: z.array(z.unknown()).optional(),
  anyOf: z.array(z.unknown()).optional(),
  allOf: z.array(z.unknown()).optional(),
  format: z.string().optional(),
});

const VendorToolSchema = z.object({
  name: z.string(),
  description: z.string(),
  inputSchema: z.object({
    type: z.string(),
    properties: z.record(z.string(), VendorPropertySchema),
    required: z.array(z.string()).optional(),
    additionalProperties: z.boolean().optional(),
    oneOf: z.array(z.unknown()).optional(),
    anyOf: z.array(z.unknown()).optional(),
    allOf: z.array(z.unknown()).optional(),
  }),
  annotations: z
    .object({
      readOnlyHint: z.boolean().optional(),
      destructiveHint: z.boolean().optional(),
      idempotentHint: z.boolean().optional(),
      openWorldHint: z.boolean().optional(),
    })
    .optional(),
});

const auditListedTools = (tools: readonly unknown[]): readonly string[] => {
  const validTools: VendorToolSchemaInput[] = [];
  const issues: string[] = [];

  if (tools.length !== EXPECTED_TOOL_COUNT) {
    issues.push(`schema tools/list: expected ${EXPECTED_TOOL_COUNT} D12 tools, got ${tools.length}`);
  }

  for (let i = 0; i < tools.length; i++) {
    const parsed = VendorToolSchema.safeParse(tools[i]);
    if (parsed.success) {
      validTools.push(parsed.data);
    } else {
      const detail = parsed.error.issues[0]?.message ?? 'malformed tool schema';
      issues.push(`schema tool[${i}]: ${detail}`);
    }
  }

  for (const issue of validateVendorSchemas(validTools)) {
    issues.push(`${issue.vendor} ${issue.tool}: ${issue.message}`);
  }
  return issues;
};

/**
 * Runs one Live Sample against the unmodified built `dist/cli.js` binary under Node.js (D1, D34, D35).
 */
export const runCliSample = (
  sample: LiveSample,
  env: Readonly<Record<string, string | undefined>>,
  nodeBin: string = resolveNodeBinary(),
): Promise<CellOutcome> =>
  new Promise((resolve) => {
    const args: string[] = [DIST_CLI_PATH, sample.cliSubcommand, sample.url];
    if (sample.lang !== undefined) {
      args.push('--lang', sample.lang);
    }
    if (sample.maxLength !== undefined) {
      args.push('--max-length', String(sample.maxLength));
    }
    if (sample.startIndex !== undefined) {
      args.push('--start-index', String(sample.startIndex));
    }
    if (sample.headers) {
      for (const [key, value] of Object.entries(sample.headers)) {
        args.push('--header', `${key}: ${value}`);
      }
    }

    const proc = spawn(nodeBin, args, {
      stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...env },
    });

    let stdout = '';
    let stderr = '';
    proc.stdout.on('data', (chunk: Buffer) => {
      stdout += chunk.toString('utf-8');
    });
    proc.stderr.on('data', (chunk: Buffer) => {
      stderr += chunk.toString('utf-8');
    });
    proc.on('error', (error) => {
      resolve({ ok: false, output: `Failed to spawn dist/cli.js: ${error.message}` });
    });
    proc.on('close', (code) => {
      resolve({
        ok: code === 0,
        output: code === 0 ? stdout : stderr.trim(),
      });
    });
  });

export type McpDriver = {
  readonly callSample: (sample: LiveSample) => Promise<CellOutcome>;
  readonly schemaIssues: readonly string[];
  readonly close: () => Promise<void>;
};

const toStringEnv = (env: Readonly<Record<string, string | undefined>>): Record<string, string> => {
  const clean: Record<string, string> = {};
  for (const [k, v] of Object.entries(env)) {
    if (v !== undefined) {
      clean[k] = v;
    }
  }
  return clean;
};

/**
 * Connects a stock `@modelcontextprotocol/sdk` `Client` over `StdioClientTransport` to unmodified
 * `dist/index.js` and validates Anthropic/Gemini/OpenAI tool schemas on startup (D33, D34).
 */
export const createStdioMcpDriver = async (
  env: Readonly<Record<string, string | undefined>>,
  nodeBin: string = resolveNodeBinary(),
): Promise<McpDriver> => {
  const transport = new StdioClientTransport({
    command: nodeBin,
    args: [DIST_SERVER_PATH],
    env: toStringEnv(env),
    stderr: 'pipe',
  });
  const client = new Client({ name: 'fetch-mcp-verifier-stdio', version: '1.0.0' });
  await client.connect(transport);

  try {
    const listed = await client.listTools();
    const issues = auditListedTools(listed.tools);

    return {
      schemaIssues: issues,
      callSample: async (sample) => {
        const res = await client.callTool({ name: sample.tool, arguments: buildToolArguments(sample) });
        return extractToolOutcome(res);
      },
      close: async () => {
        await client.close();
      },
    };
  } catch (error) {
    await client.close().catch(() => undefined);
    throw error;
  }
};

/**
 * Spawns unmodified `dist/index.js --http --port <ephemeral>` under Node.js, connects a stock
 * `@modelcontextprotocol/sdk` `Client` via `StreamableHTTPClientTransport`, and validates schemas (D32, D33, D34).
 */
export const createHttpMcpDriver = async (
  env: Readonly<Record<string, string | undefined>>,
  nodeBin: string = resolveNodeBinary(),
): Promise<McpDriver> => {
  const port = await findFreePort();
  const proc = spawn(nodeBin, [DIST_SERVER_PATH, '--http', '--host', '127.0.0.1', '--port', String(port)], {
    stdio: ['ignore', 'pipe', 'pipe'],
    env: { ...env },
  });

  const killChild = async (): Promise<void> => {
    if (proc.exitCode !== null || proc.killed) return;
    proc.kill('SIGTERM');
    await new Promise<void>((resolve) => {
      const killTimer = setTimeout(() => {
        proc.kill('SIGKILL');
        resolve();
      }, 1500);
      proc.once('close', () => {
        clearTimeout(killTimer);
        resolve();
      });
    });
  };

  try {
    await new Promise<void>((resolve, reject) => {
      let stderr = '';
      const timer = setTimeout(() => {
        proc.kill();
        reject(new Error(`Timed out waiting for dist/index.js --http on port ${port}. stderr: ${stderr}`));
      }, 5000);

      proc.stderr.on('data', (chunk: Buffer) => {
        stderr += chunk.toString('utf-8');
        if (stderr.includes(`http://127.0.0.1:${port}/mcp`)) {
          clearTimeout(timer);
          resolve();
        }
      });
      proc.on('error', (error) => {
        clearTimeout(timer);
        reject(error);
      });
      proc.on('close', (code) => {
        clearTimeout(timer);
        reject(new Error(`dist/index.js --http exited early (${String(code)}): ${stderr}`));
      });
    });

    const transport = new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${port}/mcp`));
    const client = new Client({ name: 'fetch-mcp-verifier-http', version: '1.0.0' });
    await client.connect(transport);

    try {
      const listed = await client.listTools();
      const issues = auditListedTools(listed.tools);

      return {
        schemaIssues: issues,
        callSample: async (sample) => {
          const res = await client.callTool({ name: sample.tool, arguments: buildToolArguments(sample) });
          return extractToolOutcome(res);
        },
        close: async () => {
          await client.close();
          await killChild();
        },
      };
    } catch (error) {
      await client.close().catch(() => undefined);
      throw error;
    }
  } catch (error) {
    await killChild();
    throw error;
  }
};
