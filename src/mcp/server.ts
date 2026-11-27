import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { CallToolRequestSchema, ErrorCode, ListToolsRequestSchema, McpError } from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';
import { executeFetch } from '../fetching/execute.ts';
import type { WebFormat } from '../fetching/nouns.ts';
import type { FetchPorts, ResolveProxyPort } from '../fetching/ports.ts';
import { normalizeHostname } from '../fetching/queries.ts';
import { validateResolvedIps } from '../fetching/verbs.ts';
import type { EnvMap, OperatorLimits } from '../policy/nouns.ts';
import { resolveProxyPolicy } from '../policy/verbs.ts';
import { err, ok, type Result } from '../shared/result.ts';
import { executeFetchTranscript } from '../transcript/execute.ts';
import type { CheckHostPort, FetchPagePort, ResolveTranscriptProxyPort, YtDlpPort } from '../transcript/ports.ts';

export const MCP_TOOL_NAMES = [
  'fetch_html',
  'fetch_markdown',
  'fetch_readable',
  'fetch_text',
  'fetch_json',
  'fetch_transcript',
] as const;

export type McpToolName = (typeof MCP_TOOL_NAMES)[number];

export type McpToolDefinition = {
  readonly name: McpToolName;
  readonly description: string;
  readonly inputSchema: {
    readonly type: 'object';
    readonly properties: Readonly<Record<string, { readonly type: string; readonly description: string }>>;
    readonly required: readonly ['url'];
  };
};

export type McpToolCallResult = {
  readonly content: readonly [{ readonly type: 'text'; readonly text: string }];
  readonly isError: boolean;
};

export type McpProtocolError = {
  readonly code: -32602;
  readonly message: string;
};

export type McpDispatchDeps = {
  readonly fetchPorts: FetchPorts;
  readonly ytDlp: YtDlpPort;
  readonly env: EnvMap;
  readonly limits: OperatorLimits;
};

export type McpServerDeps = McpDispatchDeps & {
  readonly version: string;
};

const WEB_TOOL_FORMAT: Readonly<Record<Exclude<McpToolName, 'fetch_transcript'>, WebFormat>> = {
  fetch_html: 'html',
  fetch_markdown: 'markdown',
  fetch_readable: 'readable',
  fetch_text: 'text',
  fetch_json: 'json',
};

const isMcpToolName = (name: string): name is McpToolName => (MCP_TOOL_NAMES as readonly string[]).includes(name);

// Zod v4 strips unknown keys by default, silently discarding any smuggled `proxy` field (I6, D28).
const WebToolArgsSchema = z.object({
  url: z.string(),
  headers: z.record(z.string(), z.string()).optional(),
  max_length: z.number().optional(),
  start_index: z.number().optional(),
});

const TranscriptToolArgsSchema = WebToolArgsSchema.extend({
  lang: z.string().optional(),
});

const formatZodError = (error: z.ZodError): string => {
  const first = error.issues[0];
  if (!first) return 'Invalid arguments';
  const field = first.path.length > 0 ? `${first.path.join('.')}: ` : '';
  const detail = first.message.replace(/^Invalid input:\s*/i, '');
  return `Invalid arguments: ${field}${detail}`;
};

const buildCommonProperties = (defaultLimit: number) => ({
  url: { type: 'string', description: 'URL of the website to fetch' },
  headers: { type: 'object', description: 'Optional headers to include in the request' },
  max_length: { type: 'number', description: `Maximum number of characters to return (default: ${defaultLimit})` },
  start_index: { type: 'number', description: 'Start content from this character index (default: 0)' },
});

/**
 * Lists the six Terminology-aligned MCP tools (D12, I6) and rejects any unrecognized cursor with -32602 (D27).
 */
export const listTools = (
  defaultLimit: number,
  cursor?: string,
): Result<{ readonly tools: readonly McpToolDefinition[] }, McpProtocolError> => {
  if (cursor !== undefined) {
    return err({ code: -32602, message: 'Invalid pagination cursor' });
  }

  const common = buildCommonProperties(defaultLimit);
  return ok({
    tools: [
      {
        name: 'fetch_html',
        description: 'Fetch a website and return its unmodified contents as HTML',
        inputSchema: { type: 'object', properties: common, required: ['url'] },
      },
      {
        name: 'fetch_markdown',
        description: 'Fetch a website and return its contents converted to Markdown',
        inputSchema: { type: 'object', properties: common, required: ['url'] },
      },
      {
        name: 'fetch_readable',
        description:
          'Fetch a website and return its main content parsed by Mozilla Readability, converted to Markdown. Strips navigation, ads, and boilerplate.',
        inputSchema: { type: 'object', properties: common, required: ['url'] },
      },
      {
        name: 'fetch_text',
        description: 'Fetch a website and return plain text with HTML tags, scripts, and styles removed',
        inputSchema: { type: 'object', properties: common, required: ['url'] },
      },
      {
        name: 'fetch_json',
        description: 'Fetch a JSON file from a URL',
        inputSchema: {
          type: 'object',
          properties: { ...common, url: { type: 'string', description: 'URL of the JSON resource to fetch' } },
          required: ['url'],
        },
      },
      {
        name: 'fetch_transcript',
        description: 'Fetch a YouTube video transcript (via yt-dlp when available, or direct caption extraction)',
        inputSchema: {
          type: 'object',
          properties: {
            ...common,
            url: { type: 'string', description: 'URL of the YouTube video' },
            lang: { type: 'string', description: "Language code for captions (default: 'en')" },
          },
          required: ['url'],
        },
      },
    ],
  });
};

/**
 * Dispatches an MCP `tools/call` invocation over the shared domain core (D1, D6, D12, D14, D24, D26, D28, I6).
 * Unknown tool names return `-32602`; argument validation and domain errors return `isError: true`.
 */
export const dispatchToolCall = async (
  name: string,
  rawArgs: unknown,
  deps: McpDispatchDeps,
): Promise<Result<McpToolCallResult, McpProtocolError>> => {
  if (!isMcpToolName(name)) {
    return err({ code: -32602, message: `Unknown tool: ${name}` });
  }

  // Operator-only proxy policy: caller can never supply or override proxy (I6).
  const resolveFetchProxy: ResolveProxyPort = (targetUrl) => {
    const resolved = resolveProxyPolicy(targetUrl, deps.env);
    if (!resolved.ok) {
      return err({ kind: 'invalid_request', message: resolved.error.message });
    }
    return ok(resolved.value.kind === 'proxy' ? String(resolved.value.url) : undefined);
  };

  const fetchPorts: FetchPorts = {
    ...deps.fetchPorts,
    resolveProxy: deps.fetchPorts.resolveProxy ?? resolveFetchProxy,
  };

  if (name === 'fetch_transcript') {
    const parsed = TranscriptToolArgsSchema.safeParse(rawArgs ?? {});
    if (!parsed.success) {
      return ok({ content: [{ type: 'text', text: formatZodError(parsed.error) }], isError: true });
    }

    const resolveTranscriptProxy: ResolveTranscriptProxyPort = (targetUrl) => {
      const resolved = resolveProxyPolicy(targetUrl, deps.env);
      if (!resolved.ok) {
        return err({ kind: 'invalid_request', message: resolved.error.message });
      }
      return ok(resolved.value.kind === 'proxy' ? String(resolved.value.url) : undefined);
    };

    const fetchPage: FetchPagePort = async (targetUrl, reqHeaders) => {
      const res = await executeFetch(
        { url: targetUrl, format: 'html', headers: reqHeaders, maxLength: 0 },
        fetchPorts,
        { maxResponseBytes: deps.limits.maxResponseBytes },
      );
      if (!res.ok) {
        const kind = res.error.kind === 'blocked_url' ? 'blocked_url' : 'fetch_error';
        return err({ kind, message: res.error.message });
      }
      return ok(String(res.value));
    };

    const checkHost: CheckHostPort = async (hostname) => {
      const host = normalizeHostname(hostname);
      const lookup = await fetchPorts.dnsLookup(host);
      if (!lookup.ok) {
        return err({ kind: 'blocked_url', message: lookup.error.message });
      }
      const validated = validateResolvedIps(host, lookup.value);
      if (!validated.ok) {
        return err({ kind: 'blocked_url', message: validated.error.message });
      }
      return ok(undefined);
    };

    const result = await executeFetchTranscript(
      {
        url: parsed.data.url,
        ...(parsed.data.headers !== undefined ? { headers: parsed.data.headers } : {}),
        ...(parsed.data.lang !== undefined ? { lang: parsed.data.lang } : {}),
        ...(parsed.data.start_index !== undefined ? { startIndex: parsed.data.start_index } : {}),
        ...(parsed.data.max_length !== undefined ? { maxLength: parsed.data.max_length } : {}),
      },
      { fetchPage, checkHost, resolveProxy: resolveTranscriptProxy, ytDlp: deps.ytDlp },
      { defaultLimit: deps.limits.defaultLimit },
    );

    if (!result.ok) {
      return ok({ content: [{ type: 'text', text: result.error.message }], isError: true });
    }
    return ok({ content: [{ type: 'text', text: String(result.value) }], isError: false });
  }

  const parsed = WebToolArgsSchema.safeParse(rawArgs ?? {});
  if (!parsed.success) {
    return ok({ content: [{ type: 'text', text: formatZodError(parsed.error) }], isError: true });
  }

  const format = WEB_TOOL_FORMAT[name];
  const result = await executeFetch(
    {
      url: parsed.data.url,
      format,
      ...(parsed.data.headers !== undefined ? { headers: parsed.data.headers } : {}),
      ...(parsed.data.start_index !== undefined ? { startIndex: parsed.data.start_index } : {}),
      ...(parsed.data.max_length !== undefined ? { maxLength: parsed.data.max_length } : {}),
    },
    fetchPorts,
    {
      defaultLimit: deps.limits.defaultLimit,
      maxResponseBytes: deps.limits.maxResponseBytes,
    },
  );

  if (!result.ok) {
    return ok({ content: [{ type: 'text', text: result.error.message }], isError: true });
  }
  return ok({ content: [{ type: 'text', text: String(result.value) }], isError: false });
};

/**
 * Creates an MCP 2025-11-25 stdio server advertising only the `tools` capability (D13, D27, D28).
 */
export const createMcpServer = (deps: McpServerDeps): Server => {
  const server = new Server(
    {
      name: 'zcaceres/fetch',
      version: deps.version,
    },
    {
      capabilities: {
        tools: {},
      },
    },
  );

  server.setRequestHandler(ListToolsRequestSchema, async (request) => {
    const listed = listTools(deps.limits.defaultLimit, request.params?.cursor);
    if (!listed.ok) {
      throw new McpError(ErrorCode.InvalidParams, listed.error.message);
    }
    return {
      tools: listed.value.tools.map((tool) => ({
        name: tool.name,
        description: tool.description,
        inputSchema: {
          type: 'object' as const,
          properties: { ...tool.inputSchema.properties },
          required: [...tool.inputSchema.required],
        },
      })),
    };
  });

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const dispatched = await dispatchToolCall(request.params.name, request.params.arguments, deps);
    if (!dispatched.ok) {
      throw new McpError(ErrorCode.InvalidParams, dispatched.error.message);
    }
    return {
      content: [...dispatched.value.content],
      isError: dispatched.value.isError,
    };
  });

  return server;
};
