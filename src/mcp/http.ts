import http from 'node:http';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { z } from 'zod';
import { err, ok, type Result } from '../shared/result.ts';
import { createMcpServer, dispatchToolCall, listTools, type McpServerDeps } from './server.ts';

export const DEFAULT_HTTP_HOST = '127.0.0.1';
export const DEFAULT_HTTP_PORT = 3000;
export const MCP_HTTP_ENDPOINT = '/mcp';

export type ServerMode =
  | { readonly kind: 'stdio' }
  | { readonly kind: 'http'; readonly host: string; readonly port: number };

export type HttpGuardError = {
  readonly status: 403;
  readonly message: string;
};

export type StreamableHttpRequest = {
  readonly method: string;
  readonly path: string;
  readonly headers: Readonly<Record<string, string | undefined>>;
  readonly body?: string;
};

export type StreamableHttpResponse = {
  readonly status: number;
  readonly contentType: string;
  readonly body: string;
};

export type StreamableHttpHandlerDeps = McpServerDeps & {
  readonly boundHost: string;
  readonly boundPort: number;
};

const PORT_DIGITS_REGEX = /^\d+$/;

const normalizeHost = (hostname: string): string => {
  const bare = hostname.startsWith('[') && hostname.endsWith(']') ? hostname.slice(1, -1) : hostname;
  const lowered = bare.toLowerCase().replace(/\.+$/, '');
  if (lowered.includes(':')) {
    try {
      const canonical = new URL(`http://[${lowered}]/`).hostname;
      return canonical.startsWith('[') && canonical.endsWith(']') ? canonical.slice(1, -1) : canonical;
    } catch {
      return lowered;
    }
  }
  return lowered;
};

const isLoopbackHost = (hostname: string): boolean => {
  const normalized = normalizeHost(hostname);
  return normalized === '127.0.0.1' || normalized === 'localhost' || normalized === '::1';
};

const findHeader = (headers: Readonly<Record<string, string | undefined>>, target: string): string | undefined => {
  const lower = target.toLowerCase();
  let found: string | undefined;
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === lower) {
      found = value;
    }
  }
  return found;
};

/**
 * Parses `mcp-fetch-server` startup arguments (`stdio` by default, or `--http [--host <addr>] [--port <n>]`) (D32).
 */
export const parseServerArgs = (argv: readonly string[]): Result<ServerMode, string> => {
  let httpMode = false;
  let host: string | undefined;
  let port: number | undefined;

  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    if (flag === '--http') {
      httpMode = true;
    } else if (flag === '--host') {
      const value = argv[i + 1];
      if (value === undefined || value.startsWith('--') || value.trim().length === 0) {
        return err('--host requires a value');
      }
      const trimmed = value.trim();
      const unbracketed = trimmed.startsWith('[') && trimmed.endsWith(']') ? trimmed.slice(1, -1).trim() : trimmed;
      if (unbracketed.length === 0) {
        return err('--host requires a value');
      }
      host = unbracketed;
      i++;
    } else if (flag === '--port') {
      const value = argv[i + 1];
      const parsed = value !== undefined && PORT_DIGITS_REGEX.test(value) ? Number.parseInt(value, 10) : Number.NaN;
      if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > 65535) {
        return err(`Invalid --port "${value ?? ''}": must be an integer between 1 and 65535`);
      }
      port = parsed;
      i++;
    } else {
      return err(`Unknown flag: ${flag ?? ''}`);
    }
  }

  if (!httpMode) {
    if (host !== undefined) return err('--host requires --http');
    if (port !== undefined) return err('--port requires --http');
    return ok({ kind: 'stdio' });
  }

  return ok({
    kind: 'http',
    host: host ?? DEFAULT_HTTP_HOST,
    port: port ?? DEFAULT_HTTP_PORT,
  });
};

/**
 * Validates HTTP `Host` and `Origin` headers against the bound address to prevent DNS rebinding against
 * localhost Streamable HTTP MCP endpoints (D32).
 */
export const validateHttpOriginAndHost = (
  headers: Readonly<Record<string, string | undefined>>,
  boundHost: string,
  boundPort: number,
): Result<void, HttpGuardError> => {
  const boundLoopback = isLoopbackHost(boundHost);
  const expectedPort = String(boundPort);

  const rawHost = findHeader(headers, 'host')?.trim();
  if (!rawHost || /[\s@/?#]/.test(rawHost)) {
    return err({ status: 403, message: `Forbidden Host header: "${rawHost ?? ''}"` });
  }

  let parsedHostUrl: URL;
  try {
    parsedHostUrl = new URL(`http://${rawHost}`);
  } catch {
    return err({ status: 403, message: `Forbidden Host header: "${rawHost}"` });
  }

  if (
    parsedHostUrl.username !== '' ||
    parsedHostUrl.password !== '' ||
    parsedHostUrl.pathname !== '/' ||
    parsedHostUrl.search !== '' ||
    parsedHostUrl.hash !== ''
  ) {
    return err({ status: 403, message: `Forbidden Host header: "${rawHost}"` });
  }

  const hostName = normalizeHost(parsedHostUrl.hostname);
  const hostPort = parsedHostUrl.port || '80';
  const hostMatches = boundLoopback ? isLoopbackHost(hostName) : hostName === normalizeHost(boundHost);
  if (!hostMatches || hostPort !== expectedPort) {
    return err({ status: 403, message: `Forbidden Host header: "${rawHost}"` });
  }

  const originHeader = findHeader(headers, 'origin');
  if (originHeader !== undefined) {
    const rawOrigin = originHeader.trim();
    if (rawOrigin.length === 0 || rawOrigin.endsWith('/')) {
      return err({ status: 403, message: `Forbidden Origin header: "${rawOrigin}"` });
    }
    let parsedOrigin: URL;
    try {
      parsedOrigin = new URL(rawOrigin);
    } catch {
      return err({ status: 403, message: `Forbidden Origin header: "${rawOrigin}"` });
    }
    if (
      (parsedOrigin.protocol !== 'http:' && parsedOrigin.protocol !== 'https:') ||
      parsedOrigin.username !== '' ||
      parsedOrigin.password !== '' ||
      parsedOrigin.pathname !== '/' ||
      parsedOrigin.search !== '' ||
      parsedOrigin.hash !== ''
    ) {
      return err({ status: 403, message: `Forbidden Origin header: "${rawOrigin}"` });
    }
    const originHost = normalizeHost(parsedOrigin.hostname);
    const originMatches = boundLoopback ? isLoopbackHost(originHost) : originHost === normalizeHost(boundHost);
    if (!originMatches) {
      return err({ status: 403, message: `Forbidden Origin header: "${rawOrigin}"` });
    }
  }

  return ok(undefined);
};

const JsonRpcRequestSchema = z.object({
  jsonrpc: z.literal('2.0'),
  id: z.union([z.string(), z.number(), z.null()]).optional(),
  method: z.string().min(1),
  params: z.record(z.string(), z.unknown()).optional(),
});

/**
 * Pure stateless Streamable HTTP request handler for `/mcp` used by the harness and unit tests (D3, D32).
 * Delegates tool listing and execution directly to `src/mcp/server.ts`.
 */
export const handleStreamableHttpRequest = async (
  req: StreamableHttpRequest,
  deps: StreamableHttpHandlerDeps,
): Promise<StreamableHttpResponse> => {
  const pathname = req.path.split('?', 1)[0] ?? req.path;
  if (pathname !== MCP_HTTP_ENDPOINT) {
    return { status: 404, contentType: 'text/plain', body: 'Not Found' };
  }

  const guard = validateHttpOriginAndHost(req.headers, deps.boundHost, deps.boundPort);
  if (!guard.ok) {
    return { status: guard.error.status, contentType: 'text/plain', body: guard.error.message };
  }

  if (req.method.toUpperCase() !== 'POST') {
    return { status: 405, contentType: 'text/plain', body: 'Method Not Allowed' };
  }

  let rawJson: unknown;
  try {
    rawJson = JSON.parse(req.body ?? '');
  } catch {
    return { status: 400, contentType: 'text/plain', body: 'Invalid JSON body' };
  }

  const parsedRpc = JsonRpcRequestSchema.safeParse(rawJson);
  if (!parsedRpc.success) {
    return {
      status: 400,
      contentType: 'application/json',
      body: JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Invalid Request' } }),
    };
  }

  const { id, method, params } = parsedRpc.data;

  if (id === undefined && method.startsWith('notifications/')) {
    return { status: 202, contentType: 'text/plain', body: '' };
  }

  if (method === 'initialize') {
    return {
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: id ?? null,
        result: {
          protocolVersion: '2025-11-25',
          capabilities: { tools: {} },
          serverInfo: { name: 'zcaceres/fetch', version: deps.version },
        },
      }),
    };
  }

  if (method === 'tools/list') {
    const rawCursor = params?.cursor;
    if (rawCursor !== undefined && typeof rawCursor !== 'string') {
      return {
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: id ?? null,
          error: { code: -32603, message: 'Invalid cursor type' },
        }),
      };
    }

    const listed = listTools(deps.limits.defaultLimit, rawCursor);
    if (!listed.ok) {
      return {
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: id ?? null,
          error: { code: listed.error.code, message: listed.error.message },
        }),
      };
    }

    return {
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: id ?? null,
        result: { tools: listed.value.tools },
      }),
    };
  }

  if (method === 'tools/call') {
    const toolName = params?.name;
    if (typeof toolName !== 'string') {
      return {
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: id ?? null,
          error: { code: -32602, message: 'Missing tool name' },
        }),
      };
    }

    const rawArgs = params?.arguments;
    if (rawArgs !== undefined && (typeof rawArgs !== 'object' || rawArgs === null || Array.isArray(rawArgs))) {
      return {
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: id ?? null,
          error: { code: -32603, message: 'Invalid arguments type' },
        }),
      };
    }

    const dispatched = await dispatchToolCall(toolName, rawArgs, deps);
    if (!dispatched.ok) {
      return {
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: id ?? null,
          error: { code: dispatched.error.code, message: dispatched.error.message },
        }),
      };
    }

    return {
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: id ?? null,
        result: dispatched.value,
      }),
    };
  }

  return {
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: id ?? null,
      error: { code: -32601, message: 'Method not found' },
    }),
  };
};

export type RunningHttpMcpServer = {
  readonly host: string;
  readonly port: number;
  readonly url: string;
  readonly close: () => Promise<void>;
};

const flattenIncomingHeaders = (headers: http.IncomingHttpHeaders): Readonly<Record<string, string | undefined>> => {
  const flat: Record<string, string | undefined> = {};
  for (const [key, value] of Object.entries(headers)) {
    if (Array.isArray(value)) {
      flat[key] = value.join(', ');
    } else {
      flat[key] = value;
    }
  }
  return flat;
};

/**
 * Starts a real Node HTTP server exposing MCP 2025-11-25 Streamable HTTP statelessly on `/mcp`
 * with `Host`/`Origin` DNS-rebinding guards (D3, D32).
 */
export const startStreamableHttpServer = (
  deps: McpServerDeps,
  host: string = DEFAULT_HTTP_HOST,
  port: number = DEFAULT_HTTP_PORT,
): Promise<RunningHttpMcpServer> =>
  new Promise((resolve, reject) => {
    let actualPort = port;

    const httpServer = http.createServer((req, res) => {
      const rawUrl = req.url ?? '/';
      const pathname = rawUrl.split('?', 1)[0] ?? '/';
      if (pathname !== MCP_HTTP_ENDPOINT) {
        res.writeHead(404, { 'content-type': 'text/plain' });
        res.end('Not Found');
        return;
      }

      const guard = validateHttpOriginAndHost(flattenIncomingHeaders(req.headers), host, actualPort);
      if (!guard.ok) {
        res.writeHead(guard.error.status, { 'content-type': 'text/plain' });
        res.end(guard.error.message);
        return;
      }

      if ((req.method ?? '').toUpperCase() !== 'POST') {
        res.writeHead(405, { 'content-type': 'text/plain', allow: 'POST' });
        res.end('Method Not Allowed');
        return;
      }

      const mcpServer = createMcpServer(deps);
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: undefined,
        enableJsonResponse: true,
      });

      res.on('close', () => {
        void transport.close();
        void mcpServer.close();
      });

      void (async () => {
        try {
          await mcpServer.connect(transport);
          await transport.handleRequest(req, res);
        } catch (error: unknown) {
          if (!res.headersSent) {
            const detail = error instanceof Error ? error.message : String(error);
            res.writeHead(500, { 'content-type': 'application/json' });
            res.end(
              JSON.stringify({
                jsonrpc: '2.0',
                id: null,
                error: { code: -32603, message: `Internal error: ${detail}` },
              }),
            );
          }
        }
      })();
    });

    httpServer.on('error', reject);
    httpServer.listen(port, host, () => {
      const addr = httpServer.address();
      if (typeof addr === 'object' && addr !== null) {
        actualPort = addr.port;
      }
      const displayHost = host.includes(':') ? `[${host}]` : host;
      resolve({
        host,
        port: actualPort,
        url: `http://${displayHost}:${actualPort}${MCP_HTTP_ENDPOINT}`,
        close: () =>
          new Promise<void>((resolveClose) => {
            httpServer.close(() => resolveClose());
          }),
      });
    });
  });
