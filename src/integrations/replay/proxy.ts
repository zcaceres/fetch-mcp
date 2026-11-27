import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import type net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import tls from 'node:tls';
import type { Cassette, CassetteExchange } from '../../verification/nouns.ts';

export type RunningReplayProxy = {
  readonly proxyUrl: string;
  readonly port: number;
  readonly caCertPath: string;
  readonly close: () => Promise<void>;
};

type HostCert = {
  readonly key: string;
  readonly cert: string;
};

const HOP_BY_HOP_HEADERS = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
]);

const normalizeUrlKey = (rawUrl: string): string => {
  try {
    return new URL(rawUrl).href;
  } catch {
    return rawUrl;
  }
};

const createEphemeralCa = () => {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'fetch-mcp-replay-ca-'));
  const caKeyPath = path.join(dir, 'ca.key');
  const caCertPath = path.join(dir, 'ca.pem');
  const caExtPath = path.join(dir, 'ca.cnf');

  writeFileSync(
    caExtPath,
    [
      '[req]',
      'distinguished_name = dn',
      'x509_extensions = v3_ca',
      'prompt = no',
      '[dn]',
      'CN = Fetch MCP Replay Root CA',
      '[v3_ca]',
      'basicConstraints = critical,CA:TRUE',
      'keyUsage = critical,keyCertSign,cRLSign',
    ].join('\n'),
  );

  execFileSync(
    'openssl',
    [
      'req',
      '-x509',
      '-newkey',
      'rsa:2048',
      '-nodes',
      '-keyout',
      caKeyPath,
      '-out',
      caCertPath,
      '-days',
      '1',
      '-config',
      caExtPath,
    ],
    { stdio: 'ignore' },
  );

  const certCache = new Map<string, HostCert>();
  let serial = 1;

  const issueHostCert = (hostname: string): HostCert => {
    const cached = certCache.get(hostname);
    if (cached) return cached;

    const id = serial++;
    const keyPath = path.join(dir, `leaf-${id}.key`);
    const csrPath = path.join(dir, `leaf-${id}.csr`);
    const certPath = path.join(dir, `leaf-${id}.pem`);
    const extPath = path.join(dir, `leaf-${id}.ext`);
    const sanEntry =
      hostname.includes(':') || /^\d+\.\d+\.\d+\.\d+$/.test(hostname) ? `IP:${hostname}` : `DNS:${hostname}`;

    writeFileSync(
      extPath,
      ['basicConstraints=CA:FALSE', 'keyUsage=digitalSignature,keyEncipherment', `subjectAltName=${sanEntry}`].join(
        '\n',
      ),
    );

    execFileSync(
      'openssl',
      ['req', '-newkey', 'rsa:2048', '-nodes', '-keyout', keyPath, '-out', csrPath, '-subj', `/CN=${hostname}`],
      { stdio: 'ignore' },
    );

    execFileSync(
      'openssl',
      [
        'x509',
        '-req',
        '-in',
        csrPath,
        '-CA',
        caCertPath,
        '-CAkey',
        caKeyPath,
        '-CAcreateserial',
        '-out',
        certPath,
        '-days',
        '1',
        '-extfile',
        extPath,
      ],
      { stdio: 'ignore' },
    );

    const issued: HostCert = {
      key: readFileSync(keyPath, 'utf-8'),
      cert: readFileSync(certPath, 'utf-8'),
    };
    certCache.set(hostname, issued);
    return issued;
  };

  return {
    caCertPath,
    issueHostCert,
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
};

const writeExchangeResponse = (
  res: http.ServerResponse,
  exchange: CassetteExchange | undefined,
  reqUrl: string,
): void => {
  if (!exchange) {
    res.writeHead(502, { 'content-type': 'text/plain' });
    res.end(`Replay cassette missing exchange for ${reqUrl}`);
    return;
  }

  const outHeaders: Record<string, string> = {};
  for (const [key, value] of Object.entries(exchange.headers)) {
    const lower = key.toLowerCase();
    if (HOP_BY_HOP_HEADERS.has(lower) || lower === 'content-length') continue;
    outHeaders[lower] = value;
  }

  const body = Buffer.from(exchange.bodyBase64, 'base64');
  outHeaders['content-length'] = String(body.byteLength);
  res.writeHead(exchange.status, outHeaders);
  res.end(body);
};

/**
 * Starts a local HTTP and HTTPS `CONNECT` replay proxy on `127.0.0.1:<ephemeral>` backed by an ephemeral
 * Root CA (`NODE_EXTRA_CA_CERTS`). Unmodified `dist/` binaries route public URLs through Operator
 * `HTTP_PROXY`/`HTTPS_PROXY` so `I1`–`I7` remain 100% active during offline cassette replay (D34).
 */
export const startReplayProxy = (cassettes: readonly Cassette[]): Promise<RunningReplayProxy> =>
  new Promise((resolve, reject) => {
    const exchangeMap = new Map<string, CassetteExchange>();
    for (const cassette of cassettes) {
      for (const exchange of cassette.exchanges) {
        exchangeMap.set(normalizeUrlKey(exchange.url), exchange);
      }
    }

    const ca = createEphemeralCa();
    const activeSockets = new Set<net.Socket>();

    const server = http.createServer((req, res) => {
      const targetUrl = req.url ?? '';
      const exchange = exchangeMap.get(normalizeUrlKey(targetUrl));
      writeExchangeResponse(res, exchange, targetUrl);
    });

    server.on('connect', (req, clientSocket: net.Socket, head: Buffer) => {
      clientSocket.on('error', () => {
        clientSocket.destroy();
      });

      const authority = req.url ?? '';
      const lastColon = authority.lastIndexOf(':');
      const rawHost = lastColon !== -1 ? authority.slice(0, lastColon) : authority;
      const portNum = lastColon !== -1 ? Number.parseInt(authority.slice(lastColon + 1), 10) : 443;
      const hostname = rawHost.startsWith('[') && rawHost.endsWith(']') ? rawHost.slice(1, -1) : rawHost;

      let hostCert: HostCert;
      try {
        hostCert = ca.issueHostCert(hostname);
      } catch {
        clientSocket.write('HTTP/1.1 500 Internal Server Error\r\n\r\n');
        clientSocket.destroy();
        return;
      }

      clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');

      const tlsSocket = new tls.TLSSocket(clientSocket, {
        isServer: true,
        key: hostCert.key,
        cert: hostCert.cert,
      });
      activeSockets.add(tlsSocket);
      tlsSocket.on('close', () => activeSockets.delete(tlsSocket));
      tlsSocket.on('error', () => {
        tlsSocket.destroy();
      });

      const innerHttp = http.createServer((innerReq, innerRes) => {
        const displayHost = hostname.includes(':') ? `[${hostname}]` : hostname;
        const portSuffix = portNum === 443 ? '' : `:${portNum}`;
        const fullUrl = `https://${displayHost}${portSuffix}${innerReq.url ?? '/'}`;
        const exchange = exchangeMap.get(normalizeUrlKey(fullUrl));
        writeExchangeResponse(innerRes, exchange, fullUrl);
      });

      innerHttp.emit('connection', tlsSocket);
      if (head.length > 0) {
        tlsSocket.unshift(head);
      }
    });

    server.on('error', (error) => {
      ca.cleanup();
      reject(error);
    });

    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      const port = typeof addr === 'object' && addr !== null ? addr.port : 0;
      resolve({
        proxyUrl: `http://127.0.0.1:${port}`,
        port,
        caCertPath: ca.caCertPath,
        close: () =>
          new Promise<void>((resolveClose) => {
            for (const s of activeSockets) {
              s.destroy();
            }
            server.close(() => {
              ca.cleanup();
              resolveClose();
            });
          }),
      });
    });
  });
