import { afterAll, beforeAll, describe, expect, it } from 'bun:test';
import http from 'node:http';
import net from 'node:net';
import { executeFetch } from '../../fetching/execute.ts';
import { TargetUrl } from '../../fetching/nouns.ts';
import { err, ok } from '../../shared/result.ts';
import { createRealHttpGet } from './client.ts';
import { buildProxyAuthHeader, openHttpConnectTunnel } from './proxy.ts';

const openSockets = new Set<net.Socket>();

const trackSocket = (socket: net.Socket): void => {
  openSockets.add(socket);
  socket.once('close', () => openSockets.delete(socket));
};

const listenHttp = (handler: http.RequestListener): Promise<{ server: http.Server; port: number }> =>
  new Promise((resolve, reject) => {
    const server = http.createServer(handler);
    server.on('connection', trackSocket);
    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      if (!addr || typeof addr === 'string') {
        reject(new Error('Expected TCP address'));
        return;
      }
      resolve({ server, port: addr.port });
    });
  });

const listenTcp = (onSocket: (socket: net.Socket) => void): Promise<{ server: net.Server; port: number }> =>
  new Promise((resolve, reject) => {
    const server = net.createServer((socket) => {
      trackSocket(socket);
      onSocket(socket);
    });
    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      if (!addr || typeof addr === 'string') {
        reject(new Error('Expected TCP address'));
        return;
      }
      resolve({ server, port: addr.port });
    });
  });

const closeServer = (server: net.Server): Promise<void> =>
  new Promise((resolve) => {
    server.close(() => resolve());
  });

describe('real proxy transport (Slice 02, PL-9)', () => {
  const servers: net.Server[] = [];
  let targetPort = 0;

  beforeAll(async () => {
    const target = await listenHttp((req, res) => {
      if (req.url === '/big') {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('x'.repeat(250));
        return;
      }
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(`<p>target:${req.url}</p>`);
    });
    servers.push(target.server);
    targetPort = target.port;
  });

  afterAll(async () => {
    for (const socket of openSockets) {
      socket.destroy();
    }
    openSockets.clear();
    await Promise.all(servers.map(closeServer));
  });

  it('forwards HTTP targets via HTTP proxy with Proxy-Authorization and enforces maxBytes (D5, I5)', async () => {
    let seenUrl: string | undefined;
    let seenAuth: string | undefined;
    let seenHost: string | undefined;

    const proxy = await listenHttp((req, res) => {
      seenUrl = req.url;
      seenAuth = req.headers['proxy-authorization'];
      seenHost = req.headers.host;
      if (req.url?.endsWith('/big')) {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('a'.repeat(250));
        return;
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ via: 'http-proxy' }));
    });
    servers.push(proxy.server);

    const httpGet = createRealHttpGet({ maxBytes: 100, timeoutMs: 2000 });
    const proxyUrl = `http://alice:s3cr3t@127.0.0.1:${proxy.port}/`;
    const okRes = await httpGet(TargetUrl('http://unresolvable.invalid/page'), {}, [], proxyUrl);

    expect(okRes.ok).toBe(true);
    if (okRes.ok) {
      expect(okRes.value.status).toBe(200);
      expect(new TextDecoder().decode(okRes.value.rawBytes)).toBe('{"via":"http-proxy"}');
    }
    expect(seenUrl).toBe('http://unresolvable.invalid/page');
    expect(seenHost).toBe('unresolvable.invalid');
    expect(seenAuth).toBe(`Basic ${Buffer.from('alice:s3cr3t').toString('base64')}`);

    const tooBig = await httpGet(TargetUrl('http://unresolvable.invalid/big'), {}, [], proxyUrl);
    expect(tooBig).toEqual({
      ok: false,
      error: { kind: 'response_too_large', message: 'Response too large: exceeded 100 byte limit' },
    });
  });

  it('opens HTTP CONNECT tunnels with Proxy-Authorization and redacts credentials on non-200 failure (D5, D14)', async () => {
    let seenRequest = '';
    const connectOk = await listenTcp((socket) => {
      let buf = Buffer.alloc(0);
      const onData = (chunk: Buffer) => {
        buf = Buffer.concat([buf, chunk]);
        const end = buf.indexOf('\r\n\r\n');
        if (end === -1) return;
        socket.off('data', onData);
        seenRequest = buf.subarray(0, end).toString('latin1');
        socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        socket.on('data', (payload: Buffer) => {
          if (payload.toString('utf-8') === 'ping') {
            socket.write('pong');
          }
        });
      };
      socket.on('data', onData);
    });
    servers.push(connectOk.server);

    const tunnel = await openHttpConnectTunnel(
      new URL(`http://bob:p4ss@127.0.0.1:${connectOk.port}`),
      new URL('https://unresolvable.invalid:8443/path'),
      2000,
    );
    expect(tunnel.ok).toBe(true);
    if (tunnel.ok) {
      const reply = await new Promise<string>((resolve) => {
        tunnel.value.once('data', (chunk: Buffer) => resolve(chunk.toString('utf-8')));
        tunnel.value.write('ping');
      });
      tunnel.value.destroy();
      expect(reply).toBe('pong');
    }
    expect(seenRequest).toContain('CONNECT unresolvable.invalid:8443 HTTP/1.1');
    expect(seenRequest).toContain(`Proxy-Authorization: Basic ${Buffer.from('bob:p4ss').toString('base64')}`);

    const connectDeny = await listenTcp((socket) => {
      socket.once('data', () => {
        socket.end('HTTP/1.1 407 Proxy Authentication Required\r\n\r\n');
      });
    });
    servers.push(connectDeny.server);

    const httpGet = createRealHttpGet({ timeoutMs: 2000 });
    const denied = await httpGet(
      TargetUrl('https://unresolvable.invalid/secret'),
      {},
      [],
      `http://bob:topsecret@127.0.0.1:${connectDeny.port}/`,
    );
    expect(denied.ok).toBe(false);
    if (!denied.ok) {
      expect(denied.error.kind).toBe('network_error');
      expect(denied.error.message).toContain(`via proxy http://127.0.0.1:${connectDeny.port}/`);
      expect(denied.error.message).toContain('407');
      expect(denied.error.message).not.toContain('topsecret');
    }
  });

  it('tunnels HTTP through SOCKS5 and SOCKS5h with ATYP 0x03 remote hostname delegation and optional RFC 1929 auth (D23)', async () => {
    const observedDomains: string[] = [];

    const createSocks5Server = (requiredCreds?: readonly [string, string]) =>
      listenTcp((client) => {
        let stage: 'greeting' | 'auth' | 'request' = 'greeting';
        let buf = Buffer.alloc(0);

        const onData = (chunk: Buffer) => {
          buf = Buffer.concat([buf, chunk]);

          if (stage === 'greeting') {
            if (buf.length < 2) return;
            const nmethods = buf[1] ?? 0;
            if (buf.length < 2 + nmethods) return;
            const methods = [...buf.subarray(2, 2 + nmethods)];
            buf = buf.subarray(2 + nmethods);

            if (requiredCreds) {
              if (!methods.includes(0x02)) {
                client.end(Buffer.from([0x05, 0xff]));
                return;
              }
              client.write(Buffer.from([0x05, 0x02]));
              stage = 'auth';
            } else {
              client.write(Buffer.from([0x05, 0x00]));
              stage = 'request';
            }
          }

          if (stage === 'auth') {
            if (buf.length < 2) return;
            const ulen = buf[1] ?? 0;
            if (buf.length < 2 + ulen + 1) return;
            const plen = buf[2 + ulen] ?? 0;
            if (buf.length < 3 + ulen + plen) return;
            const user = buf.subarray(2, 2 + ulen).toString('utf-8');
            const pass = buf.subarray(3 + ulen, 3 + ulen + plen).toString('utf-8');
            buf = buf.subarray(3 + ulen + plen);

            if (!requiredCreds || user !== requiredCreds[0] || pass !== requiredCreds[1]) {
              client.end(Buffer.from([0x01, 0x01]));
              return;
            }
            client.write(Buffer.from([0x01, 0x00]));
            stage = 'request';
          }

          if (stage === 'request') {
            if (buf.length < 5) return;
            const atyp = buf[3];
            if (atyp !== 0x03) {
              client.end(Buffer.from([0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
              return;
            }
            const dlen = buf[4] ?? 0;
            if (buf.length < 5 + dlen + 2) return;
            const domain = buf.subarray(5, 5 + dlen).toString('utf-8');
            const remainder = buf.subarray(5 + dlen + 2);
            observedDomains.push(domain);
            client.off('data', onData);

            const upstream = net.connect({ host: '127.0.0.1', port: targetPort }, () => {
              client.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0]));
              if (remainder.length > 0) upstream.write(remainder);
              client.pipe(upstream);
              upstream.pipe(client);
            });
            upstream.on('error', () => client.destroy());
          }
        };

        client.on('data', onData);
      });

    const socksNoAuth = await createSocks5Server();
    const socksAuth = await createSocks5Server(['alice', 's3cr3t']);
    servers.push(socksNoAuth.server, socksAuth.server);

    const httpGet = createRealHttpGet({ timeoutMs: 2000 });
    const res5 = await httpGet(
      TargetUrl('http://socks5-remote.invalid/s5'),
      {},
      [],
      `socks5://127.0.0.1:${socksNoAuth.port}`,
    );
    expect(res5.ok).toBe(true);
    if (res5.ok) {
      expect(new TextDecoder().decode(res5.value.rawBytes)).toBe('<p>target:/s5</p>');
    }

    const res5h = await httpGet(
      TargetUrl('http://socks5h-remote.invalid/s5h'),
      {},
      [],
      `socks5h://alice:s3cr3t@127.0.0.1:${socksAuth.port}`,
    );
    expect(res5h.ok).toBe(true);
    if (res5h.ok) {
      expect(new TextDecoder().decode(res5h.value.rawBytes)).toBe('<p>target:/s5h</p>');
    }

    expect(observedDomains).toEqual(['socks5-remote.invalid', 'socks5h-remote.invalid']);

    const badAuth = await httpGet(
      TargetUrl('http://socks5h-remote.invalid/denied'),
      {},
      [],
      `socks5://alice:wrongpass@127.0.0.1:${socksAuth.port}`,
    );
    expect(badAuth.ok).toBe(false);
    if (!badAuth.ok) {
      expect(badAuth.error.kind).toBe('network_error');
      expect(badAuth.error.message).toContain(`via proxy socks5://127.0.0.1:${socksAuth.port}`);
      expect(badAuth.error.message).not.toContain('wrongpass');
    }
  });

  it('tunnels HTTP through SOCKS4 and SOCKS4a using 0.0.0.1 + domain name extension (D23)', async () => {
    const seen: Array<{ readonly userid: string; readonly domain: string }> = [];

    const socks4 = await listenTcp((client) => {
      let buf = Buffer.alloc(0);
      const onData = (chunk: Buffer) => {
        buf = Buffer.concat([buf, chunk]);
        if (buf.length < 9) return;
        const userEnd = buf.indexOf(0x00, 8);
        if (userEnd === -1) return;
        const is4a = buf[4] === 0 && buf[5] === 0 && buf[6] === 0 && (buf[7] ?? 0) !== 0;
        if (!is4a) {
          client.end(Buffer.from([0x00, 0x5b, 0, 0, 0, 0, 0, 0]));
          return;
        }
        const domainEnd = buf.indexOf(0x00, userEnd + 1);
        if (domainEnd === -1) return;

        const userid = buf.subarray(8, userEnd).toString('utf-8');
        const domain = buf.subarray(userEnd + 1, domainEnd).toString('utf-8');
        const remainder = buf.subarray(domainEnd + 1);
        seen.push({ userid, domain });
        client.off('data', onData);

        const upstream = net.connect({ host: '127.0.0.1', port: targetPort }, () => {
          client.write(Buffer.from([0x00, 0x5a, 0, 0, 0, 0, 0, 0]));
          if (remainder.length > 0) upstream.write(remainder);
          client.pipe(upstream);
          upstream.pipe(client);
        });
        upstream.on('error', () => client.destroy());
      };
      client.on('data', onData);
    });
    servers.push(socks4.server);

    const httpGet = createRealHttpGet({ timeoutMs: 2000 });
    const res4 = await httpGet(
      TargetUrl('http://socks4-remote.invalid/s4'),
      {},
      [],
      `socks4://bob@127.0.0.1:${socks4.port}`,
    );
    expect(res4.ok).toBe(true);
    if (res4.ok) {
      expect(new TextDecoder().decode(res4.value.rawBytes)).toBe('<p>target:/s4</p>');
    }

    const res4a = await httpGet(
      TargetUrl('http://socks4a-remote.invalid/s4a'),
      {},
      [],
      `socks4a://127.0.0.1:${socks4.port}`,
    );
    expect(res4a.ok).toBe(true);
    if (res4a.ok) {
      expect(new TextDecoder().decode(res4a.value.rawBytes)).toBe('<p>target:/s4a</p>');
    }

    expect(seen).toEqual([
      { userid: 'bob', domain: 'socks4-remote.invalid' },
      { userid: '', domain: 'socks4a-remote.invalid' },
    ]);
  });

  it('aborts hanging proxy connections on timeout and blocks private Target URLs locally via executeFetch (D8, D9, I1)', async () => {
    let proxyHits = 0;
    const hangingProxy = await listenTcp((socket) => {
      proxyHits++;
      socket.on('error', () => {});
    });
    servers.push(hangingProxy.server);

    const httpGet = createRealHttpGet({ timeoutMs: 90 });
    const timedOut = await httpGet(
      TargetUrl('http://slow.invalid/hang'),
      {},
      [],
      `socks5://127.0.0.1:${hangingProxy.port}`,
    );
    expect(timedOut).toEqual({
      ok: false,
      error: { kind: 'timeout', message: 'Request timed out after 90ms fetching http://slow.invalid/hang' },
    });

    const beforeSsrf = proxyHits;
    const blocked = await executeFetch(
      { url: 'http://127.0.0.1/secret', format: 'html' },
      {
        httpGet,
        dnsLookup: async () => err({ kind: 'blocked_url', message: 'should not be called' }),
        resolveProxy: () => ok(`socks5://127.0.0.1:${hangingProxy.port}`),
      },
    );
    expect(blocked).toEqual({
      ok: false,
      error: { kind: 'blocked_url', message: 'Blocked Target URL: private address "127.0.0.1"' },
    });
    expect(proxyHits).toBe(beforeSsrf);
  });

  it('handles unencoded literal % in proxy credentials without throwing URIError (PL-9, D14)', () => {
    const auth = buildProxyAuthHeader(new URL('http://user:100%pass@127.0.0.1:8080'));
    expect(auth).toBe(`Basic ${Buffer.from('user:100%pass').toString('base64')}`);
  });
});
