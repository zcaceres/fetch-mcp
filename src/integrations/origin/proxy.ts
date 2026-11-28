import net from 'node:net';
import tls from 'node:tls';
import { normalizeHostname } from '../../fetching/queries.ts';
import { err, ok, type Result } from '../../shared/result.ts';

const MAX_CONNECT_HEADER_BYTES = 16 * 1024;
const DEFAULT_SOCKS_PORT = 1080;

export type TunnelError = {
  readonly kind: 'timeout' | 'proxy_error';
  readonly message: string;
};

const getProxyPort = (proxyUrl: URL): number => {
  if (proxyUrl.port) return Number(proxyUrl.port);
  if (proxyUrl.protocol === 'https:') return 443;
  if (proxyUrl.protocol === 'http:') return 80;
  return DEFAULT_SOCKS_PORT;
};

const getTargetPort = (targetUrl: URL): number => {
  if (targetUrl.port) return Number(targetUrl.port);
  return targetUrl.protocol === 'https:' ? 443 : 80;
};

const safeDecodeComponent = (value: string): string => {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
};

export const buildProxyAuthHeader = (proxyUrl: URL): string | undefined => {
  if (!proxyUrl.username && !proxyUrl.password) return undefined;
  const creds = `${safeDecodeComponent(proxyUrl.username)}:${safeDecodeComponent(proxyUrl.password)}`;
  return `Basic ${Buffer.from(creds).toString('base64')}`;
};

const parseIpv6ToBytes = (ip: string): Uint8Array | null => {
  const parts = ip.split('::');
  if (parts.length > 2) return null;
  const left = parts[0] ? parts[0].split(':') : [];
  const right = parts.length === 2 && parts[1] ? parts[1].split(':') : [];
  const missing = 8 - (left.length + right.length);
  if (missing < 0 || (parts.length === 1 && missing !== 0)) return null;
  const groups = [...left, ...Array<string>(missing).fill('0'), ...right];
  if (groups.length !== 8) return null;

  const bytes = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    const val = Number.parseInt(groups[i] ?? '', 16);
    if (Number.isNaN(val) || val < 0 || val > 0xffff) return null;
    bytes[i * 2] = (val >> 8) & 0xff;
    bytes[i * 2 + 1] = val & 0xff;
  }
  return bytes;
};

/**
 * Opens an HTTP/HTTPS proxy `CONNECT` tunnel to `targetUrl` (D5, D9).
 */
export const openHttpConnectTunnel = (
  proxyUrl: URL,
  targetUrl: URL,
  timeoutMs: number,
): Promise<Result<net.Socket, TunnelError>> =>
  new Promise((resolve) => {
    const proxyHost = normalizeHostname(proxyUrl.hostname);
    const proxyPort = getProxyPort(proxyUrl);
    const targetHost = normalizeHostname(targetUrl.hostname);
    const targetPort = getTargetPort(targetUrl);
    const authority = targetHost.includes(':') ? `[${targetHost}]:${targetPort}` : `${targetHost}:${targetPort}`;

    const rawSocket: net.Socket =
      proxyUrl.protocol === 'https:'
        ? tls.connect({ host: proxyHost, port: proxyPort, servername: net.isIP(proxyHost) ? undefined : proxyHost })
        : net.connect({ host: proxyHost, port: proxyPort });

    let settled = false;
    let headerBuf = Buffer.alloc(0);

    const cleanup = (): void => {
      rawSocket.off('data', onData);
      rawSocket.off('error', onError);
      rawSocket.off('end', onEnd);
      rawSocket.setTimeout(0);
    };

    const fail = (kind: TunnelError['kind'], message: string): void => {
      if (settled) return;
      settled = true;
      cleanup();
      rawSocket.destroy();
      resolve(err({ kind, message }));
    };

    const onError = (error: Error): void => fail('proxy_error', error.message);
    const onEnd = (): void => fail('proxy_error', 'Proxy closed connection during CONNECT handshake');

    const onConnect = (): void => {
      const proxyAuth = buildProxyAuthHeader(proxyUrl);
      const lines = [`CONNECT ${authority} HTTP/1.1`, `Host: ${authority}`];
      if (proxyAuth) {
        lines.push(`Proxy-Authorization: ${proxyAuth}`);
      }
      lines.push('', '');
      rawSocket.write(lines.join('\r\n'));
    };

    const onData = (chunk: Buffer): void => {
      headerBuf = Buffer.concat([headerBuf, chunk]);
      const headerEnd = headerBuf.indexOf('\r\n\r\n');
      if (headerEnd === -1) {
        if (headerBuf.length > MAX_CONNECT_HEADER_BYTES) {
          fail('proxy_error', 'Proxy CONNECT response headers too large');
        }
        return;
      }

      const headerText = headerBuf.subarray(0, headerEnd).toString('latin1');
      const statusLine = headerText.split('\r\n')[0] ?? '';
      const statusMatch = /^HTTP\/\d+\.\d+\s+(\d{3})/.exec(statusLine);
      const statusCode = statusMatch ? Number(statusMatch[1]) : 0;

      if (statusCode !== 200) {
        fail('proxy_error', `Proxy CONNECT failed: ${statusLine || 'invalid response'}`);
        return;
      }

      cleanup();
      const remainder = headerBuf.subarray(headerEnd + 4);
      if (remainder.length > 0) {
        rawSocket.unshift(remainder);
      }

      settled = true;
      resolve(ok(rawSocket));
    };

    rawSocket.setTimeout(timeoutMs, () => fail('timeout', `Request timed out after ${timeoutMs}ms`));
    rawSocket.on('error', onError);
    rawSocket.on('data', onData);
    rawSocket.once('end', onEnd);

    if (proxyUrl.protocol === 'https:') {
      rawSocket.once('secureConnect', onConnect);
    } else {
      rawSocket.once('connect', onConnect);
    }
  });

/**
 * Opens a SOCKS4 / SOCKS4a tunnel to `targetUrl`, using SOCKS4a domain extension (`0.0.0.1` + hostname)
 * for hostnames per D8 and D23.
 */
export const openSocks4Tunnel = (
  proxyUrl: URL,
  targetUrl: URL,
  timeoutMs: number,
): Promise<Result<net.Socket, TunnelError>> =>
  new Promise((resolve) => {
    const proxyHost = normalizeHostname(proxyUrl.hostname);
    const proxyPort = getProxyPort(proxyUrl);
    const targetHost = normalizeHostname(targetUrl.hostname);
    const targetPort = getTargetPort(targetUrl);

    if (net.isIPv6(targetHost)) {
      resolve(err({ kind: 'proxy_error', message: 'SOCKS4 does not support IPv6 targets' }));
      return;
    }

    const useridBytes = Buffer.from(safeDecodeComponent(proxyUrl.username), 'utf-8');
    let packet: Buffer;
    if (net.isIPv4(targetHost)) {
      const octets = targetHost.split('.').map((part) => Number.parseInt(part, 10));
      packet = Buffer.concat([
        Buffer.from([0x04, 0x01, (targetPort >> 8) & 0xff, targetPort & 0xff, ...octets]),
        useridBytes,
        Buffer.from([0x00]),
      ]);
    } else {
      const hostBytes = Buffer.from(targetHost, 'utf-8');
      packet = Buffer.concat([
        Buffer.from([0x04, 0x01, (targetPort >> 8) & 0xff, targetPort & 0xff, 0x00, 0x00, 0x00, 0x01]),
        useridBytes,
        Buffer.from([0x00]),
        hostBytes,
        Buffer.from([0x00]),
      ]);
    }

    const socket = net.connect({ host: proxyHost, port: proxyPort });
    let settled = false;
    let buf = Buffer.alloc(0);

    const cleanup = (): void => {
      socket.off('data', onData);
      socket.off('error', onError);
      socket.off('end', onEnd);
      socket.setTimeout(0);
    };

    const fail = (kind: TunnelError['kind'], message: string): void => {
      if (settled) return;
      settled = true;
      cleanup();
      socket.destroy();
      resolve(err({ kind, message }));
    };

    const onError = (error: Error): void => fail('proxy_error', error.message);
    const onEnd = (): void => fail('proxy_error', 'SOCKS4 proxy closed connection during handshake');

    const onData = (chunk: Buffer): void => {
      buf = Buffer.concat([buf, chunk]);
      if (buf.length < 8) return;

      const replyCode = buf[1];
      if (replyCode !== 0x5a) {
        fail('proxy_error', `SOCKS4 request rejected (code 0x${(replyCode ?? 0).toString(16)})`);
        return;
      }

      cleanup();
      const remainder = buf.subarray(8);
      if (remainder.length > 0) {
        socket.unshift(remainder);
      }
      settled = true;
      resolve(ok(socket));
    };

    socket.setTimeout(timeoutMs, () => fail('timeout', `Request timed out after ${timeoutMs}ms`));
    socket.on('error', onError);
    socket.on('data', onData);
    socket.once('end', onEnd);
    socket.once('connect', () => socket.write(packet));
  });

/**
 * Opens a SOCKS5 / SOCKS5h tunnel (RFC 1928 + RFC 1929 optional auth), always sending ATYP `0x03`
 * domain name for hostnames so DNS resolution is delegated to the proxy per D8 and D23.
 */
export const openSocks5Tunnel = (
  proxyUrl: URL,
  targetUrl: URL,
  timeoutMs: number,
): Promise<Result<net.Socket, TunnelError>> =>
  new Promise((resolve) => {
    const proxyHost = normalizeHostname(proxyUrl.hostname);
    const proxyPort = getProxyPort(proxyUrl);
    const targetHost = normalizeHostname(targetUrl.hostname);
    const targetPort = getTargetPort(targetUrl);

    const hasCreds = Boolean(proxyUrl.username || proxyUrl.password);
    const userBytes = Buffer.from(safeDecodeComponent(proxyUrl.username), 'utf-8');
    const passBytes = Buffer.from(safeDecodeComponent(proxyUrl.password), 'utf-8');
    if (hasCreds && (userBytes.length > 255 || passBytes.length > 255)) {
      resolve(err({ kind: 'proxy_error', message: 'SOCKS5 credentials exceed 255-byte limit' }));
      return;
    }

    let addrSection: Buffer;
    if (net.isIPv4(targetHost)) {
      const octets = targetHost.split('.').map((part) => Number.parseInt(part, 10));
      addrSection = Buffer.from([0x01, ...octets]);
    } else if (net.isIPv6(targetHost)) {
      const ipv6Bytes = parseIpv6ToBytes(targetHost);
      if (!ipv6Bytes) {
        resolve(err({ kind: 'proxy_error', message: `Invalid IPv6 target address "${targetHost}"` }));
        return;
      }
      addrSection = Buffer.concat([Buffer.from([0x04]), Buffer.from(ipv6Bytes)]);
    } else {
      const hostBytes = Buffer.from(targetHost, 'utf-8');
      if (hostBytes.length > 255) {
        resolve(err({ kind: 'proxy_error', message: 'Target hostname exceeds SOCKS5 255-byte limit' }));
        return;
      }
      addrSection = Buffer.concat([Buffer.from([0x03, hostBytes.length]), hostBytes]);
    }

    const connectReq = Buffer.concat([
      Buffer.from([0x05, 0x01, 0x00]),
      addrSection,
      Buffer.from([(targetPort >> 8) & 0xff, targetPort & 0xff]),
    ]);

    const socket = net.connect({ host: proxyHost, port: proxyPort });
    let settled = false;
    let stage: 'greeting' | 'auth' | 'connect' = 'greeting';
    let buf = Buffer.alloc(0);

    const cleanup = (): void => {
      socket.off('data', onData);
      socket.off('error', onError);
      socket.off('end', onEnd);
      socket.setTimeout(0);
    };

    const fail = (kind: TunnelError['kind'], message: string): void => {
      if (settled) return;
      settled = true;
      cleanup();
      socket.destroy();
      resolve(err({ kind, message }));
    };

    const onError = (error: Error): void => fail('proxy_error', error.message);
    const onEnd = (): void => fail('proxy_error', 'SOCKS5 proxy closed connection during handshake');

    const onData = (chunk: Buffer): void => {
      buf = Buffer.concat([buf, chunk]);

      if (stage === 'greeting') {
        if (buf.length < 2) return;
        const ver = buf[0];
        const method = buf[1];
        buf = buf.subarray(2);

        if (ver !== 0x05) {
          fail('proxy_error', `Unexpected SOCKS version 0x${(ver ?? 0).toString(16)}`);
          return;
        }
        if (method === 0x00) {
          stage = 'connect';
          socket.write(connectReq);
        } else if (method === 0x02 && hasCreds) {
          stage = 'auth';
          socket.write(
            Buffer.concat([
              Buffer.from([0x01, userBytes.length]),
              userBytes,
              Buffer.from([passBytes.length]),
              passBytes,
            ]),
          );
        } else {
          fail('proxy_error', 'SOCKS5 proxy rejected authentication method');
          return;
        }
      }

      if (stage === 'auth') {
        if (buf.length < 2) return;
        const status = buf[1];
        buf = buf.subarray(2);
        if (status !== 0x00) {
          fail('proxy_error', 'SOCKS5 authentication failed');
          return;
        }
        stage = 'connect';
        socket.write(connectReq);
      }

      if (stage === 'connect') {
        if (buf.length < 4) return;
        if (buf[0] !== 0x05) {
          fail('proxy_error', 'Invalid SOCKS5 connect response');
          return;
        }
        const rep = buf[1];
        if (rep !== 0x00) {
          fail('proxy_error', `SOCKS5 connect failed (code 0x${(rep ?? 0).toString(16)})`);
          return;
        }

        const atyp = buf[3];
        let totalLen: number;
        if (atyp === 0x01) {
          totalLen = 4 + 4 + 2;
        } else if (atyp === 0x04) {
          totalLen = 4 + 16 + 2;
        } else if (atyp === 0x03) {
          if (buf.length < 5) return;
          totalLen = 5 + (buf[4] ?? 0) + 2;
        } else {
          fail('proxy_error', `Unsupported SOCKS5 reply ATYP 0x${(atyp ?? 0).toString(16)}`);
          return;
        }

        if (buf.length < totalLen) return;
        cleanup();
        const remainder = buf.subarray(totalLen);
        if (remainder.length > 0) {
          socket.unshift(remainder);
        }
        settled = true;
        resolve(ok(socket));
      }
    };

    socket.setTimeout(timeoutMs, () => fail('timeout', `Request timed out after ${timeoutMs}ms`));
    socket.on('error', onError);
    socket.on('data', onData);
    socket.once('end', onEnd);
    socket.once('connect', () => {
      const greeting = hasCreds ? Buffer.from([0x05, 0x02, 0x00, 0x02]) : Buffer.from([0x05, 0x01, 0x00]);
      socket.write(greeting);
    });
  });

/**
 * Upgrades an established tunnel socket to TLS for `https:` targets, setting SNI for hostnames.
 */
export const wrapTlsOverTunnel = (
  socket: net.Socket,
  targetUrl: URL,
  timeoutMs: number,
): Promise<Result<tls.TLSSocket, TunnelError>> =>
  new Promise((resolve) => {
    const targetHost = normalizeHostname(targetUrl.hostname);
    const tlsSocket = tls.connect({
      socket,
      host: targetHost,
      servername: net.isIP(targetHost) ? undefined : targetHost,
    });

    let settled = false;

    const cleanup = (): void => {
      tlsSocket.off('error', onError);
      tlsSocket.setTimeout(0);
    };

    const fail = (kind: TunnelError['kind'], message: string): void => {
      if (settled) return;
      settled = true;
      cleanup();
      tlsSocket.destroy();
      resolve(err({ kind, message }));
    };

    const onError = (error: Error): void => fail('proxy_error', error.message);

    tlsSocket.setTimeout(timeoutMs, () => fail('timeout', `Request timed out after ${timeoutMs}ms`));
    tlsSocket.once('error', onError);
    tlsSocket.once('secureConnect', () => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve(ok(tlsSocket));
    });
  });
