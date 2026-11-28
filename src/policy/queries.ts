const PORT_REGEX = /^\d+$/;

const normalizeHostname = (hostname: string): string => {
  const bare = hostname.startsWith('[') && hostname.endsWith(']') ? hostname.slice(1, -1) : hostname;
  return bare.toLowerCase().replace(/\.+$/, '');
};

const canonicalizeIpv6 = (rawIpv6: string): string | null => {
  try {
    return normalizeHostname(new URL(`http://[${rawIpv6}]/`).hostname);
  } catch {
    return null;
  }
};

const getEffectivePort = (url: URL): string => {
  if (url.port) return url.port;
  return url.protocol === 'https:' ? '443' : '80';
};

/**
 * Returns true if `targetUrl` matches any comma-separated entry in `noProxy` (`*`, exact host,
 * `.domain`/subdomain suffix, optional `:port`, and `[ipv6]:port` with canonical IPv6 matching) (D24).
 */
export const isNoProxyMatch = (targetUrl: URL, noProxy: string | undefined): boolean => {
  if (!noProxy) return false;
  const host = normalizeHostname(targetUrl.hostname);
  const port = getEffectivePort(targetUrl);

  for (const rawEntry of noProxy.split(',')) {
    const entry = rawEntry.trim().toLowerCase();
    if (!entry) continue;
    if (entry === '*') return true;

    let entryHost = entry;
    let entryPort: string | undefined;
    let isIpv6Entry = false;

    if (entry.startsWith('[')) {
      const closing = entry.indexOf(']');
      if (closing === -1) continue;
      const remainder = entry.slice(closing + 1);
      if (remainder.length > 0) {
        if (!remainder.startsWith(':')) continue;
        entryPort = remainder.slice(1);
        if (!PORT_REGEX.test(entryPort)) continue;
      }
      const canonical = canonicalizeIpv6(entry.slice(1, closing));
      if (canonical === null) continue;
      entryHost = canonical;
      isIpv6Entry = true;
    } else {
      const firstColon = entry.indexOf(':');
      const lastColon = entry.lastIndexOf(':');
      if (firstColon !== -1 && firstColon === lastColon) {
        entryHost = entry.slice(0, lastColon);
        entryPort = entry.slice(lastColon + 1);
        if (!PORT_REGEX.test(entryPort)) continue;
      } else if (firstColon !== -1) {
        const canonical = canonicalizeIpv6(entry);
        if (canonical === null) continue;
        entryHost = canonical;
        isIpv6Entry = true;
      }
    }

    if (entryPort !== undefined && entryPort !== port) {
      continue;
    }

    if (isIpv6Entry) {
      if (host === entryHost) return true;
      continue;
    }

    const pattern = entryHost.replace(/^\.+/, '').replace(/\.+$/, '');
    if (!pattern) continue;

    if (host === pattern || host.endsWith(`.${pattern}`)) {
      return true;
    }
  }

  return false;
};

/**
 * Removes username/password credentials from valid and malformed proxy URL strings so secrets never appear
 * in errors or logs (D31, I7).
 */
export const redactProxyUrl = (proxyUrl: string): string => {
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(proxyUrl)) {
    try {
      const parsed = new URL(proxyUrl);
      if (parsed.username || parsed.password) {
        parsed.username = '';
        parsed.password = '';
      }
      return parsed.href;
    } catch {
      // Fall through to regex redaction for malformed scheme-prefixed URLs
    }
  }
  return proxyUrl.replace(
    /^([a-zA-Z][a-zA-Z0-9+.-]*:\/\/)?[\s\S]*@/,
    (_match, scheme: string | undefined) => `${scheme ?? ''}<redacted>@`,
  );
};
