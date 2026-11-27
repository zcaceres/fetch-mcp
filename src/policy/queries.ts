const normalizeHostname = (hostname: string): string => {
  const bare = hostname.startsWith('[') && hostname.endsWith(']') ? hostname.slice(1, -1) : hostname;
  return bare.toLowerCase().replace(/\.+$/, '');
};

const getEffectivePort = (url: URL): string => {
  if (url.port) return url.port;
  return url.protocol === 'https:' ? '443' : '80';
};

/**
 * Returns true if `targetUrl` matches any comma-separated entry in `noProxy` (`*`, exact host,
 * `.domain`/subdomain suffix, optional `:port`, and `[ipv6]:port`) (D24).
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

    if (entry.startsWith('[')) {
      const closing = entry.indexOf(']');
      if (closing !== -1) {
        entryHost = entry.slice(1, closing);
        if (entry[closing + 1] === ':') {
          entryPort = entry.slice(closing + 2);
        }
      }
    } else {
      const lastColon = entry.lastIndexOf(':');
      if (lastColon !== -1 && entry.indexOf(':') === lastColon) {
        entryHost = entry.slice(0, lastColon);
        entryPort = entry.slice(lastColon + 1);
      }
    }

    if (entryPort && entryPort !== port) {
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
 * Removes username/password credentials from a proxy URL string so secrets never appear in errors or logs.
 */
export const redactProxyUrl = (proxyUrl: string): string => {
  try {
    const parsed = new URL(proxyUrl);
    if (parsed.username || parsed.password) {
      parsed.username = '';
      parsed.password = '';
    }
    return parsed.href;
  } catch {
    return proxyUrl.replace(/([a-zA-Z][a-zA-Z0-9+.-]*:\/\/)[^/@]*@/g, '$1<redacted>@');
  }
};
