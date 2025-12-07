// src/deps/index.ts
// Dependency injection container for testing

import dns from "dns/promises";

export interface FetcherDependencies {
  fetch: typeof globalThis.fetch;
  dnsResolve4: typeof dns.resolve4;
  dnsResolve6: typeof dns.resolve6;
}

/**
 * Dependency container for injection during tests
 * Allows mocking of fetch and DNS resolution
 */
class DependencyContainer {
  private deps: FetcherDependencies = {
    fetch: globalThis.fetch,
    dnsResolve4: dns.resolve4.bind(dns),
    dnsResolve6: dns.resolve6.bind(dns),
  };

  get(): FetcherDependencies {
    return this.deps;
  }

  set(dependencies: Partial<FetcherDependencies>): void {
    this.deps = { ...this.deps, ...dependencies };
  }

  reset(): void {
    this.deps = {
      fetch: globalThis.fetch,
      dnsResolve4: dns.resolve4.bind(dns),
      dnsResolve6: dns.resolve6.bind(dns),
    };
  }
}

export const dependencies = new DependencyContainer();
