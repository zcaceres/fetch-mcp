import { err, ok } from '../../src/shared/result.ts';
import type { Command } from '../command.ts';

export const dnsCommand: Command = {
  kind: 'world',
  usage: 'dns set <host> <ip...> | dns empty <host> | dns fail <host> <reason...>',
  summary: 'configure mocked DNS Resolver records and failures',
  run: async (args, world) => {
    const [action, host, ...rest] = args;
    if (action === 'set') {
      if (!host || rest.length === 0) {
        return err('usage: dns set <host> <ip...>');
      }
      world.dns.set(host, rest);
      return ok([`dns: ${host} -> ${rest.join(', ')}`]);
    }

    if (action === 'empty') {
      if (!host) {
        return err('usage: dns empty <host>');
      }
      world.dns.empty(host);
      return ok([`dns: ${host} -> (empty)`]);
    }

    if (action === 'fail') {
      if (!host || rest.length === 0) {
        return err('usage: dns fail <host> <reason...>');
      }
      world.dns.fail(host, rest.join(' '));
      return ok([`dns: fail ${host}`]);
    }

    return err('usage: dns set <host> <ip...> | dns empty <host> | dns fail <host> <reason...>');
  },
};
