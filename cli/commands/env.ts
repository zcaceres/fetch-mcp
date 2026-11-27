import { err, ok } from '../../src/shared/result.ts';
import type { Command } from '../command.ts';

const USAGE = 'usage: env set <KEY> <VALUE...> | env unset <KEY> | env clear';

export const envCommand: Command = {
  kind: 'world',
  usage: USAGE,
  summary: 'configure mocked Operator environment variables (proxy and limits)',
  run: async (args, world) => {
    const [action, key, ...valueParts] = args;

    if (action === 'set') {
      if (!key || valueParts.length === 0) {
        return err('usage: env set <KEY> <VALUE...>');
      }
      const value = valueParts.join(' ');
      world.env.set(key, value);
      return ok([`env: ${key}=${value}`]);
    }

    if (action === 'unset') {
      if (!key) {
        return err('usage: env unset <KEY>');
      }
      world.env.delete(key);
      return ok([`env: unset ${key}`]);
    }

    if (action === 'clear') {
      world.env.clear();
      return ok(['env: cleared']);
    }

    return err(USAGE);
  },
};
