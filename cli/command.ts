import type { Result } from '../src/shared/result.ts';
import type { World } from './world.ts';

/**
 * A harness command.
 *
 * - A **domain** command runs a context's verb or query under Terminology's name.
 * - A **world** command drives an external system's in-memory mock.
 *
 * `run` returns lines to print, or an error printed by the session as `error: ...`.
 * Output must contain no blank lines and no line starting with `#` or `>`.
 */
export type Command = {
  readonly kind: 'domain' | 'world';
  readonly usage: string;
  readonly summary: string;
  readonly run: (args: readonly string[], world: World) => Promise<Result<readonly string[], string>>;
};
