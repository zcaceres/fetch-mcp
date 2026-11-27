import { err, ok } from '../../src/shared/result.ts';
import type { Command } from '../command.ts';

const USAGE =
  'usage: ytdlp available <true|false> | ytdlp serve <url> <lang> <xml...> | ytdlp empty <url> | ytdlp fail <url> <reason...> | ytdlp timeout <url> | ytdlp last-args';

export const ytdlpCommand: Command = {
  kind: 'world',
  usage: USAGE,
  summary: 'configure and inspect mocked yt-dlp CLI availability, responses, and argv',
  run: async (args, world) => {
    const [action, ...rest] = args;

    if (action === 'available') {
      const flag = rest[0];
      if (flag !== 'true' && flag !== 'false') {
        return err('usage: ytdlp available <true|false>');
      }
      world.ytdlp.setAvailable(flag === 'true');
      return ok([`ytdlp: available ${flag}`]);
    }

    if (action === 'serve') {
      const [url, lang, ...xmlParts] = rest;
      if (!url || !lang || xmlParts.length === 0) {
        return err('usage: ytdlp serve <url> <lang> <xml...>');
      }
      world.ytdlp.serve(url, lang, xmlParts.join(' '));
      return ok([`ytdlp: serve ${lang} ${url}`]);
    }

    if (action === 'empty') {
      const [url] = rest;
      if (!url) {
        return err('usage: ytdlp empty <url>');
      }
      world.ytdlp.empty(url);
      return ok([`ytdlp: empty ${url}`]);
    }

    if (action === 'fail') {
      const [url, ...reasonParts] = rest;
      if (!url || reasonParts.length === 0) {
        return err('usage: ytdlp fail <url> <reason...>');
      }
      world.ytdlp.fail(url, reasonParts.join(' '));
      return ok([`ytdlp: fail ${url}`]);
    }

    if (action === 'timeout') {
      const [url] = rest;
      if (!url) {
        return err('usage: ytdlp timeout <url>');
      }
      world.ytdlp.timeout(url);
      return ok([`ytdlp: timeout ${url}`]);
    }

    if (action === 'last-args') {
      const recorded = world.ytdlp.lastArgs();
      if (!recorded) {
        return ok(['(not invoked)']);
      }
      return ok([`args: ${recorded.join(' ')}`]);
    }

    return err(USAGE);
  },
};
