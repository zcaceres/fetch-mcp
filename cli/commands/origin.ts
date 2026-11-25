import { err, ok } from '../../src/shared/result.ts';
import type { Command } from '../command.ts';

const USAGE =
  'usage: origin serve <url> <status> <body...> | origin redirect <url> <status> <location> | origin fail <url> <reason...> | origin last-headers <url>';

export const originCommand: Command = {
  kind: 'world',
  usage:
    'origin serve <url> <status> <body...> | origin redirect <url> <status> <location> | origin fail <url> <reason...> | origin last-headers <url>',
  summary: 'configure and inspect mocked Remote Origin Server responses and failures',
  run: async (args, world) => {
    const [action, url, ...rest] = args;
    if (action === 'serve') {
      const [statusStr, ...bodyParts] = rest;
      if (!url || !statusStr) {
        return err('usage: origin serve <url> <status> <body...>');
      }
      const status = Number(statusStr);
      if (!Number.isInteger(status) || status < 100 || status > 599) {
        return err(`Invalid HTTP status: "${statusStr}"`);
      }
      world.origin.serve(url, status, bodyParts.join(' '));
      return ok([`origin: ${status} ${url}`]);
    }

    if (action === 'redirect') {
      const [statusStr, location] = rest;
      if (!url || !statusStr || !location) {
        return err('usage: origin redirect <url> <status> <location>');
      }
      const status = Number(statusStr);
      if (!Number.isInteger(status) || status < 300 || status > 399) {
        return err(`Invalid redirect status: "${statusStr}"`);
      }
      world.origin.redirect(url, status, location);
      return ok([`origin: redirect ${status} ${url} -> ${location}`]);
    }

    if (action === 'fail') {
      if (!url || rest.length === 0) {
        return err('usage: origin fail <url> <reason...>');
      }
      world.origin.fail(url, rest.join(' '));
      return ok([`origin: fail ${url}`]);
    }

    if (action === 'last-headers') {
      if (!url) {
        return err('usage: origin last-headers <url>');
      }
      const headers = world.origin.lastHeaders(url);
      if (headers === undefined) {
        return ok(['(not requested)']);
      }
      const entries = Object.entries(headers).sort(([a], [b]) => a.localeCompare(b));
      if (entries.length === 0) {
        return ok(['(no headers)']);
      }
      return ok(entries.map(([key, value]) => `header: ${key}: ${value}`));
    }

    return err(USAGE);
  },
};
