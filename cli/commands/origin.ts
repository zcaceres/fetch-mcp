import { redactProxyUrl } from '../../src/policy/queries.ts';
import { err, ok } from '../../src/shared/result.ts';
import type { Command } from '../command.ts';

const USAGE =
  'usage: origin serve|header|compress|repeat|corrupt|redirect|fail|timeout|last-headers|last-pinned|last-proxy|attempts <url> ...';

export const originCommand: Command = {
  kind: 'world',
  usage: USAGE,
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

    if (action === 'header') {
      const [name, ...valueParts] = rest;
      if (!url || !name || valueParts.length === 0) {
        return err('usage: origin header <url> <name> <value...>');
      }
      const value = valueParts.join(' ');
      const updated = world.origin.header(url, name, value);
      if (!updated.ok) return updated;
      return ok([`origin: header ${url} ${name}: ${value}`]);
    }

    if (action === 'compress') {
      const [encoding, ...bodyParts] = rest;
      if (!url || !encoding) {
        return err('usage: origin compress <url> <encoding> <body...>');
      }
      world.origin.compress(url, encoding, bodyParts.join(' '));
      return ok([`origin: compress ${encoding} ${url}`]);
    }

    if (action === 'repeat') {
      const [countStr, encoding] = rest;
      if (!url || !countStr) {
        return err('usage: origin repeat <url> <count> [encoding]');
      }
      const count = Number(countStr);
      if (!Number.isInteger(count) || count < 0) {
        return err(`Invalid repeat count: "${countStr}"`);
      }
      world.origin.repeat(url, count, encoding);
      return ok([`origin: repeat ${count} ${url}`]);
    }

    if (action === 'corrupt') {
      const [encoding] = rest;
      if (!url || !encoding) {
        return err('usage: origin corrupt <url> <encoding>');
      }
      world.origin.corrupt(url, encoding);
      return ok([`origin: corrupt ${encoding} ${url}`]);
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

    if (action === 'timeout') {
      if (!url) {
        return err('usage: origin timeout <url>');
      }
      world.origin.timeout(url);
      return ok([`origin: timeout ${url}`]);
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

    if (action === 'last-pinned') {
      if (!url) {
        return err('usage: origin last-pinned <url>');
      }
      const pinned = world.origin.lastPinned(url);
      if (pinned === undefined) {
        return ok(['(not requested)']);
      }
      return ok([`pinned: ${pinned.join(', ')}`]);
    }

    if (action === 'last-proxy') {
      if (!url) {
        return err('usage: origin last-proxy <url>');
      }
      const proxy = world.origin.lastProxy(url);
      if (proxy === undefined) {
        return ok(['(not requested)']);
      }
      if (proxy === null) {
        return ok(['proxy: direct']);
      }
      return ok([`proxy: ${redactProxyUrl(proxy)}`]);
    }

    if (action === 'attempts') {
      if (!url) {
        return err('usage: origin attempts <url>');
      }
      return ok([`attempts: ${world.origin.attempts(url)}`]);
    }

    return err(USAGE);
  },
};
