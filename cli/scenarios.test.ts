import { describe, expect, it } from 'bun:test';
import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { parse, passed, report, run } from './scenario.ts';
import { createSession } from './session.ts';

const SCENARIOS_DIR = join(import.meta.dir, '..', 'scenarios');

const entries = await readdir(SCENARIOS_DIR, { recursive: true });
const files = entries
  .filter((entry) => entry.endsWith('.txt'))
  .sort()
  .map((entry) => join(SCENARIOS_DIR, entry));

describe('scenarios', () => {
  for (const file of files) {
    it(file.replace(`${SCENARIOS_DIR}/`, ''), async () => {
      const content = await readFile(file, 'utf8');
      const ran = await run(parse(content), createSession());
      if (!passed(ran)) {
        throw new Error(`Scenario mismatch in ${file}:\n\n${report(ran)}`);
      }
      expect(passed(ran)).toBe(true);
    });
  }
});
