import { readdir, readFile, stat, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { createInterface } from 'node:readline/promises';
import { parse, passed, render, report, run } from './scenario.ts';
import { createSession } from './session.ts';

const [mode, ...rest] = process.argv.slice(2);

/** A file, or every `.txt` file under a folder. */
const scenarioFiles = async (targetPath: string): Promise<string[]> => {
  if (!(await stat(targetPath)).isDirectory()) return [targetPath];
  const entries = await readdir(targetPath, { recursive: true });
  return entries
    .filter((entry) => entry.endsWith('.txt'))
    .sort()
    .map((entry) => join(targetPath, entry));
};

if (mode === 'run') {
  const write = rest.includes('--write');
  const paths = rest.filter((arg) => arg !== '--write');
  if (paths.length === 0) {
    console.error('usage: harness run <scenario file or folder>... [--write]');
    process.exit(2);
  }
  const files = (await Promise.all(paths.map(scenarioFiles))).flat();
  const failed: string[] = [];
  for (const file of files) {
    const ran = await run(parse(await readFile(file, 'utf8')), createSession());
    console.log(`── ${file}`);
    console.log(report(ran));
    if (passed(ran)) continue;
    if (write) {
      await writeFile(file, render(ran));
      console.log(`── wrote what it prints now to ${file}`);
    } else {
      failed.push(file);
    }
  }
  console.log(failed.length === 0 ? `── ${files.length} passed` : `── failed: ${failed.join(', ')}`);
  process.exit(failed.length === 0 ? 0 : 1);
} else {
  console.log('The harness: every external system is mocked in memory and resets on exit. Type help for commands.');
  const session = createSession();
  const rl = createInterface({ input: process.stdin, output: process.stdout, prompt: '> ' });
  rl.prompt();
  for await (const line of rl) {
    if (line.trim() === 'exit') break;
    for (const out of await session.exec(line)) console.log(out);
    rl.prompt();
  }
  rl.close();
}
