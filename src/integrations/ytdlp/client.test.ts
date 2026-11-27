import { afterAll, beforeAll, describe, expect, it } from 'bun:test';
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { LanguageCode, YouTubeUrl } from '../../transcript/nouns.ts';
import { createRealYtDlp } from './client.ts';

describe('real yt-dlp client (Slice 03)', () => {
  let fixtureDir: string;

  beforeAll(() => {
    fixtureDir = mkdtempSync(path.join(tmpdir(), 'fetch-mcp-ytdlp-test-'));
  });

  afterAll(() => {
    rmSync(fixtureDir, { recursive: true, force: true });
  });

  const makeScript = (name: string, body: string): string => {
    const filePath = path.join(fixtureDir, name);
    writeFileSync(filePath, `#!/bin/sh\n${body}\n`, 'utf-8');
    chmodSync(filePath, 0o755);
    return filePath;
  };

  it('probes isAvailable() once, caches the result, and returns false for missing binaries (D7)', async () => {
    const countFile = path.join(fixtureDir, 'version-count.txt');
    const stub = makeScript(
      'ytdlp-version.sh',
      `echo x >> "${countFile}"\nif [ "$1" = "--version" ]; then echo "2026.01.01"; exit 0; fi\nexit 1`,
    );

    const client = createRealYtDlp({ binary: stub });
    expect(await client.isAvailable()).toBe(true);
    expect(await client.isAvailable()).toBe(true);
    expect(readFileSync(countFile, 'utf-8').trim().split('\n')).toHaveLength(1);

    const missing = createRealYtDlp({ binary: path.join(fixtureDir, 'does-not-exist-ytdlp') });
    expect(await missing.isAvailable()).toBe(false);
    expect(await missing.isAvailable()).toBe(false);
  });

  it('passes safe argv with -- sentinel, reads matched .srv1 file, and cleans up temp dir (FT-3, D21)', async () => {
    const argsFile = path.join(fixtureDir, 'captured-args.txt');
    const tmpRecordFile = path.join(fixtureDir, 'captured-tmpdir.txt');
    const stub = makeScript(
      'ytdlp-ok.sh',
      `printf '%s\\n' "$@" > "${argsFile}"
OUT=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then
    OUT="$2"
    shift 2
    continue
  fi
  shift
done
dirname "$OUT" > "${tmpRecordFile}"
printf '<transcript><text start="1.5" dur="2.0">Hello from stub</text></transcript>' > "\${OUT}.en-US.srv1"
exit 0`,
    );

    const client = createRealYtDlp({ binary: stub });
    const result = await client.downloadSubtitles(
      YouTubeUrl('https://www.youtube.com/watch?v=demo1'),
      LanguageCode('en'),
    );

    expect(result).toEqual({
      ok: true,
      value: {
        xml: '<transcript><text start="1.5" dur="2.0">Hello from stub</text></transcript>',
        lang: 'en-US',
        langName: 'en-US',
      },
    });

    const recordedTmpDir = readFileSync(tmpRecordFile, 'utf-8').trim();
    expect(recordedTmpDir.length).toBeGreaterThan(0);
    expect(existsSync(recordedTmpDir)).toBe(false);

    const args = readFileSync(argsFile, 'utf-8').trim().split('\n');
    expect(args.slice(0, 8)).toEqual([
      '--write-sub',
      '--write-auto-sub',
      '--sub-lang',
      'en',
      '--sub-format',
      'srv1',
      '--skip-download',
      '-o',
    ]);
    expect(args.slice(-2)).toEqual(['--', 'https://www.youtube.com/watch?v=demo1']);
  });

  it('returns err and cleans up temp dir on non-zero exit or missing .srv1 file (FT-4)', async () => {
    const failTmpFile = path.join(fixtureDir, 'fail-tmpdir.txt');
    const failStub = makeScript(
      'ytdlp-fail.sh',
      `OUT=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then OUT="$2"; shift 2; continue; fi
  shift
done
dirname "$OUT" > "${failTmpFile}"
echo "ERROR: video unavailable" >&2
exit 1`,
    );

    const failClient = createRealYtDlp({ binary: failStub });
    const failRes = await failClient.downloadSubtitles(
      YouTubeUrl('https://www.youtube.com/watch?v=bad'),
      LanguageCode('en'),
    );
    expect(failRes.ok).toBe(false);
    if (!failRes.ok) {
      expect(failRes.error).toContain('yt-dlp failed:');
    }
    expect(existsSync(readFileSync(failTmpFile, 'utf-8').trim())).toBe(false);

    const emptyTmpFile = path.join(fixtureDir, 'empty-tmpdir.txt');
    const emptyStub = makeScript(
      'ytdlp-empty.sh',
      `OUT=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then OUT="$2"; shift 2; continue; fi
  shift
done
dirname "$OUT" > "${emptyTmpFile}"
exit 0`,
    );

    const emptyClient = createRealYtDlp({ binary: emptyStub });
    const emptyRes = await emptyClient.downloadSubtitles(
      YouTubeUrl('https://www.youtube.com/watch?v=nosub'),
      LanguageCode('en'),
    );
    expect(emptyRes).toEqual({ ok: false, error: 'yt-dlp did not produce subtitle files' });
    expect(existsSync(readFileSync(emptyTmpFile, 'utf-8').trim())).toBe(false);
  });

  it('terminates slow subprocesses on timeout and cleans up temp dir (FT-3, D9)', async () => {
    const slowTmpFile = path.join(fixtureDir, 'slow-tmpdir.txt');
    const slowStub = makeScript(
      'ytdlp-slow.sh',
      `OUT=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then OUT="$2"; shift 2; continue; fi
  shift
done
printf '%s' "\${OUT%/*}" > "${slowTmpFile}"
sleep 5`,
    );

    const client = createRealYtDlp({ binary: slowStub, timeoutMs: 350 });
    const res = await client.downloadSubtitles(YouTubeUrl('https://www.youtube.com/watch?v=slow'), LanguageCode('en'));

    expect(res).toEqual({ ok: false, error: 'yt-dlp timed out after 350ms' });
    expect(existsSync(readFileSync(slowTmpFile, 'utf-8').trim())).toBe(false);
  });

  it('rejects .srv1 files exceeding maxBytes and cleans up temp dir (I5)', async () => {
    const bigTmpFile = path.join(fixtureDir, 'big-tmpdir.txt');
    const bigStub = makeScript(
      'ytdlp-big.sh',
      `OUT=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then OUT="$2"; shift 2; continue; fi
  shift
done
dirname "$OUT" > "${bigTmpFile}"
printf '<transcript><text start="0">%0100d</text></transcript>' 0 > "\${OUT}.en.srv1"
exit 0`,
    );

    const client = createRealYtDlp({ binary: bigStub, maxBytes: 50 });
    const res = await client.downloadSubtitles(YouTubeUrl('https://www.youtube.com/watch?v=big'), LanguageCode('en'));

    expect(res).toEqual({ ok: false, error: 'yt-dlp subtitle file exceeded 50 byte limit' });
    expect(existsSync(readFileSync(bigTmpFile, 'utf-8').trim())).toBe(false);
  });

  it('prefers exact case-insensitive lang match over regional prefix when multiple .srv1 files exist (FT-6, D20)', async () => {
    const stub = makeScript(
      'ytdlp-multi.sh',
      `OUT=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then OUT="$2"; shift 2; continue; fi
  shift
done
printf '<transcript><text start="0">EXACT</text></transcript>' > "\${OUT}.en.srv1"
printf '<transcript><text start="0">REGIONAL</text></transcript>' > "\${OUT}.en-US.srv1"
printf '<transcript><text start="0">OTHER</text></transcript>' > "\${OUT}.de.srv1"
exit 0`,
    );

    const client = createRealYtDlp({ binary: stub });
    const exactRes = await client.downloadSubtitles(
      YouTubeUrl('https://www.youtube.com/watch?v=multi'),
      LanguageCode('EN'),
    );
    expect(exactRes).toEqual({
      ok: true,
      value: {
        xml: '<transcript><text start="0">EXACT</text></transcript>',
        lang: 'en',
        langName: 'en',
      },
    });
  });
});
