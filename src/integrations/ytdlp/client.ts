import { type ExecFileException, execFile } from 'node:child_process';
import { mkdtemp, readdir, readFile, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { err, ok, type Result } from '../../shared/result.ts';
import type { LanguageCode, TargetUrl } from '../../transcript/nouns.ts';
import type { YtDlpPort, YtDlpResult } from '../../transcript/ports.ts';
import { buildYtDlpArgs } from '../../transcript/queries.ts';

export const DEFAULT_YTDLP_TIMEOUT_MS = 30_000;
export const DEFAULT_YTDLP_MAX_BYTES = 10 * 1024 * 1024;
const PROBE_TIMEOUT_MS = 5_000;

const PROXY_ENV_KEYS = [
  'HTTP_PROXY',
  'HTTPS_PROXY',
  'ALL_PROXY',
  'NO_PROXY',
  'http_proxy',
  'https_proxy',
  'all_proxy',
  'no_proxy',
] as const;

const buildSanitizedChildEnv = (): NodeJS.ProcessEnv => {
  const env: NodeJS.ProcessEnv = { ...process.env };
  for (const key of PROXY_ENV_KEYS) {
    delete env[key];
  }
  return env;
};

export type RealYtDlpOptions = {
  readonly binary?: string;
  readonly timeoutMs?: number;
  readonly maxBytes?: number;
  readonly proxy?: string;
};

const isTimedOutError = (error: ExecFileException): boolean => error.killed === true || error.code === 'ETIMEDOUT';

const runExecFile = (
  binary: string,
  args: readonly string[],
  timeoutMs: number,
): Promise<Result<void, { readonly timedOut: boolean; readonly message: string }>> =>
  new Promise((resolve) => {
    execFile(
      binary,
      [...args],
      { timeout: timeoutMs, maxBuffer: 1024 * 1024, env: buildSanitizedChildEnv() },
      (error, _stdout, stderr) => {
        if (!error) {
          resolve(ok(undefined));
          return;
        }
        if (isTimedOutError(error)) {
          resolve(err({ timedOut: true, message: `yt-dlp timed out after ${timeoutMs}ms` }));
          return;
        }
        const detail = stderr.trim() || error.message;
        resolve(err({ timedOut: false, message: `yt-dlp failed: ${detail}` }));
      },
    );
  });

const extractFileLang = (filename: string): string | undefined => /\.([^.]+)\.srv1$/.exec(filename)?.[1];

const selectSubtitleFile = (
  files: readonly string[],
  lang: LanguageCode,
): { readonly file: string; readonly matchedLang: string } | undefined => {
  const candidates = [...files].sort().map((file) => ({ file, fileLang: extractFileLang(file) }));
  const target = lang.toLowerCase();

  const exact = candidates.find((c) => c.fileLang?.toLowerCase() === target);
  if (exact?.fileLang) return { file: exact.file, matchedLang: exact.fileLang };

  const prefix = candidates.find((c) => c.fileLang?.toLowerCase().startsWith(`${target}-`));
  if (prefix?.fileLang) return { file: prefix.file, matchedLang: prefix.fileLang };

  const unlabeled = candidates.find((c) => c.fileLang === undefined);
  if (unlabeled) return { file: unlabeled.file, matchedLang: lang };

  return undefined;
};

/**
 * Creates a real async `YtDlpPort` backed by `node:child_process` `execFile` (no shell).
 * Enforces `--write-sub`, `--write-auto-sub`, `--` sentinel (D21), `30s` timeout (D9),
 * `MAX_RESPONSE_BYTES` file cap (I5), and guaranteed temp-dir cleanup.
 */
export const createRealYtDlp = (options: RealYtDlpOptions = {}): YtDlpPort => {
  const binary = options.binary ?? 'yt-dlp';
  const timeoutMs = options.timeoutMs ?? DEFAULT_YTDLP_TIMEOUT_MS;
  const maxBytes = options.maxBytes ?? DEFAULT_YTDLP_MAX_BYTES;
  let cachedAvailable: boolean | undefined;

  const isAvailable = async (): Promise<boolean> => {
    if (cachedAvailable !== undefined) {
      return cachedAvailable;
    }
    const probe = await runExecFile(binary, ['--version'], PROBE_TIMEOUT_MS);
    cachedAvailable = probe.ok;
    return cachedAvailable;
  };

  const downloadSubtitles = async (
    url: TargetUrl,
    lang: LanguageCode,
    proxyUrl?: string,
  ): Promise<Result<YtDlpResult, string>> => {
    let tmpDir: string;
    try {
      tmpDir = await mkdtemp(path.join(tmpdir(), 'mcp-fetch-ytdlp-'));
    } catch (error: unknown) {
      const msg = error instanceof Error ? error.message : String(error);
      return err(`yt-dlp failed to create temp directory: ${msg}`);
    }

    try {
      const outputTemplate = path.join(tmpDir, 'sub');
      const args = buildYtDlpArgs(url, lang, outputTemplate, proxyUrl ?? options.proxy);
      const run = await runExecFile(binary, args, timeoutMs);
      if (!run.ok) {
        return err(run.error.message);
      }

      const files = (await readdir(tmpDir)).filter((f) => f.endsWith('.srv1'));
      const selected = selectSubtitleFile(files, lang);
      if (!selected) {
        return err('yt-dlp did not produce subtitle files');
      }

      const fullPath = path.join(tmpDir, selected.file);
      const info = await stat(fullPath);
      if (info.size > maxBytes) {
        return err(`yt-dlp subtitle file exceeded ${maxBytes} byte limit`);
      }

      const xml = await readFile(fullPath, 'utf-8');
      return ok({ xml, lang: selected.matchedLang, langName: selected.matchedLang });
    } catch (error: unknown) {
      const msg = error instanceof Error ? error.message : String(error);
      return err(`yt-dlp failed: ${msg}`);
    } finally {
      await rm(tmpDir, { recursive: true, force: true }).catch(() => {});
    }
  };

  return {
    isAvailable,
    downloadSubtitles,
  };
};
