import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type {
  Cassette,
  CassetteExchange,
  CellOutcome,
  FormFactor,
  LiveSample,
  VerificationCell,
  VerificationReport,
} from '../../verification/nouns.ts';
import {
  checkFormFactorParity,
  classifyCellStatus,
  evaluateOutputChecks,
  formatReportSummary,
  summarizeReport,
} from '../../verification/queries.ts';
import { LIVE_SAMPLES } from '../../verification/samples.ts';
import { parseCassette, updateCassette } from '../../verification/verbs.ts';
import {
  createHttpMcpDriver,
  createStdioMcpDriver,
  type McpDriver,
  resolveNodeBinary,
  runCliSample,
} from './drivers.ts';
import { startReplayProxy } from './proxy.ts';

const REPO_ROOT = path.resolve(import.meta.dir, '../../..');
const MAX_RECORD_BYTES = 10 * 1024 * 1024;
export const CASSETTES_DIR = path.join(REPO_ROOT, 'fixtures/cassettes');

export const loadCassettesFromDisk = (
  samples: readonly LiveSample[] = LIVE_SAMPLES,
  cassettesDir: string = CASSETTES_DIR,
): readonly Cassette[] => {
  const loaded: Cassette[] = [];
  for (const sample of samples) {
    if (!sample.cassetteFile) continue;
    const fullPath = path.join(cassettesDir, sample.cassetteFile);
    const raw: unknown = JSON.parse(readFileSync(fullPath, 'utf-8'));
    const parsed = parseCassette(raw);
    if (!parsed.ok) {
      throw new Error(`Failed to load cassette ${sample.cassetteFile}: ${parsed.error}`);
    }
    loaded.push(parsed.value);
  }
  return loaded;
};

const recordLiveExchangeChain = async (
  startUrl: string,
  customHeaders?: Readonly<Record<string, string>>,
): Promise<readonly CassetteExchange[]> => {
  const exchanges: CassetteExchange[] = [];
  let currentUrl = startUrl;

  const baseHeaders: Record<string, string> = {
    'User-Agent':
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Accept-Encoding': 'gzip, deflate, br',
  };
  if (customHeaders) {
    for (const [k, v] of Object.entries(customHeaders)) {
      baseHeaders[k] = v;
    }
  }

  for (let hop = 0; hop < 10; hop++) {
    const parsed = new URL(currentUrl);
    const transport = parsed.protocol === 'https:' ? https : http;
    const hopResult = await new Promise<CassetteExchange>((resolve, reject) => {
      const req = transport.request(
        parsed,
        {
          method: 'GET',
          headers: baseHeaders,
          timeout: 30_000,
        },
        (res) => {
          const chunks: Buffer[] = [];
          let totalBytes = 0;
          let aborted = false;

          res.on('data', (chunk: Buffer) => {
            if (aborted) return;
            totalBytes += chunk.byteLength;
            if (totalBytes > MAX_RECORD_BYTES) {
              aborted = true;
              const capErr = new Error(
                `Recorded response for ${currentUrl} exceeded ${MAX_RECORD_BYTES} byte cap (I5)`,
              );
              req.destroy(capErr);
              reject(capErr);
              return;
            }
            chunks.push(chunk);
          });
          res.on('end', () => {
            if (aborted) return;
            const flatHeaders: Record<string, string> = {};
            for (const [k, v] of Object.entries(res.headers)) {
              if (v === undefined) continue;
              flatHeaders[k.toLowerCase()] = Array.isArray(v) ? v.join(', ') : v;
            }
            resolve({
              url: currentUrl,
              method: 'GET',
              status: res.statusCode ?? 0,
              headers: flatHeaders,
              bodyBase64: Buffer.concat(chunks).toString('base64'),
            });
          });
          res.on('error', reject);
        },
      );
      req.on('error', reject);
      req.on('timeout', () => {
        req.destroy(new Error(`Timed out recording ${currentUrl}`));
      });
      req.end();
    });

    exchanges.push(hopResult);
    const loc = hopResult.headers.location?.trim();
    if ([301, 302, 303, 307, 308].includes(hopResult.status) && loc) {
      currentUrl = new URL(loc, currentUrl).href;
      continue;
    }
    break;
  }

  return exchanges;
};

export type RunMatrixOptions = {
  readonly mode: 'replay' | 'live';
  readonly record?: boolean;
  readonly samples?: readonly LiveSample[];
  readonly cassettesDir?: string;
};

/**
 * Executes the 3-Form-Factor verification matrix (`cli`, `mcp-stdio`, `mcp-http`) against
 * either offline local replay Cassettes or the live internet (D1, D32, D33, D34, D35).
 */
export const runVerificationMatrix = async (options: RunMatrixOptions): Promise<VerificationReport> => {
  const samples = options.samples ?? LIVE_SAMPLES;
  const cassettesDir = options.cassettesDir ?? CASSETTES_DIR;
  const nodeBin = resolveNodeBinary();
  const recordedAt = new Date().toISOString();

  let closeProxy: (() => Promise<void>) | undefined;
  let stdioDriver: McpDriver | undefined;
  let httpDriver: McpDriver | undefined;
  const cells: VerificationCell[] = [];

  try {
    let childEnv: Record<string, string | undefined>;

    if (options.mode === 'replay') {
      const cassettes = loadCassettesFromDisk(samples, cassettesDir);
      const proxy = await startReplayProxy(cassettes);
      closeProxy = proxy.close;
      // Keep PATH limited to node + standard system bins during replay so yt-dlp falls back cleanly to direct proxy replay
      const nodeDir = path.dirname(nodeBin);
      childEnv = {
        ...process.env,
        PATH: `${nodeDir}:/usr/bin:/bin`,
        HTTP_PROXY: proxy.proxyUrl,
        HTTPS_PROXY: proxy.proxyUrl,
        http_proxy: '',
        https_proxy: '',
        ALL_PROXY: '',
        all_proxy: '',
        NO_PROXY: '',
        no_proxy: '',
        NODE_EXTRA_CA_CERTS: proxy.caCertPath,
        DEFAULT_LIMIT: '',
        MAX_RESPONSE_BYTES: '',
      };
    } else {
      childEnv = { ...process.env };
    }

    stdioDriver = await createStdioMcpDriver(childEnv, nodeBin);
    httpDriver = await createHttpMcpDriver(childEnv, nodeBin);

    if (stdioDriver.schemaIssues.length > 0) {
      cells.push({
        targetId: 'mcp-schema-conformance',
        category: 'html-article',
        formFactor: 'mcp-stdio',
        status: 'fail',
        durationMs: 0,
        details: stdioDriver.schemaIssues.join('; '),
      });
    }
    if (httpDriver.schemaIssues.length > 0) {
      cells.push({
        targetId: 'mcp-schema-conformance',
        category: 'html-article',
        formFactor: 'mcp-http',
        status: 'fail',
        durationMs: 0,
        details: httpDriver.schemaIssues.join('; '),
      });
    }

    const formFactors: readonly FormFactor[] = ['cli', 'mcp-stdio', 'mcp-http'];

    for (const sample of samples) {
      let sampleAllPassed = true;
      const sampleOutcomes: Partial<Record<FormFactor, CellOutcome>> = {};
      const sampleCellStartIdx = cells.length;

      for (const ff of formFactors) {
        const started = performance.now();
        try {
          const outcome =
            ff === 'cli'
              ? await runCliSample(sample, childEnv, nodeBin)
              : ff === 'mcp-stdio'
                ? await stdioDriver.callSample(sample)
                : await httpDriver.callSample(sample);
          sampleOutcomes[ff] = outcome;
          const durationMs = Math.round(performance.now() - started);
          const failures = evaluateOutputChecks(outcome, sample.checks);
          const status = classifyCellStatus(options.mode, sample.liveOptional, outcome.ok, failures);

          if (status !== 'pass') {
            sampleAllPassed = false;
          }
          cells.push({
            targetId: sample.id,
            category: sample.category,
            formFactor: ff,
            status,
            durationMs,
            ...(failures.length > 0 ? { details: failures.join('; ') } : {}),
          });
        } catch (error: unknown) {
          sampleAllPassed = false;
          const durationMs = Math.round(performance.now() - started);
          cells.push({
            targetId: sample.id,
            category: sample.category,
            formFactor: ff,
            status: 'fail',
            durationMs,
            details: error instanceof Error ? error.message : String(error),
          });
        }
      }

      // Enforce byte-for-byte 3-way parity across cli, mcp-stdio, and mcp-http in replay mode (LV-5)
      if (
        options.mode === 'replay' &&
        sampleOutcomes.cli !== undefined &&
        sampleOutcomes['mcp-stdio'] !== undefined &&
        sampleOutcomes['mcp-http'] !== undefined
      ) {
        const parityFailures = checkFormFactorParity({
          cli: sampleOutcomes.cli,
          'mcp-stdio': sampleOutcomes['mcp-stdio'],
          'mcp-http': sampleOutcomes['mcp-http'],
        });
        if (parityFailures.length > 0) {
          sampleAllPassed = false;
          const parityMsg = parityFailures.join('; ');
          for (let idx = sampleCellStartIdx; idx < cells.length; idx++) {
            const cell = cells[idx];
            if (cell && cell.status === 'pass') {
              cells[idx] = { ...cell, status: 'fail', details: parityMsg };
            }
          }
        }
      }

      if (options.mode === 'live' && options.record && sample.cassetteFile) {
        const cassettePath = path.join(cassettesDir, sample.cassetteFile);
        let existing: Cassette | undefined;
        try {
          const parsedExisting = parseCassette(JSON.parse(readFileSync(cassettePath, 'utf-8')));
          if (parsedExisting.ok) existing = parsedExisting.value;
        } catch {
          existing = undefined;
        }

        if (sampleAllPassed) {
          // For transcript samples, keep curated dual-hop (watch + srv1 XML) cassette unless direct XML is also captured
          if (sample.tool === 'fetch_transcript' && existing !== undefined) {
            continue;
          }
          try {
            const exchanges = await recordLiveExchangeChain(sample.url, sample.headers);
            const candidate: Cassette = {
              version: 1,
              targetId: sample.id,
              recordedAt,
              exchanges,
            };
            const updated = updateCassette(existing, candidate, true);
            if (updated.ok) {
              mkdirSync(cassettesDir, { recursive: true });
              writeFileSync(cassettePath, `${JSON.stringify(updated.value, null, 2)}\n`);
            }
          } catch (error: unknown) {
            const detail = error instanceof Error ? error.message : String(error);
            process.stderr.write(`Warning: failed to record cassette for "${sample.id}": ${detail}\n`);
          }
        } else {
          // Enforce D34: never overwrite existing valid Cassette when live verification fails
          updateCassette(existing, { version: 1, targetId: sample.id, recordedAt, exchanges: [] }, false);
        }
      }
    }
  } finally {
    await httpDriver?.close().catch(() => undefined);
    await stdioDriver?.close().catch(() => undefined);
    await closeProxy?.().catch(() => undefined);
  }

  return summarizeReport(options.mode, cells, recordedAt);
};

const isDirectEntrypoint = (): boolean => {
  const entry = process.argv[1];
  if (!entry) return false;
  return path.resolve(entry) === fileURLToPath(import.meta.url);
};

if (isDirectEntrypoint()) {
  const argv = process.argv.slice(2);
  const mode: 'replay' | 'live' = argv.includes('--live') ? 'live' : 'replay';
  const record = argv.includes('--record');
  const jsonOnly = argv.includes('--json');

  runVerificationMatrix({ mode, record })
    .then((report) => {
      if (jsonOnly) {
        process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
      } else {
        process.stdout.write(`${formatReportSummary(report)}\n\n${JSON.stringify(report, null, 2)}\n`);
      }
      process.exit(report.ok ? 0 : 1);
    })
    .catch((error: unknown) => {
      const msg = error instanceof Error ? error.message : String(error);
      process.stderr.write(`Verification runner failed: ${msg}\n`);
      process.exit(1);
    });
}
