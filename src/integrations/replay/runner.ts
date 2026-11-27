import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { type Headers, ResolvedIp, TargetUrl } from '../../fetching/nouns.ts';
import type { DnsLookupPort, HttpGetPort } from '../../fetching/ports.ts';
import { isIpLiteral, normalizeHostname, stripCrossOriginHeaders } from '../../fetching/queries.ts';
import {
  decodeResponseBody,
  MAX_REDIRECTS,
  prepareFetch,
  validateRedirectHop,
  validateResolvedIps,
} from '../../fetching/verbs.ts';
import { LanguageCode } from '../../transcript/nouns.ts';
import { extractCaptionTracks, selectCaptionTrack } from '../../transcript/verbs.ts';
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
import { createRealDnsLookup } from '../dns/client.ts';
import { createRealHttpGet } from '../origin/client.ts';
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

export type RecordExchangePorts = {
  readonly httpGet: HttpGetPort;
  readonly dnsLookup: DnsLookupPort;
};

/**
 * Records a live HTTP(S) exchange chain using the shared SSRF-hardened URL, DNS pinning,
 * cross-origin header stripping, redirect-hop cap, and byte-cap guards (I1, I2, I4, I5, D8, D9, D34).
 */
export const recordLiveExchangeChain = async (
  startUrl: string,
  customHeaders?: Readonly<Record<string, string>>,
  ports: RecordExchangePorts = {
    httpGet: createRealHttpGet({ maxBytes: MAX_RECORD_BYTES, timeoutMs: 30_000 }),
    dnsLookup: createRealDnsLookup(),
  },
): Promise<readonly CassetteExchange[]> => {
  const prepared = prepareFetch({ url: startUrl, format: 'html', headers: customHeaders });
  if (!prepared.ok) {
    throw new Error(prepared.error.message);
  }

  const exchanges: CassetteExchange[] = [];
  let currentUrl: TargetUrl = prepared.value.url;
  let currentHeaders: Headers = prepared.value.headers;

  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    const parsed = new URL(currentUrl);
    const hostname = normalizeHostname(parsed.hostname);
    let pinnedIps: readonly ResolvedIp[];
    if (isIpLiteral(hostname)) {
      pinnedIps = [ResolvedIp(hostname)];
    } else {
      const dnsRes = await ports.dnsLookup(hostname);
      if (!dnsRes.ok) {
        throw new Error(dnsRes.error.message);
      }
      const validIps = validateResolvedIps(hostname, dnsRes.value);
      if (!validIps.ok) {
        throw new Error(validIps.error.message);
      }
      pinnedIps = validIps.value;
    }

    const wireRes = await ports.httpGet(currentUrl, currentHeaders, pinnedIps);
    if (!wireRes.ok) {
      throw new Error(wireRes.error.message);
    }

    const wire = wireRes.value;
    const flatHeaders: Record<string, string> = {};
    for (const [k, v] of Object.entries(wire.headers)) {
      flatHeaders[k.toLowerCase()] = v;
    }
    exchanges.push({
      url: currentUrl,
      method: 'GET',
      status: wire.status,
      headers: flatHeaders,
      bodyBase64: Buffer.from(wire.rawBytes).toString('base64'),
    });

    const loc = flatHeaders.location?.trim();
    if ([301, 302, 303, 307, 308].includes(wire.status) && loc) {
      const nextStep = validateRedirectHop(currentUrl, loc, currentHeaders, hop, MAX_REDIRECTS);
      if (!nextStep.ok) {
        throw new Error(nextStep.error.message);
      }
      currentUrl = nextStep.value.nextUrl;
      currentHeaders = nextStep.value.headers;
      continue;
    }
    break;
  }

  return exchanges;
};

/**
 * Records all wire-level exchanges required to replay a Live Sample offline, including both the
 * watch-page exchange chain and the matched caption-track XML (`&fmt=srv1`) chain for `fetch_transcript`
 * samples (D7, D20, D34, D35, I4).
 */
export const recordLiveSampleExchanges = async (
  sample: LiveSample,
  ports?: RecordExchangePorts,
): Promise<readonly CassetteExchange[]> => {
  const watchExchanges = await recordLiveExchangeChain(sample.url, sample.headers, ports);
  if (sample.tool !== 'fetch_transcript') {
    return watchExchanges;
  }

  const lastWatch = watchExchanges[watchExchanges.length - 1];
  if (!lastWatch) {
    throw new Error(`No watch page exchange recorded for "${sample.id}"`);
  }

  const decodedHtml = decodeResponseBody(
    TargetUrl(lastWatch.url),
    lastWatch.headers,
    Buffer.from(lastWatch.bodyBase64, 'base64'),
    MAX_RECORD_BYTES,
  );
  if (!decodedHtml.ok) {
    throw new Error(decodedHtml.error.message);
  }

  const tracks = extractCaptionTracks(decodedHtml.value);
  if (!tracks.ok) {
    throw new Error(tracks.error.message);
  }

  const selected = selectCaptionTrack(tracks.value, LanguageCode(sample.lang ?? 'en'));
  if (!selected.ok) {
    throw new Error(selected.error.message);
  }

  let captionUrl = selected.value.baseUrl;
  let crossedOrigin = true;
  try {
    const parsedCaptionUrl = new URL(captionUrl);
    if (!parsedCaptionUrl.searchParams.has('fmt')) {
      parsedCaptionUrl.searchParams.set('fmt', 'srv1');
    }
    captionUrl = parsedCaptionUrl.href;
    crossedOrigin =
      parsedCaptionUrl.origin !== new URL(sample.url).origin ||
      parsedCaptionUrl.origin !== new URL(lastWatch.url).origin;
  } catch {
    // Let recordLiveExchangeChain fail with a typed validation error on malformed URLs
  }

  const captionHeaders = crossedOrigin && sample.headers ? stripCrossOriginHeaders(sample.headers) : sample.headers;
  const captionExchanges = await recordLiveExchangeChain(captionUrl, captionHeaders, ports);
  return [...watchExchanges, ...captionExchanges];
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
        sampleId: 'mcp-schema-conformance',
        category: 'html-article',
        formFactor: 'mcp-stdio',
        status: 'fail',
        durationMs: 0,
        details: stdioDriver.schemaIssues.join('; '),
      });
    }
    if (httpDriver.schemaIssues.length > 0) {
      cells.push({
        sampleId: 'mcp-schema-conformance',
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
            sampleId: sample.id,
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
            sampleId: sample.id,
            category: sample.category,
            formFactor: ff,
            status: 'fail',
            durationMs,
            details: error instanceof Error ? error.message : String(error),
          });
        }
      }

      // Enforce byte-for-byte 3-way parity across cli, mcp-stdio, and mcp-http in deterministic offline replay mode (LV-5, D34)
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
          try {
            const exchanges = await recordLiveSampleExchanges(sample);
            const candidate: Cassette = {
              version: 1,
              sampleId: sample.id,
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
            updateCassette(existing, { version: 1, sampleId: sample.id, recordedAt, exchanges: [] }, false);
          }
        } else {
          // Enforce D34: never overwrite existing valid Cassette when live verification fails
          updateCassette(existing, { version: 1, sampleId: sample.id, recordedAt, exchanges: [] }, false);
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
