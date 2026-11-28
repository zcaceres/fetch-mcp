import type {
  Cassette,
  CellOutcome,
  CellStatus,
  FormFactor,
  OutputCheck,
  VendorCheckIssue,
  VendorToolSchemaInput,
  VerificationCell,
  VerificationReport,
} from './nouns.ts';

const SNAKE_CASE_REGEX = /^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$/;

const SENSITIVE_CASSETTE_HEADERS: ReadonlySet<string> = new Set([
  'authorization',
  'cookie',
  'set-cookie',
  'proxy-authorization',
  'x-api-key',
]);

const redactUrlCredentials = (rawUrl: string): string => {
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(rawUrl)) {
    try {
      const parsed = new URL(rawUrl);
      if (parsed.username || parsed.password) {
        parsed.username = '';
        parsed.password = '';
      }
      return parsed.href;
    } catch {
      return rawUrl.replace(/^([a-zA-Z][a-zA-Z0-9+.-]*:\/\/)[\s\S]*@/, '$1<redacted>@');
    }
  }
  if (rawUrl.startsWith('//')) {
    try {
      const parsed = new URL(`http:${rawUrl}`);
      if (parsed.username || parsed.password) {
        parsed.username = '';
        parsed.password = '';
        return parsed.href.replace(/^http:/, '');
      }
      return rawUrl;
    } catch {
      return rawUrl.replace(/^(\/\/)[\s\S]*@/, '$1<redacted>@');
    }
  }
  return rawUrl;
};

/**
 * Audits MCP tool definitions against Anthropic (Claude), Google (Gemini), and OpenAI MCP server rules
 * (D12, D33, I6). Pure infallible query returning an empty list when all checks pass.
 */
export const validateVendorSchemas = (tools: readonly VendorToolSchemaInput[]): readonly VendorCheckIssue[] => {
  const issues: VendorCheckIssue[] = [];

  for (const tool of tools) {
    if (!SNAKE_CASE_REGEX.test(tool.name)) {
      issues.push({
        vendor: 'anthropic',
        tool: tool.name,
        message: 'tool name must be snake_case',
      });
    }

    if (tool.description.trim().length === 0) {
      issues.push({
        vendor: 'openai',
        tool: tool.name,
        message: 'tool description must be non-empty',
      });
    }

    if (tool.inputSchema.type !== 'object') {
      issues.push({
        vendor: 'openai',
        tool: tool.name,
        message: 'inputSchema.type must be "object"',
      });
    }

    if (tool.inputSchema.additionalProperties !== false) {
      issues.push({
        vendor: 'openai',
        tool: tool.name,
        message: 'inputSchema must declare additionalProperties: false for strict mode',
      });
    }

    if (
      tool.inputSchema.oneOf !== undefined ||
      tool.inputSchema.anyOf !== undefined ||
      tool.inputSchema.allOf !== undefined
    ) {
      issues.push({
        vendor: 'openai',
        tool: tool.name,
        message: 'inputSchema must not use oneOf/anyOf/allOf composition keywords',
      });
    }

    if ('proxy' in tool.inputSchema.properties) {
      issues.push({
        vendor: 'anthropic',
        tool: tool.name,
        message: 'inputSchema must never expose a caller-controlled proxy property (I6)',
      });
    }

    for (const [propName, prop] of Object.entries(tool.inputSchema.properties)) {
      if (!prop.type) {
        issues.push({
          vendor: 'gemini',
          tool: tool.name,
          message: `property "${propName}" must declare an explicit type`,
        });
      }
      if (prop.oneOf !== undefined || prop.anyOf !== undefined || prop.allOf !== undefined) {
        issues.push({
          vendor: 'openai',
          tool: tool.name,
          message: `property "${propName}" must not use oneOf/anyOf/allOf keywords`,
        });
      }
      if (prop.format !== undefined) {
        issues.push({
          vendor: 'openai',
          tool: tool.name,
          message: `property "${propName}" must omit non-portable JSON Schema format "${prop.format}"`,
        });
      }
      if (prop.type === 'object') {
        const additional = prop.additionalProperties;
        if (typeof additional !== 'object' || additional === null || additional.type !== 'string') {
          issues.push({
            vendor: 'gemini',
            tool: tool.name,
            message: `object property "${propName}" must declare typed additionalProperties (e.g. { type: "string" })`,
          });
        }
      }
    }

    const ann = tool.annotations;
    if (
      ann?.readOnlyHint !== true ||
      ann.destructiveHint !== false ||
      ann.idempotentHint !== true ||
      ann.openWorldHint !== true
    ) {
      issues.push({
        vendor: 'anthropic',
        tool: tool.name,
        message:
          'tool must declare MCP 2025-11-25 annotations { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true }',
      });
    }
  }

  return issues;
};

/**
 * Strips sensitive headers (`Authorization`, `Cookie`, `Set-Cookie`, `Proxy-Authorization`, `X-Api-Key`)
 * and redacts URL credentials across every exchange in a Cassette (D31, D34, D35, I7).
 */
export const redactCassette = (cassette: Cassette): Cassette => ({
  ...cassette,
  exchanges: cassette.exchanges.map((ex) => {
    const cleanHeaders: Record<string, string> = {};
    for (const [key, value] of Object.entries(ex.headers)) {
      const lower = key.toLowerCase();
      if (SENSITIVE_CASSETTE_HEADERS.has(lower)) continue;
      cleanHeaders[lower] = lower === 'location' ? redactUrlCredentials(value) : value;
    }
    return {
      ...ex,
      url: redactUrlCredentials(ex.url),
      headers: cleanHeaders,
    };
  }),
});

/**
 * Evaluates resilient structural Output Checks against a cell's outcome (D34, D35).
 * Returns an empty list when every check passes, or one human-readable message per failed check.
 */
export const evaluateOutputChecks = (outcome: CellOutcome, checks: readonly OutputCheck[]): readonly string[] => {
  const failures: string[] = [];

  for (const check of checks) {
    switch (check.kind) {
      case 'expect_ok':
        if (!outcome.ok) {
          failures.push(`expected success, got error: ${outcome.output}`);
        }
        break;
      case 'expect_error':
        if (outcome.ok) {
          failures.push('expected error, got success');
        } else if (check.contains !== undefined && !outcome.output.includes(check.contains)) {
          failures.push(`expected error containing "${check.contains}", got "${outcome.output}"`);
        }
        break;
      case 'min_length':
        if (outcome.output.length < check.value) {
          failures.push(`expected output length >= ${check.value}, got ${outcome.output.length}`);
        }
        break;
      case 'contains':
        if (!outcome.output.includes(check.text)) {
          failures.push(`expected output to contain "${check.text}"`);
        }
        break;
      case 'not_contains':
        if (outcome.output.includes(check.text)) {
          failures.push(`expected output NOT to contain "${check.text}"`);
        }
        break;
      case 'valid_json':
        try {
          JSON.parse(outcome.output);
        } catch {
          failures.push('expected valid JSON output');
        }
        break;
      case 'starts_with':
        if (!outcome.output.startsWith(check.prefix)) {
          failures.push(`expected output to start with "${check.prefix}"`);
        }
        break;
      default: {
        const exhaustive: never = check;
        return exhaustive;
      }
    }
  }

  return failures;
};

/**
 * Classifies a Live Sample × Form Factor cell outcome per D34:
 * - In replay mode, every sample is strictly required (never `skipped_env`).
 * - In live mode, optional live samples become `skipped_env` ONLY when the fetch itself failed (`!outcomeOk`);
 *   Output Check failures on a succeeded fetch (`outcomeOk === true`) always mark `fail`.
 */
export const classifyCellStatus = (
  mode: 'replay' | 'live',
  liveOptional: boolean | undefined,
  outcomeOk: boolean,
  failures: readonly string[],
): CellStatus => {
  if (failures.length === 0) {
    return 'pass';
  }
  if (mode === 'live' && liveOptional === true && !outcomeOk) {
    return 'skipped_env';
  }
  return 'fail';
};

/**
 * Verifies exact `ok` and output text parity across CLI, MCP stdio, and MCP Streamable HTTP
 * for deterministic offline Cassette replay (LV-5, D1, D32, D34, D35).
 */
export const checkFormFactorParity = (outcomes: Readonly<Record<FormFactor, CellOutcome>>): readonly string[] => {
  const failures: string[] = [];
  const baseline = outcomes.cli;

  for (const ff of ['mcp-stdio', 'mcp-http'] as const) {
    const candidate = outcomes[ff];
    if (candidate.ok !== baseline.ok) {
      failures.push(`parity mismatch (${ff} vs cli): ok=${candidate.ok} !== ${baseline.ok}`);
    } else if (candidate.output !== baseline.output) {
      if (candidate.output.length === baseline.output.length) {
        failures.push(
          `parity mismatch (${ff} vs cli): output content differs (same length ${candidate.output.length})`,
        );
      } else {
        failures.push(
          `parity mismatch (${ff} vs cli): output length ${candidate.output.length} !== ${baseline.output.length}`,
        );
      }
    }
  }

  return failures;
};

const statusLabel = (status: CellStatus): 'PASS' | 'FAIL' | 'SKIP' => {
  switch (status) {
    case 'pass':
      return 'PASS';
    case 'fail':
      return 'FAIL';
    case 'skipped_env':
      return 'SKIP';
    default: {
      const exhaustive: never = status;
      return exhaustive;
    }
  }
};

/**
 * Summarizes individual verification cells into a derived Verification Report (D30, D34, D35).
 */
export const summarizeReport = (
  mode: 'replay' | 'live',
  cells: readonly VerificationCell[],
  recordedAt: string,
): VerificationReport => {
  let pass = 0;
  let fail = 0;
  let skippedEnv = 0;

  for (const cell of cells) {
    switch (cell.status) {
      case 'pass':
        pass++;
        break;
      case 'fail':
        fail++;
        break;
      case 'skipped_env':
        skippedEnv++;
        break;
      default: {
        const exhaustive: never = cell.status;
        return exhaustive;
      }
    }
  }

  return {
    mode,
    recordedAt,
    totals: { pass, fail, skippedEnv },
    cells,
    ok: fail === 0,
  };
};

/**
 * Formats a concise human-readable Verification Report table for terminal/agent inspection (D34, D35).
 */
export const formatReportSummary = (report: VerificationReport): string => {
  const lines: string[] = [
    `Verification (${report.mode}) — pass: ${report.totals.pass}, fail: ${report.totals.fail}, skipped_env: ${report.totals.skippedEnv}`,
  ];
  for (const cell of report.cells) {
    const icon = statusLabel(cell.status);
    const detail = cell.details ? ` — ${cell.details}` : '';
    lines.push(`  [${icon}] ${cell.sampleId} (${cell.formFactor}, ${cell.durationMs}ms)${detail}`);
  }
  return lines.join('\n');
};
