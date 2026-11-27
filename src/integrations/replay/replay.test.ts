import { describe, expect, it } from 'bun:test';
import { LIVE_SAMPLES } from '../../verification/samples.ts';
import { runVerificationMatrix } from './runner.ts';

describe('offline multi-form-factor cassette replay matrix (LV-3, LV-4, LV-5, D32, D33, D34, D35)', () => {
  it('replays all 8 curated real-world Live Samples across cli, mcp-stdio, and mcp-http with zero SSRF backdoors', async () => {
    const report = await runVerificationMatrix({ mode: 'replay' });

    expect(report.mode).toBe('replay');
    expect(report.totals.fail).toBe(0);
    expect(report.totals.skippedEnv).toBe(0);
    expect(report.totals.pass).toBe(LIVE_SAMPLES.length * 3);
    expect(report.ok).toBe(true);
  }, 30_000);
});
