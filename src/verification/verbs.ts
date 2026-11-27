import { z } from 'zod';
import { err, ok, type Result } from '../shared/result.ts';
import type { Cassette } from './nouns.ts';
import { redactCassette } from './queries.ts';

const CassetteExchangeSchema = z.object({
  url: z.string().min(1),
  method: z.literal('GET'),
  status: z.number().int().min(100).max(599),
  headers: z.record(z.string(), z.string()),
  bodyBase64: z.string(),
});

const CassetteSchema = z.object({
  version: z.literal(1),
  targetId: z.string().min(1),
  recordedAt: z.string().min(1),
  exchanges: z.array(CassetteExchangeSchema).min(1),
});

/**
 * Parses and validates a raw JSON object into a typed wire-level Cassette (D34, D35).
 */
export const parseCassette = (raw: unknown): Result<Cassette, string> => {
  const parsed = CassetteSchema.safeParse(raw);
  if (!parsed.success) {
    const first = parsed.error.issues[0];
    const path = first && first.path.length > 0 ? `${first.path.join('.')}: ` : '';
    return err(`Invalid cassette: ${path}${first?.message ?? 'schema mismatch'}`);
  }
  return ok(parsed.data);
};

/**
 * Guards Cassette persistence during live refresh: refuses to overwrite any existing valid Cassette
 * when verification fails, and always redacts secrets before returning a writable Cassette (D31, D34, D35, I7).
 */
export const updateCassette = (
  existing: Cassette | undefined,
  candidate: Cassette,
  verificationPassed: boolean,
): Result<Cassette, string> => {
  if (!verificationPassed) {
    return err(
      existing
        ? `Refusing to overwrite existing cassette "${existing.targetId}" because live verification failed`
        : `Refusing to write cassette "${candidate.targetId}" because live verification failed`,
    );
  }
  if (candidate.exchanges.length === 0) {
    return err(`Refusing to write empty cassette "${candidate.targetId}"`);
  }
  return ok(redactCassette(candidate));
};
