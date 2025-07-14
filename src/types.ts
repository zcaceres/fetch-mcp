import { z } from "zod";

export const downloadLimit = Number.parseInt(process.env.DEFAULT_LIMIT ?? "5000") ?? 5000;

export const RequestPayloadSchema = z.object({
  url: z.string().url(),
  headers: z.record(z.string()).optional(),
  max_length: z.number().int().min(0).optional().default(downloadLimit),
  start_index: z.number().int().min(0).optional().default(0),
});

// Make sure TypeScript treats the fields as optional with defaults
export type RequestPayload = {
  url: string;
  headers?: Record<string, string>;
  max_length?: number;
  start_index?: number;
};
