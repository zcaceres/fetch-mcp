// src/risk/types.ts
// Type definitions for risk detection and security context

import type { RiskProfile } from "./profiles.js";

// Response metadata interface
export interface ResponseMetadata {
  truncated: boolean;
  totalLength: number;
  startIndex: number;
  fetchedLength: number;
  contentType?: string;
}

// Security context for LLM guidance
export interface SecurityContext {
  content_origin: "external_fetch";
  sandbox_applied: boolean;
  content_type_validated: boolean;
  known_risks: string[];
  risk_profile: RiskProfile;
  // SHA-256 hash of the escaped, delimited content for integrity checks
  content_hash?: string;
  // Traffic-light helper for UIs (red | amber | green)
  risk_score?: "red" | "amber" | "green";
  // Indicates metadata/security_context was truncated due to MAX_METADATA_SIZE
  metadata_truncated?: boolean;
}
