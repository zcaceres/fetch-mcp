// src/risk/detection.ts
// Risk detection functions for content analysis

import {
  INJECTION_PATTERNS,
  DELIMITER_ESCAPE_PATTERNS,
  SOCIAL_ENGINEERING_PATTERNS,
  MULTI_TOOL_PATTERNS,
  CONTEXT_OVERFLOW_PATTERNS,
} from "./patterns.js";
import {
  decodeHtmlEntities,
  normalizeHomoglyphs,
  detectBase64Injection,
} from "./encoding.js";
import type { ResponseMetadata } from "./types.js";

/**
 * Detect known security risks in content
 * Includes detection for encoded attacks (HTML entities, homoglyphs, Base64)
 */
export function detectKnownRisks(
  content: string,
  metadata: ResponseMetadata,
): string[] {
  const risks: string[] = [];

  // Check for truncation
  if (metadata.truncated) {
    risks.push("content_truncated");
  }

  // Check for script tags (in HTML content)
  if (/<script[\s>]/i.test(content)) {
    risks.push("contains_script_tags");
  }

  // Check for iframe tags
  if (/<iframe[\s>]/i.test(content)) {
    risks.push("contains_iframe");
  }

  // Check for event handlers
  if (/\bon(click|error|load|mouseover|focus)\s*=/i.test(content)) {
    risks.push("contains_event_handlers");
  }

  // Check for javascript: URLs
  if (/javascript:/i.test(content)) {
    risks.push("contains_javascript_url");
  }

  // Prepare normalized versions for pattern detection
  const decodedContent = decodeHtmlEntities(content);
  const normalizedContent = normalizeHomoglyphs(decodedContent);

  // Helper to check patterns against content variants
  const checkPatterns = (
    patterns: Array<{ pattern: RegExp; risk: string }>,
    checkEncoded = true,
  ) => {
    for (const { pattern, risk } of patterns) {
      // Check original content
      if (pattern.test(content)) {
        if (!risks.includes(risk)) {
          risks.push(risk);
        }
      }
      if (checkEncoded) {
        // Check HTML-decoded content (if different)
        if (decodedContent !== content && pattern.test(decodedContent)) {
          if (!risks.includes(risk)) {
            risks.push(risk);
          }
          if (!risks.includes("html_entity_encoded_attack")) {
            risks.push("html_entity_encoded_attack");
          }
        }
        // Check homoglyph-normalized content (if different)
        if (
          normalizedContent !== decodedContent &&
          pattern.test(normalizedContent)
        ) {
          if (!risks.includes(risk)) {
            risks.push(risk);
          }
          if (!risks.includes("homoglyph_attack")) {
            risks.push("homoglyph_attack");
          }
        }
      }
    }
  };

  // Check core injection patterns (with encoding detection)
  checkPatterns(INJECTION_PATTERNS, true);

  // Check delimiter escape patterns (original content only - structural attack)
  checkPatterns(DELIMITER_ESCAPE_PATTERNS, false);

  // Check social engineering patterns (with encoding detection)
  checkPatterns(SOCIAL_ENGINEERING_PATTERNS, true);

  // Check multi-tool attack patterns (with encoding detection)
  checkPatterns(MULTI_TOOL_PATTERNS, true);

  // Check context overflow patterns (original content only - structural)
  checkPatterns(CONTEXT_OVERFLOW_PATTERNS, false);

  // Check for Base64-encoded injection attempts
  if (detectBase64Injection(content)) {
    if (!risks.includes("potential_injection_attempt")) {
      risks.push("potential_injection_attempt");
    }
    risks.push("base64_encoded_attack");
  }

  return risks;
}
