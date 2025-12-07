// src/risk/patterns.ts
// Risk detection patterns for prompt injection and other attacks

// Risk detection patterns - Instruction Override & Role Hijack
export const INJECTION_PATTERNS = [
  // Instruction override attacks
  {
    pattern:
      /ignore\s+(all\s+)?(your\s+)?(previous|prior)\s+(instructions|rules|guidelines)/i,
    risk: "potential_injection_attempt",
  },
  {
    pattern: /ignore\s+(all\s+)?previous/i,
    risk: "potential_injection_attempt",
  },
  {
    pattern: /ignore\s+your\s+instructions/i,
    risk: "potential_injection_attempt",
  },
  {
    pattern: /disregard\s+(all\s+)?(previous|prior|above)/i,
    risk: "potential_injection_attempt",
  },
  // Role hijack / fake system messages
  { pattern: /new\s+(system\s+)?instructions?:/i, risk: "fake_system_message" },
  { pattern: /SYSTEM:\s/i, risk: "fake_system_message" },
  // Exfiltration attempts - broad patterns
  {
    pattern: /reveal\s+(your\s+)?(system\s+)?(prompt|instructions)/i,
    risk: "exfiltration_attempt",
  },
  {
    pattern:
      /output\s+(your\s+)?(full\s+)?(instructions|config|configuration)/i,
    risk: "exfiltration_attempt",
  },
  {
    pattern: /summarize\s+(the\s+)?(your\s+)?(rules|guidelines|instructions)/i,
    risk: "exfiltration_attempt",
  },
  {
    pattern: /what\s+are\s+(the\s+)?(your\s+)?(rules|instructions|guidelines)/i,
    risk: "exfiltration_attempt",
  },
  {
    pattern: /show\s+(me\s+)?(your\s+)?(system\s+)?(prompt|instructions)/i,
    risk: "exfiltration_attempt",
  },
];

// Delimiter escape detection patterns
export const DELIMITER_ESCAPE_PATTERNS = [
  // XML envelope escape attempts
  { pattern: /<\/content>/i, risk: "delimiter_escape_attempt" },
  { pattern: /<\/fetch_result>/i, risk: "delimiter_escape_attempt" },
  { pattern: /<\/security_context>/i, risk: "delimiter_escape_attempt" },
  { pattern: /<\/metadata>/i, risk: "delimiter_escape_attempt" },
  // CJK delimiter spoofing
  { pattern: /「END\s+EXTERNAL/i, risk: "delimiter_escape_attempt" },
  { pattern: /」\s*(END|BEGIN)\s+EXTERNAL/i, risk: "delimiter_escape_attempt" },
  // Fake metadata injection
  { pattern: /<metadata>\s*\{/i, risk: "delimiter_escape_attempt" },
  { pattern: /<security_context>\s*\{/i, risk: "delimiter_escape_attempt" },
];

// Social engineering detection patterns
// Note: These have higher false positive rates but are valuable signals
export const SOCIAL_ENGINEERING_PATTERNS = [
  // Urgency keywords combined with requests
  {
    pattern: /\b(URGENT|IMMEDIATELY|TIME-SENSITIVE|CRITICAL|EMERGENCY)\b/i,
    risk: "social_engineering_attempt",
  },
  // Authority claims with requests
  {
    pattern: /\b(developer|admin|support|team)\s*(need|require|want)/i,
    risk: "social_engineering_attempt",
  },
  {
    pattern: /\byour\s+(developer|admin|support|team)\b/i,
    risk: "social_engineering_attempt",
  },
  // Maintenance/debug mode claims
  {
    pattern: /\b(maintenance|debug|test)\s+mode\b/i,
    risk: "social_engineering_attempt",
  },
  // Verification/compliance manipulation
  {
    pattern:
      /\b(verify|prove|confirm)\s+(you\s+are\s+)?(working|correct|function)/i,
    risk: "social_engineering_attempt",
  },
  // Authority impersonation
  {
    pattern: /\bI\s+am\s+(a|the|your)\s+(developer|admin|creator|owner)\b/i,
    risk: "social_engineering_attempt",
  },
  // For debugging/testing claims
  {
    pattern: /\bfor\s+(debugging|testing|verification)\s+purposes?\b/i,
    risk: "social_engineering_attempt",
  },
];

// Multi-tool attack detection patterns
export const MULTI_TOOL_PATTERNS = [
  // Common tool names that shouldn't appear in fetched content
  {
    pattern:
      /\b(use|call|execute|run)\s+(the\s+)?(write_file|read_file|execute|run_command|shell|bash|terminal)\s+(tool|function|command)?\b/i,
    risk: "multi_tool_attack",
  },
  {
    pattern: /\b(create|write|save)\s+(a\s+)?file\s+(at|to|in)\b/i,
    risk: "multi_tool_attack",
  },
  // Exfiltration via URL patterns
  {
    pattern:
      /\b(make|send)\s+(a\s+)?(request|fetch)\s+to\s+https?:\/\/[^\s]+\?(key|token|secret|password|data)=/i,
    risk: "multi_tool_attack",
  },
  {
    pattern: /https?:\/\/[^\s]+(steal|exfil|leak|capture)[^\s]*/i,
    risk: "multi_tool_attack",
  },
  // Command execution requests
  {
    pattern: /\bexecute\s+(this|the\s+following)\s+(command|code|script)\b/i,
    risk: "multi_tool_attack",
  },
];

// Context overflow detection
export const CONTEXT_OVERFLOW_PATTERNS = [
  // Repeated padding followed by injection attempt
  {
    pattern: /(.)\1{50,}.*\b(ignore|disregard|reveal|output)\b/is,
    risk: "context_overflow_attack",
  },
  // Large amounts of filler text
  {
    pattern:
      /\b(padding|filler|noise)\b.{1000,}\b(instruction|prompt|system)\b/is,
    risk: "context_overflow_attack",
  },
];
