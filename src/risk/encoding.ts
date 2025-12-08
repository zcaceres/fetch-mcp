// src/risk/encoding.ts
// Encoding detection and normalization utilities for attack detection

import punycode from "punycode";

/**
 * Decode URL-encoded characters (percent encoding)
 * Handles %XX hex sequences (e.g., %69 → 'i', %3C → '<')
 */
export function decodeUrlEncoding(text: string): string {
  try {
    // First pass: decode standard percent-encoding
    let decoded = text.replace(/%([0-9A-Fa-f]{2})/g, (_, hex) =>
      String.fromCharCode(parseInt(hex, 16)),
    );
    // Second pass: handle double-encoded sequences (%25XX → %XX → char)
    decoded = decoded.replace(/%([0-9A-Fa-f]{2})/g, (_, hex) =>
      String.fromCharCode(parseInt(hex, 16)),
    );
    return decoded;
  } catch {
    return text;
  }
}

/**
 * Decode HTML entities to detect encoded injection attempts
 * Handles both numeric (&#73;) and named (&lt;) entities
 */
export function decodeHtmlEntities(text: string): string {
  // Decode numeric entities (decimal: &#73; and hex: &#x49;)
  let decoded = text.replace(/&#(\d+);/g, (_, code) =>
    String.fromCharCode(parseInt(code, 10)),
  );
  decoded = decoded.replace(/&#x([0-9a-fA-F]+);/g, (_, code) =>
    String.fromCharCode(parseInt(code, 16)),
  );

  // Decode common named entities used in injection attempts
  const namedEntities: Record<string, string> = {
    "&lt;": "<",
    "&gt;": ">",
    "&amp;": "&",
    "&quot;": '"',
    "&apos;": "'",
    "&nbsp;": " ",
    "&copy;": "©",
    "&reg;": "®",
  };
  for (const [entity, char] of Object.entries(namedEntities)) {
    decoded = decoded.split(entity).join(char);
  }

  return decoded;
}

/**
 * Unicode homoglyph map: visually similar characters that could bypass detection
 * Maps confusable characters to their ASCII equivalents
 */
const HOMOGLYPH_MAP: Record<string, string> = {
  // Cyrillic lowercase lookalikes
  а: "a",
  е: "e",
  і: "i",
  о: "o",
  р: "p",
  с: "c",
  у: "y",
  х: "x",
  ѕ: "s",
  ј: "j",
  ԁ: "d",
  ԛ: "q",
  ԝ: "w",
  һ: "h",
  ɡ: "g",
  // Cyrillic uppercase lookalikes
  А: "A",
  В: "B",
  Е: "E",
  І: "I",
  К: "K",
  М: "M",
  Н: "H",
  О: "O",
  Р: "P",
  С: "C",
  Т: "T",
  Х: "X",
  Ѕ: "S",
  Ј: "J",
  // Greek lowercase lookalikes
  α: "a",
  ο: "o",
  ν: "v",
  ρ: "p",
  τ: "t",
  ω: "w",
  ι: "i",
  // Greek uppercase lookalikes
  Α: "A",
  Β: "B",
  Ε: "E",
  Η: "H",
  Ι: "I",
  Κ: "K",
  Μ: "M",
  Ν: "N",
  Ο: "O",
  Ρ: "P",
  Τ: "T",
  Χ: "X",
  Υ: "Y",
  Ζ: "Z",
  // Fullwidth lowercase
  ａ: "a",
  ｂ: "b",
  ｃ: "c",
  ｄ: "d",
  ｅ: "e",
  ｆ: "f",
  ｇ: "g",
  ｈ: "h",
  ｉ: "i",
  ｊ: "j",
  ｋ: "k",
  ｌ: "l",
  ｍ: "m",
  ｎ: "n",
  ｏ: "o",
  ｐ: "p",
  ｑ: "q",
  ｒ: "r",
  ｓ: "s",
  ｔ: "t",
  ｕ: "u",
  ｖ: "v",
  ｗ: "w",
  ｘ: "x",
  ｙ: "y",
  ｚ: "z",
  // Fullwidth uppercase
  Ａ: "A",
  Ｂ: "B",
  Ｃ: "C",
  Ｄ: "D",
  Ｅ: "E",
  Ｆ: "F",
  Ｇ: "G",
  Ｈ: "H",
  Ｉ: "I",
  Ｊ: "J",
  Ｋ: "K",
  Ｌ: "L",
  Ｍ: "M",
  Ｎ: "N",
  Ｏ: "O",
  Ｐ: "P",
  Ｑ: "Q",
  Ｒ: "R",
  Ｓ: "S",
  Ｔ: "T",
  Ｕ: "U",
  Ｖ: "V",
  Ｗ: "W",
  Ｘ: "X",
  Ｙ: "Y",
  Ｚ: "Z",
  // Mathematical/special variants
  ℯ: "e",
  ℊ: "g",
  ℎ: "h",
  ⅰ: "i",
  ⅱ: "ii",
  ⅲ: "iii",
  ℓ: "l",
  ℕ: "N",
  ℙ: "P",
  ℚ: "Q",
  ℝ: "R",
  ℤ: "Z",
  // Zero-width and special spaces (remove them)
  "\u200B": "",
  "\u200C": "",
  "\u200D": "",
  "\uFEFF": "",
  "\u00A0": " ",
};

/**
 * Normalize Unicode homoglyphs to ASCII for detection
 */
export function normalizeHomoglyphs(text: string): string {
  let normalized = text;
  for (const [homoglyph, ascii] of Object.entries(HOMOGLYPH_MAP)) {
    normalized = normalized.split(homoglyph).join(ascii);
  }
  return normalized;
}

/**
 * Recursively decode HTML entities to catch double/triple encoding
 * Example: &#38;#105;gnore → &#105;gnore → ignore
 * Limited to MAX_ITERATIONS to prevent DoS via deeply nested encoding
 */
const MAX_DECODE_ITERATIONS = 3;

export function decodeHtmlEntitiesRecursive(text: string): string {
  let current = text;
  let previous = "";

  for (let i = 0; i < MAX_DECODE_ITERATIONS && current !== previous; i++) {
    previous = current;
    current = decodeHtmlEntities(current);
  }

  return current;
}

/**
 * Normalize punycode/IDN domains to Unicode for homoglyph detection
 * Example: xn--80ak6aa92e.com → москва.com (which may contain homoglyphs)
 *
 * This catches IDN homograph attacks where attackers register domains like:
 * - xn--pple-43d.com (аpple.com with Cyrillic 'а')
 * - xn--80a1acny.xn--p1ai (россия.рф)
 */
export function decodePunycode(text: string): string {
  try {
    // Find punycode-encoded segments (xn--...)
    return text.replace(/xn--[a-z0-9-]+/gi, (match) => {
      try {
        return punycode.toUnicode(match);
      } catch {
        return match;
      }
    });
  } catch {
    return text;
  }
}

/**
 * Comprehensive text normalization for attack detection
 * Applies all decoding/normalization passes in the correct order
 */
export function normalizeForDetection(text: string): string {
  let normalized = text;

  // 1. Decode URL encoding first (may reveal HTML entities)
  normalized = decodeUrlEncoding(normalized);

  // 2. Recursively decode HTML entities (catches double encoding)
  normalized = decodeHtmlEntitiesRecursive(normalized);

  // 3. Decode punycode domains (reveals Unicode for homoglyph check)
  normalized = decodePunycode(normalized);

  // 4. Normalize homoglyphs to ASCII
  normalized = normalizeHomoglyphs(normalized);

  return normalized;
}

/**
 * Known Base64-encoded injection phrases
 * We check for common dangerous phrases that might be Base64 encoded
 */
const BASE64_DANGER_PHRASES = [
  "ignore previous instructions",
  "ignore all previous",
  "disregard previous",
  "reveal system prompt",
  "output your instructions",
  "new instructions:",
  "SYSTEM:",
];

/**
 * Check if content contains Base64-encoded injection attempts
 */
export function detectBase64Injection(content: string): boolean {
  // Find potential Base64 strings (at least 20 chars, valid base64 alphabet)
  const base64Pattern = /[A-Za-z0-9+/=]{20,}/g;
  const matches = content.match(base64Pattern) || [];

  for (const match of matches) {
    try {
      // Attempt to decode
      const decoded = Buffer.from(match, "base64").toString("utf-8");
      // Check if decoded content contains dangerous phrases
      const lowerDecoded = decoded.toLowerCase();
      for (const phrase of BASE64_DANGER_PHRASES) {
        if (lowerDecoded.includes(phrase.toLowerCase())) {
          return true;
        }
      }
    } catch {
      // Invalid base64, skip
    }
  }
  return false;
}
