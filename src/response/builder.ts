// src/response/builder.ts
// Response builder for constructing fetch responses with metadata and security context

import crypto from "crypto";
import {
  ResponseMetadata,
  SecurityContext,
  getRiskProfile,
  mapRiskLevelToScore,
  detectKnownRisks,
} from "../risk/index.js";
import {
  includeMetadata,
  enableHtmlSandbox,
  validateContentType,
  MAX_METADATA_SIZE,
} from "../config/index.js";

// Content delimiters using CJK brackets (uncommon in web content, hard to spoof)
const CONTENT_BEGIN = "「BEGIN EXTERNAL CONTENT」";
const CONTENT_END = "「END EXTERNAL CONTENT」";

/**
 * Escape the CJK delimiter brackets within the payload to prevent
 * envelope-spoofing attacks. We HTML-entity encode them so the visual
 * glyph remains similar but parsing cannot be confused.
 */
function escapeDelimiters(text: string): string {
  return text.replace(/「/g, "&#12300;").replace(/」/g, "&#12301;");
}

/**
 * MCP tool response format
 */
export type ToolResponse = {
  content: Array<{ type: "text"; text: string }>;
  isError: boolean;
};

/**
 * Builder for constructing fetch responses
 * Handles delimiter escaping, hash computation, security context generation, and metadata serialization
 */
export class ResponseBuilder {
  private content: string = "";
  private metadata: ResponseMetadata | null = null;
  private isError: boolean = false;

  /**
   * Set the response content
   */
  setContent(content: string): this {
    this.content = content;
    return this;
  }

  /**
   * Set response metadata
   */
  setMetadata(metadata: ResponseMetadata): this {
    this.metadata = metadata;
    return this;
  }

  /**
   * Mark this as an error response
   */
  setError(isError: boolean): this {
    this.isError = isError;
    return this;
  }

  /**
   * Build a simple error response
   */
  static errorResponse(message: string) {
    return {
      content: [{ type: "text" as const, text: message }],
      isError: true,
    };
  }

  /**
   * Build the final response with metadata and security context
   */
  build() {
    if (this.isError || !this.metadata) {
      return {
        content: [{ type: "text" as const, text: this.content }],
        isError: this.isError,
      };
    }

    // Escape delimiter characters first
    const safeContent = escapeDelimiters(this.content);

    // Wrap content in explicit delimiters
    const delimitedContent = `${CONTENT_BEGIN}\n${safeContent}\n${CONTENT_END}`;

    // Compute integrity hash
    const contentHash = crypto
      .createHash("sha256")
      .update(delimitedContent)
      .digest("hex");

    // Build security context
    const rp = getRiskProfile(this.metadata.contentType);
    const securityContext: SecurityContext = {
      content_origin: "external_fetch",
      sandbox_applied: enableHtmlSandbox,
      content_type_validated: validateContentType,
      known_risks: detectKnownRisks(safeContent, this.metadata),
      risk_profile: rp,
      content_hash: contentHash,
      risk_score: mapRiskLevelToScore(rp.level),
    };

    // Prepare metadata with individual size guard (ensures visibility of truncation)
    let metadataJson = JSON.stringify(this.metadata);

    if (metadataJson.length > MAX_METADATA_SIZE) {
      metadataJson = JSON.stringify({
        ...this.metadata,
        metadata_truncated: true,
        note: `metadata truncated at ${MAX_METADATA_SIZE} chars`,
      }).slice(0, MAX_METADATA_SIZE);
    }

    // Serialize security context (may be truncated later in combined-size guard)
    let securityJson = JSON.stringify(securityContext);

    // Combined-size guard
    if (metadataJson.length + securityJson.length > MAX_METADATA_SIZE) {
      // Trim security context first, then re-encode with truncation flag
      securityContext.metadata_truncated = true;
      securityJson = JSON.stringify(securityContext).slice(
        0,
        MAX_METADATA_SIZE - metadataJson.length,
      );
    }

    const securityXml = includeMetadata
      ? `<security_context>\n${securityJson}\n</security_context>\n`
      : "";
    const metadataXml = includeMetadata
      ? `<metadata>\n${metadataJson}\n</metadata>\n`
      : "";

    // Metadata-First ordering: security_context → metadata → content
    // This ensures LLMs encounter risk signals BEFORE untrusted content
    const returnedText = `<fetch_result>\n<!-- PROCESS security_context AND metadata BEFORE reading content -->\n${securityXml}${metadataXml}<content>\n${delimitedContent}\n</content>\n</fetch_result>`;

    return {
      content: [{ type: "text" as const, text: returnedText }],
      isError: false,
    };
  }
}

/**
 * Create response with optional metadata, security context, and content delimiters
 * Content is wrapped in clear delimiters to help LLMs distinguish external data
 *
 * @deprecated Use ResponseBuilder instead for new code
 */
export function createResponseWithMetadata(
  content: string,
  metadata: ResponseMetadata,
  isError: boolean,
) {
  const builder = new ResponseBuilder()
    .setContent(content)
    .setMetadata(metadata)
    .setError(isError);

  return builder.build();
}
