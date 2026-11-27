export type VendorName = 'anthropic' | 'gemini' | 'openai';

export type VendorJsonSchemaProperty = {
  readonly type?: string;
  readonly description?: string;
  readonly additionalProperties?: boolean | { readonly type?: string };
  readonly oneOf?: readonly unknown[];
  readonly anyOf?: readonly unknown[];
  readonly allOf?: readonly unknown[];
  readonly format?: string;
};

export type VendorToolAnnotations = {
  readonly readOnlyHint?: boolean;
  readonly destructiveHint?: boolean;
  readonly idempotentHint?: boolean;
  readonly openWorldHint?: boolean;
};

export type VendorToolSchemaInput = {
  readonly name: string;
  readonly description: string;
  readonly inputSchema: {
    readonly type: string;
    readonly properties: Readonly<Record<string, VendorJsonSchemaProperty>>;
    readonly required?: readonly string[];
    readonly additionalProperties?: boolean;
    readonly oneOf?: readonly unknown[];
    readonly anyOf?: readonly unknown[];
    readonly allOf?: readonly unknown[];
  };
  readonly annotations?: VendorToolAnnotations;
};

export type VendorCheckIssue = {
  readonly vendor: VendorName;
  readonly tool: string;
  readonly message: string;
};

export type FormFactor = 'cli' | 'mcp-stdio' | 'mcp-http';

export type SampleCategory = 'html-article' | 'markdown-docs' | 'json-and-encoding' | 'refusal' | 'youtube-transcript';

export type CassetteExchange = {
  readonly url: string;
  readonly method: 'GET';
  readonly status: number;
  readonly headers: Readonly<Record<string, string>>;
  readonly bodyBase64: string;
};

export type Cassette = {
  readonly version: 1;
  readonly targetId: string;
  readonly recordedAt: string;
  readonly exchanges: readonly CassetteExchange[];
};

export type OutputCheck =
  | { readonly kind: 'expect_ok' }
  | { readonly kind: 'expect_error'; readonly contains?: string }
  | { readonly kind: 'min_length'; readonly value: number }
  | { readonly kind: 'contains'; readonly text: string }
  | { readonly kind: 'not_contains'; readonly text: string }
  | { readonly kind: 'valid_json' }
  | { readonly kind: 'starts_with'; readonly prefix: string };

export type LiveSample = {
  readonly id: string;
  readonly category: SampleCategory;
  readonly description: string;
  readonly tool: 'fetch_html' | 'fetch_markdown' | 'fetch_readable' | 'fetch_text' | 'fetch_json' | 'fetch_transcript';
  readonly cliSubcommand: 'html' | 'markdown' | 'readable' | 'text' | 'json' | 'transcript';
  readonly url: string;
  readonly lang?: string;
  readonly maxLength?: number;
  readonly startIndex?: number;
  readonly headers?: Readonly<Record<string, string>>;
  readonly cassetteFile?: string;
  readonly liveOptional?: boolean;
  readonly checks: readonly OutputCheck[];
};

export type CellOutcome = {
  readonly ok: boolean;
  readonly output: string;
};

export type CellStatus = 'pass' | 'fail' | 'skipped_env';

export type VerificationCell = {
  readonly targetId: string;
  readonly category: SampleCategory;
  readonly formFactor: FormFactor;
  readonly status: CellStatus;
  readonly durationMs: number;
  readonly details?: string;
};

export type VerificationReport = {
  readonly mode: 'replay' | 'live';
  readonly recordedAt: string;
  readonly totals: {
    readonly pass: number;
    readonly fail: number;
    readonly skippedEnv: number;
  };
  readonly cells: readonly VerificationCell[];
  readonly ok: boolean;
};
