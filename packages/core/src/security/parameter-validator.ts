import Ajv, { type JSONSchemaType, type ValidateFunction } from 'ajv';
import addFormats from 'ajv-formats';
import type { SecurityMiddleware, PipelineContext, SecurityDecision } from '../pipeline/types';

/**
 * ToolSchemaCache maintains a registry of JSON Schemas for MCP tools.
 *
 * The schemas are populated from the `tools/list` responses of upstream
 * MCP servers. When the firewall can't find a schema for a tool, it
 * falls back to basic structural validation.
 *
 * The cache is keyed by `serverName:toolName`.
 */
export class ToolSchemaCache {
  private schemas: Map<string, JSONSchemaType<unknown>> = new Map();
  private validators: Map<string, ValidateFunction> = new Map();
  private ajv: Ajv;

  constructor() {
    this.ajv = new Ajv({
      allErrors: true,
      strict: false, // Allow non-standard JSON Schema keywords from MCP servers
      removeAdditional: false,
      useDefaults: true,
      coerceTypes: false,
    });
    addFormats(this.ajv);
  }

  /**
   * Register a tool schema (typically from a tools/list response).
   */
  registerTool(serverName: string, toolName: string, schema: Record<string, unknown>): void {
    const key = `${serverName}:${toolName}`;
    this.schemas.set(key, schema as JSONSchemaType<unknown>);

    try {
      const validate = this.ajv.compile(schema);
      this.validators.set(key, validate);
    } catch (err) {
      // Schema compilation failed — we'll fall back to basic validation
      this.validators.delete(key);
    }
  }

  /**
   * Register multiple tools at once (from a tools/list response).
   */
  registerTools(
    serverName: string,
    tools: Array<{ name: string; inputSchema?: Record<string, unknown> }>,
  ): void {
    for (const tool of tools) {
      if (tool.inputSchema) {
        this.registerTool(serverName, tool.name, tool.inputSchema);
      }
    }
  }

  /**
   * Get the compiled validator for a tool, or null if no schema is registered.
   */
  getValidator(serverName: string, toolName: string): ValidateFunction | null {
    return this.validators.get(`${serverName}:${toolName}`) ?? null;
  }

  /**
   * Check if a schema is registered for a tool.
   */
  hasSchema(serverName: string, toolName: string): boolean {
    return this.validators.has(`${serverName}:${toolName}`);
  }

  /**
   * Get the raw schema for a tool.
   */
  getSchema(serverName: string, toolName: string): Record<string, unknown> | null {
    return this.schemas.get(`${serverName}:${toolName}`) ?? null;
  }

  /**
   * Clear all cached schemas (useful on hot-reload).
   */
  clear(): void {
    this.schemas.clear();
    this.validators.clear();
  }

  /**
   * Get the number of registered schemas.
   */
  get size(): number {
    return this.schemas.size;
  }
}

// ─── Enhanced Parameter Validation Middleware ─────────────────

export interface ParameterValidationOptions {
  enabled: boolean;
  strictMode?: boolean;
  maxStringLength?: number;
  /** AJV instance for full JSON Schema validation */
  schemaCache?: ToolSchemaCache;
}

/**
 * Enhanced ParameterValidationMiddleware that uses AJV for
 * full JSON Schema validation when a tool schema is registered.
 *
 * Falls back to basic structural checks (path traversal, null bytes,
 * deep nesting) when no schema is available.
 *
 * Priority: 50
 */
export class ParameterValidationMiddleware implements SecurityMiddleware {
  readonly name = 'parameter-validation';
  readonly priority = 50;
  readonly phase = 'request' as const;

  private enabled: boolean;
  private strictMode: boolean;
  private maxStringLength: number;
  private schemaCache: ToolSchemaCache | null;

  constructor(opts: ParameterValidationOptions) {
    this.enabled = opts.enabled;
    this.strictMode = opts.strictMode ?? false;
    this.maxStringLength = opts.maxStringLength ?? 1_048_576;
    this.schemaCache = opts.schemaCache ?? null;
  }

  async evaluate(ctx: PipelineContext): Promise<SecurityDecision | null> {
    if (!this.enabled) return null;

    // Only validate tools/call and prompts/get
    if (ctx.method !== 'tools/call' && ctx.method !== 'prompts/get') {
      return null;
    }

    if (!ctx.request.params) {
      if (ctx.method === 'tools/call') {
        return {
          verdict: 'block',
          reason: 'Missing required parameters for tools/call',
          errorCode: -32602,
        };
      }
      return null;
    }

    // Basic structural checks first
    const stringCheck = this.checkStringLengths(ctx.request.params);
    if (stringCheck) return stringCheck;

    const suspiciousCheck = this.checkSuspiciousPatterns(ctx.request.params);
    if (suspiciousCheck) return suspiciousCheck;

    // ─── AJV JSON Schema validation ──────────────────────
    if (this.schemaCache && ctx.toolName) {
      const validator = this.schemaCache.getValidator(ctx.serverName, ctx.toolName);

      if (validator) {
        // Extract the actual arguments from params
        const args = ctx.method === 'tools/call'
          ? (ctx.request.params as Record<string, unknown>).arguments
          : ctx.request.params;

        const valid = validator(args ?? ctx.request.params);

        if (!valid) {
          const errors = validator.errors ?? [];
          const errorMessages = errors.map((e) => {
            const path = e.instancePath || '(root)';
            return `${path}: ${e.message}`;
          });

          return {
            verdict: 'block',
            reason: `Parameter validation failed:\n  ${errorMessages.join('\n  ')}`,
            errorCode: -32602,
            metadata: {
              validationErrors: errorMessages,
              schemaName: `${ctx.serverName}:${ctx.toolName}`,
              ajvErrors: errors.slice(0, 10), // Limit to first 10 errors
            },
          };
        }
      }
    }

    return null;
  }

  // ─── Basic checks (unchanged from Phase 1) ────────────

  private checkStringLengths(obj: unknown, depth = 0): SecurityDecision | null {
    if (depth > 10) return null;

    if (typeof obj === 'string') {
      if (obj.length > this.maxStringLength) {
        return {
          verdict: 'block',
          reason: `Parameter string exceeds maximum length of ${this.maxStringLength} characters`,
          errorCode: -32602,
        };
      }
    } else if (Array.isArray(obj)) {
      for (const item of obj) {
        const result = this.checkStringLengths(item, depth + 1);
        if (result) return result;
      }
    } else if (obj !== null && typeof obj === 'object') {
      for (const value of Object.values(obj)) {
        const result = this.checkStringLengths(value, depth + 1);
        if (result) return result;
      }
    }

    return null;
  }

  private checkSuspiciousPatterns(params: Record<string, unknown>): SecurityDecision | null {
    const serialized = JSON.stringify(params);

    // Path traversal
    if (/\.\.\/|\.\.\\/.test(serialized)) {
      return {
        verdict: 'block',
        reason: 'Path traversal pattern detected in parameters',
        errorCode: -32602,
        metadata: { pattern: 'path-traversal' },
      };
    }

    // Null byte injection (check raw params before JSON serialization)
    if (hasNullByte(params)) {
      return {
        verdict: 'block',
        reason: 'Null byte injection detected in parameters',
        errorCode: -32602,
        metadata: { pattern: 'null-byte' },
      };
    }

    // Deep nesting (potential DoS)
    const depth = this.measureDepth(params);
    if (depth > 20) {
      return {
        verdict: 'block',
        reason: `Object nesting depth ${depth} exceeds maximum of 20`,
        errorCode: -32602,
        metadata: { pattern: 'deep-nesting' },
      };
    }

    // SQL injection patterns (basic)
    if (this.hasSqlInjectionPatterns(serialized)) {
      return {
        verdict: 'block',
        reason: 'Potential SQL injection pattern detected in parameters',
        errorCode: -32602,
        metadata: { pattern: 'sql-injection' },
      };
    }

    // Command injection patterns
    if (this.hasCommandInjectionPatterns(serialized)) {
      return {
        verdict: 'block',
        reason: 'Potential command injection pattern detected in parameters',
        errorCode: -32602,
        metadata: { pattern: 'command-injection' },
      };
    }

    return null;
  }

  private hasSqlInjectionPatterns(text: string): boolean {
    const patterns = [
      /(\bSELECT\b.*\bFROM\b.*\bWHERE\b)/i,
      /(\bDROP\b\s+\bTABLE\b)/i,
      /(\bDELETE\b\s+\bFROM\b)/i,
      /(\bINSERT\b\s+\bINTO\b)/i,
      /(\bUPDATE\b\s+\bSET\b)/i,
      /(';\s*--)/,
      /(\bUNION\b\s+\bSELECT\b)/i,
    ];

    return patterns.some((p) => p.test(text));
  }

  private hasCommandInjectionPatterns(text: string): boolean {
    const patterns = [
      /\$\([^)]*\)/,           // $(cmd) subshell
      /`[^`]+`/,               // backtick subshell
      /\|\s*(?:sh|bash|cmd|powershell|python|perl|ruby|lua)(?:\s|$)/i,  // pipe to shell
      /&&\s*(?:rm|mv|cp|curl|wget|nc|telnet|chmod|chown|kill|reboot|shutdown)/i,  // chained destructive
      /\|\|\s*(?:rm|shutdown)/i,  // || fallback attack
      /;\s*(?:rm\s+-rf|mkfs|dd\s+if|cat\s+\/dev)/i,  // semicolon + destructive
      /\/dev\/(?:null|zero|random|urandom)\s+of=/i,   // dd-style overwrite
      /sudo\s+(?:rm|mv|chmod)/i,   // sudo + destructive
      /\/etc\/(?:passwd|shadow|sudoers)/i,  // targeting system files
      />\s*\/dev\/[a-z]+/,      // redirect to device
      /<(?:__import__|eval|exec|compile)\(/i,  // Python code injection
      /System\.(?:exec|getRuntime|exit)/i,  // Java code injection
      /os\.(?:system|popen|exec)/i,  // Python os injection
    ];

    return patterns.some((p) => p.test(text));
  }

  private measureDepth(obj: unknown): number {
    if (obj === null || typeof obj !== 'object') return 0;
    if (Array.isArray(obj)) {
      return 1 + Math.max(0, ...obj.map((item) => this.measureDepth(item)));
    }
    const values = Object.values(obj as Record<string, unknown>);
    if (values.length === 0) return 1;
    return 1 + Math.max(...values.map((v) => this.measureDepth(v)));
  }
}

/**
 * Check if any string value in the object tree contains a null byte.
 * This must be done before JSON.stringify since JSON escapes null bytes.
 */
function hasNullByte(obj: unknown): boolean {
  if (typeof obj === 'string') return obj.includes('\0');
  if (Array.isArray(obj)) return obj.some(hasNullByte);
  if (obj !== null && typeof obj === 'object') {
    return Object.values(obj as Record<string, unknown>).some(hasNullByte);
  }
  return false;
}
