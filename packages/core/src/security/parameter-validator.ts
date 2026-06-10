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

    // Collect raw string values for checks that fail on JSON-escaped text
    const rawValues = collectStringValues(params);

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

    // ─── Expanded Injection Detection ─────────────────────────

    // SQL injection
    const sqlResult = this.detectSqlInjection(serialized);
    if (sqlResult) return sqlResult;

    // Command injection
    const cmdResult = this.detectCommandInjection(serialized, rawValues);
    if (cmdResult) return cmdResult;

    // NoSQL injection
    const nosqlResult = this.detectNoSqlInjection(serialized, params, rawValues);
    if (nosqlResult) return nosqlResult;

    // XSS (Cross-Site Scripting)
    const xssResult = this.detectXss(serialized);
    if (xssResult) return xssResult;

    // SSTI (Server-Side Template Injection)
    const sstiResult = this.detectSsti(serialized);
    if (sstiResult) return sstiResult;

    // LDAP injection
    const ldapResult = this.detectLdapInjection(serialized);
    if (ldapResult) return ldapResult;

    // XXE (XML External Entity)
    const xxeResult = this.detectXxe(serialized);
    if (xxeResult) return xxeResult;

    // CRLF / HTTP header injection (check raw values too — JSON.stringify escapes \r\n)
    const crlfResult = this.detectCrlfInjection(serialized, rawValues);
    if (crlfResult) return crlfResult;

    // Prototype pollution (check raw values for JSON-embedded payloads)
    const protoResult = this.detectPrototypePollution(params, rawValues);
    if (protoResult) return protoResult;

    // ReDoS attack via malicious regex patterns
    const redosResult = this.detectReDoS(serialized);
    if (redosResult) return redosResult;

    return null;
  }

  // ─── SQL Injection Detection (12 patterns) ─────────────────

  private detectSqlInjection(text: string): SecurityDecision | null {
    const patterns: Array<[RegExp, string]> = [
      [/(\bSELECT\b.*\bFROM\b.*\bWHERE\b)/i, 'SELECT..FROM..WHERE'],
      [/(\bDROP\b\s+\bTABLE\b)/i, 'DROP TABLE'],
      [/(\bDROP\b\s+\bDATABASE\b)/i, 'DROP DATABASE'],
      [/(\bDELETE\b\s+\bFROM\b)/i, 'DELETE FROM'],
      [/(\bINSERT\b\s+\bINTO\b)/i, 'INSERT INTO'],
      [/(\bUPDATE\b\s+\w+\s+\bSET\b)/i, 'UPDATE ... SET'],
      [/(';\s*--)/, 'SQL comment escape'],
      [/(\bUNION\b\s+\bSELECT\b)/i, 'UNION SELECT'],
      [/(\bALTER\b\s+\bTABLE\b)/i, 'ALTER TABLE'],
      [/(\bTRUNCATE\b\s+\bTABLE\b)/i, 'TRUNCATE TABLE'],
      [/(\bEXEC\b\s+(?:sp_|xp_|@))/i, 'EXEC stored procedure'],
      [/(\bEXECUTE\b\s+(?:sp_|xp_|@))/i, 'EXECUTE stored procedure'],
      [/(\bSLEEP\b\s*\(|\bBENCHMARK\b\s*\()/i, 'SQL timing attack'],
    ];

    for (const [regex, label] of patterns) {
      if (regex.test(text)) {
        return {
          verdict: 'block',
          reason: `SQL injection pattern detected: ${label}`,
          errorCode: -32602,
          metadata: { pattern: 'sql-injection', subPattern: label },
        };
      }
    }
    return null;
  }

  // ─── NoSQL Injection Detection (14 patterns) ───────────────

  private detectNoSqlInjection(text: string, params: Record<string, unknown>, rawValues: string[]): SecurityDecision | null {
    // MongoDB operators in keys (require raw object check, not serialized)
    const keyCheck = hasNoSqlOperators(params);
    if (keyCheck) {
      return {
        verdict: 'block',
        reason: `NoSQL injection pattern detected: ${keyCheck}`,
        errorCode: -32602,
        metadata: { pattern: 'nosql-injection', subPattern: keyCheck },
      };
    }

    // Build a combined search target: serialized JSON + raw string values
    // (Raw values preserve unescaped quotes in JSON-embedded payloads)
    const allText = [text, ...rawValues].join('\n');

    const patterns: Array<[RegExp, string]> = [
      // MongoDB operators in values
      [/\{\s*["\\]*\$where["\\]*\s*:/, '$where operator'],
      [/\{\s*["\\]*\$regex["\\]*\s*:/, '$regex operator'],
      [/\{\s*["\\]*\$ne["\\]*\s*:/, '$ne operator'],
      [/\{\s*["\\]*\$gt["\\]*\s*:\s*\{\s*["\\]*\$regex/, '$gt + $regex chained'],
      // JavaScript execution in MongoDB
      [/\$where["\\]*\s*:\s*['"\\]*(?:function|this\.|while\s*\()/i, '$where with JS'],
      [/\$expr["\\]*\s*:/, '$expr operator'],
      // Bypass patterns
      [/\{\s*["\\]*\$gt["\\]*\s*:\s*""/, '$gt empty string bypass'],
      [/\{"\$nin"\s*:\s*\[\]/, '$nin empty array bypass'],
      [/\{\s*"\$nin"\s*:\s*\[/, '$nin operator in value'],
      // Redis injection
      [/\b(?:CONFIG\s+SET|FLUSHALL|FLUSHDB|SHUTDOWN|SAVE)\b/i, 'Redis destructive command'],
      // MongoDB connection string manipulation
      [/mongodb(?:\+srv)?:\/\/[^@]+@/, 'MongoDB connection string'],
    ];

    for (const [regex, label] of patterns) {
      if (regex.test(allText)) {
        return {
          verdict: 'block',
          reason: `NoSQL injection pattern detected: ${label}`,
          errorCode: -32602,
          metadata: { pattern: 'nosql-injection', subPattern: label },
        };
      }
    }
    return null;
  }

  // ─── Command Injection Detection (20 patterns) ─────────────

  private detectCommandInjection(text: string, rawValues: string[]): SecurityDecision | null {
    const allText = [text, ...rawValues].join('\n');

    const patterns: Array<[RegExp, string]> = [
      // Unix shell
      [/\$\([^)]*\)/, '$(cmd) subshell'],
      [/`[^`]+`/, '`cmd` backtick'],
      [/\|\s*(?:sh|bash|zsh|fish|cmd|powershell|pwsh|python|perl|ruby|lua|node)\b/i, 'pipe to shell'],
      // Chained commands
      [/&&\s*(?:rm|mv|cp|curl|wget|nc|telnet|chmod|chown|kill|reboot|shutdown|nohup|setsid)/i, 'chained destructive cmd'],
      [/\|\|\s*(?:rm|shutdown|reboot|halt)/i, '|| fallback attack'],
      [/;\s*(?:rm\s+-rf|mkfs|dd\s+if=|cat\s+\/dev|echo\s+[^|]+\||wget\s+|curl\s+)/i, 'semicolon destructive'],
      // Device manipulation (both orders: /dev/sda of=X and of=/dev/sda)
      [/(?:\/dev\/(?:null|zero|random|urandom|mem|kmem|sda|hd[a-z])\s+of=|\bof=\s*\/dev\/(?:null|zero|random|urandom|mem|kmem|sda|hd[a-z]))/i, 'dd device overwrite'],
      [/sudo\s+(?:rm|mv|chmod|chown|kill|reboot|shutdown)/i, 'sudo destructive'],
      [/\/etc\/(?:passwd|shadow|sudoers|crontab|hosts|resolv\.conf)/i, 'system file targeting'],
      [/>\s*\/dev\/[a-z]+/, 'redirect to device'],
      [/>\s*\/etc\/[a-z]/, 'redirect to /etc'],
      [/\bchmod\s+[0-7]*7[0-7]*7/, 'chmod 777'],
      [/\bchown\s+-R\s+\S+\s+\//, 'chown -R /'],
      // Code injection
      [/<(?:__import__|eval|exec|compile|__builtins__)\(/i, 'Python code injection'],
      [/os\.(?:system|popen|popen2|popen3|popen4|execv|execve|spawn[lp]?)\s*\(/i, 'Python os injection'],
      [/subprocess\.(?:call|run|Popen|check_output|getoutput)\s*\(/i, 'Python subprocess'],
      [/System\.(?:exec|getRuntime|exit|gc)\s*\(/i, 'Java code injection'],
      [/Runtime\.getRuntime\(\)\.exec/, 'Java Runtime.exec'],
      [/ProcessBuilder\s*\(/, 'Java ProcessBuilder'],
      [/\bchild_process\b.*\bexec\b/i, 'Node.js child_process'],
    ];

    for (const [regex, label] of patterns) {
      if (regex.test(allText)) {
        return {
          verdict: 'block',
          reason: `Command injection pattern detected: ${label}`,
          errorCode: -32602,
          metadata: { pattern: 'command-injection', subPattern: label },
        };
      }
    }

    for (const [regex, label] of patterns) {
      if (regex.test(text)) {
        return {
          verdict: 'block',
          reason: `Command injection pattern detected: ${label}`,
          errorCode: -32602,
          metadata: { pattern: 'command-injection', subPattern: label },
        };
      }
    }
    return null;
  }

  // ─── XSS Detection (16 patterns) ───────────────────────────

  private detectXss(text: string): SecurityDecision | null {
    const patterns: Array<[RegExp, string]> = [
      // Script tags
      [/<\s*script[^>]*>[\s\S]*?<\s*\/\s*script\s*>/i, '<script> tag'],
      [/<\s*script[^>]*\/?\s*>/i, '<script> self-closing'],
      // Event handlers
      [/\bon\w+\s*=\s*["'][^"']*(?:javascript|eval|alert|prompt|confirm|document\.cookie)/i, 'on* event handler'],
      [/\bon\w+\s*=\s*[^"'\s>]+/i, 'on* inline handler'],
      // JavaScript URIs
      [/javascript\s*:/i, 'javascript: URI'],
      [/data\s*:\s*text\/html/i, 'data:text/html URI'],
      // DOM manipulation
      [/document\.(?:cookie|write|writeln|domain|URL)/i, 'document DOM manipulation'],
      [/\.innerHTML\s*=|\.outerHTML\s*=/i, 'innerHTML assignment'],
      [/eval\s*\([^)]*\)/, 'eval() call'],
      // HTML injection patterns
      [/<\s*(?:iframe|frame|object|embed|applet|meta|link|base)\b/i, 'dangerous HTML tag'],
      [/<\s*img[^>]+(?:src|onerror)\s*=/i, '<img> with event'],
      [/<\s*svg[^>]*onload/i, '<svg onload>'],
      [/<\s*body[^>]*onload/i, '<body onload>'],
      // Encoding bypasses
      [/(?:&#x?[0-9a-f]+;){4,}/i, 'HTML entity encoding'],
      [/\\x[0-9a-f]{2}/i, 'hex escape sequence'],
      [/\\u[0-9a-f]{4}/i, 'unicode escape sequence'],
      // CSS injection
      [/expression\s*\(/i, 'CSS expression()'],
      [/url\s*\(\s*["']?\s*(?:javascript|data):/i, 'CSS url() with JS'],
    ];

    for (const [regex, label] of patterns) {
      if (regex.test(text)) {
        return {
          verdict: 'block',
          reason: `XSS pattern detected: ${label}`,
          errorCode: -32602,
          metadata: { pattern: 'xss', subPattern: label },
        };
      }
    }
    return null;
  }

  // ─── SSTI Detection (18 patterns) ──────────────────────────

  private detectSsti(text: string): SecurityDecision | null {
    const patterns: Array<[RegExp, string]> = [
      // Jinja2 / Flask
      [/\{\{[\s\S]*?(?:__class__|__bases__|__mro__|__subclasses__|__globals__|__init__)[\s\S]*?\}\}/, 'Jinja2 dunder traversal'],
      [/\{\{[\s\S]*?config[\s\S]*?\}\}/, 'Jinja2 config access'],
      [/\{\{[\s\S]*?self[\s\S]*?\}\}/, 'Jinja2 self reference'],
      [/\{\{[\s\S]*?request[\s\S]*?\}\}/, 'Jinja2 request access'],
      [/\{\{[\s\S]*?lipsum\s*\([\s\S]*?\}\}/, 'Jinja2 lipsum'],
      [/{%\s*(?:import|include|extends|macro|set)\s+/, 'Jinja2 control block'],
      // Twig / PHP
      [/\(\s*getenv\s*\(/i, 'Twig getenv'],
      [/\b(?:system|exec|passthru|shell_exec|popen|proc_open)\s*\(/i, 'PHP code exec'],
      [/\b(?:file_get_contents|file_put_contents|unlink|rename)\s*\(/i, 'PHP file ops'],
      // FreeMarker / Java
      [/\$\{(?:__)?(?:class|getClass|forName)[\s\S]*?\}/, 'FreeMarker class access'],
      [/\$\{[\s\S]*?\.getClass\(\)[\s\S]*?\}/, 'FreeMarker getClass'],
      // Velocity
      [/#(?:set|if|foreach|macro|include|parse|evaluate)\s*\(/, 'Velocity directive'],
      // Handlebars / Mustache
      [/\{\{#(?:with|each|if|unless|lookup)\s+/, 'Handlebars block helper'],
      // ERB / Ruby
      [/<%=[\s\S]*?(?:system|exec|eval|`|IO\.|File\.|Kernel\.)[\s\S]*?%>/, 'ERB code execution'],
      // Smarty / PHP
      [/\{(?:php|include_php|literal|fetch|math)\}/i, 'Smarty dangerous tag'],
      // General SSTI payloads
      [/['"]\.__class__\.__mro__/, 'Python MRO chain'],
      [/['"]\.__class__\.__bases__/, 'Python bases chain'],
      [/\bupdate\s+\w+\s+set\s+\w+\s*=\s*\w+\s*\|\|\s*(?:sleep|pg_sleep)/i, 'SQL via SSTI'],
    ];

    for (const [regex, label] of patterns) {
      if (regex.test(text)) {
        return {
          verdict: 'block',
          reason: `SSTI pattern detected: ${label}`,
          errorCode: -32602,
          metadata: { pattern: 'ssti', subPattern: label },
        };
      }
    }
    return null;
  }

  // ─── LDAP Injection Detection (10 patterns) ────────────────

  private detectLdapInjection(text: string): SecurityDecision | null {
    const patterns: Array<[RegExp, string]> = [
      // LDAP filter injection
      [/(?:^|[^\\])\(\s*(?:\||\&|\!)\s*\(/, 'LDAP logical operator'],
      [/(?:\*\)\s*\()|(?:\(.*\*.*\(.*\))/, 'LDAP wildcard injection'],
      [/\b(?:objectClass|cn|ou|dc|uid|sn)\s*=\s*\*/, 'LDAP wildcard match'],
      // LDAP DN injection
      [/\\00/, 'LDAP null byte'],
      [/[^\\]\\2a/i, 'LDAP escape bypass'],
      // LDAP query manipulation
      [/(?:^|[^\\])\(\s*!\s*\(/, 'LDAP NOT operator'],
      [/(?:^|[^\\])\(\s*\|/, 'LDAP OR operator'],
      [/admin\*\)/, 'LDAP admin wildcard bypass'],
      // LDAP injection via attributes
      [/\(.*\|.*\(.*\).*\)/, 'LDAP nested OR'],
      [/userPassword\s*=/, 'LDAP password attribute'],
    ];

    for (const [regex, label] of patterns) {
      if (regex.test(text)) {
        return {
          verdict: 'block',
          reason: `LDAP injection pattern detected: ${label}`,
          errorCode: -32602,
          metadata: { pattern: 'ldap-injection', subPattern: label },
        };
      }
    }
    return null;
  }

  // ─── XXE Detection (8 patterns) ────────────────────────────

  private detectXxe(text: string): SecurityDecision | null {
    // Also check raw values for unescaped quotes
    const patterns: Array<[RegExp, string]> = [
      // External entity declarations (handle both " and escaped \")
      [/<!ENTITY\s+\S+\s+(?:SYSTEM|PUBLIC)\s+["'\\]/, 'DOCTYPE entity declaration'],
      [/<!ENTITY\s+\S+\s+SYSTEM\s+["'\\](?:file|http|https|ftp|php|expect|gopher):/, 'external entity'],
      [/%\s*\S+;\s*(?:SYSTEM|PUBLIC)/, 'parameter entity'],
      // XInclude
      [/<xi:include\s+/i, 'XInclude attack'],
      [/xmlns:xi\s*=\s*["'\\]http:\/\/www\.w3\.org\/2001\/XInclude/, 'XInclude namespace'],
      // Billion laughs (3+ consecutive entity declarations, handles escaped quotes)
      [/(?:<!ENTITY\s+\w+\s+["'\\\w]+>\s*){3,}/, 'billion laughs expansion'],
      // XML style XSLT
      [/<\?xml-stylesheet\s+/i, 'xml-stylesheet PI'],
      [/<xsl:(?:stylesheet|transform|include|import)\s+/i, 'XSLT injection'],
    ];

    for (const [regex, label] of patterns) {
      if (regex.test(text)) {
        return {
          verdict: 'block',
          reason: `XXE pattern detected: ${label}`,
          errorCode: -32602,
          metadata: { pattern: 'xxe', subPattern: label },
        };
      }
    }
    return null;
  }

  // ─── CRLF / Header Injection Detection (8 patterns) ────────

  private detectCrlfInjection(text: string, rawValues: string[]): SecurityDecision | null {
    const allText = [text, ...rawValues].join('\n');

    const patterns: Array<[RegExp, string]> = [
      // CRLF sequences (check raw values for literal \r\n, and escaped form in serialized)
      [/\r\n/, 'CRLF (\\r\\n) sequence'],
      [/\\r\\n/, 'escaped CRLF'],
      [/(?:%0[dD]%0[aA])/, 'URL-encoded CRLF'],
      [/(?:%0[dD])/, 'URL-encoded CR'],
      [/(?:%0[aA])/, 'URL-encoded LF'],
      // HTTP header injection
      [/Content-Type\s*:\s*[\s\S]*\r?\n/i, 'Content-Type header injection'],
      [/Set-Cookie\s*:\s*[\s\S]*\r?\n/i, 'Set-Cookie header injection'],
      [/Location\s*:\s*[\s\S]*\r?\n/i, 'Location header injection'],
      [/\n\s*(?:HTTP\/|Host:|User-Agent:|Cookie:|Authorization:)/i, 'HTTP header smuggling'],
    ];

    for (const [regex, label] of patterns) {
      if (regex.test(allText)) {
        return {
          verdict: 'block',
          reason: `CRLF/header injection detected: ${label}`,
          errorCode: -32602,
          metadata: { pattern: 'crlf-injection', subPattern: label },
        };
      }
    }
    return null;
  }

  // ─── Prototype Pollution Detection (10 patterns) ───────────

  private detectPrototypePollution(params: Record<string, unknown>, rawValues: string[]): SecurityDecision | null {
    const dangerousKeys = [
      '__proto__',
      'constructor',
      'prototype',
      '__defineGetter__',
      '__defineSetter__',
      '__lookupGetter__',
      '__lookupSetter__',
    ];

    const found = findDangerousKeys(params, new Set(dangerousKeys));
    if (found) {
      return {
        verdict: 'block',
        reason: `Prototype pollution key detected: "${found}"`,
        errorCode: -32602,
        metadata: { pattern: 'prototype-pollution', subPattern: found },
      };
    }

    // Check serialized + raw values for JSON-embedded proto pollution
    const allText = [JSON.stringify(params), ...rawValues].join('\n');

    if (/"__proto__"\s*:\s*\{/.test(allText)) {
      return {
        verdict: 'block',
        reason: 'Prototype pollution via __proto__ assignment detected',
        errorCode: -32602,
        metadata: { pattern: 'prototype-pollution', subPattern: '__proto__ assignment' },
      };
    }

    if (/"constructor"\s*:\s*\{.*"prototype"/.test(allText)) {
      return {
        verdict: 'block',
        reason: 'Prototype pollution via constructor.prototype detected',
        errorCode: -32602,
        metadata: { pattern: 'prototype-pollution', subPattern: 'constructor.prototype' },
      };
    }

    return null;
  }

  // ─── ReDoS Detection (6 patterns) ──────────────────────────

  private detectReDoS(text: string): SecurityDecision | null {
    // Only check if the text contains regex-looking patterns (parentheses + quantifiers)
    // Avoid checking all normal text to prevent false positives
    if (!/\(.+\)[+*{]/.test(text)) return null;

    const patterns: Array<[RegExp, string]> = [
      // Exponential backtracking: (expr+)+ or (expr*)+
      [/\([^)]+[+*]\)[+{]/, 'nested quantifier'],
      // Evil regex: (. *)+ or (.+)+ patterns
      [/\(\.\*\)\+/, '(. *)+ repetition'],
      [/\(\.\+\)\+/, '(.+)+ repetition'],
      // Evil regex: ([chars]+)*  — the classic backtracking bomb
      [/\(\[[^\]]+\][+*]\)[+*]/, '([chars]+)* evil pattern'],
      // Repeated group with lower bound: (expr){n,}
      [/\([^)]+\)\{\d+,\}/, 'group with lower bound repetition'],
      // Large bounded repetition: (expr){100,}
      [/\([^)]+\)\{[5-9]\d+,\}/, 'group with high repetition bound'],
    ];

    for (const [regex, label] of patterns) {
      if (regex.test(text)) {
        return {
          verdict: 'warn',
          reason: `Potential ReDoS pattern detected in input: ${label}`,
          errorCode: -32602,
          metadata: { pattern: 'redos', subPattern: label },
        };
      }
    }
    return null;
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

// ─── Module-level helpers ────────────────────────────────────

/**
 * Collect all string values from an object tree (recursive).
 * Returns raw strings that preserve unescaped characters,
 * used for checking patterns that fail on JSON-escaped strings.
 */
function collectStringValues(obj: unknown, depth = 0): string[] {
  if (depth > 10 || obj === null || typeof obj !== 'object') return [];
  const results: string[] = [];

  if (Array.isArray(obj)) {
    for (const item of obj) {
      if (typeof item === 'string') results.push(item);
      else results.push(...collectStringValues(item, depth + 1));
    }
  } else {
    for (const value of Object.values(obj as Record<string, unknown>)) {
      if (typeof value === 'string') results.push(value);
      else results.push(...collectStringValues(value, depth + 1));
    }
  }

  return results;
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

/**
 * Check if any key in the object tree contains NoSQL operators.
 * These are typically used in MongoDB injection via $ operators.
 */
function hasNoSqlOperators(obj: unknown, depth = 0): string | null {
  if (depth > 10 || obj === null || typeof obj !== 'object') return null;

  // Check for dangerous keys at this level
  if (obj !== null && typeof obj === 'object' && !Array.isArray(obj)) {
    for (const key of Object.keys(obj as Record<string, unknown>)) {
      // NoSQL operator keys
      if (/^\$(?:where|regex|ne|gt|gte|lt|lte|in|nin|and|or|nor|not|exists|type|mod|expr|text|search|elemMatch|all|size|jsonSchema|function|return|query)/i.test(key)) {
        return key;
      }
      // Check nested objects
      const value = (obj as Record<string, unknown>)[key];
      const nested = hasNoSqlOperators(value, depth + 1);
      if (nested) return `${key}.${nested}`;
    }
  }

  if (Array.isArray(obj)) {
    for (let i = 0; i < obj.length; i++) {
      const nested = hasNoSqlOperators(obj[i], depth + 1);
      if (nested) return `[${i}].${nested}`;
    }
  }

  return null;
}

/**
 * Recursively check if any key in the object tree matches dangerous keys.
 * Used for prototype pollution detection.
 */
function findDangerousKeys(obj: unknown, dangerous: Set<string>, depth = 0): string | null {
  if (depth > 10 || obj === null || typeof obj !== 'object') return null;

  if (obj !== null && typeof obj === 'object' && !Array.isArray(obj)) {
    for (const key of Object.keys(obj as Record<string, unknown>)) {
      if (dangerous.has(key)) return key;
      const value = (obj as Record<string, unknown>)[key];
      const nested = findDangerousKeys(value, dangerous, depth + 1);
      if (nested) return nested;
    }
  }

  if (Array.isArray(obj)) {
    for (const item of obj) {
      const nested = findDangerousKeys(item, dangerous, depth + 1);
      if (nested) return nested;
    }
  }

  return null;
}
