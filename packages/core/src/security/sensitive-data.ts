import type { SecurityMiddleware, PipelineContext, SecurityDecision, SecurityEvent } from '../pipeline/types';

export type SensitiveDataAction = 'block' | 'mask' | 'log';

export interface SensitiveDataRule {
  type: string;
  action: SensitiveDataAction;
  pattern?: string;
  name?: string;
}

// ─── Built-in patterns ────────────────────────────────────────

const BUILTIN_PATTERNS: Record<string, RegExp> = {
  'credit-card': /\b(?:\d[ -]*?){13,19}\b/,
  'api-key':
    /\b(sk-[a-zA-Z0-9]{20,}|AIza[0-9A-Za-z\-_]{35}|ghp_[a-zA-Z0-9]{36}|xox[baprs]-[a-zA-Z0-9-]{10,}|hf_[a-zA-Z0-9]{25,}|key-[a-zA-Z0-9]{32,})\b/,
  email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/,
  jwt: /\beyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b/,
  phone: /\b(?:\+\d{1,3}[-.]?)?\(?\d{3}\)?[-.]?\d{3}[-.]?\d{4}\b/,
  ssn: /\b\d{3}-\d{2}-\d{4}\b/,
};

const MASK_REPLACEMENT = '***REDACTED***';

/**
 * Middleware that scans response bodies for sensitive data patterns
 * (PII, secrets, credentials) and either blocks, masks, or logs them.
 *
 * Runs in the response phase only, since sensitive data typically
 * comes FROM the upstream server.
 *
 * Priority: 120 (runs early in response pipeline)
 */
export class SensitiveDataMiddleware implements SecurityMiddleware {
  readonly name = 'sensitive-data';
  readonly priority = 120;
  readonly phase = 'response' as const;

  private detectors: CompiledDetector[];

  constructor(rules: SensitiveDataRule[]) {
    this.detectors = rules.map(compileDetector);
  }

  async evaluate(ctx: PipelineContext): Promise<SecurityDecision | null> {
    if (this.detectors.length === 0) return null;
    if (!ctx.response) return null;

    const responseText = JSON.stringify(ctx.response);

    for (const detector of this.detectors) {
      const matches = responseText.match(detector.regex);
      if (!matches || matches.length === 0) continue;

      switch (detector.action) {
        case 'block':
          return {
            verdict: 'block',
            reason: `Sensitive data detected: ${detector.label}`,
            errorCode: -32001,
            metadata: {
              detectorType: detector.type,
              matchCount: matches.length,
              // Don't include actual matches — that would be counter-productive!
            },
          };

        case 'mask': {
          // We can't directly modify the response here (middleware is read-only),
          // but we can emit a strong warning and let the proxy layer mask it.
          const maskedText = responseText.replace(detector.regex, MASK_REPLACEMENT);
          return {
            verdict: 'warn',
            reason: `Sensitive data masked: ${detector.label} (${matches.length} occurrences)`,
            metadata: {
              detectorType: detector.type,
              matchCount: matches.length,
              action: 'mask',
              maskedResponse: maskedText,
            },
          };
        }

        case 'log':
          return {
            verdict: 'warn',
            reason: `Sensitive data found (logged only): ${detector.label} (${matches.length} occurrences)`,
            metadata: {
              detectorType: detector.type,
              matchCount: matches.length,
              action: 'log',
            },
          };
      }
    }

    return null;
  }

  /**
   * Apply masking to a response body string.
   * Called by the proxy layer when a mask decision is returned.
   */
  maskResponse(raw: string): string {
    let result = raw;
    for (const detector of this.detectors) {
      if (detector.action === 'mask') {
        result = result.replace(detector.regex, MASK_REPLACEMENT);
      }
    }
    return result;
  }
}

// ─── Detector compilation ─────────────────────────────────────

interface CompiledDetector {
  type: string;
  label: string;
  regex: RegExp;
  action: SensitiveDataAction;
}

function compileDetector(rule: SensitiveDataRule): CompiledDetector {
  let regex: RegExp;

  if (rule.type === 'custom' && rule.pattern) {
    regex = new RegExp(rule.pattern, 'gi');
  } else if (BUILTIN_PATTERNS[rule.type]) {
    regex = BUILTIN_PATTERNS[rule.type]!;
  } else {
    throw new Error(`Unknown sensitive data detector type: ${rule.type}`);
  }

  return {
    type: rule.type,
    label: rule.name ?? rule.type,
    regex,
    action: rule.action,
  };
}
