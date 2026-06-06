import type { SecurityMiddleware, PipelineContext, SecurityDecision } from '../pipeline/types';

export interface ContentFilterRuleDef {
  pattern: string;
  action: 'block' | 'mask' | 'log';
  phase: 'input' | 'output' | 'both';
}

/**
 * Middleware that scans request parameters and response bodies
 * for dangerous patterns (command injection, SQL injection, XSS, etc.).
 *
 * Priority: 60 (input), 100 (output)
 */
export class ContentFilterMiddleware implements SecurityMiddleware {
  readonly name = 'content-filter';
  readonly priority = 60;
  readonly phase = 'both' as const;

  private rules: CompiledRule[];

  constructor(rules: ContentFilterRuleDef[]) {
    this.rules = rules.map(compileRule);
  }

  async evaluate(ctx: PipelineContext): Promise<SecurityDecision | null> {
    if (this.rules.length === 0) return null;

    // Determine the text to scan based on phase
    let target: string | undefined;

    if (ctx.response && ctx.response) {
      // Response phase
      target = JSON.stringify(ctx.response);
    } else {
      // Request phase
      target = JSON.stringify(ctx.request.params ?? {});
    }

    if (!target) return null;

    for (const rule of this.rules) {
      // Skip rules not applicable to this phase
      const isRequest = !ctx.response;
      if (rule.phase === 'input' && !isRequest) continue;
      if (rule.phase === 'output' && isRequest) continue;

      const match = rule.regex.test(target);
      if (!match) continue;

      switch (rule.action) {
        case 'block':
          return {
            verdict: 'block',
            reason: `Content filter matched pattern: "${rule.pattern}"`,
            errorCode: -32001,
            metadata: { pattern: rule.pattern, phase: isRequest ? 'input' : 'output' },
          };

        case 'mask':
          // Return a modified response with the pattern masked
          // (The actual masking happens in the response transformer)
          return {
            verdict: 'warn',
            reason: `Content filter masked pattern: "${rule.pattern}"`,
            metadata: { pattern: rule.pattern, action: 'mask' },
          };

        case 'log':
          return {
            verdict: 'warn',
            reason: `Content filter detected pattern: "${rule.pattern}"`,
            metadata: { pattern: rule.pattern, action: 'log' },
          };
      }
    }

    return null;
  }
}

interface CompiledRule {
  pattern: string;
  regex: RegExp;
  action: ContentFilterRuleDef['action'];
  phase: ContentFilterRuleDef['phase'];
}

function compileRule(rule: ContentFilterRuleDef): CompiledRule {
  return {
    pattern: rule.pattern,
    regex: new RegExp(rule.pattern, 'gi'),
    action: rule.action,
    phase: rule.phase,
  };
}
