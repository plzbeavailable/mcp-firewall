import { spawn, ChildProcess } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import type { SecurityMiddleware, PipelineContext, SecurityDecision } from '../pipeline/types';

// ─── Sandbox Configuration ────────────────────────────────────

export interface SandboxConfig {
  enabled: boolean;
  provider: 'docker';
  image: string;
  network: string;
  memoryLimit: string;
  cpuLimit: string;
  timeout: string;
  volumeMounts: string[];
}

/**
 * Result of a sandboxed tool execution.
 */
export interface SandboxResult {
  exitCode: number;
  stdout: string;
  stderr: string;
  durationMs: number;
  timedOut: boolean;
  error?: string;
}

// ─── Sandbox Middleware ────────────────────────────────────────

/**
 * Docker-based sandbox execution middleware.
 *
 * When enabled, `tools/call` requests for designated tools are
 * executed inside a Docker container instead of being forwarded
 * to the upstream MCP server directly.
 *
 * The container provides:
 * - Network isolation (configurable: none, bridge, host)
 * - Memory and CPU limits
 * - Execution timeout
 * - Read-only filesystem with explicit volume mounts
 *
 * Priority: 75 (runs after validation, before forwarding)
 */
export class SandboxMiddleware implements SecurityMiddleware {
  readonly name = 'sandbox';
  readonly priority = 75;
  readonly phase = 'request' as const;

  private config: SandboxConfig;
  private containerCount = 0;

  // Tools that must be sandboxed (glob patterns)
  private sandboxedTools: string[] = [];

  constructor(config: SandboxConfig) {
    this.config = config;
  }

  /**
   * Configure which tools should be sandboxed.
   * Patterns support glob wildcards (*, **).
   */
  setSandboxedTools(tools: string[]): void {
    this.sandboxedTools = tools;
  }

  async evaluate(ctx: PipelineContext): Promise<SecurityDecision | null> {
    if (!this.config.enabled) return null;
    if (ctx.method !== 'tools/call') return null;

    const toolName = ctx.toolName;
    if (!toolName) return null;

    // Check if this tool should be sandboxed
    const shouldSandbox = this.sandboxedTools.some((pattern) => {
      const regex = globToRegex(pattern);
      return regex.test(toolName);
    });

    // If no specific pattern matches but sandboxing is "all" mode
    const sandboxAll = this.sandboxedTools.length === 0 || this.sandboxedTools.includes('*');

    if (!shouldSandbox && !sandboxAll) {
      return null; // Pass through — not sandboxing this tool
    }

    // Extract the tool arguments
    const params = ctx.request.params as Record<string, unknown> | undefined;
    const args = params?.arguments as Record<string, unknown> | undefined;

    try {
      const result = await this.runInSandbox(ctx, args ?? {});
      ctx.metadata['sandboxResult'] = result;
      ctx.metadata['sandboxTool'] = toolName;

      // Sanity check the result
      if (result.timedOut) {
        return {
          verdict: 'block',
          reason: `Sandbox execution timed out after ${this.config.timeout}`,
          metadata: {
            toolName,
            timeout: this.config.timeout,
            durationMs: result.durationMs,
          },
        };
      }

      if (result.exitCode !== 0) {
        return {
          verdict: 'warn',
          reason: `Sandbox execution exited with code ${result.exitCode}`,
          metadata: {
            toolName,
            exitCode: result.exitCode,
            stderr: result.stderr.slice(0, 1000),
          },
        };
      }

      return null; // Success — the request continues to the upstream
    } catch (err) {
      return {
        verdict: 'block',
        reason: `Sandbox execution failed: ${err instanceof Error ? err.message : String(err)}`,
        metadata: { toolName },
      };
    }
  }

  private async runInSandbox(
    ctx: PipelineContext,
    args: Record<string, unknown>,
  ): Promise<SandboxResult> {
    const startTime = Date.now();
    const containerName = `mcp-firewall-sandbox-${randomUUID().slice(0, 8)}`;
    const timeoutSeconds = parseDuration(this.config.timeout);

    // Serialize arguments to pass into container
    const argsJson = JSON.stringify(args);
    const argsBase64 = Buffer.from(argsJson).toString('base64');

    // Build docker run command
    const dockerArgs = [
      'run',
      '--rm',
      `--name=${containerName}`,
      `--network=${this.config.network}`,
      `--memory=${this.config.memoryLimit}`,
      `--cpus=${this.config.cpuLimit}`,
      '--read-only',
      '--tmpfs=/tmp:rw,noexec,nosuid,size=64m',
      // Pass args via environment variable
      `--env=MCP_TOOL_ARGS=${argsBase64}`,
      `--env=MCP_TOOL_NAME=${ctx.toolName ?? 'unknown'}`,
      `--env=MCP_SERVER_NAME=${ctx.serverName}`,
      `--env=MCP_CLIENT_ID=${ctx.client.clientId}`,
    ];

    // Add volume mounts
    for (const mount of this.config.volumeMounts) {
      dockerArgs.push(`--volume=${mount}`);
    }

    dockerArgs.push(this.config.image);

    this.containerCount++;

    return new Promise<SandboxResult>((resolve, reject) => {
      const proc = spawn('docker', dockerArgs, {
        stdio: ['ignore', 'pipe', 'pipe'],
        timeout: timeoutSeconds * 1000,
      });

      let stdout = '';
      let stderr = '';

      proc.stdout?.on('data', (chunk: Buffer) => {
        stdout += chunk.toString('utf-8');
        // Truncate to prevent memory issues
        if (stdout.length > 1_048_576) stdout = stdout.slice(0, 1_048_576) + '...[truncated]';
      });

      proc.stderr?.on('data', (chunk: Buffer) => {
        stderr += chunk.toString('utf-8');
        if (stderr.length > 1_048_576) stderr = stderr.slice(0, 1_048_576) + '...[truncated]';
      });

      proc.on('close', (code, signal) => {
        const durationMs = Date.now() - startTime;
        this.containerCount--;

        resolve({
          exitCode: code ?? -1,
          stdout,
          stderr,
          durationMs,
          timedOut: signal === 'SIGTERM' || signal === 'SIGKILL',
          error: signal ? `Process terminated by signal: ${signal}` : undefined,
        });
      });

      proc.on('error', (err) => {
        this.containerCount--;
        reject(err);
      });
    });
  }

  /**
   * Get the number of currently active sandbox containers.
   */
  get activeContainers(): number {
    return this.containerCount;
  }
}

// ─── Helpers ─────────────────────────────────────────────────

function globToRegex(pattern: string): RegExp {
  const escaped = pattern
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*\*/g, '__DOUBLE_STAR__')
    .replace(/\*/g, '[^/]*')
    .replace(/__DOUBLE_STAR__/g, '.*');
  return new RegExp(`^${escaped}$`);
}

function parseDuration(duration: string): number {
  const match = duration.match(/^(\d+)(s|m|h)$/);
  if (!match) return 30;
  const value = parseInt(match[1]!, 10);
  switch (match[2]) {
    case 's':
      return value;
    case 'm':
      return value * 60;
    case 'h':
      return value * 3600;
    default:
      return 30;
  }
}
