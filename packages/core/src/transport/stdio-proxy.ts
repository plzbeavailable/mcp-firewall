import { spawn, ChildProcess } from 'node:child_process';
import { createInterface, Interface } from 'node:readline';
import { parseMessage, serializeMessage, JSONRPCMessage } from './mcp-types';

export interface StdioProxyOptions {
  /** Command to spawn the upstream MCP server */
  command: string;
  /** Arguments to the command */
  args?: string[];
  /** Environment variables to pass to the child process */
  env?: Record<string, string>;
  /** Callback for each message flowing client → server */
  onRequest?: (msg: JSONRPCMessage) => Promise<JSONRPCMessage | null>;
  /** Callback for each message flowing server → client */
  onResponse?: (msg: JSONRPCMessage) => Promise<JSONRPCMessage | null>;
  /** Callback when the child process exits */
  onExit?: (code: number | null, signal: string | null) => void;
  /** Callback on proxy errors */
  onError?: (err: Error) => void;
}

/**
 * StdioProxy implements a transparent stdio-to-stdio proxy between
 * the parent process (AI client) and a child process (MCP server).
 *
 * Architecture:
 *
 *   Parent (AI Client)                    Child (MCP Server)
 *       │                                       │
 *       │  stdin (parent writes)                │
 *       ▼                                       │
 *   ┌────────────┐                              │
 *   │ StdioProxy │ ──stdin──► (child's stdin)  │
 *   │            │                              │
 *   │            │ ◄─stdout─ (child's stdout)  │
 *   └────────────┘                              │
 *       │                                       │
 *       │  stdout (parent reads)                │
 *       ▼                                       ▼
 *
 * The proxy forwards all JSON-RPC messages bidirectionally.
 * Interceptors can modify or block messages.
 */
export class StdioProxy {
  private child: ChildProcess | null = null;
  private parentStdin: Interface | null = null;
  private childStdout: Interface | null = null;
  private options: Required<StdioProxyOptions>;

  constructor(options: StdioProxyOptions) {
    this.options = {
      command: options.command,
      args: options.args ?? [],
      env: options.env ?? {},
      onRequest: options.onRequest ?? (async (msg) => msg),
      onResponse: options.onResponse ?? (async (msg) => msg),
      onExit: options.onExit ?? (() => {}),
      onError: options.onError ?? (() => {}),
    };
  }

  /**
   * Start the proxy. Spawns the child process and sets up
   * bidirectional communication.
   */
  start(): void {
    const childEnv = { ...process.env, ...this.options.env };

    this.child = spawn(this.options.command, this.options.args, {
      stdio: ['pipe', 'pipe', 'inherit'], // stderr goes to parent stderr
      env: childEnv,
      // Windows: hide the console window for the child process
      windowsHide: true,
    });

    if (!this.child.stdin || !this.child.stdout) {
      throw new Error('Failed to spawn child process: stdin/stdout not available');
    }

    // ── Parent stdin → Child stdin ──────────────────────────
    this.parentStdin = createInterface({
      input: process.stdin,
      crlfDelay: Infinity,
    });

    this.parentStdin.on('line', async (line: string) => {
      const trimmed = line.trim();
      if (!trimmed) return;

      try {
        const msg = parseMessage(trimmed);
        if (!msg) {
          // Not JSON-RPC; forward as-is (could be legacy or debugging)
          this.child!.stdin!.write(line + '\n');
          return;
        }

        // Run request interceptor
        const processed = await this.options.onRequest(msg);

        if (processed !== null) {
          // Forward to child
          this.child!.stdin!.write(serializeMessage(processed));
        } else {
          // Message was blocked — but the interceptor should have
          // already written the error response to stdout.
          // Nothing to forward.
        }
      } catch (err) {
        this.options.onError(
          err instanceof Error ? err : new Error(String(err)),
        );
      }
    });

    // ── Child stdout → Parent stdout ────────────────────────
    this.childStdout = createInterface({
      input: this.child.stdout,
      crlfDelay: Infinity,
    });

    this.childStdout.on('line', async (line: string) => {
      const trimmed = line.trim();
      if (!trimmed) return;

      try {
        const msg = parseMessage(trimmed);
        if (!msg) {
          process.stdout.write(line + '\n');
          return;
        }

        // Run response interceptor
        const processed = await this.options.onResponse(msg);

        if (processed !== null) {
          process.stdout.write(serializeMessage(processed));
        }
      } catch (err) {
        this.options.onError(
          err instanceof Error ? err : new Error(String(err)),
        );
      }
    });

    // ── Child lifecycle ─────────────────────────────────────
    this.child.on('exit', (code, signal) => {
      this.options.onExit(code, signal);
    });

    this.child.on('error', (err) => {
      this.options.onError(err);
    });
  }

  /**
   * Write a message directly to the child process stdin.
   * Useful for sending management messages outside the parent stdin stream.
   */
  writeToChild(msg: JSONRPCMessage): void {
    if (!this.child?.stdin) {
      throw new Error('Child process not running');
    }
    this.child.stdin.write(serializeMessage(msg));
  }

  /**
   * Gracefully stop the proxy. Kills the child process and closes streams.
   */
  async stop(): Promise<void> {
    this.parentStdin?.close();

    if (this.child) {
      this.child.stdin?.end();
      // Give the child a moment to flush
      await new Promise<void>((resolve) => {
        const timer = setTimeout(() => {
          if (this.child && !this.child.killed) {
            this.child.kill('SIGTERM');
          }
          resolve();
        }, 1000);

        this.child?.on('exit', () => {
          clearTimeout(timer);
          resolve();
        });
      });
    }

    this.child = null;
    this.parentStdin = null;
    this.childStdout = null;
  }
}
