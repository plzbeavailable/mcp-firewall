import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawn, ChildProcess } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { createInterface } from 'node:readline';
import { resolve } from 'node:path';

// ─── Helpers ──────────────────────────────────────────────────

interface JsonRpcResponse {
  jsonrpc: '2.0';
  id: string | number;
  result?: unknown;
  error?: { code: number; message: string; data?: unknown };
}

/**
 * Send a JSON-RPC request to a child process via stdin and wait for the response.
 */
function sendRequest(
  proc: ChildProcess,
  method: string,
  params?: Record<string, unknown>,
  id?: string | number,
): Promise<JsonRpcResponse> {
  return new Promise((resolve, reject) => {
    const requestId = id ?? randomUUID().slice(0, 8);
    const request = JSON.stringify({
      jsonrpc: '2.0',
      id: requestId,
      method,
      params,
    });

    const rl = createInterface({ input: proc.stdout!, crlfDelay: Infinity });

    const timeout = setTimeout(() => {
      rl.close();
      reject(new Error(`Request timed out: ${method}`));
    }, 15000);

    const onLine = (line: string) => {
      const trimmed = line.trim();
      if (!trimmed) return;

      try {
        const msg = JSON.parse(trimmed) as JsonRpcResponse;
        if (msg.id === requestId) {
          clearTimeout(timeout);
          rl.off('line', onLine);
          rl.close();
          resolve(msg);
        }
      } catch {
        // Not JSON or different id — keep listening
      }
    };

    rl.on('line', onLine);
    proc.stdin!.write(request + '\n');
  });
}

/**
 * Wait for the child process to output a specific string on stderr.
 */
function waitForStderr(proc: ChildProcess, pattern: string, timeoutMs = 5000): Promise<void> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error(`Timeout waiting for stderr pattern: ${pattern}`));
    }, timeoutMs);

    const onData = (chunk: Buffer) => {
      const text = chunk.toString();
      if (text.includes(pattern)) {
        clearTimeout(timer);
        proc.stderr!.off('data', onData);
        resolve();
      }
    };

    proc.stderr!.on('data', onData);
  });
}

// ─── Tests ────────────────────────────────────────────────────

describe('MCP Firewall Integration', () => {
  let firewall: ChildProcess | null = null;

  afterAll(() => {
    if (firewall && !firewall.killed) {
      firewall.kill('SIGTERM');
    }
  });

  it(
    'should proxy initialize handshake',
    async () => {
      // Spawn the firewall which will spawn the mock server
      const mockServerPath = resolve(__dirname, '../../fixtures/mock-mcp-server.js');

      firewall = spawn('node', [
        resolve(__dirname, '../../../apps/proxy/dist/index.js'),
        'run',
        resolve(__dirname, '../../fixtures/test-firewall-config.yaml'),
      ], {
        stdio: ['pipe', 'pipe', 'pipe'],
        env: {
          ...process.env,
          MOCK_SERVER_PATH: mockServerPath,
        },
      });

      // Wait for firewall to be ready
      await waitForStderr(firewall, 'Stdio proxy ready');

      // Send initialize
      const initResponse = await sendRequest(firewall, 'initialize', {
        protocolVersion: '2024-11-05',
        capabilities: {},
        clientInfo: { name: 'test-client', version: '1.0.0' },
      });

      expect(initResponse.result).toBeDefined();
      expect((initResponse.result as Record<string, unknown>)?.serverInfo).toBeDefined();
    },
    20000,
  );

  it(
    'should proxy tools/list',
    async () => {
      if (!firewall) throw new Error('Firewall not started');

      // First initialize (required by MCP protocol)
      await sendRequest(firewall, 'initialize', {
        protocolVersion: '2024-11-05',
        capabilities: {},
        clientInfo: { name: 'test-client', version: '1.0.0' },
      });

      // Then list tools
      const response = await sendRequest(firewall, 'tools/list');

      expect(response.result).toBeDefined();
      const result = response.result as { tools?: Array<{ name: string }> };
      expect(result.tools).toBeDefined();
      expect(result.tools!.length).toBeGreaterThan(0);
    },
    20000,
  );

  it(
    'should proxy tools/call for echo',
    async () => {
      if (!firewall) throw new Error('Firewall not started');

      // Initialize
      await sendRequest(firewall, 'initialize', {
        protocolVersion: '2024-11-05',
        capabilities: {},
        clientInfo: { name: 'test-client', version: '1.0.0' },
      });

      // Call echo
      const response = await sendRequest(firewall, 'tools/call', {
        name: 'echo',
        arguments: { message: 'Hello Firewall!' },
      });

      expect(response.result).toBeDefined();
      const result = response.result as { content?: Array<{ text: string }> };
      expect(result.content?.[0]?.text).toContain('Hello Firewall!');
    },
    20000,
  );

  it(
    'should reject unknown methods when blockUnknown is true',
    async () => {
      if (!firewall) throw new Error('Firewall not started');

      // Initialize
      await sendRequest(firewall, 'initialize', {
        protocolVersion: '2024-11-05',
        capabilities: {},
        clientInfo: { name: 'test-client', version: '1.0.0' },
      });

      // Try a method not in the allowlist
      const response = await sendRequest(firewall, 'dangerous/method');

      expect(response.error).toBeDefined();
      expect(response.error!.code).toBe(-32601);
    },
    20000,
  );

  it(
    'should block write_file when RBAC denies',
    async () => {
      if (!firewall) throw new Error('Firewall not started');

      // Initialize
      await sendRequest(firewall, 'initialize', {
        protocolVersion: '2024-11-05',
        capabilities: {},
        clientInfo: { name: 'test-client', version: '1.0.0' },
      });

      // Try to call write_file (should be blocked by RBAC)
      const response = await sendRequest(firewall, 'tools/call', {
        name: 'write_file',
        arguments: { path: '/tmp/test.txt', content: 'evil data' },
      });

      // Should get an error because RBAC blocks write_*
      expect(response.error).toBeDefined();
    },
    20000,
  );

  it(
    'should block path traversal in params',
    async () => {
      if (!firewall) throw new Error('Firewall not started');

      // Initialize
      await sendRequest(firewall, 'initialize', {
        protocolVersion: '2024-11-05',
        capabilities: {},
        clientInfo: { name: 'test-client', version: '1.0.0' },
      });

      // Try path traversal
      const response = await sendRequest(firewall, 'tools/call', {
        name: 'echo',
        arguments: { message: '../../../etc/passwd' },
      });

      // Should be blocked by parameter validator
      expect(response.error).toBeDefined();
    },
    20000,
  );
});
