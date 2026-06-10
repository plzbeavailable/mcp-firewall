#!/usr/bin/env node

import { defineCommand, runMain } from 'citty';
import { MCPFirewall } from '@ziwansi/mcp-firewall-core';
import { loadConfig, type FirewallConfig } from '@ziwansi/mcp-firewall-config';
import { readFileSync, writeFileSync, existsSync, statSync } from 'node:fs';
import { MONITOR_HTML } from './monitor.html.js';
import { resolve, dirname } from 'node:path';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Read version from package.json at runtime
let CLI_VERSION = '0.1.0';
try {
  const pkgPath = resolve(__dirname, '../package.json');
  const pkg = JSON.parse(readFileSync(pkgPath, 'utf-8'));
  if (pkg.version) CLI_VERSION = pkg.version;
} catch { /* fall back to default */ }

// ─── Helpers ───────────────────────────────────────────────────

function ask(rl: ReturnType<typeof createInterface>, question: string): Promise<string> {
  return new Promise((resolve) => {
    rl.question(question, (answer: string) => resolve(answer.trim()));
  });
}

// ─── Preset configs ────────────────────────────────────────────

const PRESETS: Record<string, string> = {
  readonly: `# MCP Firewall — Read-Only Preset
# Allows reading files, blocks all writes/deletes/moves.
# Safe default for sharing your filesystem with an AI.

version: "1"
mode: stdio

upstreams:
  - name: filesystem
    transport: stdio
    command: npx
    args:
      - "-y"
      - "@modelcontextprotocol/server-filesystem"
      - "/tmp"

policies:
  methodAllowlist:
    enabled: true
    allowedMethods:
      - initialize
      - ping
      - tools/list
      - tools/call
      - resources/list
      - resources/read
      - prompts/list
      - prompts/get
      - notifications/initialized
    blockUnknown: true

  rbac:
    enabled: true
    defaultDeny: true
    rules:
      - name: "allow-system-methods"
        principals:
          - type: client-id
            pattern: "*"
        targets:
          - method: "initialize"
          - method: "ping"
          - method: "tools/list"
          - method: "notifications/initialized"
        permission: allow
      - name: "allow-reads"
        principals:
          - type: client-id
            pattern: "*"
        targets:
          - method: "tools/call"
            toolName: "read_file"
        permission: allow
      - name: "allow-read-text"
        principals:
          - type: client-id
            pattern: "*"
        targets:
          - method: "tools/call"
            toolName: "read_text_file"
        permission: allow
      - name: "allow-read-multiple"
        principals:
          - type: client-id
            pattern: "*"
        targets:
          - method: "tools/call"
            toolName: "read_multiple_files"
        permission: allow
      - name: "allow-list"
        principals:
          - type: client-id
            pattern: "*"
        targets:
          - method: "tools/call"
            toolName: "list_directory"
        permission: allow
      - name: "allow-search"
        principals:
          - type: client-id
            pattern: "*"
        targets:
          - method: "tools/call"
            toolName: "search_files"
        permission: allow
      - name: "allow-get-info"
        principals:
          - type: client-id
            pattern: "*"
        targets:
          - method: "tools/call"
            toolName: "get_file_info"
        permission: allow
      - name: "allow-list-allowed"
        principals:
          - type: client-id
            pattern: "*"
        targets:
          - method: "tools/call"
            toolName: "list_allowed_directories"
        permission: allow

  parameterValidation:
    enabled: true

  contentFilter:
    enabled: true
    rules:
      - pattern: "(\\\\|/)(\\\\.env|\\\\.git-credentials|\\\\.npmrc|credentials\\\\.json|secrets?\\\\.(ya?ml|json|env))"
        action: block
        phase: input
      - pattern: "(\\\\|/)(id_rsa|id_ed25519|id_ecdsa|.*\\\\.pem|.*\\\\.key(?!\\\\w))"
        action: block
        phase: input

  sensitiveData:
    enabled: true
    detectors:
      - type: api-key
        action: mask
      - type: credit-card
        action: mask
      - type: jwt
        action: mask
      - type: email
        action: mask
      - type: phone
        action: mask
      - type: ssn
        action: mask
      - type: private-key
        action: block
      - type: connection-string
        action: block

auth:
  enabled: false

observability:
  auditLog:
    enabled: true
    output: file
    file: "./logs/audit.jsonl"
    format: jsonl
  tokenTracking:
    enabled: false
  metrics:
    enabled: false
  tracing:
    enabled: false

dashboard:
  enabled: false
sandbox:
  enabled: false
`,

  full: `# MCP Firewall — Full Access Preset
# Allows all tools. Still validates parameters and masks sensitive data.

version: "1"
mode: stdio

upstreams:
  - name: filesystem
    transport: stdio
    command: npx
    args:
      - "-y"
      - "@modelcontextprotocol/server-filesystem"
      - "/tmp"

policies:
  methodAllowlist:
    enabled: true
    allowedMethods:
      - initialize
      - ping
      - tools/list
      - tools/call
      - resources/list
      - resources/read
      - prompts/list
      - prompts/get
      - notifications/initialized
    blockUnknown: true

  rbac:
    enabled: false
    rules: []

  rateLimiting:
    enabled: true
    rules:
      - name: "per-minute"
        window: "1m"
        maxRequests: 120
        keyBy: ["client-id"]

  parameterValidation:
    enabled: true

  contentFilter:
    enabled: true
    rules:
      - pattern: "(\\\\|/)(\\\\.env|\\\\.git-credentials|\\\\.npmrc|credentials\\\\.json|secrets?\\\\.(ya?ml|json|env))"
        action: block
        phase: input
      - pattern: "(\\\\|/)(id_rsa|id_ed25519|id_ecdsa|.*\\\\.pem|.*\\\\.key(?!\\\\w))"
        action: block
        phase: input

  sensitiveData:
    enabled: true
    detectors:
      - type: api-key
        action: mask
      - type: credit-card
        action: mask
      - type: jwt
        action: mask
      - type: email
        action: mask
      - type: phone
        action: mask
      - type: ssn
        action: mask
      - type: private-key
        action: block
      - type: connection-string
        action: block

auth:
  enabled: false

observability:
  auditLog:
    enabled: true
    output: file
    file: "./logs/audit.jsonl"
    format: jsonl
  tokenTracking:
    enabled: false
  metrics:
    enabled: false
  tracing:
    enabled: false

dashboard:
  enabled: false
sandbox:
  enabled: false
`,
};

// ─── Run command ────────────────────────────────────────────────

const runCommand = defineCommand({
  meta: {
    name: 'run',
    description: 'Start the MCP Firewall proxy',
  },
  args: {
    config: {
      type: 'positional',
      description: 'Path to config file (YAML or JSON)',
      required: true,
    },
    port: {
      type: 'string',
      description: 'Override HTTP server port',
    },
    'log-level': {
      type: 'string',
      description: 'Log level: debug, info, warn, error',
      default: 'info',
    },
  },
  async run({ args }) {
    const configPath = resolve(args.config);

    if (!existsSync(configPath)) {
      console.error(`[mcp-firewall] Config file not found: ${configPath}`);
      console.error(`[mcp-firewall] Run 'mcp-firewall init' to create one.`);
      process.exit(1);
    }

    console.error(`[mcp-firewall] Loading config from: ${configPath}`);

    try {
      const { config } = loadConfig(configPath);

      if (args.port) {
        config.server.port = parseInt(args.port, 10);
      }

      const firewall = new MCPFirewall({ config, hotReload: true });

      const shutdown = async () => {
        console.error('\n[mcp-firewall] Shutting down...');
        await firewall.stop();
        process.exit(0);
      };

      process.on('SIGINT', shutdown);
      process.on('SIGTERM', shutdown);

      await firewall.start();

      if (config.mode === 'http') {
        console.error(`[mcp-firewall] Ready. Proxy: http://${config.server.host}:${config.server.port}`);
        if (config.observability.metrics.enabled) {
          console.error(`[mcp-firewall] Metrics: http://${config.server.host}:${config.observability.metrics.port}${config.observability.metrics.path}`);
        }
        if (config.dashboard.enabled) {
          console.error(`[mcp-firewall] Dashboard: http://${config.dashboard.host}:${config.dashboard.port}`);
        }
      } else {
        console.error('[mcp-firewall] Stdio proxy ready. Waiting for requests from parent process...');
      }

    } catch (err) {
      console.error('[mcp-firewall] Failed to start:');
      if (err instanceof Error) {
        console.error(`  ${err.message}`);
        // Show hints for common errors
        if (err.message.includes('EADDRINUSE')) {
          console.error('  Hint: Another process is using this port. Stop it or choose a different port with --port.');
        }
      }
      process.exit(1);
    }
  },
});

// ─── Init command ───────────────────────────────────────────────

const initCommand = defineCommand({
  meta: {
    name: 'init',
    description: 'Generate a firewall configuration file',
  },
  args: {
    output: {
      type: 'string',
      description: 'Output file path',
      default: 'mcp-firewall.yaml',
    },
    preset: {
      type: 'string',
      description: 'Preset: readonly (safe, blocks writes) or full (allows all)',
      default: 'readonly',
    },
    force: {
      type: 'boolean',
      description: 'Overwrite existing file',
      default: false,
    },
    interactive: {
      type: 'boolean',
      description: 'Interactive setup wizard',
      default: false,
    },
  },
  async run({ args }) {
    const outputPath = resolve(args.output);

    // Check if file exists
    if (existsSync(outputPath) && !args.force) {
      console.error(`[mcp-firewall] File already exists: ${outputPath}`);
      console.error('[mcp-firewall] Use --force to overwrite, or --interactive to reconfigure.');
      process.exit(1);
    }

    let content: string;

    if (args.interactive) {
      // Interactive wizard
      const rl = createInterface({ input: process.stdin, output: process.stdout });
      console.log('\n🛡️  MCP Firewall — Setup Wizard\n');
      console.log('This will generate a config file for your MCP server.\n');

      const upstreamCmd = await ask(rl, 'MCP server command (e.g. npx @modelcontextprotocol/server-filesystem): ');
      const upstreamArgs = await ask(rl, 'Arguments (space-separated, e.g. /tmp): ');
      const upstreamName = await ask(rl, 'Server name [filesystem]: ') || 'filesystem';
      const mode = await ask(rl, 'Mode: stdio (for Claude Desktop/Cursor) or http (for team server) [stdio]: ') || 'stdio';
      const auditOutput = await ask(rl, 'Audit log output: file, stdout [file]: ') || 'file';
      const auditPath = auditOutput === 'file' ? (await ask(rl, 'Audit log path [./logs/audit.jsonl]: ') || './logs/audit.jsonl') : '';
      const presetChoice = await ask(rl, 'Preset: readonly (blocks write/delete) or full (allows all) [readonly]: ') || 'readonly';

      rl.close();

      const argsArray = upstreamArgs ? upstreamArgs.split(/\s+/) : ['/tmp'];

      // Build YAML from user input
      const presetConfig = PRESETS[presetChoice] ?? PRESETS.readonly;
      // Replace upstream section
      content = presetConfig
        .replace('transport: stdio\n    command: npx\n    args:\n      - "-y"\n      - "@modelcontextprotocol/server-filesystem"\n      - "/tmp"',
          `transport: ${mode === 'http' ? 'streamable-http' : 'stdio'}\n    command: ${upstreamCmd.includes(' ') ? upstreamCmd.split(' ')[0]! : upstreamCmd}\n    args:\n${argsArray.map(a => `      - "${a}"`).join('\n')}`)
        .replace('mode: stdio', `mode: ${mode}`);

      if (auditOutput === 'stdout') {
        content = content.replace('output: file\n    file: "./logs/audit.jsonl"', 'output: stdout');
      } else if (auditPath) {
        content = content.replace('./logs/audit.jsonl', auditPath);
      }

      console.log(`\n✅ Config generated: ${outputPath}`);
    } else {
      // Use preset
      content = PRESETS[args.preset] ?? PRESETS.readonly;
      console.error(`[mcp-firewall] Generated ${args.preset} preset config: ${outputPath}`);
    }

    writeFileSync(outputPath, content, 'utf-8');
    console.error('[mcp-firewall] Edit this file to customize policies.');
    console.error(`[mcp-firewall] Then run: mcp-firewall run ${outputPath}`);
  },
});

// ─── Validate command ───────────────────────────────────────────

const validateCommand = defineCommand({
  meta: {
    name: 'validate',
    description: 'Validate a firewall configuration file',
  },
  args: {
    config: {
      type: 'positional',
      description: 'Path to config file (YAML or JSON)',
      required: true,
    },
  },
  run({ args }) {
    const configPath = resolve(args.config);

    if (!existsSync(configPath)) {
      console.error(`❌ File not found: ${configPath}`);
      process.exit(1);
    }

    try {
      const { config } = loadConfig(configPath);
      console.log(`✅ Configuration is valid`);
      console.log(`   File: ${configPath}`);
      console.log(`   Mode: ${config.mode}`);
      console.log(`   Upstreams: ${config.upstreams.length}`);
      for (const u of config.upstreams) {
        console.log(`     • ${u.name} (${u.transport})`);
      }
      console.log(`   Method allowlist: ${config.policies.methodAllowlist.enabled ? `${config.policies.methodAllowlist.allowedMethods.length} methods` : 'disabled'}`);
      console.log(`   RBAC: ${config.policies.rbac.enabled ? `${config.policies.rbac.rules.length} rules` + (config.policies.rbac.defaultDeny ? ' (default deny)' : '') : 'disabled'}`);
      console.log(`   Rate limiting: ${config.policies.rateLimiting.enabled ? `${config.policies.rateLimiting.rules.length} rules` : 'disabled'}`);
      console.log(`   Parameter validation: ${config.policies.parameterValidation.enabled ? 'enabled' : 'disabled'}`);
      console.log(`   Sensitive data: ${config.policies.sensitiveData.enabled ? `${config.policies.sensitiveData.detectors.length} detectors` : 'disabled'}`);
      console.log(`   Audit log: ${config.observability.auditLog.enabled ? `${config.observability.auditLog.output}` : 'disabled'}`);
    } catch (err) {
      console.error(`❌ Invalid configuration:`);
      if (err instanceof Error) {
        const msg = err.message;
        console.error(`   ${msg}`);

        // Parse Zod error for friendly path display
        if (msg.includes('Required') || msg.includes('Unrecognized') || msg.includes('Invalid')) {
          console.error('\n   💡 Troubleshooting:');
          console.error('   • Check that all required fields are present');
          console.error('   • Verify YAML indentation is correct');
          console.error('   • Use snake_case or camelCase — both are accepted');
          console.error('   • Run "mcp-firewall init --preset readonly" for a valid starting config');
        }
      }
      process.exit(1);
    }
  },
});

// ─── Status command ─────────────────────────────────────────────

const statusCommand = defineCommand({
  meta: {
    name: 'status',
    description: 'Show running firewall status and health',
  },
  args: {
    config: {
      type: 'positional',
      description: 'Path to config file',
      default: 'mcp-firewall.yaml',
    },
  },
  run({ args }) {
    const configPath = resolve(args.config);
    let config: FirewallConfig | null = null;

    // Try to load config (non-fatal if missing)
    try {
      const result = loadConfig(configPath);
      config = result.config;
    } catch {
      // No config — just show what we can
    }

    console.log('🛡️  MCP Firewall Status\n');

    // Config info
    if (config) {
      console.log(`   Config: ${configPath}`);
      console.log(`   Mode: ${config.mode}`);
      console.log(`   Metrics: ${config.observability.metrics.enabled ? `http://localhost:${config.observability.metrics.port}/metrics` : 'disabled'}`);
      console.log(`   Dashboard: ${config.dashboard.enabled ? `http://localhost:${config.dashboard.port}` : 'disabled'}`);
      console.log('');
    }

    // Check audit log
    if (config?.observability.auditLog.enabled) {
      const logFile = resolve(dirname(configPath), config.observability.auditLog.file ?? 'audit.log');
      if (existsSync(logFile)) {
        const stats = statSync(logFile);
        const lines = readFileSync(logFile, 'utf-8').trim().split('\n').filter(Boolean);
        const blocks = lines.filter(l => l.includes('"block"')).length;
        const allows = lines.filter(l => l.includes('"allow"')).length;
        console.log(`   Audit log: ${logFile}`);
        console.log(`   Entries: ${lines.length} total (${allows} allowed, ${blocks} blocked)`);
        console.log(`   Size: ${(stats.size / 1024).toFixed(1)} KB`);
        console.log(`   Last modified: ${stats.mtime.toLocaleString()}`);

        // Show last entry
        if (lines.length > 0) {
          try {
            const last = JSON.parse(lines[lines.length - 1]!);
            console.log(`\n   Last request:`);
            console.log(`   ${last.timestamp ?? '?'} | ${last.method ?? '?'} | ${last.verdict?.toUpperCase() ?? '?'} | ${last.toolName ?? 'N/A'} | ${last.durationMs ?? '?'}ms`);
            if (last.blockReason) {
              console.log(`   Block reason: ${last.blockReason}`);
            }
          } catch {
            // Ignore parse errors
          }
        }
      } else {
        console.log(`   Audit log: ${logFile} (no entries yet)`);
      }
    } else {
      console.log('   Audit log: disabled');
    }

    // Running processes
    console.log('\n   💡 Quick start: mcp-firewall run <config>');
  },
});

// ─── Logs command ───────────────────────────────────────────────

const logsCommand = defineCommand({
  meta: {
    name: 'logs',
    description: 'Tail the audit log file',
  },
  args: {
    config: {
      type: 'string',
      description: 'Path to firewall config file',
      default: 'mcp-firewall.yaml',
    },
    follow: {
      type: 'boolean',
      description: 'Follow the log (tail -f)',
      default: false,
    },
    lines: {
      type: 'string',
      description: 'Number of lines to show',
      default: '20',
    },
  },
  run({ args }) {
    const configPath = resolve(args.config);

    let logFile: string;
    try {
      const result = loadConfig(configPath);
      logFile = resolve(dirname(configPath), result.config.observability.auditLog.file ?? 'audit.log');
    } catch {
      console.error('❌ Could not load config to find audit log path.');
      console.error(`   File: ${configPath}`);
      console.error('   Use: mcp-firewall logs --config <path>');
      process.exit(1);
    }

    if (!existsSync(logFile)) {
      console.error(`❌ Audit log not found: ${logFile}`);
      console.error('   No requests have been processed yet, or audit logging is disabled.');
      process.exit(1);
    }

    if (args.follow) {
      // Tail mode
      const maxLines = parseInt(args.lines, 10) || 20;
      console.log(`📋 Tailing ${logFile} (last ${maxLines} lines, Ctrl+C to stop)\n`);

      // Show last N lines first
      const allLines = readFileSync(logFile, 'utf-8').trim().split('\n').filter(Boolean);
      const recent = allLines.slice(-maxLines);
      for (const line of recent) {
        formatLogLine(line);
      }

      // Watch for new lines
      let lastSize = statSync(logFile).size;
      const interval = setInterval(() => {
        try {
          const currentSize = statSync(logFile).size;
          if (currentSize > lastSize) {
            const newContent = readFileSync(logFile, 'utf-8').slice(lastSize);
            const newLines = newContent.trim().split('\n').filter(Boolean);
            for (const line of newLines) {
              formatLogLine(line);
            }
            lastSize = currentSize;
          }
        } catch {
          // File might be temporarily locked
        }
      }, 1000);

      process.on('SIGINT', () => { clearInterval(interval); process.exit(0); });
    } else {
      // Dump last N lines
      const maxLines = parseInt(args.lines, 10) || 20;
      const allLines = readFileSync(logFile, 'utf-8').trim().split('\n').filter(Boolean);
      const recent = allLines.slice(-maxLines);
      console.log(`📋 Last ${recent.length} entries from ${logFile}\n`);
      for (const line of recent) {
        formatLogLine(line);
      }
    }
  },
});

function formatLogLine(line: string): void {
  try {
    const entry = JSON.parse(line);
    const ts = (entry.timestamp as string)?.substring(11, 23) ?? '--:--:--.---';
    const method = (entry.method as string ?? '?').padEnd(20);
    const verdict = (entry.verdict as string ?? '?').toUpperCase().padEnd(5);
    const verdictColor = entry.verdict === 'block' ? '🚫' : entry.verdict === 'warn' ? '⚠️ ' : '✅';
    const tool = (entry.toolName as string) ?? 'N/A';
    const duration = `${entry.durationMs ?? '?'}ms`.padStart(6);
    console.log(`${verdictColor} ${ts} | ${method} | ${verdict} | ${duration} | ${tool}`);
    if (entry.blockReason) {
      console.log(`   ↳ ${entry.blockReason}`);
    }
  } catch {
    console.log(line);
  }
}

// ─── Dashboard command ──────────────────────────────────────────

const dashboardCommand = defineCommand({
  meta: {
    name: 'dashboard',
    description: 'Start the web dashboard for real-time monitoring',
  },
  args: {
    port: {
      type: 'string',
      description: 'Dashboard port',
      default: '9021',
    },
    config: {
      type: 'string',
      description: 'Path to firewall config (to find audit log)',
    },
    'log-file': {
      type: 'string',
      description: 'Direct path to audit log file (overrides config)',
    },
  },
  async run({ args }) {
    const port = parseInt(args.port, 10);
    console.error(`[mcp-firewall] Dashboard starting on port ${port}...`);
    console.error(`[mcp-firewall] Open http://localhost:${port}`);

    const http = await import('node:http');
    const fs = await import('node:fs');
    const fsp = await import('node:fs/promises');
    const path = await import('node:path');

    // Resolve audit log path
    let auditLogPath: string | null = null;
    let configLayers: Record<string, boolean> = {};

    // Resolve audit log path
    if (args['log-file']) {
      auditLogPath = path.resolve(args['log-file']);
    } else if (args.config) {
      try {
        const configPath = path.resolve(args.config);
        const { config } = loadConfig(configPath);
        auditLogPath = path.resolve(path.dirname(configPath), config.observability.auditLog.file ?? 'audit.log');
      } catch { /* config optional */ }
    }

    // Load security layer status — try config file, then defaults
    const configPath = args.config ? path.resolve(args.config) : path.resolve('mcp-firewall.yaml');
    try {
      const { config } = loadConfig(configPath);
      configLayers = {
        methodAllowlist: config.policies.methodAllowlist.enabled,
        rbac: config.policies.rbac.enabled,
        rateLimiting: config.policies.rateLimiting.enabled,
        parameterValidation: config.policies.parameterValidation.enabled,
        contentFilter: config.policies.contentFilter.enabled,
        sensitiveData: config.policies.sensitiveData.enabled,
      };
      // If no explicit log file, derive from config
      if (!auditLogPath) {
        auditLogPath = path.resolve(path.dirname(configPath), config.observability.auditLog.file ?? 'audit.log');
      }
    } catch {
      // No config available — show sensible defaults so dashboard isn't empty
      configLayers = {
        methodAllowlist: true,
        rbac: true,
        rateLimiting: false,
        parameterValidation: true,
        contentFilter: true,
        sensitiveData: true,
      };
    }

    // SSE clients
    const sseClients = new Set<any>();
    let lastKnownSize = 0;

    // Notify all SSE clients
    function broadcastSSE(entry: unknown) {
      const data = `data: ${JSON.stringify(entry)}\n\n`;
      for (const client of sseClients) {
        client.write(data);
      }
    }

    // Watch audit log for changes
    let watcher: any = null;
    if (auditLogPath && fs.existsSync(auditLogPath)) {
      lastKnownSize = fs.statSync(auditLogPath).size;
      watcher = fs.watch(auditLogPath, (eventType: string) => {
        if (eventType !== 'change') return;
        try {
          const currentSize = fs.statSync(auditLogPath!).size;
          if (currentSize > lastKnownSize) {
            const fd = fs.openSync(auditLogPath!, 'r');
            const buf = Buffer.alloc(currentSize - lastKnownSize);
            fs.readSync(fd, buf, 0, buf.length, lastKnownSize);
            fs.closeSync(fd);
            const newContent = buf.toString('utf-8');
            const newLines = newContent.trim().split('\n').filter(Boolean);
            for (const line of newLines) {
              try {
                broadcastSSE(JSON.parse(line));
              } catch { /* skip */ }
            }
            lastKnownSize = currentSize;
          }
        } catch { /* file might be locked */ }
      });
    }

    // Use bundled monitor.html (always available via import)
    const monitorHtml = MONITOR_HTML;

    const server = http.createServer(async (req, res) => {
      const url = req.url ?? '/';

      // ── SSE endpoint ──
      if (url === '/api/events') {
        res.writeHead(200, {
          'Content-Type': 'text/event-stream',
          'Cache-Control': 'no-cache',
          'Connection': 'keep-alive',
          'Access-Control-Allow-Origin': '*',
        });
        res.write(':ok\n\n');
        sseClients.add(res);
        req.on('close', () => sseClients.delete(res));
        return;
      }

      // ── Status API ──
      if (url === '/api/status') {
        const result: Record<string, unknown> = {
          connected: auditLogPath ? fs.existsSync(auditLogPath) : false,
          layers: configLayers,
          entries: [],
        };

        // Read recent entries from audit log
        if (auditLogPath && fs.existsSync(auditLogPath)) {
          try {
            const content = await fsp.readFile(auditLogPath, 'utf-8');
            const lines = content.trim().split('\n').filter(Boolean);
            const recent = lines.slice(-50).reverse();
            result.entries = recent.map(l => {
              try { return JSON.parse(l); } catch { return null; }
            }).filter(Boolean);
            result.totalEntries = lines.length;
          } catch { /* skip */ }
        }

        res.writeHead(200, {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
        });
        res.end(JSON.stringify(result));
        return;
      }

      // ── Static HTML ──
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      if (monitorHtml) {
        res.end(monitorHtml);
      } else {
        res.end(`<!DOCTYPE html>
<html><head><title>MCP Firewall Dashboard</title>
<style>body{font-family:system-ui,sans-serif;background:#0d1117;color:#c9d1d9;padding:40px;text-align:center}
h1{color:#58a6ff}.card{border:1px solid #30363d;border-radius:8px;padding:24px;max-width:400px;margin:40px auto;background:#161b22}
button{background:#238636;color:#fff;border:none;padding:10px 20px;border-radius:6px;cursor:pointer;font-size:14px;margin:8px}
</style></head><body>
<h1>🛡️ MCP Firewall Dashboard</h1>
<div class="card"><p>Monitor page not found.</p>
<p>Place <code>monitor.html</code> in the project root or run from the project directory.</p>
<p>API available at <a href="/api/status">/api/status</a></p>
</div></body></html>`);
      }
    });

    server.listen(port, () => {
      console.error(`[mcp-firewall] Dashboard: http://localhost:${port}`);
      if (auditLogPath) {
        console.error(`[mcp-firewall] Watching audit log: ${auditLogPath}`);
      }
    });

    // Cleanup
    const cleanup = () => {
      if (watcher) watcher.close();
      for (const client of sseClients) client.end();
      server.close();
      process.exit(0);
    };
    process.on('SIGINT', cleanup);
    process.on('SIGTERM', cleanup);
  },
});

// ─── Main entry ─────────────────────────────────────────────────

const main = defineCommand({
  meta: {
    name: 'mcp-firewall',
    version: CLI_VERSION,
    description: 'MCP Firewall — Security & Observability proxy for MCP',
  },
  subCommands: {
    run: runCommand,
    init: initCommand,
    validate: validateCommand,
    status: statusCommand,
    logs: logsCommand,
    dashboard: dashboardCommand,
  },
});

runMain(main);
