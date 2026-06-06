#!/usr/bin/env node
// Simple runner wrapper for the mock MCP server
// Usage: node mock-mcp-server-runner.js

const { spawn } = require('node:child_process');
const path = require('node:path');

// Use tsx to run the TypeScript mock server directly
const proc = spawn('npx', ['tsx', path.join(__dirname, 'mock-mcp-server.ts')], {
  stdio: ['pipe', 'inherit', 'inherit'],
  env: { ...process.env },
});

process.stdin.pipe(proc.stdin);
proc.on('exit', (code: number | null) => process.exit(code ?? 0));
