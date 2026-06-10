<p align="center">
  <img src="https://img.shields.io/npm/v/@ziwansi/mcp-firewall?color=58a6ff" alt="npm version">
  <img src="https://img.shields.io/npm/dm/@ziwansi/mcp-firewall?color=3fb950" alt="downloads">
  <img src="https://img.shields.io/github/license/plzbeavailable/mcp-firewall?color=a371f7" alt="license">
  <img src="https://img.shields.io/badge/node-%3E%3D18-brightgreen" alt="node">
  <img src="https://img.shields.io/badge/platform-windows%20%7C%20macos%20%7C%20linux-lightgrey" alt="platform">
</p>

<h1 align="center">🛡️ MCP Firewall</h1>
<p align="center"><strong>Security & Observability Proxy for Model Context Protocol</strong></p>
<p align="center">6-layer defense-in-depth. Blocks dangerous tool calls before they reach your filesystem, database, or network.</p>

---

## Why?

When you give an AI access to MCP servers (filesystem, database, GitHub, etc.), **every tool call is a potential risk**. MCP Firewall sits as a transparent proxy between your AI client and MCP servers, inspecting every request through 6 security layers:

```
AI Client ──→ MCP Firewall ──→ MCP Server
                │
                ├─ ① Method Allowlist      Only known MCP methods pass
                ├─ ② Authentication        API key / JWT validation
                ├─ ③ RBAC                  Role-based access control
                ├─ ④ Rate Limiting         Sliding-window throttling
                ├─ ⑤ Parameter Validation  Injection & traversal detection
                └─ ⑥ Content Filter        Sensitive data masking & blocking
```

## Quick Start

```bash
npm install -g @ziwansi/mcp-firewall
mcp-firewall init
mcp-firewall run mcp-firewall.yaml
```

### Claude Desktop

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@ziwansi/mcp-firewall", "run", "./mcp-firewall.yaml"]
    }
  }
}
```

## What It Blocks

| Threat | Layer | Action |
|---|---|---|
| Unauthorized file writes | RBAC (default deny) | 🚫 Block |
| Path traversal (`../../../etc/passwd`) | Parameter Validation | 🚫 Block |
| Command injection (`$(rm -rf /)`, backtick subshell) | Parameter Validation (14 patterns) | 🚫 Block |
| Credential file access (`.env`, `.npmrc`, `id_rsa`) | Content Filter | 🚫 Block |
| API key leaks (GitHub, OpenAI, AWS) | Sensitive Data (8 detectors) | 🔒 Mask |
| Private key exposure (`-----BEGIN RSA PRIVATE KEY-----`) | Sensitive Data | 🚫 Block |
| Database connection strings in output | Sensitive Data | 🚫 Block |
| JWT token leakage | Sensitive Data | 🔒 Mask |
| Rate limit abuse | Rate Limiting | ⏱️ Throttle |

## Dashboard

```bash
mcp-firewall dashboard
# → http://localhost:9021
```

Real-time monitoring with SSE streaming, request statistics, security layer status, and audit log filtering.

## CLI

| Command | Description |
|---|---|
| `mcp-firewall run <config>` | Start the firewall proxy |
| `mcp-firewall init [--preset readonly\|full]` | Generate config file |
| `mcp-firewall validate <config>` | Validate config |
| `mcp-firewall dashboard` | Real-time monitoring UI |
| `mcp-firewall status [config]` | Firewall health |
| `mcp-firewall logs --config <path>` | Tail audit log |

## Configuration

```yaml
version: "1"
mode: stdio

upstreams:
  - name: filesystem
    transport: stdio
    command: npx
    args: ["-y", "@modelcontextprotocol/server-filesystem", "/allowed/path"]

policies:
  methodAllowlist:
    enabled: true
    allowedMethods: [initialize, ping, tools/list, tools/call]
    blockUnknown: true

  rbac:
    enabled: true
    defaultDeny: true
    rules:
      - name: "allow-reads"
        principals: [{ type: "client-id", pattern: "*" }]
        targets: [{ method: "tools/call", toolName: "read_file" }]
        permission: allow

  rateLimiting:
    enabled: true
    rules:
      - windowMs: 60000
        maxRequests: 100

  parameterValidation:
    enabled: true

  contentFilter:
    enabled: true
    rules:
      - pattern: "(\.env|\.git-credentials|id_rsa|secrets)"
        action: block

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

observability:
  auditLog:
    enabled: true
    output: file
    file: "./logs/audit.jsonl"
```

Full example: [`configs/filesystem-firewall.yaml`](configs/filesystem-firewall.yaml)

## Packages

| Package | npm | Description |
|---|---|---|
| `@ziwansi/mcp-firewall` | [![npm](https://img.shields.io/npm/v/@ziwansi/mcp-firewall)](https://www.npmjs.com/package/@ziwansi/mcp-firewall) | CLI tool |
| `@ziwansi/mcp-firewall-core` | [![npm](https://img.shields.io/npm/v/@ziwansi/mcp-firewall-core)](https://www.npmjs.com/package/@ziwansi/mcp-firewall-core) | Proxy engine + security pipeline |
| `@ziwansi/mcp-firewall-config` | [![npm](https://img.shields.io/npm/v/@ziwansi/mcp-firewall-config)](https://www.npmjs.com/package/@ziwansi/mcp-firewall-config) | Zod schemas + YAML loading |

## Cross-Platform

Works on **Windows**, **macOS**, and **Linux**. Zero native dependencies. Requires Node.js ≥ 18.

## License

MIT © [ziwansi](https://github.com/plzbeavailable)

---

<p align="center">
  <sub>⭐ Star this repo if you find it useful | PRs welcome</sub>
</p>
