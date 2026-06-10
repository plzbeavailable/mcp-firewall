<p align="center">
  <img src="https://img.shields.io/npm/v/@ziwansi/mcp-firewall?color=58a6ff" alt="version">
  <img src="https://img.shields.io/npm/dm/@ziwansi/mcp-firewall?color=3fb950" alt="downloads">
  <img src="https://img.shields.io/github/license/plzbeavailable/mcp-firewall?color=a371f7" alt="license">
  <img src="https://img.shields.io/badge/platform-windows%20%7C%20macos%20%7C%20linux-lightgrey" alt="platform">
</p>

# 🛡️ MCP Firewall

**Security & Observability proxy for MCP (Model Context Protocol)**

MCP Firewall sits between your AI client and MCP servers, providing defense-in-depth security with 11 protection layers and 108 injection detection patterns — before any tool call reaches your filesystem or database.

## Installation

```bash
npm install -g @ziwansi/mcp-firewall
```

Requires **Node.js >= 18**.

## Quick Start

```bash
# 1. Generate a safe read-only config
mcp-firewall init --preset readonly

# 2. Review and customize
#    Edit mcp-firewall.yaml to set your upstream MCP servers

# 3. Validate the config
mcp-firewall validate mcp-firewall.yaml

# 4. Start the firewall
mcp-firewall run mcp-firewall.yaml

# 5. (Optional) Open the live dashboard in another terminal
mcp-firewall dashboard
```

## How It Works

```
AI Client ──→ MCP Firewall ──→ MCP Server (filesystem, database, etc.)
                │
                ├─ 1. Method Allowlist      Only known MCP methods pass
                ├─ 2. Authentication        API key / JWT validation
                ├─ 3. RBAC                  Role-based tool permissions
                ├─ 4. Rate Limiting         Sliding-window throttling
                ├─ 5. Parameter Validation  Path traversal, injection detection
                └─ 6. Content Filter        Sensitive data masking & blocking
```

## Commands

| Command | Description |
|---|---|
| `mcp-firewall run <config>` | Start the firewall proxy |
| `mcp-firewall init [--preset readonly\|full]` | Generate a config file |
| `mcp-firewall validate <config>` | Validate a config file |
| `mcp-firewall dashboard` | Start the web monitoring UI |
| `mcp-firewall status` | Show firewall health status |
| `mcp-firewall logs` | Tail the audit log |

## Configuration

The firewall is configured via a YAML file. Generate one with `mcp-firewall init`.

### Presets

- **readonly** — Allows reading files, blocks all writes/deletes. Safe for sharing filesystem access.
- **full** — Allows all operations with all security layers enabled. Good starting point for customization.

### Security Layers

Each layer can be enabled/disabled independently:

```yaml
policies:
  methodAllowlist:
    enabled: true
    allowedMethods: [initialize, ping, tools/list, tools/call, ...]
    blockUnknown: true

  auth:
    enabled: true
    # API key or JWT validation

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
    # Automatically detects: path traversal, null bytes,
    # SQL injection, command injection (14 patterns)

  contentFilter:
    enabled: true
    rules:
      - pattern: "(\\.env|\\.git-credentials|secrets)"
        action: block

  sensitiveData:
    enabled: true
    detectors:
      - type: api-key         # AWS, GitHub, OpenAI keys
      - type: credit-card     # Visa, Mastercard, Amex
      - type: jwt             # JSON Web Tokens
      - type: email           # Email addresses
      - type: phone           # Phone numbers
      - type: ssn             # US Social Security Numbers
      - type: private-key     # RSA/EC private keys
      - type: connection-string # MongoDB, PostgreSQL, Redis URLs
```

## Dashboard

```bash
mcp-firewall dashboard --port 9021
```

Opens a real-time monitoring UI at `http://localhost:9021` with:
- Live request streaming via SSE
- Block/allow/warn statistics
- Security layer status indicators
- Configurable log filtering

## Cross-Platform

Works on **Windows**, **macOS**, and **Linux**. All code uses Node.js built-in modules with no platform-specific dependencies.

## Upstream MCP Servers

Configure any MCP server as an upstream:

```yaml
upstreams:
  - name: filesystem
    transport: stdio
    command: npx
    args:
      - "-y"
      - "@modelcontextprotocol/server-filesystem"
      - "/path/to/allowed/directory"

  - name: postgres
    transport: stdio
    command: npx
    args:
      - "-y"
      - "@modelcontextprotocol/server-postgres"
      - "postgresql://localhost/mydb"
```

## License

MIT © ziwansi
