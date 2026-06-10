<p align="center">
  <img src="https://img.shields.io/npm/v/@ziwansi/mcp-firewall?color=58a6ff" alt="npm version">
  <img src="https://img.shields.io/npm/dm/@ziwansi/mcp-firewall?color=3fb950" alt="downloads">
  <img src="https://img.shields.io/github/license/plzbeavailable/mcp-firewall?color=a371f7" alt="license">
  <img src="https://img.shields.io/badge/node-%3E%3D18-brightgreen" alt="node">
  <img src="https://img.shields.io/badge/platform-windows%20%7C%20macos%20%7C%20linux-lightgrey" alt="platform">
</p>

<h1 align="center">🛡️ MCP Firewall</h1>
<p align="center"><strong>Security & Observability Proxy for Model Context Protocol</strong></p>
<p align="center">11-layer defense-in-depth. 108 injection detection patterns. Blocks threats before they reach your filesystem, database, or network.</p>

---

## Why?

When you give an AI access to MCP servers (filesystem, database, GitHub, etc.), **every tool call is a potential risk**. MCP Firewall sits as a transparent proxy between your AI client and MCP servers, inspecting every request through 11 security layers:

```
AI Client ──→ MCP Firewall ──→ MCP Server
                │
                ├─ ⓪ IP Access Control      IPv4/IPv6 CIDR allowlist/blocklist + geo-blocking
                ├─ ⓪ Replay Detection        Nonce + timestamp anti-replay
                ├─ ① Method Allowlist        Only known MCP methods pass
                ├─ ② Authentication          API key / JWT (JWKS) validation
                ├─ ③ RBAC                    Role-based access control
                ├─ ④ Concurrency Limit       Per-client/tool max concurrent connections
                ├─ ⑤ Rate Limiting           Sliding-window throttling
                ├─ ⑥ Parameter Validation    108 injection patterns + JSON Schema + structural checks
                ├─ ⑦ Content Filter          Regex-based request/response scanning
                ├─ ⑧ Response Limits         Size, item count, depth caps
                ├─ ⑨ Sensitive Data          8 detector types (mask/block/log)
                └─ ⑩ Threat Scoring          Weighted 6-dimension aggregate risk score
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

## What It Detects

### Injection Attacks (108 patterns across 10 categories)

| Category | Pattern Count | Examples |
|---|---|---|
| **SQL Injection** | 12 | SELECT..FROM..WHERE, DROP TABLE/DB, INSERT/UPDATE/DELETE, UNION SELECT, ALTER/TRUNCATE, EXEC sp_, SLEEP/BENCHMARK |
| **NoSQL Injection** | 14 | $where, $regex, $ne, $gt/$lt, $expr, $nin, $func, key-based operator detection, Redis commands, MongoDB URI |
| **Command Injection** | 20 | $(cmd), backtick, pipe to sh/bash/powershell, chained &&/\|\|, ; destructive, dd/sudo/chmod, /etc/* targeting, Python/Java/Node.js code injection |
| **XSS** | 18 | `<script>`, onerror/onload handlers, javascript:/data: URIs, document.cookie, innerHTML, `<iframe>/<object>/<embed>`, SVG onload, HTML entities |
| **SSTI (Template Injection)** | 18 | Jinja2 __class__/__mro__ traversal, twig getenv, FreeMarker/Velocity, PHP system/file_get_contents, Smarty, ERB, Handlebars |
| **LDAP Injection** | 10 | \|/&/! logical operators, wildcard injection, DN manipulation, userPassword targeting |
| **XXE** | 8 | DOCTYPE ENTITY, SYSTEM/PUBLIC external entities, parameter entities, billion laughs, XInclude, XSLT |
| **CRLF / Header Injection** | 8 | \r\n, URL-encoded CR/LF, Content-Type/Set-Cookie/Location header injection, header smuggling |
| **Prototype Pollution** | 7 | __proto__/constructor/prototype keys, __defineGetter__/__defineSetter__, nested serialized detection |
| **ReDoS** | 6 | Nested quantifiers, (.*)+ patterns, ([chars]+)* bombs, high repetition bounds |

### Structural Defenses

| Defense | Description |
|---|---|
| Path traversal | Blocks `../` and `..\\` patterns |
| Null byte injection | Detects `\0` before JSON serialization |
| Deep nesting | Caps object depth at 20 (anti-DoS) |
| String length | Max 1MB per parameter string |
| JSON Schema | Full AJV validation when tool schema is registered |
| IP allowlist/blocklist | IPv4/IPv6 CIDR, geo-blocking |
| Replay detection | Nonce + timestamp with configurable TTL |
| Concurrency limit | Per-client/tool max + queue mode |
| Response size | Max body size / item count / nesting depth |
| Sensitive data | API keys, JWT, credit card, email, phone, SSN, private keys, connection strings |
| Threat scoring | Weighted aggregation across 6 layers, configurable warn/block thresholds |

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
  # IP access control
  ipAccess:
    enabled: true
    allowlist: ["10.0.0.0/8", "192.168.1.0/24"]
    blocklist: ["1.2.3.4"]
    defaultDeny: true

  # Replay attack prevention
  replayDetection:
    enabled: true
    nonceTtlSeconds: 300
    maxClockSkew: 30
    requireNonce: true

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

  concurrencyLimit:
    enabled: true
    maxConcurrent: 10
    maxConcurrentPerTool: 50
    queueEnabled: true
    maxQueueSize: 100

  rateLimiting:
    enabled: true
    rules:
      - name: default
        window: 1m
        maxRequests: 100
        keyBy: [client-id]

  parameterValidation:
    enabled: true
    strictMode: false

  contentFilter:
    enabled: true
    rules:
      - pattern: "(\.env|\.git-credentials|id_rsa|secrets)"
        action: block

  responseLimits:
    enabled: true
    maxResponseSize: 10485760
    maxItems: 1000
    maxResponseDepth: 20

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

  threatScoring:
    enabled: true
    blockThreshold: 80
    warnThreshold: 50
    weights:
      injectionDetection: 0.3
      rateLimiting: 0.15
      contentFilter: 0.25
      ipReputation: 0.1
      replayDetection: 0.1
      concurrency: 0.1

observability:
  auditLog:
    enabled: true
    output: file
    file: "./logs/audit.jsonl"
```

## Packages

| Package | npm | Description |
|---|---|---|
| `@ziwansi/mcp-firewall` | [![npm](https://img.shields.io/npm/v/@ziwansi/mcp-firewall)](https://www.npmjs.com/package/@ziwansi/mcp-firewall) | CLI tool |
| `@ziwansi/mcp-firewall-core` | [![npm](https://img.shields.io/npm/v/@ziwansi/mcp-firewall-core)](https://www.npmjs.com/package/@ziwansi/mcp-firewall-core) | Proxy engine + 11-layer security pipeline |
| `@ziwansi/mcp-firewall-config` | [![npm](https://img.shields.io/npm/v/@ziwansi/mcp-firewall-config)](https://www.npmjs.com/package/@ziwansi/mcp-firewall-config) | Zod schemas + YAML loading |

## Cross-Platform

Works on **Windows**, **macOS**, and **Linux**. Zero native dependencies. Requires Node.js ≥ 18.

## License

MIT © [ziwansi](https://github.com/plzbeavailable)

---

<p align="center">
  <sub>⭐ Star this repo if you find it useful | PRs welcome</sub>
</p>
