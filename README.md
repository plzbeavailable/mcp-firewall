# MCP Firewall

> **Security & Observability proxy for MCP (Model Context Protocol)**

MCP Firewall sits between your AI client and MCP servers, providing a **security pipeline** (RBAC, rate limiting, content filtering, sensitive data detection) and **full observability** (metrics, tracing, audit logging, token tracking) — all in a single TypeScript-native, MIT-licensed proxy.

## Quick Start

```bash
# Install globally
npm install -g @mcp-firewall/cli

# Generate a config file
mcp-firewall init

# Start the firewall (stdio mode — works as Claude Desktop child process)
mcp-firewall run mcp-firewall.yaml
```

### Claude Desktop Integration

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@mcp-firewall/cli", "run", "./mcp-firewall.yaml"]
    }
  }
}
```

The firewall transparently proxies all MCP traffic while applying security policies and collecting metrics.

## Features

### Security Pipeline
- **Method Allowlist** — Block unknown MCP methods
- **API Key Authentication** — Validate API keys in stdio or HTTP mode
- **RBAC** — Tool-level access control with glob pattern matching
- **Rate Limiting** — Sliding window rate limits per client/tool/server
- **Parameter Validation** — Block path traversal, null byte injection, deep nesting
- **Content Filtering** — Regex-based input/output filtering
- **Sensitive Data Detection** — Mask or block PII, API keys, JWT tokens in responses

### Observability
- **Prometheus Metrics** — Request volume, latency, error rates, token usage
- **Distributed Tracing** — OpenTelemetry traces with W3C context propagation
- **Audit Logging** — Structured JSON audit trail for every request/response
- **Token Tracking** — Estimate or extract actual token consumption
- **Health Checks** — Periodic upstream server health monitoring

## Configuration

See [examples/basic-config.yaml](examples/basic-config.yaml) for a minimal config, or [examples/production-config.yaml](examples/production-config.yaml) for a production setup.

### Key Config Sections

```yaml
version: "1"
mode: stdio  # or 'http'

# Upstream MCP servers
upstreams:
  - name: filesystem
    transport: stdio
    command: npx
    args: ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]

# RBAC Rules (optional)
policies:
  rbac:
    enabled: true
    rules:
      - name: "allow-read-only"
        principals:
          - type: client-id
            pattern: "claude-desktop"
        targets:
          - method: "tools/call"
            toolName: "read_*"
        permission: allow

  # Rate Limiting (optional)
  rate_limiting:
    enabled: true
    rules:
      - name: "per-client"
        window: "1m"
        maxRequests: 100
        keyBy: ["client-id"]

  # Sensitive Data Detection
  sensitive_data:
    enabled: true
    detectors:
      - type: credit-card
        action: mask
      - type: api-key
        action: mask

# Observability
observability:
  metrics:
    enabled: true
    port: 9090
  audit_log:
    enabled: true
    output: stdout
```

## Architecture

See the full architecture diagram in [docs/architecture.md](docs/architecture.md).

```
AI Client ──► MCP Firewall ──► MCP Server
                │
                ├── Security Pipeline (7 middlewares: allowlist→auth→RBAC→rate→validation→filter→PII)
                ├── Observability (Prometheus metrics, OTLP tracing, audit logging, token tracking)
                ├── Plugin System (JS/Wasm plugins for custom security logic)
                └── Dashboard API (Hono REST API → React SPA)
```

## Documentation

| Document | Description |
|----------|-------------|
| [Configuration Guide](docs/configuration.md) | All config options, defaults, and examples |
| [Deployment Guide](docs/deployment.md) | Claude Desktop, HTTP server, Docker, K8s |
| [Plugin Development](docs/plugin-development.md) | Build custom security plugins |
| [Architecture](docs/architecture.md) | System design, data flow, package structure |

## Deployment Modes

### Mode A: Sidecar (stdio) — Claude Desktop

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "node",
      "args": ["apps/proxy/dist/index.js", "run", "mcp-firewall.yaml"]
    }
  }
}
```

### Mode B: Team Server (HTTP)

```bash
docker compose -f examples/docker-compose.e2e.yml up -d
```

Launches: Firewall + Prometheus + Grafana (pre-built dashboards) + Jaeger + traffic generator.

### Mode C: Kubernetes

Deploy as a sidecar or standalone deployment with Prometheus ServiceMonitor. See [deployment guide](docs/deployment.md).

## Project Status

> **Phase 1 (Foundation)** — ✅ Complete
> - [x] Monorepo with pnpm + Turborepo + TypeScript strict
> - [x] Core proxy engine (stdio + HTTP + SSE transports, CORS support)
> - [x] Security pipeline (method allowlist, API key/JWT auth, RBAC, rate limiting, parameter validation with AJV, content filter, sensitive data detection)
> - [x] Observability (Prometheus metrics, OpenTelemetry tracing, audit logging, token tracking, health checks)
> - [x] CLI (run, init, validate, dashboard)
> - [x] Configuration system (YAML/JSON, Zod validation, env var interpolation, hot-reload)
> - [x] Plugin system (JS plugin loader, lifecycle management)
> - [x] Docker sandbox execution (Docker-based, opt-in)
> - [x] 73 unit tests across 7 security middlewares, 10 test files

> **Phase 2 (Security Core)** — ✅ Complete
> - [x] JSON Schema parameter validation (AJV integration + ToolSchemaCache)
> - [x] JWT/OAuth2 authentication (JWKS-based, issuer/audience/expiration checks)
> - [x] Docker sandbox execution (network isolation, resource limits, timeout)
> - [x] Plugin system (dynamic import, lifecycle hooks, custom metrics)

> **Phase 3 (Observability)** — ✅ Complete
> - [x] Database layer (SQLite via Drizzle ORM + better-sqlite3)
> - [x] Audit log repository with filtering, pagination, stats
> - [x] Grafana dashboard templates (10 panels, 3 sections)
> - [x] Docker Compose full stack (firewall + Prometheus + Grafana + Jaeger)
> - [x] E2E verified: 24 requests, 6 blocked, <1ms latency

> **Phase 4 (Dashboard)** — 📋 Planned
> - [ ] React SPA dashboard with real-time metrics
> - [ ] Policy management UI (YAML editor + live validation)
> - [ ] Audit log viewer (table + filtering + detail)

## Live Demo

```
git clone https://github.com/mcp-firewall/mcp-firewall
cd mcp-firewall
pnpm install && pnpm run build

# Start mock MCP server + firewall + playground
node tests/fixtures/mock-mcp-http.js &
node apps/proxy/dist/index.js run examples/docker-firewall-config.yaml &

# Open in browser
open examples/playground.html
```

Firewall runs on `:9020` with Prometheus metrics on `:9090`. The playground lets you send safe/blocked requests and watch metrics update in real-time.

## License

MIT © 2026 MCP Firewall Contributors
