# MCP Firewall Configuration Guide

> 完整参考文档 — 每个配置项的含义、类型、默认值和用法示例

## 目录

- [快速开始](#快速开始)
- [配置文件结构](#配置文件结构)
- [代理模式](#代理模式)
- [上游服务器](#上游服务器)
- [认证](#认证)
- [安全策略](#安全策略)
  - [方法白名单](#方法白名单)
  - [RBAC 权限控制](#rbac-权限控制)
  - [速率限制](#速率限制)
  - [参数校验](#参数校验)
  - [内容过滤](#内容过滤)
  - [敏感数据检测](#敏感数据检测)
- [可观测性](#可观测性)
  - [Prometheus Metrics](#prometheus-metrics)
  - [分布式追踪](#分布式追踪)
  - [审计日志](#审计日志)
  - [Token 追踪](#token-追踪)
- [数据库](#数据库)
- [沙箱](#沙箱)
- [仪表盘](#仪表盘)
- [环境变量](#环境变量)
- [热重载](#热重载)

---

## 快速开始

```bash
# 生成默认配置
mcp-firewall init

# 校验配置
mcp-firewall validate mcp-firewall.yaml

# 启动（stdio 模式）
mcp-firewall run mcp-firewall.yaml

# 启动（HTTP 模式）
mcp-firewall run mcp-firewall.yaml --port 9020
```

### 最小配置

```yaml
version: "1"
mode: stdio

upstreams:
  - name: filesystem
    transport: stdio
    command: npx
    args:
      - "-y"
      - "@modelcontextprotocol/server-filesystem"
      - "/allowed/path"
```

这个最小配置就能跑起来，所有安全策略使用默认值。

---

## 配置文件结构

```yaml
version: "1"           # 配置版本号（目前只有 "1"）
mode: stdio            # 代理模式：stdio 或 http

server:                # HTTP 服务器配置（mode: http 时生效）
  host: "127.0.0.1"
  port: 9020

upstreams:             # 上游 MCP 服务器列表
  - name: xxx
    transport: stdio

auth:                  # 认证配置
policies:              # 安全策略
observability:         # 可观测性
database:              # 数据库
sandbox:               # 沙箱执行
dashboard:             # Web 仪表盘
```

---

## 代理模式

### stdio 模式

防火墙作为 AI 客户端的子进程运行，通过 stdin/stdout 通信。适合 Claude Desktop 等桌面客户端。

```yaml
mode: stdio

upstreams:
  - name: my-server
    transport: stdio
    command: npx
    args: ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
```

上游配置字段：

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `name` | string | ✅ | 上游服务器名称 |
| `transport` | `"stdio"` | ✅ | 传输协议 |
| `command` | string | ✅ | 启动命令 |
| `args` | string[] | 否 | 命令参数 |
| `env` | object | 否 | 环境变量 |
| `healthCheck.enabled` | boolean | 否 | 是否启用健康检查（默认 true） |
| `healthCheck.interval` | string | 否 | 检查间隔（如 "30s"） |

### HTTP 模式

防火墙作为 HTTP 服务器运行，接受多个客户端连接。适合团队服务器部署。

```yaml
mode: http

server:
  host: "0.0.0.0"
  port: 9020

upstreams:
  - name: production-server
    transport: streamable-http
    url: "http://mcp-prod.internal:8080"
    headers:
      X-Api-Key: "${MCP_UPSTREAM_KEY}"
    healthCheck:
      enabled: true
      interval: "15s"
```

HTTP 上游配置字段：

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `name` | string | ✅ | 上游服务器名称 |
| `transport` | `"streamable-http"` | ✅ | 传输协议 |
| `url` | string | ✅ | 上游服务器完整 URL |
| `headers` | object | 否 | 转发 header |
| `healthCheck.enabled` | boolean | 否 | 是否启用健康检查 |
| `healthCheck.interval` | string | 否 | 检查间隔 |

### SSE 模式（旧版兼容）

```yaml
upstreams:
  - name: legacy-server
    transport: sse
    url: "http://old-mcp:3000"
```

> SSE 模式兼容 MCP 2024-11-05 规范。新部署推荐使用 streamable-http。

---

## 认证

### API Key

```yaml
auth:
  enabled: true
  providers:
    - type: api-key
      keys:
        - key: "${ADMIN_API_KEY}"
          clientId: admin
        - key: "dev-key-12345"
          clientId: developer
```

客户端在请求头中携带 API Key：
```
Authorization: Bearer <your-key>
```

### JWT / OAuth2

```yaml
auth:
  enabled: true
  providers:
    - type: oauth2
      jwksUrl: "https://auth.example.com/.well-known/jwks.json"
      issuer: "https://auth.example.com"
      audience: "mcp-firewall"
```

客户端携带 JWT Bearer Token：
```
Authorization: Bearer eyJhbGciOi...
```

JWT 验证流程：
1. 从 Authorization header 提取 token
2. 解码并验证 JWT 结构（3 段式）
3. 拒绝 `alg: none` 的 token
4. 验证 `iss`（issuer）和 `aud`（audience）
5. 验证 `exp`（过期时间）和 `nbf`（生效时间）
6. 从 JWKS 端点获取公钥确认 kid 存在
7. 将 `sub` claim 映射为 clientId

---

## 安全策略

### 方法白名单

控制哪些 MCP JSON-RPC 方法允许通过。

```yaml
policies:
  method_allowlist:
    enabled: true
    allowed_methods:
      - initialize
      - ping
      - tools/list
      - tools/call
      - resources/list
      - resources/read
      - prompts/list
      - prompts/get
    block_unknown: true  # false = 告警但放行
```

### RBAC 权限控制

基于角色（client-id）的访问控制，glob 模式匹配。

```yaml
policies:
  rbac:
    enabled: true
    rules:
      # 允许读操作
      - name: "allow-read"
        principals:
          - type: client-id
            pattern: "*"          # 所有客户端
        targets:
          - method: "tools/call"
            toolName: "read_*"    # 所有 read_ 开头的工具
            serverName: "filesystem"
        permission: allow

      # 拒绝写操作
      - name: "block-write"
        principals:
          - type: client-id
            pattern: "claude-*"   # 只针对 Claude 客户端
        targets:
          - method: "tools/call"
            toolName: "write_*"
            serverName: "filesystem"
        permission: deny

      # 管理员全权限
      - name: "admin-full-access"
        principals:
          - type: api-key
            pattern: "admin-*"    # admin 开头的 API key
        targets:
          - method: "*"           # 所有方法
        permission: allow
```

Principal 匹配器：

| 类型 | 说明 | 示例 |
|------|------|------|
| `client-id` | 客户端标识 | `"claude-*"` |
| `api-key` | API key 前缀 | `"admin-*"` |
| `jwt-claim` | JWT claim 值 | `"user@example.com"` |

Target 匹配器：

| 字段 | 说明 | 示例 |
|------|------|------|
| `serverName` | 上游服务器名 | `"filesystem"` |
| `toolName` | 工具名（glob） | `"write_*"`, `"*file*"` |
| `method` | JSON-RPC 方法 | `"tools/call"`, `"*"` |

> **规则：** deny 始终优先于 allow。匹配按顺序进行，第一个匹配的 deny 直接拦截。

### 速率限制

```yaml
policies:
  rate_limiting:
    enabled: true
    rules:
      # 全局限制：每个客户端每分钟最多 100 次请求
      - name: "per-client-global"
        window: "1m"
        maxRequests: 100
        keyBy: ["client-id"]
        strategy: sliding-window

      # 工具级别限制：每个客户端每分钟最多调用 30 次 echo
      - name: "per-tool-echo"
        window: "1m"
        maxRequests: 30
        keyBy: ["client-id", "tool-name"]
```

`keyBy` 可组合多个维度：`client-id`, `api-key`, `tool-name`, `server-name`

`strategy`：
- `sliding-window`：滑动窗口，精确控制
- `token-bucket`：令牌桶（需配合 `burstMultiplier`）

### 参数校验

阻止危险输入模式。

```yaml
policies:
  parameter_validation:
    enabled: true
    strict_mode: false      # true = 拒绝未知字段
    max_depth: 10           # 最大对象嵌套深度
    max_string_length: 1048576  # 最大字符串长度（1MB）
```

自动检测：
- 🗡️ 路径穿越：`../../../etc/passwd`
- 💉 空字节注入：`foo\x00.txt`
- 🏗️ 深度嵌套：超过 20 层的对象（DoS 防护）
- 🗄️ SQL 注入模式：`SELECT ... FROM ...`, `DROP TABLE`, `UNION SELECT`, `'; --`
- 📏 超长字符串：防止内存耗尽攻击

> 如果为工具注册了 JSON Schema（通过 tools/list 响应），校验将用 AJV 进行完整 schema 验证。

### 内容过滤

正则表达式模式匹配 → 拦截 / 脱敏 / 告警。

```yaml
policies:
  content_filter:
    enabled: true
    rules:
      # 拦截危险命令
      - pattern: "rm -rf"
        action: block
        phase: input

      # 告警（记录但不拦截）
      - pattern: "sudo "
        action: log
        phase: both

      # 脱敏输出
      - pattern: "\\bpassword\\s*[:=]"
        action: mask
        phase: output
```

`phase`：`input`（请求阶段）、`output`（响应阶段）、`both`

### 敏感数据检测

自动扫描响应中的敏感信息。

```yaml
policies:
  sensitive_data:
    enabled: true
    detectors:
      - type: credit-card    # 信用卡号
        action: mask         # 替换为 ***REDACTED***
      - type: api-key        # API 密钥
        action: mask
      - type: jwt            # JWT Token
        action: mask
      - type: email          # 邮箱地址
        action: log          # 记录但不脱敏
      - type: phone          # 电话号码
        action: log
      - type: custom         # 自定义模式
        name: "internal-ip"
        pattern: "10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}"
        action: mask
```

---

## 可观测性

### Prometheus Metrics

```yaml
observability:
  metrics:
    enabled: true
    port: 9090
    path: "/metrics"   # Prometheus scrape 路径
```

暴露的指标：

| 指标 | 类型 | 标签 | 说明 |
|------|------|------|------|
| `mcp_requests_total` | Counter | method, server_name, verdict | 请求总数 |
| `mcp_blocks_total` | Counter | reason, middleware | 拦截次数 |
| `mcp_request_duration_seconds` | Histogram | method, server_name | 请求延迟 |
| `mcp_token_usage_total` | Counter | server_name, direction | Token 消耗 |
| `mcp_active_connections` | Gauge | — | 活跃连接数 |
| `mcp_upstream_server_health` | Gauge | server_name | 上游健康状态 |
| `mcp_firewall_uptime_seconds` | Gauge | — | 防火墙运行时间 |

### 分布式追踪

```yaml
observability:
  tracing:
    enabled: true
    exporter: otlp          # otlp | console | none
    endpoint: "http://jaeger:4318/v1/traces"
    sampleRate: 1.0         # 1.0 = 100%, 0.1 = 10%
```

需要部署 Jaeger（Docker Compose 文件已包含）。

### 审计日志

```yaml
observability:
  audit_log:
    enabled: true
    output: stdout         # stdout | file | sqlite | postgres
    file: "audit.log"      # output: file 时有效
    format: jsonl          # jsonl | json
```

每条记录包含：
- 请求 ID、Trace ID、Span ID
- 客户端 ID、服务器名称、方法、工具名
- 请求参数（截断）+ 响应数据（截断）
- 安全判定（allow/block/warn）+ 阻断原因
- 处理耗时 + 上游耗时
- Token 估算
- 安全事件列表

### Token 追踪

```yaml
observability:
  token_tracking:
    enabled: true
    estimation_mode: conservative  # conservative | aggressive | custom
```

保守估算：每 4 个字符 ≈ 1 token（英语）。如果上游返回标准 `usage` 对象（OpenAI/Anthropic 格式）则使用实际值。

---

## 数据库

```yaml
database:
  type: sqlite            # sqlite | postgres
  sqlite:
    path: "./data/mcp-firewall.db"
  # PostgreSQL（可选）
  # postgres:
  #   host: "localhost"
  #   port: 5432
  #   database: "mcp_firewall"
  #   user: "mcp_firewall"
  #   password: "${DB_PASSWORD}"
  #   pool:
  #     min: 2
  #     max: 10
```

SQLite 用于本地开发，PostgreSQL 用于生产环境。

---

## 沙箱

```yaml
sandbox:
  enabled: true
  provider: docker
  image: "mcp-firewall/sandbox:latest"
  network: "none"           # none | bridge | host
  memoryLimit: "512m"
  cpuLimit: "1.0"
  timeout: "30s"
  volumeMounts:
    - "/tmp:/tmp:ro"        # 只读挂载
```

需要 Docker 运行。被沙箱化的工具在独立容器中执行，具有网络隔离和资源限制。

---

## 仪表盘

```yaml
dashboard:
  enabled: true
  host: "127.0.0.1"
  port: 9021
  authToken: ""            # 为空则不验证
```

Web 仪表盘提供实时指标、策略编辑、审计日志查询功能。

---

## 环境变量

配置中任何字符串都可以用 `${VAR_NAME}` 引用环境变量：

```yaml
auth:
  providers:
    - type: api-key
      keys:
        - key: "${MCP_FIREWALL_ADMIN_KEY}"
          clientId: admin

database:
  postgres:
    password: "${DB_PASSWORD}"
```

支持默认值：`${VAR_NAME:-default}`

---

## 热重载

修改 `mcp-firewall.yaml` 后，防火墙自动重载策略——无需重启。

- 使用 chokidar 监听文件变更
- 200ms 防抖，避免编辑器双重写入
- 原子切换策略引擎
- 进行中的请求用旧策略完成，新请求使用新策略
- 重载事件记录到审计日志

生产环境可以通过信号触发：
```bash
# 发送 SIGHUP 触发重载
kill -HUP $(pidof mcp-firewall)
```
