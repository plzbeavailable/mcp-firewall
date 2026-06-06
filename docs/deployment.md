# MCP Firewall 部署指南

## 目录

- [场景一：Claude Desktop 集成](#场景一claude-desktop-集成)
- [场景二：团队 HTTP 服务器](#场景二团队-http-服务器)
- [场景三：Docker Compose 全家桶](#场景三docker-compose-全家桶)
- [场景四：Kubernetes](#场景四kubernetes)
- [场景五：npm 全局安装](#场景五npm-全局安装)

---

## 场景一：Claude Desktop 集成

最简部署——防火墙作为 Claude Desktop 的子进程，透明代理 filesystem MCP Server。

### 1. 生成配置

```bash
cd ~/mcp-firewall-config
mcp-firewall init --output mcp-firewall.yaml
```

### 2. 编辑配置

```yaml
# mcp-firewall.yaml
version: "1"
mode: stdio

upstreams:
  - name: filesystem
    transport: stdio
    command: npx
    args:
      - "-y"
      - "@modelcontextprotocol/server-filesystem"
      - "/Users/me/Documents"  # 限制访问范围

policies:
  method_allowlist:
    enabled: true
    block_unknown: true

  rbac:
    enabled: true
    rules:
      - name: "allow-read-list"
        principals:
          - type: client-id
            pattern: "*"
        targets:
          - method: "tools/call"
            toolName: "read_*"
        permission: allow
      - name: "allow-list-dir"
        principals:
          - type: client-id
            pattern: "*"
        targets:
          - method: "tools/call"
            toolName: "list_*"
        permission: allow
      # 其他所有操作默认拒绝

  parameter_validation:
    enabled: true

  sensitive_data:
    enabled: true
    detectors:
      - type: api-key
        action: mask
      - type: credit-card
        action: mask
```

### 3. 配置 Claude Desktop

编辑 Claude Desktop 的 `claude_desktop_config.json`：

```json
{
  "mcpServers": {
    "filesystem-firewalled": {
      "command": "node",
      "args": [
        "/path/to/mcp-firewall/apps/proxy/dist/index.js",
        "run",
        "/Users/me/mcp-firewall-config/mcp-firewall.yaml"
      ]
    }
  }
}
```

### 4. 重启 Claude Desktop

重启后，Claude 对 filesystem MCP Server 的所有调用都经过防火墙。被拒绝的操作会显示为错误。

---

## 场景二：团队 HTTP 服务器

作为集中式代理部署，团队所有成员共用。

### 1. 准备配置

```yaml
# mcp-firewall.yaml
version: "1"
mode: http

server:
  host: "0.0.0.0"
  port: 9020

upstreams:
  - name: production-mcp
    transport: streamable-http
    url: "http://mcp-prod.internal:8080"
    healthCheck:
      enabled: true
      interval: "15s"

auth:
  enabled: true
  providers:
    - type: api-key
      keys:
        - key: "${TEAM_API_KEY}"
          clientId: team

policies:
  rbac:
    enabled: true
    rules:
      - name: "team-full-access"
        principals:
          - type: api-key
            pattern: "*"
        targets:
          - method: "*"
        permission: allow

  rate_limiting:
    enabled: true
    rules:
      - name: "team-global"
        window: "1m"
        maxRequests: 300
        keyBy: ["client-id"]

observability:
  metrics:
    enabled: true
    port: 9090

  audit_log:
    enabled: true
    output: sqlite   # 持久化到数据库

database:
  type: sqlite
  sqlite:
    path: "./data/mcp-firewall.db"
```

### 2. 作为 systemd 服务

```ini
# /etc/systemd/system/mcp-firewall.service
[Unit]
Description=MCP Firewall
After=network.target

[Service]
Type=simple
User=mcp-firewall
WorkingDirectory=/opt/mcp-firewall
Environment=NODE_ENV=production
Environment=TEAM_API_KEY=sk-secret-team-key
ExecStart=/usr/bin/node /opt/mcp-firewall/apps/proxy/dist/index.js run /etc/mcp-firewall/mcp-firewall.yaml
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now mcp-firewall
sudo systemctl status mcp-firewall
```

### 3. 客户端连接

团队成员配置 MCP 客户端，指向防火墙地址：

```json
{
  "mcpServers": {
    "team-server": {
      "command": "node",
      "args": [
        "-e",
        "process.stdin.write(JSON.stringify({jsonrpc:'2.0',id:'1',method:'initialize',params:{protocolVersion:'2024-11-05',capabilities:{},clientInfo:{name:'team',version:'1.0'}}})); process.exit(0)"
      ],
      "transport": "http",
      "url": "http://firewall.internal.example.com:9020"
    }
  }
}
```

或通过手动 HTTP 请求：

```bash
curl -X POST http://firewall.internal:9020/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TEAM_API_KEY" \
  -d '{"jsonrpc":"2.0","id":"1","method":"tools/list"}'
```

---

## 场景三：Docker Compose 全家桶

一键启动：防火墙 + Prometheus + Grafana + Jaeger + Mock MCP Server。

```bash
cd mcp-firewall
docker compose -f examples/docker-compose.e2e.yml up -d
```

提供的服务：

| 服务 | 端口 | 说明 |
|------|------|------|
| Mock MCP Server | `:8080` | 测试用 MCP 服务器 |
| MCP Firewall | `:9020` | 防火墙代理 |
| Prometheus | `:9091` | 指标收集 |
| Grafana | `:3000` | 仪表盘（预置面板） |
| Jaeger UI | `:16686` | 分布式追踪查看器 |
| Traffic Generator | — | 启动后自动发送 175+ 测试请求 |

Grafana 预置面板包含：
- 请求总量 / 拦截数量 / 延迟 / 活跃连接（统计卡片）
- 请求速率趋势图
- 延迟时间序列图
- 拦截速率与中间件分布
- Token 消耗堆叠图
- 上游服务器健康状态

---

## 场景四：Kubernetes

### Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mcp-firewall
  labels:
    app: mcp-firewall
spec:
  replicas: 3
  selector:
    matchLabels:
      app: mcp-firewall
  template:
    metadata:
      labels:
        app: mcp-firewall
    spec:
      containers:
        - name: firewall
          image: ghcr.io/mcp-firewall/mcp-firewall:v1.0.0
          ports:
            - containerPort: 9020
              name: proxy
            - containerPort: 9090
              name: metrics
            - containerPort: 9021
              name: dashboard
          env:
            - name: DB_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: mcp-firewall-db
                  key: password
          volumeMounts:
            - name: config
              mountPath: /app/mcp-firewall.yaml
              subPath: mcp-firewall.yaml
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
            limits:
              cpu: 500m
              memory: 256Mi
          readinessProbe:
            httpGet:
              path: /api/health
              port: 9021
            initialDelaySeconds: 5
            periodSeconds: 10
      volumes:
        - name: config
          configMap:
            name: mcp-firewall-config
---
apiVersion: v1
kind: Service
metadata:
  name: mcp-firewall
spec:
  selector:
    app: mcp-firewall
  ports:
    - port: 9020
      name: proxy
    - port: 9090
      name: metrics
    - port: 9021
      name: dashboard
```

### Prometheus ServiceMonitor

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: mcp-firewall
spec:
  selector:
    matchLabels:
      app: mcp-firewall
  endpoints:
    - port: metrics
      path: /metrics
      interval: 15s
```

---

## 场景五：npm 全局安装

```bash
# 安装（即将上线）
npm install -g @mcp-firewall/cli

# 或直接使用本地构建
cd mcp-firewall
pnpm run build

# 使用
mcp-firewall init
mcp-firewall validate mcp-firewall.yaml
mcp-firewall run mcp-firewall.yaml
```
