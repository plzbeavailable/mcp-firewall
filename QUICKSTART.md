# 如何在本地启用 MCP Firewall

> 3 步，1 分钟内跑起来

## 前提

- Node.js 22+（你已有）

## 激活方式：一键启动

打开终端，复制粘贴执行：

```bash
cd E:/hub/mcp-firewall

# 第 1 步：启动 Mock MCP 服务器（模拟真实的 MCP Server）
Start-Process -NoNewWindow node -ArgumentList "tests/fixtures/mock-mcp-http.js"

# 等待 2 秒
Start-Sleep 2

# 第 2 步：启动防火墙代理
Start-Process -NoNewWindow node -ArgumentList "apps/proxy/dist/index.js run examples/docker-firewall-config.yaml"

# 等待 3 秒
Start-Sleep 3

# 第 3 步：测试
Invoke-WebRequest -Uri http://localhost:9020/ -Method POST -ContentType "application/json" -Body '{"jsonrpc":"2.0","id":"1","method":"tools/call","params":{"name":"echo","arguments":{"message":"Hello Firewall!"}}}'
```

**如果你想用 Bash（Git Bash / WSL）：**

```bash
cd /e/hub/mcp-firewall

# 第 1 步
node tests/fixtures/mock-mcp-http.js &
sleep 2

# 第 2 步
node apps/proxy/dist/index.js run examples/docker-firewall-config.yaml &
sleep 3

# 第 3 步
curl -X POST http://localhost:9020/ \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":"1","method":"tools/call","params":{"name":"echo","arguments":{"message":"Hello Firewall!"}}}'
```

## 验证：确认所有服务在运行

```bash
# Mock MCP 服务器
curl http://localhost:8080/
# → {"status":"ok","server":"mock-mcp-http"}

# 防火墙代理
curl -X POST http://localhost:9020/ -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":"1","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}'
# → {"jsonrpc":"2.0","id":"1","result":{...}}

# Prometheus 指标
curl http://localhost:9090/metrics
# → mcp_firewall_uptime_seconds ...

# 仪表盘 API
curl http://localhost:9021/api/health
# → {"status":"ok"}
```

## 体验面板

浏览器打开：
```
file:///E:/hub/mcp-firewall/examples/playground.html
```

按钮一键发送请求，看到实时拦截效果。

## 停止

```bash
# 查找并停止进程
taskkill //F //IM node.exe
# 或更精确地：
netstat -ano | findstr ":8080 :9020 :9090" | ...
```

## 配置 Claude Desktop

编辑 Claude Desktop 的配置文件，加入：

```json
{
  "mcpServers": {
    "filesystem-firewalled": {
      "command": "node",
      "args": [
        "E:/hub/mcp-firewall/apps/proxy/dist/index.js",
        "run",
        "E:/hub/mcp-firewall/examples/claude-desktop-firewall.yaml"
      ]
    }
  }
}
```

然后重启 Claude Desktop，此时所有 filesystem MCP 调用都经过防火墙——写入操作被 RBAC 规则拦截，敏感数据自动脱敏。

---

## 开机自启（可选）

### Windows

创建一个 `.bat` 文件放到启动文件夹：

```bat
@echo off
cd /d E:\hub\mcp-firewall
start "Mock MCP" node tests/fixtures/mock-mcp-http.js
timeout /t 2 /nobreak > nul
start "Firewall" node apps/proxy/dist/index.js run examples/docker-firewall-config.yaml
```

路径：`Win+R` → `shell:startup` → 放入该文件 → 下次开机自动运行。

### Mac / Linux (systemd)

```bash
sudo tee /etc/systemd/system/mcp-firewall.service << 'EOF'
[Unit]
Description=MCP Firewall
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/mcp-firewall
ExecStart=/usr/bin/node /opt/mcp-firewall/apps/proxy/dist/index.js run /etc/mcp-firewall/mcp-firewall.yaml
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now mcp-firewall
```
