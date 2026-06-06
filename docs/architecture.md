# MCP Firewall Architecture

## 概述

MCP Firewall 是一个 TypeScript 代理，位于 AI 客户端和 MCP 服务器之间。它由两层组成：

```
                    ┌─────────────────────────────┐
                    │        MCP Firewall          │
                    │                             │
AI Client ──►  ┌────▼────┐       ┌────────────┐  │
              │ 代理引擎  │ ────► │ 上游 MCP    │  │
(stdio/HTTP)  │          │       │ Server      │  │
              └────┬─────┘       └────────────┘  │
                   │                               │
         ┌─────────┴──────────┐                    │
         │                    │                    │
    ┌────▼─────┐       ┌──────▼──────┐            │
    │ 安全管道  │       │ 可观测性管道 │            │
    │          │       │             │            │
    │ • 白名单  │       │ • Metrics   │            │
    │ • 认证    │       │ • Tracing   │            │
    │ • RBAC   │       │ • 审计日志  │            │
    │ • 限流    │       │ • Token追踪 │            │
    │ • 校验    │       │ • 健康检查  │            │
    │ • 过滤    │       │             │            │
    │ • 脱敏    │       └─────────────┘            │
    └──────────┘                                  │
                    ┌──────────────┐               │
                    │ 策略引擎      │               │
                    │ (编译+缓存)   │               │
                    └──────────────┘               │
                    ┌──────────────┐               │
                    │ 插件系统      │               │
                    └──────────────┘               │
                    └─────────────────────────────┘
```

## 包结构

```
mcp-firewall/
├── apps/
│   └── proxy/               @mcp-firewall/proxy
│       CLI 入口：run / init / validate / dashboard
│
├── packages/
│   ├── config/              @mcp-firewall/config
│   │   Zod schema + YAML 加载 + 热重载 + 环境变量插值
│   │
│   ├── core/                @mcp-firewall/core
│   │   ├── transport/       代理引擎（stdio / HTTP / SSE）
│   │   ├── pipeline/        PipelineContext + 中间件接口
│   │   ├── security/        7 个安全中间件
│   │   ├── observability/   Metrics / Tracing / 审计日志 / Token追踪
│   │   ├── policy/          策略编译 + 原子热重载
│   │   ├── plugin/          插件系统（动态 import + 生命周期）
│   │   └── firewall.ts      主编排器
│   │
│   ├── db/                  @mcp-firewall/db
│   │   Drizzle ORM schema + SQLite/PostgreSQL + 仓储
│   │
│   └── dashboard-api/       @mcp-firewall/dashboard-api
│       Hono REST API（Phase 4 实现）
│
├── tests/
│   ├── fixtures/            Mock MCP Server (stdio + HTTP)
│   └── integration/         E2E 集成测试
│
└── examples/
    ├── docker-compose.yml   全栈部署
    ├── prometheus.yml       Prometheus 配置
    ├── grafana-dashboards/  Grafana 预置面板
    └── *.yaml               示例配置
```

## 数据流

### Stdio 模式

```
1. Parent (AI Client) 写 JSON-RPC 到 stdin
2. StdioProxy 读取 → 解析 JSON-RPC
3. Request Interceptor:
   a. 创建 PipelineContext
   b. 创建 Tracing Span
   c. 运行安全管道（顺序执行中间件）
   d. 如果 blocked → 直接写 JSON-RPC error 到 stdout，不转发
   e. 如果 allowed → 转发给 child stdin
4. Child (MCP Server) 处理 → 写响应到 stdout
5. StdioProxy 读取 child stdout → 解析 JSON-RPC
6. Response Interceptor:
   a. 运行安全管道（响应阶段中间件）
   b. 如果 blocked → 返回 error
   c. Token 追踪
   d. 审计日志
   e. 写（可能被脱敏的）响应到 stdout
```

### HTTP 模式

```
1. Client → HTTP POST to Firewall :9020
2. HttpProxy:
   a. CORS 处理
   b. 解析 JSON-RPC body
3. Request Interceptor (同步)
4. Firewall → HTTP POST to upstream MCP Server
5. Upstream Response
6. Response Interceptor (同步)
7. Firewall → HTTP Response to Client
```

## 安全管道执行顺序

```
Request phase:
  1. MethodAllowlist (prio 10)  — 方法白名单
  2. ApiKeyAuth      (prio 20)  — 验证 API Key
  3. JwtAuth         (prio 25)  — 验证 JWT Token
  4. Rbac            (prio 30)  — 权限控制
  5. RateLimiter     (prio 40)  — 速率限制
  6. ParamValidator  (prio 50)  — 参数校验 + AJV schema
  7. ContentFilter   (prio 60)  — 内容过滤（输入阶段）
  8. Sandbox         (prio 75)  — Docker 沙箱执行
       │
       ▼  [Forward to upstream]
       │
Response phase:
  9. SensitiveData   (prio 120) — 敏感数据检测 + 脱敏
 10. ContentFilter   (prio 60)  — 内容过滤（输出阶段）
 11. AuditLog        (implicit) — 审计日志
```

每个中间件都可以返回 `block`（停止管道）、`warn`（继续但记录）或 `allow`/`null`（放行）。

## 策略引擎

```
用户 YAML 配置
    │
    ▼
Zod 校验 + 默认值合并
    │
    ▼
PolicyEngine.compile()
    ├── 编译 glob 模式 → RegExp
    ├── 转换为中间件实例
    ├── 按优先级排序
    └── 注册到 Pipeline
    │
    ▼
热重载 (chokidar)
    ├── 检测文件变更 (200ms debounce)
    ├── 重新编译策略
    ├── 创建新 Pipeline
    └── 原子替换引用 (in-flight 请求用旧 pipeline)
```
