# MCP Firewall 插件开发指南

MCP Firewall 支持通过插件扩展安全能力。插件是实现了 `SecurityPlugin` 接口的 JavaScript/TypeScript 模块。

## 快速开始

### 1. 创建插件文件

```typescript
// my-plugin.ts
import type { SecurityPlugin, PluginContext, PipelineContext, SecurityDecision } from '@mcp-firewall/core';

const plugin: SecurityPlugin = {
  name: 'my-custom-plugin',
  version: '1.0.0',
  description: 'A custom security plugin',

  // 插件加载时调用
  async onLoad(ctx: PluginContext) {
    ctx.logger.info('Plugin loaded', { version: '1.0.0' });

    // 注册自定义指标
    ctx.registerMetric('my_custom_checks_total', 'Custom checks counter', 'counter');
  },

  // 插件卸载时调用（清理资源）
  async onUnload() {
    // 关闭连接、清除定时器等
  },

  // 请求阶段：在转发之前评估
  async evaluateRequest(ctx: PipelineContext): Promise<SecurityDecision | null> {
    const params = ctx.request.params as Record<string, unknown> | undefined;
    const content = params?.arguments as Record<string, unknown> | undefined;

    // 自定义检查逻辑
    if (content?.data && typeof content.data === 'string' && content.data.includes('malware')) {
      return {
        verdict: 'block',
        reason: 'Malware signature detected by custom plugin',
        errorCode: -32001,
      };
    }

    return null; // 放行
  },

  // 响应阶段：在返回之前评估
  async evaluateResponse(ctx: PipelineContext): Promise<SecurityDecision | null> {
    // 检查响应内容
    return null;
  },

  // 修改请求参数（返回新的 request 对象）
  async transformRequest(request, ctx) {
    // 可以在这里注入默认参数
    return request;
  },

  // 修改响应数据（返回新的 response 对象）
  async transformResponse(response, ctx) {
    // 可以在这里脱敏或格式化
    return response;
  },

  // 配置热重载时调用
  onConfigReload(newConfig: Record<string, unknown>) {
    // 更新插件配置
  },
};

export default plugin;
```

### 2. 注册插件

在 `mcp-firewall.yaml` 中配置：

```yaml
plugins:
  - name: my-custom-plugin
    path: "./plugins/my-plugin.ts"       # 本地文件
    # 或从 npm 包加载:
    # package: "@my-org/mcp-firewall-plugin"
    config:
      threshold: 0.95
      blockList:
        - "forbidden-word"
        - "secret-project"
```

### 3. 启动

```bash
mcp-firewall run mcp-firewall.yaml
```

插件会在防火墙启动时自动加载。

---

## SecurityPlugin 接口参考

```typescript
interface SecurityPlugin {
  /** 唯一标识符 */
  readonly name: string;

  /** 版本号 */
  readonly version: string;

  /** 一行描述 */
  readonly description?: string;

  /** 加载时调用 */
  onLoad?(ctx: PluginContext): Promise<void>;

  /** 卸载时调用 */
  onUnload?(): Promise<void>;

  /** 请求评估（返回 block/warn/allow） */
  evaluateRequest?(ctx: PipelineContext): Promise<SecurityDecision | null>;

  /** 响应评估 */
  evaluateResponse?(ctx: PipelineContext): Promise<SecurityDecision | null>;

  /** 修改请求参数 */
  transformRequest?(request: JSONRPCRequest, ctx: PipelineContext): Promise<JSONRPCRequest>;

  /** 修改响应数据 */
  transformResponse?(response: JSONRPCResponse, ctx: PipelineContext): Promise<JSONRPCResponse>;

  /** 配置热重载 */
  onConfigReload?(newConfig: Record<string, unknown>): void;
}
```

---

## PluginContext

```typescript
interface PluginContext {
  /** 插件专属配置（来自 mcp-firewall.yaml plugins[].config） */
  config: Record<string, unknown>;

  /** 结构化日志（自动附加插件名前缀） */
  logger: {
    info(msg: string, meta?: Record<string, unknown>): void;
    warn(msg: string, meta?: Record<string, unknown>): void;
    error(msg: string, meta?: Record<string, unknown>): void;
    debug(msg: string, meta?: Record<string, unknown>): void;
  };

  /** 获取当前防火墙配置 */
  getFirewallConfig(): Record<string, unknown>;

  /** 注册自定义 Prometheus 指标 */
  registerMetric(name: string, help: string, type: 'counter' | 'gauge' | 'histogram'): void;
}
```

---

## PipelineContext

请求/响应流经管道时携带的上下文：

```typescript
interface PipelineContext {
  requestId: string;           // UUID v4
  traceId: string;             // OpenTelemetry trace ID
  spanId: string;              // OpenTelemetry span ID
  client: {
    clientId: string;
    authType: 'api-key' | 'jwt' | 'none';
    claims?: Record<string, unknown>;  // JWT claims
  };
  serverName: string;          // 上游服务器名称
  method: string;              // JSON-RPC 方法
  toolName?: string;           // 工具名（tools/call 时）
  request: JSONRPCRequest;     // 原始请求
  response?: JSONRPCResponse;  // 原始响应（仅 response 阶段）
  startTime: number;           // 入站时间戳（epoch ms）
  upstreamResponseTime?: number;
  securityEvents: SecurityEvent[];  // 已记录的安全事件
  tokenUsage?: TokenUsage;     // Token 估算
  metadata: Record<string, unknown>;  // 附加数据（中间件间共享）
}
```

---

## SecurityDecision

```typescript
interface SecurityDecision {
  verdict: 'allow' | 'block' | 'warn';
  reason: string;              // 人类可读的原因
  errorCode?: number;          // JSON-RPC 错误码（block 时）
  metadata?: Record<string, unknown>;  // 附加数据
}
```

---

## 插件开发示例

### 示例 1：IP 黑名单

```typescript
const BLOCKED_IPS = new Set(['10.0.0.1', '192.168.1.100']);

const ipBlocker: SecurityPlugin = {
  name: 'ip-blocker',
  version: '1.0.0',

  async evaluateRequest(ctx) {
    const ip = ctx.metadata['clientIp'] as string;
    if (ip && BLOCKED_IPS.has(ip)) {
      return {
        verdict: 'block',
        reason: `IP ${ip} is blocked`,
        errorCode: -32001,
      };
    }
    return null;
  },
};
```

### 示例 2：请求大小限制

```typescript
const sizeLimiter: SecurityPlugin = {
  name: 'size-limiter',
  version: '1.0.0',

  async evaluateRequest(ctx) {
    const size = JSON.stringify(ctx.request.params).length;
    if (size > 1024 * 1024) { // 1MB
      return {
        verdict: 'block',
        reason: `Request exceeds 1MB limit (${(size / 1024 / 1024).toFixed(2)}MB)`,
        errorCode: -32602,
      };
    }
    return null;
  },
};
```

### 示例 3：自定义响应脱敏

```typescript
const dataMasker: SecurityPlugin = {
  name: 'data-masker',
  version: '1.0.0',

  async transformResponse(response, ctx) {
    if ('result' in response && response.result) {
      const result = JSON.stringify(response.result);
      // 替换中国身份证号
      const masked = result.replace(
        /\b\d{6}(19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b/g,
        '***ID_MASKED***'
      );
      return JSON.parse(masked);
    }
    return response;
  },
};
```

---

## 注意事项

1. **进程内执行**——插件在防火墙主进程中运行。仅加载可信插件。
2. **错误处理**——插件抛出的异常被捕获并记录，不会导致防火墙崩溃。评估阶段异常视为 block。
3. **不可变性**——`transformRequest` 和 `transformResponse` 必须返回新对象，不能修改原对象。
4. **异步友好**——所有钩子都是 async 的，可以做网络请求、数据库查询等异步操作。
5. **未来：Wasm 沙箱**——计划支持 Wasm 插件沙箱，用燃料计量控制执行时间。
