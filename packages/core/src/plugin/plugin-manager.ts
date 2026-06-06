import type { PipelineContext, SecurityDecision } from '../pipeline/types';
import type { JSONRPCRequest, JSONRPCResponse } from '../transport/mcp-types';

// ─── Plugin interface ──────────────────────────────────────────

/**
 * Context passed to plugins at load time.
 * Provides access to firewall internals without exposing
 * the entire system.
 */
export interface PluginContext {
  /** Plugin-specific config from mcp-firewall.yaml */
  config: Record<string, unknown>;

  /** Logger that writes to the firewall's audit log */
  logger: PluginLogger;

  /** Read the current firewall configuration */
  getFirewallConfig: () => Record<string, unknown>;

  /** Register a custom metric */
  registerMetric: (name: string, help: string, type: 'counter' | 'gauge' | 'histogram') => void;
}

export interface PluginLogger {
  info(message: string, metadata?: Record<string, unknown>): void;
  warn(message: string, metadata?: Record<string, unknown>): void;
  error(message: string, metadata?: Record<string, unknown>): void;
  debug(message: string, metadata?: Record<string, unknown>): void;
}

/**
 * The SecurityPlugin interface that all plugins must implement.
 *
 * Plugins are loaded from npm packages or local files and
 * execute within the firewall process. They can:
 * - Evaluate requests (pre-forward) and responses (post-forward)
 * - Transform request params and response data
 * - Register custom metrics
 * - Access plugin-specific configuration
 *
 * Security: Plugins run in the same Node.js process. Only
 * load plugins from trusted sources. Future versions may
 * support Wasm-based sandboxing for untrusted plugins.
 */
export interface SecurityPlugin {
  /** Unique plugin identifier (camelCase, no special chars) */
  readonly name: string;

  /** Semantic version of the plugin */
  readonly version: string;

  /** Optional: one-line description */
  readonly description?: string;

  /**
   * Called when the plugin is loaded.
   * Use this to initialize resources, register metrics, etc.
   */
  onLoad?(ctx: PluginContext): Promise<void>;

  /**
   * Called when the plugin is unloaded.
   * Use this to clean up resources (close connections, clear intervals, etc.)
   */
  onUnload?(): Promise<void>;

  /**
   * Evaluate an incoming request BEFORE it's forwarded to the upstream server.
   * Return null to pass through, or a SecurityDecision to block/allow/warn.
   */
  evaluateRequest?(ctx: PipelineContext): Promise<SecurityDecision | null>;

  /**
   * Evaluate an outgoing response BEFORE it's returned to the client.
   * Return null to pass through, or a SecurityDecision to block/allow/warn.
   */
  evaluateResponse?(ctx: PipelineContext): Promise<SecurityDecision | null>;

  /**
   * Transform the request parameters before forwarding.
   * Return the modified request (or original to pass through).
   * MUST not modify the original object; return a new one.
   */
  transformRequest?(request: JSONRPCRequest, ctx: PipelineContext): Promise<JSONRPCRequest>;

  /**
   * Transform the response data before returning to client.
   * Return the modified response (or original to pass through).
   * MUST not modify the original object; return a new one.
   */
  transformResponse?(response: JSONRPCResponse, ctx: PipelineContext): Promise<JSONRPCResponse>;

  /**
   * Called when the firewall configuration is hot-reloaded.
   * Plugin config is extracted from `plugins.[name]` in the config.
   */
  onConfigReload?(newConfig: Record<string, unknown>): void;
}

// ─── Plugin Manager ────────────────────────────────────────────

export interface PluginEntry {
  plugin: SecurityPlugin;
  config: Record<string, unknown>;
  loaded: boolean;
}

/**
 * The PluginManager handles the lifecycle of all loaded plugins.
 *
 * Plugins are defined in the firewall config:
 *
 * ```yaml
 * plugins:
 *   - name: my-custom-plugin
 *     package: "@my-org/mcp-firewall-plugin"
 *     config:
 *       customOption: value
 *   - name: local-plugin
 *     path: "./plugins/my-plugin.ts"
 *     config: {}
 * ```
 */
export class PluginManager {
  private plugins: Map<string, PluginEntry> = new Map();
  private logger: PluginLogger;

  constructor(logger?: PluginLogger) {
    this.logger = logger ?? createConsoleLogger();
  }

  /**
   * Load a plugin from its module.
   * The module must export a default or named `plugin` that
   * implements the SecurityPlugin interface.
   */
  async loadPlugin(
    name: string,
    modulePath: string,
    config: Record<string, unknown>,
  ): Promise<void> {
    if (this.plugins.has(name)) {
      throw new Error(`Plugin "${name}" is already loaded`);
    }

    this.logger.info(`Loading plugin: ${name} from ${modulePath}`);

    try {
      // Dynamic import of the plugin module
      const mod = await import(modulePath);
      const plugin: SecurityPlugin = mod.default ?? mod.plugin;

      if (!plugin) {
        throw new Error(
          `Plugin module at "${modulePath}" does not export a default or named "plugin" export`,
        );
      }

      // Validate the plugin interface
      if (!plugin.name || !plugin.version) {
        throw new Error(`Plugin at "${modulePath}" is missing required "name" or "version"`);
      }

      // Call onLoad if defined
      if (plugin.onLoad) {
        const ctx = this.createPluginContext(name, config);
        await plugin.onLoad(ctx);
      }

      this.plugins.set(name, { plugin, config, loaded: true });
      this.logger.info(`Plugin loaded: ${name} v${plugin.version}`);
    } catch (err) {
      this.logger.error(
        `Failed to load plugin "${name}": ${err instanceof Error ? err.message : String(err)}`,
      );
      throw err;
    }
  }

  /**
   * Unload a plugin and call its onUnload hook.
   */
  async unloadPlugin(name: string): Promise<void> {
    const entry = this.plugins.get(name);
    if (!entry) return;

    this.logger.info(`Unloading plugin: ${name}`);

    try {
      if (entry.plugin.onUnload) {
        await entry.plugin.onUnload();
      }
    } catch (err) {
      this.logger.error(
        `Error unloading plugin "${name}": ${err instanceof Error ? err.message : String(err)}`,
      );
    }

    this.plugins.delete(name);
  }

  /**
   * Reload a plugin (unload + load).
   */
  async reloadPlugin(
    name: string,
    modulePath: string,
    config: Record<string, unknown>,
  ): Promise<void> {
    await this.unloadPlugin(name);

    // Clear require/import cache if it's a local file
    try {
      delete require.cache[require.resolve(modulePath)];
    } catch {
      // Not in require cache — that's fine
    }

    await this.loadPlugin(name, modulePath, config);
  }

  /**
   * Run all plugins' evaluateRequest hooks.
   * Returns the first block decision, or null if all pass.
   */
  async evaluateRequest(ctx: PipelineContext): Promise<SecurityDecision | null> {
    for (const [, entry] of this.plugins) {
      if (!entry.plugin.evaluateRequest) continue;

      try {
        const result = await entry.plugin.evaluateRequest(ctx);
        if (result?.verdict === 'block') return result;
      } catch (err) {
        this.logger.error(
          `Plugin "${entry.plugin.name}" error in evaluateRequest: ${err instanceof Error ? err.message : String(err)}`,
        );
      }
    }
    return null;
  }

  /**
   * Run all plugins' evaluateResponse hooks.
   * Returns the first block decision, or null if all pass.
   */
  async evaluateResponse(ctx: PipelineContext): Promise<SecurityDecision | null> {
    for (const [, entry] of this.plugins) {
      if (!entry.plugin.evaluateResponse) continue;

      try {
        const result = await entry.plugin.evaluateResponse(ctx);
        if (result?.verdict === 'block') return result;
      } catch (err) {
        this.logger.error(
          `Plugin "${entry.plugin.name}" error in evaluateResponse: ${err instanceof Error ? err.message : String(err)}`,
        );
      }
    }
    return null;
  }

  /**
   * Run all plugins' transformRequest hooks in sequence.
   */
  async transformRequest(request: JSONRPCRequest, ctx: PipelineContext): Promise<JSONRPCRequest> {
    let transformed = request;
    for (const [, entry] of this.plugins) {
      if (!entry.plugin.transformRequest) continue;
      try {
        transformed = await entry.plugin.transformRequest(transformed, ctx);
      } catch (err) {
        this.logger.error(
          `Plugin "${entry.plugin.name}" error in transformRequest: ${err instanceof Error ? err.message : String(err)}`,
        );
      }
    }
    return transformed;
  }

  /**
   * Run all plugins' transformResponse hooks in sequence.
   */
  async transformResponse(
    response: JSONRPCResponse,
    ctx: PipelineContext,
  ): Promise<JSONRPCResponse> {
    let transformed = response;
    for (const [, entry] of this.plugins) {
      if (!entry.plugin.transformResponse) continue;
      try {
        transformed = await entry.plugin.transformResponse(transformed, ctx);
      } catch (err) {
        this.logger.error(
          `Plugin "${entry.plugin.name}" error in transformResponse: ${err instanceof Error ? err.message : String(err)}`,
        );
      }
    }
    return transformed;
  }

  /**
   * Notify all plugins of a config reload.
   */
  notifyConfigReload(pluginsConfig: Record<string, Record<string, unknown>>): void {
    for (const [name, entry] of this.plugins) {
      const newConfig = pluginsConfig[name] ?? entry.config;
      entry.config = newConfig;

      if (entry.plugin.onConfigReload) {
        try {
          entry.plugin.onConfigReload(newConfig);
        } catch (err) {
          this.logger.error(
            `Plugin "${name}" error in onConfigReload: ${err instanceof Error ? err.message : String(err)}`,
          );
        }
      }
    }
  }

  /**
   * Get all loaded plugin names.
   */
  getPluginNames(): string[] {
    return Array.from(this.plugins.keys());
  }

  /**
   * Get a specific plugin entry.
   */
  getPlugin(name: string): PluginEntry | undefined {
    return this.plugins.get(name);
  }

  /**
   * Shut down all plugins.
   */
  async shutdown(): Promise<void> {
    const names = Array.from(this.plugins.keys());
    for (const name of names) {
      await this.unloadPlugin(name);
    }
  }

  private createPluginContext(pluginName: string, config: Record<string, unknown>): PluginContext {
    const customMetrics: Map<string, { name: string; help: string; type: string }> = new Map();

    return {
      config,
      logger: {
        info: (msg, meta) => this.logger.info(`[plugin:${pluginName}] ${msg}`, meta),
        warn: (msg, meta) => this.logger.warn(`[plugin:${pluginName}] ${msg}`, meta),
        error: (msg, meta) => this.logger.error(`[plugin:${pluginName}] ${msg}`, meta),
        debug: (msg, meta) => this.logger.debug(`[plugin:${pluginName}] ${msg}`, meta),
      },
      getFirewallConfig: () => ({}),
      registerMetric: (name, help, type) => {
        customMetrics.set(name, { name, help, type });
      },
    };
  }
}

// ─── Built-in logger ───────────────────────────────────────────

function createConsoleLogger(): PluginLogger {
  return {
    info: (msg, meta) => console.log(JSON.stringify({ level: 'info', msg, ...meta })),
    warn: (msg, meta) => console.warn(JSON.stringify({ level: 'warn', msg, ...meta })),
    error: (msg, meta) => console.error(JSON.stringify({ level: 'error', msg, ...meta })),
    debug: (msg, meta) => {
      if (process.env['MCP_FIREWALL_DEBUG']) {
        console.debug(JSON.stringify({ level: 'debug', msg, ...meta }));
      }
    },
  };
}
