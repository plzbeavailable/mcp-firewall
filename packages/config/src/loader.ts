import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import yaml from 'js-yaml';
import { FirewallConfig, FirewallConfigSchema } from './schema';
import { DEFAULT_CONFIG } from './defaults';
import { interpolateEnv } from './interpolate';

export interface LoadResult {
  config: FirewallConfig;
  filePath: string;
}

/**
 * Detect whether a string looks like JSON (starts with `{`) or YAML.
 */
function isJson(content: string): boolean {
  const trimmed = content.trimStart();
  return trimmed.startsWith('{');
}

/**
 * Load and validate a firewall config from a file path.
 * Supports .yaml, .yml, and .json extensions.
 * Merges user config with sensible defaults and interpolates
 * environment variables (${VAR_NAME} syntax).
 */
export function loadConfig(filePath: string): LoadResult {
  const resolved = resolve(filePath);
  const raw = readFileSync(resolved, 'utf-8');

  // Parse first, then interpolate env vars in the parsed values.
  // This avoids YAML escape issues when env var values contain backslashes (e.g. Windows paths).
  let parsed: unknown;
  if (isJson(raw)) {
    parsed = JSON.parse(raw);
  } else {
    parsed = yaml.load(raw);
  }

  // Interpolate env vars recursively in the parsed object
  const interpolated = interpolateValues(parsed);

  const merged = deepMerge(DEFAULT_CONFIG, interpolated as Record<string, unknown>);
  const config = FirewallConfigSchema.parse(merged);

  return { config, filePath: resolved };
}

/**
 * Load config from a raw string (used for inline config or testing).
 */
export function loadConfigFromString(content: string): FirewallConfig {
  let parsed: unknown;
  if (isJson(content)) {
    parsed = JSON.parse(content);
  } else {
    parsed = yaml.load(content);
  }

  const interpolated = interpolateValues(parsed);

  const merged = deepMerge(DEFAULT_CONFIG, interpolated as Record<string, unknown>);
  return FirewallConfigSchema.parse(merged);
}

/**
 * Validate a loaded config (returns parsed or throws ZodError).
 */
export function validateConfig(raw: unknown): FirewallConfig {
  return FirewallConfigSchema.parse(raw);
}

/**
 * Shallow deep merge — user values override defaults at the top level,
 * and nested object values are merged recursively.
 */
function deepMerge(
  defaults: Record<string, unknown>,
  overrides: Record<string, unknown>,
): Record<string, unknown> {
  const result = { ...defaults };
  for (const [key, val] of Object.entries(overrides)) {
    if (val !== null && typeof val === 'object' && !Array.isArray(val)) {
      const existing = result[key];
      if (existing !== null && typeof existing === 'object' && !Array.isArray(existing)) {
        result[key] = deepMerge(
          existing as Record<string, unknown>,
          val as Record<string, unknown>,
        );
        continue;
      }
    }
    result[key] = val;
  }
  return result;
}

/**
 * Recursively interpolate ${VAR_NAME} env vars in all string values of a parsed config.
 * This avoids YAML escape issues with Windows paths.
 */
function interpolateValues(value: unknown): unknown {
  if (typeof value === 'string') {
    return value.replace(/\$\{(\w+)(?::-([^}]*))?\}/g, (_m, varName: string, defaultVal: string | undefined) => {
      const envVal = process.env[varName];
      if (envVal !== undefined) return envVal;
      if (defaultVal !== undefined) return defaultVal;
      return `\${${varName}}`;
    });
  }
  if (Array.isArray(value)) {
    return value.map(interpolateValues);
  }
  if (value !== null && typeof value === 'object') {
    const result: Record<string, unknown> = {};
    for (const [key, val] of Object.entries(value as Record<string, unknown>)) {
      result[key] = interpolateValues(val);
    }
    return result;
  }
  return value;
}
