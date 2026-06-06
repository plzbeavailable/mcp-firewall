/**
 * Interpolate environment variables in a string using the ${VAR_NAME} or ${VAR_NAME:-default} syntax.
 */
export function interpolateEnv(content: string): string {
  return content.replace(/\$\{(\w+)(?::-([^}]*))?\}/g, (_match, varName: string, defaultValue: string | undefined) => {
    const value = process.env[varName];
    if (value !== undefined) return value;
    if (defaultValue !== undefined) return defaultValue;
    // Keep the placeholder if not found and no default
    return `\${${varName}}`;
  });
}
