import { watch, FSWatcher } from 'chokidar';
import { EventEmitter } from 'node:events';
import { loadConfig, LoadResult } from './loader';
import { FirewallConfig } from './schema';

export interface HotReloadEvents {
  reload: (result: LoadResult) => void;
  error: (err: Error) => void;
}

/**
 * Watches the config file for changes and emits 'reload' events.
 * Uses a small debounce to avoid double-fires from some editors.
 */
export function createConfigWatcher(filePath: string): {
  watcher: FSWatcher;
  events: EventEmitter;
  stop: () => Promise<void>;
} {
  const events = new EventEmitter();
  let debounceTimer: ReturnType<typeof setTimeout> | null = null;

  const watcher = watch(filePath, {
    persistent: true,
    ignoreInitial: true,
    awaitWriteFinish: {
      stabilityThreshold: 300,
      pollInterval: 100,
    },
  });

  watcher.on('change', () => {
    if (debounceTimer) clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => {
      try {
        const result = loadConfig(filePath);
        events.emit('reload', result);
      } catch (err) {
        events.emit('error', err instanceof Error ? err : new Error(String(err)));
      }
    }, 200); // 200ms debounce
  });

  watcher.on('error', (err) => {
    events.emit('error', err instanceof Error ? err : new Error(String(err)));
  });

  return {
    watcher,
    events,
    stop: async () => {
      if (debounceTimer) clearTimeout(debounceTimer);
      await watcher.close();
    },
  };
}

/**
 * Syntactic sugar: subscribe to hot-reload events.
 */
export function onConfigReload(
  filePath: string,
  onReload: (config: FirewallConfig) => void,
  onError?: (err: Error) => void,
): () => Promise<void> {
  const { events, stop } = createConfigWatcher(filePath);
  events.on('reload', (result: LoadResult) => onReload(result.config));
  if (onError) events.on('error', onError);
  return stop;
}
