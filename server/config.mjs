/**
 * V6.2 — server configuration.
 *
 * Resolves bind host, port, and the storage backend at
 * startup. The configuration is server-only (no
 * VITE_ prefix, no secret values). The module reads
 * THREATPULSE_HTTP_HOST and THREATPULSE_HTTP_PORT; the
 * storage adapter is selected via THREATPULSE_STORAGE_BACKEND.
 */

import { createStorageAdapter } from '../netlify/functions/_shared/storage/index.mjs';

export const HTTP_DEFAULT_HOST = '127.0.0.1';
export const HTTP_DEFAULT_PORT = 8787;

export function resolveConfig({ argv = process.argv, env = process.env } = {}) {
  const host = env.THREATPULSE_HTTP_HOST || HTTP_DEFAULT_HOST;
  const port = Number(env.THREATPULSE_HTTP_PORT || HTTP_DEFAULT_PORT);
  const backend = (env.THREATPULSE_STORAGE_BACKEND || 'netlify').toLowerCase();
  const dataRoot = env.THREATPULSE_DATA_ROOT || null;
  const dryRun = env.THREATPULSE_DRY_RUN === '1' || env.THREATPULSE_DRY_RUN === 'true';
  // Storage adapter resolution is lazy — the actual
  // construction happens when a route first uses it.
  return {
    host,
    port: Number.isFinite(port) && port > 0 ? port : HTTP_DEFAULT_PORT,
    backend,
    dataRoot,
    dryRun,
    /** Factory: returns a fresh StorageAdapter for the named store. */
    storage(storeName) {
      return createStorageAdapter({ name: backend, storeName, opts: { dataRoot } });
    },
  };
}
