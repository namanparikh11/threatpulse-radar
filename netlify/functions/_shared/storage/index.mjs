/**
 * V6.2 — Storage adapter module entry.
 *
 * Re-exports the StorageAdapter base class and the three
 * concrete adapters, plus a factory that selects an
 * adapter by name and environment.
 *
 * The factory inspects `THREATPULSE_STORAGE_BACKEND`
 * (default: 'netlify') and the relevant environment
 * variables:
 *
 *   - 'netlify' (default): NetlifyBlobsStorageAdapter.
 *     siteID and token are auto-detected from the
 *     Netlify runtime unless THREATPULSE_SITE_ID and
 *     THREATPULSE_BLOBS_TOKEN are provided.
 *   - 'filesystem': FilesystemStorageAdapter backed by
 *     THREATPULSE_DATA_ROOT (required).
 *   - 'memory': InMemoryStorageAdapter. The store is
 *     process-local and ephemeral.
 *
 * The factory does NOT touch Netlify runtime
 * environment variables when the backend is
 * 'filesystem' or 'memory', so the same code path
 * works on Hostinger Business, a VPS, or a developer's
 * laptop.
 */

import { join as pathJoin } from 'node:path';

import { InMemoryStorageAdapter } from './InMemoryStorageAdapter.mjs';

export { StorageAdapter, STORAGE_TYPE, assertValidKey } from './StorageAdapter.mjs';
export { NetlifyBlobsStorageAdapter } from './NetlifyBlobsStorageAdapter.mjs';
export { FilesystemStorageAdapter } from './FilesystemStorageAdapter.mjs';
export { InMemoryStorageAdapter } from './InMemoryStorageAdapter.mjs';

/**
 * Create a StorageAdapter by name and options. The
 * factory is the single place that maps configuration
 * to a concrete backend.
 *
 *   - name: 'netlify' | 'filesystem' | 'memory'
 *   - storeName: the Blob store / directory namespace
 *   - opts: backend-specific options
 *
 * The factory does NOT validate `opts` against the
 * deployment environment; it merely instantiates the
 * adapter. The caller is responsible for providing a
 * valid `dataRoot` for the filesystem backend.
 */
export function createStorageAdapter({ name, storeName, opts = {} } = {}) {
  const backend = (name || process.env.THREATPULSE_STORAGE_BACKEND || 'netlify').toLowerCase();
  if (backend === 'netlify') {
    return new NetlifyBlobsStorageAdapter({
      storeName,
      siteID: opts.siteID || process.env.THREATPULSE_SITE_ID || null,
      token: opts.token || process.env.THREATPULSE_BLOBS_TOKEN || null,
    });
  }
  if (backend === 'filesystem') {
    const dataRoot = opts.dataRoot || process.env.THREATPULSE_DATA_ROOT;
    if (!dataRoot) {
      throw new Error('createStorageAdapter: filesystem backend requires a dataRoot (THREATPULSE_DATA_ROOT)');
    }
    // The storeName becomes a subdirectory under the
    // data root so multiple Blob-store namespaces
    // (e.g. tpr-baseline, tpr-dataset) coexist in a
    // single filesystem root.
    return new FilesystemStorageAdapter({
      dataRoot: pathJoin(dataRoot, storeName || 'default'),
    });
  }
  if (backend === 'memory') {
    return new InMemoryStorageAdapter(opts);
  }
  throw new Error(`createStorageAdapter: unknown backend "${backend}"`);
}
