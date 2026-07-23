/**
 * V6.2 — In-memory storage adapter.
 *
 * A process-local Map-backed adapter used for:
 *   - unit and acceptance tests (no real disk or Netlify
 *     required),
 *   - ephemeral CI runs,
 *   - the optional `--dry-run` mode of the CLI jobs.
 *
 * The adapter is not persistent; data is lost when the
 * process exits. It enforces the same key validation
 * and adapter contract as the other backends.
 */

import { StorageAdapter, assertValidKey } from './StorageAdapter.mjs';

export class InMemoryStorageAdapter extends StorageAdapter {
  constructor(opts = {}) {
    super({ name: 'memory', ...opts });
    this._store = new Map(); // key -> Buffer
  }

  async _get(key) {
    assertValidKey(key);
    const v = this._store.get(key);
    if (v === undefined) return null;
    // Return a fresh copy so callers cannot mutate the
    // stored value.
    if (v instanceof Buffer) return Buffer.from(v);
    return v;
  }

  async _set(key, value) {
    assertValidKey(key);
    this._store.set(key, Buffer.isBuffer(value) ? Buffer.from(value) : Buffer.from(value));
  }

  async delete(key) {
    assertValidKey(key);
    this._store.delete(key);
  }

  async _list(prefix = '') {
    const matched = [];
    for (const k of this._store.keys()) {
      if (k.startsWith(prefix)) matched.push(k);
    }
    matched.sort();
    return { blobs: matched.map((k) => ({ key: k, etag: '' })) };
  }

  async _exists(key) {
    return this._store.has(key);
  }

  /**
   * Test seam: snapshot the underlying Map (key ->
   * bytes). Not part of the StorageAdapter contract.
   */
  snapshot() {
    const out = {};
    for (const [k, v] of this._store.entries()) {
      out[k] = Buffer.from(v);
    }
    return out;
  }

  /**
   * Test seam: clear the store.
   */
  clear() {
    this._store.clear();
  }
}
