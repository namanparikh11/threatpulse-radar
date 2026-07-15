/**
 * V6.2 — Netlify Blobs storage adapter.
 *
 * Thin wrapper over `@netlify/blobs` that exposes the
 * StorageAdapter contract. This adapter preserves every
 * existing Netlify deployment behavior: the siteID and
 * token are auto-detected from the Netlify runtime
 * environment unless explicit `siteID` + `token` are
 * provided, and a missing site context throws the same
 * way the underlying `getStore` does.
 *
 * The adapter is the production default. V6.1 behavior
 * is preserved: every existing call site continues to
 * work, the 5 public function entries continue to be
 * the only way to invoke the V6.0 / V6.1 refresh logic
 * on Netlify, and the 1 gateway function continues to
 * use the gateway-local store.
 */

import { getStore as netlifyGetStore } from '@netlify/blobs';
import { StorageAdapter, assertValidKey } from './StorageAdapter.mjs';

export class NetlifyBlobsStorageAdapter extends StorageAdapter {
  constructor({ storeName, siteID = null, token = null, consistency = null } = {}) {
    super({ name: 'netlify', siteID, token });
    if (!storeName || typeof storeName !== 'string') {
      throw new Error('NetlifyBlobsStorageAdapter: storeName is required');
    }
    this.storeName = storeName;
    this._consistency = consistency;
    // The Netlify client is created lazily on first use
    // so the constructor does not throw when invoked
    // outside the Netlify runtime (e.g. during module
    // load in local development).
    this._client = null;
  }

  _ensureClient() {
    if (this._client) return this._client;
    const opts = {};
    if (this.siteID) opts.siteID = this.siteID;
    if (this.token) opts.token = this.token;
    if (this._consistency) opts.consistency = this._consistency;
    this._client = netlifyGetStore(this.storeName, opts);
    return this._client;
  }

  async _get(key) {
    assertValidKey(key);
    const client = this._ensureClient();
    const v = await client.get(key, { type: 'arrayBuffer' });
    if (v === null || v === undefined) return null;
    return v instanceof Buffer ? Buffer.from(v) : Buffer.from(v);
  }

  async _set(key, value) {
    assertValidKey(key);
    const client = this._ensureClient();
    await client.setBinary(key, value);
  }

  async delete(key) {
    assertValidKey(key);
    const client = this._ensureClient();
    await client.delete(key);
  }

  async _list(prefix = '') {
    const client = this._ensureClient();
    const out = { blobs: [] };
    try {
      const res = await client.list({ prefix });
      if (res && Array.isArray(res.blobs)) out.blobs = res.blobs;
    } catch {
      // list() is best-effort; some deployments may
      // not support it. Return an empty result.
    }
    return out;
  }

  async _exists(key) {
    assertValidKey(key);
    const client = this._ensureClient();
    const v = await client.get(key, { type: 'arrayBuffer' });
    return v !== null && v !== undefined;
  }
}
