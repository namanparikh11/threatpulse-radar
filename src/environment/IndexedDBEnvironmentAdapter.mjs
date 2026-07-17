/**
 * V6.6 — IndexedDB environment adapter.
 *
 * Stores assets, inventory snapshots, components,
 * correlations, and review records in a single
 * database (`threatpulse-environment`). The adapter
 * never throws on a recoverable error; it returns
 * `{ ok, value }` or `{ ok: false, reason }` so the
 * caller can surface a sanitized message.
 *
 * Multi-tab notification uses a BroadcastChannel
 * (`threatpulse:environment:events`) so other tabs
 * can refresh their in-memory state when an
 * inventory or correlation is updated. The
 * BroadcastChannel is purely local — it does not
 * talk to the network.
 *
 * Schema migrations use the `onupgradeneeded` hook
 * and follow the same deterministic pattern as the
 * V6.4 workspace adapter. Bumping `DB_VERSION`
 * requires a matching migration entry.
 *
 * Atomic inventory promotion: the adapter writes
 * the inventory + its components + the asset's
 * latestInventoryId pointer in a single read-write
 * transaction. A failure rolls everything back, so
 * the previous inventory + correlation set remains
 * the source of truth.
 */

import { ASSET_SCHEMA_VERSION, COMPONENT_SCHEMA_VERSION } from './schema.mjs';
import { IDBKeyRange } from './_shim.mjs';

const DB_NAME = 'threatpulse-environment';
const DB_VERSION = 1;
const STORE_ASSETS = 'assets';
const STORE_INVENTORIES = 'inventories';
const STORE_COMPONENTS = 'components';
const STORE_CORRELATIONS = 'correlations';
const STORE_REVIEWS = 'reviews';
const STORE_META = 'meta';

const REASONS = Object.freeze({
  BLOCKED: 'indexeddb-blocked',
  QUOTA: 'quota-exceeded',
  TX_ABORTED: 'transaction-aborted',
  NOT_FOUND: 'not-found',
  INVALID: 'invalid-entry',
  UNKNOWN: 'unknown',
  CLOSED: 'adapter-closed',
  NOT_SUPPORTED: 'indexeddb-not-supported',
});

export class IndexedDBEnvironmentAdapter {
  constructor({ dbName = DB_NAME, broadcastChannelName = 'threatpulse:environment:events' } = {}) {
    this._dbName = dbName;
    this._channelName = broadcastChannelName;
    this._db = null;
    this._listeners = new Set();
    this._closed = false;
    this._unavailableReason = null;
    this._channel = null;
  }

  static get REASONS() { return REASONS; }

  static isSupported() {
    try {
      return typeof indexedDB !== 'undefined' && indexedDB !== null;
    } catch {
      return false;
    }
  }

  async open() {
    if (this._db) return { ok: true };
    if (this._closed) return { ok: false, reason: REASONS.CLOSED };
    if (!IndexedDBEnvironmentAdapter.isSupported()) {
      this._unavailableReason = REASONS.NOT_SUPPORTED;
      return { ok: false, reason: REASONS.NOT_SUPPORTED };
    }
    return new Promise((resolve) => {
      let req;
      try {
        req = indexedDB.open(this._dbName, DB_VERSION);
      } catch (err) {
        this._unavailableReason = REASONS.NOT_SUPPORTED;
        resolve({ ok: false, reason: REASONS.NOT_SUPPORTED });
        return;
      }
      req.onupgradeneeded = () => {
        const db = req.result;
        if (!db.objectStoreNames.contains(STORE_ASSETS)) {
          const s = db.createObjectStore(STORE_ASSETS, { keyPath: 'assetId' });
          s.createIndex('updatedAt', 'updatedAt', { unique: false });
          s.createIndex('archived', 'archived', { unique: false });
        }
        if (!db.objectStoreNames.contains(STORE_INVENTORIES)) {
          const s = db.createObjectStore(STORE_INVENTORIES, { keyPath: 'inventoryId' });
          s.createIndex('assetId', 'assetId', { unique: false });
          s.createIndex('importedAt', 'importedAt', { unique: false });
        }
        if (!db.objectStoreNames.contains(STORE_COMPONENTS)) {
          const s = db.createObjectStore(STORE_COMPONENTS, { keyPath: 'componentId' });
          s.createIndex('assetId', 'assetId', { unique: false });
          s.createIndex('inventoryId', 'inventoryId', { unique: false });
          s.createIndex('normalizedIdentityEcosystem', 'normalizedIdentity.ecosystem', { unique: false });
          s.createIndex('normalizedIdentityName', 'normalizedIdentity.name', { unique: false });
        }
        if (!db.objectStoreNames.contains(STORE_CORRELATIONS)) {
          const s = db.createObjectStore(STORE_CORRELATIONS, { keyPath: 'correlationId' });
          s.createIndex('assetId', 'assetId', { unique: false });
          s.createIndex('inventoryId', 'inventoryId', { unique: false });
          s.createIndex('cveId', 'cveId', { unique: false });
        }
        if (!db.objectStoreNames.contains(STORE_REVIEWS)) {
          const s = db.createObjectStore(STORE_REVIEWS, { keyPath: 'correlationId' });
          s.createIndex('updatedAt', 'updatedAt', { unique: false });
        }
        if (!db.objectStoreNames.contains(STORE_META)) {
          db.createObjectStore(STORE_META, { keyPath: 'key' });
        }
      };
      req.onsuccess = () => {
        this._db = req.result;
        this._db.onversionchange = () => {
          try { this._db.close(); } catch { /* ignore */ }
          this._db = null;
          this._notify({ type: 'version-change' });
        };
        this._openChannel();
        resolve({ ok: true });
      };
      req.onerror = () => {
        this._unavailableReason = REASONS.UNKNOWN;
        resolve({ ok: false, reason: REASONS.UNKNOWN });
      };
      req.onblocked = () => {
        this._unavailableReason = REASONS.BLOCKED;
        resolve({ ok: false, reason: REASONS.BLOCKED });
      };
    });
  }

  _openChannel() {
    if (typeof BroadcastChannel === 'undefined') return;
    try {
      this._channel = new BroadcastChannel(this._channelName);
      this._channel.onmessage = (ev) => {
        if (!ev || !ev.data || typeof ev.data !== 'object') return;
        this._notify(ev.data);
      };
    } catch { /* ignore */ }
  }

  close() {
    this._closed = true;
    try { this._channel?.close(); } catch { /* ignore */ }
    this._channel = null;
    try { this._db?.close(); } catch { /* ignore */ }
    this._db = null;
  }

  on(listener) {
    this._listeners.add(listener);
    return () => this._listeners.delete(listener);
  }

  _notify(event) {
    for (const l of this._listeners) {
      try { l(event); } catch { /* ignore */ }
    }
  }

  _postMessage(event) {
    try { this._channel?.postMessage(event); } catch { /* ignore */ }
  }

  async _ensureOpen() {
    if (this._db) return { ok: true };
    return this.open();
  }

  // ----- assets -----
  async putAsset(asset) {
    if (!asset || asset.schemaVersion !== ASSET_SCHEMA_VERSION) return { ok: false, reason: REASONS.INVALID };
    const o = await this._ensureOpen();
    if (!o.ok) return o;
    return new Promise((resolve) => {
      const tx = this._db.transaction([STORE_ASSETS], 'readwrite');
      tx.oncomplete = () => { this._postMessage({ type: 'asset-put', assetId: asset.assetId }); resolve({ ok: true }); };
      tx.onerror = () => resolve({ ok: false, reason: REASONS.TX_ABORTED });
      tx.onabort = () => resolve({ ok: false, reason: REASONS.TX_ABORTED });
      tx.objectStore(STORE_ASSETS).put(asset);
    });
  }

  async getAsset(assetId) {
    const o = await this._ensureOpen();
    if (!o.ok) return o;
    return new Promise((resolve) => {
      const tx = this._db.transaction([STORE_ASSETS], 'readonly');
      const req = tx.objectStore(STORE_ASSETS).get(assetId);
      req.onsuccess = () => resolve({ ok: true, value: req.result || null });
      req.onerror = () => resolve({ ok: false, reason: REASONS.UNKNOWN });
    });
  }

  async listAssets({ includeArchived = false } = {}) {
    const o = await this._ensureOpen();
    if (!o.ok) return [];
    return new Promise((resolve) => {
      const tx = this._db.transaction([STORE_ASSETS], 'readonly');
      const req = tx.objectStore(STORE_ASSETS).getAll();
      req.onsuccess = () => {
        const list = Array.isArray(req.result) ? req.result : [];
        const filtered = includeArchived ? list : list.filter((a) => !a.archived);
        filtered.sort((a, b) => String(a.updatedAt).localeCompare(String(b.updatedAt)));
        resolve(filtered);
      };
      req.onerror = () => resolve([]);
    });
  }

  async deleteAsset(assetId) {
    const o = await this._ensureOpen();
    if (!o.ok) return o;
    return new Promise((resolve) => {
      const tx = this._db.transaction([STORE_ASSETS], 'readwrite');
      tx.oncomplete = () => { this._postMessage({ type: 'asset-delete', assetId }); resolve({ ok: true }); };
      tx.onerror = () => resolve({ ok: false, reason: REASONS.TX_ABORTED });
      tx.onabort = () => resolve({ ok: false, reason: REASONS.TX_ABORTED });
      tx.objectStore(STORE_ASSETS).delete(assetId);
    });
  }

  // ----- inventory + components (atomic) -----
  async applyInventory({ inventory, components }) {
    if (!inventory || !Array.isArray(components)) return { ok: false, reason: REASONS.INVALID };
    if (inventory.schemaVersion !== COMPONENT_SCHEMA_VERSION) return { ok: false, reason: REASONS.INVALID };
    const o = await this._ensureOpen();
    if (!o.ok) return o;
    return new Promise((resolve) => {
      const tx = this._db.transaction(
        [STORE_INVENTORIES, STORE_COMPONENTS, STORE_ASSETS],
        'readwrite',
      );
      tx.oncomplete = () => {
        this._postMessage({ type: 'inventory-applied', inventoryId: inventory.inventoryId, assetId: inventory.assetId });
        resolve({ ok: true, inventoryId: inventory.inventoryId, componentCount: components.length });
      };
      tx.onerror = () => resolve({ ok: false, reason: REASONS.TX_ABORTED });
      tx.onabort = () => resolve({ ok: false, reason: REASONS.TX_ABORTED });
      const invStore = tx.objectStore(STORE_INVENTORIES);
      const cmpStore = tx.objectStore(STORE_COMPONENTS);
      const assetStore = tx.objectStore(STORE_ASSETS);
      invStore.put(inventory);
      // Wipe the previous components for this asset.
      const idx = cmpStore.index('assetId');
      const cursorReq = idx.openCursor(IDBKeyRange.only(inventory.assetId));
      cursorReq.onsuccess = (e) => {
        const cursor = e.target.result;
        if (cursor) { cursor.delete(); cursor.continue(); }
      };
      // Insert the new components.
      for (const c of components) cmpStore.put(c);
      // Update the asset's latestInventoryId + updatedAt.
      // The stored asset may be frozen (an
      // export-import roundtrip freezes every record),
      // so we replace it with a shallow clone before
      // mutating.
      const getReq = assetStore.get(inventory.assetId);
      getReq.onsuccess = () => {
        const a = getReq.result;
        if (a) {
          const next = Object.assign({}, a, {
            latestInventoryId: inventory.inventoryId,
            updatedAt: new Date().toISOString(),
          });
          assetStore.put(next);
        }
      };
    });
  }

  async listInventorySnapshots(assetId) {
    const o = await this._ensureOpen();
    if (!o.ok) return [];
    return new Promise((resolve) => {
      const tx = this._db.transaction([STORE_INVENTORIES], 'readonly');
      const idx = tx.objectStore(STORE_INVENTORIES).index('assetId');
      const req = idx.getAll(IDBKeyRange.only(assetId));
      req.onsuccess = () => {
        const list = Array.isArray(req.result) ? req.result : [];
        list.sort((a, b) => String(b.importedAt).localeCompare(String(a.importedAt)));
        resolve(list);
      };
      req.onerror = () => resolve([]);
    });
  }

  async getLatestInventory(assetId) {
    const list = await this.listInventorySnapshots(assetId);
    return list.length > 0 ? list[0] : null;
  }

  async deleteInventorySnapshot(inventoryId) {
    const o = await this._ensureOpen();
    if (!o.ok) return o;
    return new Promise((resolve) => {
      const tx = this._db.transaction([STORE_INVENTORIES, STORE_COMPONENTS], 'readwrite');
      tx.oncomplete = () => { this._postMessage({ type: 'inventory-deleted', inventoryId }); resolve({ ok: true }); };
      tx.onerror = () => resolve({ ok: false, reason: REASONS.TX_ABORTED });
      tx.onabort = () => resolve({ ok: false, reason: REASONS.TX_ABORTED });
      tx.objectStore(STORE_INVENTORIES).delete(inventoryId);
      const idx = tx.objectStore(STORE_COMPONENTS).index('inventoryId');
      const cursorReq = idx.openCursor(IDBKeyRange.only(inventoryId));
      cursorReq.onsuccess = (e) => {
        const cursor = e.target.result;
        if (cursor) { cursor.delete(); cursor.continue(); }
      };
    });
  }

  async listComponentsForAsset(assetId) {
    const o = await this._ensureOpen();
    if (!o.ok) return [];
    return new Promise((resolve) => {
      const tx = this._db.transaction([STORE_COMPONENTS], 'readonly');
      const idx = tx.objectStore(STORE_COMPONENTS).index('assetId');
      const req = idx.getAll(IDBKeyRange.only(assetId));
      req.onsuccess = () => {
        const list = Array.isArray(req.result) ? req.result : [];
        list.sort((a, b) => String(a.name).localeCompare(String(b.name)));
        resolve(list);
      };
      req.onerror = () => resolve([]);
    });
  }

  // ----- correlations -----
  async replaceCorrelationsForInventory({ inventoryId, correlations, assetId }) {
    const o = await this._ensureOpen();
    if (!o.ok) return o;
    return new Promise((resolve) => {
      const tx = this._db.transaction([STORE_CORRELATIONS], 'readwrite');
      tx.oncomplete = () => {
        this._postMessage({ type: 'correlations-replaced', inventoryId, assetId });
        resolve({ ok: true, count: Array.isArray(correlations) ? correlations.length : 0 });
      };
      tx.onerror = () => resolve({ ok: false, reason: REASONS.TX_ABORTED });
      tx.onabort = () => resolve({ ok: false, reason: REASONS.TX_ABORTED });
      const store = tx.objectStore(STORE_CORRELATIONS);
      const idx = store.index('inventoryId');
      const cursorReq = idx.openCursor(IDBKeyRange.only(inventoryId));
      cursorReq.onsuccess = (e) => {
        const cursor = e.target.result;
        if (cursor) { cursor.delete(); cursor.continue(); }
      };
      for (const c of (correlations || [])) store.put(c);
    });
  }

  async listCorrelationsForInventory(inventoryId) {
    const o = await this._ensureOpen();
    if (!o.ok) return [];
    return new Promise((resolve) => {
      const tx = this._db.transaction([STORE_CORRELATIONS], 'readonly');
      const idx = tx.objectStore(STORE_CORRELATIONS).index('inventoryId');
      const req = idx.getAll(IDBKeyRange.only(inventoryId));
      req.onsuccess = () => {
        const list = Array.isArray(req.result) ? req.result : [];
        list.sort((a, b) => String(a.cveId).localeCompare(String(b.cveId)));
        resolve(list);
      };
      req.onerror = () => resolve([]);
    });
  }

  async listCorrelationsForCve(cveId) {
    const o = await this._ensureOpen();
    if (!o.ok) return [];
    return new Promise((resolve) => {
      const tx = this._db.transaction([STORE_CORRELATIONS], 'readonly');
      const idx = tx.objectStore(STORE_CORRELATIONS).index('cveId');
      const req = idx.getAll(IDBKeyRange.only(cveId));
      req.onsuccess = () => resolve(Array.isArray(req.result) ? req.result : []);
      req.onerror = () => resolve([]);
    });
  }

  // ----- reviews -----
  async putReview(review) {
    const o = await this._ensureOpen();
    if (!o.ok) return o;
    return new Promise((resolve) => {
      const tx = this._db.transaction([STORE_REVIEWS], 'readwrite');
      tx.oncomplete = () => { this._postMessage({ type: 'review-put', correlationId: review.correlationId }); resolve({ ok: true }); };
      tx.onerror = () => resolve({ ok: false, reason: REASONS.TX_ABORTED });
      tx.onabort = () => resolve({ ok: false, reason: REASONS.TX_ABORTED });
      tx.objectStore(STORE_REVIEWS).put(review);
    });
  }

  async getReview(correlationId) {
    const o = await this._ensureOpen();
    if (!o.ok) return null;
    return new Promise((resolve) => {
      const tx = this._db.transaction([STORE_REVIEWS], 'readonly');
      const req = tx.objectStore(STORE_REVIEWS).get(correlationId);
      req.onsuccess = () => resolve(req.result || null);
      req.onerror = () => resolve(null);
    });
  }

  async listReviews() {
    const o = await this._ensureOpen();
    if (!o.ok) return [];
    return new Promise((resolve) => {
      const tx = this._db.transaction([STORE_REVIEWS], 'readonly');
      const req = tx.objectStore(STORE_REVIEWS).getAll();
      req.onsuccess = () => resolve(Array.isArray(req.result) ? req.result : []);
      req.onerror = () => resolve([]);
    });
  }

  async deleteReview(correlationId) {
    const o = await this._ensureOpen();
    if (!o.ok) return o;
    return new Promise((resolve) => {
      const tx = this._db.transaction([STORE_REVIEWS], 'readwrite');
      tx.oncomplete = () => { this._postMessage({ type: 'review-delete', correlationId }); resolve({ ok: true }); };
      tx.onerror = () => resolve({ ok: false, reason: REASONS.TX_ABORTED });
      tx.onabort = () => resolve({ ok: false, reason: REASONS.TX_ABORTED });
      tx.objectStore(STORE_REVIEWS).delete(correlationId);
    });
  }

  // ----- destructive -----
  async clearAll() {
    const o = await this._ensureOpen();
    if (!o.ok) return o;
    return new Promise((resolve) => {
      const tx = this._db.transaction(
        [STORE_ASSETS, STORE_INVENTORIES, STORE_COMPONENTS, STORE_CORRELATIONS, STORE_REVIEWS, STORE_META],
        'readwrite',
      );
      tx.oncomplete = () => { this._postMessage({ type: 'environment-cleared' }); resolve({ ok: true }); };
      tx.onerror = () => resolve({ ok: false, reason: REASONS.TX_ABORTED });
      tx.onabort = () => resolve({ ok: false, reason: REASONS.TX_ABORTED });
      tx.objectStore(STORE_ASSETS).clear();
      tx.objectStore(STORE_INVENTORIES).clear();
      tx.objectStore(STORE_COMPONENTS).clear();
      tx.objectStore(STORE_CORRELATIONS).clear();
      tx.objectStore(STORE_REVIEWS).clear();
      tx.objectStore(STORE_META).clear();
    });
  }
}
