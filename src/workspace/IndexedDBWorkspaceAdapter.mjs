/**
 * V6.4 — IndexedDB workspace adapter.
 *
 * Stores every entry in a single object store keyed
 * by the canonical CVE id. All writes are wrapped in
 * read-write transactions so partial failures do not
 * corrupt the database. The adapter never throws on
 * a recoverable error; it returns `{ ok: false,
 * reason }` so the UI can surface a sanitized message.
 *
 * Quota, blocked, and transaction-aborted errors are
 * normalized to the same `{ ok: false, reason }`
 * shape with a distinct reason string each. The
 * WorkspaceContext translates the reason into a
 * user-facing message.
 *
 * No data ever leaves the database through this
 * adapter. The adapter is the only module that knows
 * the database / object-store names.
 */

import { makeEntry, validateEntry, compareUpdatedAt, applyPatch, normaliseCveId } from './schema.mjs';

const DB_NAME = 'threatpulse-workspace';
const DB_VERSION = 1;
const STORE = 'entries';
const META_STORE = 'meta';

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

export class IndexedDBWorkspaceAdapter {
  constructor({ dbName = DB_NAME, storeName = STORE, metaStoreName = META_STORE } = {}) {
    this._dbName = dbName;
    this._storeName = storeName;
    this._metaStoreName = metaStoreName;
    this._db = null;
    this._listeners = new Set();
    this._closed = false;
    this._unavailableReason = null;
  }

  /** Reason constants exposed for tests. */
  static get REASONS() { return REASONS; }

  /**
   * Returns true when the current environment exposes
   * a usable indexedDB. The check is best-effort:
   * Safari private mode and some enterprise policies
   * expose a stub indexedDB that throws on first use.
   */
  static isSupported() {
    try {
      return typeof indexedDB !== 'undefined' && indexedDB !== null;
    } catch {
      return false;
    }
  }

  _checkOpen() {
    if (this._closed) {
      const err = new Error('adapter-closed');
      err.reason = REASONS.CLOSED;
      throw err;
    }
  }

  _notify(event) {
    for (const l of this._listeners) {
      try { l(event); } catch { /* ignore listener errors */ }
    }
  }

  _openDb() {
    return new Promise((resolve, reject) => {
      let req;
      try {
        req = indexedDB.open(this._dbName, DB_VERSION);
      } catch (err) {
        // Safari private mode + some enterprise
        // policies throw on the open() call itself.
        reject(err);
        return;
      }
      req.onupgradeneeded = () => {
        const db = req.result;
        if (!db.objectStoreNames.contains(this._storeName)) {
          const store = db.createObjectStore(this._storeName, { keyPath: 'cveId' });
          store.createIndex('updatedAt', 'updatedAt', { unique: false });
          store.createIndex('watched', 'watched', { unique: false });
        }
        if (!db.objectStoreNames.contains(this._metaStoreName)) {
          db.createObjectStore(this._metaStoreName, { keyPath: 'key' });
        }
      };
      req.onsuccess = () => {
        const db = req.result;
        // V6.8: mirror the V6.6 environment and V6.7
        // remediation adapters' versionchange handler so
        // a multi-tab upgrade cleanly closes the local
        // connection instead of leaving the prior tab
        // with a stale handle.
        try {
          db.onversionchange = () => {
            try { db.close(); } catch { /* noop */ }
          };
        } catch { /* noop */ }
        resolve(db);
      };
      req.onerror = () => reject(req.error || new Error('idb-open-failed'));
      req.onblocked = () => reject(new Error('idb-open-blocked'));
    });
  }

  async initialize() {
    if (!IndexedDBWorkspaceAdapter.isSupported()) {
      this._unavailableReason = REASONS.NOT_SUPPORTED;
      return { ok: false, reason: REASONS.NOT_SUPPORTED };
    }
    try {
      this._db = await this._openDb();
      return { ok: true, version: DB_VERSION };
    } catch (err) {
      this._unavailableReason = REASONS.BLOCKED;
      return { ok: false, reason: REASONS.BLOCKED, error: err && err.message };
    }
  }

  subscribe(listener) {
    this._listeners.add(listener);
    return () => this._listeners.delete(listener);
  }

  async close() {
    this._closed = true;
    this._listeners.clear();
    if (this._db) {
      try { this._db.close(); } catch { /* noop */ }
    }
    this._db = null;
  }

  _tx(stores, mode = 'readonly') {
    this._checkOpen();
    if (!this._db) {
      const err = new Error('db-not-open');
      err.reason = REASONS.BLOCKED;
      throw err;
    }
    return this._db.transaction(stores, mode);
  }

  _wrapTxError(err) {
    if (!err) return { ok: false, reason: REASONS.UNKNOWN };
    const name = err.name || '';
    if (name === 'QuotaExceededError' || err.code === 22) return { ok: false, reason: REASONS.QUOTA };
    if (name === 'AbortError' || err.code === 20) return { ok: false, reason: REASONS.TX_ABORTED };
    if (name === 'InvalidStateError' || name === 'SecurityError') return { ok: false, reason: REASONS.BLOCKED };
    return { ok: false, reason: REASONS.UNKNOWN, error: err.message };
  }

  _reqToPromise(req) {
    return new Promise((resolve, reject) => {
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error || new Error('idb-error'));
    });
  }

  async getEntry(cveId) {
    this._checkOpen();
    const id = normaliseCveId(cveId);
    if (!id) return null;
    try {
      const tx = this._tx([this._storeName], 'readonly');
      const req = tx.objectStore(this._storeName).get(id);
      const result = await this._reqToPromise(req);
      return result || null;
    } catch (err) {
      return null;
    }
  }

  async putEntry(entry) {
    this._checkOpen();
    const v = validateEntry(entry);
    if (!v.ok) return { ok: false, reason: v.reason };
    try {
      const tx = this._tx([this._storeName], 'readwrite');
      tx.objectStore(this._storeName).put(v.record);
      await this._txDone(tx);
      this._notify({ type: 'put', cveId: v.record.cveId });
      return { ok: true, record: v.record };
    } catch (err) {
      return this._wrapTxError(err);
    }
  }

  async patchEntry(cveId, patch) {
    this._checkOpen();
    const id = normaliseCveId(cveId);
    if (!id) return { ok: false, reason: 'invalid-cveId' };
    try {
      const tx = this._tx([this._storeName], 'readwrite');
      const store = tx.objectStore(this._storeName);
      const cur = await this._reqToPromise(store.get(id));
      if (!cur) return { ok: false, reason: REASONS.NOT_FOUND };
      const next = applyPatch({ ...cur }, patch || {});
      store.put(next);
      await this._txDone(tx);
      this._notify({ type: 'patch', cveId: id });
      return { ok: true, record: next };
    } catch (err) {
      return this._wrapTxError(err);
    }
  }

  async deleteEntry(cveId) {
    this._checkOpen();
    const id = normaliseCveId(cveId);
    if (!id) return { ok: false, reason: 'invalid-cveId' };
    try {
      const tx = this._tx([this._storeName], 'readwrite');
      tx.objectStore(this._storeName).delete(id);
      await this._txDone(tx);
      this._notify({ type: 'delete', cveId: id });
      return { ok: true };
    } catch (err) {
      return this._wrapTxError(err);
    }
  }

  async listEntries(filters = {}) {
    this._checkOpen();
    const want = filters || {};
    try {
      const tx = this._tx([this._storeName], 'readonly');
      const all = await this._reqToPromise(tx.objectStore(this._storeName).getAll());
      let arr = Array.isArray(all) ? all : [];
      if (want.watchedOnly) arr = arr.filter((e) => e.watched);
      if (want.notArchived === true) arr = arr.filter((e) => !e.archived);
      if (want.archivedOnly) arr = arr.filter((e) => e.archived);
      if (Array.isArray(want.triageStatuses) && want.triageStatuses.length > 0) {
        const set = new Set(want.triageStatuses);
        arr = arr.filter((e) => set.has(e.triageStatus));
      }
      if (Array.isArray(want.priorities) && want.priorities.length > 0) {
        const set = new Set(want.priorities);
        arr = arr.filter((e) => set.has(e.userPriority));
      }
      if (typeof want.query === 'string' && want.query.length > 0) {
        const q = want.query.toLocaleLowerCase();
        arr = arr.filter((e) =>
          e.cveId.toLocaleLowerCase().includes(q) ||
          (e.note && e.note.toLocaleLowerCase().includes(q)) ||
          e.tags.some((t) => t.toLocaleLowerCase().includes(q))
        );
      }
      if (Array.isArray(want.cveIds) && want.cveIds.length > 0) {
        const set = new Set(want.cveIds.map((c) => String(c).toUpperCase()));
        arr = arr.filter((e) => set.has(e.cveId));
      }
      arr.sort((a, b) => compareUpdatedAt(a, b));
      return { ok: true, entries: arr };
    } catch (err) {
      return this._wrapTxError(err);
    }
  }

  async bulkUpdate(cveIds, patch) {
    this._checkOpen();
    const set = new Set((cveIds || []).map((c) => String(c).toUpperCase()));
    if (set.size === 0) return { ok: true, updated: 0 };
    try {
      const tx = this._tx([this._storeName], 'readwrite');
      const store = tx.objectStore(this._storeName);
      let updated = 0;
      for (const id of set) {
        const cur = await this._reqToPromise(store.get(id));
        if (!cur) continue;
        const next = applyPatch({ ...cur }, patch || {});
        store.put(next);
        updated++;
      }
      await this._txDone(tx);
      if (updated > 0) this._notify({ type: 'bulk', count: updated });
      return { ok: true, updated };
    } catch (err) {
      return this._wrapTxError(err);
    }
  }

  async exportWorkspace() {
    this._checkOpen();
    try {
      const tx = this._tx([this._storeName], 'readonly');
      const all = await this._reqToPromise(tx.objectStore(this._storeName).getAll());
      const entries = (Array.isArray(all) ? all : []).sort((a, b) =>
        a.cveId < b.cveId ? -1 : a.cveId > b.cveId ? 1 : 0
      );
      return { ok: true, entries, count: entries.length };
    } catch (err) {
      return this._wrapTxError(err);
    }
  }

  async validateImport(/* payload */) { return { ok: true }; }

  async importWorkspace(/* payload, mode */) {
    return { ok: false, reason: 'not-implemented' };
  }

  async clearArchived() {
    this._checkOpen();
    try {
      const tx = this._tx([this._storeName], 'readwrite');
      const all = await this._reqToPromise(tx.objectStore(this._storeName).getAll());
      const store = tx.objectStore(this._storeName);
      let removed = 0;
      for (const e of all) {
        if (e.archived) {
          store.delete(e.cveId);
          removed++;
        }
      }
      await this._txDone(tx);
      if (removed > 0) this._notify({ type: 'bulk', count: removed });
      return { ok: true, removed };
    } catch (err) {
      return this._wrapTxError(err);
    }
  }

  async clearWorkspace() {
    this._checkOpen();
    try {
      const tx = this._tx([this._storeName], 'readwrite');
      tx.objectStore(this._storeName).clear();
      await this._txDone(tx);
      this._notify({ type: 'bulk', count: -1 });
      return { ok: true, removed: -1 };
    } catch (err) {
      return this._wrapTxError(err);
    }
  }

  async getWorkspaceMetadata() {
    this._checkOpen();
    try {
      const tx = this._tx([this._storeName], 'readonly');
      const all = await this._reqToPromise(tx.objectStore(this._storeName).getAll());
      return {
        ok: true,
        backend: 'indexeddb',
        count: Array.isArray(all) ? all.length : 0,
        warning: Array.isArray(all) && all.length >= 5000,
      };
    } catch (err) {
      return this._wrapTxError(err);
    }
  }

  _txDone(tx) {
    return new Promise((resolve, reject) => {
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error || new Error('idb-tx-failed'));
      tx.onabort = () => reject(tx.error || new Error('idb-tx-aborted'));
    });
  }

  /**
   * Operator-only: permanently delete the database
   * (used by the clear-workspace dialog when the
   * operator wants a fresh start). Returns the
   * underlying reason so the caller can surface a
   * sanitized message.
   */
  async _deleteDatabase() {
    if (!this._db) {
      // Still try the deletion via indexedDB API.
    } else {
      try { this._db.close(); } catch { /* noop */ }
      this._db = null;
    }
    return new Promise((resolve) => {
      try {
        const req = indexedDB.deleteDatabase(this._dbName);
        req.onsuccess = () => resolve({ ok: true });
        req.onerror = () => resolve({ ok: false, reason: REASONS.UNKNOWN });
        req.onblocked = () => resolve({ ok: false, reason: 'database-blocked' });
      } catch (err) {
        resolve({ ok: false, reason: REASONS.BLOCKED, error: err && err.message });
      }
    });
  }
}

export const INDEXEDDB_REASONS = REASONS;
