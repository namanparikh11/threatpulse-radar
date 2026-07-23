/**
 * V6.4 — In-memory workspace adapter.
 *
 * Stores entries in a Map. Used by tests and as the
 * ultimate fallback when IndexedDB is unavailable
 * AND the operator accepts a session-only workspace.
 *
 * The adapter NEVER persists to localStorage. The
 * only in-memory persistence is the runtime's
 * JavaScript heap.
 */

import { makeEntry, validateEntry, compareUpdatedAt, applyPatch, stampCommitted, newMutationId } from './schema.mjs';

const STORAGE_VERSION = '1.0.0';

export class InMemoryWorkspaceAdapter {
  constructor() {
    this._store = new Map();
    this._listeners = new Set();
    this._closed = false;
  }

  _checkOpen() {
    if (this._closed) throw new Error('adapter-closed');
  }

  _notify(event) {
    for (const l of this._listeners) {
      try { l(event); } catch { /* ignore listener errors */ }
    }
  }

  async initialize() {
    return { ok: true, version: STORAGE_VERSION };
  }

  subscribe(listener) {
    this._listeners.add(listener);
    return () => this._listeners.delete(listener);
  }

  async close() {
    this._closed = true;
    this._listeners.clear();
  }

  async getEntry(cveId) {
    this._checkOpen();
    return this._store.get(String(cveId).toUpperCase()) || null;
  }

  async putEntry(entry) {
    this._checkOpen();
    const v = validateEntry(entry);
    if (!v.ok) return { ok: false, reason: v.reason };
    this._store.set(v.record.cveId, v.record);
    this._notify({ type: 'put', cveId: v.record.cveId });
    return { ok: true, record: v.record };
  }

  async patchEntry(cveId, patch) {
    this._checkOpen();
    const cur = this._store.get(String(cveId).toUpperCase());
    if (!cur) return { ok: false, reason: 'not-found' };
    const patched = applyPatch({ ...cur }, patch || {});
    // Stamp a fresh mutationId and increment
    // revision. Failed writes (above) never
    // increment revision.
    const next = stampCommitted(patched, { newMutationId: newMutationId() });
    this._store.set(cur.cveId, next);
    this._notify({ type: 'patch', cveId: cur.cveId });
    return { ok: true, record: next };
  }

  async deleteEntry(cveId) {
    this._checkOpen();
    const id = String(cveId).toUpperCase();
    if (!this._store.has(id)) return { ok: false, reason: 'not-found' };
    this._store.delete(id);
    this._notify({ type: 'delete', cveId: id });
    return { ok: true };
  }

  async listEntries(filters = {}) {
    this._checkOpen();
    const want = filters || {};
    let arr = Array.from(this._store.values());
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
  }

  async bulkUpdate(cveIds, patch) {
    this._checkOpen();
    const set = new Set((cveIds || []).map((c) => String(c).toUpperCase()));
    let updated = 0;
    for (const id of set) {
      const cur = this._store.get(id);
      if (!cur) continue;
      const patched = applyPatch({ ...cur }, patch || {});
      const next = stampCommitted(patched, { newMutationId: newMutationId() });
      this._store.set(id, next);
      updated++;
    }
    if (updated > 0) this._notify({ type: 'bulk', count: updated });
    return { ok: true, updated };
  }

  async exportWorkspace() {
    this._checkOpen();
    const entries = Array.from(this._store.values()).sort((a, b) =>
      a.cveId < b.cveId ? -1 : a.cveId > b.cveId ? 1 : 0
    );
    return { ok: true, entries, count: entries.length };
  }

  async validateImport(/* payload */) { return { ok: true }; }

  async importWorkspace(payload /* , mode */) {
    this._checkOpen();
    // Minimal stub: real implementation lives in
    // exportImport.mjs and is invoked by the
    // WorkspaceContext, not by the adapter.
    return { ok: false, reason: 'not-implemented' };
  }

  async clearArchived() {
    this._checkOpen();
    let removed = 0;
    for (const [k, e] of this._store) {
      if (e.archived) { this._store.delete(k); removed++; }
    }
    if (removed > 0) this._notify({ type: 'bulk', count: removed });
    return { ok: true, removed };
  }

  async clearWorkspace() {
    this._checkOpen();
    const removed = this._store.size;
    this._store.clear();
    this._notify({ type: 'bulk', count: removed });
    return { ok: true, removed };
  }

  async getWorkspaceMetadata() {
    this._checkOpen();
    return {
      ok: true,
      backend: 'memory',
      count: this._store.size,
      warning: this._store.size >= 5000,
    };
  }
}

export const INMEMORY_STORAGE_VERSION = STORAGE_VERSION;
