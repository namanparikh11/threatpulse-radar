/**
 * V6.4 — Unavailable workspace adapter.
 *
 * A read-only stub used when the workspace is in the
 * `'unavailable'` status (IndexedDB blocked, quota
 * exceeded, private/incognito mode that disables
 * storage, or the operator explicitly disabled the
 * workspace). Every read returns `null` and every
 * write returns `{ ok: false, reason: 'unavailable' }`
 * so the UI can render a clear "local workspace
 * unavailable" state without crashing the dashboard.
 *
 * The adapter also refuses to subscribe (it has no
 * real state to notify) and to close gracefully.
 */

import { makeEntry } from './schema.mjs';

const REASON = 'unavailable';

export class UnavailableWorkspaceAdapter {
  constructor({ reason = REASON, backend = 'unavailable' } = {}) {
    this._reason = reason;
    this._backend = backend;
  }

  static get REASON() { return REASON; }

  async initialize() {
    return { ok: false, reason: this._reason };
  }

  subscribe(/* listener */) { return () => {}; }

  async close() { /* noop */ }

  async getEntry() { return null; }

  async putEntry() { return { ok: false, reason: this._reason }; }

  async patchEntry() { return { ok: false, reason: this._reason }; }

  async deleteEntry() { return { ok: false, reason: this._reason }; }

  async listEntries(/* filters */) {
    return { ok: true, entries: [] };
  }

  async bulkUpdate() { return { ok: true, updated: 0 }; }

  async exportWorkspace() {
    return { ok: true, entries: [], count: 0 };
  }

  async validateImport() { return { ok: true }; }

  async importWorkspace() { return { ok: false, reason: this._reason }; }

  async clearArchived() { return { ok: true, removed: 0 }; }

  async clearWorkspace() { return { ok: true, removed: 0 }; }

  async getWorkspaceMetadata() {
    return { ok: true, backend: this._backend, count: 0, warning: false };
  }
}

export const UNAVAILABLE_REASON = REASON;
