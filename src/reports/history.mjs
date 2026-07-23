/**
 * V6.5 — Report history (IndexedDB-backed).
 *
 * The history records one entry per export. The
 * entry is intentionally small and never contains
 * the full report body or any private note:
 *
 *   {
 *     reportId,
 *     reportType,
 *     title,
 *     generatedAt,
 *     cveCount,
 *     publicIntelligenceStatus,
 *     publicIntelligenceVersion,
 *     includePrivateNotes,
 *     includeLocalTags,
 *     includeResolved,
 *     includeArchived,
 *     redactionMode,
 *     exportFormat,
 *     exportStatus,
 *     checksum,
 *     storedAt
 *   }
 *
 * The module is purely local. It NEVER:
 *   - touches the network
 *   - writes to the URL / history
 *   - logs to the console
 *   - stores full reports, sections, notes, or tags
 *
 * When IndexedDB is unavailable the history
 * degrades to a no-op: list/add/remove/clear all
 * become best-effort no-ops that return the
 * documented empty/error responses. The dashboard
 * surfaces this as a separate clearing warning so
 * the operator can tell workspace history from
 * report history apart.
 *
 * History is opt-in. The `enabled` flag defaults
 * to true; the user can disable it from the
 * settings page; the flag is stored in
 * localStorage so it survives reloads.
 */

import { REPORT_LIMITS } from './schema.mjs';

const DB_NAME = 'threatpulse-report-history';
const DB_VERSION = 1;
const STORE = 'entries';
const LS_ENABLED_KEY = 'threatpulse:report-history:enabled';

function lsAvailable() {
  try {
    if (typeof localStorage === 'undefined') return false;
    const k = '__threatpulse_test__';
    localStorage.setItem(k, '1');
    localStorage.removeItem(k);
    return true;
  } catch {
    return false;
  }
}

function readEnabled() {
  if (!lsAvailable()) return true;
  const raw = localStorage.getItem(LS_ENABLED_KEY);
  if (raw === '0' || raw === 'false') return false;
  if (raw === '1' || raw === 'true') return true;
  return true;
}

function writeEnabled(value) {
  if (!lsAvailable()) return;
  try {
    localStorage.setItem(LS_ENABLED_KEY, value ? '1' : '0');
  } catch { /* ignore */ }
}

function openDb() {
  if (typeof indexedDB === 'undefined') return Promise.resolve(null);
  return new Promise((resolve) => {
    let req;
    try {
      req = indexedDB.open(DB_NAME, DB_VERSION);
    } catch {
      return resolve(null);
    }
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE)) {
        const store = db.createObjectStore(STORE, { keyPath: 'reportId' });
        store.createIndex('storedAt', 'storedAt', { unique: false });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => resolve(null);
    req.onblocked = () => resolve(null);
  });
}

function isAvailable() {
  return typeof indexedDB !== 'undefined';
}

/** Build a single history entry from a report. The
 *  entry contains only public-safe summary fields;
 *  no notes, no tags, no full sections. */
export function buildHistoryEntry(report, options) {
  if (!report || typeof report !== 'object') return null;
  const pi = report.publicIntelligence || {};
  const sel = report.selection || {};
  return {
    reportId: String(report.reportId || ''),
    reportType: String(report.reportType || ''),
    title: String(report.title || '').slice(0, REPORT_LIMITS.MAX_TITLE_CHARS),
    generatedAt: String(report.generatedAt || ''),
    cveCount: Array.isArray(sel.cveIds) ? sel.cveIds.length : 0,
    publicIntelligenceStatus: typeof pi.status === 'string' ? pi.status : 'unavailable',
    publicIntelligenceVersion: typeof pi.version === 'string' ? pi.version : null,
    includePrivateNotes: !!sel.includePrivateNotes,
    includeLocalTags: sel.includeLocalTags !== false,
    includeResolved: !!sel.includeResolved,
    includeArchived: !!sel.includeArchived,
    redactionMode: options && typeof options.redactionMode === 'string' ? options.redactionMode : 'none',
    exportFormat: options && typeof options.exportFormat === 'string' ? options.exportFormat : 'json',
    exportStatus: options && typeof options.exportStatus === 'string' ? options.exportStatus : 'built',
    checksum: report.integrity && typeof report.integrity.checksum === 'string' ? report.integrity.checksum : '',
    storedAt: new Date().toISOString(),
  };
}

/** Append a history entry. When history is disabled
 *  this is a no-op. When the table already holds
 *  MAX_HISTORY_ENTRIES, the oldest entry is evicted
 *  (sorted by storedAt) BEFORE the new entry is
 *  inserted. */
export async function addHistoryEntry(report, options) {
  if (!readEnabled()) return { ok: false, reason: 'disabled' };
  const entry = buildHistoryEntry(report, options);
  if (!entry || !entry.reportId) return { ok: false, reason: 'invalid-entry' };
  const db = await openDb();
  if (!db) return { ok: false, reason: 'unavailable' };
  try {
    // Evict oldest entries when at cap.
    const count = await countEntries(db);
    if (count >= REPORT_LIMITS.MAX_HISTORY_ENTRIES) {
      const excess = count - REPORT_LIMITS.MAX_HISTORY_ENTRIES + 1;
      await evictOldest(db, excess);
    }
    await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, 'readwrite');
      tx.objectStore(STORE).put(entry);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
      tx.onabort = () => reject(tx.error);
    });
    return { ok: true, entry };
  } catch {
    return { ok: false, reason: 'write-failed' };
  } finally {
    try { db.close(); } catch { /* ignore */ }
  }
}

async function countEntries(db) {
  return new Promise((resolve) => {
    const tx = db.transaction(STORE, 'readonly');
    const req = tx.objectStore(STORE).count();
    req.onsuccess = () => resolve(req.result || 0);
    req.onerror = () => resolve(0);
  });
}

async function evictOldest(db, count) {
  if (count <= 0) return;
  return new Promise((resolve) => {
    const tx = db.transaction(STORE, 'readwrite');
    const store = tx.objectStore(STORE);
    const idx = store.index('storedAt');
    const req = idx.openCursor();
    let evicted = 0;
    req.onsuccess = (e) => {
      const cursor = e.target.result;
      if (cursor && evicted < count) {
        cursor.delete();
        evicted += 1;
        cursor.continue();
      } else {
        resolve();
      }
    };
    req.onerror = () => resolve();
  });
}

/** List all history entries, newest first. */
export async function listHistoryEntries() {
  const db = await openDb();
  if (!db) return [];
  try {
    return await new Promise((resolve) => {
      const tx = db.transaction(STORE, 'readonly');
      const req = tx.objectStore(STORE).getAll();
      req.onsuccess = () => {
        const list = Array.isArray(req.result) ? req.result : [];
        list.sort((a, b) => String(b.storedAt || '').localeCompare(String(a.storedAt || '')));
        resolve(list);
      };
      req.onerror = () => resolve([]);
    });
  } finally {
    try { db.close(); } catch { /* ignore */ }
  }
}

/** Remove a single history entry by reportId. */
export async function removeHistoryEntry(reportId) {
  if (typeof reportId !== 'string' || reportId.length === 0) return { ok: false, reason: 'invalid-id' };
  const db = await openDb();
  if (!db) return { ok: false, reason: 'unavailable' };
  try {
    await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, 'readwrite');
      tx.objectStore(STORE).delete(reportId);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
    return { ok: true };
  } catch {
    return { ok: false, reason: 'delete-failed' };
  } finally {
    try { db.close(); } catch { /* ignore */ }
  }
}

/** Clear every history entry. */
export async function clearHistory() {
  const db = await openDb();
  if (!db) return { ok: false, reason: 'unavailable' };
  try {
    await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, 'readwrite');
      tx.objectStore(STORE).clear();
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
    return { ok: true };
  } catch {
    return { ok: false, reason: 'clear-failed' };
  } finally {
    try { db.close(); } catch { /* ignore */ }
  }
}

/** Enable or disable the history. When disabled,
 *  the existing entries are kept on disk so the
 *  user can re-enable without losing data. */
export function setHistoryEnabled(value) {
  writeEnabled(value !== false);
}

export function isHistoryEnabled() {
  return readEnabled();
}

export function historyAvailable() {
  return isAvailable();
}
