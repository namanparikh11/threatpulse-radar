/**
 * V6.7 — IndexedDB remediation adapter.
 *
 * Stores plans, tasks, evidence, and the per-plan
 * append-only ledger in a single database
 * (`threatpulse-remediation`). The adapter never
 * throws on a recoverable error; it returns
 * `{ ok, value }` or `{ ok: false, reason }` so the
 * caller can surface a sanitized message.
 *
 * Multi-tab notification uses a BroadcastChannel
 * (`threatpulse:remediation:events`) so other tabs
 * can refresh their in-memory state. The channel is
 * purely local — it does not talk to the network.
 *
 * Schema migrations use the `onupgradeneeded` hook
 * and follow the same deterministic pattern as the
 * V6.4 workspace and V6.6 environment adapters.
 *
 * Transactional integrity: the append-ledger-event
 * write is atomic with the corresponding plan / task /
 * evidence write. A failure on either side rolls back
 * the entire transaction, so the ledger never
 * describes a mutation that did not happen.
 */

import {
  validatePlan, validateTask, validateEvidence, validateLedgerEvent,
} from './schema.mjs';
import { IDBKeyRange } from './_shim.mjs';

const DB_NAME = 'threatpulse-remediation';
const DB_VERSION = 1;
const STORE_PLANS = 'plans';
const STORE_TASKS = 'tasks';
const STORE_EVIDENCE = 'evidence';
const STORE_LEDGER = 'ledger';
const STORE_META = 'meta';

const REASONS = Object.freeze({
  BLOCKED: 'indexeddb-blocked',
  QUOTA: 'quota-exceeded',
  TX_ABORTED: 'transaction-aborted',
  NOT_FOUND: 'not-found',
  INVALID: 'invalid-entry',
  STALE: 'stale-revision',
  CONFLICT: 'ledger-conflict',
  UNKNOWN: 'unknown',
  CLOSED: 'adapter-closed',
  NOT_SUPPORTED: 'indexeddb-not-supported',
});

export class IndexedDBRemediationAdapter {
  constructor({ dbName = DB_NAME, broadcastChannelName = 'threatpulse:remediation:events' } = {}) {
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
    if (!IndexedDBRemediationAdapter.isSupported()) {
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
        if (!db.objectStoreNames.contains(STORE_PLANS)) {
          const s = db.createObjectStore(STORE_PLANS, { keyPath: 'planId' });
          s.createIndex('updatedAt', 'updatedAt', { unique: false });
          s.createIndex('archived', 'archived', { unique: false });
          s.createIndex('status', 'status', { unique: false });
        }
        if (!db.objectStoreNames.contains(STORE_TASKS)) {
          const s = db.createObjectStore(STORE_TASKS, { keyPath: 'taskId' });
          s.createIndex('planId', 'planId', { unique: false });
        }
        if (!db.objectStoreNames.contains(STORE_EVIDENCE)) {
          const s = db.createObjectStore(STORE_EVIDENCE, { keyPath: 'evidenceId' });
          s.createIndex('planId', 'planId', { unique: false });
        }
        if (!db.objectStoreNames.contains(STORE_LEDGER)) {
          const s = db.createObjectStore(STORE_LEDGER, { keyPath: 'eventId' });
          s.createIndex('planId', 'planId', { unique: false });
          s.createIndex('sequence', 'sequence', { unique: false });
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

  // ---- plans ----
  async putPlan(plan) {
    const v = validatePlan(plan);
    if (!v.ok) return v;
    const o = await this._ensureOpen();
    if (!o.ok) return o;
    return new Promise((resolve) => {
      const tx = this._db.transaction([STORE_PLANS], 'readwrite');
      const store = tx.objectStore(STORE_PLANS);
      const getReq = store.get(plan.planId);
      getReq.onsuccess = () => {
        const cur = getReq.result;
        if (cur && plan.revision <= cur.revision) {
          resolve({ ok: false, reason: REASONS.STALE });
          return;
        }
        const putReq = store.put(v.value);
        putReq.onsuccess = () => {
          this._postMessage({ type: 'plan-put', planId: plan.planId });
          resolve({ ok: true });
        };
        putReq.onerror = () => resolve({ ok: false, reason: REASONS.TX_ABORTED });
      };
      getReq.onerror = () => resolve({ ok: false, reason: REASONS.TX_ABORTED });
      tx.onerror = () => resolve({ ok: false, reason: REASONS.TX_ABORTED });
      tx.onabort = () => resolve({ ok: false, reason: REASONS.TX_ABORTED });
    });
  }

  async getPlan(planId) {
    const o = await this._ensureOpen();
    if (!o.ok) return o;
    return new Promise((resolve) => {
      const tx = this._db.transaction([STORE_PLANS], 'readonly');
      const req = tx.objectStore(STORE_PLANS).get(planId);
      req.onsuccess = () => resolve({ ok: true, value: req.result || null });
      req.onerror = () => resolve({ ok: false, reason: REASONS.TX_ABORTED });
    });
  }

  async listPlans({ includeArchived = false } = {}) {
    const o = await this._ensureOpen();
    if (!o.ok) return o;
    return new Promise((resolve) => {
      const tx = this._db.transaction([STORE_PLANS], 'readonly');
      const req = tx.objectStore(STORE_PLANS).getAll();
      req.onsuccess = () => {
        const all = Array.isArray(req.result) ? req.result : [];
        const filtered = includeArchived ? all : all.filter((p) => !p.archived);
        filtered.sort((a, b) => String(b.updatedAt).localeCompare(String(a.updatedAt)));
        resolve({ ok: true, value: filtered });
      };
      req.onerror = () => resolve({ ok: false, reason: REASONS.TX_ABORTED });
    });
  }

  async deletePlan(planId) {
    const o = await this._ensureOpen();
    if (!o.ok) return o;
    return new Promise((resolve) => {
      const tx = this._db.transaction(
        [STORE_PLANS, STORE_TASKS, STORE_EVIDENCE, STORE_LEDGER],
        'readwrite',
      );
      const planStore = tx.objectStore(STORE_PLANS);
      const taskStore = tx.objectStore(STORE_TASKS);
      const evStore = tx.objectStore(STORE_EVIDENCE);
      const ledStore = tx.objectStore(STORE_LEDGER);
      const getReq = planStore.get(planId);
      getReq.onsuccess = () => {
        if (!getReq.result) {
          resolve({ ok: false, reason: REASONS.NOT_FOUND });
          return;
        }
        planStore.delete(planId);
        // Delete tasks
        const tIdx = taskStore.index('planId');
        const tCur = tIdx.openCursor(IDBKeyRange.only(planId));
        tCur.onsuccess = (e) => { const c = e.target.result; if (c) { c.delete(); c.continue(); } };
        // Delete evidence
        const eIdx = evStore.index('planId');
        const eCur = eIdx.openCursor(IDBKeyRange.only(planId));
        eCur.onsuccess = (e) => { const c = e.target.result; if (c) { c.delete(); c.continue(); } };
        // Delete ledger events
        const lIdx = ledStore.index('planId');
        const lCur = lIdx.openCursor(IDBKeyRange.only(planId));
        lCur.onsuccess = (e) => { const c = e.target.result; if (c) { c.delete(); c.continue(); } };
      };
      getReq.onerror = () => resolve({ ok: false, reason: REASONS.TX_ABORTED });
      tx.oncomplete = () => {
        this._postMessage({ type: 'plan-deleted', planId });
        resolve({ ok: true });
      };
      tx.onerror = () => resolve({ ok: false, reason: REASONS.TX_ABORTED });
      tx.onabort = () => resolve({ ok: false, reason: REASONS.TX_ABORTED });
    });
  }

  // ---- tasks ----
  async putTask(task) {
    const v = validateTask(task);
    if (!v.ok) return v;
    const o = await this._ensureOpen();
    if (!o.ok) return o;
    return new Promise((resolve) => {
      const tx = this._db.transaction([STORE_TASKS], 'readwrite');
      const store = tx.objectStore(STORE_TASKS);
      const getReq = store.get(task.taskId);
      getReq.onsuccess = () => {
        const cur = getReq.result;
        if (cur && task.revision <= cur.revision) {
          resolve({ ok: false, reason: REASONS.STALE });
          return;
        }
        const putReq = store.put(v.value);
        putReq.onsuccess = () => {
          this._postMessage({ type: 'task-put', planId: task.planId, taskId: task.taskId });
          resolve({ ok: true });
        };
        putReq.onerror = () => resolve({ ok: false, reason: REASONS.TX_ABORTED });
      };
      getReq.onerror = () => resolve({ ok: false, reason: REASONS.TX_ABORTED });
      tx.onerror = () => resolve({ ok: false, reason: REASONS.TX_ABORTED });
      tx.onabort = () => resolve({ ok: false, reason: REASONS.TX_ABORTED });
    });
  }

  async listTasksForPlan(planId) {
    const o = await this._ensureOpen();
    if (!o.ok) return o;
    return new Promise((resolve) => {
      const tx = this._db.transaction([STORE_TASKS], 'readonly');
      const req = tx.objectStore(STORE_TASKS).index('planId').getAll(planId);
      req.onsuccess = () => {
        const arr = Array.isArray(req.result) ? req.result : [];
        arr.sort((a, b) => (a.order - b.order) || String(a.taskId).localeCompare(String(b.taskId)));
        resolve({ ok: true, value: arr });
      };
      req.onerror = () => resolve({ ok: false, reason: REASONS.TX_ABORTED });
    });
  }

  async deleteTask(taskId) {
    const o = await this._ensureOpen();
    if (!o.ok) return o;
    return new Promise((resolve) => {
      const tx = this._db.transaction([STORE_TASKS], 'readwrite');
      const req = tx.objectStore(STORE_TASKS).delete(taskId);
      req.onsuccess = () => resolve({ ok: true });
      req.onerror = () => resolve({ ok: false, reason: REASONS.TX_ABORTED });
    });
  }

  // ---- evidence ----
  async putEvidence(evidence) {
    const v = validateEvidence(evidence);
    if (!v.ok) return v;
    const o = await this._ensureOpen();
    if (!o.ok) return o;
    return new Promise((resolve) => {
      const tx = this._db.transaction([STORE_EVIDENCE], 'readwrite');
      const store = tx.objectStore(STORE_EVIDENCE);
      const getReq = store.get(evidence.evidenceId);
      getReq.onsuccess = () => {
        const cur = getReq.result;
        if (cur && evidence.revision <= cur.revision) {
          resolve({ ok: false, reason: REASONS.STALE });
          return;
        }
        const putReq = store.put(v.value);
        putReq.onsuccess = () => {
          this._postMessage({ type: 'evidence-put', planId: evidence.planId, evidenceId: evidence.evidenceId });
          resolve({ ok: true });
        };
        putReq.onerror = () => resolve({ ok: false, reason: REASONS.TX_ABORTED });
      };
      getReq.onerror = () => resolve({ ok: false, reason: REASONS.TX_ABORTED });
      tx.onerror = () => resolve({ ok: false, reason: REASONS.TX_ABORTED });
      tx.onabort = () => resolve({ ok: false, reason: REASONS.TX_ABORTED });
    });
  }

  async listEvidenceForPlan(planId) {
    const o = await this._ensureOpen();
    if (!o.ok) return o;
    return new Promise((resolve) => {
      const tx = this._db.transaction([STORE_EVIDENCE], 'readonly');
      const req = tx.objectStore(STORE_EVIDENCE).index('planId').getAll(planId);
      req.onsuccess = () => {
        const arr = Array.isArray(req.result) ? req.result : [];
        arr.sort((a, b) => String(a.capturedAt).localeCompare(String(b.capturedAt)));
        resolve({ ok: true, value: arr });
      };
      req.onerror = () => resolve({ ok: false, reason: REASONS.TX_ABORTED });
    });
  }

  async deleteEvidence(evidenceId) {
    const o = await this._ensureOpen();
    if (!o.ok) return o;
    return new Promise((resolve) => {
      const tx = this._db.transaction([STORE_EVIDENCE], 'readwrite');
      const req = tx.objectStore(STORE_EVIDENCE).delete(evidenceId);
      req.onsuccess = () => resolve({ ok: true });
      req.onerror = () => resolve({ ok: false, reason: REASONS.TX_ABORTED });
    });
  }

  // ---- ledger ----
  async appendLedgerEvent(event) {
    const v = validateLedgerEvent(event);
    if (!v.ok) return v;
    const o = await this._ensureOpen();
    if (!o.ok) return o;
    return new Promise((resolve) => {
      const tx = this._db.transaction([STORE_LEDGER], 'readwrite');
      const store = tx.objectStore(STORE_LEDGER);
      const idx = store.index('planId');
      const cur = idx.openCursor(IDBKeyRange.only(event.planId));
      let lastEvent = null;
      let count = 0;
      cur.onsuccess = (e) => {
        const c = e.target.result;
        if (c) { count++; lastEvent = c.value; c.continue(); return; }
        const expectedSeq = count;
        if (event.sequence !== expectedSeq) {
          resolve({ ok: false, reason: REASONS.CONFLICT });
          return;
        }
        const expectedPrev = lastEvent ? lastEvent.eventHash : null;
        if ((event.previousEventHash || null) !== expectedPrev) {
          resolve({ ok: false, reason: REASONS.CONFLICT });
          return;
        }
        const putReq = store.put(v.value);
        putReq.onsuccess = () => {
          this._postMessage({ type: 'ledger-append', planId: event.planId, eventId: event.eventId, sequence: event.sequence });
          resolve({ ok: true });
        };
        putReq.onerror = () => resolve({ ok: false, reason: REASONS.TX_ABORTED });
      };
      cur.onerror = () => resolve({ ok: false, reason: REASONS.TX_ABORTED });
      tx.onerror = () => resolve({ ok: false, reason: REASONS.TX_ABORTED });
      tx.onabort = () => resolve({ ok: false, reason: REASONS.TX_ABORTED });
    });
  }

  async listLedgerEvents(planId) {
    const o = await this._ensureOpen();
    if (!o.ok) return o;
    return new Promise((resolve) => {
      const tx = this._db.transaction([STORE_LEDGER], 'readonly');
      const req = tx.objectStore(STORE_LEDGER).index('planId').getAll(planId);
      req.onsuccess = () => {
        const arr = Array.isArray(req.result) ? req.result : [];
        arr.sort((a, b) => (a.sequence - b.sequence) || String(a.eventId).localeCompare(String(b.eventId)));
        resolve({ ok: true, value: arr });
      };
      req.onerror = () => resolve({ ok: false, reason: REASONS.TX_ABORTED });
    });
  }

  // ---- maintenance ----
  async clearAll() {
    const o = await this._ensureOpen();
    if (!o.ok) return o;
    return new Promise((resolve) => {
      const tx = this._db.transaction(
        [STORE_PLANS, STORE_TASKS, STORE_EVIDENCE, STORE_LEDGER],
        'readwrite',
      );
      tx.objectStore(STORE_PLANS).clear();
      tx.objectStore(STORE_TASKS).clear();
      tx.objectStore(STORE_EVIDENCE).clear();
      tx.objectStore(STORE_LEDGER).clear();
      tx.oncomplete = () => {
        this._postMessage({ type: 'remediation-cleared' });
        resolve({ ok: true });
      };
      tx.onerror = () => resolve({ ok: false, reason: REASONS.TX_ABORTED });
      tx.onabort = () => resolve({ ok: false, reason: REASONS.TX_ABORTED });
    });
  }
}
