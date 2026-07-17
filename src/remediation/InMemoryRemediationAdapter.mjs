/**
 * V6.7 — In-memory remediation adapter.
 *
 * Used by the test runner and as a documented
 * "session-only" fallback when IndexedDB is
 * unavailable. The adapter never persists data
 * across reloads; the UI must surface this fact
 * prominently so the operator does not lose work
 * to a refresh.
 */

import {
  REMEDIATION_PLAN_SCHEMA_VERSION,
  REMEDIATION_TASK_SCHEMA_VERSION,
  REMEDIATION_EVIDENCE_SCHEMA_VERSION,
  REMEDIATION_LEDGER_SCHEMA_VERSION,
  validatePlan,
  validateTask,
  validateEvidence,
  validateLedgerEvent,
} from './schema.mjs';

const REASONS = Object.freeze({
  INVALID: 'invalid-entry',
  NOT_FOUND: 'not-found',
  STALE: 'stale-revision',
  CONFLICT: 'ledger-conflict',
  CLOSED: 'adapter-closed',
  UNKNOWN: 'unknown',
});

export class InMemoryRemediationAdapter {
  constructor() {
    this._plans = new Map();
    this._tasks = new Map();
    this._evidence = new Map();
    this._ledger = new Map();      // planId -> sorted array of events
    this._listeners = new Set();
    this._closed = false;
  }

  static get REASONS() { return REASONS; }
  static isSupported() { return true; }
  static get SCHEMA_VERSIONS() {
    return Object.freeze({
      plan: REMEDIATION_PLAN_SCHEMA_VERSION,
      task: REMEDIATION_TASK_SCHEMA_VERSION,
      evidence: REMEDIATION_EVIDENCE_SCHEMA_VERSION,
      ledger: REMEDIATION_LEDGER_SCHEMA_VERSION,
    });
  }

  async open() { return { ok: true }; }

  close() {
    this._closed = true;
    this._plans.clear();
    this._tasks.clear();
    this._evidence.clear();
    this._ledger.clear();
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

  _failIfClosed() {
    if (this._closed) return { ok: false, reason: REASONS.CLOSED };
    return null;
  }

  // ---- plans ----
  async putPlan(plan) {
    const closed = this._failIfClosed(); if (closed) return closed;
    const v = validatePlan(plan);
    if (!v.ok) return v;
    const cur = this._plans.get(plan.planId);
    if (cur && plan.revision <= cur.revision) {
      return { ok: false, reason: REASONS.STALE };
    }
    this._plans.set(plan.planId, v.value);
    this._notify({ type: 'plan-put', planId: plan.planId });
    return { ok: true };
  }

  async getPlan(planId) {
    const closed = this._failIfClosed(); if (closed) return closed;
    return { ok: true, value: this._plans.get(planId) || null };
  }

  async listPlans({ includeArchived = false } = {}) {
    const closed = this._failIfClosed(); if (closed) return closed;
    const out = Array.from(this._plans.values()).filter((p) => includeArchived || !p.archived);
    out.sort((a, b) => String(b.updatedAt).localeCompare(String(a.updatedAt)));
    return { ok: true, value: out };
  }

  async deletePlan(planId) {
    const closed = this._failIfClosed(); if (closed) return closed;
    if (!this._plans.has(planId)) return { ok: false, reason: REASONS.NOT_FOUND };
    this._plans.delete(planId);
    for (const [tid, t] of this._tasks) if (t.planId === planId) this._tasks.delete(tid);
    for (const [eid, e] of this._evidence) if (e.planId === planId) this._evidence.delete(eid);
    this._ledger.delete(planId);
    this._notify({ type: 'plan-deleted', planId });
    return { ok: true };
  }

  // ---- tasks ----
  async putTask(task) {
    const closed = this._failIfClosed(); if (closed) return closed;
    const v = validateTask(task);
    if (!v.ok) return v;
    const cur = this._tasks.get(task.taskId);
    if (cur && task.revision <= cur.revision) {
      return { ok: false, reason: REASONS.STALE };
    }
    this._tasks.set(task.taskId, v.value);
    this._notify({ type: 'task-put', planId: task.planId, taskId: task.taskId });
    return { ok: true };
  }

  async listTasksForPlan(planId) {
    const closed = this._failIfClosed(); if (closed) return closed;
    const out = [];
    for (const t of this._tasks.values()) if (t.planId === planId) out.push(t);
    out.sort((a, b) => (a.order - b.order) || String(a.taskId).localeCompare(String(b.taskId)));
    return { ok: true, value: out };
  }

  async deleteTask(taskId) {
    const closed = this._failIfClosed(); if (closed) return closed;
    if (!this._tasks.has(taskId)) return { ok: false, reason: REASONS.NOT_FOUND };
    this._tasks.delete(taskId);
    return { ok: true };
  }

  // ---- evidence ----
  async putEvidence(evidence) {
    const closed = this._failIfClosed(); if (closed) return closed;
    const v = validateEvidence(evidence);
    if (!v.ok) return v;
    const cur = this._evidence.get(evidence.evidenceId);
    if (cur && evidence.revision <= cur.revision) {
      return { ok: false, reason: REASONS.STALE };
    }
    this._evidence.set(evidence.evidenceId, v.value);
    this._notify({ type: 'evidence-put', planId: evidence.planId, evidenceId: evidence.evidenceId });
    return { ok: true };
  }

  async listEvidenceForPlan(planId) {
    const closed = this._failIfClosed(); if (closed) return closed;
    const out = [];
    for (const e of this._evidence.values()) if (e.planId === planId) out.push(e);
    out.sort((a, b) => String(a.capturedAt).localeCompare(String(b.capturedAt)));
    return { ok: true, value: out };
  }

  async deleteEvidence(evidenceId) {
    const closed = this._failIfClosed(); if (closed) return closed;
    if (!this._evidence.has(evidenceId)) return { ok: false, reason: REASONS.NOT_FOUND };
    this._evidence.delete(evidenceId);
    return { ok: true };
  }

  // ---- ledger ----
  async appendLedgerEvent(event) {
    const closed = this._failIfClosed(); if (closed) return closed;
    const v = validateLedgerEvent(event);
    if (!v.ok) return v;
    const arr = this._ledger.get(event.planId) || [];
    const expectedSeq = arr.length;
    if (event.sequence !== expectedSeq) {
      return { ok: false, reason: REASONS.CONFLICT };
    }
    if ((event.previousEventHash || null) !== (arr.length > 0 ? arr[arr.length - 1].eventHash : null)) {
      return { ok: false, reason: REASONS.CONFLICT };
    }
    arr.push(v.value);
    this._ledger.set(event.planId, arr);
    this._notify({ type: 'ledger-append', planId: event.planId, eventId: event.eventId, sequence: event.sequence });
    return { ok: true };
  }

  async listLedgerEvents(planId) {
    const closed = this._failIfClosed(); if (closed) return closed;
    return { ok: true, value: (this._ledger.get(planId) || []).slice() };
  }

  async clearAll() {
    const closed = this._failIfClosed(); if (closed) return closed;
    this._plans.clear();
    this._tasks.clear();
    this._evidence.clear();
    this._ledger.clear();
    this._notify({ type: 'remediation-cleared' });
    return { ok: true };
  }

  /** Test-only escape hatch: peek at the raw
   *  internal maps. The production React context
   *  uses the documented `list*` methods. */
  _debugDump() {
    return {
      plans: Array.from(this._plans.keys()),
      tasks: Array.from(this._tasks.keys()),
      evidence: Array.from(this._evidence.keys()),
      ledger: Array.from(this._ledger.entries()).map(([k, v]) => [k, v.length]),
    };
  }
}
