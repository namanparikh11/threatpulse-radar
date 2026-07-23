/**
 * V6.7 — Unavailable remediation adapter.
 *
 * Used when neither IndexedDB nor an in-memory
 * fallback is acceptable. Every op returns
 * `{ ok: false, reason: 'unavailable' }`. The
 * React context surfaces a prominent warning that
 * local remediation data cannot be saved in this
 * session.
 */

const REASONS = Object.freeze({
  UNAVAILABLE: 'unavailable',
});

export class UnavailableRemediationAdapter {
  static isSupported() { return false; }
  static get REASONS() { return REASONS; }

  async open() { return { ok: false, reason: REASONS.UNAVAILABLE }; }
  close() {}
  on() { return () => {}; }

  async putPlan()    { return { ok: false, reason: REASONS.UNAVAILABLE }; }
  async getPlan()    { return { ok: true, value: null }; }
  async listPlans()  { return { ok: true, value: [] }; }
  async deletePlan() { return { ok: false, reason: REASONS.UNAVAILABLE }; }
  async putTask()    { return { ok: false, reason: REASONS.UNAVAILABLE }; }
  async listTasksForPlan() { return { ok: true, value: [] }; }
  async deleteTask() { return { ok: false, reason: REASONS.UNAVAILABLE }; }
  async putEvidence() { return { ok: false, reason: REASONS.UNAVAILABLE }; }
  async listEvidenceForPlan() { return { ok: true, value: [] }; }
  async deleteEvidence() { return { ok: false, reason: REASONS.UNAVAILABLE }; }
  async appendLedgerEvent() { return { ok: false, reason: REASONS.UNAVAILABLE }; }
  async listLedgerEvents() { return { ok: true, value: [] }; }
  async clearAll() { return { ok: false, reason: REASONS.UNAVAILABLE }; }
}
