/**
 * V6.6 — Unavailable environment adapter.
 *
 * Used when neither IndexedDB nor an in-memory
 * fallback is acceptable (e.g. the user has
 * explicitly disabled local storage, or a
 * hardened enterprise policy blocks all
 * storage APIs). Every op returns
 * `{ ok: false, reason: 'unavailable' }`.
 *
 * The UI surfaces a prominent warning that
 * local environment data cannot be saved in
 * this session.
 */

const REASONS = Object.freeze({
  UNAVAILABLE: 'unavailable',
});

export class UnavailableEnvironmentAdapter {
  static isSupported() { return false; }

  static get REASONS() { return REASONS; }

  async open() { return { ok: false, reason: REASONS.UNAVAILABLE }; }
  close() {}
  on() { return () => {}; }

  async putAsset() { return { ok: false, reason: REASONS.UNAVAILABLE }; }
  async getAsset() { return { ok: true, value: null }; }
  async listAssets() { return []; }
  async deleteAsset() { return { ok: false, reason: REASONS.UNAVAILABLE }; }
  async applyInventory() { return { ok: false, reason: REASONS.UNAVAILABLE }; }
  async listInventorySnapshots() { return []; }
  async getLatestInventory() { return null; }
  async deleteInventorySnapshot() { return { ok: false, reason: REASONS.UNAVAILABLE }; }
  async listComponentsForAsset() { return []; }
  async replaceCorrelationsForInventory() { return { ok: false, reason: REASONS.UNAVAILABLE }; }
  async listCorrelationsForInventory() { return []; }
  async listCorrelationsForCve() { return []; }
  async putReview() { return { ok: false, reason: REASONS.UNAVAILABLE }; }
  async getReview() { return null; }
  async listReviews() { return []; }
  async deleteReview() { return { ok: false, reason: REASONS.UNAVAILABLE }; }
  async clearAll() { return { ok: false, reason: REASONS.UNAVAILABLE }; }
}
