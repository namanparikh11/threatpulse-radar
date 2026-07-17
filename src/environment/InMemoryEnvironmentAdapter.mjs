/**
 * V6.6 — In-memory environment adapter.
 *
 * Used by the test runner and as a documented
 * "session-only" fallback when IndexedDB is
 * unavailable. The adapter never persists data
 * across reloads; the UI must surface this fact
 * prominently so the operator does not lose
 * work to a refresh.
 */

import { ASSET_SCHEMA_VERSION, COMPONENT_SCHEMA_VERSION, validateComponent } from './schema.mjs';

const REASONS = Object.freeze({
  INVALID: 'invalid-entry',
  UNKNOWN: 'unknown',
});

export class InMemoryEnvironmentAdapter {
  constructor() {
    this._assets = new Map();
    this._inventories = new Map();
    this._components = new Map();
    this._correlations = new Map();
    this._reviews = new Map();
    this._listeners = new Set();
    this._closed = false;
  }

  static get REASONS() { return REASONS; }

  static isSupported() { return true; }

  async open() { return { ok: true }; }

  close() {
    this._closed = true;
    this._assets.clear();
    this._inventories.clear();
    this._components.clear();
    this._correlations.clear();
    this._reviews.clear();
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

  async putAsset(asset) {
    if (!asset || asset.schemaVersion !== ASSET_SCHEMA_VERSION) return { ok: false, reason: REASONS.INVALID };
    this._assets.set(asset.assetId, asset);
    this._notify({ type: 'asset-put', assetId: asset.assetId });
    return { ok: true };
  }

  async getAsset(assetId) {
    return { ok: true, value: this._assets.get(assetId) || null };
  }

  async listAssets({ includeArchived = false } = {}) {
    const list = Array.from(this._assets.values());
    const filtered = includeArchived ? list : list.filter((a) => !a.archived);
    filtered.sort((a, b) => String(a.updatedAt).localeCompare(String(b.updatedAt)));
    return filtered;
  }

  async deleteAsset(assetId) {
    this._assets.delete(assetId);
    this._notify({ type: 'asset-delete', assetId });
    return { ok: true };
  }

  async applyInventory({ inventory, components }) {
    if (!inventory || !Array.isArray(components)) return { ok: false, reason: REASONS.INVALID };
    if (inventory.schemaVersion !== COMPONENT_SCHEMA_VERSION) return { ok: false, reason: REASONS.INVALID };
    // Validate every component BEFORE mutating any
    // state. A failed validation must leave the
    // previous inventory + components intact so the
    // operator never loses data to a malformed
    // import.
    for (const c of components) {
      const v = validateComponent(c);
      if (!v.ok) return { ok: false, reason: v.reason };
    }
    this._inventories.set(inventory.inventoryId, inventory);
    // Wipe previous components for this asset
    for (const [cid, c] of this._components) {
      if (c.assetId === inventory.assetId) this._components.delete(cid);
    }
    for (const c of components) this._components.set(c.componentId, c);
    // Update asset's latestInventoryId. The stored
    // asset may be frozen (an export-import roundtrip
    // freezes every record), so we replace it with a
    // shallow clone before mutating.
    const a = this._assets.get(inventory.assetId);
    if (a) {
      const next = Object.assign({}, a, {
        latestInventoryId: inventory.inventoryId,
        updatedAt: new Date().toISOString(),
      });
      this._assets.set(a.assetId, next);
    }
    this._notify({ type: 'inventory-applied', inventoryId: inventory.inventoryId, assetId: inventory.assetId });
    return { ok: true, inventoryId: inventory.inventoryId, componentCount: components.length };
  }

  async listInventorySnapshots(assetId) {
    const list = Array.from(this._inventories.values()).filter((i) => i.assetId === assetId);
    list.sort((a, b) => String(b.importedAt).localeCompare(String(a.importedAt)));
    return list;
  }

  async getLatestInventory(assetId) {
    const list = await this.listInventorySnapshots(assetId);
    return list.length > 0 ? list[0] : null;
  }

  async deleteInventorySnapshot(inventoryId) {
    this._inventories.delete(inventoryId);
    for (const [cid, c] of this._components) {
      if (c.inventoryId === inventoryId) this._components.delete(cid);
    }
    this._notify({ type: 'inventory-deleted', inventoryId });
    return { ok: true };
  }

  async listComponentsForAsset(assetId) {
    const list = Array.from(this._components.values()).filter((c) => c.assetId === assetId);
    list.sort((a, b) => String(a.name).localeCompare(String(b.name)));
    return list;
  }

  async replaceCorrelationsForInventory({ inventoryId, correlations, assetId }) {
    for (const [cid, c] of this._correlations) {
      if (c.inventoryId === inventoryId) this._correlations.delete(cid);
    }
    for (const c of (correlations || [])) this._correlations.set(c.correlationId, c);
    this._notify({ type: 'correlations-replaced', inventoryId, assetId });
    return { ok: true, count: Array.isArray(correlations) ? correlations.length : 0 };
  }

  async listCorrelationsForInventory(inventoryId) {
    const list = Array.from(this._correlations.values()).filter((c) => c.inventoryId === inventoryId);
    list.sort((a, b) => String(a.cveId).localeCompare(String(b.cveId)));
    return list;
  }

  async listCorrelationsForCve(cveId) {
    return Array.from(this._correlations.values()).filter((c) => c.cveId === cveId);
  }

  async putReview(review) {
    this._reviews.set(review.correlationId, review);
    this._notify({ type: 'review-put', correlationId: review.correlationId });
    return { ok: true };
  }

  async getReview(correlationId) {
    return this._reviews.get(correlationId) || null;
  }

  async listReviews() {
    return Array.from(this._reviews.values());
  }

  async deleteReview(correlationId) {
    this._reviews.delete(correlationId);
    this._notify({ type: 'review-delete', correlationId });
    return { ok: true };
  }

  async clearAll() {
    this._assets.clear();
    this._inventories.clear();
    this._components.clear();
    this._correlations.clear();
    this._reviews.clear();
    this._notify({ type: 'environment-cleared' });
    return { ok: true };
  }
}
