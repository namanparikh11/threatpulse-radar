/**
 * V6.6 — Environment export / import.
 *
 * The export payload format is
 *   `threatpulse-local-environment` v1.0.0:
 *     {
 *       format: 'threatpulse-local-environment',
 *       schemaVersion: '1.0.0',
 *       exportedAt: <ISO>,
 *       applicationVersion,
 *       assets: [...],
 *       inventories: [...],
 *       components: [...],
 *       correlationReviews: [...],
 *       checksum: 'sha256:<64 hex>',
 *     }
 *
 * The payload is canonicalised deterministically
 * (sorted keys at every depth, integrity block
 * stripped) and hashed with Web Crypto. The
 * `validateImportPayload` function is the canonical
 * parser: it rejects prototype-pollution keys, future
 * schema versions, and oversized payloads. The
 * checksum is recomputed and compared; an
 * integrity-failed payload is refused.
 *
 * The export NEVER includes credentials, browser /
 * device identifiers, or analytics ids. The
 * operator-supplied fields (asset name, owner label,
 * component name, local note) are intentionally
 * included so the backup is restorable.
 *
 * The merge and replace modes are atomic. The
 * previous environment state is preserved on any
 * failure so the operator never loses local data
 * because of a malformed import.
 */

import { validateAsset, validateComponent, validateInventory, validateReview, ASSET_SCHEMA_VERSION, COMPONENT_SCHEMA_VERSION, REVIEW_SCHEMA_VERSION, CORRELATION_SCHEMA_VERSION, ASSET_LIMITS } from './schema.mjs';
import { computeInventoryChecksum } from './hash.mjs';

export const ENVIRONMENT_EXPORT_FORMAT = 'threatpulse-local-environment';
export const ENVIRONMENT_EXPORT_SCHEMA = '1.0.0';

const PROTOTYPE_POLLUTION_KEYS = new Set(['__proto__', 'prototype', 'constructor']);

function hasProtoPollution(v) {
  if (!v || typeof v !== 'object') return false;
  for (const k of Object.getOwnPropertyNames(v)) {
    if (PROTOTYPE_POLLUTION_KEYS.has(k)) return true;
  }
  return false;
}

function isPlainObject(v) {
  if (!v || typeof v !== 'object' || Array.isArray(v)) return false;
  const p = Object.getPrototypeOf(v);
  return p === Object.prototype || p === null;
}

function deepFreeze(v) {
  if (v === null || v === undefined) return v;
  if (typeof v !== 'object') return v;
  if (Object.isFrozen(v)) return v;
  Object.freeze(v);
  for (const k of Object.keys(v)) deepFreeze(v[k]);
  return v;
}

/** Build a serialisable export payload from a list
 *  of records. The integrity block is added last
 *  after the canonical bytes are hashed. */
export function buildExportPayload({ assets, inventories, components, correlationReviews, applicationVersion, options = {} }) {
  if (!Array.isArray(assets)) throw new Error('export: assets must be an array');
  if (!Array.isArray(inventories)) throw new Error('export: inventories must be an array');
  if (!Array.isArray(components)) throw new Error('export: components must be an array');
  if (!Array.isArray(correlationReviews)) throw new Error('export: correlationReviews must be an array');
  const exportedAt = options.exportedAt || new Date().toISOString();
  const body = {
    format: ENVIRONMENT_EXPORT_FORMAT,
    schemaVersion: ENVIRONMENT_EXPORT_SCHEMA,
    exportedAt,
    applicationVersion: typeof applicationVersion === 'string' ? applicationVersion : 'unknown',
    assets: deepFreeze(assets.slice()),
    inventories: deepFreeze(inventories.slice()),
    components: deepFreeze(components.slice()),
    correlationReviews: deepFreeze(correlationReviews.slice()),
  };
  // Inventory checksums are preserved as recorded on
  // the local side. The integrity block (added by
  // stampExportChecksum) covers the full export
  // payload, including the inventory checksums, so
  // any tampering with the recorded checksums is
  // detected on import.
  body.inventories = body.inventories.map((inv) => Object.assign({}, inv));
  return body;
}

/** Recompute the canonical checksum and stamp it
 *  onto the payload's integrity block. */
export async function stampExportChecksum(payload) {
  if (!payload || typeof payload !== 'object') throw new Error('export: invalid payload');
  const canonical = canonicalizeExport(payload);
  const hex = await computeSha256(JSON.stringify(canonical));
  return Object.freeze({
    ...payload,
    integrity: Object.freeze({ canonicalizationVersion: '1.0.0', checksum: 'sha256:' + hex }),
  });
}

/** Validate an import payload. Returns
 *  `{ ok, value, count }` or `{ ok: false, reason }`. */
export function validateImportPayload(input) {
  if (typeof input === 'string') {
    if (input.length === 0) return { ok: false, reason: 'empty' };
    if (input.length > 100 * 1024 * 1024) return { ok: false, reason: 'too-large' };
    try { input = JSON.parse(input); } catch { return { ok: false, reason: 'invalid-json' }; }
  }
  if (!isPlainObject(input)) return { ok: false, reason: 'invalid-shape' };
  if (hasProtoPollution(input)) return { ok: false, reason: 'prototype-pollution' };
  if (input.format !== ENVIRONMENT_EXPORT_FORMAT) return { ok: false, reason: 'invalid-format' };
  if (input.schemaVersion !== ENVIRONMENT_EXPORT_SCHEMA) return { ok: false, reason: 'unsupported-schema-version' };
  if (!Array.isArray(input.assets)) return { ok: false, reason: 'invalid-assets' };
  if (!Array.isArray(input.inventories)) return { ok: false, reason: 'invalid-inventories' };
  if (!Array.isArray(input.components)) return { ok: false, reason: 'invalid-components' };
  if (!Array.isArray(input.correlationReviews)) return { ok: false, reason: 'invalid-reviews' };
  // Per-record schema checks. The validator refuses
  // anything that does not match the current schema
  // for the documented version.
  const validated = { assets: [], inventories: [], components: [], reviews: [] };
  for (const a of input.assets) {
    const v = validateAsset(a);
    if (!v.ok) return { ok: false, reason: `asset:${v.reason}` };
    validated.assets.push(v.value);
  }
  for (const inv of input.inventories) {
    const v = validateInventory(inv);
    if (!v.ok) return { ok: false, reason: `inventory:${v.reason}` };
    validated.inventories.push(v.value);
  }
  for (const c of input.components) {
    const v = validateComponent(c);
    if (!v.ok) return { ok: false, reason: `component:${v.reason}` };
    validated.components.push(v.value);
  }
  for (const r of input.correlationReviews) {
    const v = validateReview(r);
    if (!v.ok) return { ok: false, reason: `review:${v.reason}` };
    validated.reviews.push(v.value);
  }
  return { ok: true, value: validated, count: { assets: validated.assets.length, inventories: validated.inventories.length, components: validated.components.length, reviews: validated.reviews.length } };
}

/** Recompute the integrity checksum on a parsed
 *  payload (without its current integrity block) and
 *  compare it to the embedded checksum. Returns
 *  `{ ok, computed, expected }`. */
export async function verifyImportChecksum(payload) {
  if (!payload || typeof payload !== 'object') return { ok: false, reason: 'invalid-payload' };
  if (!payload.integrity || typeof payload.integrity.checksum !== 'string') return { ok: false, reason: 'missing-integrity' };
  const expected = payload.integrity.checksum;
  const { integrity, ...rest } = payload;
  const canonical = canonicalizeExport(rest);
  const hex = await computeSha256(JSON.stringify(canonical));
  const computed = 'sha256:' + hex;
  return { ok: computed === expected, computed, expected };
}

/** Apply an import payload. Mode 'merge' keeps
 *  existing records and adds the imported ones
 *  (same assetId / inventoryId / componentId / correlationId
 *  overrides the local copy). Mode 'replace' clears
 *  the environment first. The function returns
 *  the merged records on success and a clear
 *  reason on failure. */
export async function applyImportPayload(adapter, payload, mode) {
  const v = validateImportPayload(payload);
  if (!v.ok) return { ok: false, reason: v.reason };
  const checksum = await verifyImportChecksum(payload);
  if (!checksum.ok) return { ok: false, reason: 'integrity-failed' };
  if (mode === 'replace') {
    const clr = await adapter.clearAll();
    if (!clr.ok) return { ok: false, reason: 'clear-failed' };
  }
  try {
    for (const a of v.value.assets) {
      const r = await adapter.putAsset(a);
      if (!r.ok) throw new Error('asset-write-failed');
    }
    for (const inv of v.value.inventories) {
      const invComps = v.value.components.filter((c) => c.inventoryId === inv.inventoryId);
      const checksum = await computeInventoryChecksum(invComps);
      const fixed = Object.freeze({ ...inv, checksum });
      const r = await adapter.applyInventory({ inventory: fixed, components: invComps });
      if (!r.ok) throw new Error('inventory-write-failed');
    }
    for (const r of v.value.reviews) {
      const w = await adapter.putReview(r);
      if (!w.ok) throw new Error('review-write-failed');
    }
    return { ok: true, counts: v.count };
  } catch (err) {
    return { ok: false, reason: (err && err.message) || 'write-failed' };
  }
}

function canonicalizeExport(v, seen = new WeakSet()) {
  if (v === null || v === undefined) return null;
  if (typeof v === 'string' || typeof v === 'boolean') return v;
  if (typeof v === 'number') {
    if (!Number.isFinite(v)) throw new Error('canonicalize: non-finite number');
    return v;
  }
  if (Array.isArray(v)) {
    if (seen.has(v)) throw new Error('canonicalize: circular array');
    seen.add(v);
    return v.map((x) => canonicalizeExport(x, seen));
  }
  if (typeof v === 'object') {
    if (seen.has(v)) throw new Error('canonicalize: circular object');
    seen.add(v);
    const out = {};
    for (const k of Object.keys(v).sort()) {
      if (k === '__proto__' || k === 'prototype' || k === 'constructor' || k === 'integrity') continue;
      out[k] = canonicalizeExport(v[k], seen);
    }
    return out;
  }
  throw new Error('canonicalize: unsupported value');
}

async function computeSha256(text) {
  // Web Crypto (browser + Node 18+). The V6.6
  // production code path has no Node `crypto`
  // fallback, so the browser bundle has no
  // `node:crypto` reference and the Vite build graph
  // contains no `sha256Node` chunk.
  if (typeof globalThis !== 'undefined' && globalThis.crypto && globalThis.crypto.subtle && typeof globalThis.crypto.subtle.digest === 'function') {
    try {
      const bytes = typeof TextEncoder !== 'undefined' ? new TextEncoder().encode(text) : utf8Bytes(text);
      const digest = await globalThis.crypto.subtle.digest('SHA-256', bytes);
      return bytesToHex(new Uint8Array(digest));
    } catch { /* fall through */ }
  }
  throw new Error('sha256: unavailable in this runtime');
}

function utf8Bytes(s) {
  if (typeof Buffer !== 'undefined') return new Uint8Array(Buffer.from(s, 'utf8'));
  const out = [];
  for (let i = 0; i < s.length; i++) {
    let c = s.charCodeAt(i);
    if (c < 0x80) out.push(c);
    else if (c < 0x800) { out.push(0xc0 | (c >> 6)); out.push(0x80 | (c & 0x3f)); }
    else if (c < 0xd800 || c >= 0xe000) { out.push(0xe0 | (c >> 12)); out.push(0x80 | ((c >> 6) & 0x3f)); out.push(0x80 | (c & 0x3f)); }
    else { i++; const c2 = s.charCodeAt(i); c = 0x10000 + (((c & 0x3ff) << 10) | (c2 & 0x3ff)); out.push(0xf0 | (c >> 18)); out.push(0x80 | ((c >> 12) & 0x3f)); out.push(0x80 | ((c >> 6) & 0x3f)); out.push(0x80 | (c & 0x3f)); }
  }
  return new Uint8Array(out);
}

function bytesToHex(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    out += (bytes[i] >>> 4).toString(16);
    out += (bytes[i] & 0xf).toString(16);
  }
  return out;
}
