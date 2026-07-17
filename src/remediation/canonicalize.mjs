/**
 * V6.7 — Remediation canonicalization.
 *
 * Deterministic JSON form used to compute the SHA-256
 * that anchors a ledger event. The canonical form is
 * stable across re-exports of the same logical event.
 *
 * Rules (mirroring the V6.5 reports / V6.6 env approach):
 *   - object keys are sorted alphabetically at every
 *     depth
 *   - `undefined` is dropped
 *   - non-finite numbers throw
 *   - circular references throw
 *   - prototype-pollution keys are skipped
 *   - the integrity field is NOT included in the
 *     canonical bytes
 *
 * The canonical form is consumed by:
 *   - `src/remediation/ledger.mjs` to compute the
 *     event hash chain
 *   - `src/remediation/exportImport.mjs` to compute
 *     the bundle-level integrity checksum
 */

const PROTOTYPE_POLLUTION_KEYS = new Set(['__proto__', 'prototype', 'constructor']);

function isPlainObject(v) {
  if (!v || typeof v !== 'object' || Array.isArray(v)) return false;
  const p = Object.getPrototypeOf(v);
  return p === Object.prototype || p === null;
}

function canonicalize(v, seen = new WeakSet()) {
  if (v === null || v === undefined) return null;
  if (typeof v === 'string' || typeof v === 'boolean') return v;
  if (typeof v === 'number') {
    if (!Number.isFinite(v)) throw new Error('canonicalize: non-finite number');
    return v;
  }
  if (Array.isArray(v)) {
    if (seen.has(v)) throw new Error('canonicalize: circular array');
    seen.add(v);
    return v.map((x) => canonicalize(x, seen));
  }
  if (typeof v === 'object') {
    if (seen.has(v)) throw new Error('canonicalize: circular object');
    seen.add(v);
    const out = {};
    for (const k of Object.keys(v).sort()) {
      if (PROTOTYPE_POLLUTION_KEYS.has(k)) continue;
      if (k === 'integrity' || k === 'eventHash' || k === 'checksum') continue;
      out[k] = canonicalize(v[k], seen);
    }
    return out;
  }
  throw new Error('canonicalize: unsupported value');
}

/** Return the canonical byte form of `v` as a JSON
 *  string with no whitespace, sorted keys, and
 *  integrity/EventHash/checksum fields stripped. */
export function canonicalizeToString(v) {
  return JSON.stringify(canonicalize(v));
}

/** Return the canonical object form of `v` (sorted
 *  keys, integrity stripped, no whitespace). */
export function canonicalizeObject(v) {
  return canonicalize(v);
}
