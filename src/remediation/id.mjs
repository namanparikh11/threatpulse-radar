/**
 * V6.7 — Deterministic ID helpers.
 *
 * FNV-1a 32-bit hash. Used to mint plan / task /
 * evidence / event ids from a stable canonical input.
 * The hash is collision-resistant enough for the
 * local-only data volume and is short enough to be
 * human-readable in URLs (but the IDs are never
 * placed in URLs).
 */

export function fnv1a(str) {
  if (typeof str !== 'string') throw new Error('fnv1a: input must be a string');
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h;
}

/** A short, opaque, deterministic id built from
 *  a namespace + key. The result is a 16-hex-char
 *  string of the form `pn-<hex>` for plans,
 *  `tk-<hex>` for tasks, etc. */
export function makeId(namespace, key) {
  if (typeof namespace !== 'string' || namespace.length === 0) throw new Error('makeId: namespace required');
  if (typeof key !== 'string' || key.length === 0) throw new Error('makeId: key required');
  return namespace + '-' + fnv1a(namespace + '|' + key).toString(16).padStart(8, '0');
}

export function makePlanId(key) { return makeId('plan', key); }
export function makeTaskId(key) { return makeId('task', key); }
export function makeEvidenceId(key) { return makeId('ev', key); }
export function makeEventId(key) { return makeId('evt', key); }
export function makeMutationId() {
  // Random 32-bit hex, time-prefixed. This is the
  // ONLY identifier that is allowed to be
  // non-deterministic; it only disambiguates a
  // single user's concurrent writes.
  return 'm-' + Date.now().toString(36) + '-' + Math.floor(Math.random() * 0xFFFFFFFF).toString(16).padStart(8, '0');
}

/** Local "now" timestamp. The producer of a
 *  timestamp is the user's browser; we do NOT
 *  trust any external clock. */
export function nowIso() { return new Date().toISOString(); }
