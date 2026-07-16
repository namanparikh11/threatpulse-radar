/**
 * V6.5 — Deterministic canonical JSON.
 *
 * The integrity checksum is computed over a single,
 * stable, byte-exact representation of the report
 * data. The canonical form is:
 *   - object keys sorted in ASCII order at every
 *     depth
 *   - arrays preserved in their logical order
 *     (the upstream code is responsible for
 *     cveId-sorted arrays, etc.)
 *   - no whitespace
 *   - no `undefined` values
 *   - numbers / booleans / null serialised by
 *     `JSON.stringify`
 *   - the `integrity` block is EXCLUDED from the
 *     digest input (the checksum is computed over
 *     the rest and then stored inside the integrity
 *     block)
 *
 * The function is pure: same input → same output.
 *
 * The function explicitly rejects non-finite numbers
 * and circular references so the digest input is
 * always byte-stable.
 */

const ISO_DATE_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;

/**
 * Normalise a single value for canonicalisation.
 *  - strings are returned as-is (the upstream code
 *    is responsible for trimming when appropriate)
 *  - booleans and numbers are returned as-is
 *  - null is returned as null
 *  - arrays are normalised recursively, preserving
 *    order
 *  - plain objects are normalised recursively with
 *    keys sorted in ASCII order
 *  - Date objects are serialised to ISO UTC and
 *    treated as strings
 */
function normaliseValue(v, seen = new WeakSet()) {
  if (v === null) return null;
  if (v === undefined) return null; // dropped
  if (typeof v === 'string') return v;
  if (typeof v === 'boolean') return v;
  if (typeof v === 'number') {
    if (!Number.isFinite(v)) {
      throw new Error('canonicalize: non-finite number');
    }
    return v;
  }
  if (Array.isArray(v)) {
    if (seen.has(v)) {
      throw new Error('canonicalize: circular array');
    }
    seen.add(v);
    return v.map((x) => normaliseValue(x, seen));
  }
  if (typeof v === 'object') {
    const proto = Object.getPrototypeOf(v);
    if (proto !== Object.prototype && proto !== null) {
      // Date, etc.: serialise to string.
      if (v instanceof Date) {
        return v.toISOString();
      }
      throw new Error('canonicalize: unsupported object type');
    }
    if (seen.has(v)) {
      throw new Error('canonicalize: circular object');
    }
    seen.add(v);
    const out = {};
    const keys = Object.keys(v).sort();
    for (const k of keys) {
      if (k === '__proto__' || k === 'prototype' || k === 'constructor') continue;
      out[k] = normaliseValue(v[k], seen);
    }
    return out;
  }
  throw new Error(`canonicalize: unsupported value (${typeof v})`);
}

/**
 * Build the canonical bytes for a report. The
 * `integrity` block is excluded; the upstream caller
 * computes the digest and inserts the result.
 */
export function canonicalizeReportBytes(report) {
  if (!report || typeof report !== 'object' || Array.isArray(report)) {
    throw new Error('canonicalizeReportBytes: not an object');
  }
  const { integrity, ...rest } = report;
  void integrity;
  const normalised = normaliseValue(rest);
  // Stable JSON: no whitespace, sorted keys (already
  // sorted by normaliseValue), UTF-8.
  return JSON.stringify(normalised);
}

/**
 * Compute the canonical bytes WITH the integrity
 * block restored. This is used to re-verify a
 * report after the digest has been verified
 * (the caller has already re-derived the canonical
 * bytes and matched the checksum).
 */
export function canonicalizeReportBytesWithIntegrity(report) {
  if (!report || typeof report !== 'object' || Array.isArray(report)) {
    throw new Error('canonicalizeReportBytesWithIntegrity: not an object');
  }
  return JSON.stringify(normaliseValue(report));
}

/**
 * Heuristic: true iff the given string looks like an
 * ISO-8601 UTC timestamp. The function is used by
 * exporters to decide whether to render a value as a
 * date or as a raw string.
 */
export function looksLikeIsoDate(s) {
  return typeof s === 'string' && ISO_DATE_RE.test(s);
}
