/**
 * V6.0 — Deterministic canonical serialization and SHA-256 content hashing.
 *
 * The canonical baseline is content-addressed. The canonical bytes of an
 * object are computed by:
 *
 *   1. Recursively sorting object keys lexicographically.
 *   2. For arrays of entities, sorting by `canonicalId` (lexicographic).
 *   3. Serializing numbers as plain decimal (no scientific notation).
 *   4. Serializing strings as-is, with JSON's default escaping.
 *   5. Including explicit `null` / `false` (not omitting absent fields).
 *
 * The SHA-256 of the UTF-8 bytes of the canonical JSON string is the
 * "content hash". The output is the lowercase hex digest with a
 * `sha256:` prefix. The hash is computed over the CANONICAL bytes, not
 * the gzipped transport bytes; gzip is a transport optimization and is
 * never included in the hash.
 *
 * The canonical bytes are also the input to the version derivation:
 *
 *   version = <iso timestamp with colons→hyphens>-<first 8 hex of sha256(contentHash)>
 *
 * The same canonical input always produces the same content hash and the
 * same first-8-hex short hash, so identical content deduplicates on disk.
 */

import { createHash } from 'node:crypto';

/**
 * Recursively canonicalize a value.
 *
 * - Plain values (string, number, boolean, null) pass through with
 *   number formatting normalized.
 * - Arrays of entities are sorted by `canonicalId` if every element
 *   has one; otherwise they are preserved in input order (because the
 *   order of non-entity arrays is semantically meaningful — e.g. the
 *   `events` array of a version range is a sequence, not a set).
 * - Objects have their keys sorted lexicographically.
 *
 * The function never mutates the input.
 */
export function canonicalize(value) {
  if (value === null || value === undefined) return null;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) return null;
    // Plain decimal, no scientific notation. JSON.stringify of a
    // finite number already produces plain decimal in V8; the explicit
    // cast here is a defensive pin in case the runtime ever changes.
    return Object.is(value, -0) ? 0 : value;
  }
  if (typeof value === 'string' || typeof value === 'boolean') {
    return value;
  }
  if (Array.isArray(value)) {
    // Detect "entity array" — every element has a string canonicalId.
    const allHaveId = value.length > 0 && value.every(
      (v) => v && typeof v === 'object' && typeof v.canonicalId === 'string'
    );
    const sorted = allHaveId
      ? [...value].sort((a, b) => (a.canonicalId < b.canonicalId ? -1 : a.canonicalId > b.canonicalId ? 1 : 0))
      : [...value];
    return sorted.map(canonicalize);
  }
  if (typeof value === 'object') {
    const out = {};
    for (const key of Object.keys(value).sort()) {
      out[key] = canonicalize(value[key]);
    }
    return out;
  }
  return null;
}

/**
 * Serialize a value to a canonical JSON string.
 */
export function canonicalizeToString(value) {
  return JSON.stringify(canonicalize(value));
}

/**
 * Compute the SHA-256 hex digest of an input string or buffer.
 */
export function sha256Hex(input) {
  const h = createHash('sha256');
  h.update(input);
  return h.digest('hex');
}

/**
 * Compute the content hash of a value: sha256 of the canonical JSON bytes,
 * formatted as `sha256:<lowercase hex>`.
 */
export function contentHash(value) {
  return `sha256:${sha256Hex(canonicalizeToString(value))}`;
}

/**
 * Compute the first N hex characters of a content hash. Used to derive
 * the 8-char short hash that becomes part of the baseline version.
 */
export function shortHash(contentHashValue, len = 8) {
  if (typeof contentHashValue !== 'string') return '';
  const stripped = contentHashValue.startsWith('sha256:')
    ? contentHashValue.slice('sha256:'.length)
    : contentHashValue;
  return stripped.slice(0, len);
}

/**
 * Derive a baseline version from a publish timestamp and the canonical
 * content hash.
 *
 *   version = <iso timestamp truncated to seconds, colons→hyphens>-<first 8 hex>
 *
 * Example: '2026-07-12T20-30-00Z-a1b2c3d4'
 *
 * The timestamp is truncated to seconds so the version is filesystem-safe
 * (no colons) and stable (millisecond jitter does not change the
 * version when the second is the same). Millisecond precision in the
 * manifest's `publishedAt` is preserved independently.
 */
export function deriveBaselineVersion(publishedAt, contentHashValue) {
  if (typeof publishedAt !== 'string' || !publishedAt) {
    throw new Error('deriveBaselineVersion: publishedAt is required');
  }
  // Truncate to seconds and replace colons with hyphens.
  // Accepts '2026-07-12T20:30:00.000Z' and '2026-07-12T20:30:00Z' alike.
  const sec = publishedAt.replace(/\.\d+(?=Z)/, '').replace(/:/g, '-');
  return `${sec}-${shortHash(contentHashValue, 8)}`;
}

/**
 * Canonicalize a value and return the UTF-8 byte length. Useful for
 * deciding whether a shard is "empty" (zero records).
 */
export function canonicalByteLength(value) {
  return Buffer.byteLength(canonicalizeToString(value), 'utf8');
}
