/**
 * V6.1 — Deterministic CVE-to-OSV-bucket helper.
 *
 * The OSV public projection is partitioned into 16 logical
 * buckets by the first hex digit of SHA-256(normalizedCveId).
 * The bucket is computed in the dataset function at request
 * time; no per-CVE index map is stored in `latest.json`.
 *
 * The bucket is one of the 16 lowercase hex digits
 * `0`, `1`, ..., `9`, `a`, `b`, ..., `f`.
 *
 * Retries with identical content produce identical bucket
 * assignment. The distribution is approximately uniform
 * across the CVE id space (16-bucket range).
 */

import { createHash } from 'node:crypto';

export const OSV_BUCKET_COUNT = 16;

/**
 * Compute the bucket digit for a given CVE id. The CVE id is
 * normalized (trimmed, uppercased) before hashing; the result
 * is a single lowercase hex digit.
 */
export function cveBucket(cveId) {
  if (typeof cveId !== 'string' || cveId.length === 0) {
    throw new Error('cveBucket: cveId must be a non-empty string');
  }
  const normalized = cveId.trim().toUpperCase();
  const hash = createHash('sha256').update(normalized, 'utf8').digest('hex');
  return hash[0]; // first hex digit; lowercase a-f or digit 0-9
}

/**
 * Bucket for an already-normalized CVE id (uppercase, no
 * whitespace). Slightly faster than `cveBucket` because it
 * skips normalization. Throws when the input is not
 * uppercase-only (i.e. contains any lowercase letter or
 * non-`CVE-\d{4}-\d{4,7}` shape).
 */
export function cveBucketNormalized(cveIdUpper) {
  if (typeof cveIdUpper !== 'string' || cveIdUpper.length === 0) {
    throw new Error('cveBucketNormalized: cveIdUpper must be a non-empty string');
  }
  if (!/^CVE-\d{4}-\d{4,7}$/.test(cveIdUpper)) {
    throw new Error('cveBucketNormalized: input must match /CVE-\\d{4}-\\d{4,7}/');
  }
  const hash = createHash('sha256').update(cveIdUpper, 'utf8').digest('hex');
  return hash[0];
}
