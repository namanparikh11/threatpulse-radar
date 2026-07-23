/**
 * V6.1 — Public-intelligence size budgets and bounds.
 *
 * The size budget is enforced at write time. A write that
 * exceeds a hard ceiling aborts the publication; the previous
 * latest.json is preserved. Sizes are computed on the canonical
 * (uncompressed) bytes AND the gzipped transport bytes (where
 * gzipped storage is used).
 *
 * Soft targets and hard ceilings are documented constants
 * (read by the acceptance suite). Source of truth for the
 * budget numbers; no hard-coded magic numbers in the publisher.
 */

import { gunzipSync, gzipSync } from 'node:zlib';
import { canonicalByteLength } from './canonicalHash.mjs';

/* ---- Public-intelligence envelope (dataset/latest.json) ---- */

/** Soft target for dataset/latest.json. */
export const LATEST_JSON_TARGET_BYTES = 32 * 1024;          // 32 KiB
/** Hard ceiling for dataset/latest.json. Publication aborts above. */
export const LATEST_JSON_HARD_CEILING_BYTES = 64 * 1024;    // 64 KiB

/* ---- Dataset-bound manifest (dataset/versions/{v}/manifest.json) ---- */

export const DATASET_MANIFEST_TARGET_BYTES = 5 * 1024;       // 5 KiB
export const DATASET_MANIFEST_HARD_CEILING_BYTES = 16 * 1024; // 16 KiB

/* ---- OSV per-version manifest (osv/versions/{v}/manifest.json) ---- */

export const OSV_MANIFEST_TARGET_BYTES = 5 * 1024;           // 5 KiB
export const OSV_MANIFEST_HARD_CEILING_BYTES = 16 * 1024;    // 16 KiB

/* ---- OSV latest.json ---- */

export const OSV_LATEST_TARGET_BYTES = 1024;                 // 1 KiB
export const OSV_LATEST_HARD_CEILING_BYTES = 4 * 1024;       // 4 KiB

/* ---- OSV content-addressed shard ---- */

export const OSV_SHARD_TARGET_UNCOMPRESSED_BYTES = 256 * 1024;     // 256 KiB
export const OSV_SHARD_HARD_CEILING_UNCOMPRESSED_BYTES = 1024 * 1024; // 1 MiB
export const OSV_SHARD_HARD_CEILING_COMPRESSED_BYTES = 256 * 1024;   // 256 KiB

/* ---- Dataset public comparison snapshot (logical) ---- */
// The public-snapshot hard ceiling applies to the LOGICAL
// snapshot as a single virtual object. Production data
// has been observed at 1,124,204 bytes (about 74 KiB
// over the 1 MiB hard ceiling). The 1 MiB hard ceiling
// is preserved unchanged as a per-object safety ceiling;
// the per-version snapshot is split into deterministic
// content-addressed shards so every stored object remains
// below this ceiling. See
// `publicSnapshotShards.mjs` for the sharding algorithm.
export const PUBLIC_SNAPSHOT_TARGET_UNCOMPRESSED_BYTES = 256 * 1024;     // 256 KiB
export const PUBLIC_SNAPSHOT_HARD_CEILING_UNCOMPRESSED_BYTES = 1024 * 1024; // 1 MiB
export const PUBLIC_SNAPSHOT_HARD_CEILING_COMPRESSED_BYTES = 256 * 1024;   // 256 KiB

/* ---- Dataset public comparison snapshot shards ---- */
// Per-shard size budgets. Each shard is a content-addressed
// immutable object holding a portion of the logical
// snapshot. Every shard is kept SAFELY BELOW the
// per-object safety ceiling (PUBLIC_SNAPSHOT_HARD_CEILING_UNCOMPRESSED_BYTES)
// with explicit headroom. The shard manifest itself is
// well under the dataset manifest hard ceiling so it can
// always be written atomically.
export const SNAPSHOT_SHARD_TARGET_UNCOMPRESSED_BYTES = 192 * 1024;          // 192 KiB target
export const SNAPSHOT_SHARD_HARD_CEILING_UNCOMPRESSED_BYTES = 768 * 1024;     // 768 KiB ceiling (safely under 1 MiB)
export const SNAPSHOT_SHARD_HARD_CEILING_COMPRESSED_BYTES = 192 * 1024;      // 192 KiB ceiling
// Minimum number of CVEs per shard. A single shard must
// hold at least this many CVEs; a smaller dataset is a
// degenerate single-shard case. The partitioner NEVER
// produces a shard with fewer CVEs than this cap; when
// the logical snapshot has fewer than this many CVEs the
// partitioner returns a single shard.
export const SNAPSHOT_SHARD_MIN_CVES_PER_SHARD = 8;

/* ---- Dataset changes.json.gz ---- */

export const CHANGES_TARGET_COMPRESSED_BYTES = 50 * 1024;     // 50 KiB
export const CHANGES_HARD_CEILING_COMPRESSED_BYTES = 256 * 1024; // 256 KiB

/* ---- Per-record field caps (public OSV projection) ---- */

/** Max OSV records per CVE in the public projection. */
export const OSV_RECORDS_PER_CVE_CAP = 8;
/** Max aliases per OSV record. */
export const OSV_ALIASES_PER_RECORD_CAP = 10;
/** Max references per OSV record. */
export const OSV_REFERENCES_PER_RECORD_CAP = 5;
/** Max affected packages per OSV record. */
export const OSV_PACKAGES_PER_RECORD_CAP = 6;
/** Max ranges per package. */
export const OSV_RANGES_PER_PACKAGE_CAP = 4;
/** Max events per range. */
export const OSV_EVENTS_PER_RANGE_CAP = 8;
/** Max versions per package. */
export const OSV_VERSIONS_PER_PACKAGE_CAP = 8;
/** Max primitive key/value pairs in ecosystemSpecific / databaseSpecific. */
export const OSV_ECO_SPECIFIC_MAX_PAIRS = 32;

/* ---- Deterministic bucket count for OSV shards ---- */

export const OSV_BUCKET_COUNT = 16;

/* ---- Change items cap ---- */

export const CHANGES_ITEMS_HARD_CAP = 5000;
export const CHANGES_ITEMS_DEFAULT_LIMIT = 25;
export const CHANGES_ITEMS_MAX_LIMIT = 25;

/* ---- Retention ---- */

export const MAX_RETAINED_VERSIONS_PER_PATH = 3; // current, previous, rollback

/* ---- Helpers ---- */

/**
 * Compute the uncompressed byte size of a canonical value.
 */
export function uncompressedBytes(value) {
  return canonicalByteLength(value);
}

/**
 * Compute the gzipped byte size of a JSON-serializable value.
 */
export function compressedBytes(value) {
  const json = JSON.stringify(value);
  return gzipSync(Buffer.from(json, 'utf8')).length;
}

/**
 * Gzip a JSON-serializable value to a Buffer. Throws on size
 * ceiling violation when `enforceCompressedCeiling` is provided.
 */
export function gzipJson(value, enforceCompressedCeiling = null) {
  const json = JSON.stringify(value);
  const gz = gzipSync(Buffer.from(json, 'utf8'));
  if (enforceCompressedCeiling != null && gz.length > enforceCompressedCeiling) {
    throw new SizeCeilingExceededError(
      `compressed size ${gz.length} exceeds ceiling ${enforceCompressedCeiling}`,
    );
  }
  return gz;
}

/**
 * Gunzip a Buffer to a JSON-parsed value. Defensive: returns
 * null on empty input, throws on parse error.
 */
export function gunzipJson(buffer) {
  if (!buffer || buffer.length === 0) return null;
  const text = gunzipSync(Buffer.from(buffer)).toString('utf8');
  return JSON.parse(text);
}

/**
 * Assert that an uncompressed value's size is within a hard
 * ceiling. Throws SizeCeilingExceededError if not.
 */
export function assertUncompressedSize(value, ceilingBytes, label = 'value') {
  const size = uncompressedBytes(value);
  if (size > ceilingBytes) {
    throw new SizeCeilingExceededError(
      `${label} uncompressed size ${size} exceeds ceiling ${ceilingBytes}`,
    );
  }
  return size;
}

/**
 * Custom error type. Publications that exceed a size ceiling
 * catch this and abort the publication, preserving the
 * previous latest.json.
 */
export class SizeCeilingExceededError extends Error {
  constructor(message) {
    super(message);
    this.name = 'SizeCeilingExceededError';
  }
}
