/**
 * V6.1 — Public-intelligence Blob store helpers.
 *
 * The V6.1 public-intelligence bundle is owned by the public
 * ThreatPulse Radar site and lives in a single, dedicated
 * Netlify Blobs store. The store is accessed via the public
 * site's local Netlify Blobs runtime context — no cross-site
 * access, no env var, no token. The private gateway never
 * reads this store.
 *
 * Layout (single store: tpr-public-intelligence):
 *
 *   osv/
 *     versions/{osvProjectionVersion}/
 *       manifest.json
 *     shards/sha256/{bucketContentHash}.json.gz
 *       (content-addressed shared namespace; reused across
 *        OSV projection versions when bucket content is
 *        unchanged)
 *     latest.json
 *     publication-lock
 *
 *   dataset/
 *     versions/{publicIntelligenceVersion}/
 *       manifest.json
 *       public-snapshot.json.gz
 *       changes.json.gz
 *     latest.json
 *     publication-lock
 *     change-summaries/{YYYY-MM-DD}.json
 *
 * Atomicity guarantee: each path (osv, dataset) has exactly
 * ONE mutable commit point (latest.json). All other artifacts
 * are immutable. A failed publication leaves the previous
 * latest.json intact and the previous version directory
 * intact.
 *
 * Schema versioning: per-blob schemas live under schemas/.
 * The bundle-level schema is `publicStateSchemaVersion`
 * (locked in commit 1; bumped on breaking changes).
 */

import { getStore } from '@netlify/blobs';

/** The single V6.1 public-intelligence Blob store. */
export const PUBLIC_INTELLIGENCE_STORE_NAME = 'tpr-public-intelligence';

/** OSV sub-tree. */
export const OSV_DIR = 'osv';
export const OSV_VERSIONS_DIR = `${OSV_DIR}/versions`;
export const OSV_SHARDS_DIR = `${OSV_DIR}/shards/sha256`;
export const OSV_LATEST_KEY = `${OSV_DIR}/latest.json`;
export const OSV_PUBLICATION_LOCK_KEY = `${OSV_DIR}/publication-lock`;

/** Dataset sub-tree. */
export const DATASET_DIR = 'dataset';
export const DATASET_VERSIONS_DIR = `${DATASET_DIR}/versions`;
export const DATASET_LATEST_KEY = `${DATASET_DIR}/latest.json`;
export const DATASET_PUBLICATION_LOCK_KEY = `${DATASET_DIR}/publication-lock`;
export const DATASET_CHANGE_SUMMARIES_DIR = `${DATASET_DIR}/change-summaries`;

/**
 * Per-version manifest, snapshot, and changes keys for a given
 * dataset-bound version. Helpers are pure (no I/O).
 */
export function datasetManifestKey(version) {
  assertSafeVersionId(version);
  return `${DATASET_VERSIONS_DIR}/${version}/manifest.json`;
}
export function datasetPublicSnapshotKey(version) {
  assertSafeVersionId(version);
  return `${DATASET_VERSIONS_DIR}/${version}/public-snapshot.json.gz`;
}
export function datasetChangesKey(version) {
  assertSafeVersionId(version);
  return `${DATASET_VERSIONS_DIR}/${version}/changes.json.gz`;
}

/**
 * Per-OSV-version manifest and shard key helpers. The shard
 * key is content-addressed: the bucket content hash IS the
 * key. This allows cross-version shard reuse.
 */
export function osvManifestKey(version) {
  assertSafeOsvVersionId(version);
  return `${OSV_VERSIONS_DIR}/${version}/manifest.json`;
}
export function osvShardKey(bucketContentHash) {
  assertSafeContentHash(bucketContentHash);
  // The hash is the key. No version prefix; the content-addressed
  // shared namespace allows cross-version reuse.
  const hash = bucketContentHash.startsWith('sha256:')
    ? bucketContentHash.slice('sha256:'.length)
    : bucketContentHash;
  return `${OSV_SHARDS_DIR}/${hash}.json.gz`;
}

/**
 * Resolve a handle to the public-intelligence Blob store. The
 * handle is the public site's local Netlify Blobs runtime
 * context; no cross-site access, no env var, no token.
 */
export function getPublicIntelligenceStore(opts = {}) {
  const consistency = opts.consistency ?? 'strong';
  return getStore({ name: PUBLIC_INTELLIGENCE_STORE_NAME, consistency });
}

/** OSV publication lock TTL (ms). Mirrors the V6.0 baseline lock. */
export const PUBLICATION_LOCK_TTL_MS = 5 * 60 * 1000;

/**
 * Minimal sanity check for a version id used in a Blob key.
 * Full validation lives in `publicIntelligenceValidation.mjs`;
 * this helper only guarantees the id is safe to interpolate
 * into a Blob key (no traversal, no control characters).
 */
function assertSafeVersionId(version) {
  if (typeof version !== 'string' || version.length === 0) {
    throw new Error('publicIntelligenceStore: version must be a non-empty string');
  }
  if (version.includes('/') || version.includes('\\') || version.includes('..') || version.includes('\0')) {
    throw new Error('publicIntelligenceStore: unsafe version id');
  }
}
function assertSafeOsvVersionId(version) {
  if (typeof version !== 'string' || version.length === 0) {
    throw new Error('publicIntelligenceStore: osv version must be a non-empty string');
  }
  if (version.includes('/') || version.includes('\\') || version.includes('..') || version.includes('\0')) {
    throw new Error('publicIntelligenceStore: unsafe osv version id');
  }
}
function assertSafeContentHash(hash) {
  if (typeof hash !== 'string' || hash.length === 0) {
    throw new Error('publicIntelligenceStore: content hash must be a non-empty string');
  }
  if (!/^sha256:[0-9a-f]{64}$/.test(hash) && !/^[0-9a-f]{64}$/.test(hash)) {
    throw new Error('publicIntelligenceStore: content hash must be sha256:<64 hex> or <64 hex>');
  }
}
