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

import { createStorageAdapter } from './storage/index.mjs';

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
 * V6.8: per-version shard manifest key. The dataset
 * public-snapshot is split into N deterministic
 * content-addressed shards (see
 * `publicSnapshotShards.mjs`) so the logical snapshot
 * can exceed the 1 MiB per-object safety ceiling
 * without raising the ceiling itself. The shard
 * manifest is the per-version pointer to the shards.
 */
export function datasetSnapshotShardManifestKey(version) {
  assertSafeVersionId(version);
  return `${DATASET_VERSIONS_DIR}/${version}/snapshot-shards-manifest.json`;
}

/** V6.8: content-addressed shard directory. The shard
 * key itself is built from the content hash; the
 * directory is the shared namespace across all
 * dataset-bound versions. */
export const DATASET_SHARDS_DIR = `${DATASET_DIR}/shards/sha256`;

/** V6.8: build the content-addressed shard key. The
 * hash IS the key; cross-version shard reuse is
 * allowed when the bucket content is identical. */
export function datasetShardKey(contentHash) {
  if (typeof contentHash !== 'string' || contentHash.length === 0) {
    throw new Error('publicIntelligenceStore: shard content hash must be a non-empty string');
  }
  if (!/^sha256:[0-9a-f]{64}$/.test(contentHash) && !/^[0-9a-f]{64}$/.test(contentHash)) {
    throw new Error('publicIntelligenceStore: shard content hash must be sha256:<64 hex> or <64 hex>');
  }
  const hash = contentHash.startsWith('sha256:')
    ? contentHash.slice('sha256:'.length)
    : contentHash;
  return `${DATASET_SHARDS_DIR}/${hash}.json.gz`;
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
 *
 * Hostinger filesystem mode:
 * When `THREATPULSE_STORAGE_BACKEND=filesystem` is set, the
 * returned handle is a `FilesystemStorageAdapter` rooted at
 * `$THREATPULSE_DATA_ROOT/tpr-public-intelligence`. The
 * adapter exposes the same `get` / `setJSON` / `setBinary`
 * / `list` / `delete` shape as the Netlify adapter, so every
 * downstream call site works unchanged. Writes use the
 * adapter's atomic temp+rename semantics, so a failed
 * publication leaves the previous `latest.json` and the
 * previous version directory intact.
 *
 * The Netlify path is preserved unchanged: when the env
 * variable is unset or has any value other than 'filesystem',
 * the function falls back to `getStore` from `@netlify/blobs`.
 */
export function getPublicIntelligenceStore(opts = {}) {
  const consistency = opts.consistency ?? 'strong';
  const env = opts.env || (typeof process !== 'undefined' && process.env) || {};
  const backend = (opts.backend || env.THREATPULSE_STORAGE_BACKEND || 'netlify').toLowerCase();
  if (backend === 'filesystem') {
    const dataRoot = opts.dataRoot || env.THREATPULSE_DATA_ROOT;
    if (!dataRoot) {
      throw new Error('getPublicIntelligenceStore: THREATPULSE_STORAGE_BACKEND=filesystem requires THREATPULSE_DATA_ROOT');
    }
    return createStorageAdapter({
      name: 'filesystem',
      storeName: PUBLIC_INTELLIGENCE_STORE_NAME,
      opts: { dataRoot },
    });
  }
  // Netlify path. The `getStore` helper from
  // `@netlify/blobs` throws a `MissingBlobsEnvironmentError`
  // when the Netlify runtime is absent (e.g. on a
  // workstation or a Hostinger deployment). The portable
  // `NetlifyBlobsStorageAdapter` exposes the same
  // get/set/list surface but is constructed without a
  // Netlify runtime; it works on a Hostinger deployment
  // because it routes through the V6.2 storage adapter
  // contract.
  return createStorageAdapter({
    name: 'netlify',
    storeName: PUBLIC_INTELLIGENCE_STORE_NAME,
    opts: { consistency },
  });
}

/**
 * Read a JSON value from the public-intelligence store. Returns
 * null when the key is missing or the value is malformed.
 * Defensive try/catch — a Blobs read error is treated as "missing"
 * so the publisher can recover.
 */
export async function readJson(store, key) {
  if (!store) return null;
  try {
    const v = await store.get(key, { type: 'json' });
    return v ?? null;
  } catch {
    return null;
  }
}

/**
 * Write a JSON value to the public-intelligence store. Silent
 * on Blobs write errors so a transient Blobs outage does not
 * block the publication path.
 */
export async function writeJson(store, key, value) {
  if (!store) return false;
  try {
    await store.setJSON(key, value);
    return true;
  } catch {
    return false;
  }
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
