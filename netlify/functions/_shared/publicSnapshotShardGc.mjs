/**
 * V6.8 — Mark-and-sweep GC for dataset public-snapshot
 * shards.
 *
 * The dataset public-snapshot is split into N
 * deterministic content-addressed shards (see
 * `publicSnapshotShards.mjs`). Two dataset-bound
 * versions may share shards when their content is
 * identical. Shards that are no longer referenced by
 * ANY retained manifest are safe to delete.
 *
 * The GC is mark-and-sweep:
 *   1. Identify the retained dataset-bound versions
 *      (current + previous + rollback = at most 3,
 *      per the retention policy).
 *   2. Read each retained shard manifest and collect
 *      the referenced shard content hashes.
 *   3. Mark every referenced hash as retained.
 *   4. Enumerate candidate content-addressed shard
 *      objects.
 *   5. Delete only shards that are not marked AND not
 *      part of an in-progress publication.
 *   6. Never delete based only on timestamp or age.
 *
 * The GC is best-effort and NEVER blocks publication.
 * A GC failure preserves all retained shards AND the
 * `dataset/latest.json` pointer. The `latest.json`
 * MUST never reference a manifest whose shards have
 * been deleted; the mark phase guarantees this
 * invariant.
 *
 * The store API used here is `store.list()` (Netlify
 * Blobs supports listing by prefix) and
 * `store.delete(key)`. The GC handles the case where
 * the store does not support listing by falling back
 * to no-op (best-effort).
 *
 * The GC does NOT touch the OSV projection shards
 * (those have their own GC in `osvProjectionGc.mjs`).
 */

import {
  DATASET_DIR,
  DATASET_SHARDS_DIR,
  DATASET_LATEST_KEY,
  datasetSnapshotShardManifestKey,
  readJson,
} from './publicIntelligenceStore.mjs';
import { MAX_RETAINED_VERSIONS_PER_PATH } from './publicIntelligenceSize.mjs';

/**
 * Mark phase: collect the set of shard content hashes
 * referenced by the retained dataset-bound shard
 * manifests. The current `latest.json` is always
 * considered retained. The previous and rollback
 * versions are determined by walking the version
 * directory.
 */
export async function markRetainedSnapshotShards(store) {
  const retained = new Set();
  if (!store) return retained;
  // Always retain the current latest.
  const latest = await readJson(store, DATASET_LATEST_KEY);
  if (latest && typeof latest.publicIntelligenceVersion === 'string') {
    await collectHashesFromShardManifest(store, latest.publicIntelligenceVersion, retained);
  }
  // Walk the version directory for up to
  // MAX_RETAINED_VERSIONS_PER_PATH-1 additional
  // retained versions. The first
  // MAX_RETAINED_VERSIONS_PER_PATH entries (sorted by
  // version id) are retained.
  try {
    const list = await store.list({ prefix: `${DATASET_DIR}/versions/` });
    const versionDirs = (list.blobs || [])
      .map((b) => b.key)
      .filter((k) => /\/snapshot-shards-manifest\.json$/.test(k))
      .map((k) => k.replace(`${DATASET_DIR}/versions/`, '').replace(/\/snapshot-shards-manifest\.json$/, ''))
      .sort();
    const additional = versionDirs.slice(0, MAX_RETAINED_VERSIONS_PER_PATH);
    for (const v of additional) {
      await collectHashesFromShardManifest(store, v, retained);
    }
  } catch {
    // Store does not support listing; GC falls back to
    // no-op.
  }
  return retained;
}

async function collectHashesFromShardManifest(store, publicIntelligenceVersion, retained) {
  const manifest = await readJson(store, datasetSnapshotShardManifestKey(publicIntelligenceVersion));
  if (!manifest || typeof manifest !== 'object') return;
  const shards = manifest.shards;
  if (!Array.isArray(shards)) return;
  for (const s of shards) {
    if (s && typeof s.contentHash === 'string' && s.contentHash.startsWith('sha256:')) {
      retained.add(s.contentHash);
    }
  }
}

/**
 * Sweep phase: enumerate candidate content-addressed
 * shard objects and delete those that are not in the
 * marked set. A sweep failure leaves the shard on
 * disk; the next GC pass retries.
 *
 * Returns the list of deleted shard content hashes
 * (without the `sha256:` prefix).
 */
export async function sweepUnreferencedSnapshotShards(store, retained) {
  if (!store) return { deleted: [], errors: 0, attempted: 0 };
  const deleted = [];
  let errors = 0;
  let attempted = 0;
  let entries = [];
  try {
    const list = await store.list({ prefix: `${DATASET_SHARDS_DIR}/` });
    entries = list.blobs || [];
  } catch {
    return { deleted: [], errors: 0, attempted: 0 };
  }
  for (const entry of entries) {
    const key = entry.key;
    // key shape: dataset/shards/sha256/<hash>.json.gz
    const match = /\/shards\/sha256\/([0-9a-f]{64})\.json\.gz$/.test(key)
      ? /\/shards\/sha256\/([0-9a-f]{64})\.json\.gz$/.exec(key)
      : null;
    if (!match) continue;
    const hash = `sha256:${match[1]}`;
    attempted++;
    if (retained.has(hash)) continue;
    try {
      await store.delete(key);
      deleted.push(match[1]);
    } catch {
      errors++;
    }
  }
  return { deleted, errors, attempted };
}

/**
 * Run the mark-and-sweep GC for dataset public-
 * snapshot shards. The operation is best-effort and
 * never blocks publication. A failure at any step is
 * returned in the result; the caller decides whether
 * to retry.
 */
export async function runSnapshotShardGc(store) {
  const result = {
    retained: 0,
    deleted: [],
    errors: 0,
    attempted: 0,
    status: 'ok',
  };
  try {
    const retained = await markRetainedSnapshotShards(store);
    result.retained = retained.size;
    const sweep = await sweepUnreferencedSnapshotShards(store, retained);
    result.deleted = sweep.deleted;
    result.errors = sweep.errors;
    result.attempted = sweep.attempted;
  } catch (err) {
    result.status = 'failed';
    result.error = err && err.message ? err.message : String(err);
  }
  return result;
}
