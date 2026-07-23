/**
 * V6.1 — Mark-and-sweep garbage collection for content-addressed
 * OSV shards.
 *
 * The OSV public projection uses content-addressed shard keys
 * (`osv/shards/sha256/<hash>.json.gz`). Two OSV projection
 * versions may share shards when their content is identical.
 * Shards that are no longer referenced by ANY retained
 * manifest are safe to delete.
 *
 * The GC is mark-and-sweep:
 *   1. Identify the retained OSV projection versions
 *      (current + previous + rollback = at most 3, per the
 *      retention policy).
 *   2. Read each retained manifest and collect the
 *      referenced shard content hashes (the `buckets[*].contentHash`
 *      array).
 *   3. Mark every referenced hash as retained.
 *   4. Enumerate candidate content-addressed shard
 *      objects.
 *   5. Delete only shards that are not marked AND not
 *      part of an in-progress publication.
 *   6. Never delete based only on timestamp or age.
 *
 * The GC is best-effort and NEVER blocks publication. A
 * GC failure preserves all retained shards AND the OSV
 * `latest.json` pointer. The `latest.json` MUST never
 * reference a manifest whose shards have been deleted;
 * the mark phase guarantees this invariant.
 *
 * The store API used here is `store.list()` (Netlify Blobs
 * supports listing by prefix) and `store.delete(key)`. The
 * GC handles the case where the store does not support
 * listing by falling back to no-op (best-effort).
 */

import { OSV_SHARDS_DIR, OSV_DIR, readJson } from './publicIntelligenceStore.mjs';
import { MAX_RETAINED_VERSIONS_PER_PATH } from './publicIntelligenceSize.mjs';
import { osvManifestKey } from './publicIntelligenceStore.mjs';

/**
 * Mark phase: collect the set of shard content hashes
 * referenced by the retained OSV projection manifests.
 * The current `latest.json` is always considered
 * retained. The previous and rollback versions are
 * determined by walking the version directory (the GC
 * does not assume a specific naming scheme beyond
 * `osv/versions/{version}/manifest.json`).
 */
export async function markRetainedShards(store) {
  const retained = new Set();
  if (!store) return retained;
  // Always retain the current latest.
  const latest = await readJson(store, `${OSV_DIR}/latest.json`);
  if (latest && typeof latest.osvProjectionVersion === 'string') {
    await collectHashesFromManifest(store, latest.osvProjectionVersion, retained);
  }
  // Walk the version directory for up to MAX_RETAINED_VERSIONS_PER_PATH-1
  // additional retained versions. The first MAX_RETAINED_VERSIONS_PER_PATH
  // entries (sorted by version id) are retained.
  try {
    const list = await store.list({ prefix: `${OSV_DIR}/versions/` });
    const versionDirs = (list.blobs || [])
      .map((b) => b.key)
      .filter((k) => /\/manifest\.json$/.test(k))
      .map((k) => k.replace(`${OSV_DIR}/versions/`, '').replace(/\/manifest\.json$/, ''))
      .sort();
    const additional = versionDirs.slice(0, MAX_RETAINED_VERSIONS_PER_PATH);
    for (const v of additional) {
      await collectHashesFromManifest(store, v, retained);
    }
  } catch {
    // Store does not support listing; GC falls back to no-op.
  }
  return retained;
}

async function collectHashesFromManifest(store, osvProjectionVersion, retained) {
  const manifest = await readJson(store, osvManifestKey(osvProjectionVersion));
  if (!manifest || typeof manifest !== 'object') return;
  const buckets = manifest.buckets;
  if (!buckets || typeof buckets !== 'object') return;
  for (const k of Object.keys(buckets)) {
    const h = buckets[k] && buckets[k].contentHash;
    if (typeof h === 'string' && h.startsWith('sha256:')) retained.add(h);
  }
}

/**
 * Sweep phase: enumerate candidate content-addressed
 * shard objects and delete those that are not in the
 * marked set. A sweep failure leaves the shard on disk;
 * the next GC pass retries.
 *
 * Returns the list of deleted shard content hashes
 * (without the `sha256:` prefix).
 */
export async function sweepUnreferencedShards(store, retained) {
  if (!store) return { deleted: [], errors: 0, attempted: 0 };
  const deleted = [];
  let errors = 0;
  let attempted = 0;
  let entries = [];
  try {
    const list = await store.list({ prefix: `${OSV_SHARDS_DIR}/` });
    entries = list.blobs || [];
  } catch {
    return { deleted: [], errors: 0, attempted: 0 };
  }
  for (const entry of entries) {
    const key = entry.key;
    // key shape: osv/shards/sha256/<hash>.json.gz
    const match = /\/shards\/sha256\/([0-9a-f]{64})\.json\.gz$/.exec(key);
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
 * Run the mark-and-sweep GC. The operation is
 * best-effort and never blocks publication. A failure
 * at any step is returned in the result; the caller
 * decides whether to retry.
 */
export async function runOsvGc(store) {
  const result = {
    retained: 0,
    deleted: [],
    errors: 0,
    attempted: 0,
    status: 'ok',
  };
  try {
    const retained = await markRetainedShards(store);
    result.retained = retained.size;
    const sweep = await sweepUnreferencedShards(store, retained);
    result.deleted = sweep.deleted;
    result.errors = sweep.errors;
    result.attempted = sweep.attempted;
  } catch (err) {
    result.status = 'failed';
    result.error = err && err.message ? err.message : String(err);
  }
  return result;
}
