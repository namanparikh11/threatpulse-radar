/**
 * V6.0 — Canonical bucket merge.
 *
 * The canonical baseline is partitioned into buckets (256 per entity
 * type, by the first 2 hex chars of sha256(canonicalId)). On an
 * incremental run, only the buckets affected by changed canonical
 * IDs need to be rewritten; the rest are reused as-is.
 *
 * This module owns the per-bucket merge logic. Given:
 *   - the previous bucket's entity list (read from the previous shard)
 *   - the canonicalIds being changed in this run
 *   - the new entities to upsert
 *   - the canonicalIds to remove
 *
 * produce the new bucket's entity list. The bucket is then hashed,
 * gzipped, and written under a content-addressed key.
 *
 * Determinism:
 *   The returned list is sorted by canonicalId (lexicographic) so the
 *   canonical content hash is stable across runs that produce the same
 *   logical set. The shard helper (describeShard) re-sorts as a
 *   safety net, but pre-sorting here keeps the logic local.
 *
 * Empty-bucket policy:
 *   When the merge produces a bucket with zero entities, the caller
 *   MUST NOT write a shard. The V6.0 design says "do not write empty
 *   shards" — the bucket just doesn't appear in the new manifest.
 *   `isEmptyBucket()` is the helper for this check.
 */

/**
 * Apply a set of upserts and removes to a previous bucket's entity
 * list. Returns the merged list, sorted by canonicalId.
 *
 * @param {Array} prevEntities - previous bucket's entities
 * @param {Object} changes - { upserts: Array, removes: Array<string> }
 * @returns {Array} merged, sorted, deduplicated
 */
export function applyChangesToBucket(prevEntities, { upserts = [], removes = [] } = {}) {
  if (!Array.isArray(prevEntities)) prevEntities = [];
  if (!Array.isArray(upserts)) upserts = [];
  if (!Array.isArray(removes)) removes = [];

  const removeSet = new Set(removes.filter((id) => typeof id === 'string'));
  const upsertMap = new Map();
  for (const e of upserts) {
    if (!e || typeof e.canonicalId !== 'string') continue;
    upsertMap.set(e.canonicalId, e);
  }

  const merged = [];
  for (const e of prevEntities) {
    if (!e || typeof e.canonicalId !== 'string') continue;
    if (removeSet.has(e.canonicalId)) continue;
    if (upsertMap.has(e.canonicalId)) continue; // replaced below
    merged.push(e);
  }
  for (const e of upsertMap.values()) {
    merged.push(e);
  }
  merged.sort((a, b) => (a.canonicalId < b.canonicalId ? -1 : a.canonicalId > b.canonicalId ? 1 : 0));
  return merged;
}

/**
 * Build a "delta" of canonicalIds between two bucket snapshots.
 * Returns `{ added, removed, modified }` where:
 *   - added:    canonicalIds in `next` not in `prev`
 *   - removed:  canonicalIds in `prev` not in `next`
 *   - modified: canonicalIds in both, but with different content
 *               (compared by canonical content hash)
 *
 * The content-hash comparison is what makes this incremental —
 * unchanged records (same canonical hash) are NOT modified.
 */
export function diffBuckets(prevEntities, nextEntities, hashFn) {
  if (typeof hashFn !== 'function') {
    throw new Error('diffBuckets: hashFn is required');
  }
  const prevMap = new Map();
  for (const e of (Array.isArray(prevEntities) ? prevEntities : [])) {
    if (e && typeof e.canonicalId === 'string') {
      prevMap.set(e.canonicalId, hashFn(e));
    }
  }
  const nextMap = new Map();
  for (const e of (Array.isArray(nextEntities) ? nextEntities : [])) {
    if (e && typeof e.canonicalId === 'string') {
      nextMap.set(e.canonicalId, hashFn(e));
    }
  }
  const added = [];
  const removed = [];
  const modified = [];
  for (const [id, h] of nextMap) {
    if (!prevMap.has(id)) added.push(id);
    else if (prevMap.get(id) !== h) modified.push(id);
  }
  for (const [id] of prevMap) {
    if (!nextMap.has(id)) removed.push(id);
  }
  added.sort();
  removed.sort();
  modified.sort();
  return { added, removed, modified };
}

/**
 * Build the per-bucket upsert/remove plan from a list of "this run's
 * changes" canonicalIds. The plan maps (entityType, bucket) →
 * { upserts: Array, removes: Array }.
 *
 * Input:
 *   - changesByCanonicalId: Map<canonicalId, { entityType, entity }>
 *                           where the canonicalId was upserted this run
 *   - removedCanonicalIds:  Array<{ canonicalId, entityType }>
 *                           for canonicalIds that disappeared
 *   - bucketFor:            function(canonicalId) → 2-char hex
 *
 * Output: Map<string, { entityType, bucket, upserts, removes }>
 *         keyed by "entityType:bucket"
 */
export function planBucketUpdates({ changesByCanonicalId, removedCanonicalIds, bucketFor }) {
  if (typeof bucketFor !== 'function') {
    throw new Error('planBucketUpdates: bucketFor is required');
  }
  const plan = new Map();
  if (changesByCanonicalId && typeof changesByCanonicalId.forEach === 'function') {
    changesByCanonicalId.forEach((entry, id) => {
      if (!entry || !entry.entityType || !entry.entity) return;
      const bucket = bucketFor(id);
      const key = `${entry.entityType}:${bucket}`;
      if (!plan.has(key)) plan.set(key, { entityType: entry.entityType, bucket, upserts: [], removes: [] });
      plan.get(key).upserts.push(entry.entity);
    });
  }
  if (Array.isArray(removedCanonicalIds)) {
    for (const r of removedCanonicalIds) {
      if (!r || typeof r.canonicalId !== 'string' || typeof r.entityType !== 'string') continue;
      const bucket = bucketFor(r.canonicalId);
      const key = `${r.entityType}:${bucket}`;
      if (!plan.has(key)) plan.set(key, { entityType: r.entityType, bucket, upserts: [], removes: [] });
      plan.get(key).removes.push(r.canonicalId);
    }
  }
  return plan;
}

/**
 * Empty-bucket test. The V6.0 amendment says "do not write empty
 * shards" — when a merge produces a bucket with zero entities, the
 * bucket is omitted from the new manifest.
 */
export function isEmptyBucket(entities) {
  return !Array.isArray(entities) || entities.length === 0;
}
