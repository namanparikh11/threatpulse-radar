/**
 * V6.0 — Content-addressed shard helpers.
 *
 * Per the V6.0 amendment, shard objects are immutable and content-addressed:
 *
 *   objects/sha256/<full-content-hash>.json.gz
 *
 * The bucket is a deterministic 2-char hex prefix of
 * sha256(canonicalId), so a consumer can predict the bucket for any
 * canonicalId without consulting the manifest. The manifest maps
 * (entityType, bucket) → (objectKey, sha256, byteSize, recordCount).
 *
 * When a bucket's content is unchanged, the existing object key is
 * referenced; no rewrite. This is the deduplication mechanism that makes
 * the incremental baseline efficient.
 */

import { createHash } from 'node:crypto';
import { canonicalize, sha256Hex } from './canonicalHash.mjs';

/** Number of shards per entity type. 256 buckets (2 hex chars). */
export const SHARD_BUCKETS = 256;

/**
 * Compute the deterministic bucket for a canonicalId. The bucket is the
 * first 2 hex characters of sha256(canonicalId).
 */
export function bucketFor(canonicalId) {
  if (typeof canonicalId !== 'string' || canonicalId.length === 0) {
    throw new Error('bucketFor: canonicalId is required');
  }
  return sha256Hex(canonicalId).slice(0, 2);
}

/**
 * Compute the immutable object key for a content hash. The key encodes
 * the hash directly so identical content always maps to the same key.
 */
export function objectKeyFor(contentHashValue) {
  if (typeof contentHashValue !== 'string' || !contentHashValue.startsWith('sha256:')) {
    throw new Error('objectKeyFor: expected sha256:<hex>');
  }
  return `objects/sha256/${contentHashValue.slice('sha256:'.length)}.json.gz`;
}

/**
 * Sort a list of entities into their deterministic buckets, returning a
 * map from bucket → array of entities (sorted by canonicalId within
 * the bucket, ready to serialize).
 */
export function partitionByBucket(entities) {
  const buckets = new Map();
  for (const e of entities) {
    if (!e || typeof e.canonicalId !== 'string') continue;
    const b = bucketFor(e.canonicalId);
    if (!buckets.has(b)) buckets.set(b, []);
    buckets.get(b).push(e);
  }
  for (const arr of buckets.values()) {
    arr.sort((a, b) => (a.canonicalId < b.canonicalId ? -1 : a.canonicalId > b.canonicalId ? 1 : 0));
  }
  return buckets;
}

/**
 * Compute the shard descriptor for a single bucket. Returns
 * `{ entityType, bucket, objectKey, sha256, byteSize, recordCount }`
 * where `byteSize` is the size of the GZIPPED bytes that will be
 * written to the blob, `sha256` is the hash of the canonical (un-gzipped)
 * JSON bytes, and `recordCount` is the number of entities in the shard.
 */
export async function describeShard(entityType, bucket, entities, gzipFn) {
  const canonical = canonicalize(entities);
  const canonicalStr = JSON.stringify(canonical);
  const canonicalBytes = Buffer.from(canonicalStr, 'utf8');
  const sha = `sha256:${createHash('sha256').update(canonicalBytes).digest('hex')}`;
  const gzipped = await gzipFn(canonicalBytes);
  return {
    entityType,
    bucket,
    objectKey: objectKeyFor(sha),
    sha256: sha,
    byteSize: gzipped.length,
    recordCount: entities.length,
  };
}
