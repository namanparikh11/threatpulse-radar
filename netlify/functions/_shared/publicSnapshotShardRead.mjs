/**
 * V6.8 — Dataset public-snapshot shard read path.
 *
 * Reads a per-version shard manifest and all
 * referenced shards from the public-intelligence
 * store, verifies every shard against the manifest,
 * and reassembles the logical public snapshot.
 *
 * The reassembled snapshot is byte-identical to the
 * original logical snapshot that the publisher built
 * (verified by the manifest's
 * `logicalSnapshotContentHash`).
 *
 * Read path contract:
 *   - Missing shard manifest returns `null` (the
 *     caller treats this as a structured "unavailable"
 *     state).
 *   - Missing shard returns a structured failure with
 *     `reason: 'missing-shard'` (the caller treats
 *     this as a 503 with a sanitized error code).
 *   - Corrupt shard hash returns a structured failure
 *     with `reason: 'corrupt-shard'` (the caller
 *     treats this as a 503 with a sanitized error
 *     code).
 *   - Mismatched logical content hash returns a
 *     structured failure with
 *     `reason: 'logical-hash-mismatch'` (corruption
 *     or storage-level bug).
 *   - Reordered shard descriptors are rejected by
 *     `verifySnapshotShardManifest` (the manifest
 *     carries explicit index fields).
 *
 * The function NEVER throws on a structured failure;
 * it always returns a structured result.
 *
 * The function NEVER mutates the store; it is a
 * read-only operation.
 */

import {
  DATASET_LATEST_KEY,
  datasetShardKey,
  datasetSnapshotShardManifestKey,
  readJson,
} from './publicIntelligenceStore.mjs';
import {
  verifySnapshotShardManifest,
  reassembleSnapshotFromShards,
} from './publicSnapshotShards.mjs';
import { gunzipValue } from './publicIntelligenceCompression.mjs';

/**
 * Read the per-version shard manifest. Returns
 * `null` when missing or malformed. Pure-ish (reads
 * from the store).
 */
export async function readSnapshotShardManifest(store, publicIntelligenceVersion) {
  if (!store) return null;
  if (typeof publicIntelligenceVersion !== 'string' || !publicIntelligenceVersion) return null;
  return readJson(store, datasetSnapshotShardManifestKey(publicIntelligenceVersion));
}

/**
 * Read a single shard body. Returns:
 *   - the parsed shard body on success
 *   - `null` when the shard is missing
 *   - `{ error: 'corrupt-shard', contentHash, error: '...' }`
 *     on parse error or hash mismatch
 *
 * The function NEVER throws.
 */
export async function readSnapshotShardBody(store, contentHash) {
  if (!store) return null;
  if (typeof contentHash !== 'string' || !contentHash.startsWith('sha256:')) {
    return { error: 'invalid-content-hash', contentHash };
  }
  const key = datasetShardKey(contentHash);
  let raw;
  try {
    raw = await store.get(key, { type: 'arrayBuffer' });
  } catch (err) {
    return { error: 'shard-read-failed', contentHash, error: err && err.message ? err.message : String(err) };
  }
  if (!raw) return null;
  let body;
  try {
    body = gunzipValue(raw);
  } catch (err) {
    return { error: 'corrupt-shard', contentHash, error: err && err.message ? err.message : String(err) };
  }
  if (!body || typeof body !== 'object') {
    return { error: 'corrupt-shard', contentHash, error: 'shard body is not an object' };
  }
  return body;
}

/**
 * Read and reassemble the logical public snapshot for
 * the given dataset-bound version. Returns:
 *   - `{ ok: true, snapshot, manifest, shardCount }`
 *     on success
 *   - `{ ok: false, reason: 'missing-manifest' }` when
 *     no shard manifest is present for the version
 *   - `{ ok: false, reason: 'manifest-invalid' }` when
 *     the manifest fails structural verification
 *   - `{ ok: false, reason: 'missing-shard', shard,
 *     contentHash }` when a referenced shard is not
 *     present
 *   - `{ ok: false, reason: 'corrupt-shard', shard,
 *     contentHash, error }` when a shard's bytes do
 *     not match its declared hash
 *   - `{ ok: false, reason: 'logical-hash-mismatch' }`
 *     when the reassembled logical snapshot's
 *     canonical content hash does not match the
 *     manifest's declared hash
 *   - `{ ok: false, reason: 'shard-read-failed', shard,
 *     contentHash, error }` on a transient read error
 *
 * The function NEVER throws.
 */
export async function readReassembledSnapshot(store, publicIntelligenceVersion) {
  if (!store) return { ok: false, reason: 'store-missing' };
  if (typeof publicIntelligenceVersion !== 'string' || !publicIntelligenceVersion) {
    return { ok: false, reason: 'invalid-version' };
  }
  const manifest = await readSnapshotShardManifest(store, publicIntelligenceVersion);
  if (!manifest) return { ok: false, reason: 'missing-manifest' };
  try {
    verifySnapshotShardManifest(manifest);
  } catch (err) {
    return { ok: false, reason: 'manifest-invalid', error: err && err.message ? err.message : String(err) };
  }
  // Read every shard in manifest order.
  const shardBodies = [];
  for (let i = 0; i < manifest.shards.length; i++) {
    const desc = manifest.shards[i];
    const body = await readSnapshotShardBody(store, desc.contentHash);
    if (body === null) {
      return { ok: false, reason: 'missing-shard', shard: i, contentHash: desc.contentHash };
    }
    if (body && body.error === 'corrupt-shard') {
      return { ok: false, reason: 'corrupt-shard', shard: i, contentHash: desc.contentHash, error: body.error };
    }
    if (body && body.error === 'shard-read-failed') {
      return { ok: false, reason: 'shard-read-failed', shard: i, contentHash: desc.contentHash, error: body.error };
    }
    if (body && body.error === 'invalid-content-hash') {
      return { ok: false, reason: 'corrupt-shard', shard: i, contentHash: desc.contentHash, error: 'invalid-content-hash' };
    }
    shardBodies.push(body);
  }
  try {
    const snapshot = reassembleSnapshotFromShards(manifest, shardBodies);
    return { ok: true, snapshot, manifest, shardCount: manifest.shards.length };
  } catch (err) {
    return { ok: false, reason: 'logical-hash-mismatch', error: err && err.message ? err.message : String(err) };
  }
}

/**
 * Read the current dataset-bound latest.json pointer.
 * Returns `null` when missing. Convenience helper for
 * callers that want the latest publicIntelligenceVersion
 * and the latest's content hashes.
 */
export async function readCurrentDatasetLatest(store) {
  if (!store) return null;
  return readJson(store, DATASET_LATEST_KEY);
}
