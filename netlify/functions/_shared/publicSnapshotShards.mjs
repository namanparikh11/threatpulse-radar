/**
 * V6.8 — Dataset public-snapshot deterministic sharding.
 *
 * The dataset public-comparison snapshot is built from
 * the full per-CVE observation map of the public
 * dataset envelope. Production CISA KEV universe sizes
 * (~1,200 CVEs) produce a snapshot of ~1.1 MB
 * uncompressed, which exceeds the existing 1 MiB
 * per-object safety ceiling
 * (`PUBLIC_SNAPSHOT_HARD_CEILING_UNCOMPRESSED_BYTES`).
 *
 * The 1 MiB safety ceiling is preserved unchanged.
 * The fix is storage-side: the logical snapshot is
 * partitioned into N deterministic content-addressed
 * shards, each safely below the per-object ceiling, and
 * a small per-version manifest references them. The
 * reader reassembles the logical snapshot from the
 * manifest + shards before returning the existing
 * public response contract.
 *
 * Invariants (intentional, all must hold for the
 * patch to be acceptable):
 *
 *   - PUBLIC_SNAPSHOT_HARD_CEILING_UNCOMPRESSED_BYTES
 *     is unchanged (1 MiB per-object safety ceiling).
 *   - No field of the per-CVE record is silently
 *     truncated. The partitioner moves WHOLE records
 *     between shards; a single CVE's record is never
 *     split across shards.
 *   - Shard boundaries are DETERMINISTIC. The same
 *     input snapshot always produces the same shard
 *     layout, the same shard content hashes, and the
 *     same manifest content.
 *   - The composite publicStateHash is computed from
 *     the four precomputed per-Blob hashes (already
 *     stable across shard-boundary changes — see
 *     `publicIntelligenceHash.mjs`#computePublicStateHash).
 *     Shard-boundary changes therefore CANNOT change
 *     the logical fingerprint of the public state.
 *   - The shard manifest is well under the dataset
 *     manifest hard ceiling (16 KiB) so it can always
 *     be written atomically.
 *   - Every shard is content-addressed; shards with
 *     identical content reuse the same key. Cross-
 *     version shard reuse is allowed.
 *   - Atomicity: `dataset/latest.json` is the only
 *     mutable commit point. On a shard-write or
 *     manifest-write failure, the previous
 *     `dataset/latest.json` remains valid.
 *   - The previous `latest.json` is preserved byte-
 *     identical on any structured failure.
 *   - No shard is exposed as an arbitrary static asset;
 *     shards are private to the public-intelligence
 *     store.
 *   - Object names reject traversal; the shard key
 *     helper validates the input and throws on
 *     invalid characters.
 *
 * The functions in this module are pure (no I/O).
 * Persistence is handled by the publisher
 * (`datasetBoundPublish.mjs`) and the GC
 * (`publicSnapshotShardGc.mjs`).
 */

import {
  canonicalizeToString,
  contentHash,
  sha256Hex,
  canonicalByteLength,
} from './canonicalHash.mjs';
import {
  PUBLIC_SNAPSHOT_HARD_CEILING_UNCOMPRESSED_BYTES,
  SNAPSHOT_SHARD_TARGET_UNCOMPRESSED_BYTES,
  SNAPSHOT_SHARD_HARD_CEILING_UNCOMPRESSED_BYTES,
  SNAPSHOT_SHARD_HARD_CEILING_COMPRESSED_BYTES,
  SNAPSHOT_SHARD_MIN_CVES_PER_SHARD,
  SizeCeilingExceededError,
} from './publicIntelligenceSize.mjs';

/* ---- Shard manifest schema ---- */

export const SNAPSHOT_SHARD_MANIFEST_SCHEMA_VERSION = '1.0.0';

/* ---- Helpers ---- */

/**
 * Return a sorted, deterministic array of CVE ids from
 * the snapshot's `byCve` map. The order is the canonical
 * iteration order used by the partitioner; both the
 * publisher and the reader must use the same order.
 */
export function sortedCveIds(snapshot) {
  if (!snapshot || !snapshot.byCve || typeof snapshot.byCve !== 'object') return [];
  return Object.keys(snapshot.byCve).sort();
}

/**
 * Compute the canonical byte length of a single shard
 * body. The shard body shape is the on-disk shape
 * (see `buildSnapshotShard`). The size is computed on
 * the canonical (sorted-keys) form so the size check
 * is stable across runtimes.
 */
export function shardBodyUncompressedBytes(shardBody) {
  return canonicalByteLength(shardBody);
}

/**
 * Build a single shard body. The body is the on-disk
 * shape: a top-level object with `schemaVersion`,
 * `publicIntelligenceVersion`, `index`, `cveCount`,
 * `cveIds` (sorted), and `byCve` (the per-CVE records
 * for this shard).
 *
 * `cveIds` is the sorted, deterministic list of CVEs in
 * this shard. `byCve` is the corresponding subset of
 * `snapshot.byCve`.
 */
export function buildSnapshotShard(snapshot, cveIds, index, publicIntelligenceVersion) {
  if (!Array.isArray(cveIds) || cveIds.length === 0) {
    throw new Error('buildSnapshotShard: cveIds must be a non-empty array');
  }
  const byCve = {};
  for (const cve of cveIds) {
    const rec = snapshot.byCve[cve];
    if (rec) byCve[cve] = rec;
  }
  return {
    schemaVersion: SNAPSHOT_SHARD_MANIFEST_SCHEMA_VERSION,
    publicIntelligenceVersion: publicIntelligenceVersion || (snapshot && snapshot.publicIntelligenceVersion) || '',
    index,
    cveCount: cveIds.length,
    cveIds: [...cveIds],
    byCve,
  };
}

/**
 * Compute the content hash of a shard body. The hash
 * is the canonical SHA-256 of the shard body. This is
 * the content-addressed key component.
 */
export function shardContentHash(shardBody) {
  return `sha256:${sha256Hex(canonicalizeToString(shardBody))}`;
}

/**
 * Compute the target boundary at which to start a new
 * shard. The boundary is in UNCOMPRESSED bytes.
 *
 * Strategy: walk the sorted CVE list in order, accumulate
 * a running "estimated shard size" using the canonical
 * byte length of the shard body after adding the next
 * CVE. The first CVE that pushes the running size past
 * `targetBytes` triggers a boundary — UNLESS adding the
 * CVE would leave the current shard with fewer than
 * `minCvesPerShard` CVEs (in which case the CVE is
 * added to the current shard even if it overshoots the
 * target, provided the result still fits the hard
 * ceiling).
 *
 * If a single CVE's record alone exceeds the hard
 * ceiling, the partitioner throws
 * `SizeCeilingExceededError`. A single record is never
 * split across shards; the publisher surfaces the
 * structured failure so the operator can investigate
 * the upstream data.
 *
 * @param {Object} snapshot - the public-snapshot value
 *   produced by `buildPublicSnapshot`. Must have a
 *   `.byCve` map.
 * @param {Object} [opts]
 * @param {number} [opts.targetBytes] - target bytes
 *   per shard (default: SNAPSHOT_SHARD_TARGET_UNCOMPRESSED_BYTES).
 * @param {number} [opts.hardCeilingBytes] - per-shard
 *   hard ceiling (default:
 *   SNAPSHOT_SHARD_HARD_CEILING_UNCOMPRESSED_BYTES).
 *   Must be strictly less than
 *   PUBLIC_SNAPSHOT_HARD_CEILING_UNCOMPRESSED_BYTES.
 * @param {number} [opts.minCvesPerShard] - minimum
 *   CVEs per shard (default:
 *   SNAPSHOT_SHARD_MIN_CVES_PER_SHARD). When a CVE
 *   would push the current shard past the target, the
 *   partitioner will keep adding CVEs until the shard
 *   reaches this minimum count, then start a new
 *   shard.
 * @returns {string[][]} - an array of sorted CVE-id
 *   arrays (one per shard). The outer array is
 *   deterministically ordered.
 */
export function partitionSnapshotForShards(snapshot, opts = {}) {
  if (!snapshot || !snapshot.byCve || typeof snapshot.byCve !== 'object') {
    // Empty or missing byCve: return an empty
    // partition. The publisher will write a shard
    // manifest with shardCount: 0 and an empty shards
    // array (no shard objects are written). The
    // logical snapshot is well under the per-object
    // safety ceiling in this degenerate case, but the
    // same sharded storage layout is used uniformly.
    return [];
  }
  const targetBytes = Number.isInteger(opts.targetBytes)
    ? opts.targetBytes
    : SNAPSHOT_SHARD_TARGET_UNCOMPRESSED_BYTES;
  const hardCeilingBytes = Number.isInteger(opts.hardCeilingBytes)
    ? opts.hardCeilingBytes
    : SNAPSHOT_SHARD_HARD_CEILING_UNCOMPRESSED_BYTES;
  const minCvesPerShard = Number.isInteger(opts.minCvesPerShard)
    ? opts.minCvesPerShard
    : SNAPSHOT_SHARD_MIN_CVES_PER_SHARD;
  if (hardCeilingBytes >= PUBLIC_SNAPSHOT_HARD_CEILING_UNCOMPRESSED_BYTES) {
    throw new Error('partitionSnapshotForShards: hardCeilingBytes must be strictly less than the per-object safety ceiling');
  }
  if (targetBytes <= 0 || hardCeilingBytes <= 0) {
    throw new Error('partitionSnapshotForShards: targetBytes and hardCeilingBytes must be positive');
  }
  if (minCvesPerShard < 1) {
    throw new Error('partitionSnapshotForShards: minCvesPerShard must be >= 1');
  }
  const cveIds = sortedCveIds(snapshot);
  if (cveIds.length === 0) return [];

  // First: detect any single CVE record that exceeds the
  // hard ceiling on its own. A single record is never
  // split across shards; the publisher surfaces a
  // structured failure when this happens.
  for (const cve of cveIds) {
    const singleRec = buildSnapshotShard(snapshot, [cve], 0, snapshot.publicIntelligenceVersion);
    const singleSize = shardBodyUncompressedBytes(singleRec);
    if (singleSize > hardCeilingBytes) {
      throw new SizeCeilingExceededError(
        `single-cve shard uncompressed size ${singleSize} exceeds per-shard ceiling ${hardCeilingBytes} (cve=${cve})`,
      );
    }
  }

  // Walk and partition.
  const shards = [];
  let current = [];
  // The precomputed body for the current shard. Kept in
  // sync with `current`; we only need its canonical byte
  // length to decide boundaries. We rebuild the body
  // when the boundary moves.
  let currentBody = null;
  for (const cve of cveIds) {
    const tentative = [...current, cve];
    const tentativeBody = buildSnapshotShard(snapshot, tentative, shards.length, snapshot.publicIntelligenceVersion);
    const tentativeSize = shardBodyUncompressedBytes(tentativeBody);
    if (current.length === 0) {
      // First CVE in a new shard. Always add.
      current = tentative;
      currentBody = tentativeBody;
      continue;
    }
    if (tentativeSize <= targetBytes) {
      // Under target — keep adding.
      current = tentative;
      currentBody = tentativeBody;
      continue;
    }
    // Would exceed the target. Decide:
    //   - if current shard has fewer than minCvesPerShard
    //     CVEs, keep adding even past the target (until
    //     the minimum is met or the hard ceiling is hit).
    //   - otherwise, start a new shard.
    if (current.length < minCvesPerShard) {
      if (tentativeSize <= hardCeilingBytes) {
        current = tentative;
        currentBody = tentativeBody;
        continue;
      }
      // Hard ceiling hit before the minimum is met.
      // The partitioner surfaces a structured failure.
      throw new SizeCeilingExceededError(
        `shard under construction would exceed per-shard ceiling ${hardCeilingBytes} ` +
        `before reaching the minimum CVE count ${minCvesPerShard} (current=${current.length}, ` +
        `adding ${cve} would push to ${tentativeSize})`,
      );
    }
    // Start a new shard. The current shard's body is
    // already known to fit. The new shard begins with
    // only the current CVE; the next iteration will
    // either add the next CVE (when still under
    // target) or start yet another new shard.
    shards.push(current);
    current = [cve];
    currentBody = tentativeBody;
  }
  if (current.length > 0) shards.push(current);
  return shards;
}

/**
 * Build the per-version shard manifest from the
 * partition. The manifest is the on-disk shape that
 * the reader reads to find the shards. It is well
 * under the dataset manifest hard ceiling.
 *
 * Manifest fields:
 *   - schemaVersion: SNAPSHOT_SHARD_MANIFEST_SCHEMA_VERSION
 *   - publicIntelligenceVersion: same as the logical
 *     snapshot's publicIntelligenceVersion
 *   - generatedAt: ISO timestamp of publication
 *   - publicStateHash: the composite logical hash; the
 *     reader uses this to verify the reassembled
 *     snapshot matches the served publicStateHash
 *   - shardCount: number of shards
 *   - trackedCveCount: logical tracked CVE count
 *   - logicalSnapshotContentHash: SHA-256 of the
 *     canonical LOGICAL snapshot. The reader computes
 *     the same hash from the reassembled snapshot and
 *     rejects the read on a mismatch. This is the
 *     canonical-fingerprint check; it is independent
 *     of the publicStateHash.
 *   - shards: array of `{ index, contentHash, cveCount,
 *     byteSize, compressedByteSize }` records. The order
 *     is the partition order (deterministic). The
 *     contentHash is content-addressed; the reader uses
 *     it to fetch the shard by key.
 *   - previousPublicIntelligenceVersion: preserved from
 *     the logical snapshot context for change-
 *     intelligence use; informational only.
 *   - providerComparability: the small per-provider
 *     comparability map from the logical snapshot.
 *     Carried in the manifest so the reader can
 *     reconstruct the full logical snapshot for the
 *     canonical-content-hash verification. The block
 *     is a few hundred bytes; the manifest stays well
 *     under the dataset manifest hard ceiling.
 */
export function buildSnapshotShardManifest({
  logicalSnapshot,
  shards, // array of shard bodies, in partition order
  shardContentHashes, // parallel to shards
  shardByteSizes, // parallel uncompressed byte sizes
  generatedAt,
  publicStateHash,
  previousPublicIntelligenceVersion = null,
} = {}) {
  if (!logicalSnapshot || typeof logicalSnapshot !== 'object') {
    throw new Error('buildSnapshotShardManifest: logicalSnapshot is required');
  }
  if (!Array.isArray(shards) || !Array.isArray(shardContentHashes) || !Array.isArray(shardByteSizes)) {
    throw new Error('buildSnapshotShardManifest: shards, shardContentHashes, shardByteSizes must be parallel arrays');
  }
  if (shards.length !== shardContentHashes.length || shards.length !== shardByteSizes.length) {
    throw new Error('buildSnapshotShardManifest: shards, shardContentHashes, shardByteSizes must have equal length');
  }
  if (typeof generatedAt !== 'string' || !generatedAt) {
    throw new Error('buildSnapshotShardManifest: generatedAt is required');
  }
  if (typeof publicStateHash !== 'string' || !publicStateHash.startsWith('sha256:')) {
    throw new Error('buildSnapshotShardManifest: publicStateHash (sha256:<hex>) is required');
  }
  const shardDescriptors = shards.map((body, i) => ({
    index: i,
    contentHash: shardContentHashes[i],
    cveCount: body.cveCount,
    byteSize: shardByteSizes[i],
  }));
  // Compute the canonical content hash of the LOGICAL
  // snapshot. This is the identity of the logical
  // content, independent of the storage partitioning.
  const logicalSnapshotContentHash = contentHash(logicalSnapshot);
  return {
    schemaVersion: SNAPSHOT_SHARD_MANIFEST_SCHEMA_VERSION,
    publicIntelligenceVersion: logicalSnapshot.publicIntelligenceVersion || '',
    generatedAt,
    publicStateHash,
    logicalSnapshotContentHash,
    trackedCveCount: logicalSnapshot.trackedCveCount || 0,
    shardCount: shards.length,
    shards: shardDescriptors,
    previousPublicIntelligenceVersion,
    providerComparability: logicalSnapshot.providerComparability || null,
  };
}

/**
 * Build the per-version shard manifest content hash.
 * The publisher uses this to write the atomic
 * `dataset/latest.json` pointer with a
 * `snapshotShardManifestContentHash` field; the
 * reader uses the same hash to verify the
 * manifest on read.
 */
export function snapshotShardManifestContentHash(manifest) {
  if (!manifest || typeof manifest !== 'object') return null;
  return contentHash(manifest);
}

/**
 * Verify a shard manifest's structural and hash
 * invariants. Throws on any failure. Used by the
 * reader before reassembling the logical snapshot.
 */
export function verifySnapshotShardManifest(manifest) {
  if (!manifest || typeof manifest !== 'object') {
    throw new Error('verifySnapshotShardManifest: manifest is required');
  }
  if (manifest.schemaVersion !== SNAPSHOT_SHARD_MANIFEST_SCHEMA_VERSION) {
    throw new Error(`verifySnapshotShardManifest: unexpected schemaVersion ${manifest.schemaVersion}`);
  }
  if (typeof manifest.publicIntelligenceVersion !== 'string' || !manifest.publicIntelligenceVersion) {
    throw new Error('verifySnapshotShardManifest: publicIntelligenceVersion is required');
  }
  if (typeof manifest.publicStateHash !== 'string' || !manifest.publicStateHash.startsWith('sha256:')) {
    throw new Error('verifySnapshotShardManifest: publicStateHash (sha256:<hex>) is required');
  }
  if (typeof manifest.logicalSnapshotContentHash !== 'string' || !manifest.logicalSnapshotContentHash.startsWith('sha256:')) {
    throw new Error('verifySnapshotShardManifest: logicalSnapshotContentHash (sha256:<hex>) is required');
  }
  if (!Number.isInteger(manifest.shardCount) || manifest.shardCount < 0) {
    throw new Error('verifySnapshotShardManifest: shardCount must be a non-negative integer');
  }
  if (!Array.isArray(manifest.shards) || manifest.shards.length !== manifest.shardCount) {
    throw new Error('verifySnapshotShardManifest: shards array length must equal shardCount');
  }
  let lastIndex = -1;
  for (let i = 0; i < manifest.shards.length; i++) {
    const s = manifest.shards[i];
    if (!s || typeof s !== 'object') {
      throw new Error(`verifySnapshotShardManifest: shard[${i}] is not an object`);
    }
    if (s.index !== i) {
      throw new Error(`verifySnapshotShardManifest: shard[${i}].index=${s.index} does not match array position`);
    }
    if (typeof s.contentHash !== 'string' || !s.contentHash.startsWith('sha256:')) {
      throw new Error(`verifySnapshotShardManifest: shard[${i}].contentHash must be sha256:<hex>`);
    }
    if (!Number.isInteger(s.cveCount) || s.cveCount < 0) {
      throw new Error(`verifySnapshotShardManifest: shard[${i}].cveCount must be a non-negative integer`);
    }
    if (!Number.isInteger(s.byteSize) || s.byteSize < 0) {
      throw new Error(`verifySnapshotShardManifest: shard[${i}].byteSize must be a non-negative integer`);
    }
    if (s.index !== lastIndex + 1) {
      throw new Error('verifySnapshotShardManifest: shard indices must be consecutive from 0');
    }
    lastIndex = s.index;
  }
  // If trackedCveCount is present, it must equal the
  // sum of shard cveCount.
  if (typeof manifest.trackedCveCount === 'number') {
    let total = 0;
    for (const s of manifest.shards) total += s.cveCount;
    if (total !== manifest.trackedCveCount) {
      throw new Error(
        `verifySnapshotShardManifest: trackedCveCount ${manifest.trackedCveCount} does not equal sum of shard cveCount (${total})`,
      );
    }
  }
  // providerComparability, when present, must be an
  // object or null. The reader uses it to reconstruct
  // the full logical snapshot. New manifests always
  // carry it; legacy manifests (if any) are tolerated.
  if (
    manifest.providerComparability !== undefined
    && manifest.providerComparability !== null
    && (typeof manifest.providerComparability !== 'object' || Array.isArray(manifest.providerComparability))
  ) {
    throw new Error('verifySnapshotShardManifest: providerComparability must be an object or null');
  }
  return true;
}

/**
 * Reassemble the logical public snapshot from a
 * verified manifest and a list of shard bodies (in
 * manifest order). Returns a fresh object with the
 * same shape as the original logical snapshot.
 *
 * The reassembled snapshot is verified against the
 * manifest's `logicalSnapshotContentHash`; a mismatch
 * is a hard error (it indicates corruption or a
 * storage-level bug).
 */
export function reassembleSnapshotFromShards(manifest, shardBodies) {
  verifySnapshotShardManifest(manifest);
  if (!Array.isArray(shardBodies) || shardBodies.length !== manifest.shardCount) {
    throw new Error(
      `reassembleSnapshotFromShards: expected ${manifest.shardCount} shard bodies, got ${shardBodies && shardBodies.length}`,
    );
  }
  // Verify each shard body against its descriptor.
  const byCve = {};
  let trackedCveCount = 0;
  for (let i = 0; i < shardBodies.length; i++) {
    const body = shardBodies[i];
    const desc = manifest.shards[i];
    if (!body || typeof body !== 'object') {
      throw new Error(`reassembleSnapshotFromShards: shard[${i}] body is not an object`);
    }
    if (body.index !== desc.index) {
      throw new Error(`reassembleSnapshotFromShards: shard[${i}].index=${body.index} does not match descriptor ${desc.index}`);
    }
    if (body.cveCount !== desc.cveCount) {
      throw new Error(`reassembleSnapshotFromShards: shard[${i}].cveCount=${body.cveCount} does not match descriptor ${desc.cveCount}`);
    }
    if (!Array.isArray(body.cveIds) || body.cveIds.length !== desc.cveCount) {
      throw new Error(`reassembleSnapshotFromShards: shard[${i}].cveIds length does not match`);
    }
    const expectedHash = shardContentHash(body);
    if (expectedHash !== desc.contentHash) {
      throw new Error(
        `reassembleSnapshotFromShards: shard[${i}] content hash mismatch ` +
        `(expected ${desc.contentHash}, computed ${expectedHash})`,
      );
    }
    // Verify each CVE's record.
    for (const cve of body.cveIds) {
      const rec = body.byCve[cve];
      if (!rec) {
        throw new Error(`reassembleSnapshotFromShards: shard[${i}] declares cve ${cve} but byCve has no record`);
      }
      byCve[cve] = rec;
      trackedCveCount++;
    }
  }
  // Build the logical snapshot. The exact shape mirrors
  // the input logical snapshot used to build the
  // manifest (so the hash matches). The
  // providerComparability block is restored from the
  // manifest (it is small enough to carry in the
  // manifest directly; see `buildSnapshotShardManifest`).
  const logical = {
    schemaVersion: '1.0.0',
    publicIntelligenceVersion: manifest.publicIntelligenceVersion,
    generatedAt: manifest.generatedAt,
    providerComparability: manifest.providerComparability || null,
    trackedCveCount,
    byCve,
  };
  // Verify the canonical content hash of the
  // reassembled logical snapshot. The hash is computed
  // over the FULL logical snapshot (including
  // providerComparability); the publisher stored the
  // same hash in the manifest, so a mismatch indicates
  // corruption or a storage-level bug.
  const computedHash = contentHash(logical);
  if (computedHash !== manifest.logicalSnapshotContentHash) {
    throw new Error(
      `reassembleSnapshotFromShards: logical content hash mismatch ` +
      `(expected ${manifest.logicalSnapshotContentHash}, computed ${computedHash})`,
    );
  }
  return logical;
}

/**
 * Verify that every shard body in a partition is under
 * the per-shard hard ceiling. The publisher calls this
 * AFTER partition and BEFORE writing. Throws
 * `SizeCeilingExceededError` on the first violation.
 *
 * Compressed size is also checked at the publisher
 * level (`SNAPSHOT_SHARD_HARD_CEILING_COMPRESSED_BYTES`).
 */
export function assertAllShardsUnderCeiling(shardBodies, hardCeilingBytes = SNAPSHOT_SHARD_HARD_CEILING_UNCOMPRESSED_BYTES) {
  for (let i = 0; i < shardBodies.length; i++) {
    const size = shardBodyUncompressedBytes(shardBodies[i]);
    if (size > hardCeilingBytes) {
      throw new SizeCeilingExceededError(
        `shard[${i}] uncompressed size ${size} exceeds per-shard ceiling ${hardCeilingBytes}`,
      );
    }
  }
  return true;
}

/* ---- Storage key shape ---- */

/**
 * Content-addressed storage key for a snapshot shard.
 * The key is the content hash (hex) under a content-
 * addressed directory; no version prefix. Two shards
 * with identical content share the same key. The hash
 * is the sha256 of the canonical shard body; the
 * publisher uses `shardContentHash(body)` to obtain it.
 *
 * Throws on any input that isn't a well-formed
 * `sha256:<64 hex>` or `<64 hex>` hash; the path-
 * traversal / symlink-escape guard lives in the
 * storage adapter.
 */
export function snapshotShardKey(contentHashValue) {
  if (typeof contentHashValue !== 'string' || contentHashValue.length === 0) {
    throw new Error('snapshotShardKey: contentHashValue must be a non-empty string');
  }
  if (!/^sha256:[0-9a-f]{64}$/.test(contentHashValue) && !/^[0-9a-f]{64}$/.test(contentHashValue)) {
    throw new Error('snapshotShardKey: contentHashValue must be sha256:<64 hex> or <64 hex>');
  }
  const hash = contentHashValue.startsWith('sha256:')
    ? contentHashValue.slice('sha256:'.length)
    : contentHashValue;
  return `dataset/shards/sha256/${hash}.json.gz`;
}

/**
 * Storage key for the per-version shard manifest. The
 * manifest is written under the same per-version
 * directory as the previous single-blob snapshot
 * (which is now a degenerate case for new
 * publications). The reader reads the manifest FIRST
 * and then the shards.
 */
export function snapshotShardManifestKey(publicIntelligenceVersion) {
  if (typeof publicIntelligenceVersion !== 'string' || publicIntelligenceVersion.length === 0) {
    throw new Error('snapshotShardManifestKey: publicIntelligenceVersion is required');
  }
  if (
    publicIntelligenceVersion.includes('/')
    || publicIntelligenceVersion.includes('\\')
    || publicIntelligenceVersion.includes('..')
    || publicIntelligenceVersion.includes('\0')
  ) {
    throw new Error('snapshotShardManifestKey: unsafe publicIntelligenceVersion');
  }
  return `dataset/versions/${publicIntelligenceVersion}/snapshot-shards-manifest.json`;
}
