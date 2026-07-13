/**
 * V6.0 — Baseline publish.
 *
 * The publish module owns the V6.0 publication contract. It is the
 * only place in the codebase that knows the exact shape of:
 *
 *   1. The version manifest (immutable, keyed by version)
 *   2. The latest pointer (atomic commit point, mutable)
 *   3. The delta file (immutable, from-version → to-version)
 *
 * The V6.0 amendment is explicit: the latest manifest is THE single
 * strongly-consistent write. Failed publication leaves
 * `manifests/latest.json` unchanged, so consumers always see either
 * the previous version or the new one — never a partial.
 *
 * Content hash:
 *   The "canonical content hash" on the manifest is the SHA-256 of
 *   the canonical JSON of the manifest object (minus the
 *   `canonicalContentHash` field itself, which is computed LAST).
 *   Consumers can verify a manifest by recomputing this hash and
 *   comparing.
 *
 * Delta:
 *   Deltas are NOT required for consumers (the version manifest is
 *   self-sufficient), but they are a bandwidth optimization for
 *   consumers that already have a copy of the previous baseline.
 *   A delta says "given the previous baseline at version X, apply
 *   these upserts and tombstones to reach version Y". The
 *   `upserts` and `tombstones` are the COMPLETE canonical entity
 *   objects (not just canonicalIds), so a consumer can apply a
 *   delta with no further lookups.
 *
 *   The delta is generated only when there is a previous version.
 *   The first version (bootstrap) has no delta — consumers fetch
 *   the version manifest and follow the shard map.
 */

import {
  contentHash as computeContentHash,
} from './canonicalHash.mjs';
import {
  LATEST_MANIFEST_KEY,
  MANIFESTS_DIR,
  readJson,
  readVersionManifest,
  writeVersionManifest,
  writeLatestManifest,
  writeDelta,
  readDelta,
} from './baselineStore.mjs';

export const DELTA_FILENAME_SEPARATOR = '__to__';
export const BASELINE_SCHEMA_VERSION = '1.0.0';
export const DELTA_SCHEMA_VERSION = '1.0.0';

/**
 * Build the immutable version manifest for a published baseline.
 *
 * @param {Object} args
 * @param {string} args.version       - the new version string
 * @param {string|null} args.previousVersion - the previous version, if any
 * @param {string} args.publishedAt   - ISO timestamp
 * @param {string} args.configHash    - sha256:<hex> of the active OSV config
 * @param {Object} args.shards        - { [entityType]: { [bucket]: shardDesc } }
 *                                      where shardDesc = { objectKey, sha256, byteSize, recordCount }
 * @param {Object} args.sourceStatus  - { [source]: { status, fetchedAt, recordCount, error? } }
 * @param {string|null} args.deltaHash - sha256:<hex> of the delta, or null
 *                                       (null for the first version)
 *
 * @returns {Object} the manifest
 */
export function buildVersionManifest({
  version,
  previousVersion = null,
  publishedAt,
  configHash,
  shards,
  sourceStatus,
  deltaHash = null,
} = {}) {
  if (typeof version !== 'string' || version.length === 0) {
    throw new Error('buildVersionManifest: version is required');
  }
  if (typeof publishedAt !== 'string' || publishedAt.length === 0) {
    throw new Error('buildVersionManifest: publishedAt is required');
  }
  if (typeof configHash !== 'string' || !configHash.startsWith('sha256:')) {
    throw new Error('buildVersionManifest: configHash must be sha256:<hex>');
  }
  if (!shards || typeof shards !== 'object') {
    throw new Error('buildVersionManifest: shards is required');
  }
  if (!sourceStatus || typeof sourceStatus !== 'object') {
    throw new Error('buildVersionManifest: sourceStatus is required');
  }

  // Compute aggregate stats per entity type. The sum of all
  // recordCounts across all buckets is the baseline size.
  const perType = {};
  let totalRecords = 0;
  let totalBytes = 0;
  let totalBuckets = 0;
  for (const [entityType, buckets] of Object.entries(shards)) {
    let count = 0;
    let bytes = 0;
    let bucketCount = 0;
    for (const desc of Object.values(buckets || {})) {
      count += desc.recordCount;
      bytes += desc.byteSize;
      bucketCount += 1;
    }
    perType[entityType] = { recordCount: count, byteSize: bytes, bucketCount };
    totalRecords += count;
    totalBytes += bytes;
    totalBuckets += bucketCount;
  }

  // The manifest is built in two pieces:
  //   1. `coreFields` — everything that defines the manifest's
  //      content. This is the data over which `canonicalContentHash`
  //      is computed. The hash is a content hash, not a metadata
  //      hash; consumers recomputing it must get the same answer
  //      regardless of the optional `deltaHash` pointer.
  //   2. `canonicalContentHash` — the SHA-256 of the canonical
  //      bytes of `coreFields`. Attached LAST so it is not a
  //      self-reference.
  //   3. `deltaHash` — the SHA-256 of the delta file, if any.
  //      Attached AFTER the hash is computed, so it does not
  //      affect the hash. This breaks the circular reference
  //      between the manifest's content hash and the delta's
  //      `targetManifestHash` (the delta's targetManifestHash
  //      matches the manifest's canonicalContentHash; the
  //      delta's own hash is referenced from the manifest as
  //      `deltaHash` for cross-checking but is not part of the
  //      manifest's content).
  //
  // The `deltaHash` field is preserved when a manifest is read
  // back; consumers can verify the delta's `deltaSha256` against
  // the manifest's `deltaHash` to confirm they are looking at
  // the same delta.
  const coreFields = {
    schemaVersion: BASELINE_SCHEMA_VERSION,
    baselineVersion: version,
    previousVersion,
    publishedAt,
    configHash,
    sourceStatus,
    shards,
    stats: {
      totalRecords,
      totalCompressedBytes: totalBytes,
      totalBuckets,
      perType,
    },
  };
  const canonicalContentHash = computeContentHash(coreFields);
  return { ...coreFields, canonicalContentHash, deltaHash };
}

/**
 * Build a delta object from a previous baseline to a new one.
 *
 * @param {Object} args
 * @param {string} args.baseVersion       - the version we're deltawing from
 * @param {string} args.baseManifestHash  - canonicalContentHash of the base manifest
 * @param {string} args.targetVersion     - the new version
 * @param {string} args.targetManifestHash - canonicalContentHash of the new manifest
 * @param {Object} args.upserts           - { [canonicalId]: { entityType, entity } }
 * @param {Object} args.tombstones        - { [tombstoneId]: tombstoneEntity }
 * @param {string} args.generatedAt       - ISO timestamp
 *
 * @returns {Object} the delta
 */
export function buildDelta({
  baseVersion,
  baseManifestHash,
  targetVersion,
  targetManifestHash,
  upserts,
  tombstones,
  generatedAt,
} = {}) {
  if (typeof baseVersion !== 'string' || baseVersion.length === 0) {
    throw new Error('buildDelta: baseVersion is required');
  }
  if (typeof baseManifestHash !== 'string' || !baseManifestHash.startsWith('sha256:')) {
    throw new Error('buildDelta: baseManifestHash must be sha256:<hex>');
  }
  if (typeof targetVersion !== 'string' || targetVersion.length === 0) {
    throw new Error('buildDelta: targetVersion is required');
  }
  if (typeof targetManifestHash !== 'string' || !targetManifestHash.startsWith('sha256:')) {
    throw new Error('buildDelta: targetManifestHash must be sha256:<hex>');
  }
  if (typeof generatedAt !== 'string' || generatedAt.length === 0) {
    throw new Error('buildDelta: generatedAt is required');
  }

  const upsertList = Object.values(upserts || {}).map((u) => u.entity);
  const tombstoneList = Object.values(tombstones || {});

  const base = {
    schemaVersion: DELTA_SCHEMA_VERSION,
    baseVersion,
    baseManifestHash,
    targetVersion,
    targetManifestHash,
    upserts: upsertList,
    tombstones: tombstoneList,
    generatedAt,
  };
  // Delta SHA-256: hash the canonical bytes of the delta EXCLUDING
  // the `deltaSha256` field (which is computed last).
  const deltaSha256 = computeContentHash(base);
  return { ...base, deltaSha256 };
}

/**
 * Build the `deltas/{from}__to__{to}.json` key. Exposed for tests.
 */
export function deltaKey(fromVersion, toVersion) {
  return `deltas/${fromVersion}${DELTA_FILENAME_SEPARATOR}${toVersion}.json`;
}

/**
 * Generate the publication artifacts: version manifest and delta.
 * Returns `{ manifest, delta, deltaKey }`.
 *
 * `deltaKey` is null when there is no previous version (the
 * bootstrap case).
 *
 * This function does NOT write to the Blob store. The caller
 * (the orchestrator) is responsible for the I/O so it can roll
 * back on a failure.
 *
 * Single-pass: the manifest's `canonicalContentHash` is computed
 * over a stable subset of fields (excluding `deltaHash`), so we
 * can build the manifest and the delta in one shot. The delta's
 * `targetManifestHash` matches the manifest's
 * `canonicalContentHash` exactly.
 */
export function generatePublicationArtifacts({
  version,
  previousVersion,
  previousManifest = null,
  publishedAt,
  configHash,
  shards,
  sourceStatus,
  upserts,
  tombstones,
  generatedAt = publishedAt,
} = {}) {
  let delta = null;
  let deltaKeyStr = null;

  if (previousVersion && previousManifest && previousManifest.canonicalContentHash) {
    // We need the manifest's canonicalContentHash to embed in the
    // delta. Build a first-cut manifest with deltaHash=null to
    // get the hash, then build the delta, then re-build the
    // manifest with the real deltaHash. The hash is stable
    // because `deltaHash` is excluded from the content hash.
    const manifestNoDelta = buildVersionManifest({
      version,
      previousVersion,
      publishedAt,
      configHash,
      shards,
      sourceStatus,
      deltaHash: null,
    });
    const targetManifestHash = manifestNoDelta.canonicalContentHash;
    delta = buildDelta({
      baseVersion: previousVersion,
      baseManifestHash: previousManifest.canonicalContentHash,
      targetVersion: version,
      targetManifestHash,
      upserts: upserts || {},
      tombstones: tombstones || {},
      generatedAt,
    });
    deltaKeyStr = deltaKey(previousVersion, version);
  }

  const manifest = buildVersionManifest({
    version,
    previousVersion,
    publishedAt,
    configHash,
    shards,
    sourceStatus,
    deltaHash: delta ? delta.deltaSha256 : null,
  });

  return { manifest, delta, deltaKey: deltaKeyStr };
}

/**
 * Publish the baseline atomically. Writes:
 *   1. The version manifest (immutable; key = manifests/versions/{version}.json)
 *   2. The delta file (immutable; only if delta != null)
 *   3. The latest pointer (atomic commit point; key = manifests/latest.json)
 *
 * The order matters. The latest pointer is written LAST, so a
 * reader that sees the new pointer can also find the version
 * manifest and the delta. A reader that sees the old pointer
 * still sees a consistent previous version.
 *
 * The caller is expected to have already written all the shard
 * objects. This function only writes the manifest / delta / pointer.
 */
export async function publishBaseline({
  store,
  manifest,
  delta = null,
  deltaKeyName = null,
}) {
  if (!store) throw new Error('publishBaseline: store is required');
  if (!manifest || typeof manifest.baselineVersion !== 'string') {
    throw new Error('publishBaseline: manifest with baselineVersion is required');
  }
  // Write the immutable version manifest
  const wroteVersion = await writeVersionManifest(store, manifest.baselineVersion, manifest);
  if (!wroteVersion) return { ok: false, reason: 'writeVersionManifest failed' };

  // Write the delta (if any)
  if (delta && deltaKeyName) {
    const wroteDelta = await writeDelta(store, delta.baseVersion, delta.targetVersion, delta);
    if (!wroteDelta) return { ok: false, reason: 'writeDelta failed' };
  }

  // Atomic commit: write the latest pointer LAST.
  const wroteLatest = await writeLatestManifest(store, manifest);
  if (!wroteLatest) {
    // The version manifest and (optionally) delta are written but
    // the pointer is unchanged. The next run will overwrite the
    // same version key (it's the same content), but the previous
    // pointer remains. A separate "adopt orphan" pass would close
    // this gap; for V6.0 we accept that a transient failure
    // between manifest write and pointer write requires the next
    // run to succeed.
    return { ok: false, reason: 'writeLatestManifest failed' };
  }
  return { ok: true, manifest, delta, deltaKey: deltaKeyName };
}

/**
 * Verify a manifest's canonical content hash. Returns true if the
 * hash is valid. Used by tests and by consumer-side verification.
 *
 * The hash is computed over the manifest EXCLUDING
 * `canonicalContentHash` AND `deltaHash`. The latter is metadata
 * that does not affect the content; it is excluded from both the
 * build (buildVersionManifest) and the verify (this function) so
 * a consumer-side verifier and a publisher produce the same hash.
 */
export function verifyManifestHash(manifest) {
  if (!manifest || typeof manifest !== 'object') return false;
  const expected = manifest.canonicalContentHash;
  if (typeof expected !== 'string' || !expected.startsWith('sha256:')) return false;
  const { canonicalContentHash, deltaHash, ...rest } = manifest;
  // Suppress the unused-variable lint; deltaHash is intentionally
  // destructured out of the hash input.
  void deltaHash;
  const actual = computeContentHash(rest);
  return actual === expected;
}

/**
 * Re-export the Blob store key constants. The orchestrator and the
 * consumer client use these via this module so the layout is
 * documented in one place.
 */
export { LATEST_MANIFEST_KEY, MANIFESTS_DIR, readJson, readVersionManifest, readDelta };
