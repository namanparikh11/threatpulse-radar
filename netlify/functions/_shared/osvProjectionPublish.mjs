/**
 * V6.1 — OSV public projection publisher.
 *
 * The publisher runs as a sub-step of the V6.0 canonical
 * baseline Background Function (after the atomic
 * `tpr-baseline/manifests/latest.json` write, inside the
 * existing V6.0 publication lock window). It is
 * best-effort: a failure here preserves the previous OSV
 * `latest.json` and never invalidates the canonical
 * publication.
 *
 * Pipeline:
 *   1. Read the canonical entities (the caller is
 *      responsible for loading them — this module accepts
 *      them as input).
 *   2. For each CVE in the public tracked universe, build
 *      the multi-record bounded OSV public context.
 *   3. Partition into 16 deterministic buckets.
 *   4. For each bucket:
 *      a. Compute the bucket content hash.
 *      b. If a Blob with the same content hash already
 *         exists, reuse it (no write).
 *      c. Otherwise, gzipped-write the new bucket under
 *         its content-addressed key.
 *   5. Build the per-version manifest with the 16
 *      bucket content hashes.
 *   6. Compute the manifest content hash.
 *   7. If the manifest content hash matches any retained
 *      version's manifest content hash, skip writing the
 *      manifest and `latest.json` (skip-unchanged
 *      publication). The previous `latest.json` remains
 *      valid.
 *   8. Write the immutable manifest.
 *   9. Write `osv/latest.json` LAST (atomic pointer).
 *
 * Atomicity: `latest.json` is the only mutable commit
 * point. All other artifacts are immutable. A failure at
 * any step preserves the previous `latest.json` and the
 * previous version directory.
 *
 * Locking: the publisher is called inside the V6.0
 * canonical publication lock window. The V6.0 lock
 * already serializes publication across Background
 * Function invocations. A second-layer OSV publication
 * lock is exposed for the standalone test path; it is a
 * no-op when called from inside the V6.0 lock.
 */

import { getStore } from '@netlify/blobs';
import {
  PUBLIC_INTELLIGENCE_STORE_NAME,
  OSV_DIR,
  OSV_VERSIONS_DIR,
  OSV_SHARDS_DIR,
  PUBLICATION_LOCK_TTL_MS,
  osvManifestKey,
  osvShardKey,
  readJson,
  writeJson,
} from './publicIntelligenceStore.mjs';
import {
  deriveOsvProjectionVersion,
  contentAddressedHash,
} from './publicIntelligenceHash.mjs';
import {
  projectCveToOsvPublic,
  partitionIntoBuckets,
  bucketContentHash,
} from './osvPublicProjection.mjs';
import {
  OSV_SHARD_HARD_CEILING_UNCOMPRESSED_BYTES,
  OSV_SHARD_HARD_CEILING_COMPRESSED_BYTES,
  OSV_LATEST_HARD_CEILING_BYTES,
  OSV_BUCKET_COUNT,
  SizeCeilingExceededError,
  assertUncompressedSize,
  gzipJson,
} from './publicIntelligenceSize.mjs';
import { gzipValue, gunzipValue } from './publicIntelligenceCompression.mjs';
import { canonicalize, canonicalizeToString, contentHash } from './canonicalHash.mjs';

/**
 * Build the OSV public projection for a single canonical
 * baseline version. Returns the per-version manifest body
 * and the 16-bucket partition. Pure.
 */
export function buildOsvProjection(canonicalEntities, { canonicalBaselineVersion, canonicalManifestHash } = {}) {
  if (typeof canonicalBaselineVersion !== 'string' || !canonicalBaselineVersion) {
    throw new Error('buildOsvProjection: canonicalBaselineVersion is required');
  }
  if (typeof canonicalManifestHash !== 'string' || !canonicalManifestHash.startsWith('sha256:')) {
    throw new Error('buildOsvProjection: canonicalManifestHash (sha256:<hex>) is required');
  }
  if (!Array.isArray(canonicalEntities)) {
    throw new Error('buildOsvProjection: canonicalEntities must be an array');
  }
  // Group canonical entities by CVE. Each canonical
  // vulnerability entity is keyed by its `osvId`. We
  // collect the canonical entities that map to a given
  // CVE via the entity's aliases array.
  const byCvePublic = {};
  for (const ent of canonicalEntities) {
    if (!ent || typeof ent !== 'object') continue;
    if (typeof ent.osvId !== 'string') continue;
    // The CVE id is either the primary id (when the
    // OSV id is CVE-...) or any of the aliases.
    const aliases = Array.isArray(ent.aliases) ? ent.aliases : [];
    const cvesFromPrimary = ent.osvId.startsWith('CVE-') ? [ent.osvId] : [];
    const cvesFromAliases = aliases.filter((a) => typeof a === 'string' && a.startsWith('CVE-'));
    const cves = Array.from(new Set([...cvesFromPrimary, ...cvesFromAliases]));
    for (const cve of cves) {
      if (!byCvePublic[cve]) byCvePublic[cve] = [];
      byCvePublic[cve].push(ent);
    }
  }
  // Project each CVE to its bounded public context.
  const byCveProjected = {};
  for (const cve of Object.keys(byCvePublic)) {
    const ctx = projectCveToOsvPublic(cve, byCvePublic[cve]);
    if (ctx) byCveProjected[cve] = ctx;
  }
  // Partition into 16 buckets.
  const buckets = partitionIntoBuckets(byCveProjected);
  // Wrap each bucket with the schema-required top-level
  // fields, then compute the per-bucket content hash from
  // the wrapped body. The shard write uses the same
  // wrapped body so the content-addressed key matches
  // the actual gzipped bytes.
  const wrappedBuckets = buckets.map((b, i) => {
    const recordsRemovedTotal = Object.values(b.byCve).reduce(
      (acc, cve) => acc + (cve && cve.truncation ? cve.truncation.recordsRemoved : 0),
      0,
    );
    const cvesTruncated = Object.values(b.byCve).filter(
      (cve) => cve && cve.truncation && cve.truncation.recordsRemoved > 0,
    ).length;
    return {
      schemaVersion: '1.0.0',
      bucket: b.bucket,
      byCve: b.byCve,
      bucketContentHash: null, // placeholder; set below
      truncation: { recordsRemovedTotal, cvesTruncated },
    };
  });
  for (let i = 0; i < wrappedBuckets.length; i++) {
    wrappedBuckets[i].bucketContentHash = bucketContentHash(wrappedBuckets[i]);
  }
  const bucketHashes = wrappedBuckets.map((b) => b.bucketContentHash);
  const osvProjectionVersion = deriveOsvProjectionVersion(canonicalBaselineVersion, canonicalManifestHash);
  const generatedAt = new Date().toISOString();
  const manifest = {
    schemaVersion: '1.0.0',
    osvProjectionVersion,
    canonicalBaselineVersion,
    canonicalManifestHash,
    generatedAt,
    bucketCount: OSV_BUCKET_COUNT,
    buckets: bucketHashes.reduce((acc, h, i) => {
      acc[i.toString(16)] = {
        contentHash: h,
        cveCount: buckets[i].cveCount,
      };
      return acc;
    }, {}),
    truncation: {
      bucketsTruncated: 0,
    },
  };
  return { manifest, buckets: wrappedBuckets, byCveProjected };
}

/**
 * Read the current OSV `latest.json` pointer. Returns
 * null when missing or malformed.
 */
export async function readOsvLatest(store) {
  return readJson(store, `${OSV_DIR}/latest.json`);
}

/**
 * Determine whether a new OSV projection version is
 * content-identical to any retained version. When true,
 * the publisher skips writing the manifest and the
 * latest.json.
 *
 * The comparison ignores `generatedAt` (a per-publication
 * timestamp) so that a re-publication with identical
 * canonical content but a different wall-clock second is
 * detected as unchanged. The manifest hash for skip-unchanged
 * detection is computed over a normalized view of the
 * manifest with `generatedAt` and the manifest's own
 * `schemaVersion` removed.
 */
export function isProjectionUnchanged(newManifest, retainedManifests) {
  if (!newManifest || typeof newManifest !== 'object') return false;
  if (!Array.isArray(retainedManifests)) return false;
  const newNorm = normalizeForSkip(newManifest);
  const newHash = contentHash(newNorm);
  for (const old of retainedManifests) {
    if (!old || typeof old !== 'object') continue;
    const oldNorm = normalizeForSkip(old);
    if (contentHash(oldNorm) === newHash) return true;
  }
  return false;
}

/**
 * Strip volatile fields from a manifest for skip-unchanged
 * comparison. Volatile: `generatedAt` (per-publication
 * timestamp), `schemaVersion` is preserved because it
 * represents the structural format.
 */
function normalizeForSkip(manifest) {
  if (!manifest || typeof manifest !== 'object') return manifest;
  const { generatedAt, ...rest } = manifest;
  return rest;
}

/**
 * Acquire the OSV publication lock. Best-effort; returns
 * false when another writer holds a non-expired lock.
 */
export async function tryAcquireOsvLock(store, now = new Date(), ttlMs = PUBLICATION_LOCK_TTL_MS) {
  const lockKey = `${OSV_DIR}/publication-lock`;
  try {
    const existing = await readJson(store, lockKey);
    if (existing && typeof existing.expiresAt === 'string') {
      const t = new Date(existing.expiresAt).getTime();
      if (!Number.isNaN(t) && t > now.getTime()) return false;
    }
    const expiresAt = new Date(now.getTime() + ttlMs).toISOString();
    const payload = { startedAt: now.toISOString(), expiresAt: expiresAt.toISOString() };
    await writeJson(store, lockKey, payload);
    return true;
  } catch {
    return false;
  }
}

export async function releaseOsvLock(store) {
  const lockKey = `${OSV_DIR}/publication-lock`;
  try { await store.delete(lockKey); } catch { /* noop */ }
}

/**
 * Build the OSV public projection and write it to the
 * public-intelligence Blob store. Best-effort: returns
 * `{ skipped: true, reason: ... }` on size ceiling
 * violation or no-op cases; throws SizeCeilingExceededError
 * when an individual shard exceeds the hard ceiling.
 *
 * Inputs:
 *   - store: the public-intelligence Blob store handle
 *     (from `getPublicIntelligenceStore`).
 *   - canonicalEntities: array of canonical vulnerability
 *     entities from the just-published canonical baseline.
 *   - options: { canonicalBaselineVersion, canonicalManifestHash, now }
 *
 * The caller is expected to invoke this from inside the
 * V6.0 canonical publication lock window.
 */
export async function publishOsvProjection(store, canonicalEntities, options = {}) {
  const { canonicalBaselineVersion, canonicalManifestHash } = options;
  if (!store) throw new Error('publishOsvProjection: store is required');
  if (!Array.isArray(canonicalEntities)) {
    throw new Error('publishOsvProjection: canonicalEntities must be an array');
  }

  // Build the projection. Pure; no I/O.
  const { manifest, buckets } = buildOsvProjection(canonicalEntities, {
    canonicalBaselineVersion,
    canonicalManifestHash,
  });

  // Validate per-bucket uncompressed sizes. A bucket
  // that exceeds the hard ceiling aborts the publication
  // (the previous latest.json is preserved).
  for (let i = 0; i < buckets.length; i++) {
    assertUncompressedSize(buckets[i], OSV_SHARD_HARD_CEILING_UNCOMPRESSED_BYTES, `osv-shard-${i.toString(16)}`);
  }

  // Skip-unchanged check: read the retained manifests
  // (current, previous, rollback) and compare.
  const retained = await readRetainedOsvManifests(store, manifest.osvProjectionVersion);
  if (isProjectionUnchanged(manifest, retained.map((r) => r.manifest))) {
    return { skipped: true, reason: 'projection-unchanged', osvProjectionVersion: manifest.osvProjectionVersion };
  }

  // Write the 16 buckets. Reuse any existing content-addressed shard.
  for (let i = 0; i < buckets.length; i++) {
    const bucket = buckets[i];
    const bucketHash = manifest.buckets[i.toString(16)].contentHash;
    const key = osvShardKey(bucketHash);
    // Reuse: if the Blob already exists with this content hash, skip.
    let alreadyExists = false;
    try {
      const existing = await store.get(key, { type: 'arrayBuffer' });
      if (existing && existing.length > 0) {
        const want = gzipValue(bucket);
        if (existing.length === want.length) {
          alreadyExists = true;
        }
      }
    } catch {
      alreadyExists = false;
    }
    if (!alreadyExists) {
      const gz = gzipValue(bucket);
      if (gz.length > OSV_SHARD_HARD_CEILING_COMPRESSED_BYTES) {
        throw new SizeCeilingExceededError(
          `osv-shard-${i.toString(16)} compressed size ${gz.length} exceeds ceiling ${OSV_SHARD_HARD_CEILING_COMPRESSED_BYTES}`,
        );
      }
      try {
        await store.setBinary(key, gz);
      } catch {
        return { skipped: true, reason: 'shard-write-failed', bucket: i.toString(16) };
      }
    }
  }

  // Write the immutable manifest.
  const manifestKey = osvManifestKey(manifest.osvProjectionVersion);
  try {
    await writeJson(store, manifestKey, manifest);
  } catch {
    return { skipped: true, reason: 'manifest-write-failed', osvProjectionVersion: manifest.osvProjectionVersion };
  }

  // Compute the manifest content hash for `latest.json`.
  const manifestContentHash = contentHash(manifest);

  // Write the atomic pointer LAST. Validate size.
  const latest = {
    schemaVersion: '1.0.0',
    osvProjectionVersion: manifest.osvProjectionVersion,
    canonicalBaselineVersion: manifest.canonicalBaselineVersion,
    canonicalManifestHash: manifest.canonicalManifestHash,
    manifestContentHash,
    generatedAt: manifest.generatedAt,
  };
  const latestJson = canonicalizeToString(latest);
  if (latestJson.length > OSV_LATEST_HARD_CEILING_BYTES) {
    // Roll back the manifest write by leaving it as an
    // orphan (not referenced by latest.json). The GC
    // step removes it. The previous latest.json is
    // preserved.
    return { skipped: true, reason: 'latest-json-too-large', osvProjectionVersion: manifest.osvProjectionVersion };
  }
  try {
    await writeJson(store, `${OSV_DIR}/latest.json`, latest);
  } catch {
    return { skipped: true, reason: 'latest-write-failed', osvProjectionVersion: manifest.osvProjectionVersion };
  }

  return {
    skipped: false,
    osvProjectionVersion: manifest.osvProjectionVersion,
    canonicalBaselineVersion: manifest.canonicalBaselineVersion,
    manifestContentHash,
    bucketCount: OSV_BUCKET_COUNT,
  };
}

/**
 * Read the retained OSV projection manifests (current,
 * previous, rollback) for skip-unchanged detection.
 * Returns an array of `{ osvProjectionVersion, manifest }`
 * pairs.
 */
export async function readRetainedOsvManifests(store, currentOsvProjectionVersion) {
  if (!store) return [];
  const latest = await readOsvLatest(store);
  const retainedVersions = new Set();
  if (latest && typeof latest.osvProjectionVersion === 'string') {
    retainedVersions.add(latest.osvProjectionVersion);
    if (typeof currentOsvProjectionVersion === 'string') {
      retainedVersions.add(currentOsvProjectionVersion);
    }
  }
  // GC step would have removed the rollback; we read up
  // to 3 versions in case rollback is still on disk. For
  // skip-unchanged detection, we read just the latest.
  const out = [];
  for (const v of retainedVersions) {
    try {
      const m = await readJson(store, osvManifestKey(v));
      if (m) out.push({ osvProjectionVersion: v, manifest: m });
    } catch { /* skip */ }
  }
  return out;
}
