/**
 * V6.1 — Dataset-bound public-intelligence publisher.
 *
 * The dataset-bound publisher runs as a sub-step of the
 * V5.2 dataset refresh orchestrator (after the
 * `latest-dataset` write completes and after the
 * Vulnrichment and GitHub Advisory refresh passes have
 * completed). It builds the per-CVE public comparison
 * snapshot, the source-health observations, and the
 * change-intelligence items (in commit 4); it then writes
 * the immutable per-version artifacts and the atomic
 * `dataset/latest.json` pointer.
 *
 * Atomicity: `dataset/latest.json` is the only mutable
 * commit point. All other artifacts are immutable. A
 * failure at any step preserves the previous
 * `latest.json` and the previous version directory.
 *
 * Skip-unchanged: when the new `publicStateHash` matches
 * the previous successful public-intelligence version's
 * `publicStateHash`, the publisher skips writing the
 * manifest, snapshot, and changes (no change happened),
 * and the previous `latest.json` remains valid.
 *
 * The `datasetPublicHash`, `vulnrichmentPublicHash`, and
 * `githubAdvisoryPublicHash` are stored in their
 * respective Blob envelopes as internal metadata
 * (`INTERNAL_BLOB_FIELDS`-stripped at serve time). The
 * composite `publicStateHash` is computed at write time
 * from the four currently-served state pieces and is the
 * compatibility record for read-time matching.
 *
 * Locking: the publisher is called inside the V5.2 dataset
 * refresh lock window. The V5.2 lock already serializes
 * publication across Background Function invocations. A
 * second-layer publication lock is exposed for the
 * standalone test path; it is a no-op when called from
 * inside the V5.2 lock.
 */

import {
  PUBLIC_INTELLIGENCE_STORE_NAME,
  DATASET_DIR,
  DATASET_VERSIONS_DIR,
  DATASET_LATEST_KEY,
  DATASET_PUBLICATION_LOCK_KEY,
  PUBLICATION_LOCK_TTL_MS,
  datasetManifestKey,
  datasetPublicSnapshotKey,
  datasetChangesKey,
  readJson,
  writeJson,
} from './publicIntelligenceStore.mjs';
import {
  computePublicStateHash,
  computeDatasetPublicHash,
  computeEnrichmentPublicHash,
  derivePublicIntelligenceVersion,
  computePublicHash,
  PUBLIC_PROJECTION_SCHEMA_VERSION,
  PUBLIC_STATE_SCHEMA_VERSION,
} from './publicIntelligenceHash.mjs';
import {
  DATASET_MANIFEST_HARD_CEILING_BYTES,
  PUBLIC_SNAPSHOT_HARD_CEILING_UNCOMPRESSED_BYTES,
  PUBLIC_SNAPSHOT_HARD_CEILING_COMPRESSED_BYTES,
  CHANGES_HARD_CEILING_COMPRESSED_BYTES,
  LATEST_JSON_HARD_CEILING_BYTES,
  assertUncompressedSize,
  SizeCeilingExceededError,
} from './publicIntelligenceSize.mjs';
import { gzipValue, gunzipValue } from './publicIntelligenceCompression.mjs';
import { contentHash, canonicalizeToString } from './canonicalHash.mjs';
import { buildPublicSnapshot } from './publicSnapshot.mjs';
import { buildSourceHealthBlob } from './sourceHealth.mjs';

/**
 * Compute the four-hash composite public state hash from
 * the four currently-served state pieces. Pure.
 */
export function derivePublicState({ datasetEnvelope, vulnrichmentCache, githubAdvisoryCache, osvProjection } = {}) {
  const datasetPublicHash = computeDatasetPublicHash(datasetEnvelope);
  const vulnrichmentPublicHash = computeEnrichmentPublicHash(vulnrichmentCache);
  const githubAdvisoryPublicHash = computeEnrichmentPublicHash(githubAdvisoryCache);
  const referencedOsvProjectionVersion = osvProjection && osvProjection.osvProjectionVersion
    ? osvProjection.osvProjectionVersion
    : null;
  const referencedOsvProjectionContentHash = osvProjection && osvProjection.manifestContentHash
    ? osvProjection.manifestContentHash
    : (osvProjection && osvProjection.osvProjectionManifestHash
      ? osvProjection.osvProjectionManifestHash
      : null);
  const publicStateHash = computePublicStateHash({
    datasetPublicHash,
    vulnrichmentPublicHash,
    githubAdvisoryPublicHash,
    referencedOsvProjectionVersion,
    referencedOsvProjectionContentHash,
  });
  return {
    datasetPublicHash,
    vulnrichmentPublicHash,
    githubAdvisoryPublicHash,
    referencedOsvProjectionVersion,
    referencedOsvProjectionContentHash,
    publicStateHash,
  };
}

/**
 * Build the dataset-bound manifest from the current
 * state and the previous-snapshot reference (for the
 * `previousPublicIntelligenceVersion` field). Pure.
 *
 * `changeItems` is an empty array at this stage; commit 4
 * fills it in.
 */
export function buildDatasetManifest({
  generatedAt,
  publicStateHash,
  datasetEnvelope,
  vulnrichmentCache,
  githubAdvisoryCache,
  osvProjection,
  previousPublicIntelligenceVersion = null,
  changeSummary = {
    newlyTracked: 0, noLongerTracked: 0,
    factNewlyAvailable: 0, factChanged: 0, factNoLongerPresent: 0,
    providerStatusChanged: 0,
    epssMateriallyIncreased: 0, epssMateriallyDecreased: 0,
  },
  comparableAxes = ['kev', 'severity-class', 'epss', 'ssvc', 'github-advisory', 'first-patched', 'osv', 'cvss-source'],
  suppressedAxes = [],
  partial = false,
  reasons = [],
} = {}) {
  if (typeof generatedAt !== 'string' || !generatedAt) {
    throw new Error('buildDatasetManifest: generatedAt is required');
  }
  if (typeof publicStateHash !== 'string' || !publicStateHash.startsWith('sha256:')) {
    throw new Error('buildDatasetManifest: publicStateHash (sha256:<hex>) is required');
  }
  if (!datasetEnvelope || !datasetEnvelope.fetchedAt) {
    throw new Error('buildDatasetManifest: datasetEnvelope.fetchedAt is required');
  }
  // datasetContentHash: the V6.0 contentHash of the public
  // dataset envelope (INTERNAL_BLOB_FIELDS stripped). This
  // is the same value as datasetPublicHash.
  const datasetContentHash = computeDatasetPublicHash(datasetEnvelope);
  const publicIntelligenceVersion = derivePublicIntelligenceVersion(generatedAt, publicStateHash);
  return {
    schemaVersion: '1.0.0',
    publicIntelligenceVersion,
    generatedAt,
    publicStateHash,
    datasetFetchedAt: datasetEnvelope.fetchedAt,
    datasetContentHash,
    referencedOsvProjectionVersion: osvProjection && osvProjection.osvProjectionVersion ? osvProjection.osvProjectionVersion : null,
    referencedOsvProjectionContentHash: osvProjection && osvProjection.manifestContentHash ? osvProjection.manifestContentHash : null,
    publicProjectionSchemaVersion: PUBLIC_PROJECTION_SCHEMA_VERSION,
    publicStateSchemaVersion: PUBLIC_STATE_SCHEMA_VERSION,
    comparesFreshBase: previousPublicIntelligenceVersion !== null,
    previousPublicIntelligenceVersion,
    changeSummary,
    comparableAxes,
    suppressedAxes,
    partial,
    reasons,
    truncation: { changeItems: { shown: 0, total: 0 } },
  };
}

/**
 * Determine whether a new dataset-bound publication is
 * content-identical to any retained version. The
 * comparison is performed on the `publicStateHash`
 * directly: identical public state means identical
 * content, regardless of the publication wall-clock
 * second. The publicStateHash is THE identity of the
 * bundle's content; the publicIntelligenceVersion is
 * derived from it but is not the comparison basis.
 */
export function isDatasetBoundUnchanged(newPublicStateHash, retainedManifests) {
  if (typeof newPublicStateHash !== 'string' || !newPublicStateHash.startsWith('sha256:')) return false;
  if (!Array.isArray(retainedManifests)) return false;
  for (const old of retainedManifests) {
    if (!old || typeof old !== 'object') continue;
    if (old.publicStateHash === newPublicStateHash) return true;
  }
  return false;
}

/**
 * Acquire the dataset-bound publication lock. Best-effort;
 * returns false when another writer holds a non-expired
 * lock.
 */
export async function tryAcquireDatasetLock(store, now = new Date(), ttlMs = PUBLICATION_LOCK_TTL_MS) {
  if (!store) return false;
  try {
    const existing = await readJson(store, DATASET_PUBLICATION_LOCK_KEY);
    if (existing && typeof existing.expiresAt === 'string') {
      const t = new Date(existing.expiresAt).getTime();
      if (!Number.isNaN(t) && t > now.getTime()) return false;
    }
    const expiresAt = new Date(now.getTime() + ttlMs).toISOString();
    const payload = { startedAt: now.toISOString(), expiresAt: expiresAt.toISOString() };
    await writeJson(store, DATASET_PUBLICATION_LOCK_KEY, payload);
    return true;
  } catch {
    return false;
  }
}

export async function releaseDatasetLock(store) {
  if (!store) return;
  try { await store.delete(DATASET_PUBLICATION_LOCK_KEY); } catch { /* noop */ }
}

/**
 * Read the current dataset-bound latest.json pointer.
 * Returns null when missing or malformed.
 */
export async function readDatasetLatest(store) {
  return readJson(store, DATASET_LATEST_KEY);
}

/**
 * Read the retained dataset-bound manifests (current,
 * previous, rollback) for skip-unchanged detection.
 */
export async function readRetainedDatasetManifests(store) {
  if (!store) return [];
  const latest = await readDatasetLatest(store);
  const out = [];
  if (latest && typeof latest.publicIntelligenceVersion === 'string') {
    const m = await readJson(store, datasetManifestKey(latest.publicIntelligenceVersion));
    if (m) out.push({ publicIntelligenceVersion: latest.publicIntelligenceVersion, manifest: m });
  }
  // Also check up to MAX_RETAINED_VERSIONS_PER_PATH-1
  // previous versions. The version directory walk is
  // best-effort.
  try {
    const list = await store.list({ prefix: `${DATASET_VERSIONS_DIR}/` });
    const keys = (list.blobs || [])
      .filter((b) => /\/manifest\.json$/.test(b.key))
      .map((b) => b.key.replace(`${DATASET_VERSIONS_DIR}/`, '').replace(/\/manifest\.json$/, ''))
      .sort();
    for (const v of keys.slice(0, 3)) {
      if (out.find((r) => r.publicIntelligenceVersion === v)) continue;
      const m = await readJson(store, datasetManifestKey(v));
      if (m) out.push({ publicIntelligenceVersion: v, manifest: m });
    }
  } catch { /* noop */ }
  return out;
}

/**
 * Publish the dataset-bound public-intelligence bundle.
 * Best-effort: returns `{ skipped: true, reason: ... }`
 * on skip-unchanged or on size-ceiling violations; throws
 * `SizeCeilingExceededError` only when a per-blob hard
 * ceiling is exceeded.
 *
 * The caller is expected to invoke this from inside the
 * V5.2 dataset refresh lock window.
 */
export async function publishDatasetBound(store, {
  datasetEnvelope,
  vulnrichmentCache,
  githubAdvisoryCache,
  osvProjection,
  changeIntelligence = null, // { items, summary, comparableAxes, suppressedAxes, partial, reasons } | null
  now = new Date(),
} = {}) {
  if (!store) throw new Error('publishDatasetBound: store is required');
  if (!datasetEnvelope) throw new Error('publishDatasetBound: datasetEnvelope is required');

  // Compute the composite public state hash.
  const state = derivePublicState({ datasetEnvelope, vulnrichmentCache, githubAdvisoryCache, osvProjection });

  // Read the previous latest.json for the previousPublicIntelligenceVersion
  // reference.
  const previousLatest = await readDatasetLatest(store);
  const previousPublicIntelligenceVersion = previousLatest && typeof previousLatest.publicIntelligenceVersion === 'string'
    ? previousLatest.publicIntelligenceVersion
    : null;

  // Build the per-version artifacts.
  const generatedAt = now.toISOString();
  const changeSummary = changeIntelligence && changeIntelligence.summary
    ? changeIntelligence.summary
    : {
        newlyTracked: 0, noLongerTracked: 0,
        factNewlyAvailable: 0, factChanged: 0, factNoLongerPresent: 0,
        providerStatusChanged: 0,
        epssMateriallyIncreased: 0, epssMateriallyDecreased: 0,
      };
  const comparableAxes = changeIntelligence && Array.isArray(changeIntelligence.comparableAxes)
    ? changeIntelligence.comparableAxes
    : ['kev', 'severity-class', 'epss', 'ssvc', 'github-advisory', 'first-patched', 'osv', 'cvss-source'];
  const suppressedAxes = changeIntelligence && Array.isArray(changeIntelligence.suppressedAxes)
    ? changeIntelligence.suppressedAxes
    : [];
  const partial = changeIntelligence && changeIntelligence.partial === true;
  const reasons = changeIntelligence && Array.isArray(changeIntelligence.reasons)
    ? changeIntelligence.reasons
    : [];

  const manifest = buildDatasetManifest({
    generatedAt,
    publicStateHash: state.publicStateHash,
    datasetEnvelope,
    vulnrichmentCache,
    githubAdvisoryCache,
    osvProjection,
    previousPublicIntelligenceVersion,
    changeSummary,
    comparableAxes,
    suppressedAxes,
    partial,
    reasons,
  });

  // Skip-unchanged check.
  const retained = await readRetainedDatasetManifests(store);
  if (isDatasetBoundUnchanged(manifest.publicStateHash, retained.map((r) => r.manifest))) {
    return { skipped: true, reason: 'dataset-bound-unchanged', publicIntelligenceVersion: manifest.publicIntelligenceVersion };
  }

  // Build the per-CVE public comparison snapshot.
  const snapshot = buildPublicSnapshot({
    datasetEnvelope,
    vulnrichmentCache,
    githubAdvisoryCache,
    osvProjection,
    now,
  });
  snapshot.publicIntelligenceVersion = manifest.publicIntelligenceVersion;
  assertUncompressedSize(snapshot, PUBLIC_SNAPSHOT_HARD_CEILING_UNCOMPRESSED_BYTES, 'public-snapshot');

  // Build the source-health observations blob.
  const sourceHealthObservations = buildSourceHealthObservationsFromCaches({
    datasetEnvelope, vulnrichmentCache, githubAdvisoryCache, osvProjection, now,
  });
  const sourceHealthBlob = buildSourceHealthBlob(sourceHealthObservations, now);

  // Write the manifest.
  const manifestJson = canonicalizeToString(manifest);
  if (manifestJson.length > DATASET_MANIFEST_HARD_CEILING_BYTES) {
    return { skipped: true, reason: 'manifest-too-large', publicIntelligenceVersion: manifest.publicIntelligenceVersion };
  }
  try {
    await writeJson(store, datasetManifestKey(manifest.publicIntelligenceVersion), manifest);
  } catch {
    return { skipped: true, reason: 'manifest-write-failed', publicIntelligenceVersion: manifest.publicIntelligenceVersion };
  }

  // Write the public snapshot (gzipped).
  const snapshotGz = gzipValue(snapshot);
  if (snapshotGz.length > PUBLIC_SNAPSHOT_HARD_CEILING_COMPRESSED_BYTES) {
    return { skipped: true, reason: 'snapshot-too-large', publicIntelligenceVersion: manifest.publicIntelligenceVersion };
  }
  try {
    await store.setBinary(datasetPublicSnapshotKey(manifest.publicIntelligenceVersion), snapshotGz);
  } catch {
    return { skipped: true, reason: 'snapshot-write-failed', publicIntelligenceVersion: manifest.publicIntelligenceVersion };
  }

  // Write the source-health observations (gzipped, alongside the manifest).
  const sourceHealthKey = `${DATASET_VERSIONS_DIR}/${manifest.publicIntelligenceVersion}/source-health.json.gz`;
  const sourceHealthGz = gzipValue(sourceHealthBlob);
  try {
    await store.setBinary(sourceHealthKey, sourceHealthGz);
  } catch {
    // Source-health write is best-effort; the previous
    // version's source-health remains valid.
  }

  // Write the changes items (when provided). Empty list is allowed.
  const changeItems = changeIntelligence && Array.isArray(changeIntelligence.items)
    ? changeIntelligence.items
    : [];
  if (changeItems.length > 0) {
    const changesBlob = {
      schemaVersion: '1.0.0',
      publicIntelligenceVersion: manifest.publicIntelligenceVersion,
      generatedAt: manifest.generatedAt,
      comparesFreshBase: previousPublicIntelligenceVersion !== null,
      previousPublicIntelligenceVersion,
      items: changeItems,
    };
    const changesGz = gzipValue(changesBlob);
    if (changesGz.length > CHANGES_HARD_CEILING_COMPRESSED_BYTES) {
      return { skipped: true, reason: 'changes-too-large', publicIntelligenceVersion: manifest.publicIntelligenceVersion };
    }
    try {
      await store.setBinary(datasetChangesKey(manifest.publicIntelligenceVersion), changesGz);
    } catch {
      return { skipped: true, reason: 'changes-write-failed', publicIntelligenceVersion: manifest.publicIntelligenceVersion };
    }
    // Update the manifest's truncation metadata.
    manifest.truncation.changeItems = { shown: Math.min(changeItems.length, 25), total: changeItems.length };
    try {
      await writeJson(store, datasetManifestKey(manifest.publicIntelligenceVersion), manifest);
    } catch { /* noop */ }
  }

  // Compute the dataset-bound manifest content hash for `latest.json`.
  const manifestContentHash = contentHash(manifest);

  // Write the atomic pointer LAST.
  const latest = {
    schemaVersion: '1.0.0',
    publicIntelligenceVersion: manifest.publicIntelligenceVersion,
    generatedAt: manifest.generatedAt,
    publicStateHash: manifest.publicStateHash,
    publicStateFingerprint: manifest.publicStateHash.slice('sha256:'.length, 'sha256:'.length + 12),
    referencedOsvProjectionVersion: manifest.referencedOsvProjectionVersion,
    manifestContentHash,
    previousPublicIntelligenceVersion,
  };
  const latestJson = canonicalizeToString(latest);
  if (latestJson.length > LATEST_JSON_HARD_CEILING_BYTES) {
    return { skipped: true, reason: 'latest-json-too-large', publicIntelligenceVersion: manifest.publicIntelligenceVersion };
  }
  try {
    await writeJson(store, DATASET_LATEST_KEY, latest);
  } catch {
    return { skipped: true, reason: 'latest-write-failed', publicIntelligenceVersion: manifest.publicIntelligenceVersion };
  }

  return {
    skipped: false,
    publicIntelligenceVersion: manifest.publicIntelligenceVersion,
    publicStateHash: manifest.publicStateHash,
    publicStateFingerprint: latest.publicStateFingerprint,
    manifestContentHash,
  };
}

/**
 * Build the per-source observations for the source-health
 * blob. The observations are derived from the cache
 * states and the dataset envelope; the public state is
 * derived at request time from the persisted observations.
 */
function buildSourceHealthObservationsFromCaches({
  datasetEnvelope, vulnrichmentCache, githubAdvisoryCache, osvProjection, now,
}) {
  const fetchedAt = datasetEnvelope && datasetEnvelope.fetchedAt ? datasetEnvelope.fetchedAt : now.toISOString();
  const totalCount = datasetEnvelope && Array.isArray(datasetEnvelope.data) ? datasetEnvelope.data.length : 0;
  const enrichedNvd = (datasetEnvelope && datasetEnvelope.data
    ? datasetEnvelope.data.filter((r) => typeof r.cvssScore === 'number' && r.cvssScore > 0).length
    : 0);
  const enrichedEpss = (datasetEnvelope && datasetEnvelope.data
    ? datasetEnvelope.data.filter((r) => typeof r.epssProbability === 'number' && r.epssProbability > 0).length
    : 0);
  const enrichedSsvc = (datasetEnvelope && datasetEnvelope.data
    ? datasetEnvelope.data.filter((r) => typeof r.ssvcExploitation === 'string').length
    : 0);
  const enrichedGh = (datasetEnvelope && datasetEnvelope.data
    ? datasetEnvelope.data.filter((r) => r && r.githubAdvisory && r.githubAdvisory.ghsaId).length
    : 0);
  return {
    cisa_kev: {
      lastSuccessfulFetchAt: fetchedAt,
      lastAttemptedFetchAt: fetchedAt,
      lastAttemptOutcome: datasetEnvelope && datasetEnvelope.mode === 'live' ? 'success' : 'hard-failure',
      usableCoverage: datasetEnvelope && datasetEnvelope.mode === 'live' ? totalCount : 0,
      totalCoverage: totalCount,
      thresholdMinutes: 90,
      sanitizedReason: datasetEnvelope && datasetEnvelope.mode === 'live' ? null : 'CISA KEV was unreachable on the last attempt; existing data preserved.',
    },
    nvd: {
      lastSuccessfulFetchAt: fetchedAt,
      lastAttemptedFetchAt: fetchedAt,
      lastAttemptOutcome: datasetEnvelope && datasetEnvelope.nvdStatus === 'nvd' ? 'success' : (datasetEnvelope && datasetEnvelope.nvdStatus === 'unavailable' ? 'hard-failure' : 'success'),
      usableCoverage: enrichedNvd,
      totalCoverage: totalCount,
      thresholdMinutes: 90,
      sanitizedReason: datasetEnvelope && datasetEnvelope.nvdStatus === 'unavailable' ? (datasetEnvelope.nvdReason || 'NVD enrichment unavailable.') : null,
    },
    first_epss: {
      lastSuccessfulFetchAt: fetchedAt,
      lastAttemptedFetchAt: fetchedAt,
      lastAttemptOutcome: datasetEnvelope && datasetEnvelope.epssStatus === 'first' ? 'success' : (datasetEnvelope && datasetEnvelope.epssStatus === 'unavailable' ? 'hard-failure' : 'success'),
      usableCoverage: enrichedEpss,
      totalCoverage: totalCount,
      thresholdMinutes: 90,
      sanitizedReason: datasetEnvelope && datasetEnvelope.epssStatus === 'unavailable' ? (datasetEnvelope.epssReason || 'EPSS enrichment unavailable.') : null,
    },
    cisa_vulnrichment: {
      lastSuccessfulFetchAt: vulnrichmentCache && vulnrichmentCache.updatedAt ? vulnrichmentCache.updatedAt : null,
      lastAttemptedFetchAt: vulnrichmentCache && vulnrichmentCache.updatedAt ? vulnrichmentCache.updatedAt : null,
      lastAttemptOutcome: vulnrichmentCache && vulnrichmentCache.records && Object.keys(vulnrichmentCache.records).length > 0 ? 'soft-partial' : 'success',
      usableCoverage: enrichedSsvc,
      totalCoverage: totalCount,
      thresholdMinutes: 14 * 24 * 60,
      sanitizedReason: datasetEnvelope && datasetEnvelope.vulnrichmentStatus === 'partial' ? 'Incremental backfill in progress.' : null,
    },
    github_advisory: {
      lastSuccessfulFetchAt: githubAdvisoryCache && githubAdvisoryCache.updatedAt ? githubAdvisoryCache.updatedAt : null,
      lastAttemptedFetchAt: githubAdvisoryCache && githubAdvisoryCache.updatedAt ? githubAdvisoryCache.updatedAt : null,
      lastAttemptOutcome: githubAdvisoryCache && githubAdvisoryCache.records && Object.keys(githubAdvisoryCache.records).length > 0 ? 'soft-partial' : 'success',
      usableCoverage: enrichedGh,
      totalCoverage: totalCount,
      thresholdMinutes: 14 * 24 * 60,
      sanitizedReason: datasetEnvelope && datasetEnvelope.githubAdvisoryStatus === 'partial' ? 'Incremental backfill in progress.' : null,
    },
    osv: {
      lastSuccessfulFetchAt: osvProjection && osvProjection.generatedAt ? osvProjection.generatedAt : null,
      lastAttemptedFetchAt: osvProjection && osvProjection.generatedAt ? osvProjection.generatedAt : null,
      lastAttemptOutcome: osvProjection && osvProjection.osvProjectionVersion ? 'success' : 'hard-failure',
      usableCoverage: osvProjection && osvProjection.trackedCveCount ? osvProjection.trackedCveCount : 0,
      totalCoverage: totalCount,
      thresholdMinutes: 180,
      sanitizedReason: !osvProjection || !osvProjection.osvProjectionVersion ? 'OSV canonical baseline is not yet published.' : null,
    },
  };
}
