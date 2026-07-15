/**
 * V6.1 — Public dataset read modes.
 *
 * Three read modes are supported by extending the
 * existing `dataset.mjs` function (NO new function
 * entry file):
 *
 *   1. Default (no `view` query param) — the V5.7-
 *      compatible public dataset envelope with V6.1
 *      additions (sources, changeSummary, public
 *      intelligence status). The V5.7 public surface
 *      is preserved; the new fields are additive.
 *
 *   2. `view=osv` — returns the bounded per-CVE OSV
 *      public projection for one CVE. Validates that
 *      the requested version matches the currently-
 *      attached dataset-bound version. Reads the
 *      immutable OSV shard by content hash.
 *
 *   3. `view=changes` — returns the per-category
 *      change items for the currently-attached version.
 *      Bounded to a maximum of 25 items per request.
 *
 * Sanitized error responses only. No internal fields.
 * No upstream provider calls. No canonical-baseline
 * reads.
 *
 * The retained previous and rollback versions are
 * server-side only; query modes accept only the
 * currently-attached version. Arbitrary retained-
 * version browsing is not exposed.
 */

import {
  getPublicIntelligenceStore,
  DATASET_LATEST_KEY,
  datasetManifestKey,
  datasetChangesKey,
  readJson,
  osvShardKey,
  osvManifestKey,
  OSV_SHARDS_DIR,
  OSV_LATEST_KEY,
} from './publicIntelligenceStore.mjs';
import {
  computePublicStateHash,
  computeDatasetPublicHash,
  computeEnrichmentPublicHash,
  derivePublicIntelligenceVersion,
  PUBLIC_PROJECTION_SCHEMA_VERSION,
  PUBLIC_STATE_SCHEMA_VERSION,
} from './publicIntelligenceHash.mjs';
import {
  gunzipValue,
} from './publicIntelligenceCompression.mjs';
import {
  validateView,
  validateVersion,
  validateCve,
  validateCategory,
  validateLimit,
  validateBucket,
} from './publicIntelligenceValidation.mjs';
import { CHANGES_ITEMS_MAX_LIMIT } from './publicIntelligenceSize.mjs';
import { cveBucketNormalized } from './publicIntelligenceBucket.mjs';
import { buildPublicSourceHealth } from './sourceHealth.mjs';
import { filterByCategory } from './changeIntelligence.mjs';

/**
 * Read the current public-intelligence latest.json
 * pointer. Returns null when missing.
 */
async function readDatasetLatest(store) {
  return readJson(store, DATASET_LATEST_KEY);
}

/**
 * Compute the current publicStateHash from the four
 * currently-served state pieces. The dataset public
 * hash is read from the envelope's `datasetPublicHash`
 * internal field (already precomputed at write time);
 * the enrichment cache hashes are computed from the
 * publicly-projected `records` map.
 */
export function computeCurrentPublicStateHash({ datasetEnvelope, vulnrichmentCache, githubAdvisoryCache, osvProjection } = {}) {
  return computePublicStateHash({
    datasetPublicHash: datasetEnvelope && datasetEnvelope.datasetPublicHash
      ? datasetEnvelope.datasetPublicHash
      : computeDatasetPublicHash(datasetEnvelope),
    vulnrichmentPublicHash: computeEnrichmentPublicHash(vulnrichmentCache),
    githubAdvisoryPublicHash: computeEnrichmentPublicHash(githubAdvisoryCache),
    referencedOsvProjectionVersion: osvProjection && osvProjection.osvProjectionVersion
      ? osvProjection.osvProjectionVersion
      : null,
    referencedOsvProjectionContentHash: osvProjection && osvProjection.manifestContentHash
      ? osvProjection.manifestContentHash
      : null,
  });
}

/**
 * Sanitized JSON response helper.
 */
function jsonResponse(status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'X-Content-Type-Options': 'nosniff',
    },
  });
}

/**
 * Handle `view=osv` mode. Validates the parameters,
 * enforces the current-version-only rule, and returns
 * the per-CVE OSV public projection.
 */
export async function readOsvView({
  store, datasetEnvelope, vulnrichmentCache, githubAdvisoryCache, osvProjection,
  versionParam, cveParam, bucketParam,
} = {}) {
  // 1. Validate parameters
  if (!store) {
    return jsonResponse(503, { error: 'public-intelligence-unavailable' });
  }
  const version = validateVersion(versionParam);
  if (!version) return jsonResponse(400, { error: 'invalid-version' });
  const cve = validateCve(cveParam);
  if (!cve) return jsonResponse(400, { error: 'invalid-cve' });

  // 2. Read the latest.json pointer
  const latest = await readDatasetLatest(store);
  if (!latest) {
    return jsonResponse(503, { error: 'public-intelligence-unavailable' });
  }

  // 3. Compute the current publicStateHash from the four
  //    currently-served state pieces.
  const currentPublicStateHash = computeCurrentPublicStateHash({
    datasetEnvelope, vulnrichmentCache, githubAdvisoryCache, osvProjection,
  });
  if (currentPublicStateHash !== latest.publicStateHash) {
    return jsonResponse(503, { error: 'public-state-drift' });
  }

  // 4. Require the requested version to match the
  //    currently-attached version.
  if (version !== latest.publicIntelligenceVersion) {
    return jsonResponse(409, {
      error: 'version-mismatch',
      currentVersion: latest.publicIntelligenceVersion,
    });
  }

  // 5. Read the dataset-bound manifest.
  const manifest = await readJson(store, datasetManifestKey(version));
  if (!manifest) {
    return jsonResponse(503, { error: 'immutable-projection-unavailable' });
  }
  if (manifest.publicStateHash !== currentPublicStateHash) {
    return jsonResponse(503, { error: 'immutable-projection-unavailable' });
  }

  // 6. Compute the OSV bucket from the CVE id.
  const bucket = bucketParam ? validateBucket(bucketParam) : cveBucketNormalized(cve);
  if (!bucket) return jsonResponse(400, { error: 'invalid-cve' });

  // 7. Read the referenced OSV version manifest. The
  //    dataset-bound manifest references the OSV version
  //    but the bucket map lives in the OSV version's own
  //    manifest (per the V6.1 OSV publication contract).
  const osvVersion = manifest.referencedOsvProjectionVersion;
  if (!osvVersion) {
    return jsonResponse(503, { error: 'immutable-projection-unavailable' });
  }
  const osvManifestKeyStr = osvManifestKey(osvVersion);
  const osvManifest = await readJson(store, osvManifestKeyStr);
  if (!osvManifest || typeof osvManifest !== 'object') {
    return jsonResponse(503, { error: 'immutable-projection-unavailable' });
  }
  const bucketInfo = osvManifest.buckets && osvManifest.buckets[bucket];
  if (!bucketInfo || !bucketInfo.contentHash) {
    // The OSV projection has no records for this CVE at
    // the current version (the bucket exists but is
    // empty, or the bucket is missing entirely). The
    // caller treats this as 404.
    return jsonResponse(404, { error: 'not-found' });
  }

  // 8. Read the OSV shard by its content-addressed key.
  const shardKey = osvShardKey(bucketInfo.contentHash);
  const shardGz = await store.get(shardKey, { type: 'arrayBuffer' });
  if (!shardGz) {
    return jsonResponse(503, { error: 'immutable-projection-unavailable' });
  }
  const shardJson = gunzipValue(shardGz);
  if (!shardJson || typeof shardJson !== 'object' || !shardJson.byCve) {
    return jsonResponse(503, { error: 'immutable-projection-unavailable' });
  }
  const cveRecord = shardJson.byCve[cve];
  if (!cveRecord) {
    return jsonResponse(404, { error: 'not-found' });
  }

  return jsonResponse(200, {
    osv: cveRecord,
    publicIntelligenceVersion: version,
    bucket,
    truncation: cveRecord.truncation || { recordsRemoved: 0 },
  });
}

/**
 * Handle `view=changes` mode. Returns the per-category
 * change items for the currently-attached version.
 */
export async function readChangesView({
  store, datasetEnvelope, vulnrichmentCache, githubAdvisoryCache, osvProjection,
  versionParam, categoryParam, limitParam,
} = {}) {
  if (!store) {
    return jsonResponse(503, { error: 'public-intelligence-unavailable' });
  }
  const version = validateVersion(versionParam);
  if (!version) return jsonResponse(400, { error: 'invalid-version' });
  const category = validateCategory(categoryParam);
  if (!category) return jsonResponse(400, { error: 'invalid-category' });
  const limit = validateLimit(limitParam, CHANGES_ITEMS_MAX_LIMIT);
  if (limit === null) return jsonResponse(400, { error: 'invalid-limit' });

  const latest = await readDatasetLatest(store);
  if (!latest) {
    return jsonResponse(503, { error: 'public-intelligence-unavailable' });
  }
  const currentPublicStateHash = computeCurrentPublicStateHash({
    datasetEnvelope, vulnrichmentCache, githubAdvisoryCache, osvProjection,
  });
  if (currentPublicStateHash !== latest.publicStateHash) {
    return jsonResponse(503, { error: 'public-state-drift' });
  }
  if (version !== latest.publicIntelligenceVersion) {
    return jsonResponse(409, {
      error: 'version-mismatch',
      currentVersion: latest.publicIntelligenceVersion,
    });
  }

  const changesGz = await store.get(datasetChangesKey(version), { type: 'arrayBuffer' });
  if (!changesGz) {
    // No changes blob at this version (empty change
    // intelligence — e.g. first run or no changes).
    return jsonResponse(200, {
      items: [],
      totalMatching: 0,
      truncated: { shown: 0, total: 0 },
      publicIntelligenceVersion: version,
    });
  }
  const changesJson = gunzipValue(changesGz);
  if (!changesJson || !Array.isArray(changesJson.items)) {
    return jsonResponse(503, { error: 'immutable-projection-unavailable' });
  }
  const filtered = filterByCategory(changesJson.items, category, limit);
  return jsonResponse(200, {
    ...filtered,
    publicIntelligenceVersion: version,
  });
}

/**
 * Detect whether a request is a V6.1 view-mode request.
 * Returns the view name (lowercase) or null.
 */
export function detectViewMode(request) {
  let url = null;
  try {
    if (request && typeof request.url === 'string') url = new URL(request.url);
  } catch {
    return null;
  }
  if (!url) return null;
  const view = url.searchParams.get('view');
  if (!view) return null;
  return validateView(view);
}

/**
 * Read query parameters for a view-mode request.
 */
export function readViewParams(request) {
  let url = null;
  try {
    if (request && typeof request.url === 'string') url = new URL(request.url);
  } catch {
    return {};
  }
  if (!url) return {};
  return {
    versionParam: url.searchParams.get('version'),
    cveParam: url.searchParams.get('cve'),
    bucketParam: url.searchParams.get('bucket'),
    categoryParam: url.searchParams.get('category'),
    limitParam: url.searchParams.get('limit'),
  };
}
