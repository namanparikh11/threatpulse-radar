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
 * precomputed, write-time-computed hash inputs. The
 * request path NEVER synchronously re-hashes the
 * complete Vulnrichment or GitHub Advisory caches —
 * the per-Blob public hashes are precomputed at write
 * time (see `computeEnrichmentPublicHash` callers in
 * `vulnrichmentRefresh.mjs` and
 * `githubAdvisoryRefresh.mjs`, and
 * `computeDatasetPublicHashForBlob` in `refresh.mjs`)
 * and stored in the envelope.
 *
 * Returns a structured result:
 *   {
 *     publicStateHash: string | null,  // null when any required hash is missing
 *     available: boolean,              // true iff all required hashes are present
 *     missingHashes: string[],         // names of missing required hashes
 *   }
 *
 * When any required stored hash is missing, the request
 * path MUST treat the public intelligence as unavailable
 * (`publicIntelligenceStatus: 'unavailable'` for the
 * default response; 503 with a sanitized error code for
 * the view modes). The full hash is NEVER recomputed
 * from the full cache on a normal dashboard request.
 *
 * Pre-V6.1 envelopes without stored hashes are upgraded
 * in the background dataset cycle (see
 * `upgradeLegacyEnvelopes` in
 * `v61BackgroundChain.mjs`); the next successful
 * refresh writes the hash atomically with the content.
 * Until that upgrade completes, the request path reports
 * `unavailable` — it does NOT guess or attach a stale
 * hash, and it does NOT perform full-cache
 * canonicalization.
 */
export function computeCurrentPublicStateHash({ datasetEnvelope, vulnrichmentCache, githubAdvisoryCache, osvProjection } = {}) {
  const missing = [];
  const datasetPublicHash = (datasetEnvelope && typeof datasetEnvelope.datasetPublicHash === 'string')
    ? datasetEnvelope.datasetPublicHash
    : (missing.push('datasetPublicHash'), null);
  const vulnrichmentPublicHash = (vulnrichmentCache && typeof vulnrichmentCache.vulnrichmentPublicHash === 'string')
    ? vulnrichmentCache.vulnrichmentPublicHash
    : (missing.push('vulnrichmentPublicHash'), null);
  const githubAdvisoryPublicHash = (githubAdvisoryCache && typeof githubAdvisoryCache.githubAdvisoryPublicHash === 'string')
    ? githubAdvisoryCache.githubAdvisoryPublicHash
    : (missing.push('githubAdvisoryPublicHash'), null);
  if (missing.length > 0) {
    return { publicStateHash: null, available: false, missingHashes: missing };
  }
  const referencedOsvProjectionVersion = osvProjection && osvProjection.osvProjectionVersion
    ? osvProjection.osvProjectionVersion
    : null;
  const referencedOsvProjectionContentHash = osvProjection && osvProjection.manifestContentHash
    ? osvProjection.manifestContentHash
    : null;
  return {
    publicStateHash: computePublicStateHash({
      datasetPublicHash,
      vulnrichmentPublicHash,
      githubAdvisoryPublicHash,
      referencedOsvProjectionVersion,
      referencedOsvProjectionContentHash,
    }),
    available: true,
    missingHashes: [],
  };
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
  //    precomputed, write-time-computed stored hashes. If
  //    any required stored hash is missing, the public
  //    intelligence is unavailable and we report 503. We
  //    do NOT fall back to re-hashing the full caches.
  const hashResult = computeCurrentPublicStateHash({
    datasetEnvelope, vulnrichmentCache, githubAdvisoryCache, osvProjection,
  });
  if (!hashResult.available) {
    return jsonResponse(503, { error: 'public-intelligence-unavailable', reason: 'missing-stored-hash' });
  }
  if (hashResult.publicStateHash !== latest.publicStateHash) {
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
  if (manifest.publicStateHash !== hashResult.publicStateHash) {
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
  const hashResult = computeCurrentPublicStateHash({
    datasetEnvelope, vulnrichmentCache, githubAdvisoryCache, osvProjection,
  });
  if (!hashResult.available) {
    return jsonResponse(503, { error: 'public-intelligence-unavailable', reason: 'missing-stored-hash' });
  }
  if (hashResult.publicStateHash !== latest.publicStateHash) {
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
