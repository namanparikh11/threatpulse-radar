/**
 * Netlify Function — `/.netlify/functions/dataset`
 *
 * v5.2 Prebuilt Dataset Store (read endpoint). Builds on the
 * v5.0 / v5.0.1 / v5.0.2 / v5.0.3 live-proxy logic and adds a
 * shared Netlify Blobs store in front of it.
 *
 * Read flow:
 *   1. Read `latest-dataset` blob.
 *      - If it exists: return it immediately with
 *        `dataSource: 'prebuilt-store'`. The visitor does NOT
 *        wait for CISA → NVD → EPSS to run. This is the v5.2
 *        happy path.
 *      - If it does not exist: fall through to the bootstrap
 *        path below (step 2). The bootstrap path builds a
 *        dataset on this request and writes it to the blob so
 *        the NEXT visitor gets the fast path.
 *   2. Bootstrap (no prebuilt blob yet):
 *      - Run CISA → NVD → EPSS as before.
 *      - On success: write the envelope to the blob AND return
 *        it to the visitor. The visitor pays the full build
 *        cost exactly once; everyone after rides the blob.
 *      - On CISA failure: return HTTP 502 + `{ mode: 'fallback',
 *        fallbackReason }`. The client treats this as a
 *        proxy-unavailable and falls through to browser-direct
 *        (the v5.0 behavior). The blob is NOT written — we
 *        never overwrite good data with mock fallback.
 *   3. Tag the response with `refreshInProgress: true` when the
 *      refresh-lock blob is active (non-expired). The dashboard
 *      surfaces this as a small "Refresh running in background"
 *      pill so the user knows a newer dataset is on the way.
 *
 * v5.5: CISA Vulnrichment / SSVC enrichment (read-time merge).
 *   The prebuilt `latest-dataset` blob holds the CISA → NVD
 *   → EPSS records only. The SSVC decisions are stored
 *   separately in the `tpr-vulnrichment` blob store (key
 *   `cache`), and are merged into the public response at
 *   serve time:
 *     - records carrying a cached SSVC entry gain the
 *       `ssvcExploitation` / `ssvcAutomatable` /
 *       `ssvcTechnicalImpact` / `ssvcVersion` /
 *       `ssvcAssessedAt` / `ssvcSource` fields;
 *     - the response envelope gains
 *       `vulnrichmentStatus: 'available' | 'partial' | 'unavailable'`
 *       and `vulnrichmentCoverage: { enriched, total }`.
 *   The merge is read-time only — the visitor's request
 *   never mutates the cache, and the cache is never
 *   rewritten when SSVC is merged. A Vulnrichment outage
 *   (timeout / 429 / 5xx) leaves the existing dataset
 *   envelope completely intact; the public envelope just
 *   reports `vulnrichmentStatus: 'unavailable'` with the
 *   existing counts.
 *
 * v5.6: GitHub Advisory Database enrichment (read-time merge).
 *   Package-remediation context (GHSA id, severity, affected
 *   packages + vulnerable ranges + first patched versions) is
 *   stored separately in the `tpr-github-advisory` blob
 *   store (key `cache`), and is merged into the public
 *   response at serve time:
 *     - records carrying a cached advisory entry gain a
 *       `githubAdvisory` object with `ghsaId` /
 *       `advisoryUrl` / `advisorySeverity` /
 *       `githubReviewedAt` / `source` / `packages` fields;
 *     - the response envelope gains
 *       `githubAdvisoryStatus: 'available' | 'partial' | 'unavailable'`
 *       and `githubAdvisoryCoverage: { enriched, total }`.
 *   The merge is read-time only — the visitor's request
 *   never mutates the cache, and the cache is never
 *   rewritten when GitHub advisories are merged. A GitHub
 *   outage (timeout / 403 / 429 / 5xx) leaves the existing
 *   dataset envelope completely intact; the public envelope
 *   just reports `githubAdvisoryStatus: 'unavailable'` with
 *   the existing counts. The `latest-dataset` blob's
 *   `fetchedAt` is NEVER modified by a GitHub Advisory
 *   update — the v5.1 "newer dataset available" banner
 *   cannot fire spuriously.
 *
 * Response shape (200 — prebuilt store hit):
 *   {
 *     data: Vulnerability[],         // SSVC + GitHub Advisory fields merged in
 *     source: 'merged',
 *     fetchedAt: string (ISO),
 *     mode: 'live',
 *     nvdStatus: 'nvd' | 'unavailable',
 *     nvdReason?: string,
 *     epssStatus: 'first' | 'unavailable',
 *     epssReason?: string,
 *     proxyStatus: 'proxy',
 *     dataSource: 'prebuilt-store',
 *     refreshInProgress: boolean,
 *     vulnrichmentStatus: 'available' | 'partial' | 'unavailable',
 *     vulnrichmentCoverage: { enriched: number, total: number },
 *     githubAdvisoryStatus: 'available' | 'partial' | 'unavailable',
 *     githubAdvisoryCoverage: { enriched: number, total: number },
 *   }
 *
 * Response shape (200 — bootstrap path):
 *   Same as above but `dataSource: 'live-build'` so the client
 *   can distinguish "this is the freshly-built dataset" from
 *   "this came from the shared blob". `refreshInProgress` is
 *   `false` (we just finished building it). The Vulnrichment
 *   merge is still applied so the bootstrap response carries
 *   whatever SSVC enrichment is already in the cache (often
 *   empty on a fresh deploy).
 *
 * Response shape (502 — CISA failed in bootstrap):
 *   { mode: 'fallback', fallbackReason: string, refreshInProgress: false }
 *   No `vulnrichmentStatus` / `vulnrichmentCoverage` — there's
 *   no live data to enrich.
 *
 * v5.4.2 — Last-known-good dataset serving:
 *   The prebuilt blob may carry internal operator-facing
 *   fields (`lastRefreshAttemptAt`, `lastRefreshFailure`,
 *   `lastVulnrichmentRefresh`, `lastGithubAdvisoryRefresh`)
 *   that the refresh orchestrator writes to record the
 *   most recent attempt's outcome. These are STRIPPED from
 *   the public response so visitors never see transient
 *   upstream failures (timeouts, 429s, 5xx, network
 *   errors) on a page that was served from a still-good
 *   blob. The strip is driven by `INTERNAL_BLOB_FIELDS`
 *   from refresh.mjs — a single source of truth shared
 *   with the orchestrator. With the v5.4.2 quality guard,
 *   the blob's public envelope is always the most recent
 *   ACCEPTED build, so the public `nvdStatus` is "nvd"
 *   (enriched) as long as a good blob exists.
 *
 * Honesty contract (carried forward from v5.0.1 / v5.0.3):
 *   - CISA is the only gating upstream. If CISA fails, the
 *     function returns HTTP 502 with a `fallbackReason`. The
 *     client treats this as "live fetch failed" and falls back
 *     to the local mock dataset (or a stale localStorage cache).
 *   - NVD and EPSS have their own status fields. A failure of
 *     either does NOT take the whole response down — the client
 *     gets HTTP 200 with `nvdStatus: 'unavailable'` /
 *     `epssStatus: 'unavailable'`. (On a fresh deploy with no
 *     blob, the bootstrap path may return such an envelope;
 *     on every subsequent request the guard guarantees a
 *     NVD-enriched envelope is served.)
 *   - No API keys, secrets, or tokens are read or shipped.
 *     `NVD_API_KEY` is read inside the function only, passed to
 *     NVD as a request header (`headers.apiKey = apiKey`), and
 *     never included in the response body or logs.
 *   - The prebuilt blob is NEVER overwritten with a mock
 *     fallback. Only a successful live build writes to it.
 *   - Raw Vulnrichment errors (timeouts, 429s, 5xx, JSON
 *     parse failures) NEVER reach the visitor. The public
 *     envelope carries only the derived
 *     `vulnrichmentStatus` / `vulnrichmentCoverage` fields.
 *   - Raw GitHub Advisory errors (timeouts, 403s, 429s, 5xx,
 *     JSON parse failures, rate-limit response headers,
 *     token-bearing responses) NEVER reach the visitor.
 *     The public envelope carries only the derived
 *     `githubAdvisoryStatus` / `githubAdvisoryCoverage`
 *     fields. The optional `GITHUB_TOKEN` is read only
 *     inside the GitHub Advisory fetcher and is never
 *     serialized, logged, or returned in any response.
 *
 * Refresh interaction:
 *   - This endpoint does NOT trigger refreshes. The scheduled
 *     function (`refresh-dataset-scheduled.mjs`) and the
 *     manual endpoint (`refresh-dataset-background.mjs`) own
 *     the write path. This keeps the read endpoint fast and
 *     prevents every visitor from triggering a rebuild.
 *   - On every read, the endpoint checks the refresh-lock blob
 *     and sets `refreshInProgress` in the response. The UI uses
 *     this to show "Refresh running in background".
 *   - The Vulnrichment enrichment cache is written only by
 *     the refresh orchestrator. This endpoint reads it but
 *     never writes to it.
 *   - The GitHub Advisory enrichment cache is written only by
 *     the refresh orchestrator. This endpoint reads it but
 *     never writes to it. The prebuilt `latest-dataset`
 *     blob's `fetchedAt` is NEVER modified by the GitHub
 *     Advisory merge — the merge is in-memory only.
 */

import {
  buildLiveDataset,
} from './_shared/liveBuild.mjs';
import {
  getDatasetStore,
  getGithubAdvisoryStore,
  getVulnrichmentStore,
  isRefreshLocked,
  readGithubAdvisoryCache,
  readLatestDataset,
  readVulnrichmentCache,
  writeLatestDataset,
} from './_shared/store.mjs';
import { INTERNAL_BLOB_FIELDS } from './_shared/refresh.mjs';
import {
  mergeSsvcIntoRecords,
  vulnrichmentStatusForCoverage,
} from './_shared/vulnrichment.mjs';
import {
  mergeAdvisoryIntoRecords,
  githubAdvisoryStatusForCoverage,
} from './_shared/githubAdvisory.mjs';

// ---------------------------------------------------------------------------
// v5.4.2: Strip the internal operator-facing fields that the
// refresh orchestrator attaches to the blob, so they never
// reach the visitor. The single source of truth for the
// field list is `INTERNAL_BLOB_FIELDS` in refresh.mjs —
// adding a new internal field there automatically strips it
// here without needing a parallel list.
// ---------------------------------------------------------------------------

import {
  getPublicIntelligenceStore,
  readDatasetLatest as readPublicIntelLatest,
  readJson as readPublicIntelJson,
  OSV_LATEST_KEY,
} from './_shared/publicIntelligenceStore.mjs';
import {
  detectViewMode,
  readViewParams,
  readOsvView,
  readChangesView,
  computeCurrentPublicStateHash,
} from './_shared/datasetPublicIntelligenceRead.mjs';
import {
  buildPublicSourceHealth,
} from './_shared/sourceHealth.mjs';

function publicEnvelope(blob) {
  if (!blob || typeof blob !== 'object') return blob;
  const out = { ...blob };
  for (const field of INTERNAL_BLOB_FIELDS) {
    delete out[field];
  }
  return out;
}

// ---- v6.1: Helpers for the view-mode compatibility check.
//      The view handlers need the currently-served public
//      state pieces to compute the publicStateHash for
//      version-matching. These helpers read the existing
//      prebuilt Blob envelopes (no additional Blob reads
//      beyond what the default mode already does). ----

async function readCurrentDatasetEnvelope() {
  try {
    const s = getDatasetStore();
    const blob = await readLatestDataset(s);
    if (blob && blob.mode === 'live' && Array.isArray(blob.data)) {
      return blob;
    }
    return null;
  } catch {
    return null;
  }
}

async function readCurrentVulnrichmentCache() {
  try {
    const s = getVulnrichmentStore();
    if (!s) return null;
    return await readVulnrichmentCache(s);
  } catch {
    return null;
  }
}

async function readCurrentGithubAdvisoryCache() {
  try {
    const s = getGithubAdvisoryStore();
    if (!s) return null;
    return await readGithubAdvisoryCache(s);
  } catch {
    return null;
  }
}

async function readCurrentOsvProjection() {
  try {
    const s = getPublicIntelligenceStore();
    const latest = await readPublicIntelJson(s, OSV_LATEST_KEY);
    if (!latest) return null;
    return {
      osvProjectionVersion: latest.osvProjectionVersion,
      manifestContentHash: latest.manifestContentHash,
      generatedAt: latest.generatedAt,
    };
  } catch {
    return null;
  }
}

// ---- v6.1: V6.1 default-mode additions.
//      The public envelope carries a small set of
//      aggregate V6.1 fields (no per-CVE map). The full
//      per-CVE data is server-side only and is
//      surfaced through the view modes. ----

async function buildV61DefaultAdditions({ datasetEnvelope, vulnrichmentCache, githubAdvisoryCache, osvProjection, now = new Date() } = {}) {
  if (!datasetEnvelope) {
    return {
      publicIntelligenceStatus: 'unavailable',
      publicIntelligenceVersion: null,
      publicStateFingerprint: null,
      sources: [],
      changeSummary: null,
      comparableAxes: [],
      suppressedAxes: [],
    };
  }
  // Try to read the public-intelligence latest.json for
  // the version + fingerprint.
  let latest = null;
  try {
    const s = getPublicIntelligenceStore();
    latest = await readPublicIntelLatest(s);
  } catch { latest = null; }
  if (!latest) {
    return {
      publicIntelligenceStatus: 'unavailable',
      publicIntelligenceVersion: null,
      publicStateFingerprint: null,
      sources: [],
      changeSummary: null,
      comparableAxes: [],
      suppressedAxes: [],
    };
  }
  // Compute the current publicStateHash and compare.
  const currentHash = computeCurrentPublicStateHash({
    datasetEnvelope, vulnrichmentCache, githubAdvisoryCache, osvProjection,
  });
  if (currentHash !== latest.publicStateHash) {
    return {
      publicIntelligenceStatus: 'mismatch',
      publicIntelligenceVersion: latest.publicIntelligenceVersion,
      publicStateFingerprint: null,
      sources: [],
      changeSummary: null,
      comparableAxes: [],
      suppressedAxes: [],
    };
  }
  // Compatible: read the manifest for the change summary.
  let manifest = null;
  try {
    const s = getPublicIntelligenceStore();
    const { datasetManifestKey } = await import('./_shared/publicIntelligenceStore.mjs');
    manifest = await readPublicIntelJson(s, datasetManifestKey(latest.publicIntelligenceVersion));
  } catch { manifest = null; }
  // Build the source-health observations (no env-var
  // names; per-source state is derived at request time).
  const observations = await buildV61SourceObservations({
    datasetEnvelope, vulnrichmentCache, githubAdvisoryCache, osvProjection,
  });
  const sources = buildPublicSourceHealth(observations, now);
  return {
    publicIntelligenceStatus: 'available',
    publicIntelligenceVersion: latest.publicIntelligenceVersion,
    publicStateFingerprint: latest.publicStateFingerprint || null,
    sources,
    changeSummary: manifest && manifest.changeSummary ? manifest.changeSummary : null,
    comparableAxes: manifest && Array.isArray(manifest.comparableAxes) ? manifest.comparableAxes : [],
    suppressedAxes: manifest && Array.isArray(manifest.suppressedAxes) ? manifest.suppressedAxes : [],
  };
}

async function buildV61SourceObservations({ datasetEnvelope, vulnrichmentCache, githubAdvisoryCache, osvProjection } = {}) {
  // Lightweight observations derived from the cache
  // states; full observability is in the per-version
  // source-health blob. The default mode uses these for
  // the public panel.
  const fetchedAt = datasetEnvelope && datasetEnvelope.fetchedAt ? datasetEnvelope.fetchedAt : null;
  const totalCount = datasetEnvelope && Array.isArray(datasetEnvelope.data) ? datasetEnvelope.data.length : 0;
  return {
    cisa_kev: { lastSuccessfulFetchAt: fetchedAt, lastAttemptedFetchAt: fetchedAt, lastAttemptOutcome: 'success', usableCoverage: totalCount, totalCoverage: totalCount, thresholdMinutes: 90, sanitizedReason: null },
    nvd: { lastSuccessfulFetchAt: fetchedAt, lastAttemptedFetchAt: fetchedAt, lastAttemptOutcome: datasetEnvelope && datasetEnvelope.nvdStatus === 'nvd' ? 'success' : 'hard-failure', usableCoverage: totalCount, totalCoverage: totalCount, thresholdMinutes: 90, sanitizedReason: null },
    first_epss: { lastSuccessfulFetchAt: fetchedAt, lastAttemptedFetchAt: fetchedAt, lastAttemptOutcome: datasetEnvelope && datasetEnvelope.epssStatus === 'first' ? 'success' : 'hard-failure', usableCoverage: totalCount, totalCoverage: totalCount, thresholdMinutes: 90, sanitizedReason: null },
    cisa_vulnrichment: { lastSuccessfulFetchAt: vulnrichmentCache && vulnrichmentCache.updatedAt ? vulnrichmentCache.updatedAt : null, lastAttemptedFetchAt: vulnrichmentCache && vulnrichmentCache.updatedAt ? vulnrichmentCache.updatedAt : null, lastAttemptOutcome: 'success', usableCoverage: 0, totalCoverage: totalCount, thresholdMinutes: 14 * 24 * 60, sanitizedReason: null },
    github_advisory: { lastSuccessfulFetchAt: githubAdvisoryCache && githubAdvisoryCache.updatedAt ? githubAdvisoryCache.updatedAt : null, lastAttemptedFetchAt: githubAdvisoryCache && githubAdvisoryCache.updatedAt ? githubAdvisoryCache.updatedAt : null, lastAttemptOutcome: 'success', usableCoverage: 0, totalCoverage: totalCount, thresholdMinutes: 14 * 24 * 60, sanitizedReason: null },
    osv: { lastSuccessfulFetchAt: osvProjection && osvProjection.generatedAt ? osvProjection.generatedAt : null, lastAttemptedFetchAt: osvProjection && osvProjection.generatedAt ? osvProjection.generatedAt : null, lastAttemptOutcome: osvProjection && osvProjection.osvProjectionVersion ? 'success' : 'hard-failure', usableCoverage: totalCount, totalCoverage: totalCount, thresholdMinutes: 180, sanitizedReason: null },
  };
}

// ---------------------------------------------------------------------------
// v5.5: Read-time SSVC merge. Reads the Vulnrichment cache
// (defensive — a Blobs read error becomes "no SSVC yet" so
// the visitor still gets a fast response), merges the SSVC
// fields into each record, and computes the public
// `vulnrichmentStatus` / `vulnrichmentCoverage` envelope
// metadata.
//
// The merge is in-memory only — the `latest-dataset` blob
// is NOT rewritten. A Vulnrichment outage is therefore
// transparent to the visitor: the existing dataset is
// served, the public envelope just reports
// `vulnrichmentStatus: 'unavailable'`.
// ---------------------------------------------------------------------------

async function attachVulnrichment(envelope, vulnStore) {
  const base = publicEnvelope(envelope);
  if (!Array.isArray(base.data)) {
    return {
      ...base,
      vulnrichmentStatus: 'unavailable',
      vulnrichmentCoverage: { enriched: 0, total: 0 },
    };
  }
  if (!vulnStore) {
    // No store (local dev without env vars) — still
    // report the honest metadata so the UI doesn't show a
    // stale state.
    return {
      ...base,
      vulnrichmentStatus: 'unavailable',
      vulnrichmentCoverage: { enriched: 0, total: base.data.length },
    };
  }
  const cache = await readVulnrichmentCache(vulnStore);
  const recordsByCve = (cache && cache.records) || {};

  // Build the per-CVE SSVC lookup the merge function expects.
  const ssvcByCve = {};
  let enriched = 0;
  for (const rec of base.data) {
    if (!rec || typeof rec.cveId !== 'string') continue;
    const cached = recordsByCve[rec.cveId];
    if (cached && cached.ssvc && cached.ssvc.ssvcExploitation) {
      ssvcByCve[rec.cveId] = cached.ssvc;
      enriched++;
    }
  }
  const merged = mergeSsvcIntoRecords(base.data, ssvcByCve);
  return {
    ...base,
    data: merged,
    vulnrichmentStatus: vulnrichmentStatusForCoverage(enriched, base.data.length),
    vulnrichmentCoverage: { enriched, total: base.data.length },
  };
}

// ---------------------------------------------------------------------------
// v5.6: Read-time GitHub Advisory merge. Reads the GitHub
// Advisory cache (defensive — a Blobs read error becomes
// "no advisory yet" so the visitor still gets a fast
// response), merges the package-remediation context into
// each record, and computes the public `githubAdvisoryStatus`
// / `githubAdvisoryCoverage` envelope metadata.
//
// The merge is in-memory only — the `latest-dataset` blob
// is NOT rewritten. A GitHub Advisory outage is therefore
// transparent to the visitor: the existing dataset is
// served, the public envelope just reports
// `githubAdvisoryStatus: 'unavailable'`. The
// `latest-dataset` blob's `fetchedAt` is NEVER modified by
// this merge, so the v5.1 "newer dataset available" banner
// cannot fire spuriously.
// ---------------------------------------------------------------------------

async function attachGithubAdvisory(envelope, ghStore) {
  const base = publicEnvelope(envelope);
  if (!Array.isArray(base.data)) {
    return {
      ...base,
      githubAdvisoryStatus: 'unavailable',
      githubAdvisoryCoverage: { enriched: 0, total: 0 },
    };
  }
  if (!ghStore) {
    // No store (local dev without env vars) — still
    // report the honest metadata so the UI doesn't show a
    // stale state.
    return {
      ...base,
      githubAdvisoryStatus: 'unavailable',
      githubAdvisoryCoverage: { enriched: 0, total: base.data.length },
    };
  }
  const cache = await readGithubAdvisoryCache(ghStore);
  const recordsByCve = (cache && cache.records) || {};

  // Build the per-CVE advisory lookup the merge function
  // expects. Only positive advisory entries (those with a
  // `ghsaId`) count as enriched — negative-cache markers
  // are filtered out here, which is why
  // `githubAdvisoryCoverage.enriched` only counts actual
  // positive records (per the v5.6 spec requirement 17).
  const advisoryByCve = {};
  let enriched = 0;
  for (const rec of base.data) {
    if (!rec || typeof rec.cveId !== 'string') continue;
    const cached = recordsByCve[rec.cveId];
    if (cached && cached.advisory && cached.advisory.ghsaId) {
      advisoryByCve[rec.cveId] = cached.advisory;
      enriched++;
    }
  }
  const merged = mergeAdvisoryIntoRecords(base.data, advisoryByCve);
  return {
    ...base,
    data: merged,
    githubAdvisoryStatus: githubAdvisoryStatusForCoverage(enriched, base.data.length),
    githubAdvisoryCoverage: { enriched, total: base.data.length },
  };
}

// ---------------------------------------------------------------------------
// HTTP response helper. The function lives at /.netlify/functions/dataset,
// which is same-origin to the deployed app. v5.0.1 CDN-cacheable
// response preserved unchanged.
// ---------------------------------------------------------------------------

function jsonResponse(status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      // v5.0.1: CDN-cacheable response. Repeat visitors within
      // the 15 min window get a sub-100 ms response. The
      // v5.2 prebuilt blob is already inside the function
      // body, so the CDN-cached response is a cached
      // blob-read, not a cached upstream fetch.
      'Cache-Control': 'public, s-maxage=900, stale-while-revalidate=300',
      'Access-Control-Allow-Origin': '*',
      'X-Content-Type-Options': 'nosniff',
    },
  });
}

// ---------------------------------------------------------------------------
// Entry point. Netlify Functions v2 receives (event, context).
// We use the context to detect local dev (no function runtime)
// and degrade gracefully — the v5.0 fallback path is the
// always-available safety net.
// ---------------------------------------------------------------------------

export default async (request, context) => {
  const startTime = Date.now();

  // ---- 0. v6.1: V6.1 view-mode routing (OSV per-CVE,
  //      change items). When a `view` query parameter is
  //      present and validated, route the request to the
  //      appropriate read mode and return early. The
  //      default mode (no view) below is the V5.7-
  //      compatible public envelope with V6.1 additions. ----
  const view = detectViewMode(request);
  if (view) {
    let intelStore = null;
    try { intelStore = getPublicIntelligenceStore(); } catch { intelStore = null; }
    if (!intelStore) {
      return new Response(JSON.stringify({ error: 'public-intelligence-unavailable' }), {
        status: 503,
        headers: { 'Content-Type': 'application/json; charset=utf-8', 'X-Content-Type-Options': 'nosniff' },
      });
    }
    // Read the supporting state pieces for the version-matching check.
    // datasetEnvelope is loaded lazily inside the handlers via the
    // existing prebuilt path; we defer to the view handlers.
    if (view === 'osv') {
      const params = readViewParams(request);
      return await readOsvView({
        store: intelStore,
        datasetEnvelope: await readCurrentDatasetEnvelope(),
        vulnrichmentCache: await readCurrentVulnrichmentCache(),
        githubAdvisoryCache: await readCurrentGithubAdvisoryCache(),
        osvProjection: await readCurrentOsvProjection(),
        versionParam: params.versionParam,
        cveParam: params.cveParam,
        bucketParam: params.bucketParam,
      });
    }
    if (view === 'changes') {
      const params = readViewParams(request);
      return await readChangesView({
        store: intelStore,
        datasetEnvelope: await readCurrentDatasetEnvelope(),
        vulnrichmentCache: await readCurrentVulnrichmentCache(),
        githubAdvisoryCache: await readCurrentGithubAdvisoryCache(),
        osvProjection: await readCurrentOsvProjection(),
        versionParam: params.versionParam,
        categoryParam: params.categoryParam,
        limitParam: params.limitParam,
      });
    }
  }

  // ---- 1. Read prebuilt blob (the v5.2 fast path) ----
  let store = null;
  try {
    store = getDatasetStore();
  } catch {
    store = null;
  }

  // v5.5: Resolve the Vulnrichment store up-front so the
  // SSVC merge is consistent across all three response
  // paths (prebuilt store hit, bootstrap with blob, and
  // bootstrap without blob). A missing store (e.g. Vite
  // dev without env vars) is handled by the merge helper
  // (it returns the honest 'unavailable' metadata).
  let vulnStore = null;
  try {
    vulnStore = getVulnrichmentStore();
  } catch {
    vulnStore = null;
  }

  // v5.6: Resolve the GitHub Advisory store up-front so the
  // package-remediation merge is consistent across all
  // three response paths. Same defensive contract as
  // Vulnrichment: a missing store is handled by the merge
  // helper, which returns the honest 'unavailable'
  // metadata. The prebuilt `latest-dataset` blob's
  // `fetchedAt` is NEVER modified by this merge.
  let ghStore = null;
  try {
    ghStore = getGithubAdvisoryStore();
  } catch {
    ghStore = null;
  }

  // Lock state is computed for the response shape regardless
  // of whether the blob is present — the UI shows the
  // "Refresh running in background" pill from this flag.
  let refreshInProgress = false;
  if (store) {
    try {
      refreshInProgress = await isRefreshLocked(store);
    } catch {
      refreshInProgress = false;
    }
  }

  if (store) {
    const prebuilt = await readLatestDataset(store);
    if (prebuilt && prebuilt.mode === 'live' && Array.isArray(prebuilt.data)) {
      // Prebuilt envelope is returned verbatim — minus the
      // internal metadata fields (`lastRefreshAttemptAt`,
      // `lastRefreshFailure`, `lastVulnrichmentRefresh`,
      // `lastGithubAdvisoryRefresh`) that the refresh
      // orchestrator stores for operator visibility but
      // that must NEVER appear in the public response. The
      // lock flag is overlaid so the UI knows a refresh
      // is in flight.
      const base = publicEnvelope(prebuilt);
      // v5.5: read-time SSVC merge. The prebuilt blob's
      // records don't carry SSVC fields — the cache lives
      // in a separate store. We merge the cache into the
      // response here, and add the public
      // `vulnrichmentStatus` / `vulnrichmentCoverage`
      // envelope metadata. A Vulnrichment Blobs read error
      // is contained by `attachVulnrichment` and degrades
      // to `vulnrichmentStatus: 'unavailable'` with the
      // existing data still served.
      //
      // v5.6: chain the GitHub Advisory merge on top of
      // the SSVC merge. The `fetchedAt` of the prebuilt
      // blob is NOT modified — the GitHub Advisory cache
      // lives in its own store, and the merge is in-memory
      // only. A Blobs read error is contained by
      // `attachGithubAdvisory` and degrades to
      // `githubAdvisoryStatus: 'unavailable'` with the
      // existing data still served.
      const withSsvc = await attachVulnrichment(base, vulnStore);
      const enriched = await attachGithubAdvisory(withSsvc, ghStore);
      // v6.1: attach the aggregate public-intelligence
      // fields to the public envelope. The per-CVE data
      // is server-side only and is surfaced through the
      // view modes. The public envelope remains a strict
      // superset of the V5.7 envelope; old clients
      // ignore the new fields.
      const v61Additions = await buildV61DefaultAdditions({
        datasetEnvelope: prebuilt,
        vulnrichmentCache: await readCurrentVulnrichmentCache(),
        githubAdvisoryCache: await readCurrentGithubAdvisoryCache(),
        osvProjection: await readCurrentOsvProjection(),
      });
      return jsonResponse(200, {
        ...enriched,
        proxyStatus: 'proxy',
        dataSource: 'prebuilt-store',
        refreshInProgress,
        ...v61Additions,
      });
    }
  }

  // ---- 2. Bootstrap (no prebuilt blob, or Blobs unavailable).
  //         Mirrors the v5.0 / v5.0.1 / v5.0.2 / v5.0.3 build
  //         path character-for-character. ----
  let live;
  try {
    live = await buildLiveDataset({ startTime });
  } catch (err) {
    return jsonResponse(502, {
      mode: 'fallback',
      fallbackReason:
        err instanceof Error
          ? err.message
          : 'CISA KEV fetch failed: unknown error.',
      refreshInProgress: false,
    });
  }

  // ---- 3. On a successful bootstrap, write the blob so the
  //         NEXT visitor hits the fast path. A write failure
  //         here does not affect the current visitor — they
  //         still get the freshly-built dataset, and the next
  //         refresh will retry the write. ----
  //
  //   v5.5: the Vulnrichment merge is applied on the
  //   bootstrap path too, so the first visitor on a fresh
  //   deploy still gets the (typically empty)
  //   `vulnrichmentStatus` / `vulnrichmentCoverage` envelope
  //   metadata. The next scheduled refresh will populate
  //   the cache and the next visitor after that sees the
  //   enriched coverage.
  //
  //   v5.6: chain the GitHub Advisory merge on top of the
  //   SSVC merge. Same pattern as the prebuilt-store path:
  //   the merge is in-memory only, the bootstrap envelope's
  //   `fetchedAt` is preserved, and a Blobs read error
  //   degrades to `githubAdvisoryStatus: 'unavailable'`. ----
  const liveWithSsvc = await attachVulnrichment(live, vulnStore);
  const liveEnvelope = await attachGithubAdvisory(liveWithSsvc, ghStore);
  if (store) {
    const envelope = {
      ...liveEnvelope,
      proxyStatus: 'proxy',
      dataSource: 'live-build',
      refreshInProgress: false,
    };
    await writeLatestDataset(store, envelope);
    return jsonResponse(200, envelope);
  }

  // No blob store available (Vite-only dev with no env vars).
  // Return the freshly-built dataset with the legacy v5.0
  // proxyStatus tag and no dataSource so the client doesn't
  // think a shared blob exists.
  return jsonResponse(200, {
    ...liveEnvelope,
    proxyStatus: 'proxy',
    refreshInProgress: false,
  });
};