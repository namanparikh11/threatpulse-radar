/**
 * v5.5 — Vulnrichment refresh orchestrator.
 *
 * This module is the *write path* for the Vulnrichment
 * cache. It is invoked by `refresh.mjs` after a successful
 * CISA → NVD → EPSS build, on both the manual and scheduled
 * triggers. The visitor's `dataset.mjs` read path is NOT
 * affected by this module — it only reads the cache that
 * this module writes.
 *
 * Contract (matches the v5.5 product spec):
 *
 *   - Fetch only missing or stale CVE entries. A cached
 *     entry is "stale" after `VULNRICHMENT_STALE_DAYS` (7
 *     days, conservative).
 *   - Maximum `VULNRICHMENT_MAX_PER_RUN` CVEs per cycle
 *     (default 50).
 *   - Concurrency limited to `VULNRICHMENT_CONCURRENCY` (5).
 *   - Within the to-enrich set, sort by KEV `dateAdded`
 *     descending so the newest KEV entries are enriched
 *     first.
 *   - 404 for a single CVE → "no Vulnrichment record",
 *     NOT a failure. A lightweight negative-cache marker
 *     (`{ ssvc: null, status: 'missing', cachedAt, checkedAt }`)
 *     is written so the same CVE isn't re-selected within
 *     the staleness window. The cycle continues.
 *   - Timeout, network error, 429, 5xx → preserve the
 *     existing cache entry for that CVE, continue with the
 *     rest.
 *   - Raw provider errors are NEVER returned to the
 *     visitor. The public envelope carries
 *     `vulnrichmentStatus: 'available' | 'partial' |
 *     'unavailable'` and `vulnrichmentCoverage: {enriched,
 *     total}` only.
 *
 * Result envelope (mirrors the v5.2.6 `runRefresh` shape):
 *
 *   { status: 'completed',
 *     enriched: number,
 *     total: number,
 *     attempted: number,
 *     missing: number,
 *     transient: number,
 *     reason?: string,
 *     lastAttemptAt: ISO string }
 *
 *   status values:
 *     - 'completed'   : the cycle ran (even if zero CVEs
 *                       were eligible). enriched/total reflect
 *                       the cache state after the write.
 *     - 'skipped'     : no CVE list available (the main
 *                       build produced no records, or no
 *                       dataset blob was readable). The
 *                       cache is left untouched.
 *     - 'failed'      : an unexpected error prevented the
 *                       cycle from running at all (e.g. the
 *                       Blobs store could not be opened).
 *                       The cache is left untouched.
 *
 * The orchestrator does NOT throw. Every error path returns
 * a structured envelope so the caller (refresh.mjs) can
 * record the outcome in the existing internal metadata
 * without a try/catch.
 */
import {
  VULNRICHMENT_CONCURRENCY,
  VULNRICHMENT_MAX_PER_RUN,
  cveToRepoPath,
  extractSsvcFromAdp,
  fetchOneVulnrichment,
  prioritizeCvesForRefresh,
  settledAll,
  vulnrichmentStatusForCoverage,
} from './vulnrichment.mjs';
import {
  readVulnrichmentCache,
  writeVulnrichmentCache,
} from './store.mjs';

// ---------------------------------------------------------------------------
// Public entry point.
// ---------------------------------------------------------------------------

/**
 * Run a Vulnrichment enrichment pass.
 *
 * @param {object}   opts
 * @param {object}   opts.store                Netlify Blobs store handle
 *                                             for the Vulnrichment cache.
 * @param {Array}    opts.cveList              Array of {cveId, dateAdded}
 *                                             entries from the most
 *                                             recently built dataset.
 * @param {object}   [opts.now]                Date (for tests).
 * @param {number}   [opts.maxItems]           Override the default cap.
 * @param {number}   [opts.concurrency]        Override the default
 *                                             concurrency.
 * @param {number}   [opts.staleDays]          Override the staleness
 *                                             window.
 * @param {function} [opts.fetcher]            Test seam — overrides
 *                                             fetchOneVulnrichment's
 *                                             internal fetcher.
 * @param {function} [opts.nowFn]              Test seam — replaces
 *                                             `Date.now()` for
 *                                             staleness math.
 *
 * @returns {Promise<{status, enriched, total, attempted, missing,
 *                    transient, reason?, lastAttemptAt}>}
 */
export async function runVulnrichmentRefresh(opts = {}) {
  const {
    store,
    cveList,
    now = new Date(),
    maxItems = VULNRICHMENT_MAX_PER_RUN,
    concurrency = VULNRICHMENT_CONCURRENCY,
    staleDays,
    fetcher,
    nowFn,
  } = opts;

  const startedAt = now instanceof Date ? now : new Date(now);
  const lastAttemptAt = startedAt.toISOString();

  if (!store) {
    return {
      status: 'skipped',
      enriched: 0,
      total: 0,
      attempted: 0,
      missing: 0,
      transient: 0,
      reason: 'No Blob store available for Vulnrichment cache.',
      lastAttemptAt,
    };
  }
  if (!Array.isArray(cveList) || cveList.length === 0) {
    return {
      status: 'skipped',
      enriched: 0,
      total: 0,
      attempted: 0,
      missing: 0,
      transient: 0,
      reason: 'No CVE list available; main dataset has no records.',
      lastAttemptAt,
    };
  }

  // ---- 1. Read the existing cache (defensive — a transient
  //         read error is treated as "no cache yet", NOT a
  //         hard failure of this cycle). ----
  const existing = await readVulnrichmentCache(store);
  const cacheMap = (existing && existing.records && typeof existing.records === 'object')
    ? { ...existing.records }
    : {};

  // ---- 2. Decide the to-enrich set. ----
  const nowMs = typeof nowFn === 'function' ? nowFn() : Date.now();
  const toEnrich = prioritizeCvesForRefresh({
    cveList,
    cache: cacheMap,
    maxItems,
    staleDays,
    now: nowMs,
  });

  // ---- 3. Fetch in parallel. Each task is a closure that
  //         never throws; it returns a structured result. ----
  let attempted = 0;
  let missing = 0;
  let transient = 0;
  let enrichedDelta = 0;
  const transientReasons = new Set();

  if (toEnrich.length > 0) {
    const tasks = toEnrich.map((cveId) => async () => {
      attempted++;
      const result = await fetchOneVulnrichment(cveId, fetcher ? { fetcher } : {});
      if (result.outcome === 'ok') {
        const ssvc = extractSsvcFromAdp(result.record);
        if (ssvc) {
          cacheMap[cveId] = {
            ssvc,
            cachedAt: nowMs,
          };
          enrichedDelta++;
        } else {
          // 200 OK but the record has no CISA-ADP SSVC
          // container. Treat as "missing" — the file exists
          // but doesn't carry the data we care about. Write
          // a negative-cache marker so we don't refetch
          // within the staleness window (unless an existing
          // positive SSVC record is already cached — see
          // the defensive note below).
          missing++;
          writeMissingMarkerIfNoPositive(cacheMap, cveId, nowMs);
        }
      } else if (result.outcome === 'missing') {
        // 404 → no CISA Vulnrichment assessment available.
        // Write a lightweight negative-cache marker so the
        // same CVE isn't re-selected every cycle. The
        // `prioritizeCvesForRefresh` staleness window (7 d)
        // controls when this entry becomes eligible again;
        // if CISA eventually publishes an assessment, the
        // next cycle after the TTL will pick it up.
        //
        // Defensive: if a POSITIVE SSVC record is already
        // cached for this CVE, keep it. A 404 must never
        // delete an existing positive SSVC record (the
        // upstream might be temporarily inconsistent, or the
        // CISA assessment may have been removed since the
        // last successful fetch — losing real data is worse
        // than keeping a possibly-stale one).
        missing++;
        writeMissingMarkerIfNoPositive(cacheMap, cveId, nowMs);
      } else {
        // 'transient' — preserve any existing cache entry.
        transient++;
        if (result.reason) transientReasons.add(truncateForReason(result.reason, 80));
      }
      return result;
    });

    await settledAll(tasks, Math.min(concurrency, tasks.length));
  }

  // ---- 4. Persist the updated cache. A write failure is
  //         surfaced as 'failed' status but the in-memory
  //         state isn't corrupted — the next cycle will
  //         re-attempt the same CVEs (their cache entries
  //         are still missing/stale). ----
  const totalCves = cveList.length;
  const enrichedTotal = countEnriched(cacheMap, cveList);

  const writeOk = await writeVulnrichmentCache(store, {
    records: cacheMap,
    updatedAt: lastAttemptAt,
  });
  if (!writeOk) {
    return {
      status: 'failed',
      enriched: enrichedTotal,
      total: totalCves,
      attempted,
      missing,
      transient,
      reason: 'Failed to write Vulnrichment cache blob.',
      lastAttemptAt,
    };
  }

  const reason = buildReason({
    attempted,
    missing,
    transient,
    reasons: Array.from(transientReasons),
  });

  return {
    status: 'completed',
    enriched: enrichedTotal,
    total: totalCves,
    attempted,
    missing,
    transient,
    reason,
    lastAttemptAt,
  };
}

// ---------------------------------------------------------------------------
// Pure helpers exposed for the acceptance suite.
// ---------------------------------------------------------------------------

/**
 * Apply a single fresh fetch result to a cache map. Returns
 * a NEW map; the input is not mutated. The semantics mirror
 * the per-task work inside `runVulnrichmentRefresh`:
 *
 *   - outcome === 'ok' + valid SSVC → upsert the cache entry.
 *   - outcome === 'ok' + no SSVC   → write a 'missing' marker
 *                                    (200 OK but no CISA-ADP
 *                                    SSVC container), unless
 *                                    a positive record is
 *                                    already cached (defensive
 *                                    — see the spec).
 *   - outcome === 'missing'         → write a 'missing' marker
 *                                    (HTTP 404 — "no CISA
 *                                    Vulnrichment assessment
 *                                    available"), unless a
 *                                    positive record is
 *                                    already cached. The
 *                                    marker carries a
 *                                    `checkedAt` timestamp so
 *                                    the same CVE isn't
 *                                    re-selected within the
 *                                    staleness window.
 *   - outcome === 'transient'       → preserve any existing
 *                                    cache entry (do NOT clear,
 *                                    do NOT write a marker).
 */
export function applyFetchResultToCache(cacheMap, cveId, outcome, record, cachedAtMs) {
  const out = { ...(cacheMap || {}) };
  const existing = out[cveId];
  const hasPositive = existing && existing.ssvc && existing.ssvc.ssvcExploitation;
  if (outcome === 'ok') {
    const ssvc = extractSsvcFromAdp(record);
    if (ssvc) {
      out[cveId] = { ssvc, cachedAt: cachedAtMs };
    } else if (!hasPositive) {
      out[cveId] = {
        ssvc: null,
        status: 'missing',
        cachedAt: cachedAtMs,
        checkedAt: cachedAtMs,
      };
    }
    // else: existing positive record stays.
  } else if (outcome === 'missing') {
    if (!hasPositive) {
      out[cveId] = {
        ssvc: null,
        status: 'missing',
        cachedAt: cachedAtMs,
        checkedAt: cachedAtMs,
      };
    }
    // else: existing positive record stays (a 404 must
    // never delete an existing positive SSVC record).
  }
  // 'transient' leaves the cache unchanged for this CVE
  // (preserves the existing entry on purpose — see the
  // spec).
  return out;
}

/**
 * Compute the public `vulnrichmentCoverage` + `vulnrichmentStatus`
 * envelope from the current cache and the dataset's CVE
 * list. Pure.
 *
 * Coverage counts the CVEs in the dataset that have a
 * SSVC entry in the cache. CVEs that aren't in the
 * Vulnrichment repository (404 → no record) do NOT count
 * as enriched; they count as "missing" in the orchestrator's
 * internal counters but the public status reflects only
 * "actually enriched / total in dataset".
 */
export function computeCoverageForPublic(cacheMap, cveList) {
  const total = Array.isArray(cveList) ? cveList.length : 0;
  const enriched = countEnriched(cacheMap, cveList);
  return {
    enriched,
    total,
    status: vulnrichmentStatusForCoverage(enriched, total),
  };
}

// ---------------------------------------------------------------------------
// Internals.
// ---------------------------------------------------------------------------

function countEnriched(cacheMap, cveList) {
  if (!cacheMap || typeof cacheMap !== 'object') return 0;
  if (!Array.isArray(cveList)) return 0;
  let n = 0;
  for (const entry of cveList) {
    if (!entry || typeof entry.cveId !== 'string') continue;
    const cached = cacheMap[entry.cveId];
    if (cached && cached.ssvc && cached.ssvc.ssvcExploitation) n++;
  }
  return n;
}

/**
 * Write a lightweight negative-cache marker to the cache
 * map for a CVE that returned a "no record exists" signal
 * (HTTP 404, or HTTP 200 with no CISA-ADP SSVC container).
 *
 * Defensive: if the cache already holds a POSITIVE SSVC
 * record for this CVE, the existing entry is preserved
 * untouched. A 404 must never delete an existing positive
 * SSVC record — losing real data on a transient upstream
 * inconsistency is worse than keeping a possibly-stale
 * one. The caller still increments the `missing` counter
 * for the operator-facing reason string, but the
 * public-facing `vulnrichmentCoverage.enriched` count is
 * unaffected (the positive record still counts).
 */
function writeMissingMarkerIfNoPositive(cacheMap, cveId, checkedAtMs) {
  const existing = cacheMap && cacheMap[cveId];
  if (existing && existing.ssvc && existing.ssvc.ssvcExploitation) {
    // Existing positive record — leave it alone.
    return;
  }
  cacheMap[cveId] = {
    ssvc: null,
    status: 'missing',
    cachedAt: checkedAtMs,
    checkedAt: checkedAtMs,
  };
}

function buildReason({ attempted, missing, transient, reasons }) {
  if (attempted === 0) return undefined;
  const parts = [];
  parts.push(`attempted ${attempted}`);
  if (missing > 0) parts.push(`${missing} missing`);
  if (transient > 0) {
    const why = reasons.length > 0 ? ` (${reasons.slice(0, 2).join('; ')})` : '';
    parts.push(`${transient} transient${why}`);
  }
  return parts.join(', ');
}

function truncateForReason(s, max) {
  if (typeof s !== 'string') return '';
  if (s.length <= max) return s;
  return s.slice(0, max - 1) + '\u2026';
}
