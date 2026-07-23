/**
 * v5.6 — GitHub Advisory refresh orchestrator.
 *
 * This module is the *write path* for the GitHub Advisory
 * cache. It is invoked by `refresh.mjs` after a successful
 * CISA → NVD → EPSS build, on both the manual and scheduled
 * triggers. The visitor's `dataset.mjs` read path is NOT
 * affected by this module — it only reads the cache that
 * this module writes.
 *
 * Contract (matches the v5.6 product spec):
 *
 *   - Fetch only missing or stale CVE entries. A cached
 *     entry is "stale" after `GITHUB_ADVISORY_STALE_DAYS` (7
 *     days, conservative).
 *   - Maximum `GITHUB_ADVISORY_MAX_PER_RUN_AUTH` (50) CVEs
 *     per cycle WITH a `GITHUB_TOKEN`, or
 *     `GITHUB_ADVISORY_MAX_PER_RUN_UNAUTH` (25) WITHOUT.
 *   - Concurrency limited to `GITHUB_ADVISORY_CONCURRENCY` (4).
 *   - Within the to-enrich set, sort by KEV `dateAdded`
 *     descending so the newest KEV entries are enriched
 *     first.
 *   - HTTP 200 + empty array OR HTTP 404 → "no GitHub
 *     reviewed advisory for this CVE", NOT a failure. A
 *     lightweight negative-cache marker
 *     (`{ advisory: null, status: 'missing', cachedAt,
 *     checkedAt }`) is written so the same CVE isn't
 *     re-selected within the staleness window. The cycle
 *     continues.
 *   - HTTP 403 / 429 / 5xx, timeout, network error →
 *     preserve the existing cache entry for that CVE,
 *     continue with the rest. The internal
 *     `lastGithubAdvisoryRefresh` metadata records the
 *     sanitized reason for operator visibility; the public
 *     envelope is unaffected.
 *   - Inspect `x-ratelimit-remaining` on every response.
 *     When the remaining allowance drops below
 *     `GITHUB_ADVISORY_MIN_REMAINING` (10), stop the
 *     current provider pass — the orchestrator records
 *     `rateLimited: true` in its envelope so the next
 *     cycle can short-circuit until the reset window.
 *   - Raw provider errors, rate-limit response headers,
 *     and the GitHub token NEVER reach the visitor. The
 *     public envelope carries only `githubAdvisoryStatus:
 *     'available' | 'partial' | 'unavailable'` and
 *     `githubAdvisoryCoverage: { enriched, total }`.
 *
 * Result envelope (mirrors the v5.2.6 `runRefresh` /
 * v5.5 `runVulnrichmentRefresh` shape):
 *
 *   { status: 'completed' | 'skipped' | 'failed' | 'rate-limited',
 *     enriched: number,
 *     total: number,
 *     attempted: number,
 *     empty: number,            // 200 + empty-array (treated like "missing")
 *     transient: number,        // 403/429/5xx/timeout/network
 *     reason?: string,
 *     lastAttemptAt: ISO string,
 *     rateLimited?: boolean,    // true when the cycle stopped early
 *     retryAfter?: ISO string } // when rate-limited, the upstream reset time
 *
 *   status values:
 *     - 'completed'    : the cycle ran (even if zero CVEs
 *                        were eligible). enriched/total
 *                        reflect the cache state after the
 *                        write.
 *     - 'skipped'      : no CVE list available or no
 *                        Blob store. The cache is left
 *                        untouched.
 *     - 'failed'       : an unexpected error prevented the
 *                        cycle from running at all (e.g.
 *                        the Blobs store could not be
 *                        opened). The cache is left
 *                        untouched.
 *     - 'rate-limited' : the cycle stopped early because
 *                        GitHub returned a 403/429 OR
 *                        `x-ratelimit-remaining` dropped
 *                        below the configured minimum.
 *                        Already-written cache entries are
 *                        persisted (the partial-cycle
 *                        progress is not lost). The
 *                        orchestrator surfaces
 *                        `retryAfter` so the next cycle
 *                        can wait.
 *
 * The orchestrator does NOT throw. Every error path returns
 * a structured envelope so the caller (refresh.mjs) can
 * record the outcome in the existing internal metadata
 * without a try/catch.
 */
import {
  GITHUB_ADVISORY_CONCURRENCY,
  GITHUB_ADVISORY_MAX_PER_RUN_AUTH,
  GITHUB_ADVISORY_MAX_PER_RUN_UNAUTH,
  GITHUB_ADVISORY_MIN_REMAINING,
  GITHUB_ADVISORY_STALE_DAYS,
  extractReviewedAdvisories,
  fetchOneCveAdvisories,
  githubAdvisoryStatusForCoverage,
  prioritizeCvesForRefresh,
  settledAll,
} from './githubAdvisory.mjs';
import {
  readGithubAdvisoryCache,
  writeGithubAdvisoryCache,
} from './store.mjs';
import { computeEnrichmentPublicHash } from './publicIntelligenceHash.mjs';

function computeEnrichmentPublicHashForCache(cache) {
  if (!cache || typeof cache !== 'object') return null;
  // Strip the internal hash field before hashing.
  const { vulnrichmentPublicHash, githubAdvisoryPublicHash, ...rest } = cache;
  return computeEnrichmentPublicHash(rest);
}

// ---------------------------------------------------------------------------
// Public entry point.
// ---------------------------------------------------------------------------

/**
 * Run a GitHub Advisory enrichment pass.
 *
 * @param {object}   opts
 * @param {object}   opts.store                Netlify Blobs store handle
 *                                             for the GitHub Advisory cache.
 * @param {Array}    opts.cveList              Array of {cveId, dateAdded}
 *                                             entries from the most
 *                                             recently built dataset.
 * @param {object}   [opts.now]                Date (for tests).
 * @param {number}   [opts.maxItems]           Override the default cap.
 * @param {number}   [opts.concurrency]        Override the default
 *                                             concurrency.
 * @param {number}   [opts.staleDays]          Override the staleness
 *                                             window.
 * @param {number}   [opts.minRemaining]       Override the rate-limit
 *                                             floor.
 * @param {boolean}  [opts.auth]               Test seam — `true` to
 *                                             add the `Authorization`
 *                                             header in the production
 *                                             fetcher. The test suite
 *                                             uses a mock fetcher and
 *                                             does not exercise the
 *                                             production fetcher, so
 *                                             this is a no-op in tests.
 * @param {function} [opts.fetcher]            Test seam — overrides
 *                                             fetchOneCveAdvisories's
 *                                             internal fetcher.
 * @param {function} [opts.hasToken]           Test seam — replaces the
 *                                             `process.env.GITHUB_TOKEN`
 *                                             detection. Returns
 *                                             boolean. Defaults to a
 *                                             runtime check.
 * @param {function} [opts.nowFn]              Test seam — replaces
 *                                             `Date.now()` for
 *                                             staleness math.
 *
 * @returns {Promise<{status, enriched, total, attempted, empty,
 *                    transient, reason?, lastAttemptAt, rateLimited?,
 *                    retryAfter?}>}
 */
export async function runGithubAdvisoryRefresh(opts = {}) {
  const {
    store,
    cveList,
    now = new Date(),
    maxItems,
    concurrency = GITHUB_ADVISORY_CONCURRENCY,
    staleDays = GITHUB_ADVISORY_STALE_DAYS,
    minRemaining = GITHUB_ADVISORY_MIN_REMAINING,
    auth,
    fetcher,
    hasToken,
    nowFn,
  } = opts;

  const startedAt = now instanceof Date ? now : new Date(now);
  const lastAttemptAt = startedAt.toISOString();

  // Resolve authentication: the orchestrator decides the
  // cap based on whether a GITHUB_TOKEN is set. The token
  // itself is read only inside the production fetcher
  // (githubAdvisory.mjs#defaultFetcher) and is never
  // propagated to test seams, log lines, or response
  // bodies. `hasToken` is the test seam — when not
  // provided, we check process.env directly.
  const hasGithubToken = typeof hasToken === 'function'
    ? hasToken() === true
    : (typeof process !== 'undefined' && !!process.env && typeof process.env.GITHUB_TOKEN === 'string' && process.env.GITHUB_TOKEN.length > 0);
  const effectiveMaxItems = Number.isFinite(maxItems) && maxItems > 0
    ? Math.floor(maxItems)
    : (hasGithubToken
        ? GITHUB_ADVISORY_MAX_PER_RUN_AUTH
        : GITHUB_ADVISORY_MAX_PER_RUN_UNAUTH);
  const effectiveAuth = auth === true || hasGithubToken;

  if (!store) {
    return {
      status: 'skipped',
      enriched: 0,
      total: 0,
      attempted: 0,
      empty: 0,
      transient: 0,
      reason: 'No Blob store available for GitHub Advisory cache.',
      lastAttemptAt,
    };
  }
  if (!Array.isArray(cveList) || cveList.length === 0) {
    return {
      status: 'skipped',
      enriched: 0,
      total: 0,
      attempted: 0,
      empty: 0,
      transient: 0,
      reason: 'No CVE list available; main dataset has no records.',
      lastAttemptAt,
    };
  }

  // ---- 1. Read the existing cache (defensive — a transient
  //         read error is treated as "no cache yet", NOT a
  //         hard failure of this cycle). ----
  const existing = await readGithubAdvisoryCache(store);
  const cacheMap = (existing && existing.records && typeof existing.records === 'object')
    ? { ...existing.records }
    : {};

  // ---- 2. Decide the to-enrich set. ----
  const nowMs = typeof nowFn === 'function' ? nowFn() : Date.now();
  const toEnrich = prioritizeCvesForRefresh({
    cveList,
    cache: cacheMap,
    maxItems: effectiveMaxItems,
    staleDays,
    now: nowMs,
  });

  // ---- 3. Fetch in parallel. Each task is a closure that
  //         never throws; it returns a structured result. ----
  let attempted = 0;
  let emptyCount = 0;
  let transientCount = 0;
  const transientReasons = new Set();
  let rateLimited = false;
  let firstRetryAfter = null;

  if (toEnrich.length > 0) {
    const tasks = toEnrich.map((cveId) => async () => {
      attempted++;
      const result = await fetchOneCveAdvisories(cveId, {
        fetcher,
        auth: effectiveAuth,
      });

      // Per spec requirement 5: stop the current pass when
      // the remaining allowance is too low. The check
      // happens BEFORE we write the cache entry so a
      // partially-completed cycle leaves the cache
      // consistent with what GitHub told us.
      if (
        typeof result.remaining === 'number' &&
        result.remaining < minRemaining
      ) {
        rateLimited = true;
        if (result.retryAfter && !firstRetryAfter) {
          firstRetryAfter = result.retryAfter;
        }
        // Mark this and any subsequent task as transient
        // and stop processing. We still return the result
        // for the current task; the orchestrator's loop
        // continues but a follow-on pass will see
        // `rateLimited` and bail.
        transientCount++;
        if (result.reason) {
          transientReasons.add(truncateForReason(result.reason, 80));
        }
        return result;
      }

      if (result.outcome === 'ok') {
        const advisory = extractReviewedAdvisories(result.records);
        if (advisory) {
          cacheMap[cveId] = {
            advisory,
            cachedAt: nowMs,
          };
        } else {
          // 200 OK but the body filtered out to nothing
          // (all advisories were either not `type=reviewed`
          // or were withdrawn). Treat as "missing" — write
          // a negative-cache marker so we don't refetch
          // within the staleness window (unless an
          // existing positive record is already cached —
          // see the defensive note below).
          emptyCount++;
          writeMissingMarkerIfNoPositive(cacheMap, cveId, nowMs);
        }
      } else if (result.outcome === 'empty') {
        // 200 + empty array OR 404 → "no GitHub reviewed
        // advisory for this CVE". Write a negative-cache
        // marker so the same CVE isn't re-selected every
        // cycle. The 7-day staleness window controls when
        // this entry becomes eligible again; if GitHub
        // eventually publishes an advisory, the next cycle
        // after the TTL will pick it up.
        //
        // Defensive: if a POSITIVE advisory record is
        // already cached for this CVE, keep it. A 404 or
        // empty result must never delete an existing
        // positive record.
        emptyCount++;
        writeMissingMarkerIfNoPositive(cacheMap, cveId, nowMs);
      } else {
        // 'transient' — preserve any existing cache entry.
        // A 403/429/5xx/timeout/network failure on a CVE
        // that's already in the cache does NOT clear the
        // existing advisory. The cycle continues.
        transientCount++;
        if (result.reason) {
          transientReasons.add(truncateForReason(result.reason, 80));
        }
        if (result.retryAfter && !firstRetryAfter) {
          firstRetryAfter = result.retryAfter;
        }
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

  // If we hit the rate limit, we still persist whatever we
  // managed to write — a partial backfill is better than
  // nothing, and the public envelope will honestly report
  // the partial coverage. The `rateLimited` flag on the
  // result envelope lets the next cycle short-circuit if
  // appropriate.
  // v6.1: compute the GitHub Advisory cache public hash.
  // The hash describes the publicly projected `records`
  // map only (not the `updatedAt` metadata). The returned
  // value is stored in the cache envelope's
  // `githubAdvisoryPublicHash` internal field.
  const cachePayload = {
    records: cacheMap,
    updatedAt: lastAttemptAt,
  };
  const githubAdvisoryPublicHash = computeEnrichmentPublicHashForCache(cachePayload);
  const writeOk = await writeGithubAdvisoryCache(store, {
    ...cachePayload,
    githubAdvisoryPublicHash,
  });
  if (!writeOk) {
    return {
      status: 'failed',
      enriched: enrichedTotal,
      total: totalCves,
      attempted,
      empty: emptyCount,
      transient: transientCount,
      reason: 'Failed to write GitHub Advisory cache blob.',
      lastAttemptAt,
    };
  }

  const reason = buildReason({
    attempted,
    empty: emptyCount,
    transient: transientCount,
    reasons: Array.from(transientReasons),
  });

  // If the pass was halted by the rate-limit floor before
  // the orchestrator completed every task, surface the
  // 'rate-limited' status so the caller's bookkeeping is
  // honest. The public envelope still shows the partial
  // coverage we DID manage to write.
  if (rateLimited) {
    return {
      status: 'rate-limited',
      enriched: enrichedTotal,
      total: totalCves,
      attempted,
      empty: emptyCount,
      transient: transientCount,
      reason: reason || 'GitHub rate-limit floor reached',
      lastAttemptAt,
      rateLimited: true,
      retryAfter: firstRetryAfter || undefined,
    };
  }

  return {
    status: 'completed',
    enriched: enrichedTotal,
    total: totalCves,
    attempted,
    empty: emptyCount,
    transient: transientCount,
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
 * the per-task work inside `runGithubAdvisoryRefresh`:
 *
 *   - outcome === 'ok' + valid advisory → upsert the cache entry.
 *   - outcome === 'ok' + no advisory   → write a 'missing' marker
 *                                         (200 OK but filtered
 *                                         to nothing), unless a
 *                                         positive record is
 *                                         already cached
 *                                         (defensive — see the
 *                                         spec).
 *   - outcome === 'empty'              → write a 'missing' marker
 *                                         (200 + empty array or
 *                                         HTTP 404), unless a
 *                                         positive record is
 *                                         already cached.
 *   - outcome === 'transient'          → preserve any existing
 *                                         cache entry (do NOT
 *                                         clear, do NOT write a
 *                                         marker).
 */
export function applyFetchResultToCache(cacheMap, cveId, outcome, records, cachedAtMs) {
  const out = { ...(cacheMap || {}) };
  const existing = out[cveId];
  const hasPositive = existing && existing.advisory
    && existing.advisory.ghsaId;
  if (outcome === 'ok') {
    const advisory = extractReviewedAdvisories(records);
    if (advisory) {
      out[cveId] = { advisory, cachedAt: cachedAtMs };
    } else if (!hasPositive) {
      out[cveId] = {
        advisory: null,
        status: 'missing',
        cachedAt: cachedAtMs,
        checkedAt: cachedAtMs,
      };
    }
    // else: existing positive record stays.
  } else if (outcome === 'empty') {
    if (!hasPositive) {
      out[cveId] = {
        advisory: null,
        status: 'missing',
        cachedAt: cachedAtMs,
        checkedAt: cachedAtMs,
      };
    }
    // else: existing positive record stays (a 404 / empty
    // result must never delete an existing positive
    // advisory record).
  }
  // 'transient' leaves the cache unchanged for this CVE
  // (preserves the existing entry on purpose — see the
  // spec).
  return out;
}

/**
 * Compute the public `githubAdvisoryCoverage` +
 * `githubAdvisoryStatus` envelope from the current cache
 * and the dataset's CVE list. Pure.
 *
 * Coverage counts the CVEs in the dataset that have a
 * positive advisory entry in the cache. CVEs that aren't
 * in the GitHub Advisory Database (200 + empty array or
 * HTTP 404) do NOT count as enriched; they count as
 * "empty" in the orchestrator's internal counters but the
 * public status reflects only "actually enriched / total
 * in dataset".
 */
export function computeCoverageForPublic(cacheMap, cveList) {
  const total = Array.isArray(cveList) ? cveList.length : 0;
  const enriched = countEnriched(cacheMap, cveList);
  return {
    enriched,
    total,
    status: githubAdvisoryStatusForCoverage(enriched, total),
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
    if (cached && cached.advisory && cached.advisory.ghsaId) n++;
  }
  return n;
}

/**
 * Write a lightweight negative-cache marker to the cache
 * map for a CVE that returned a "no advisory exists" signal
 * (HTTP 200 with empty array, HTTP 200 with all entries
 * filtered out, or HTTP 404).
 *
 * Defensive: if the cache already holds a POSITIVE advisory
 * record for this CVE, the existing entry is preserved
 * untouched. A 404 / empty result must never delete an
 * existing positive advisory record — losing real data on a
 * transient upstream inconsistency is worse than keeping a
 * possibly-stale one. The caller still increments the
 * `empty` counter for the operator-facing reason string,
 * but the public-facing `githubAdvisoryCoverage.enriched`
 * count is unaffected (the positive record still counts).
 */
function writeMissingMarkerIfNoPositive(cacheMap, cveId, checkedAtMs) {
  const existing = cacheMap && cacheMap[cveId];
  if (existing && existing.advisory && existing.advisory.ghsaId) {
    // Existing positive record — leave it alone.
    return;
  }
  cacheMap[cveId] = {
    advisory: null,
    status: 'missing',
    cachedAt: checkedAtMs,
    checkedAt: checkedAtMs,
  };
}

function buildReason({ attempted, empty, transient, reasons }) {
  if (attempted === 0) return undefined;
  const parts = [];
  parts.push(`attempted ${attempted}`);
  if (empty > 0) parts.push(`${empty} empty`);
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
