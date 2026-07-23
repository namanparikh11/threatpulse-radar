/**
 * V6.1 — Source health observations and derived state.
 *
 * The V6.1 source health model persists OBSERVATIONS
 * (lastSuccessfulFetchAt, lastAttemptOutcome, coverage,
 * threshold, sanitized reason). The five public states
 * (unknown, fresh, partial, stale, unavailable) are
 * DERIVED at request time from the observations. Time
 * passing alone moves `fresh` to `stale` without requiring
 * a new bundle publication.
 *
 * A provider attempt failure does NOT erase recent
 * last-known-good usability: a hard failure after a
 * successful observation matches the `partial` state
 * (with a sanitized reason), not `unavailable`. The
 * `unavailable` state is reserved for the case where no
 * successful observation exists AND a definitive hard
 * failure has been recorded.
 *
 * Decision tree (mutually exclusive, ordered):
 *
 *   1. unknown:
 *        lastSuccessfulFetchAt === null
 *        AND lastAttemptOutcome !== 'hard-failure'
 *
 *   2. unavailable:
 *        lastSuccessfulFetchAt === null
 *        AND lastAttemptOutcome === 'hard-failure'
 *        AND lastAttemptedFetchAt !== null
 *
 *   3. stale:
 *        lastSuccessfulFetchAt !== null
 *        AND (now - lastSuccessfulFetchAt) >= thresholdMinutes
 *
 *   4. partial:
 *        lastSuccessfulFetchAt !== null
 *        AND (now - lastSuccessfulFetchAt) < thresholdMinutes
 *        AND (
 *          usableCoverage < totalCoverage
 *          OR lastAttemptOutcome === 'soft-partial'
 *          OR (lastAttemptOutcome === 'hard-failure'
 *              AND lastAttemptedFetchAt > lastSuccessfulFetchAt)
 *        )
 *
 *   5. fresh:
 *        lastSuccessfulFetchAt !== null
 *        AND (now - lastSuccessfulFetchAt) < thresholdMinutes
 *        AND usableCoverage === totalCoverage
 *        AND lastAttemptOutcome !== 'soft-partial'
 *        AND lastAttemptOutcome !== 'hard-failure'
 *
 * Exactly one state is returned. The `sanitizedReason` is
 * exposed separately from the state, when present, as a
 * tooltip on the state chip.
 */

export const SOURCE_HEALTH_STATES = Object.freeze([
  'unknown', 'fresh', 'partial', 'stale', 'unavailable',
]);

/**
 * Per-source registry entry (the static, content-addressed
 * source registry). Used by the source-health derivation
 * for the threshold, authentication mode, refresh
 * schedule, and limitations.
 */
export const SOURCE_REGISTRY_V11 = {
  schemaVersion: '1.1.0',
  sources: [
    {
      id: 'cisa_kev',
      displayName: 'CISA KEV',
      type: 'gating',
      purpose: 'Catalog of vulnerabilities known to be exploited in the wild.',
      provenanceUrl: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
      authentication: 'none',
      refreshSchedule: { cron: '*/30 * * * *', description: 'Every 30 minutes' },
      thresholdMinutes: 90,
      limitations: 'Single source of truth for in-the-wild exploitation status. No CVSS, no EPSS.',
    },
    {
      id: 'nvd',
      displayName: 'NVD',
      type: 'enrichment',
      purpose: 'CVSS scores and vulnerability metadata.',
      provenanceUrl: 'https://nvd.nist.gov/',
      authentication: 'optional-server-side',
      refreshSchedule: { cron: '*/30 * * * *', description: 'Every 30 minutes' },
      thresholdMinutes: 90,
      limitations: 'CVSS scores only. Subject to public-anonymous rate limits.',
    },
    {
      id: 'first_epss',
      displayName: 'FIRST EPSS',
      type: 'enrichment',
      purpose: 'Probability of exploitation in the wild.',
      provenanceUrl: 'https://www.first.org/epss/',
      authentication: 'none',
      refreshSchedule: { cron: '*/30 * * * *', description: 'Every 30 minutes' },
      thresholdMinutes: 90,
      limitations: 'Daily-refreshed probabilities. Intraday changes are not reflected.',
    },
    {
      id: 'cisa_vulnrichment',
      displayName: 'CISA Vulnrichment',
      type: 'incremental',
      purpose: 'CISA-ADP SSVC decision context.',
      provenanceUrl: 'https://github.com/cisagov/vulnrichment',
      authentication: 'none',
      refreshSchedule: { cron: 'incremental', description: '50 CVEs per refresh cycle' },
      thresholdMinutes: 14 * 24 * 60,
      limitations: 'Incremental backfill. Partial coverage is normal until the cycle completes.',
      backfill: { cadenceDays: 7, maxPerCycle: 50 },
    },
    {
      id: 'github_advisory',
      displayName: 'GitHub Advisory Database',
      type: 'incremental',
      purpose: 'Reviewed package-remediation context.',
      provenanceUrl: 'https://github.com/advisories',
      authentication: 'optional-server-side',
      refreshSchedule: { cron: 'incremental', description: '50 CVEs per refresh cycle' },
      thresholdMinutes: 14 * 24 * 60,
      limitations: 'Incremental backfill. Only reviewed advisories are surfaced.',
      backfill: { cadenceDays: 7, maxPerCycle: 50 },
    },
    {
      id: 'osv',
      displayName: 'OSV',
      type: 'canonical',
      purpose: 'Canonical vulnerability / advisory / package baseline.',
      provenanceUrl: 'https://osv.dev/',
      authentication: 'none',
      refreshSchedule: { cron: '0 * * * *', description: 'Hourly' },
      thresholdMinutes: 180,
      limitations: 'Hourly cadence. 15-minute wall-clock per Background Function invocation.',
    },
  ],
};

/**
 * Convert a timestamp to its `minutesSince` value relative
 * to `now`. Returns null when the timestamp is missing
 * or unparseable. Negative values (timestamps in the
 * future) are clamped to 0.
 */
function minutesSince(timestamp, now) {
  if (typeof timestamp !== 'string' || !timestamp) return null;
  const t = new Date(timestamp).getTime();
  if (Number.isNaN(t)) return null;
  const ms = now.getTime() - t;
  if (ms < 0) return 0;
  return Math.floor(ms / (60 * 1000));
}

/**
 * Determine whether a timestamp is more recent than
 * another. Missing or invalid timestamps are treated as
 * "not more recent" (returns false).
 */
function isAfter(a, b) {
  if (typeof a !== 'string' || !a) return false;
  if (typeof b !== 'string' || !b) return true;
  const ta = new Date(a).getTime();
  const tb = new Date(b).getTime();
  if (Number.isNaN(ta) || Number.isNaN(tb)) return false;
  return ta > tb;
}

/**
 * Derive the public state for a single source from its
 * persisted observations. Returns one of the five
 * documented states. See the file header for the
 * decision tree.
 */
export function deriveSourceState(observations, now = new Date()) {
  if (!observations || typeof observations !== 'object') return 'unknown';
  const {
    lastSuccessfulFetchAt = null,
    lastAttemptedFetchAt = null,
    lastAttemptOutcome = null,
    usableCoverage = 0,
    totalCoverage = 0,
    thresholdMinutes = 0,
  } = observations;

  const hasObservation = typeof lastSuccessfulFetchAt === 'string' && lastSuccessfulFetchAt.length > 0;
  const hasAttempt = typeof lastAttemptedFetchAt === 'string' && lastAttemptedFetchAt.length > 0;
  const hardFailed = lastAttemptOutcome === 'hard-failure';
  const softPartial = lastAttemptOutcome === 'soft-partial';

  // 1. unknown: no successful observation AND (no
  //    definitive hard failure OR no attempt recorded).
  //    A hard-failure outcome without a recorded attempt
  //    is treated as unknown (defensive: the outcome is
  //    inconsistent with the attempt log).
  if (!hasObservation && (!hardFailed || !hasAttempt)) return 'unknown';

  // 2. unavailable
  if (!hasObservation && hardFailed && hasAttempt) return 'unavailable';

  const age = minutesSince(lastSuccessfulFetchAt, now);
  const isStale = age === null || age >= thresholdMinutes;

  // 3. stale
  if (isStale) return 'stale';

  const completeCoverage = usableCoverage >= totalCoverage && totalCoverage > 0;
  const attemptDegrades =
    softPartial ||
    (hardFailed && isAfter(lastAttemptedFetchAt, lastSuccessfulFetchAt));

  // 4. partial
  if (!completeCoverage || attemptDegrades) return 'partial';

  // 5. fresh
  return 'fresh';
}

/**
 * Build the public source-health payload from a list of
 * observations, one per source. The returned payload
 * includes the derived state and a sanitized warning
 * separate from the state.
 */
export function buildPublicSourceHealth(observationsById, now = new Date()) {
  if (!observationsById || typeof observationsById !== 'object') return [];
  const out = [];
  for (const src of SOURCE_REGISTRY_V11.sources) {
    const obs = observationsById[src.id] || null;
    const state = deriveSourceState(obs, now);
    const age = obs && obs.lastSuccessfulFetchAt
      ? minutesSince(obs.lastSuccessfulFetchAt, now)
      : null;
    out.push({
      id: src.id,
      displayName: src.displayName,
      type: src.type,
      purpose: src.purpose,
      provenanceUrl: src.provenanceUrl,
      authentication: src.authentication,
      refreshSchedule: src.refreshSchedule,
      freshness: {
        state,
        lastSuccessfulFetchAt: obs ? obs.lastSuccessfulFetchAt : null,
        lastAttemptedFetchAt: obs ? obs.lastAttemptedFetchAt : null,
        minutesSinceSuccess: age,
        thresholdMinutes: src.thresholdMinutes,
        partialReason: state === 'partial' && obs && obs.sanitizedReason ? obs.sanitizedReason : undefined,
        unavailableReason: state === 'unavailable' && obs && obs.sanitizedReason ? obs.sanitizedReason : undefined,
      },
      coverage: {
        enriched: obs ? obs.usableCoverage : 0,
        total: obs ? obs.totalCoverage : 0,
      },
      limitations: src.limitations,
      ...(src.backfill ? { backfill: src.backfill } : {}),
    });
  }
  return out;
}

/**
 * Build the compressed server-side source-health JSON
 * (the per-version source-health blob). The blob
 * persists only the OBSERVATIONS; the public state is
 * derived at request time.
 */
export function buildSourceHealthBlob(observationsById, now = new Date()) {
  const sources = [];
  for (const src of SOURCE_REGISTRY_V11.sources) {
    const obs = observationsById[src.id] || null;
    sources.push({
      id: src.id,
      lastSuccessfulFetchAt: obs ? obs.lastSuccessfulFetchAt : null,
      lastAttemptedFetchAt: obs ? obs.lastAttemptedFetchAt : null,
      lastAttemptOutcome: obs ? obs.lastAttemptOutcome : null,
      usableCoverage: obs ? obs.usableCoverage : 0,
      totalCoverage: obs ? obs.totalCoverage : 0,
      thresholdMinutes: src.thresholdMinutes,
      sanitizedReason: obs && obs.sanitizedReason ? obs.sanitizedReason : null,
    });
  }
  return {
    schemaVersion: '1.0.0',
    generatedAt: now.toISOString(),
    sources,
  };
}
