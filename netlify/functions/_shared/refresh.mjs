/**
 * Shared refresh logic for v5.2.
 *
 * Pure orchestration — takes a function that does the
 * CISA → NVD → FIRST EPSS build (and a writer function) and
 * returns a normalized result envelope. The actual upstream
 * fetching lives in `liveBuild.mjs` so this module doesn't
 * duplicate the field-mapping rules.
 *
 * Used by:
 *   - refresh-dataset-background.mjs (HTTP trigger, fires on
 *     manual button click)
 *   - refresh-dataset-scheduled.mjs  (cron trigger, every 30 min)
 *
 * Why the orchestrator is split out:
 *   The lock + write + result-shape contract must be IDENTICAL
 *   for both triggers. If the manual button's refresh wrote a
 *   slightly different envelope than the scheduled one, the
 *   client would see two different `proxyStatus` values for the
 *   "same" dataset. This module is the single source of truth
 *   for that envelope shape.
 *
 * v5.2.6 — NVD backoff + dataset quality guard:
 *   Problem: an NVD HTTP 429 (rate-limit) refresh would
 *   overwrite the existing `latest-dataset` blob with a worse
 *   envelope — `nvdStatus: "unavailable"`, no CVSS scores for
 *   the rate-limited chunk, and `cvssScore: 0` for every record.
 *   The next visitor would silently see a less-enriched
 *   dashboard until the next successful refresh, with no
 *   indication that the data got worse.
 *
 *   Minimum safe fix:
 *     1. After a successful build, read the EXISTING
 *        `latest-dataset` blob (if any).
 *     2. Compare old vs new by the documented quality rule:
 *        - new is "rate-limited" iff
 *          new.nvdStatus === "unavailable" AND
 *          /429|rate limit/i.test(new.nvdReason)
 *        - old is "better" iff
 *          old.nvdStatus === "nvd" AND
 *          countCvssAboveZero(old) >= countCvssAboveZero(new)
 *     3. If BOTH hold → skip the overwrite. The existing
 *        blob continues to serve visitors.
 *     4. When a refresh is preserved by the guard (or skipped
 *        outright because the cooldown is already active and
 *        an existing good blob is present), set the
 *        `nvd-cooldown` blob so the NEXT refresh can
 *        short-circuit the doomed NVD call.
 *     5. The cooldown is cleared when a fresh, non-rate-limited
 *        build completes successfully.
 *
 *   Result statuses (v5.2.6):
 *     'completed'  — new blob written.
 *     'preserved'  — new build succeeded but the quality guard
 *                    refused to overwrite an existing better blob
 *                    (NVD rate-limited; existing has more coverage).
 *                    The existing blob continues to serve visitors.
 *                    `reason` explains why.
 *     'cooldown'   — NVD cooldown was active AND an existing good
 *                    blob was present, so we skipped the build
 *                    entirely (no point in doing work we'd
 *                    discard). `reason` explains why.
 *     'in-progress'— another refresh already holds the lock.
 *     'failed'     — build threw or returned a non-live result.
 *
 * v5.4.2 — Last-known-good dataset serving:
 *   The v5.2.6 quality guard was narrow — it fired only on
 *   rate-limit downgrades. A real production incident
 *   showed this is not enough: a scheduled refresh
 *   timed out against NVD, and the guard let the
 *   timeout-degraded envelope overwrite the existing
 *   NVD-enriched blob. Visitors saw CVSS scores drop to 0
 *   and a timeout banner appear.
 *
 *   Broader rule: any NVD-unavailable refresh with a good
 *   existing blob is preserved. The new envelope is
 *   discarded, the existing blob continues to serve, and
 *   the public UI keeps showing "NVD: enriched" until a
 *   genuinely better (NVD-enriched) build arrives. The
 *   internal `lastRefreshFailure` metadata records the
 *   precise reason (timeout / 429 / 5xx / network /
 *   cooldown-skip) so operators can see why a refresh
 *   didn't update the blob, but that field is stripped
 *   from the public response.
 *
 *   The guard still preserves the v5.2.6 contracts:
 *     - the bootstrap path (no existing blob) still writes
 *       the (possibly degraded) envelope, so visitors on a
 *       fresh deploy have something to look at;
 *     - the 'completed' / 'preserved' / 'cooldown' /
 *       'in-progress' / 'failed' status set is unchanged;
 *     - the refresh-lock + cooldown short-circuits are
 *       unchanged;
 *     - `forceRefresh: true` and `manualRefresh()` still
 *       call this orchestrator, so the guard fires on
 *       both the manual and scheduled paths.
 *
 * v5.5 — CISA Vulnrichment / SSVC enrichment:
 *   After a successful 'completed' write, the orchestrator
 *   also runs the Vulnrichment enrichment pass (see
 *   `vulnrichmentRefresh.mjs`). The pass reads the new
 *   envelope's CVE list and enriches the SSVC cache
 *   incrementally:
 *     - missing or stale (≥ 7 d) CVEs only;
 *     - max 50 per cycle;
 *     - concurrency 5;
 *     - KEV-newest first.
 *   The Vulnrichment pass shares the same lock as the main
 *   build (no double-refresh risk) and the outcome is
 *   recorded on the existing `latest-dataset` blob as an
 *   internal `lastVulnrichmentRefresh` field. The field is
 *   stripped from the public response by `dataset.mjs`
 *   (via the `INTERNAL_BLOB_FIELDS` set below) — visitors
 *   only see the derived `vulnrichmentStatus` /
 *   `vulnrichmentCoverage` envelope metadata, computed at
 *   read-time in `dataset.mjs`.
 *
 *   The Vulnrichment pass is best-effort. A failure or
 *   partial completion of the Vulnrichment cycle does NOT
 *   downgrade the main build's status — the 'completed'
 *   / 'preserved' / 'cooldown' / 'in-progress' / 'failed'
 *   set is unchanged. The public `vulnrichmentStatus`
 *   honestly reflects the cache state (available / partial
 *   / unavailable).
 */
import {
  clearNvdCooldown,
  clearRefreshLock,
  getVulnrichmentStore,
  isNvdCooldownActive,
  isRefreshLocked,
  LATEST_DATASET_KEY,
  readLatestDataset,
  readNvdCooldown,
  REFRESH_LOCK_TTL_MS,
  writeLatestDataset,
  writeNvdCooldown,
} from './store.mjs';
import { readNvdOutcome } from './liveBuild.mjs';
import { runVulnrichmentRefresh } from './vulnrichmentRefresh.mjs';

/**
 * Default envelope shape written to the latest-dataset blob on
 * a successful refresh. Mirrors the v5.0 / v5.1 `FetchResult`
 * contract — `mode: 'live'`, `source: 'merged'`, the per-provider
 * status fields, and the function's `proxyStatus`. The
 * `dataSource: 'prebuilt-store'` tag is a v5.2 addition that
 * tells the client "this came from the shared blob, not a live
 * build on this request".
 */
function envelopeFor(payload, extra = {}) {
  return {
    ...payload,
    proxyStatus: 'proxy',
    dataSource: 'prebuilt-store',
    ...extra,
  };
}

/**
 * v5.2.6: Count the records in an envelope that have a positive
 * CVSS score. Used by the quality guard to compare an existing
 * blob against a freshly-built one. Defensive against malformed
 * envelopes (null data, missing cvssScore fields).
 */
export function countCvssAboveZero(envelope) {
  if (!envelope || !Array.isArray(envelope.data)) return 0;
  let n = 0;
  for (const rec of envelope.data) {
    if (rec && typeof rec.cvssScore === 'number' && rec.cvssScore > 0) n++;
  }
  return n;
}

/**
 * v5.2.6: Returns `true` iff the envelope's NVD status +
 * reason indicate a rate-limit failure that would overwrite a
 * better blob if we wrote it. Matches the documented rule:
 *   nvdStatus === 'unavailable' AND
 *   /429|rate limit/i.test(nvdReason)
 *
 * Exported so the acceptance suite can verify the predicate
 * without going through `runRefresh`.
 *
 * v5.4.2: retained for backwards compatibility (the
 * acceptance-prebuilt suite still tests the narrow
 * rate-limit-only check). The broader rule that drives the
 * production guard is `isNvdTransientOrSkipped` below.
 */
export function isNvdRateLimitedReason(envelope) {
  if (!envelope) return false;
  if (envelope.nvdStatus !== 'unavailable') return false;
  if (typeof envelope.nvdReason !== 'string') return false;
  return /429|rate\s*limit/i.test(envelope.nvdReason);
}

/**
 * v5.4.2: Broader predicate — returns `true` iff the
 * envelope's NVD enrichment failed in a way that should
 * NOT overwrite a good existing blob. Covers every
 * transient failure mode the live-build pipeline can
 * produce:
 *
 *   - rate-limited  (HTTP 429 from NVD)
 *   - timed-out     (per-request or overall budget exhausted)
 *   - http-error    (HTTP 5xx or other non-2xx upstream)
 *   - network-error (DNS / connection refused / TLS / etc.)
 *   - cooldown-skipped (orchestrator asked us to skip the
 *                       NVD fetch because the cooldown is
 *                       active and no good existing blob is
 *                       present — the synthetic 'cooldown
 *                       active' envelope should still be
 *                       discarded if a good blob exists)
 *
 * The check is name-based for rate-limit / timeout / http-
 * error (matching the stable reason strings produced by
 * `liveBuild.mjs`) and Symbol-based for cooldown-skipped
 * (the outcome attached via `NVD_OUTCOME`).
 *
 * Exported for the acceptance suite.
 */
export function isNvdTransientOrSkipped(envelope) {
  if (!envelope) return false;
  if (envelope.nvdStatus !== 'unavailable') return false;
  const outcome = readNvdOutcome(envelope);
  if (outcome === 'cooldown-skipped') return true;
  if (typeof envelope.nvdReason !== 'string') return false;
  if (/429|rate\s*limit/i.test(envelope.nvdReason)) return true;
  if (/timed\s*out|after\s+\d+\s*ms/i.test(envelope.nvdReason)) return true;
  if (/HTTP\s+5\d\d/i.test(envelope.nvdReason)) return true;
  if (/fetch\s*failed|fetch\s*error|ENOTFOUND|ECONNREFUSED|ETIMEDOUT|EAI_AGAIN/i.test(envelope.nvdReason)) {
    return true;
  }
  // Unknown failure type — still treat as transient to be
  // safe (don't overwrite a good blob with an unknown-bad
  // blob). The orchestrator logs the raw reason via
  // lastRefreshFailure so the operator can investigate.
  return true;
}

/**
 * v5.4.2: Decide whether to skip overwriting the existing
 * `latest-dataset` blob with a freshly-built one. The guard
 * is intentionally simple — it fires whenever:
 *
 *   1. An existing blob IS present (nothing to preserve
 *      against on a fresh deploy).
 *   2. The new envelope's NVD status is 'unavailable' (i.e.
 *      the new build lost NVD enrichment for any reason —
 *      timeout, 429, 5xx, network, or cooldown-skip).
 *   3. The existing blob has NVD enriched (`nvdStatus: 'nvd'`)
 *      AND has at least one CVSS-positive record.
 *
 * In all other cases (no existing blob, new is enriched,
 * old is also degraded, etc.) the guard returns false and
 * the write proceeds.
 *
 * The v5.2.6 guard additionally required the new to be
 * rate-limit-classified AND the old to have at least as
 * many CVSS-positive records as the new. v5.4.2 broadens
 * both conditions: any NVD-unavailable new is a downgrade
 * when a good old exists, and a single CVSS-positive record
 * in the old is enough to count as "good" (the rest are
 * CISA-derived severity, which is preserved either way).
 */
export function shouldSkipOverwrite(oldEnvelope, newEnvelope) {
  if (!oldEnvelope) return false;
  if (!newEnvelope) return false;
  if (newEnvelope.nvdStatus !== 'unavailable') return false;
  if (oldEnvelope.nvdStatus !== 'nvd') return false;
  if (countCvssAboveZero(oldEnvelope) === 0) return false;
  return true;
}

/**
 * v5.4.2: Build the internal `lastRefreshFailure` payload
 * to merge into the blob. Exported so the acceptance suite
 * can verify the shape and the truncation rules without
 * going through the orchestrator.
 *
 * Shape:
 *   {
 *     type: 'rate-limited' | 'timed-out' | 'http-error' |
 *           'network-error' | 'cooldown-skipped' |
 *           'preserved' | 'build-error' | 'unknown',
 *     reason: string,  // truncated to ~200 chars
 *     at: ISO string,  // when the failure was recorded
 *   }
 *
 * `type` is derived from the envelope's NVD outcome (via
 * `readNvdOutcome`) when one is present, otherwise from a
 * short keyword check on the reason. `reason` is the
 * envelope's `nvdReason` truncated for safety.
 */
export function buildRefreshFailurePayload(envelope, now = new Date()) {
  const rawReason =
    envelope && typeof envelope.nvdReason === 'string'
      ? envelope.nvdReason
      : 'unknown reason';
  const outcome = readNvdOutcome(envelope);
  let type = outcome;
  if (!type || type === 'enriched') {
    // Fall back to keyword classification for envelopes
    // produced before v5.4.2 (no NVD_OUTCOME attached).
    if (/429|rate\s*limit/i.test(rawReason)) type = 'rate-limited';
    else if (/timed\s*out|after\s+\d+\s*ms/i.test(rawReason)) type = 'timed-out';
    else if (/HTTP\s+5\d\d/i.test(rawReason)) type = 'http-error';
    else if (/cooldown\s*active/i.test(rawReason)) type = 'cooldown-skipped';
    else if (/fetch\s*failed|fetch\s*error|ENOTFOUND|ECONNREFUSED|ETIMEDOUT|EAI_AGAIN/i.test(rawReason)) {
      type = 'network-error';
    } else {
      type = 'unknown';
    }
  }
  return {
    type,
    reason: truncateForFailureReason(rawReason, 200),
    at: now.toISOString(),
  };
}

function truncateForFailureReason(s, max) {
  if (typeof s !== 'string') return 'unknown reason';
  if (s.length <= max) return s;
  return s.slice(0, max - 1) + '\u2026';
}

/**
 * v5.4.2: Internal fields that the orchestrator writes to
 * the blob alongside the public envelope, and that
 * `dataset.mjs` strips before sending the response to the
 * visitor. Exposed as a single Set so the strip logic in
 * `dataset.mjs` can iterate the same source of truth.
 *
 * v5.5: added `lastVulnrichmentRefresh` — the per-cycle
 * outcome of the Vulnrichment enrichment pass (status,
 * enriched/total counts, last attempt time). Operators see
 * it via the blob inspector; visitors never see the raw
 * operator metadata. The derived public fields
 * (`vulnrichmentStatus` / `vulnrichmentCoverage`) are
 * computed at read-time in `dataset.mjs` and are NOT on
 * this strip list because they ARE public.
 */
export const INTERNAL_BLOB_FIELDS = new Set([
  'lastRefreshAttemptAt',
  'lastRefreshFailure',
  'lastVulnrichmentRefresh',
]);

/**
 * Run a refresh: acquire the lock, run the build (via
 * `buildFn`), write the result to the blob (only on success),
 * and release the lock (best-effort).
 *
 *   buildFn(opts) must return a successful live FetchResult
 *   (mode === 'live', source === 'merged') OR throw on
 *   failure. The function MUST NOT return a mock fallback —
 *   that contract is enforced here (a non-live result from
 *   buildFn is treated as a build failure and the existing
 *   blob is left untouched).
 *
 *   buildFn is called with a single `{ skipNvd: boolean }`
 *   argument. v5.2.6 sets `skipNvd: true` when the NVD
 *   cooldown is active AND there is no existing good blob
 *   (so the build still runs to refresh CISA + EPSS, but the
 *   NVD fetch is short-circuited).
 *
 * Returns (v5.2.6):
 *   { status: 'completed', fetchedAt, refreshInProgress: false }
 *     — a successful refresh; the blob has been updated.
 *   { status: 'preserved', reason, refreshInProgress: false }
 *     — v5.2.6: the new build succeeded but the quality guard
 *       refused to overwrite an existing better blob. The
 *       existing blob continues to serve visitors.
 *   { status: 'cooldown',  reason, refreshInProgress: false }
 *     — v5.2.6: the NVD cooldown was active AND an existing
 *       good blob was present; we skipped the build entirely.
 *   { status: 'in-progress', fetchedAt: null, refreshInProgress: true }
 *     — the lock was already held; nothing was built.
 *   { status: 'failed', reason, refreshInProgress: false }
 *     — the build threw or returned a non-live result; the
 *       existing blob is preserved.
 */
export async function runRefresh({ store, buildFn, now = new Date() } = {}) {
  if (!store) {
    return {
      status: 'failed',
      reason: 'No Blob store available (v5.2 requires Netlify Blobs).',
      refreshInProgress: false,
    };
  }

  // ---- 1. Lock check (skip if another refresh is in progress) ----
  if (await isRefreshLocked(store, now)) {
    return {
      status: 'in-progress',
      fetchedAt: null,
      refreshInProgress: true,
    };
  }

  // ---- 2. Acquire the lock ----
  const acquired = await tryAcquireOrSkip(store, now);
  if (!acquired) {
    return {
      status: 'in-progress',
      fetchedAt: null,
      refreshInProgress: true,
    };
  }

  // ---- 3. v5.2.6: read the existing blob + cooldown marker.
  //         Used by the short-circuit (cooldown + good blob)
  //         and by the post-build quality guard. ----
  const existing = await readLatestDataset(store);
  const cooldown = await readNvdCooldown(store);
  const cooldownActive = isNvdCooldownActive(cooldown, now);
  const existingIsGood =
    !!existing &&
    existing.nvdStatus === 'nvd' &&
    countCvssAboveZero(existing) > 0;

  // ---- 4. v5.2.6: cooldown short-circuit.
  //   If the cooldown is active AND there's an existing good
  //   blob to keep serving, skip the build entirely. No point
  //   in doing work (CISA + NVD + EPSS) that the quality guard
  //   would discard. The existing blob continues to serve
  //   visitors. ----
  //
  //   v5.4.2: still update the internal `lastRefreshAttemptAt`
  //   / `lastRefreshFailure` metadata on the existing blob so
  //   operators can see why the latest attempt was a no-op.
  if (cooldownActive && existingIsGood) {
    await writeInternalMetadata(
      store,
      buildRefreshFailurePayload(
        {
          nvdStatus: 'unavailable',
          nvdReason:
            (cooldown && cooldown.reason) ||
            'NVD cooldown active; existing blob preserved.',
        },
        now,
      ),
      now,
    );
    await clearRefreshLock(store);
    return {
      status: 'cooldown',
      reason:
        (cooldown && cooldown.reason) ||
        'NVD cooldown active; existing blob preserved.',
      refreshInProgress: false,
    };
  }

  // ---- 5. Build the dataset (outside the try so a thrown build
  //         still falls through to the lock-release path).
  //         v5.2.6: when the cooldown is active but no good
  //         existing blob is present (e.g. a fresh deploy that
  //         caught NVD mid-rate-limit), still run the build —
  //         but ask `buildFn` to skip the doomed NVD fetch so
  //         we don't waste a minute hammering NVD. The result
  //         will be a CISA + EPSS envelope with NVD unavailable,
  //         which the bootstrap path on the dataset endpoint
  //         will surface honestly. ----
  let result;
  let buildError = null;
  try {
    result = await buildFn({ skipNvd: cooldownActive && !existingIsGood });
    if (!result || result.mode !== 'live' || result.source !== 'merged') {
      buildError = new Error(
        'Refresh build returned a non-live result; existing blob is preserved.',
      );
    }
  } catch (err) {
    buildError = err instanceof Error ? err : new Error(String(err));
  }

  // ---- 6. Build failure → release lock, leave existing blob ----
  //
  //   v5.4.2: still update the internal metadata so operators
  //   can see that a refresh was attempted and what failed.
  if (buildError) {
    await writeInternalMetadata(
      store,
      {
        type: 'build-error',
        reason: truncateForFailureReason(buildError.message, 200),
        at: now.toISOString(),
      },
      now,
    );
    await clearRefreshLock(store);
    return {
      status: 'failed',
      reason: buildError.message,
      refreshInProgress: false,
    };
  }

  const envelope = envelopeFor(result);

  // ---- 7. v5.4.2: Quality guard — refuse to overwrite a good
  //   existing blob with any NVD-unavailable downgrade. The
  //   guard fires for every transient NVD failure mode
  //   (rate-limit, timeout, 5xx, network, cooldown-skip) —
  //   see `shouldSkipOverwrite` for the predicate. ----
  if (shouldSkipOverwrite(existing, envelope)) {
    // Mark the cooldown so the next refresh short-circuits
    // the doomed NVD fetch and goes straight to 'cooldown'.
    await writeNvdCooldown(
      store,
      buildCooldownPayloadFromEnvelope(envelope, now),
    );
    // v5.4.2: update the internal metadata on the existing
    // blob so operators can see why the latest refresh
    // didn't update the public dataset.
    await writeInternalMetadata(
      store,
      buildRefreshFailurePayload(envelope, now),
      now,
    );
    const outcome = readNvdOutcome(envelope) || 'unavailable';
    await clearRefreshLock(store);
    return {
      status: 'preserved',
      reason:
        `NVD ${outcome} downgrade detected (${truncateForReason(
          envelope.nvdReason || 'unknown',
          160,
        )}); ` +
        `existing blob preserved with ${countCvssAboveZero(existing)} ` +
        `CVSS-positive record(s) vs ${countCvssAboveZero(envelope)} in the ` +
        `new build.`,
      refreshInProgress: false,
    };
  }

  // ---- 8. Write the envelope. Clear the cooldown marker on
  //   a non-rate-limited success so the next refresh goes
  //   through the normal NVD path again. ----
  //
  //   v5.4.2: stamp `lastRefreshAttemptAt` and clear
  //   `lastRefreshFailure` on the written envelope. The
  //   metadata is internal — `dataset.mjs` strips it from
  //   the public response.
  //
  //   v5.5: also run the Vulnrichment enrichment pass and
  //   record its outcome in the internal `lastVulnrichmentRefresh`
  //   field on the same blob. The pass shares the same lock as
  //   the main build — no double-refresh risk. Failures of
  //   the Vulnrichment pass do NOT downgrade the main build's
  //   status; the field is purely informational.
  let vulnrichmentOutcome = null;
  try {
    const vulnStore = getVulnrichmentStore();
    const cveList = (envelope.data || []).map((r) => ({
      cveId: r.cveId,
      dateAdded: r.publishedDate || null,
    }));
    vulnrichmentOutcome = await runVulnrichmentRefresh({
      store: vulnStore,
      cveList,
      now,
    });
  } catch (err) {
    // Defensive: a thrown Vulnrichment cycle must never
    // break the main refresh. The `runVulnrichmentRefresh`
    // contract is to NEVER throw, but a defensive catch
    // here keeps the main refresh's 'completed' status
    // honest even if a future regression introduces a
    // throw.
    vulnrichmentOutcome = {
      status: 'failed',
      enriched: 0,
      total: 0,
      attempted: 0,
      missing: 0,
      transient: 0,
      reason:
        err instanceof Error
          ? `Vulnrichment pass threw: ${err.message}`
          : 'Vulnrichment pass threw an unknown error.',
      lastAttemptAt: now.toISOString(),
    };
  }

  await writeLatestDataset(store, {
    ...envelope,
    lastRefreshAttemptAt: now.toISOString(),
    lastRefreshFailure: null,
    lastVulnrichmentRefresh: vulnrichmentOutcome,
  });
  if (!isNvdRateLimitedReason(envelope)) {
    await clearNvdCooldown(store);
  } else {
    // Even when the new is rate-limited, if it has STRICTLY
    // MORE CVSS-positive records than the old (so the guard
    // let us write), keep the cooldown so the next refresh
    // knows NVD is still flaky.
    await writeNvdCooldown(
      store,
      buildCooldownPayloadFromEnvelope(envelope, now),
    );
  }
  await clearRefreshLock(store);

  return {
    status: 'completed',
    fetchedAt: envelope.fetchedAt,
    refreshInProgress: false,
  };
}

/**
 * v5.4.2: Update the internal metadata fields on the
 * existing `latest-dataset` blob without touching the
 * public envelope. Used by the 'cooldown', 'failed', and
 * 'preserved' paths so operators can see when the latest
 * refresh was attempted and what blocked the write.
 *
 * No-op when there's no existing blob (nothing to attach
 * the metadata to — the first refresh failure on a fresh
 * deploy simply has no record).
 */
async function writeInternalMetadata(store, failurePayload, now) {
  if (!store) return false;
  let existing;
  try {
    existing = await readLatestDataset(store);
  } catch {
    return false;
  }
  if (!existing) return false;
  try {
    await store.setJSON(LATEST_DATASET_KEY, {
      ...existing,
      lastRefreshAttemptAt: now.toISOString(),
      lastRefreshFailure: failurePayload || null,
    });
    return true;
  } catch {
    return false;
  }
}

/**
 * Inner acquire helper, isolated so the runRefresh body reads
 * top-down. Returns `true` on successful acquisition.
 */
async function tryAcquireOrSkip(store, now) {
  // Inline acquire to keep the lock semantics in one place.
  const { tryAcquireRefreshLock } = await import('./store.mjs');
  return tryAcquireRefreshLock(store, now);
}

/**
 * Build a cooldown payload from a freshly-built envelope.
 * Internal helper — uses the same TTL as the public
 * `buildCooldownPayload` from `store.mjs` but derives the
 * reason from the envelope's `nvdReason` so the marker
 * carries useful operator-facing context (e.g. "NVD rate
 * limit reached (HTTP 429). ...").
 */
function buildCooldownPayloadFromEnvelope(envelope, now) {
  // Inline import to avoid a circular reference at module
  // load time (this module re-exports helpers from store.mjs).
  return {
    setAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + 15 * 60 * 1000).toISOString(),
    reason:
      typeof envelope?.nvdReason === 'string'
        ? truncateForReason(envelope.nvdReason, 200)
        : 'NVD rate limit detected',
  };
}

function truncateForReason(s, max) {
  if (typeof s !== 'string') return 'NVD rate limit detected';
  if (s.length <= max) return s;
  return s.slice(0, max - 1) + '…';
}

/**
 * Pure-JS helper exported for the acceptance suite. Mirrors
 * the lock + cooldown + quality-guard + write + release
 * contract without touching the Blob store. Returns the same
 * `{ status, fetchedAt, refreshInProgress }` shape as
 * `runRefresh`.
 *
 *   - If `existingLock` is active (per `isLockActive`), returns
 *     `{ status: 'in-progress', ... }`.
 *   - If `existingCooldown` is active AND `existingBlob` is
 *     "good" (nvdStatus==='nvd' with cvssScore>0 records),
 *     returns `{ status: 'cooldown', reason }`.
 *   - If `build` returns a non-live result or throws, returns
 *     `{ status: 'failed', ... }`.
 *   - If the freshly-built envelope should NOT overwrite the
 *     existing blob per the v5.4.2 quality guard (any
 *     NVD-unavailable downgrade against a good existing
 *     blob), returns `{ status: 'preserved', reason }`.
 *   - Otherwise returns `{ status: 'completed', fetchedAt }`.
 *
 * `writeResult` is a callback `(envelope) => void` so the
 * test can verify the envelope shape without touching Blobs.
 * It is called ONLY when the status is 'completed'.
 */
export function decideRefresh({
  existingLock,
  existingCooldown,
  existingBlob,
  buildResult,
  buildError,
  now = new Date(),
  ttlMs = REFRESH_LOCK_TTL_MS,
}) {
  if (existingLock && isLockActivePure(existingLock, now)) {
    return {
      status: 'in-progress',
      fetchedAt: null,
      refreshInProgress: true,
    };
  }
  if (
    existingCooldown &&
    isCooldownActivePure(existingCooldown, now) &&
    isGoodBlobPure(existingBlob)
  ) {
    return {
      status: 'cooldown',
      reason:
        (existingCooldown && existingCooldown.reason) ||
        'NVD cooldown active; existing blob preserved.',
      refreshInProgress: false,
    };
  }
  if (buildError) {
    return {
      status: 'failed',
      reason: buildError instanceof Error ? buildError.message : String(buildError),
      refreshInProgress: false,
    };
  }
  if (!buildResult || buildResult.mode !== 'live' || buildResult.source !== 'merged') {
    return {
      status: 'failed',
      reason: 'Refresh build returned a non-live result; existing blob is preserved.',
      refreshInProgress: false,
    };
  }
  if (shouldSkipOverwrite(existingBlob, buildResult)) {
    const oldCount = countCvssAboveZero(existingBlob);
    const newCount = countCvssAboveZero(buildResult);
    const outcome = readNvdOutcome(buildResult) || 'unavailable';
    return {
      status: 'preserved',
      reason:
        `NVD ${outcome} downgrade detected; ` +
        `existing blob preserved (${oldCount} vs ${newCount} CVSS-positive records).`,
      refreshInProgress: false,
    };
  }
  return {
    status: 'completed',
    fetchedAt: buildResult.fetchedAt,
    refreshInProgress: false,
  };
}

function isLockActivePure(lock, now) {
  if (!lock) return false;
  if (typeof lock.expiresAt !== 'string') return false;
  const t = new Date(lock.expiresAt).getTime();
  if (Number.isNaN(t)) return false;
  return t > now.getTime();
}

function isCooldownActivePure(cooldown, now) {
  if (!cooldown) return false;
  if (typeof cooldown.expiresAt !== 'string') return false;
  const t = new Date(cooldown.expiresAt).getTime();
  if (Number.isNaN(t)) return false;
  return t > now.getTime();
}

function isGoodBlobPure(blob) {
  if (!blob) return false;
  if (blob.nvdStatus !== 'nvd') return false;
  return countCvssAboveZero(blob) > 0;
}

/**
 * Pure-JS helper for the acceptance suite: decide whether a
 * refresh should be skipped because another refresh is in
 * progress. Mirrors the `isRefreshLocked` Blob-based check.
 */
export function shouldSkipRefresh(existingLock, now = new Date()) {
  return isLockActivePure(existingLock, now);
}