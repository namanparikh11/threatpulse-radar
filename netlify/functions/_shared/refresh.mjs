/**
 * Shared refresh logic for v5.2.
 *
 * Pure orchestration — takes a function that does the
 * CISA → NVD → FIRST EPSS build (and a writer function) and
 * returns a normalized result envelope. The actual upstream
 * fetching lives in `dataset.mjs` so this module doesn't
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
 */
import {
  clearRefreshLock,
  isRefreshLocked,
  REFRESH_LOCK_TTL_MS,
  writeLatestDataset,
} from './store.mjs';

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
 * Run a refresh: acquire the lock, run the build (via
 * `buildFn`), write the result to the blob (only on success),
 * and release the lock (best-effort).
 *
 *   buildFn() must return a successful live FetchResult
 *   (mode === 'live', source === 'merged') OR throw on
 *   failure. The function MUST NOT return a mock fallback —
 *   that contract is enforced here (a non-live result from
 *   buildFn is treated as a build failure and the existing
 *   blob is left untouched).
 *
 * Returns:
 *   { status: 'completed', fetchedAt, refreshInProgress: false }
 *     — a successful refresh; the blob has been updated.
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

  // ---- 3. Build the dataset (outside the try so a thrown build
  //         still falls through to the lock-release path) ----
  let result;
  let buildError = null;
  try {
    result = await buildFn();
    if (!result || result.mode !== 'live' || result.source !== 'merged') {
      buildError = new Error(
        'Refresh build returned a non-live result; existing blob is preserved.',
      );
    }
  } catch (err) {
    buildError = err instanceof Error ? err : new Error(String(err));
  }

  // ---- 4. Write on success, leave existing blob on failure ----
  if (buildError) {
    await clearRefreshLock(store);
    return {
      status: 'failed',
      reason: buildError.message,
      refreshInProgress: false,
    };
  }

  const envelope = envelopeFor(result);
  await writeLatestDataset(store, envelope);
  await clearRefreshLock(store);

  return {
    status: 'completed',
    fetchedAt: envelope.fetchedAt,
    refreshInProgress: false,
  };
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
 * Pure-JS helper exported for the acceptance suite. Mirrors
 * the lock + write + release contract without touching the
 * Blob store. Returns the same `{ status, fetchedAt,
 * refreshInProgress }` shape as `runRefresh`.
 *
 *   - If `existingLock` is active (per `isLockActive`), returns
 *     `{ status: 'in-progress', ... }`.
 *   - If `build` returns a non-live result or throws, returns
 *     `{ status: 'failed', ... }`.
 *   - Otherwise returns `{ status: 'completed', fetchedAt }`.
 *
 * `writeResult` is a callback `(envelope) => void` so the
 * test can verify the envelope shape without touching Blobs.
 */
export function decideRefresh({
  existingLock,
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

/**
 * Pure-JS helper for the acceptance suite: decide whether a
 * refresh should be skipped because another refresh is in
 * progress. Mirrors the `isRefreshLocked` Blob-based check.
 */
export function shouldSkipRefresh(existingLock, now = new Date()) {
  return isLockActivePure(existingLock, now);
}