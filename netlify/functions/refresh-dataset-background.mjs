/**
 * Netlify Background Function — `/.netlify/functions/refresh-dataset-background`
 *
 * v5.2 manual-refresh endpoint. Triggered by the dashboard's
 * "Refresh live data" button (a POST from the client).
 *
 * Why a *background* function (filename suffix `-background.mjs`):
 *   Netlify background functions have up to a 15-minute timeout
 *   (vs. the 26-second sync limit on regular functions). A full
 *   CISA → NVD → EPSS build can take 30–60 s on a cold cache
 *   without an NVD_API_KEY (NVD chunks fetch serially under
 *   the 5-req/30s anonymous rate limit). The background suffix
 *   gives the refresh room to complete without being killed by
 *   Netlify's sync timeout. The function returns its Response
 *   as soon as the lock is acquired — the actual build runs
 *   in the background.
 *
 * Flow:
 *   1. Acquire the refresh-lock blob. If another refresh
 *      already holds it (non-expired), return
 *      `202 { status: 'in-progress', refreshInProgress: true }`.
 *      The dashboard uses this to show the existing "Refresh
 *      running in background" pill.
 *   2. Otherwise, kick off the build via `runRefresh`. The
 *      orchestrator:
 *        - runs `buildLiveDataset()` (the shared pipeline),
 *        - on success: writes the envelope to `latest-dataset`
 *          and releases the lock,
 *        - on failure: releases the lock and leaves the
 *          existing blob untouched.
 *   3. The dashboard's existing 5-minute v5.1 polling picks up
 *      the new blob on the next tick and surfaces the
 *      "New dataset available" banner. The user clicks Apply.
 *      No auto-reload, no auto-replace — the v5.1 UX contract is
 *      preserved end-to-end.
 *
 * Response shape (200 — refresh completed in the same invocation):
 *   { status: 'completed', fetchedAt: string (ISO), refreshInProgress: false }
 *
 * Response shape (202 — refresh started, will complete in the background):
 *   { status: 'started', fetchedAt: null, refreshInProgress: true }
 *
 * Response shape (202 — another refresh already in progress):
 *   { status: 'in-progress', fetchedAt: null, refreshInProgress: true }
 *
 * Response shape (500 — orchestrator failed to start):
 *   { status: 'failed', reason: string, refreshInProgress: false }
 */

import {
  getDatasetStore,
} from './_shared/store.mjs';
import {
  runRefresh,
} from './_shared/refresh.mjs';
import { buildLiveDataset } from './_shared/liveBuild.mjs';

export default async (request, context) => {
  // ---- 1. Resolve the Blob store. In local dev with no Blobs
  //         context, fail fast with a clear error. ----
  let store;
  try {
    store = getDatasetStore();
  } catch (err) {
    return jsonResponse(500, {
      status: 'failed',
      reason: 'Blob store unavailable: ' + (err instanceof Error ? err.message : String(err)),
      refreshInProgress: false,
    });
  }

  // ---- 2. Use `context.waitUntil` to keep the function alive
  //         beyond the response when the build is going to
  //         take a while. This is the documented Netlify
  //         pattern for fire-and-forget work after a Response
  //         is sent. The Response itself is sent as soon as
  //         the lock is acquired; the build completes in the
  //         background. ----
  let buildPromise = null;
  if (context && typeof context.waitUntil === 'function') {
    buildPromise = runRefresh({
      store,
      buildFn: () => buildLiveDataset(),
    });
    context.waitUntil(buildPromise);
  } else {
    // No `context.waitUntil` available (older runtime or
    // unit-test harness). Run synchronously. Netlify's
    // background-function runtime always provides context;
    // this branch is purely defensive.
    buildPromise = runRefresh({
      store,
      buildFn: () => buildLiveDataset(),
    });
  }

  // Peek at the lock decision synchronously so we can return
  // a useful status immediately. If the lock was NOT
  // acquirable (another refresh is in progress), `runRefresh`
  // will return `{ status: 'in-progress' }` without running
  // the build.
  const earlyResult = await peekLockDecision(store);
  if (earlyResult.refreshInProgress) {
    return jsonResponse(202, {
      status: 'in-progress',
      fetchedAt: null,
      refreshInProgress: true,
    });
  }

  // We expect the build to be quick enough that the
  // background invocation will complete before the next
  // visitor hits the dataset endpoint, but we don't BLOCK
  // on it — the user gets an immediate 202 "started"
  // response and the dashboard polls for the new dataset
  // via the v5.1 mechanism.
  return jsonResponse(202, {
    status: 'started',
    fetchedAt: null,
    refreshInProgress: true,
  });
};

function jsonResponse(status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Access-Control-Allow-Origin': '*',
      'X-Content-Type-Options': 'nosniff',
    },
  });
}

/**
 * Synchronous check for whether the lock is currently held.
 * Used to give the user immediate feedback when they click
 * "Refresh live data" and another refresh is already running.
 * Mirrors the lock check inside `runRefresh` so the two
 * agree on whether the lock was acquired.
 */
async function peekLockDecision(store) {
  try {
    const { isRefreshLocked } = await import('./_shared/store.mjs');
    const held = await isRefreshLocked(store);
    return { refreshInProgress: held };
  } catch {
    return { refreshInProgress: false };
  }
}