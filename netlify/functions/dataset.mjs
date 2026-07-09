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
 * Response shape (200 — prebuilt store hit):
 *   {
 *     data: Vulnerability[],
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
 *   }
 *
 * Response shape (200 — bootstrap path):
 *   Same as above but `dataSource: 'live-build'` so the client
 *   can distinguish "this is the freshly-built dataset" from
 *   "this came from the shared blob". `refreshInProgress` is
 *   `false` (we just finished building it).
 *
 * Response shape (502 — CISA failed in bootstrap):
 *   { mode: 'fallback', fallbackReason: string, refreshInProgress: false }
 *
 * Honesty contract (carried forward from v5.0.1 / v5.0.3):
 *   - CISA is the only gating upstream. If CISA fails, the
 *     function returns HTTP 502 with a `fallbackReason`. The
 *     client treats this as "live fetch failed" and falls back
 *     to the local mock dataset (or a stale localStorage cache).
 *   - NVD and EPSS have their own status fields. A failure of
 *     either does NOT take the whole response down — the client
 *     gets HTTP 200 with `nvdStatus: 'unavailable'` /
 *     `epssStatus: 'unavailable'`.
 *   - No API keys, secrets, or tokens are read or shipped.
 *     `NVD_API_KEY` is read inside the function only, passed to
 *     NVD as a request header (`headers.apiKey = apiKey`), and
 *     never included in the response body or logs.
 *   - The prebuilt blob is NEVER overwritten with a mock
 *     fallback. Only a successful live build writes to it.
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
 */

import {
  buildLiveDataset,
} from './_shared/liveBuild.mjs';
import {
  getDatasetStore,
  isRefreshLocked,
  readLatestDataset,
  writeLatestDataset,
} from './_shared/store.mjs';

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

  // ---- 1. Read prebuilt blob (the v5.2 fast path) ----
  let store = null;
  try {
    store = getDatasetStore();
  } catch {
    store = null;
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
      // Prebuilt envelope is returned verbatim. The lock flag
      // is overlaid so the UI knows a refresh is in flight.
      return jsonResponse(200, {
        ...prebuilt,
        proxyStatus: 'proxy',
        dataSource: 'prebuilt-store',
        refreshInProgress,
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
  if (store) {
    const envelope = {
      ...live,
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
    ...live,
    proxyStatus: 'proxy',
    refreshInProgress: false,
  });
};