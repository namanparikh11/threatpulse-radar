/**
 * Netlify Scheduled Function — `/.netlify/functions/refresh-dataset-scheduled`
 *
 * v5.2 periodic-refresh endpoint. Triggered by a cron schedule
 * configured in `netlify.toml`:
 *
 *   [functions."refresh-dataset-scheduled"]
 *     schedule = "*/30 * * * *"
 *
 * Why a separate scheduled function (not the same handler as
 * the manual endpoint):
 *   - Scheduled functions receive a different event shape
 *     (no `Request`, no `context.waitUntil`); the handler
 *     signature is `(event) => Response | undefined`.
 *   - Keeping the two entry points separate lets each one
 *     log its trigger source clearly ("scheduled" vs "manual")
 *     and lets the scheduled path run without an HTTP
 *     context (no headers, no status codes — it just runs).
 *
 * Conservative cadence:
 *   Every 30 minutes. The task spec calls for "a conservative
 *   interval first, such as hourly or every 30 minutes" —
 *   30 min chosen so the public demo gets a fresh dataset
 *   twice per hour without hammering the upstream feeds. The
 *   v5.0.1 CDN cache (`s-maxage=900` = 15 min) is still in
 *   place, so visitors within a 15-min window hit the cached
 *   response either way; the schedule just refreshes the
 *   blob so the NEXT visitor after the cache expires gets a
 *   fresh build.
 *
 * Lock interaction:
 *   The scheduled function uses the same `runRefresh`
 *   orchestrator as the manual endpoint. If a manual refresh
 *   is already in progress (lock held), the scheduled run
 *   returns `{ status: 'in-progress' }` without starting a
 *   duplicate build. The next scheduled tick will retry.
 *
 * Flow (mirrors `refresh-dataset-background.mjs`):
 *   1. Acquire the refresh-lock blob.
 *   2. If already held: return early (the manual endpoint
 *      will finish it).
 *   3. Otherwise: run CISA → NVD → EPSS.
 *   4. On success: write to `latest-dataset`, release lock.
 *   5. On failure: release lock, leave existing blob intact.
 */

import {
  getDatasetStore,
} from './_shared/store.mjs';
import {
  runRefresh,
} from './_shared/refresh.mjs';
import { buildLiveDataset } from './_shared/liveBuild.mjs';

export default async (event) => {
  const trigger = event?.body ? 'manual-via-event' : 'scheduled';
  // `event.body` is the standard Netlify marker for "this
  // scheduled function was invoked manually with a payload";
  // a real cron tick has no body. Either way we treat it as
  // "go refresh" — the lock + write logic is identical.

  let store;
  try {
    store = getDatasetStore();
  } catch (err) {
    // Scheduled functions can't return a Response the way
    // HTTP functions do — they log + exit. On a Blobs error
    // we just log and let the next tick retry.
    console.error(
      `[v5.2 scheduled refresh] Blob store unavailable (trigger=${trigger}):`,
      err instanceof Error ? err.message : err,
    );
    return;
  }

  const result = await runRefresh({
    store,
    buildFn: () => buildLiveDataset(),
  });

  console.log(
    `[v5.2 scheduled refresh] trigger=${trigger} status=${result.status}` +
    (result.fetchedAt ? ` fetchedAt=${result.fetchedAt}` : '') +
    (result.reason ? ` reason=${result.reason}` : ''),
  );
};