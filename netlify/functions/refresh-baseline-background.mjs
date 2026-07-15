/**
 * V6.0 — Netlify Background Function for the V6.0 canonical baseline.
 *
 *   /.netlify/functions/refresh-baseline-background
 *
 * The Background Function does the actual work: it calls
 * `runOsvBackground()` in a loop until the orchestrator reports
 * `done: true`. The loop is bounded by a wall-clock timeout (14
 * minutes) that leaves 1 minute of margin under the 15-minute
 * Background Function ceiling.
 *
 * Auth:
 *   The function rejects any request that does not present a
 *   matching X-Trigger-Secret header. The secret is configured via
 *   THREATPULSE_REFRESH_TRIGGER_SECRET on the Netlify site's
 *   environment. Visitors (or any client without the secret)
 *   cannot trigger a refresh; they get a 401.
 *
 * Return shape:
 *   The function returns 202 immediately after the orchestrator
 *   loop completes, with a JSON body summarizing the result. The
 *   actual ingestion happens during the loop. The response is
 *   the final result of the run, not a per-iteration status.
 *
 *   In production, the response is mostly for the scheduled
 *   function's logs (it captures the body via `fetch()`). The
 *   real operator-facing telemetry is the bootstrap state Blob
 *   and the Netlify function logs.
 *
 *   Per amendment #4, the function does NOT use
 *   `context.waitUntil` — the orchestrator runs in the foreground
 *   of the function. The response is sent when the loop
 *   completes, and the function returns. A run that exceeds the
 *   14-minute budget is cut off; the orchestrator's resume
 *   cursor picks up where it left off on the next invocation.
 */

import { gzipSync } from 'node:zlib';
import { getBaselineStore } from './_shared/baselineStore.mjs';
import { runOsvBackground } from './_shared/osvBackground.mjs';
import { runBaselinePublicationChain } from './_shared/v61BackgroundChain.mjs';
import {
  TRIGGER_HEADER,
  TRIGGER_SECRET_ENV_VAR,
  validateTriggerSecret,
  getTriggerSecretFromEnv,
} from './_shared/triggerAuth.mjs';

const LOG_PREFIX = '[v6.0 background refresh]';
const MAX_WALL_MS = 14 * 60 * 1000;
const TRIGGER_NAME = 'refresh-baseline-background';

async function defaultGzipFn(buf) { return gzipSync(buf); }

function jsonResponse(status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
    },
  });
}

/**
 * Testable inner handler. Takes all dependencies explicitly so
 * the unit tests can inject a store and an orchestrator stub.
 *
 * @param {Object} args
 * @param {Request|Object} args.request - the inbound request
 * @param {string|null} args.expectedSecret - the configured trigger secret
 * @param {Function} args.resolveStore - returns the Blob store (or throws)
 * @param {Function} args.runOrchestrator - the runOsvBackground-like function
 * @param {Object} args.gzipFn - the gzip helper passed to the orchestrator
 * @param {number} args.maxWallMs - the wall-clock cap for the loop
 * @param {Function} [args.now] - clock injection
 * @param {string} args.triggerName - the trigger name in logs/responses
 * @param {string} args.logPrefix - log line prefix
 * @param {string} args.triggerHeader - the header name to read
 * @returns {Promise<Response>}
 */
export async function handleRefreshBaselineBackground({
  request,
  expectedSecret,
  resolveStore,
  runOrchestrator,
  gzipFn = defaultGzipFn,
  maxWallMs = MAX_WALL_MS,
  now = () => Date.now(),
  triggerName = TRIGGER_NAME,
  logPrefix = LOG_PREFIX,
  triggerHeader = TRIGGER_HEADER,
}) {
  // 1. Validate the trigger secret. This is the only thing
  //    standing between a visitor and a refresh of the canonical
  //    baseline. Reject BEFORE doing any other work.
  if (typeof expectedSecret !== 'string' || expectedSecret.length === 0) {
    console.error(`${logPrefix} ${TRIGGER_SECRET_ENV_VAR} is not set on this site`);
    return jsonResponse(500, { status: 'failed', reason: 'trigger secret not configured', trigger: triggerName });
  }
  const provided = request && typeof request.headers.get === 'function'
    ? request.headers.get(triggerHeader)
    : null;
  if (!provided || !validateTriggerSecret(provided, expectedSecret)) {
    return jsonResponse(401, { status: 'unauthorized', trigger: triggerName });
  }

  // 2. Resolve the Blob store. The background function lives
  //    on the public ThreatPulse Radar site (the same site that
  //    owns the `tpr-baseline` Blob store). The `resolveStore`
  //    dependency is `getBaselineStore()` in production, which
  //    uses the Netlify runtime's auto-detected local context —
  //    no cross-site env vars are required. The private gateway
  //    is a SEPARATE Netlify site and only READS the store via
  //    cross-site env vars; it never runs the background
  //    function.
  let store;
  try {
    store = await resolveStore();
  } catch (err) {
    return jsonResponse(500, {
      status: 'failed',
      reason: 'store unavailable: ' + (err && err.message ? err.message : String(err)),
      trigger: triggerName,
    });
  }

  // 3. Run the orchestrator in a loop. Each iteration processes
  //    a slice bounded by the orchestrator's defaults. The loop
  //    exits when the orchestrator reports `done: true` (which
  //    can mean: all work done, no work to do, or a fatal error).
  //    The loop is bounded by the wall-clock maxWallMs so a
  //    pathological run does not exceed the 15-minute ceiling.
  const startMs = now();
  let totalProcessed = 0;
  let iterations = 0;
  let lastResult = null;
  let publishedCount = 0;
  while (now() - startMs < maxWallMs) {
    iterations++;
    let r;
    try {
      r = await runOrchestrator({ store, gzipFn });
    } catch (err) {
      console.error(`${logPrefix} orchestrator threw unexpectedly:`, err && err.message ? err.message : err);
      return jsonResponse(500, {
        status: 'failed',
        reason: 'orchestrator threw: ' + (err && err.message ? err.message : String(err)),
        trigger: triggerName,
        iterations,
        totalProcessed,
        elapsedMs: now() - startMs,
      });
    }
    lastResult = r;
    totalProcessed += (r && r.recordsProcessed) || 0;
    if (r && r.published) publishedCount++;
    if (r && r.done) break;
  }

  // 4. Build a compact summary. The full manifest is available
  //    in the Blob store; we only include identifying fields
  //    here. The V6.1 sub-result slots (v61OsvProjection,
  //    v61OsvGc) are surfaced as compact, sanitized tags so
  //    operators can see the chain outcome without exposing
  //    hashes, Blob keys, or stack traces.
  const summary = {
    status: lastResult ? lastResult.status : 'failed',
    trigger: triggerName,
    iterations,
    totalProcessed,
    publishedCount,
    elapsedMs: now() - startMs,
    manifest: lastResult && lastResult.manifest ? {
      baselineVersion: lastResult.manifest.baselineVersion,
      previousVersion: lastResult.manifest.previousVersion,
      publishedAt: lastResult.manifest.publishedAt,
      canonicalContentHash: lastResult.manifest.canonicalContentHash,
      totalRecords: lastResult.manifest.stats && lastResult.manifest.stats.totalRecords,
    } : null,
    errorCount: lastResult ? (lastResult.errors || []).length : 0,
    v61: lastResult ? {
      osvProjection: lastResult.v61OsvProjection && lastResult.v61OsvProjection.skipped === false
        ? 'published'
        : (lastResult.v61OsvProjection && lastResult.v61OsvProjection.skipped === true
            ? `skipped:${lastResult.v61OsvProjection.reason || 'unspecified'}`
            : 'not-run'),
      osvGc: lastResult.v61OsvGc && lastResult.v61OsvGc.status === 'ok'
        ? `ok:retained=${lastResult.v61OsvGc.retained || 0}:deleted=${(lastResult.v61OsvGc.deleted || []).length}`
        : (lastResult.v61OsvGc ? `failed` : 'not-run'),
    } : null,
  };
  console.log(`${logPrefix} iterations=${iterations} totalProcessed=${totalProcessed} publishedCount=${publishedCount} elapsedMs=${summary.elapsedMs} status=${summary.status} v61=${summary.v61 ? `${summary.v61.osvProjection}/${summary.v61.osvGc}` : 'n/a'}`);
  return jsonResponse(202, summary);
}

/**
 * Production handler. Resolves dependencies from the live
 * environment and delegates to the testable inner handler.
 */
export default async (request) => {
  return handleRefreshBaselineBackground({
    request,
    expectedSecret: getTriggerSecretFromEnv(),
    resolveStore: () => getBaselineStore(),
    runOrchestrator: (args) => runBaselinePublicationChain({ ...args, runOrchestrator: (a) => runOsvBackground(a) }),
    gzipFn: defaultGzipFn,
  });
};

// Mark this as a Netlify Background Function. The filename suffix
// `-background.mjs` is the primary signal; the exported `config`
// is documentation of the same intent. (Netlify uses the filename
// suffix at deploy time.)
export const config = {
  background: true,
};

