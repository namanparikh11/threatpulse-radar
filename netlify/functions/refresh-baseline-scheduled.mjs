/**
 * V6.0 — Netlify Scheduled Function for the V6.0 canonical baseline.
 *
 *   /.netlify/functions/refresh-baseline-scheduled
 *
 * The Scheduled Function is THIN by design. It must complete well
 * under the 30-second Netlify Scheduled Function ceiling. Its only
 * job is to send an authenticated POST to the Background Function
 * (refresh-baseline-background) and return. The actual OSV
 * ingestion + canonical baseline build + publication work happens
 * in the Background Function, which has a 15-minute ceiling.
 *
 * Auth:
 *   The POST includes the THREATPULSE_REFRESH_TRIGGER_SECRET in
 *   the X-Trigger-Secret header. The Background Function validates
 *   the header in constant time and rejects any other caller.
 *   Visitors (or any other client) cannot trigger a refresh because
 *   they do not have the secret.
 *
 * URL:
 *   The Scheduled Function has no inbound Request URL. It derives
 *   the site URL from the `DEPLOY_URL` or `URL` environment
 *   variables (set by Netlify). If neither is set, the function
 *   logs an error and returns; the next cron tick will retry.
 *
 * Trigger source:
 *   A real cron tick has no event body. A manual invocation (e.g.
 *   from the Netlify dashboard) typically has a body. We log
 *   which one it was so operators can see the difference.
 */

import {
  TRIGGER_HEADER,
  REFRESH_BACKGROUND_PATH,
  TRIGGER_SECRET_ENV_VAR,
  getTriggerSecretFromEnv,
} from './_shared/triggerAuth.mjs';

const LOG_PREFIX = '[v6.0 scheduled refresh]';

export default async (event) => {
  const trigger = event?.body ? 'manual-via-event' : 'scheduled';

  // 1. Resolve the secret. Without it, we cannot invoke the
  //    background function. Fail fast with a clear log.
  const secret = getTriggerSecretFromEnv();
  if (!secret) {
    console.error(`${LOG_PREFIX} ${TRIGGER_SECRET_ENV_VAR} is not set; refusing to trigger background`);
    return;
  }

  // 2. Resolve the site URL. The scheduled function is invoked
  //    outside an HTTP context; it has no Request URL. Netlify
  //    sets DEPLOY_URL on production deploys and URL in some
  //    contexts (e.g. branch deploys).
  const siteUrl = process.env.DEPLOY_URL || process.env.URL || '';
  if (!siteUrl) {
    console.error(`${LOG_PREFIX} no site URL available (DEPLOY_URL/URL); cannot POST to background`);
    return;
  }
  const target = `${siteUrl.replace(/\/$/, '')}/.netlify/functions/${REFRESH_BACKGROUND_PATH}`;

  // 3. Send the authenticated POST. We do NOT await any
  //    background work; the background function returns 202
  //    immediately and runs the orchestrator in the background.
  const scheduledAt = new Date().toISOString();
  const start = Date.now();
  let resp;
  try {
    resp = await fetch(target, {
      method: 'POST',
      headers: {
        [TRIGGER_HEADER]: secret,
        'Content-Type': 'application/json',
        'X-Trigger-Source': trigger,
      },
      body: JSON.stringify({ trigger, scheduledAt }),
    });
  } catch (err) {
    console.error(`${LOG_PREFIX} POST to background failed:`, err && err.message ? err.message : err);
    return;
  }
  const elapsed = Date.now() - start;
  // We do NOT log the secret or the response body. The status
  // code is sufficient to know whether the trigger was accepted.
  console.log(`${LOG_PREFIX} trigger=${trigger} status=${resp.status} elapsedMs=${elapsed}`);
};
