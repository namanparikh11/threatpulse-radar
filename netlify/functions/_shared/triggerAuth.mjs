/**
 * V6.0 — Trigger authentication for the V6.0 background refresh.
 *
 * The Scheduled Function (refresh-baseline-scheduled) is invoked by
 * Netlify's cron — it has no inbound HTTP request to authenticate.
 * It POSTs to the Background Function (refresh-baseline-background)
 * with a shared secret in the X-Trigger-Secret header. The
 * background function validates the header and rejects all other
 * callers.
 *
 * Why a shared secret and not a per-request signed payload:
 *   The trigger is a server-to-server call from a known Netlify
 *   function. Per-request signing would add complexity for no
 *   security benefit: a request signed by a leaked secret is no
 *   harder to forge than a request with the leaked secret in the
 *   header. The shared secret is the only thing an attacker would
 *   need either way, and the secret lives only in the Netlify
 *   site's environment.
 *
 * Constant-time comparison:
 *   `validateTriggerSecret` uses crypto.timingSafeEqual on equal-
 *   length buffers. Lengths are checked BEFORE the comparison so a
 *   short input is rejected before a long buffer comparison could
 *   be used as a side channel.
 *
 * The V6.0 spec (amendment #4) is explicit: visitors must not be
 * able to trigger refresh or publication. The 401 response is
 * returned for any missing or invalid secret. The secret itself
 * is never logged.
 */

import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

/** Header name used by the scheduled function to authenticate the trigger. */
export const TRIGGER_HEADER = 'x-trigger-secret';

/** Background Function path (under /.netlify/functions/). */
export const REFRESH_BACKGROUND_PATH = 'refresh-baseline-background';

/** Env var name for the shared trigger secret. */
export const TRIGGER_SECRET_ENV_VAR = 'THREATPULSE_REFRESH_TRIGGER_SECRET';

/**
 * Validate the trigger secret in constant time. Returns true iff
 * the provided header value exactly matches the expected secret.
 *
 * @param {string} provided - the value from the X-Trigger-Secret header
 * @param {string} expected - the configured secret
 * @returns {boolean}
 */
export function validateTriggerSecret(provided, expected) {
  if (typeof provided !== 'string' || typeof expected !== 'string') return false;
  if (provided.length === 0 || expected.length === 0) return false;
  // Buffers must be equal length for timingSafeEqual. Hash both
  // sides to a fixed length and compare — this avoids the
  // "short secret rejected fast" timing channel and produces a
  // single 32-byte comparison regardless of input length.
  const ph = createHash('sha256').update(provided, 'utf8').digest();
  const eh = createHash('sha256').update(expected, 'utf8').digest();
  return timingSafeEqual(ph, eh);
}

/**
 * Pull the trigger secret from the environment. Returns null if
 * unset. Used by both the scheduled function (to include in the
 * POST) and the background function (to validate the POST).
 */
export function getTriggerSecretFromEnv(env = process.env) {
  const v = env && env[TRIGGER_SECRET_ENV_VAR];
  if (typeof v !== 'string' || v.length === 0) return null;
  return v;
}
