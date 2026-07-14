/**
 * V6.0 \u2014 Gateway-side Blob store helpers.
 *
 * The private sync gateway lives on a SEPARATE Netlify site
 * from the public ThreatPulse Radar site. It does not own any
 * Blob store; it only READS from two stores on the public
 * site via Netlify Blobs' server-to-server cross-site access:
 *
 *   1. `tpr-baseline` \u2014 the canonical baseline (manifests,
 *      version manifests, content-addressed shards, deltas,
 *      source registry). Read-only. Token env var:
 *      THREATPULSE_BLOBS_ACCESS_TOKEN.
 *
 *   2. `tpr-private-credentials` \u2014 a SEPARATE Blob store
 *      holding the HMAC digests of every issued consumer
 *      credential (one Blob per keyId at `credentials/<keyId>`).
 *      The public site does NOT mix credential records into
 *      the baseline store; they live in their own store so
 *      the credential lifecycle can be audited, rotated, and
 *      revoked independently of the baseline data. Read-only
 *      from the gateway. Token env var:
 *      THREATPULSE_CREDENTIALS_BLOBS_ACCESS_TOKEN.
 *
 *   Both tokens must be Netlify Blobs access tokens for the
 *   PUBLIC site. The site ID is shared:
 *   THREATPULSE_BASELINE_SITE_ID.
 *
 *   If THREATPULSE_CREDENTIALS_BLOBS_ACCESS_TOKEN is unset,
 *   the gateway falls back to THREATPULSE_BLOBS_ACCESS_TOKEN
 *   so an operator with a single multi-store token can use
 *   one env var for both stores. The fallback is documented
 *   here as the explicit behavior; the default deployment
 *   (per docs/deployment.md) uses two separate tokens.
 *
 * This file is the GATEWAY's view of the public site's
 * stores. The public site's `netlify/functions/_shared/baselineStore.mjs`
 * is a different module that has the LOCAL-context helpers
 * used by the V6.0 publisher functions. The two files share
 * only the store-name constants.
 */

import { getStore } from '@netlify/blobs';

/** Public-site Blob store names \u2014 read-only from the gateway. */
export const BASELINE_STORE_NAME = 'tpr-baseline';
export const PRIVATE_CREDENTIALS_STORE_NAME = 'tpr-private-credentials';

/** Key prefixes for the baseline store. */
export const MANIFESTS_DIR = 'manifests';
export const LATEST_MANIFEST_KEY = `${MANIFESTS_DIR}/latest.json`;
export const SOURCE_REGISTRY_KEY = 'source-registry';

/** Env var names. */
export const BASELINE_SITE_ID_ENV_VAR = 'THREATPULSE_BASELINE_SITE_ID';
export const BASELINE_BLOBS_ACCESS_TOKEN_ENV_VAR = 'THREATPULSE_BLOBS_ACCESS_TOKEN';
export const CREDENTIALS_BLOBS_ACCESS_TOKEN_ENV_VAR = 'THREATPULSE_CREDENTIALS_BLOBS_ACCESS_TOKEN';

/**
 * Resolve a handle to the public site's `tpr-baseline` Blob
 * store. Reads only.
 */
export function getCrossSiteBaselineStore() {
  const siteID = process.env[BASELINE_SITE_ID_ENV_VAR];
  const token = process.env[BASELINE_BLOBS_ACCESS_TOKEN_ENV_VAR];
  if (!siteID || !token) {
    throw new Error(
      `getCrossSiteBaselineStore: ${BASELINE_SITE_ID_ENV_VAR} and ` +
      `${BASELINE_BLOBS_ACCESS_TOKEN_ENV_VAR} must be set`,
    );
  }
  return getStore({
    name: BASELINE_STORE_NAME,
    siteID,
    token,
    consistency: 'strong',
  });
}

/**
 * Resolve a handle to the public site's `tpr-private-credentials`
 * Blob store. Reads only.
 *
 * Token precedence:
 *   1. THREATPULSE_CREDENTIALS_BLOBS_ACCESS_TOKEN (preferred;
 *      allows the operator to scope this token to the credentials
 *      store only).
 *   2. THREATPULSE_BLOBS_ACCESS_TOKEN (fallback; works when the
 *      operator has a single multi-store token that covers both
 *      `tpr-baseline` and `tpr-private-credentials`).
 *
 * If neither is set, throws. Failing closed (no anonymous
 * fallback) is the V6.0 security policy.
 */
export function getCrossSitePrivateCredentialsStore() {
  const siteID = process.env[BASELINE_SITE_ID_ENV_VAR];
  if (!siteID) {
    throw new Error(
      `getCrossSitePrivateCredentialsStore: ${BASELINE_SITE_ID_ENV_VAR} must be set`,
    );
  }
  const token = process.env[CREDENTIALS_BLOBS_ACCESS_TOKEN_ENV_VAR]
    || process.env[BASELINE_BLOBS_ACCESS_TOKEN_ENV_VAR];
  if (!token) {
    throw new Error(
      `getCrossSitePrivateCredentialsStore: ${CREDENTIALS_BLOBS_ACCESS_TOKEN_ENV_VAR} ` +
      `(or ${BASELINE_BLOBS_ACCESS_TOKEN_ENV_VAR} as fallback) must be set`,
    );
  }
  return getStore({
    name: PRIVATE_CREDENTIALS_STORE_NAME,
    siteID,
    token,
    consistency: 'strong',
  });
}

/**
 * Read a JSON value from a Blob store. Returns null on missing
 * or malformed data. Defensive try/catch so a transient Blobs
 * read error becomes a 404 (route-level) rather than a 500.
 */
export async function readJson(store, key) {
  try {
    const v = await store.get(key, { type: 'json' });
    return v ?? null;
  } catch {
    return null;
  }
}

/**
 * Read an immutable version manifest from the baseline store.
 */
export async function readVersionManifest(store, version) {
  return readJson(store, `${MANIFESTS_DIR}/versions/${version}.json`);
}

/**
 * Read a delta file from the baseline store.
 */
export async function readDelta(store, fromVersion, toVersion) {
  return readJson(store, `deltas/${fromVersion}__to__${toVersion}.json`);
}
