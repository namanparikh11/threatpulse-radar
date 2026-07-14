/**
 * V6.0 — Gateway-side Blob store helpers.
 *
 * The private sync gateway lives on a SEPARATE Netlify site
 * from the public ThreatPulse Radar site. It reads from TWO
 * Blob stores, with two completely different access models:
 *
 *   1. `tpr-baseline` (the canonical baseline) lives on the
 *      PUBLIC site. The gateway reads it via Netlify Blobs'
 *      server-to-server cross-site access. The env vars
 *      THREATPULSE_BASELINE_SITE_ID and
 *      THREATPULSE_BLOBS_ACCESS_TOKEN carry the public
 *      site's Netlify site ID and a Blobs access token scoped
 *      to `tpr-baseline`, read-only.
 *
 *   2. `tpr-private-credentials` (consumer credential HMACs)
 *      lives on the GATEWAY site itself. The gateway reads it
 *      via the local Netlify Blobs runtime context (no
 *      siteID, no token, no cross-site access). The operator
 *      creates the store on the gateway site via the Netlify
 *      Blobs UI and writes `credentials/<keyId>` records there
 *      directly. The public site never sees this store.
 *
 *   Why gateway-local for credentials:
 *
 *     - The gateway is the ONLY component that needs to
 *       verify a consumer credential. Putting the store on
 *       the gateway means the public-site operator does not
 *       have read access to the credential records, and a
 *       compromise of the public site cannot enumerate or
 *       attempt to read credential HMACs.
 *
 *     - The gateway's Netlify runtime has direct local-
 *       context access to its own Blobs store. No token, no
 *       site ID, no cross-site round trip. The auth check
 *       stays server-side and uses the gateway's own
 *       authentication boundary.
 *
 *     - The blast-radius argument is REVERSED: a token
 *       scoped to the public-site `tpr-baseline` cannot
 *       authorize reading the gateway's `tpr-private-credentials`.
 *       The two stores are in two different Netlify sites
 *       and are gated by two different operator-controlled
 *       boundaries.
 *
 *     - The HMAC pepper (`THREATPULSE_CREDENTIAL_PEPPER`) is
 *       server-side only on the gateway. Even an attacker
 *       with read access to the gateway's `tpr-private-credentials`
 *       store cannot forge a credential without the pepper.
 *
 *   Only the canonical baseline store is cross-site. The
 *   credentials store is gateway-local. The two never share
 *   an access token.
 *
 * This file is the GATEWAY's view of its own stores. The
 * public site's `netlify/functions/_shared/baselineStore.mjs`
 * is a different module that has the LOCAL-context helpers
 * used by the V6.0 publisher functions on the public site.
 * The two files share only the store-name constants.
 */

import { getStore } from '@netlify/blobs';

/** Public-site Blob store name (read-only cross-site from the gateway). */
export const BASELINE_STORE_NAME = 'tpr-baseline';

/** Gateway-local Blob store name for consumer credential HMACs. */
export const CREDENTIALS_STORE_NAME = 'tpr-private-credentials';

/** Key prefixes for the baseline store. */
export const MANIFESTS_DIR = 'manifests';
export const LATEST_MANIFEST_KEY = `${MANIFESTS_DIR}/latest.json`;
export const SOURCE_REGISTRY_KEY = 'source-registry';

/** Env var names. */
export const BASELINE_SITE_ID_ENV_VAR = 'THREATPULSE_BASELINE_SITE_ID';
export const BASELINE_BLOBS_ACCESS_TOKEN_ENV_VAR = 'THREATPULSE_BLOBS_ACCESS_TOKEN';

/**
 * Resolve a handle to the public site's `tpr-baseline` Blob
 * store. Reads only. Requires the public site's Netlify site
 * ID and a read-only access token scoped to `tpr-baseline`.
 *
 * The token MUST be scoped to `tpr-baseline` only. It does
 * NOT authorize reads of any other store. In particular, it
 * does NOT authorize reads of the gateway-local
 * `tpr-private-credentials` store (which lives on a different
 * Netlify site and is gated by a different operator-controlled
 * boundary).
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
 * Resolve a handle to the GATEWAY's own `tpr-private-credentials`
 * Blob store. Reads only. Uses the GATEWAY site's local Netlify
 * Blobs runtime context — no siteID, no access token, no
 * cross-site access.
 *
 * The local runtime context is provided by Netlify when the
 * function is invoked on the gateway site. The
 * `tpr-private-credentials` store is created on the gateway
 * site in the Netlify UI; the public site never sees or
 * touches it.
 *
 * The function reads NO env vars. This is intentional and is
 * the security-critical property: there is no env var that
 * authorizes reading the credential store, because no
 * operator needs to authorize it — the gateway's own
 * runtime context is the only access path.
 */
export function getCredentialsStore() {
  return getStore({
    name: CREDENTIALS_STORE_NAME,
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
