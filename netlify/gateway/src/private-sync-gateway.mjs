/**
 * V6.0 — Private sync gateway.
 *
 * Per the V6.0 amendment #1, the canonical baseline is private.
 * The public ThreatPulse site exposes only the V5.7 dashboard
 * dataset. The private sync gateway is a separate Netlify
 * function (in a separate site, by deploy topology) that:
 *
 *   1. Authenticates the caller with an HMAC-SHA256 credential
 *      (see _shared/credentials.mjs).
 *   2. Reads the canonical baseline from the PUBLIC site's
 *      `tpr-baseline` Blob store using the cross-site env vars
 *      THREATPULSE_BASELINE_SITE_ID and THREATPULSE_BLOBS_ACCESS_TOKEN.
 *      These values must NEVER appear in client code, browser
 *      bundles, logs, fixtures, screenshots, or docs.
 *   3. Reads the consumer credential HMAC from the PUBLIC site's
 *      `tpr-private-credentials` Blob store (a SEPARATE store
 *      from `tpr-baseline`) using a separate cross-site access
 *      token (env var THREATPULSE_CREDENTIALS_BLOBS_ACCESS_TOKEN).
 *      The two stores are decoupled so the credential lifecycle
 *      (issue, rotate, revoke) is independent of the baseline
 *      data lifecycle.
 *   4. Returns the requested artifact.
 *
 * Per amendment #1, there is NO anonymous function for the
 * canonical baseline. The only public endpoint is the existing
 * V5.7 dashboard dataset surface. Visitors cannot bypass the
 * private gateway to read the canonical baseline.
 *
 * Routes (mounted at /private/v1/* via netlify.toml):
 *   GET /private/v1/manifest                  → current manifest
 *   GET /private/v1/manifest/{version}        → version manifest
 *   GET /private/v1/delta?from={v}&to={v}     → delta
 *   GET /private/v1/shard?key={objectKey}     → content-addressed shard
 *   GET /private/v1/snapshot?version={v}      → full snapshot
 *   GET /private/v1/sources                   → source registry
 *
 * Per amendment #5, the rate limit is configured via the
 * function's exported `config` (NOT in netlify.toml). The
 * initial rule is 200 requests per 60-second window. Netlify
 * Functions v2 applies this with its default per-IP
 * aggregation; the previous `aggregateBy: ['ip', 'domain']`
 * field was silently ignored by Netlify (not a real config
 * key) and has been removed. Per-client hard quotas are
 * deferred until an atomic counter store exists.
 */

import {
  parseCredential, verifyCredential, getPepperFromEnv,
  credentialBlobKey,
} from './_shared/credentials.mjs';
import {
  getCrossSiteBaselineStore, getCrossSitePrivateCredentialsStore,
  readJson, readVersionManifest, readDelta,
  LATEST_MANIFEST_KEY, SOURCE_REGISTRY_KEY,
} from './_shared/baselineStore.mjs';

const GATEWAY_PATH_PREFIX = '/private/v1';
const AUTH_HEADER = 'authorization';
const BEARER_PREFIX = 'Bearer ';

/**
 * Safe character set for baseline version strings. A version
 * is interpolated into a Blob key (`manifests/versions/<v>.json`
 * or `deltas/<from>__to__<to>.json`), so the pattern rejects
 * path-traversal attempts (`..`, `/`, `\`, whitespace, and any
 * character outside `[A-Za-z0-9._-]`). The maximum length is
 * 128 — comfortably above any plausible version string while
 * bounding the Blob-key length.
 *
 * Mirrors the per-shard `key` validation in `handleShard`
 * (the shard key uses a richer alphabet because it includes
 * the `objects/sha256/<hex>.json.gz` path).
 */
const VERSION_PATTERN = /^[A-Za-z0-9._-]{1,128}$/;

/**
 * Validate a baseline-version string. Returns true iff the
 * input is a non-empty string of length <= 128 containing only
 * safe characters. Use this for the `version` path segment of
 * `/manifest/{version}` and the `from` / `to` / `version`
 * query parameters of `/delta` and `/snapshot`.
 */
function isValidVersionString(s) {
  return typeof s === 'string' && VERSION_PATTERN.test(s);
}

const ROUTE = Object.freeze({
  MANIFEST: 'manifest',
  DELTA: 'delta',
  SHARD: 'shard',
  SNAPSHOT: 'snapshot',
  SOURCES: 'sources',
});

function jsonResponse(status, body, extraHeaders = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      ...extraHeaders,
    },
  });
}

function unauthorized(reason = 'unauthorized') {
  return jsonResponse(401, { status: 'unauthorized', reason });
}

function badRequest(reason) {
  return jsonResponse(400, { status: 'bad-request', reason });
}

function notFound(reason) {
  return jsonResponse(404, { status: 'not-found', reason });
}

function serverError(reason) {
  return jsonResponse(500, { status: 'failed', reason });
}

/**
 * Read the `Authorization: Bearer tpr_xxx_yyy` header and return
 * the credential string. Returns null if missing or malformed.
 */
function extractCredential(request) {
  const h = request && typeof request.headers.get === 'function'
    ? request.headers.get(AUTH_HEADER)
    : null;
  if (typeof h !== 'string') return null;
  if (!h.startsWith(BEARER_PREFIX)) return null;
  const cred = h.slice(BEARER_PREFIX.length).trim();
  if (cred.length === 0) return null;
  return cred;
}

/**
 * Parse the request URL to determine the route and parameters.
 * Returns `{ route, params }` or null on an unrecognized route.
 */
function parseRoute(request) {
  const url = new URL(request.url);
  const path = url.pathname;
  if (!path.startsWith(GATEWAY_PATH_PREFIX)) return null;
  const rest = path.slice(GATEWAY_PATH_PREFIX.length).replace(/^\/+/, '');
  const segs = rest.split('/').filter((s) => s.length > 0);
  if (segs.length === 0) return null;
  const first = segs[0];
  if (first === ROUTE.MANIFEST) {
    if (segs.length === 1) {
      return { route: ROUTE.MANIFEST, version: null, url };
    }
    if (segs.length === 2) {
      return { route: ROUTE.MANIFEST, version: segs[1], url };
    }
    return null;
  }
  if (first === ROUTE.DELTA) {
    const from = url.searchParams.get('from');
    const to = url.searchParams.get('to');
    return { route: ROUTE.DELTA, from, to, url };
  }
  if (first === ROUTE.SHARD) {
    const key = url.searchParams.get('key');
    return { route: ROUTE.SHARD, key, url };
  }
  if (first === ROUTE.SNAPSHOT) {
    const version = url.searchParams.get('version') || url.searchParams.get('v');
    return { route: ROUTE.SNAPSHOT, version, url };
  }
  if (first === ROUTE.SOURCES) {
    return { route: ROUTE.SOURCES, url };
  }
  return null;
}

/* ------------------------------------------------------------------ */
/* Route handlers                                                      */
/* ------------------------------------------------------------------ */

async function handleManifest(store, { version }) {
  if (version !== null) {
    if (!isValidVersionString(version)) {
      return badRequest('invalid version');
    }
    const m = await readVersionManifest(store, version);
    if (!m) return notFound(`version '${version}' not found`);
    return jsonResponse(200, m, {
      'Cache-Control': 'public, max-age=60, s-maxage=60',
      'X-Baseline-Version': version,
    });
  }
  const m = await readJson(store, LATEST_MANIFEST_KEY);
  if (!m) return notFound('no baseline published yet');
  return jsonResponse(200, m, {
    'Cache-Control': 'public, max-age=30, s-maxage=30',
    'X-Baseline-Version': m.baselineVersion || 'unknown',
  });
}

async function handleDelta(store, { from, to }) {
  if (!from || !to) return badRequest('both from and to are required');
  if (!isValidVersionString(from) || !isValidVersionString(to)) {
    return badRequest('invalid from or to');
  }
  const d = await readDelta(store, from, to);
  if (!d) return notFound(`no delta from '${from}' to '${to}'`);
  return jsonResponse(200, d, {
    'Cache-Control': 'public, max-age=60, s-maxage=60',
    'X-Delta-From': from,
    'X-Delta-To': to,
  });
}

async function handleShard(store, { key }) {
  if (!key) return badRequest('key parameter is required');
  // Reject keys that look like traversal attempts. The valid key
  // shape is `objects/sha256/<hex>.json.gz` or
  // `manifests/versions/<version>.json` or `deltas/<from>__to__<to>.json`.
  if (key.includes('..') || key.startsWith('/') || key.startsWith('\\')) {
    return badRequest('invalid key');
  }
  if (!/^[a-zA-Z0-9_\-./]+$/.test(key)) {
    return badRequest('invalid key characters');
  }
  try {
    const bytes = await store.get(key, { type: 'arrayBuffer' });
    if (!bytes) return notFound(`shard '${key}' not found`);
    return new Response(bytes, {
      status: 200,
      headers: {
        'Content-Type': 'application/octet-stream',
        'Content-Encoding': 'gzip',
        'Cache-Control': 'public, max-age=31536000, immutable',
      },
    });
  } catch (err) {
    return serverError('shard read failed: ' + (err && err.message ? err.message : err));
  }
}

async function handleSnapshot(store, { version }) {
  if (!version) return badRequest('version parameter is required');
  if (!isValidVersionString(version)) {
    return badRequest('invalid version');
  }
  const m = await readVersionManifest(store, version);
  if (!m) return notFound(`version '${version}' not found`);
  // Read all shards in the manifest and package them. The result
  // is a single JSON envelope. This is the "give me everything"
  // endpoint for clients that want to do a one-shot offline
  // bootstrap.
  const shardKeys = [];
  for (const entityType of Object.keys(m.shards || {})) {
    for (const bucket of Object.keys(m.shards[entityType] || {})) {
      shardKeys.push(m.shards[entityType][bucket].objectKey);
    }
  }
  const shards = {};
  for (const k of shardKeys) {
    try {
      const bytes = await store.get(k, { type: 'arrayBuffer' });
      if (bytes) {
        // The gateway returns the gzipped shard as a base64 string
        // so the response is a single JSON document the client
        // can persist as one file. This keeps the snapshot
        // endpoint a single round-trip.
        shards[k] = Buffer.from(bytes).toString('base64');
      }
    } catch {
      // Skip a single missing shard; the rest of the snapshot
      // is still useful. The manifest is the authoritative
      // pointer; a missing shard indicates storage drift and
      // should be visible in the response.
      shards[k] = null;
    }
  }
  return jsonResponse(200, {
    manifest: m,
    shards,
    encoding: { shards: 'base64-gzip' },
  }, {
    'Cache-Control': 'public, max-age=60, s-maxage=60',
    'X-Baseline-Version': version,
  });
}

async function handleSources(store) {
  const r = await readJson(store, SOURCE_REGISTRY_KEY);
  if (!r) return notFound('source registry not found');
  return jsonResponse(200, r, {
    'Cache-Control': 'public, max-age=300, s-maxage=300',
  });
}

/* ------------------------------------------------------------------ */
/* Testable inner handler                                              */
/* ------------------------------------------------------------------ */

/**
 * Inner handler. Takes all dependencies explicitly so the unit
 * tests can stub the stores and the request.
 *
 * The handler uses TWO store handles:
 *   - `resolveStore()`         → `tpr-baseline` (read-only,
 *                                baseline data: manifests,
 *                                shards, deltas, sources)
 *   - `resolveCredentialsStore()` → `tpr-private-credentials`
 *                                (read-only, HMAC digests of
 *                                issued credentials)
 *
 * The two stores live on the public site; the gateway is a
 * separate Netlify site that accesses them via Netlify Blobs'
 * server-to-server cross-site access. Splitting the credential
 * store from the baseline store means the credential lifecycle
 * (issue, rotate, revoke) is decoupled from the baseline
 * publication lifecycle, and the public-site operator can grant
 * read access to `tpr-baseline` for analysis without also
 * exposing the credential digests.
 */
export async function handlePrivateSyncGateway({
  request,
  pepper,
  store = null,
  resolveStore = () => store,
  resolveCredentialsStore = null,
  readStoreRecord = async (s, key) => readJson(s, key),
}) {
  if (typeof pepper !== 'string' || pepper.length === 0) {
    return serverError('credential pepper not configured');
  }
  const credential = extractCredential(request);
  if (!credential) return unauthorized();

  // Parse first so we can read the keyId from the credential
  // (without verifying yet). Then read the stored HMAC for that
  // keyId, then verify. This is a single Blob read per request,
  // against the credentials store (NOT the baseline store).
  const parsed = parseCredential(credential);
  if (!parsed) return unauthorized();

  let storeHandle;
  try {
    storeHandle = await resolveStore();
  } catch (err) {
    return serverError('store unavailable: ' + (err && err.message ? err.message : err));
  }
  if (!storeHandle) {
    return serverError('store not available');
  }

  let credentialsStoreHandle;
  try {
    credentialsStoreHandle = resolveCredentialsStore
      ? await resolveCredentialsStore()
      : storeHandle;
  } catch (err) {
    return serverError('credentials store unavailable: ' + (err && err.message ? err.message : err));
  }
  if (!credentialsStoreHandle) {
    return serverError('credentials store not available');
  }

  let storeRecord;
  try {
    storeRecord = await readStoreRecord(credentialsStoreHandle, credentialBlobKey(parsed.keyId));
  } catch {
    storeRecord = null;
  }

  const verification = verifyCredential({ credential, pepper, storeRecord });
  if (!verification.valid) return unauthorized();

  // Route the request
  const route = parseRoute(request);
  if (!route) return notFound('unknown route');

  if (request.method !== 'GET' && request.method !== 'HEAD') {
    return jsonResponse(405, { status: 'method-not-allowed' });
  }

  switch (route.route) {
    case ROUTE.MANIFEST: return handleManifest(storeHandle, route);
    case ROUTE.DELTA:    return handleDelta(storeHandle, route);
    case ROUTE.SHARD:    return handleShard(storeHandle, route);
    case ROUTE.SNAPSHOT: return handleSnapshot(storeHandle, route);
    case ROUTE.SOURCES:  return handleSources(storeHandle);
    default: return notFound('unknown route');
  }
}

/**
 * Production handler. Wires the real dependencies.
 */
export default async (request) => {
  const pepper = getPepperFromEnv();
  return handlePrivateSyncGateway({
    request,
    pepper,
    // Baseline data: manifests, shards, deltas, sources.
    resolveStore: () => getCrossSiteBaselineStore(),
    // Credential HMACs: separate `tpr-private-credentials` store.
    resolveCredentialsStore: () => getCrossSitePrivateCredentialsStore(),
  });
};

/**
 * Per amendment #5: rate limit and path are exported on the
 * function's `config`, NOT in netlify.toml. The path is the mount
 * path of the gateway; the rate limit is a reasonable initial
 * rule (200 req / 60s, Netlify's default per-IP aggregation).
 * Per-client hard quotas are deferred until an atomic counter
 * store exists.
 *
 * Note: a previous version of this config included an
 * `aggregateBy: ['ip', 'domain']` field. Netlify Functions v2
 * only honors `windowLimit` and `windowSize`; the custom field
 * was silently ignored, so the docstring claim of "aggregated by
 * IP and domain" was misleading. The field is removed; the
 * limit is whatever Netlify's default aggregation is. The doc
 * now matches reality.
 */
export const config = {
  path: '/private/v1/*',
  rateLimit: {
    windowLimit: 200,
    windowSize: 60,
  },
};
