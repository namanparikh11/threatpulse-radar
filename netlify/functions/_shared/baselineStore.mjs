/**
 * V6.0 — Public-site Blob store helpers for the canonical baseline.
 *
 * This file is the PUBLIC SITE'S view of the baseline Blob
 * store. The public site OWNS `tpr-baseline`; this file provides
 * the LOCAL-context helpers used by the V6.0 publisher functions
 * (refresh-baseline-background, the OSV orchestrator, etc.).
 *
 * The canonical baseline lives in the public ThreatPulse site's
 * `tpr-baseline` Blob store. The store is intentionally separate
 * from the existing dashboard caches (`tpr-dataset`,
 * `tpr-vulnrichment`, `tpr-github-advisory`) and the OSV
 * ingestion cache (`tpr-osv`).
 *
 * The V6.0 amendment requires that there is exactly ONE mutable
 * commit point: `manifests/latest.json`. All other artifacts are
 * immutable and content-addressed.
 *
 * Layout:
 *   tpr-baseline/
 *     manifests/latest.json               ← THE atomic commit point (mutable)
 *     manifests/versions/{version}.json   ← immutable version manifests
 *     objects/sha256/{hash}.json.gz       ← immutable content-addressed shards
 *     deltas/{from}__to__{to}.json         ← immutable deltas
 *     publication-lock                    ← transient publication lock
 *     source-health                       ← aggregate source health
 *     source-registry                     ← static source registry
 *
 * The credential records do NOT live in this store. They live in
 * the SEPARATE `tpr-private-credentials` Blob store, which the
 * private gateway reads via cross-site env vars. See
 * `netlify/gateway/src/_shared/baselineStore.mjs` for the
 * gateway's view of both stores.
 *
 * Cross-site access helpers (the previous `getCrossSiteBaselineStore`
 * function) are NOT in this file. They live in
 * `netlify/gateway/src/_shared/baselineStore.mjs` because the
 * public site does not need them; it has direct local-context
 * access via the Netlify runtime. Only the gateway needs
 * cross-site access, and the gateway is a separate Netlify site
 * with its own copy of the helpers.
 */

import { getStore } from '@netlify/blobs';
import { gunzipSync, gzipSync } from 'node:zlib';

export const BASELINE_STORE_NAME = 'tpr-baseline';

export const MANIFESTS_DIR = 'manifests';
export const LATEST_MANIFEST_KEY = `${MANIFESTS_DIR}/latest.json`;
export const SOURCE_HEALTH_KEY = 'source-health';
export const SOURCE_REGISTRY_KEY = 'source-registry';
export const PUBLICATION_LOCK_KEY = 'publication-lock';

export const PUBLICATION_LOCK_TTL_MS = 5 * 60 * 1000;

const ENTITY_TYPES = ['vulnerability', 'advisory', 'package', 'relationship', 'tombstone'];

/**
 * Resolve a handle to the public site's `tpr-baseline` Blob store.
 *
 * The public site has direct local-context access via the
 * Netlify runtime. The previous `getCrossSiteBaselineStore`
 * helper was moved to `netlify/gateway/src/_shared/baselineStore.mjs`
 * because only the gateway needs cross-site access; the public
 * site uses the local runtime context via this function.
 */
export function getBaselineStore(opts = {}) {
  const storeOpts = {
    name: BASELINE_STORE_NAME,
    consistency: opts.consistency ?? 'strong',
  };
  if (opts.siteID) storeOpts.siteID = opts.siteID;
  if (opts.token) storeOpts.token = opts.token;
  return getStore(storeOpts);
}

/**
 * Read a JSON value from the store. Returns null if missing or malformed.
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
 * Write a JSON value to the store. Silent on write failure.
 */
export async function writeJson(store, key, value) {
  try {
    await store.setJSON(key, value);
    return true;
  } catch {
    return false;
  }
}

/**
 * Read the latest manifest. This is the atomic commit point.
 */
export async function readLatestManifest(store) {
  return readJson(store, LATEST_MANIFEST_KEY);
}

/**
 * Atomically overwrite the latest manifest. This is the single
 * strongly-consistent write that consumers check. There is no separate
 * latest-pointer or rollback-pointer — `previousVersion` is inside the
 * manifest itself.
 */
export async function writeLatestManifest(store, manifest) {
  return writeJson(store, LATEST_MANIFEST_KEY, manifest);
}

/**
 * Read an immutable version manifest.
 */
export async function readVersionManifest(store, version) {
  return readJson(store, `${MANIFESTS_DIR}/versions/${version}.json`);
}

/**
 * Write an immutable version manifest.
 */
export async function writeVersionManifest(store, version, manifest) {
  return writeJson(store, `${MANIFESTS_DIR}/versions/${version}.json`, manifest);
}

/**
 * Read a content-addressed shard. The blob is gzipped JSON.
 */
export async function readShard(store, objectKey) {
  try {
    const bytes = await store.get(objectKey, { type: 'arrayBuffer' });
    if (!bytes) return null;
    return JSON.parse(gunzipSync(Buffer.from(bytes)).toString('utf8'));
  } catch {
    return null;
  }
}

/**
 * Write a content-addressed shard. Computes the canonical JSON, gzips,
 * writes to `objects/sha256/<hash>.json.gz`. Returns the object key.
 *
 * The caller is expected to have already computed the bucket, content
 * hash, byte size, and record count via `describeShard()` from the
 * `contentAddressedShards` module. This function just performs the
 * write to whatever object key the caller passes.
 */
export async function writeShard(store, objectKey, canonicalEntities) {
  try {
    const canonicalStr = JSON.stringify(canonicalEntities);
    const gzipped = gzipSync(Buffer.from(canonicalStr, 'utf8'));
    await store.setBinary(objectKey, gzipped);
    return true;
  } catch {
    return false;
  }
}

/**
 * Get-or-create a content-addressed shard. If an object with the same
 * content hash already exists in the store, return its key without
 * writing. Otherwise write the new content and return the new key.
 *
 * This is the deduplication primitive that makes the incremental
 * baseline efficient: unchanged content never gets re-uploaded.
 *
 * NOTE: Netlify Blobs does not expose a "list by prefix" API in the way
 * GCS does, so true deduplication requires the caller to pass in a
 * `knownKeys` set built from the existing manifest. The
 * `publishBaseline()` orchestrator builds this set.
 */
export async function getOrCreateShard(store, contentHashValue, canonicalEntities, knownKeys) {
  const key = `objects/sha256/${contentHashValue.slice('sha256:'.length)}.json.gz`;
  if (knownKeys && knownKeys.has(key)) {
    return { key, deduplicated: true };
  }
  const ok = await writeShard(store, key, canonicalEntities);
  if (!ok) return { key, deduplicated: false, error: 'write failed' };
  return { key, deduplicated: false };
}

/**
 * Acquire the publication lock. Returns true on success, false if the
 * lock is held by another writer.
 */
export async function acquirePublicationLock(store, now = new Date(), ttlMs = PUBLICATION_LOCK_TTL_MS) {
  const expiresAt = new Date(now.getTime() + ttlMs);
  const payload = { acquiredAt: now.toISOString(), expiresAt: expiresAt.toISOString() };
  // Read-then-write is the standard pattern for Netlify Blobs
  // (strongly consistent). A racing writer sees the lock and
  // returns false.
  try {
    const existing = await readJson(store, PUBLICATION_LOCK_KEY);
    if (existing && new Date(existing.expiresAt).getTime() > now.getTime()) {
      return false;
    }
    await writeJson(store, PUBLICATION_LOCK_KEY, payload);
    const recheck = await readJson(store, PUBLICATION_LOCK_KEY);
    if (recheck && recheck.acquiredAt === payload.acquiredAt) return true;
    return false;
  } catch {
    return false;
  }
}

/**
 * Release the publication lock. Best-effort.
 */
export async function releasePublicationLock(store) {
  try {
    await store.delete(PUBLICATION_LOCK_KEY);
  } catch {
    // best-effort
  }
}

/**
 * Read the aggregate source-health blob.
 */
export async function readSourceHealth(store) {
  return readJson(store, SOURCE_HEALTH_KEY);
}

/**
 * Write the aggregate source-health blob.
 */
export async function writeSourceHealth(store, health) {
  return writeJson(store, SOURCE_HEALTH_KEY, health);
}

/**
 * Read the static source-registry blob.
 */
export async function readSourceRegistry(store) {
  return readJson(store, SOURCE_REGISTRY_KEY);
}

/**
 * Write the static source-registry blob.
 */
export async function writeSourceRegistry(store, registry) {
  return writeJson(store, SOURCE_REGISTRY_KEY, registry);
}

/**
 * Read a delta file. Returns the parsed JSON or null.
 */
export async function readDelta(store, fromVersion, toVersion) {
  const key = `deltas/${fromVersion}__to__${toVersion}.json`;
  return readJson(store, key);
}

/**
 * Write a delta file. The delta JSON is NOT gzipped (deltas are
 * small; gzipping would add a decompression step on the consumer
 * side for marginal benefit).
 */
export async function writeDelta(store, fromVersion, toVersion, delta) {
  const key = `deltas/${fromVersion}__to__${toVersion}.json`;
  return writeJson(store, key, delta);
}

export { ENTITY_TYPES };
