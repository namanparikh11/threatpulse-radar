/**
 * V6.1 — Public-intelligence composite hash, version id, and
 * per-Blob public-hash helpers.
 *
 * The public dashboard response is the merge of:
 *   - the public dataset envelope (after INTERNAL_BLOB_FIELDS strip)
 *   - the publicly projected Vulnrichment SSVC cache (records[] only)
 *   - the publicly projected GitHub Advisory cache (records[] only)
 *   - the referenced immutable OSV public projection (manifest hash)
 *
 * A cache change (even with the same dataset `fetchedAt`) must
 * produce a new composite `publicStateHash` and a new
 * dataset-bound version id. The composite hash is computed at
 * write time and persisted; the read path reuses the persisted
 * hashes (no re-hashing of cache contents on every dashboard
 * request).
 *
 * Per-Blob internal public-hash metadata is written into the
 * dataset / Vulnrichment / GitHub Advisory Blob envelopes
 * themselves, so a single Blob read yields both content and
 * its public hash atomically. The internal hash fields are
 * added to `INTERNAL_BLOB_FIELDS` (see `refresh.mjs`) so they
 * are stripped from the public response.
 *
 * The full `publicStateHash` is internal-only. The default
 * public response exposes a short, non-security diagnostic
 * fingerprint (the 12-hex version id) but never the full hash.
 */

import { createHash } from 'node:crypto';
import { canonicalize, canonicalizeToString, sha256Hex, shortHash } from './canonicalHash.mjs';

/**
 * The current public-intelligence schema versions. Bumped on
 * breaking changes; never silently changed.
 */
export const PUBLIC_PROJECTION_SCHEMA_VERSION = '1.0.0';
export const PUBLIC_STATE_SCHEMA_VERSION = '1.0.0';

/**
 * Compute the public hash of a Blob's publicly projected content.
 * The hash describes the deterministic publicly projected fields
 * (INTERNAL_BLOB_FIELDS stripped). This hash is written INTO the
 * Blob envelope as `_publicHash` and stripped at read time.
 *
 * Stable: identical input always produces the same hash.
 */
export function computePublicHash(value) {
  if (value === null || value === undefined) return null;
  return `sha256:${sha256Hex(canonicalizeToString(value))}`;
}

/**
 * Strip the INTERNAL_BLOB_FIELDS from an envelope before
 * hashing, so the hash describes the publicly visible content
 * only. The strip list is intentionally not parametrized —
 * the V6.0 INTERNAL_BLOB_FIELDS set is the single source of
 * truth, and this helper is the single point of use.
 */
export function stripForPublicHash(envelope) {
  if (!envelope || typeof envelope !== 'object') return envelope;
  const out = { ...envelope };
  // V6.0 + V6.1 INTERNAL_BLOB_FIELDS, mirrored here so the
  // V6.1 hash helpers don't import the refresh module
  // (which would create a circular import). The V6.0 module
  // remains the canonical owner of the strip list.
  const internal = [
    'lastRefreshAttemptAt',
    'lastRefreshFailure',
    'lastVulnrichmentRefresh',
    'lastGithubAdvisoryRefresh',
    'datasetPublicHash',
    'vulnrichmentPublicHash',
    'githubAdvisoryPublicHash',
    'lastPublicIntelligenceRefresh',
    'lastSourceHealthRefresh',
    'lastOsvProjectionRefresh',
    'lastChangeIntelligenceRefresh',
    'lastChangeIntelligenceBaseVersion',
    '_publicHash',
  ];
  for (const f of internal) delete out[f];
  return out;
}

/**
 * Compute the public hash of the dataset envelope (with internal
 * fields stripped).
 */
export function computeDatasetPublicHash(envelope) {
  return computePublicHash(stripForPublicHash(envelope));
}

/**
 * Compute the public hash of a Vulnrichment or GitHub Advisory
 * cache. The hash covers the publicly projected `records` map
 * only — the cache's own `updatedAt` metadata is excluded so
 * the hash is stable across the same content with different
 * cache timestamps.
 */
export function computeEnrichmentPublicHash(cache) {
  if (!cache || typeof cache !== 'object') return null;
  const records = cache.records && typeof cache.records === 'object'
    ? cache.records
    : {};
  return `sha256:${sha256Hex(canonicalizeToString({ records }))}`;
}

/**
 * Compute the composite `publicStateHash` from the four
 * precomputed inputs. Deterministic and stable.
 */
export function computePublicStateHash({
  datasetPublicHash,
  vulnrichmentPublicHash,
  githubAdvisoryPublicHash,
  referencedOsvProjectionVersion,
  referencedOsvProjectionContentHash,
} = {}) {
  const payload = canonicalizeToString({
    datasetPublicHash: datasetPublicHash ?? null,
    vulnrichmentPublicHash: vulnrichmentPublicHash ?? null,
    githubAdvisoryPublicHash: githubAdvisoryPublicHash ?? null,
    referencedOsvProjectionVersion: referencedOsvProjectionVersion ?? null,
    referencedOsvProjectionContentHash: referencedOsvProjectionContentHash ?? null,
    publicProjectionSchemaVersion: PUBLIC_PROJECTION_SCHEMA_VERSION,
    publicStateSchemaVersion: PUBLIC_STATE_SCHEMA_VERSION,
  });
  return `sha256:${sha256Hex(payload)}`;
}

/**
 * Derive a filesystem-safe dataset-bound version id from a
 * publish timestamp and the composite publicStateHash. The
 * first 12 hex characters of the hash are used; this is
 * collision-resistant in practice (12 hex = 48 bits of
 * entropy).
 */
export function derivePublicIntelligenceVersion(generatedAt, publicStateHashValue, hashLen = 12) {
  if (typeof generatedAt !== 'string' || !generatedAt) {
    throw new Error('derivePublicIntelligenceVersion: generatedAt is required');
  }
  if (typeof publicStateHashValue !== 'string' || !publicStateHashValue.startsWith('sha256:')) {
    throw new Error('derivePublicIntelligenceVersion: publicStateHash must be sha256:<hex>');
  }
  if (!Number.isInteger(hashLen) || hashLen < 1 || hashLen > 64) {
    throw new Error('derivePublicIntelligenceVersion: hashLen must be 1..64');
  }
  // Truncate to seconds and replace colons with hyphens (filesystem-safe).
  const sec = generatedAt.replace(/\.\d+(?=Z)/, '').replace(/:/g, '-');
  return `${sec}-${shortHash(publicStateHashValue, hashLen)}`;
}

/**
 * Derive a collision-resistant OSV projection version id. The
 * canonical baseline version is timestamp-derived; we append
 * the first 12 hex of the canonical manifest content hash to
 * disambiguate retries within the same timestamp window and
 * to make identical-content retries reuse the same id.
 */
export function deriveOsvProjectionVersion(canonicalBaselineVersion, canonicalManifestHash, hashLen = 12) {
  if (typeof canonicalBaselineVersion !== 'string' || !canonicalBaselineVersion) {
    throw new Error('deriveOsvProjectionVersion: canonicalBaselineVersion is required');
  }
  if (typeof canonicalManifestHash !== 'string' || !canonicalManifestHash.startsWith('sha256:')) {
    throw new Error('deriveOsvProjectionVersion: canonicalManifestHash must be sha256:<hex>');
  }
  if (!Number.isInteger(hashLen) || hashLen < 1 || hashLen > 64) {
    throw new Error('deriveOsvProjectionVersion: hashLen must be 1..64');
  }
  return `${canonicalBaselineVersion}-${shortHash(canonicalManifestHash, hashLen)}`;
}

/**
 * Quick fingerprint for the public response. This is a short,
 * non-security diagnostic value derived from the public state
 * hash; it is NOT a security verification token and must never
 * be used as such.
 */
export function publicStateFingerprint(publicStateHashValue) {
  if (typeof publicStateHashValue !== 'string') return null;
  return shortHash(publicStateHashValue, 12);
}

/**
 * Stable sha256 hex (no prefix) for use in OSV content-addressed
 * shard keys. Returns the lowercase hex digest of an input.
 */
export function contentAddressedHash(value) {
  return sha256Hex(canonicalizeToString(value));
}
