/**
 * V6.1 — Public-intelligence query parameter validators.
 *
 * The dataset function's `view=osv` and `view=changes` modes
 * accept only validated, well-formed parameters. Malformed
 * parameters return HTTP 400 with a sanitized body
 * (`{"error":"invalid-<field>"}`).
 *
 * Path-traversal attempts (e.g. `cve=../foo`,
 * `version=../foo`, `bucket=../foo`) are rejected with 400.
 *
 * The current-version-only rule is enforced separately in
 * `dataset.mjs` (after this validation step).
 */

/** Regex for a public-intelligence version id. The timestamp is
 * truncated to seconds and the colons are replaced with hyphens
 * (the same convention as `canonicalHash.deriveBaselineVersion`).
 * The trailing hash is 12 hex chars. */
export const VERSION_REGEX = /^\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}Z-[0-9a-f]{12}$/;

/** Regex for an OSV projection version id. The format is
 * `<canonical-baseline-version>-<manifest-hash-12-hex>`. The
 * canonical-baseline-version's hash is 8-16 hex. The manifest
 * hash is 12 hex. */
export const OSV_VERSION_REGEX = /^\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}Z-[0-9a-f]{8,16}-[0-9a-f]{12}$/;

/** Regex for a CVE id (case-insensitive on the prefix). */
export const CVE_REGEX = /^CVE-\d{4}-\d{4,7}$/i;

/** Regex for a 16-bucket hex digit (case-insensitive). */
export const BUCKET_REGEX = /^[0-9a-f]$/i;

/** Valid `view` values. */
export const VALID_VIEWS = new Set(['osv', 'changes']);

/** Valid change-intelligence category values. */
export const VALID_CATEGORIES = new Set([
  'newly-tracked',
  'no-longer-tracked',
  'fact-newly-available',
  'fact-changed',
  'fact-no-longer-present',
  'provider-status-changed',
]);

/**
 * Validate a `view` parameter. Returns the normalized view name
 * or null when invalid.
 */
export function validateView(value) {
  if (typeof value !== 'string') return null;
  if (!VALID_VIEWS.has(value)) return null;
  return value;
}

/**
 * Validate a `version` parameter. Returns the version id or
 * null when invalid. Does NOT enforce the current-version
 * match; that is done in the dataset function.
 */
export function validateVersion(value) {
  if (typeof value !== 'string') return null;
  if (!VERSION_REGEX.test(value)) return null;
  return value;
}

/**
 * Validate a `cve` parameter. Returns the uppercased CVE id or
 * null when invalid. Always uppercases; the public dataset
 * uses uppercased CVE ids.
 */
export function validateCve(value) {
  if (typeof value !== 'string') return null;
  if (!CVE_REGEX.test(value)) return null;
  return value.toUpperCase();
}

/**
 * Validate a `category` parameter for `view=changes`.
 */
export function validateCategory(value) {
  if (typeof value !== 'string') return null;
  if (!VALID_CATEGORIES.has(value)) return null;
  return value;
}

/**
 * Validate a `limit` parameter. Returns an integer in
 * [1, CHANGES_ITEMS_MAX_LIMIT] or null when invalid.
 */
export function validateLimit(value, max = 25) {
  const n = typeof value === 'string' ? parseInt(value, 10) : value;
  if (!Number.isInteger(n)) return null;
  if (n < 1 || n > max) return null;
  return n;
}

/**
 * Validate a `bucket` parameter (OSV shard selection). Returns
 * the lowercase hex digit or null when invalid.
 */
export function validateBucket(value) {
  if (typeof value !== 'string') return null;
  if (!BUCKET_REGEX.test(value)) return null;
  return value.toLowerCase();
}
