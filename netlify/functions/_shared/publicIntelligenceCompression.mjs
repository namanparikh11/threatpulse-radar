/**
 * V6.1 — Public-intelligence gzip compression helpers.
 *
 * Public-intelligence Blobs that may grow large (public
 * snapshot, changes items, OSV shards) are stored gzipped
 * to keep Blob sizes within the Netlify Blobs free-tier
 * limits and to reduce read time. The compression is
 * transport-level only; content hashes are computed on the
 * canonical (uncompressed) bytes, not the gzipped bytes.
 *
 * The dataset / Vulnrichment / GitHub Advisory Blobs are
 * stored as plain JSON (the V6.0 convention). The internal
 * per-Blob public-hash metadata is added to those JSON
 * values directly.
 *
 * The helpers here are pure (no I/O). The Netlify Blobs
 * `setBinary` / `get` API is used by the publisher to
 * actually write / read the gzipped buffers.
 */

import { gunzipSync, gzipSync } from 'node:zlib';

/**
 * Gzip a value to a Buffer. The input is JSON-serialized
 * first; the canonical (sorted-keys) form is NOT used
 * here because the canonical form is for hashing, not for
 * transport.
 */
export function gzipValue(value) {
  return gzipSync(Buffer.from(JSON.stringify(value), 'utf8'));
}

/**
 * Gunzip a Buffer to a JSON-parsed value. Returns null
 * when the input is null or empty; throws on parse error.
 */
export function gunzipValue(buffer) {
  if (!buffer) return null;
  if (buffer.length === 0) return null;
  const text = gunzipSync(Buffer.from(buffer)).toString('utf8');
  return JSON.parse(text);
}

/**
 * Convenience: gzip and return a base64-encoded string
 * for debugging / fixture purposes. The actual write path
 * uses the Buffer directly with `setBinary`.
 */
export function gzipToBase64(value) {
  return gzipValue(value).toString('base64');
}
