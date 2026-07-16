/**
 * V6.5 — Report integrity.
 *
 * The integrity block contains a SHA-256 checksum
 * computed over the canonical report bytes with the
 * integrity block stripped. The async Web Crypto path
 * is always used in the browser; the test runner
 * falls back to Node `crypto` via the runtime
 * dispatcher in `sha256.mjs`.
 *
 * The checksum is NOT a digital signature. It is a
 * tamper-evidence hash: an operator can re-derive the
 * canonical bytes locally and confirm the digest
 * matches the embedded one. No third party is
 * involved.
 */

import { canonicalizeReportBytes } from './canonicalize.mjs';
import { digestString, ShaUnavailableError } from './sha256.mjs';
import { CANONICALIZATION_VERSION } from './schema.mjs';

/** Compute the integrity block for a report.
 *  Returns `{ canonicalizationVersion, checksum }`
 *  where `checksum` is the `sha256:`-prefixed hex
 *  digest of the canonical bytes (with the integrity
 *  block excluded). */
export async function computeIntegrity(report) {
  const canonical = canonicalizeReportBytes(report);
  const hex = await digestString(canonical);
  return {
    canonicalizationVersion: CANONICALIZATION_VERSION,
    checksum: `sha256:${hex}`,
  };
}

/** Synchronous variant for unit tests that pre-compute
 *  the canonical bytes. The browser never calls this
 *  in production; the report builders are async. */
export function computeIntegrityFromHex(report, hex) {
  return {
    canonicalizationVersion: CANONICALIZATION_VERSION,
    checksum: `sha256:${hex}`,
  };
}

/** A short, non-cryptographic prefix of the
 *  checksum, suitable for inline display in the
 *  preview. The full digest is preserved in the
 *  integrity block of the JSON. */
export function shortChecksum(checksum) {
  if (typeof checksum !== 'string') return '';
  if (!checksum.startsWith('sha256:')) return checksum;
  const tail = checksum.slice('sha256:'.length);
  if (tail.length <= 12) return tail;
  return tail.slice(0, 12);
}

export { ShaUnavailableError };
