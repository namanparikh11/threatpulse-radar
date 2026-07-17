/**
 * V6.6 — Public SHA-256 entry.
 *
 * Browser-reachable public surface. Uses Web Crypto
 * (crypto.subtle.digest) so the production browser
 * bundle NEVER contains a Node `crypto` reference.
 * The Vite build graph has no `sha256Node` chunk.
 *
 * Node test runners (Node 18+) also expose
 * `globalThis.crypto.subtle`, so the same browser
 * implementation works in the test runner. The
 * previous dual-impl dispatch (browser + Node
 * `crypto`) was removed in V6.6 because it forced
 * Vite to bundle a `sha256Node` chunk for the
 * browser, even though the Node path was never
 * reached at runtime.
 *
 * Both implementations return a lowercase hex digest
 * WITHOUT the `sha256:` prefix. The caller composes
 * the `sha256:` prefix when building the integrity
 * block of a report.
 *
 * Failure model: when no SHA-256 implementation is
 * reachable, the helpers throw a sanitized
 * `ShaUnavailableError`. No remote hashing service
 * is ever used.
 */

import {
  isAvailable as browserIsAvailable,
  digest as browserDigest,
  digestString as browserDigestString,
  ShaUnavailableError as BrowserShaUnavailableError,
} from './sha256Browser.mjs';

export class ShaUnavailableError extends Error {
  constructor() {
    super('sha256: unavailable in this runtime');
    this.name = 'ShaUnavailableError';
  }
}

/** True when Web Crypto's subtle digest with SHA-256
 *  is reachable. Browser production path + Node 18+
 *  test runner both report `true`. */
export async function isAvailable() {
  return browserIsAvailable();
}

export async function digest(bytes) {
  return await browserDigest(bytes);
}

export async function digestString(s) {
  return await browserDigestString(s);
}

export async function digestPrefixed(s) {
  return `sha256:${await digestString(s)}`;
}

/** The current implementation. Always 'browser' (Web
 *  Crypto). Kept as a public field for callers that
 *  want to inspect the active path. The V6.5
 *  `ACTIVE_IMPL` field is preserved for backward
 *  compatibility with downstream consumers. */
export const ACTIVE_IMPL = 'browser';

// Re-export the browser unavailable-error class so
// callers catch a single class regardless of the
// runtime.
export { BrowserShaUnavailableError };
