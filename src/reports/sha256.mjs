/**
 * V6.5 — Public SHA-256 entry.
 *
 * The browser production path uses Web Crypto
 * (`sha256Browser.mjs`). The Node test runner uses
 * Node `crypto` (`sha256Node.mjs`). The dispatch is
 * runtime-based; the Vite browser build never reaches
 * the Node path so no `node:crypto` externalization
 * warning is emitted.
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

const IS_BROWSER = (typeof window !== 'undefined' && typeof document !== 'undefined');
const IS_NODE = (typeof process !== 'undefined' && !!process.versions && !!process.versions.node);

function pickImpl() {
  if (IS_BROWSER) return 'browser';
  if (IS_NODE) return 'node';
  return 'browser'; // best-effort; the browser module will
  // surface a clean unavailable error
}

/** The current implementation. */
export const ACTIVE_IMPL = pickImpl();

/** Re-export the unavailable-error class so callers
 *  catch a single class regardless of the active
 *  implementation. */
export class ShaUnavailableError extends Error {
  constructor() {
    super('sha256: unavailable in this runtime');
    this.name = 'ShaUnavailableError';
  }
}

/** True when the active implementation can serve a
 *  digest. The browser path requires Web Crypto. The
 *  Node path requires `node:crypto`. The function
 *  returns false in either case when the underlying
 *  primitive is missing. */
export async function isAvailable() {
  if (ACTIVE_IMPL === 'browser') return browserIsAvailable();
  const nodeMod = await import('./sha256Node.mjs');
  return nodeMod.isAvailable();
}

export async function digest(bytes) {
  if (ACTIVE_IMPL === 'browser') return await browserDigest(bytes);
  const nodeMod = await import('./sha256Node.mjs');
  return await nodeMod.digest(bytes);
}

export async function digestString(s) {
  if (ACTIVE_IMPL === 'browser') return await browserDigestString(s);
  const nodeMod = await import('./sha256Node.mjs');
  return await nodeMod.digestString(s);
}

export async function digestPrefixed(s) {
  return `sha256:${await digestString(s)}`;
}
