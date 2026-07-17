/**
 * V6.7 — Remediation SHA-256 helper.
 *
 * Browser-reachable Web Crypto wrapper. The V6.7
 * code path uses Web Crypto only (browser + Node 18+
 * both expose `globalThis.crypto.subtle`), so the
 * production browser bundle has no `node:crypto`
 * reference and the Vite build graph contains no
 * `sha256Node` chunk.
 *
 * Returns the lowercase hex digest WITHOUT the
 * `sha256:` prefix. The caller composes the
 * `sha256:` prefix when stamping the ledger event
 * hash or the bundle integrity block.
 *
 * Failure model: when Web Crypto is unavailable the
 * helpers throw a sanitized "sha256: unavailable in
 * this runtime" error. No remote hashing service is
 * ever used.
 */

function bytesToHex(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    out += (bytes[i] >>> 4).toString(16);
    out += (bytes[i] & 0xf).toString(16);
  }
  return out;
}

function utf8Bytes(s) {
  if (typeof TextEncoder !== 'undefined') return new TextEncoder().encode(s);
  if (typeof Buffer !== 'undefined') return new Uint8Array(Buffer.from(s, 'utf8'));
  const out = [];
  for (let i = 0; i < s.length; i++) {
    let c = s.charCodeAt(i);
    if (c < 0x80) out.push(c);
    else if (c < 0x800) { out.push(0xc0 | (c >> 6)); out.push(0x80 | (c & 0x3f)); }
    else if (c < 0xd800 || c >= 0xe000) { out.push(0xe0 | (c >> 12)); out.push(0x80 | ((c >> 6) & 0x3f)); out.push(0x80 | (c & 0x3f)); }
    else { i++; const c2 = s.charCodeAt(i); c = 0x10000 + (((c & 0x3ff) << 10) | (c2 & 0x3ff)); out.push(0xf0 | (c >> 18)); out.push(0x80 | ((c >> 12) & 0x3f)); out.push(0x80 | ((c >> 6) & 0x3f)); out.push(0x80 | (c & 0x3f)); }
  }
  return new Uint8Array(out);
}

export class ShaUnavailableError extends Error {
  constructor() {
    super('sha256: unavailable in this runtime');
    this.name = 'ShaUnavailableError';
  }
}

/** True when Web Crypto's subtle digest with
 *  SHA-256 is reachable. */
export function isAvailable() {
  try {
    if (typeof globalThis === 'undefined') return false;
    const c = globalThis.crypto;
    if (!c || !c.subtle || typeof c.subtle.digest !== 'function') return false;
    return true;
  } catch {
    return false;
  }
}

/** Compute a SHA-256 over a string. Returns the
 *  lowercase hex digest without a `sha256:` prefix. */
export async function sha256Hex(str) {
  const bytes = utf8Bytes(str || '');
  if (!isAvailable()) throw new ShaUnavailableError();
  try {
    const subtle = globalThis.crypto.subtle;
    const digest = await subtle.digest('SHA-256', bytes);
    return bytesToHex(new Uint8Array(digest));
  } catch {
    throw new ShaUnavailableError();
  }
}

/** Compute a SHA-256 over raw bytes. Returns the
 *  lowercase hex digest without a `sha256:` prefix. */
export async function sha256HexBytes(bytes) {
  if (!isAvailable()) throw new ShaUnavailableError();
  try {
    const subtle = globalThis.crypto.subtle;
    const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    const digest = await subtle.digest('SHA-256', view);
    return bytesToHex(new Uint8Array(digest));
  } catch {
    throw new ShaUnavailableError();
  }
}

/** Returns the `sha256:<64 hex>` prefixed form. */
export async function sha256HexPrefixed(str) {
  return `sha256:${await sha256Hex(str)}`;
}
