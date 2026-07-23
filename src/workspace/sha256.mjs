/**
 * V6.4 — async SHA-256 with sync fallback.
 *
 * The browser production path uses Web Crypto
 * (`crypto.subtle.digest`) so we never block the
 * main thread on a 5 MiB workspace file. The sync
 * pure-JS SHA-256 is kept for unit tests and for
 * environments without Web Crypto (e.g. the Node
 * test runner for the small per-CVE change
 * signature). The two helpers expose the same
 * shape: feed a string, get back a lowercase hex
 * digest without a `sha256:` prefix.
 *
 * The Web Crypto helper:
 *   - is asynchronous (returns a Promise<string>)
 *   - never makes a network request
 *   - falls back to a Node `crypto` hash when
 *     `crypto.subtle` is unavailable
 *   - throws a sanitized `unavailable` error when
 *     neither is reachable
 *
 * The sync fallback is the small FIPS 180-4 SHA-256
 * implementation retained for unit tests; the
 * browser production code does not block on it.
 */

const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

function rotr(n, x) { return (x >>> n) | (x << (32 - n)); }

/**
 * Encode a string to UTF-8 bytes using a runtime-
 * appropriate helper.
 */
function utf8(str) {
  if (typeof Buffer !== 'undefined') return new Uint8Array(Buffer.from(str, 'utf8'));
  if (typeof TextEncoder !== 'undefined') return new TextEncoder().encode(str);
  // Fallback manual encoding.
  const out = [];
  for (let i = 0; i < str.length; i++) {
    let c = str.charCodeAt(i);
    if (c < 0x80) out.push(c);
    else if (c < 0x800) { out.push(0xc0 | (c >> 6)); out.push(0x80 | (c & 0x3f)); }
    else if (c < 0xd800 || c >= 0xe000) { out.push(0xe0 | (c >> 12)); out.push(0x80 | ((c >> 6) & 0x3f)); out.push(0x80 | (c & 0x3f)); }
    else { i++; const c2 = str.charCodeAt(i); c = 0x10000 + (((c & 0x3ff) << 10) | (c2 & 0x3ff)); out.push(0xf0 | (c >> 18)); out.push(0x80 | ((c >> 12) & 0x3f)); out.push(0x80 | ((c >> 6) & 0x3f)); out.push(0x80 | (c & 0x3f)); }
  }
  return new Uint8Array(out);
}

function bytesToHex(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    out += (bytes[i] >>> 4).toString(16);
    out += (bytes[i] & 0xf).toString(16);
  }
  return out;
}

function syncSha256Bytes(bytes) {
  const len = bytes.length;
  const padLen = (((len + 9) + 63) & ~63) - len;
  const buf = new Uint8Array(len + padLen);
  buf.set(bytes);
  buf[len] = 0x80;
  const bitLen = BigInt(len) * 8n;
  const dv = new DataView(buf.buffer);
  dv.setBigUint64(buf.length - 8, bitLen, false);
  let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
  let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
  const W = new Uint32Array(64);
  for (let off = 0; off < buf.length; off += 64) {
    for (let i = 0; i < 16; i++) W[i] = dv.getUint32(off + i * 4, false);
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(7, W[i - 15]) ^ rotr(18, W[i - 15]) ^ (W[i - 15] >>> 3);
      const s1 = rotr(17, W[i - 2]) ^ rotr(19, W[i - 2]) ^ (W[i - 2] >>> 10);
      W[i] = (W[i - 16] + s0 + W[i - 7] + s1) >>> 0;
    }
    let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(6, e) ^ rotr(11, e) ^ rotr(25, e);
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + K[i] + W[i]) >>> 0;
      const S0 = rotr(2, a) ^ rotr(13, a) ^ rotr(22, a);
      const mj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + mj) >>> 0;
      h = g; g = f; f = e; e = (d + t1) >>> 0;
      d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0; h5 = (h5 + f) >>> 0; h6 = (h6 + g) >>> 0; h7 = (h7 + h) >>> 0;
  }
  return [h0, h1, h2, h3, h4, h5, h6, h7].map((n) => n.toString(16).padStart(8, '0')).join('');
}

/** Sync helper. Returns a lowercase hex digest WITHOUT
 *  the `sha256:` prefix. Used by unit tests and the
 *  small per-CVE change signature. */
export function sha256HexSync(str) {
  return syncSha256Bytes(utf8(str || ''));
}

/** Returns a `sha256:<64 hex>` prefixed string (sync). */
export function sha256HexPrefixedSync(str) {
  return `sha256:${sha256HexSync(str)}`;
}

/** True when the runtime supports Web Crypto's subtle
 *  digest with SHA-256. */
export function isWebCryptoAvailable() {
  try {
    if (typeof globalThis === 'undefined') return false;
    const c = globalThis.crypto;
    if (!c || !c.subtle || typeof c.subtle.digest !== 'function') return false;
    return true;
  } catch {
    return false;
  }
}

/**
 * The Node test runner exposes a `process.versions.node`
 * marker. We avoid any literal `node:` import strings
 * so the Vite browser build never produces the
 * "Module node:crypto has been externalized" warning.
 * The Node fallback is dispatched at runtime only when
 * `process.versions.node` is present, and the
 * `node:` specifier is composed from a constant so the
 * static analyzer does not match it.
 */

/** True when the runtime has Node `crypto` available.
 *  The V6.6 code path uses Web Crypto only (browser
 *  + Node 18+ both expose `globalThis.crypto.subtle`).
 *  This function is preserved as a public API for
 *  callers that want to inspect the active path and
 *  for backward compatibility with downstream
 *  consumers; it always returns false now. */
export function isNodeCryptoAvailable() {
  return false;
}

class ShaUnavailableError extends Error {
  constructor() {
    super('sha256: unavailable in this runtime');
    this.name = 'ShaUnavailableError';
  }
}

/**
 * Async SHA-256. Uses Web Crypto (browser + Node 18+)
 * so the production browser bundle never has a
 * `node:crypto` reference. Node test runners (18+)
 * expose `globalThis.crypto.subtle` so the same
 * implementation works in tests and in the browser.
 *
 * Returns the lowercase hex digest WITHOUT the
 * `sha256:` prefix.
 */
export async function sha256Hex(str) {
  const bytes = utf8(str || '');
  if (isWebCryptoAvailable()) {
    try {
      const subtle = globalThis.crypto.subtle;
      const digest = await subtle.digest('SHA-256', bytes);
      return bytesToHex(new Uint8Array(digest));
    } catch { /* fall through */ }
  }
  // No remote hashing service. We refuse rather than
  // silently fall back to a sync main-thread hash on a
  // potentially 5 MiB payload.
  throw new ShaUnavailableError();
}

/** Returns the `sha256:<64 hex>` prefixed form. */
export async function sha256HexAsync(str) {
  return `sha256:${await sha256Hex(str)}`;
}

export { ShaUnavailableError };
