/**
 * V6.6 — Inventory checksum helpers.
 *
 * The inventory checksum is a SHA-256 over the
 * canonical JSON of the parsed component list.
 *
 * The implementation uses Web Crypto
 * (`globalThis.crypto.subtle.digest`) which is
 * available in the production browser AND in
 * Node 18+ (the test runner runtime). The V6.6
 * code path deliberately does NOT include a Node
 * `crypto` fallback, so the production browser
 * bundle has no `node:crypto` reference. The
 * Vite build graph contains no `sha256Node`
 * chunk and emits no `node:crypto` externalization
 * warning.
 *
 * The checksum is exposed as `sha256:<64 hex>`. The
 * short form (12 hex chars) is what the UI shows in
 * the inventory header.
 *
 * Failure model: when Web Crypto is unavailable the
 * helpers throw a sanitized "sha256: unavailable in
 * this runtime" error. No remote hashing service is
 * ever used.
 */

async function webCryptoDigestHex(bytes) {
  if (typeof globalThis === 'undefined') return null;
  const c = globalThis.crypto;
  if (!c || !c.subtle || typeof c.subtle.digest !== 'function') return null;
  try {
    const digest = await c.subtle.digest('SHA-256', bytes);
    return bytesToHex(new Uint8Array(digest));
  } catch {
    return null;
  }
}

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

/** Compute a SHA-256 over a string. Returns the
 *  lowercase hex digest without a `sha256:` prefix.
 *  Uses Web Crypto (browser + Node 18+); the V6.6
 *  build has no Node `crypto` fallback so the
 *  production browser bundle has no `node:crypto`
 *  reference. */
export async function sha256Hex(str) {
  const bytes = utf8Bytes(str || '');
  const web = await webCryptoDigestHex(bytes);
  if (web) return web;
  throw new Error('sha256: unavailable in this runtime');
}

/** Compute the canonical inventory checksum. The
 *  canonical form is the JSON.stringify of the
 *  component list with sorted keys at every depth
 *  and no whitespace. */
export async function computeInventoryChecksum(components) {
  const canonical = canonicalize(components);
  return 'sha256:' + await sha256Hex(JSON.stringify(canonical));
}

/** Verify an inventory checksum. */
export async function verifyInventoryChecksum(components, expected) {
  if (typeof expected !== 'string' || !expected.startsWith('sha256:')) return false;
  const actual = await computeInventoryChecksum(components);
  return actual === expected;
}

/** Recursive canonical JSON. Sorted keys, no
 *  whitespace, drops `undefined`, throws on
 *  non-finite numbers and circular references. */
function canonicalize(v, seen = new WeakSet()) {
  if (v === null || v === undefined) return null;
  if (typeof v === 'string' || typeof v === 'boolean') return v;
  if (typeof v === 'number') {
    if (!Number.isFinite(v)) throw new Error('canonicalize: non-finite number');
    return v;
  }
  if (Array.isArray(v)) {
    if (seen.has(v)) throw new Error('canonicalize: circular array');
    seen.add(v);
    return v.map((x) => canonicalize(x, seen));
  }
  if (typeof v === 'object') {
    if (seen.has(v)) throw new Error('canonicalize: circular object');
    seen.add(v);
    const out = {};
    for (const k of Object.keys(v).sort()) {
      if (k === '__proto__' || k === 'prototype' || k === 'constructor') continue;
      out[k] = canonicalize(v[k], seen);
    }
    return out;
  }
  throw new Error('canonicalize: unsupported value');
}
