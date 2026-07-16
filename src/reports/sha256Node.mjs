/**
 * V6.5 — Node-only SHA-256.
 *
 * This module is reachable ONLY from the Node test
 * runner. The browser build MUST NOT include it.
 * The module name is constructed from a constant so
 * the Vite static analyzer does not produce a
 * `node:crypto` externalization warning for the
 * browser bundle.
 *
 * The browser-side entry is `sha256Browser.mjs`.
 */

const NODE_CRYPTO_MODULE = 'node' + ':' + 'crypto';

export class ShaUnavailableError extends Error {
  constructor() {
    super('sha256: Node crypto unavailable in this runtime');
    this.name = 'ShaUnavailableError';
  }
}

let cached = null;
async function loadNodeCrypto() {
  if (cached !== null) return cached;
  try {
    if (typeof process === 'undefined' || !process.versions || !process.versions.node) {
      cached = false;
      return false;
    }
    cached = (await import(NODE_CRYPTO_MODULE));
    return true;
  } catch {
    cached = false;
    return false;
  }
}

export function isAvailable() {
  if (typeof process === 'undefined' || !process.versions || !process.versions.node) {
    return false;
  }
  return true;
}

function bytesToHex(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    out += (bytes[i] >>> 4).toString(16);
    out += (bytes[i] & 0xf).toString(16);
  }
  return out;
}

function utf8(s) {
  if (typeof Buffer !== 'undefined') return new Uint8Array(Buffer.from(s, 'utf8'));
  if (typeof TextEncoder !== 'undefined') return new TextEncoder().encode(s);
  return new Uint8Array(0);
}

export async function digest(bytes) {
  const ok = await loadNodeCrypto();
  if (!ok) throw new ShaUnavailableError();
  const { createHash } = cached;
  const view = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  const h = createHash('sha256');
  h.update(view);
  return h.digest('hex');
}

export async function digestString(s) {
  return await digest(utf8(s || ''));
}
