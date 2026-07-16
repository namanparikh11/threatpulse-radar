/**
 * V6.5 — Browser-only SHA-256.
 *
 * This module is reachable from the browser
 * production path. It uses Web Crypto
 * (`crypto.subtle.digest`) and never references any
 * Node-only module. The Vite browser build MUST NOT
 * emit the "Module node:crypto has been externalized"
 * warning for this file.
 *
 * Functions:
 *   - isAvailable(): true when Web Crypto is reachable
 *   - digest(bytes): Promise<string> lowercase hex
 *   - digestString(s): Promise<string> lowercase hex
 *
 * When Web Crypto is not available, the helper
 * throws a sanitized `ShaUnavailableError` so the
 * caller can surface a clean error message.
 */

export class ShaUnavailableError extends Error {
  constructor() {
    super('sha256: Web Crypto unavailable in this runtime');
    this.name = 'ShaUnavailableError';
  }
}

function getSubtle() {
  try {
    if (typeof globalThis === 'undefined') return null;
    const c = globalThis.crypto;
    if (!c || !c.subtle || typeof c.subtle.digest !== 'function') return null;
    return c.subtle;
  } catch {
    return null;
  }
}

export function isAvailable() {
  return getSubtle() !== null;
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

export async function digest(bytes) {
  const subtle = getSubtle();
  if (!subtle) throw new ShaUnavailableError();
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  const digest = await subtle.digest('SHA-256', view);
  return bytesToHex(new Uint8Array(digest));
}

export async function digestString(s) {
  return await digest(utf8(s || ''));
}

export { ShaUnavailableError as BrowserShaUnavailableError };
