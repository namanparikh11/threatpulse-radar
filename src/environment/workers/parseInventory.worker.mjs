/**
 * V6.6 — Inventory parser worker.
 *
 * Runs `parseImport` off the main thread so a 25 MiB
 * SBOM does not freeze the dashboard. The worker is
 * self-contained: it imports only the import
 * pipeline and a tiny pure-JS SHA-256 helper. The
 * worker NEVER:
 *   - calls the network
 *   - writes to localStorage / IndexedDB
 *   - logs to the console in production
 *   - reads the URL or the history
 *
 * Communication protocol (main -> worker):
 *   { type: 'parse', jobId, payload: { text, options, checksumInput } }
 *   { type: 'cancel', jobId }
 *
 * Communication protocol (worker -> main):
 *   { type: 'progress', jobId, processed, total }
 *   { type: 'result', jobId, ok: true, result, checksum }
 *   { type: 'result', jobId, ok: false, reason }
 *   { type: 'cancelled', jobId }
 *
 * The checksum is a pure-JS SHA-256 of the canonical
 * text bytes; the main thread re-runs the same digest
 * on the result components to produce the final
 * inventory checksum via Web Crypto. The worker
 * checksum is included for debugging only.
 */

import { parseImport } from '../import.mjs';

const REASONS = Object.freeze({
  CANCELLED: 'cancelled',
  UNKNOWN: 'unknown',
});

self.addEventListener('message', (ev) => {
  if (!ev || !ev.data || typeof ev.data !== 'object') return;
  const msg = ev.data;
  if (msg.type === 'cancel') {
    cancelJobs.add(msg.jobId);
    return;
  }
  if (msg.type === 'parse') {
    const { jobId, payload } = msg;
    if (!jobId || !payload || typeof payload.text !== 'string') {
      self.postMessage({ type: 'result', jobId, ok: false, reason: 'invalid-message' });
      return;
    }
    runJob(jobId, payload).catch((err) => {
      self.postMessage({ type: 'result', jobId, ok: false, reason: err && err.message ? err.message : REASONS.UNKNOWN });
    });
  }
});

const cancelJobs = new Set();

async function runJob(jobId, payload) {
  // Progress reporting is chunked; parseImport is
  // synchronous, so we slice the result into batches
  // of 500 components and yield to the event loop
  // between batches.
  const out = parseImport(payload.text, payload.options || {});
  if (!out.ok) {
    self.postMessage({ type: 'result', jobId, ok: false, reason: out.reason });
    return;
  }
  const total = out.result.components.length;
  if (total === 0) {
    self.postMessage({ type: 'result', jobId, ok: true, result: out.result, checksum: '' });
    return;
  }
  const batch = 500;
  let processed = 0;
  while (processed < total) {
    if (cancelJobs.has(jobId)) {
      self.postMessage({ type: 'cancelled', jobId });
      return;
    }
    const next = Math.min(processed + batch, total);
    processed = next;
    self.postMessage({ type: 'progress', jobId, processed, total });
    // Yield to the event loop so cancellation
    // messages can be processed.
    await new Promise((r) => setTimeout(r, 0));
  }
  // Final checksum over the canonical text (the
  // worker never sees the network; this is purely
  // a fingerprint for the import record).
  const checksum = 'sha256:' + bytesToHex(sha256Sync(payload.text));
  self.postMessage({ type: 'result', jobId, ok: true, result: out.result, checksum });
}

// ---- pure-JS SHA-256 (used only inside the worker) ----
const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c5, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);
function rotr(n, x) { return (x >>> n) | (x << (32 - n)); }
function utf8(s) {
  if (typeof TextEncoder !== 'undefined') return new TextEncoder().encode(s);
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
function sha256Sync(str) {
  const bytes = utf8(str);
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
    let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, hh = h7;
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(6, e) ^ rotr(11, e) ^ rotr(25, e);
      const ch = (e & f) ^ (~e & g);
      const t1 = (hh + S1 + ch + K[i] + W[i]) >>> 0;
      const S0 = rotr(2, a) ^ rotr(13, a) ^ rotr(22, a);
      const mj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + mj) >>> 0;
      hh = g; g = f; f = e; e = (d + t1) >>> 0;
      d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0; h5 = (h5 + f) >>> 0; h6 = (h6 + g) >>> 0; h7 = (h7 + hh) >>> 0;
  }
  return [h0, h1, h2, h3, h4, h5, h6, h7];
}
function bytesToHex(arr) {
  let out = '';
  for (let i = 0; i < arr.length; i++) {
    out += (arr[i] >>> 4).toString(16);
    out += (arr[i] & 0xf).toString(16);
  }
  return out;
}
