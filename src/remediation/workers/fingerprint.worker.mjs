/**
 * V6.7 — File-fingerprint worker.
 *
 * Computes a SHA-256 of an in-memory byte buffer off
 * the main thread so a 25 MiB file does not freeze
 * the dashboard. The worker is self-contained: it
 * imports only the in-worker SHA-256 helper. The
 * worker NEVER:
 *   - calls the network
 *   - writes to localStorage / IndexedDB
 *   - logs to the console in production
 *   - reads the URL or the history
 *
 * The worker uses Web Crypto. It does not import
 * `node:crypto` and is safe to bundle into the
 * production browser.
 *
 * Communication protocol (main -> worker):
 *   { type: 'fingerprint', jobId, payload: { name, mimeType, sizeBytes, lastModified, buffer } }
 *   { type: 'verify',     jobId, payload: { name, mimeType, sizeBytes, lastModified, buffer, expected } }
 *   { type: 'cancel',     jobId }
 *
 * Communication protocol (worker -> main):
 *   { type: 'progress', jobId, processed, total }
 *   { type: 'result',   jobId, ok: true, fingerprint }
 *   { type: 'result',   jobId, ok: false, reason }
 *   { type: 'verify',    jobId, ok: 'matches' | 'differs' | 'cancelled' }
 *   { type: 'cancelled', jobId }
 *
 * The worker is short-lived. The dispatcher spawns
 * one per job, terminates it on result, and rejects
 * any stale message that arrives after a cancel.
 */

const REASONS = Object.freeze({
  CANCELLED: 'cancelled',
  INVALID: 'invalid-message',
  UNKNOWN: 'unknown',
});

self.addEventListener('message', (ev) => {
  if (!ev || !ev.data || typeof ev.data !== 'object') return;
  const msg = ev.data;
  if (msg.type === 'cancel') {
    cancelJobs.add(msg.jobId);
    return;
  }
  if (msg.type === 'fingerprint') {
    const { jobId, payload } = msg;
    if (!jobId || !payload || !payload.buffer) {
      self.postMessage({ type: 'result', jobId, ok: false, reason: REASONS.INVALID });
      return;
    }
    runFingerprintJob(jobId, payload).catch((err) => {
      self.postMessage({ type: 'result', jobId, ok: false, reason: err && err.message ? err.message : REASONS.UNKNOWN });
    });
  } else if (msg.type === 'verify') {
    const { jobId, payload } = msg;
    if (!jobId || !payload || !payload.buffer || typeof payload.expected !== 'string') {
      self.postMessage({ type: 'verify', jobId, ok: 'cancelled' });
      return;
    }
    runVerifyJob(jobId, payload).catch((err) => {
      self.postMessage({ type: 'verify', jobId, ok: 'cancelled' });
    });
  }
});

const cancelJobs = new Set();

async function runFingerprintJob(jobId, payload) {
  const bytes = payload.buffer instanceof Uint8Array ? payload.buffer : new Uint8Array(payload.buffer);
  const total = bytes.length;
  const batch = 1024 * 1024; // 1 MiB chunks
  let processed = 0;
  // Yield to the event loop between chunks so the
  // main thread can process a `cancel` message.
  while (processed < total) {
    if (cancelJobs.has(jobId)) {
      self.postMessage({ type: 'cancelled', jobId });
      return;
    }
    const next = Math.min(processed + batch, total);
    processed = next;
    self.postMessage({ type: 'progress', jobId, processed, total });
    await new Promise((r) => setTimeout(r, 0));
  }
  if (cancelJobs.has(jobId)) {
    self.postMessage({ type: 'cancelled', jobId });
    return;
  }
  // Compute the SHA-256 via Web Crypto. The buffer is
  // discarded immediately after the digest.
  const hex = await digestHex(bytes);
  self.postMessage({
    type: 'result',
    jobId,
    ok: true,
    fingerprint: {
      fileName: payload.name || '',
      sizeBytes: total,
      mimeType: payload.mimeType || '',
      lastModified: typeof payload.lastModified === 'number' ? payload.lastModified : null,
      checksum: 'sha256:' + hex,
    },
  });
}

async function runVerifyJob(jobId, payload) {
  const bytes = payload.buffer instanceof Uint8Array ? payload.buffer : new Uint8Array(payload.buffer);
  if (cancelJobs.has(jobId)) {
    self.postMessage({ type: 'verify', jobId, ok: 'cancelled' });
    return;
  }
  const hex = await digestHex(bytes);
  const got = 'sha256:' + hex;
  const ok = got === payload.expected ? 'matches' : 'differs';
  self.postMessage({ type: 'verify', jobId, ok });
}

function bytesToHex(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    out += (bytes[i] >>> 4).toString(16);
    out += (bytes[i] & 0xf).toString(16);
  }
  return out;
}

async function digestHex(bytes) {
  // Web Crypto is the only path; no Node fallback.
  const c = (typeof globalThis !== 'undefined' && globalThis.crypto) || null;
  if (!c || !c.subtle || typeof c.subtle.digest !== 'function') {
    throw new Error('sha256: Web Crypto unavailable in worker');
  }
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  const digest = await c.subtle.digest('SHA-256', view);
  return bytesToHex(new Uint8Array(digest));
}
