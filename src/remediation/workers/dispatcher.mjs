/**
 * V6.7 — File-fingerprint worker dispatcher.
 *
 * Main-thread wrapper around the fingerprint worker.
 * Falls back to a synchronous main-thread path when
 * the worker is unavailable (older browsers, the
 * Node test runner, hardened enterprise policies
 * that block worker scripts).
 *
 * Each call returns a `handle` with:
 *   - onProgress(cb)
 *   - cancel()
 *   - result(): Promise<...>
 *
 * The dispatcher tracks every outstanding job in a
 * `genRef` counter. When the consumer calls
 * `cancel()`, the dispatcher bumps genRef and
 * resolves the pending result with reason 'cancelled'
 * if the worker has not already finished. Stale
 * messages that arrive after the cancel are ignored.
 *
 * The dispatcher NEVER:
 *   - touches the network
 *   - writes to the URL / history
 *   - logs to the console in production
 *   - re-uses a worker across cancel + new job
 *     (a new worker is spawned per job to keep the
 *     lifecycle simple)
 */

const REASONS = Object.freeze({
  CANCELLED: 'cancelled',
  WORKER_UNAVAILABLE: 'worker-unavailable',
  INVALID_MESSAGE: 'invalid-message',
  UNKNOWN: 'unknown',
  TOO_LARGE: 'file-too-large',
});

let nextJobId = 1;
const MAX_FILE_BYTES = 25 * 1024 * 1024;

/** Spawn a fingerprint job. Returns a handle. */
export function startFingerprintJob({ name, mimeType, sizeBytes, lastModified, buffer, onProgress }) {
  if (typeof sizeBytes === 'number' && sizeBytes > MAX_FILE_BYTES) {
    return {
      handle: makeSyncHandle({ ok: false, reason: REASONS.TOO_LARGE }),
    };
  }
  if (typeof Worker === 'undefined' || typeof import.meta === 'undefined') {
    return startSyncFingerprint({ name, mimeType, sizeBytes, lastModified, buffer, onProgress });
  }
  const jobId = 'fp-' + (nextJobId++);
  let worker;
  try {
    worker = new Worker(new URL('./fingerprint.worker.mjs', import.meta.url), { type: 'module' });
  } catch (err) {
    return startSyncFingerprint({ name, mimeType, sizeBytes, lastModified, buffer, onProgress });
  }
  const handle = makeWorkerHandle(worker, jobId, onProgress);
  worker.postMessage({
    type: 'fingerprint',
    jobId,
    payload: { name, mimeType, sizeBytes, lastModified, buffer },
  });
  return { handle };
}

/** Spawn a verify job. Returns a handle. */
export function startVerifyJob({ name, mimeType, sizeBytes, lastModified, buffer, expected, onProgress }) {
  if (typeof sizeBytes === 'number' && sizeBytes > MAX_FILE_BYTES) {
    return { handle: makeSyncHandle({ ok: false, reason: REASONS.TOO_LARGE }) };
  }
  if (typeof Worker === 'undefined' || typeof import.meta === 'undefined') {
    return startSyncVerify({ name, mimeType, sizeBytes, lastModified, buffer, expected, onProgress });
  }
  const jobId = 'vf-' + (nextJobId++);
  let worker;
  try {
    worker = new Worker(new URL('./fingerprint.worker.mjs', import.meta.url), { type: 'module' });
  } catch (err) {
    return startSyncVerify({ name, mimeType, sizeBytes, lastModified, buffer, expected, onProgress });
  }
  const handle = makeWorkerHandle(worker, jobId, onProgress, /* verify */ true);
  worker.postMessage({
    type: 'verify',
    jobId,
    payload: { name, mimeType, sizeBytes, lastModified, buffer, expected },
  });
  return { handle };
}

function makeWorkerHandle(worker, jobId, onProgress, isVerify = false) {
  let cancelled = false;
  let progressCb = typeof onProgress === 'function' ? onProgress : null;
  let resolveResult;
  let rejectResult;
  const result = new Promise((resolve, reject) => {
    resolveResult = resolve;
    rejectResult = reject;
  });
  worker.onmessage = (ev) => {
    if (!ev || !ev.data || typeof ev.data !== 'object') return;
    if (cancelled) return;
    const m = ev.data;
    if (m.jobId !== jobId) return;
    if (m.type === 'progress') {
      if (progressCb) progressCb({ processed: m.processed, total: m.total });
      return;
    }
    if (m.type === 'result' && m.ok) {
      cleanup();
      resolveResult({ ok: true, fingerprint: m.fingerprint });
      return;
    }
    if (m.type === 'result' && !m.ok) {
      cleanup();
      resolveResult({ ok: false, reason: m.reason || REASONS.UNKNOWN });
      return;
    }
    if (m.type === 'verify') {
      cleanup();
      resolveResult({ ok: true, verifyOutcome: m.ok });
      return;
    }
    if (m.type === 'cancelled') {
      cleanup();
      resolveResult({ ok: false, reason: REASONS.CANCELLED });
      return;
    }
  };
  worker.onerror = (err) => {
    if (cancelled) return;
    cleanup();
    rejectResult(err);
  };
  function cleanup() {
    try { worker.terminate(); } catch { /* ignore */ }
  }
  return {
    cancel() {
      if (cancelled) return;
      cancelled = true;
      try { worker.postMessage({ type: 'cancel', jobId }); } catch { /* ignore */ }
      resolveResult({ ok: false, reason: REASONS.CANCELLED });
      cleanup();
    },
    onProgress(cb) { progressCb = typeof cb === 'function' ? cb : null; },
    result() { return result; },
  };
}

function makeSyncHandle(resultObj) {
  return {
    cancel() { /* no-op */ },
    onProgress() {},
    result() { return Promise.resolve(resultObj); },
  };
}

function startSyncFingerprint({ name, mimeType, sizeBytes, lastModified, buffer, onProgress }) {
  let cancelled = false;
  const out = (async () => {
    if (cancelled) return { ok: false, reason: REASONS.CANCELLED };
    if (typeof sizeBytes === 'number' && sizeBytes > MAX_FILE_BYTES) {
      return { ok: false, reason: REASONS.TOO_LARGE };
    }
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer || []);
    const total = bytes.length;
    if (onProgress) {
      const step = 1024 * 1024;
      let processed = 0;
      while (processed < total) {
        if (cancelled) return { ok: false, reason: REASONS.CANCELLED };
        const next = Math.min(processed + step, total);
        processed = next;
        onProgress({ processed, total });
        await new Promise((r) => setTimeout(r, 0));
      }
    }
    const c = (typeof globalThis !== 'undefined' && globalThis.crypto) || null;
    if (!c || !c.subtle || typeof c.subtle.digest !== 'function') {
      return { ok: false, reason: REASONS.WORKER_UNAVAILABLE };
    }
    const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    const digest = await c.subtle.digest('SHA-256', view);
    const hex = bytesToHex(new Uint8Array(digest));
    return {
      ok: true,
      fingerprint: {
        fileName: name || '',
        sizeBytes: total,
        mimeType: mimeType || '',
        lastModified: typeof lastModified === 'number' ? lastModified : null,
        checksum: 'sha256:' + hex,
      },
    };
  })();
  return {
    handle: {
      cancel() { cancelled = true; },
      onProgress() {},
      result() { return out; },
    },
  };
}

function startSyncVerify({ name, mimeType, sizeBytes, lastModified, buffer, expected, onProgress }) {
  let cancelled = false;
  const out = (async () => {
    if (cancelled) return { ok: false, reason: REASONS.CANCELLED };
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer || []);
    const c = (typeof globalThis !== 'undefined' && globalThis.crypto) || null;
    if (!c || !c.subtle || typeof c.subtle.digest !== 'function') {
      return { ok: false, reason: REASONS.WORKER_UNAVAILABLE };
    }
    const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    const digest = await c.subtle.digest('SHA-256', view);
    const hex = bytesToHex(new Uint8Array(digest));
    const got = 'sha256:' + hex;
    return { ok: true, verifyOutcome: got === expected ? 'matches' : 'differs' };
  })();
  return {
    handle: {
      cancel() { cancelled = true; },
      onProgress() {},
      result() { return out; },
    },
  };
}

function bytesToHex(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    out += (bytes[i] >>> 4).toString(16);
    out += (bytes[i] & 0xf).toString(16);
  }
  return out;
}

export { REASONS, MAX_FILE_BYTES };
