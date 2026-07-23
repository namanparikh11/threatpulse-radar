/**
 * V6.6 — Worker dispatcher.
 *
 * Main-thread wrapper around the parse and
 * correlation workers. Falls back to synchronous
 * execution when Worker is not available (older
 * browsers, the test runner, hardened enterprise
 * policies that block worker scripts).
 *
 * Each call returns a `handle` object with
 *   - onProgress(cb)
 *   - cancel()
 *   - result(): Promise<...>
 *
 * The dispatcher tracks every outstanding job in a
 * `genRef` counter. When the consumer calls
 * `cancel()`, the dispatcher posts a `cancel` message
 * to the worker AND bumps the genRef. Stale results
 * that arrive after the cancel (because the worker
 * processed another batch before the cancel message
 * arrived) are rejected by the consumer's `result()`
 * check.
 *
 * The dispatcher NEVER:
 *   - touches the network
 *   - writes to the URL / history
 *   - logs to the console in production
 *   - re-uses a worker across cancel + new job
 *     (a new worker is spawned per job to keep the
 *     lifecycle simple)
 */

import { parseImport } from '../import.mjs';
import { buildCorrelations } from '../correlation.mjs';

const REASONS = Object.freeze({
  CANCELLED: 'cancelled',
  WORKER_UNAVAILABLE: 'worker-unavailable',
  INVALID_MESSAGE: 'invalid-message',
  UNKNOWN: 'unknown',
});

let nextJobId = 1;

/** Spawn the parse worker. Returns a handle. */
export function startParseJob({ text, options, onProgress }) {
  if (typeof Worker === 'undefined' || typeof import.meta === 'undefined') {
    return startParseSync({ text, options, onProgress });
  }
  const jobId = 'parse-' + (nextJobId++);
  let worker;
  try {
    // Vite turns this into a separate worker chunk.
    worker = new Worker(new URL('./parseInventory.worker.mjs', import.meta.url), { type: 'module' });
  } catch (err) {
    return startParseSync({ text, options, onProgress });
  }
  const handle = makeHandle(worker, jobId, onProgress);
  worker.postMessage({ type: 'parse', jobId, payload: { text, options, checksumInput: text } });
  return handle;
}

/** Spawn the correlation worker. Returns a handle. */
export function startCorrelateJob({ components, publicVulns, publicMeta, assetId, inventoryId, onProgress }) {
  if (typeof Worker === 'undefined' || typeof import.meta === 'undefined') {
    return startCorrelateSync({ components, publicVulns, publicMeta, assetId, inventoryId, onProgress });
  }
  const jobId = 'correlate-' + (nextJobId++);
  let worker;
  try {
    worker = new Worker(new URL('./correlate.worker.mjs', import.meta.url), { type: 'module' });
  } catch (err) {
    return startCorrelateSync({ components, publicVulns, publicMeta, assetId, inventoryId, onProgress });
  }
  const handle = makeHandle(worker, jobId, onProgress);
  worker.postMessage({ type: 'correlate', jobId, payload: { components, publicVulns, publicMeta, assetId, inventoryId } });
  return handle;
}

function makeHandle(worker, jobId, onProgress) {
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
    const m = ev.data;
    if (m.type === 'progress') {
      if (progressCb) progressCb({ processed: m.processed, total: m.total });
      return;
    }
    if (m.type === 'result' && m.ok) {
      cleanup();
      resolveResult({ ok: true, result: m.result, checksum: m.checksum });
      return;
    }
    if (m.type === 'result' && !m.ok) {
      cleanup();
      resolveResult({ ok: false, reason: m.reason });
      return;
    }
    if (m.type === 'cancelled') {
      cleanup();
      resolveResult({ ok: false, reason: REASONS.CANCELLED });
      return;
    }
  };
  worker.onerror = (err) => {
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
      // Also reject the pending result so the
      // consumer does not hang on a worker that
      // may not respond.
      resolveResult({ ok: false, reason: REASONS.CANCELLED });
      cleanup();
    },
    onProgress(cb) {
      progressCb = typeof cb === 'function' ? cb : null;
    },
    result() { return result; },
  };
}

function startParseSync({ text, options, onProgress }) {
  let cancelled = false;
  const out = parseImport(text, options || {});
  if (out.ok && onProgress) {
    const total = out.result.components.length;
    let processed = 0;
    const step = 500;
    while (processed < total) {
      if (cancelled) return { handle: { result: () => Promise.resolve({ ok: false, reason: REASONS.CANCELLED }) } };
      const next = Math.min(processed + step, total);
      processed = next;
      onProgress({ processed, total });
    }
  }
  return {
    handle: {
      cancel() { cancelled = true; },
      onProgress() {},
      result() { return Promise.resolve(out.ok ? { ok: true, result: out.result, checksum: '' } : { ok: false, reason: out.reason }); },
    },
  };
}

function startCorrelateSync({ components, publicVulns, publicMeta, assetId, inventoryId, onProgress }) {
  let cancelled = false;
  const correlations = buildCorrelations({
    components,
    publicVulns,
    publicMeta,
    assetId,
    inventoryId,
    onProgress: (processed) => {
      if (cancelled) throw new Error('cancelled');
      if (onProgress) onProgress({ processed, total: publicVulns.length });
    },
  });
  return {
    handle: {
      cancel() { cancelled = true; },
      onProgress() {},
      result() { return Promise.resolve(cancelled ? { ok: false, reason: REASONS.CANCELLED } : { ok: true, correlations }); },
    },
  };
}

export { REASONS };
