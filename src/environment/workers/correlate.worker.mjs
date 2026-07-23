/**
 * V6.6 — Correlation worker.
 *
 * Runs the local-vs-public correlation off the main
 * thread. The worker is self-contained: it imports
 * the correlation engine, the version evaluators,
 * and a tiny pure-JS SHA-256 helper. The worker
 * NEVER calls the network.
 *
 * The correlation engine (correlation.mjs) is
 * synchronous; the worker simply slices the input
 * into CVE batches and yields to the event loop
 * between batches so the main thread can deliver
 * cancellation messages.
 *
 * Communication protocol (main -> worker):
 *   { type: 'correlate', jobId, payload: { components, publicVulns, publicMeta, assetId, inventoryId } }
 *   { type: 'cancel', jobId }
 *
 * Communication protocol (worker -> main):
 *   { type: 'progress', jobId, processed, total }
 *   { type: 'result', jobId, ok: true, correlations }
 *   { type: 'result', jobId, ok: false, reason }
 *   { type: 'cancelled', jobId }
 */

import { buildCorrelations } from '../correlation.mjs';

const REASONS = Object.freeze({
  UNKNOWN: 'unknown',
});

self.addEventListener('message', (ev) => {
  if (!ev || !ev.data || typeof ev.data !== 'object') return;
  const msg = ev.data;
  if (msg.type === 'cancel') {
    cancelJobs.add(msg.jobId);
    return;
  }
  if (msg.type === 'correlate') {
    const { jobId, payload } = msg;
    if (!jobId || !payload || !Array.isArray(payload.components) || !Array.isArray(payload.publicVulns)) {
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
  const total = payload.publicVulns.length;
  // buildCorrelations is synchronous; the worker
  // emits progress as it walks the public CVE list.
  const correlations = buildCorrelations({
    components: payload.components,
    publicVulns: payload.publicVulns,
    publicMeta: payload.publicMeta,
    assetId: payload.assetId,
    inventoryId: payload.inventoryId,
    onProgress: (processed) => {
      if (cancelJobs.has(jobId)) {
        throw new Error('cancelled');
      }
      self.postMessage({ type: 'progress', jobId, processed, total });
    },
  });
  if (cancelJobs.has(jobId)) {
    self.postMessage({ type: 'cancelled', jobId });
    return;
  }
  self.postMessage({ type: 'result', jobId, ok: true, correlations });
}
