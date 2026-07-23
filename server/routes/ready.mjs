/**
 * V6.2 — portable HTTP route: /ready
 *
 * Readiness probe. Returns 200 when the storage backend
 * is reachable and a `latest-dataset` blob is present;
 * 503 otherwise. The probe does NOT call any upstream
 * provider; it only verifies the storage adapter is
 * functional.
 */

import { readLatestDataset } from '../../netlify/functions/_shared/store.mjs';

export async function handleReady({ config }) {
  const datasetStore = config.storage('tpr-dataset');
  try {
    const env = await readLatestDataset(datasetStore);
    if (!env || typeof env !== 'object') {
      return jsonResponse(503, { ready: false, reason: 'no-dataset-envelope' });
    }
    return jsonResponse(200, { ready: true, fetchedAt: env.fetchedAt || null });
  } catch (err) {
    return jsonResponse(503, { ready: false, reason: err && err.message ? err.message : String(err) });
  }
}

function jsonResponse(status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
    },
  });
}
