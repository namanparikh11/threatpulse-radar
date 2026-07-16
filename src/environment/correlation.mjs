/**
 * V6.6 — Local-vs-public correlation engine.
 *
 * STUB — full implementation lands in commit 3. The
 * stub exposes the same public API so the worker
 * dispatcher can wire through end-to-end.
 *
 * The full engine will:
 *   1. For each local component, build a deterministic
 *      identity key (purl / ecosystem+name+version).
 *   2. For each public CVE with OSV or GitHub
 *      Advisory context, check whether any local
 *      component identity matches the provider
 *      package list.
 *   3. Evaluate the version against the provider's
 *      range using the documented evaluator registry.
 *   4. Emit a `Correlation` record per (asset, CVE)
 *      pair with one of the six documented states.
 */

import { CORRELATION_SCHEMA_VERSION } from './schema.mjs';

/** Build correlations. The current implementation
 *  is a stub that returns an empty list. Commit 3
 *  replaces this with the full engine. */
export function buildCorrelations({ components, publicVulns, publicMeta, assetId, inventoryId, onProgress }) {
  if (typeof onProgress === 'function') {
    try { onProgress((publicVulns || []).length); } catch { /* ignore */ }
  }
  return Object.freeze([]);
}

export { CORRELATION_SCHEMA_VERSION };
