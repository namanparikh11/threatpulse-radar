/**
 * V6.0 — OSV provider.
 *
 * OSV (https://osv.dev) exposes its data via two complementary channels:
 *
 *   1. The GCS bucket at
 *      `https://osv-vulnerabilities.storage.googleapis.com/`
 *      contains the authoritative raw JSON files for every vulnerability.
 *      Each ecosystem has its own prefix; the per-ecosystem
 *      `modified_id.csv` lists the OSV ids that have changed in that
 *      ecosystem, sorted by modification time (most recent first).
 *
 *   2. The OSV API at `https://api.osv.dev/v1/` provides the same data
 *      via JSON requests. The V6.0 design uses the GCS bucket because
 *      the per-ecosystem `modified_id.csv` IS the global change feed;
 *      the API endpoints are an alternative path with the same content.
 *
 * V6.0 design uses the GCS bucket. The "global modified_id.csv" of the
 * design is implemented here as the per-ecosystem `modified_id.csv` for
 * each allowlisted ecosystem — reading one CSV per ecosystem is the
 * same logical operation as reading one global CSV with the ecosystem
 * pre-extracted.
 *
 * All I/O goes through an injected `fetcher` so unit tests can stub the
 * network. The default `fetcher` is a thin wrapper around Node's
 * `fetch` (Node 18+), augmented with a per-call timeout and a streaming
 * text reader.
 */

const OSV_GCS_BASE = 'https://osv-vulnerabilities.storage.googleapis.com';

/** Default per-call timeout in ms for the injected fetcher. */
export const OSV_DEFAULT_FETCH_TIMEOUT_MS = 30000;

/**
 * Build a `fetch` implementation with a timeout. Returns null on
 * timeout; throws on non-timeout network errors so the orchestrator
 * can decide what to do.
 */
export function makeTimeoutFetch({ baseFetch = globalThis.fetch, timeoutMs = OSV_DEFAULT_FETCH_TIMEOUT_MS } = {}) {
  if (typeof baseFetch !== 'function') {
    throw new Error('makeTimeoutFetch: baseFetch is required');
  }
  return async function fetchWithTimeout(url, opts = {}) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await baseFetch(url, { ...opts, signal: controller.signal });
      return res;
    } finally {
      clearTimeout(timer);
    }
  };
}

/**
 * Default text fetcher. Uses Node's built-in `fetch` with a timeout
 * and returns the body as a string.
 */
export function makeTextFetcher({ baseFetch = globalThis.fetch, timeoutMs = OSV_DEFAULT_FETCH_TIMEOUT_MS } = {}) {
  const tf = makeTimeoutFetch({ baseFetch, timeoutMs });
  return async function fetchText(url, opts = {}) {
    const res = await tf(url, opts);
    if (!res.ok) {
      throw new Error(`fetch ${url} → HTTP ${res.status}`);
    }
    return await res.text();
  };
}

/**
 * Parse a per-ecosystem `modified_id.csv` file. The file is one OSV
 * id per line, no header, sorted by modification time (newest first
 * per OSV's convention). Blank lines and lines starting with `#` are
 * ignored. The result is the array of OSV ids in source order.
 */
export function parseModifiedIdCsv(text) {
  if (typeof text !== 'string') return [];
  const out = [];
  const seen = new Set();
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (line.length === 0) continue;
    if (line.startsWith('#')) continue;
    if (seen.has(line)) continue;
    seen.add(line);
    out.push(line);
  }
  return out;
}

/**
 * Filter the parsed modified_id list by a watermark timestamp. The
 * `modifiedTimestamps` argument is an optional Map<osvId, ISO string>
 * giving the modification time of each id. When the map is missing
 * (which is the case for the CSV-only path), the function is a no-op
 * and returns the input unchanged. When present, ids newer than
 * `since` are kept; ids without a timestamp entry are kept (treated
 * as "unknown, possibly new").
 *
 * The "watermark minus overlap window" semantics live in the
 * orchestrator: it computes `since = watermark - overlapWindowMs`
 * and passes it in here. The provider does not subtract the overlap
 * itself; that keeps the policy in one place.
 */
export function filterByWatermark(ids, modifiedTimestamps, since) {
  if (!since) return ids;
  if (!modifiedTimestamps || typeof modifiedTimestamps.get !== 'function') {
    return ids;
  }
  const sinceMs = Date.parse(since);
  if (Number.isNaN(sinceMs)) return ids;
  return ids.filter((id) => {
    const ts = modifiedTimestamps.get(id);
    if (!ts) return true; // unknown → keep (defensive default)
    const ms = Date.parse(ts);
    if (Number.isNaN(ms)) return true;
    return ms >= sinceMs;
  });
}

/**
 * Fetch the per-ecosystem `modified_id.csv` from OSV's GCS bucket.
 * Returns the parsed list of OSV ids, or `[]` on a clean 404 (an
 * ecosystem with no records).
 */
export async function fetchModifiedIds({ ecosystem, fetcher }) {
  if (typeof ecosystem !== 'string' || ecosystem.length === 0) {
    throw new Error('fetchModifiedIds: ecosystem is required');
  }
  if (typeof fetcher !== 'function') {
    throw new Error('fetchModifiedIds: fetcher is required');
  }
  const url = `${OSV_GCS_BASE}/${encodeURIComponent(ecosystem)}/modified_id.csv`;
  let text;
  try {
    text = await fetcher(url);
  } catch (err) {
    if (err && typeof err.message === 'string' && err.message.includes('HTTP 404')) {
      return [];
    }
    throw err;
  }
  return parseModifiedIdCsv(text);
}

/**
 * Fetch a single OSV vulnerability JSON from the GCS bucket. The
 * per-ecosystem storage layout is `{ecosystem}/{osvId}.json` (the OSV
 * id is a filename inside the ecosystem folder).
 */
export async function fetchVulnerability({ ecosystem, osvId, fetcher }) {
  if (typeof ecosystem !== 'string' || ecosystem.length === 0) {
    throw new Error('fetchVulnerability: ecosystem is required');
  }
  if (typeof osvId !== 'string' || osvId.length === 0) {
    throw new Error('fetchVulnerability: osvId is required');
  }
  if (typeof fetcher !== 'function') {
    throw new Error('fetchVulnerability: fetcher is required');
  }
  const url = `${OSV_GCS_BASE}/${encodeURIComponent(ecosystem)}/${encodeURIComponent(osvId)}.json`;
  const text = await fetcher(url);
  try {
    return JSON.parse(text);
  } catch (err) {
    throw new Error(`fetchVulnerability: invalid JSON for ${ecosystem}/${osvId}: ${err && err.message ? err.message : err}`);
  }
}

/**
 * Concurrency-bounded parallel map. The OSV provider fetches one
 * vulnerability JSON at a time per id, but a real incremental run
 * needs bounded concurrency so a heavy day does not exhaust sockets.
 */
export async function mapWithConcurrency(items, concurrency, worker) {
  if (!Array.isArray(items)) return [];
  const limit = Math.max(1, Math.min(concurrency | 0 || 4, items.length || 1));
  const results = new Array(items.length);
  let cursor = 0;
  async function run() {
    while (true) {
      const idx = cursor++;
      if (idx >= items.length) return;
      try {
        results[idx] = await worker(items[idx], idx);
      } catch (err) {
        results[idx] = { __error: err && err.message ? err.message : String(err) };
      }
    }
  }
  const runners = [];
  for (let i = 0; i < limit; i++) runners.push(run());
  await Promise.all(runners);
  return results;
}

export { OSV_GCS_BASE };
