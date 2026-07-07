/**
 * FIRST EPSS (Exploit Prediction Scoring System) — live provider.
 *
 * Endpoint:
 *   https://api.first.org/data/v1/epss?cve=CVE-XXXX-NNNN,CVE-XXXX-NNNN,...
 *
 * FIRST's API is public, CORS-enabled, and supports a comma-separated
 * `cve` query parameter for batch lookups. We don't fabricate EPSS
 * scores for CVEs that aren't in the FIRST response — those records
 * keep `epssProbability: 0` (and the UI surfaces "EPSS: unavailable"
 * if the whole fetch failed).
 *
 * Strategy:
 *   - The CISA KEV catalog has ~1000 entries; a single URL with all
 *     CVEs joined by commas would be ~16 KB and exceed most browser
 *     URL limits. We chunk at CHUNK_SIZE CVEs per request.
 *   - All chunks are fetched in parallel.
 *   - A chunk fetch can fail individually without taking the whole
 *     merge down — partial results are kept. The service layer
 *     decides whether the overall fetch is "first" (all chunks ok)
 *     or "unavailable" (any chunk failed OR the whole batch errored).
 */
import type { Vulnerability } from '../../types/vulnerability';

const EPSS_BASE_URL = 'https://api.first.org/data/v1/epss';
const CHUNK_SIZE = 100;
const FETCH_TIMEOUT_MS = 8_000;

export interface EpssScore {
  /** Probability 0..1 (FIRST returns a string; we parse it). */
  epss: number;
  /** Percentile 0..1 — kept for future "top X% most likely" features. */
  percentile: number;
}

/** Shape of one record inside FIRST's `data` array. */
interface FirstEpssRecord {
  cve: string;
  epss: string;
  percentile: string;
}

/** Top-level shape of the FIRST EPSS response. */
interface FirstEpssResponse {
  status?: string;
  status_code?: number;
  version?: string;
  total?: number;
  data?: FirstEpssRecord[];
}

/** Empty / absent EPSS result. */
const EMPTY_EPSS_MAP: ReadonlyMap<string, EpssScore> = new Map();

/**
 * Look up EPSS scores for a list of CVE IDs. Returns a Map from
 * `cveId` to `{ epss, percentile }`. CVE IDs that aren't present
 * in FIRST's response (e.g. very recent CVEs not yet scored) are
 * simply absent from the map — the caller leaves their
 * `epssProbability` at `0` rather than fabricating a value.
 *
 * Throws on network error, abort, non-2xx, or shape mismatch. The
 * service layer catches and surfaces `epssStatus: 'unavailable'`.
 */
export async function fetchEpssForCves(
  cveIds: string[]
): Promise<Map<string, EpssScore>> {
  if (cveIds.length === 0) return new Map(EMPTY_EPSS_MAP);

  const uniqueCves = Array.from(new Set(cveIds.map((c) => c.trim()).filter(Boolean)));
  if (uniqueCves.length === 0) return new Map(EMPTY_EPSS_MAP);

  const chunks: string[][] = [];
  for (let i = 0; i < uniqueCves.length; i += CHUNK_SIZE) {
    chunks.push(uniqueCves.slice(i, i + CHUNK_SIZE));
  }

  const results = await Promise.allSettled(chunks.map((chunk) => fetchOneChunk(chunk)));

  const merged = new Map<string, EpssScore>();
  let allOk = true;
  for (const r of results) {
    if (r.status === 'rejected') {
      allOk = false;
      continue;
    }
    for (const [cve, score] of r.value) {
      merged.set(cve, score);
    }
  }

  if (!allOk && merged.size === 0) {
    // Total failure: every chunk rejected. Throw so the service
    // layer can set epssStatus to 'unavailable' with the reason.
    const reasons = results
      .filter((r): r is PromiseRejectedResult => r.status === 'rejected')
      .map((r) => (r.reason instanceof Error ? r.reason.message : String(r.reason)))
      .join('; ');
    throw new Error(`FIRST EPSS fetch failed for all ${chunks.length} chunk(s): ${reasons}`);
  }

  return merged;
}

/* ------------------------------------------------------------------ */
/* Internals                                                          */
/* ------------------------------------------------------------------ */

async function fetchOneChunk(cveChunk: string[]): Promise<Map<string, EpssScore>> {
  const url = `${EPSS_BASE_URL}?cve=${encodeURIComponent(cveChunk.join(','))}`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

  try {
    const response = await fetch(url, {
      signal: controller.signal,
      headers: { Accept: 'application/json' },
      cache: 'no-store',
    });
    if (!response.ok) {
      throw new Error(
        `FIRST EPSS chunk fetch failed: HTTP ${response.status} ${response.statusText}`
      );
    }
    const body = (await response.json()) as FirstEpssResponse;
    if (!body || !Array.isArray(body.data)) {
      throw new Error('FIRST EPSS response has unexpected shape (no data array)');
    }
    return new Map(body.data.map(parseEpssRecord));
  } finally {
    clearTimeout(timer);
  }
}

function parseEpssRecord(rec: FirstEpssRecord): [string, EpssScore] {
  const epss = parseProbability(rec.epss);
  const percentile = parseProbability(rec.percentile);
  return [rec.cve, { epss, percentile }];
}

/** Parse a FIRST API probability string. Falls back to 0 on bad input. */
function parseProbability(raw: string | undefined): number {
  if (raw == null) return 0;
  const n = Number.parseFloat(raw);
  if (Number.isNaN(n)) return 0;
  // Clamp to [0, 1] — defensive against FIRST ever returning garbage.
  if (n < 0) return 0;
  if (n > 1) return 1;
  return n;
}

/**
 * Apply an EPSS map to a list of CISA-normalized Vulnerability records.
 * Returns a NEW array (the input is not mutated) with `epssProbability`
 * set from the map when a match exists. Records whose CVE is absent
 * from the EPSS response keep `epssProbability: 0`.
 *
 * This is the single place we hand EPSS data into the CISA records.
 * Pure function — easy to test.
 */
export function enrichWithEpss(
  records: Vulnerability[],
  epssMap: ReadonlyMap<string, EpssScore>
): Vulnerability[] {
  return records.map((v) => {
    const score = epssMap.get(v.cveId);
    if (!score) return v; // No EPSS data for this CVE — leave at 0.
    return { ...v, epssProbability: score.epss };
  });
}
