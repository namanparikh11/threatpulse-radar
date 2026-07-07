/**
 * NVD CVE 2.0 — live provider.
 *
 * Endpoint:
 *   https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-XXXX-NNNN,...
 *
 * NVD's API is public, CORS-enabled, and supports a comma-separated
 * `cveId` query parameter for batch lookups. We do NOT fabricate
 * CVSS scores for CVEs that aren't in the NVD response — those
 * records keep `cvssScore: 0` and the UI surfaces "NVD: unavailable"
 * if the whole fetch failed.
 *
 * Rate limit (per NVD's docs): 5 requests / 30 s without an API
 * key. With ~1000 CISA CVEs / 100 per chunk = 10 requests, the
 * first load can take a minute. Each chunk is sent in parallel
 * with its own 8 s AbortController timeout so a slow / blocked
 * response can't hang the dashboard — the service layer catches
 * and falls through.
 *
 * Strategy:
 *   - Chunk at CHUNK_SIZE CVEs per request (URL length safety).
 *   - All chunks are fetched in parallel via Promise.allSettled.
 *   - A chunk can fail individually without taking the whole
 *     merge down — partial results are kept. The service layer
 *     decides whether the overall fetch is "nvd" (all chunks ok)
 *     or "unavailable" (any chunk failed OR the whole batch
 *     errored).
 *
 * Severity extraction prefers CVSS v3.1, then v3.0, then v2.
 * For v2 metrics, severity is derived from the baseScore using
 * the standard mapping (>= 9 Critical, >= 7 High, >= 4 Medium,
 * else Low) — NVD's v2 responses don't always carry a
 * `baseSeverity` string.
 */
import type { Severity, Vulnerability } from '../../types/vulnerability';

const NVD_BASE_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const CHUNK_SIZE = 100;
const FETCH_TIMEOUT_MS = 8_000;

export interface NvdScore {
  /** 0.0 - 10.0 (NVD's CVSS base score). */
  cvssScore: number;
  /** Severity derived from NVD's baseSeverity or from the score. */
  severity: Severity;
}

/** Shape of one `vulnerabilities[i]` item in NVD's response. */
interface NvdVulnerabilityItem {
  cve?: {
    id?: string;
    metrics?: NvdMetrics;
  };
}

/** Shape of one CVSS metric object inside `metrics.cvssMetricVxx`. */
interface NvdMetric {
  cvssData?: {
    baseScore?: number;
    baseSeverity?: string;
  };
}

/** Shape of `cve.metrics`. */
interface NvdMetrics {
  cvssMetricV31?: NvdMetric[];
  cvssMetricV30?: NvdMetric[];
  cvssMetricV2?: NvdMetric[];
}

/** Top-level shape of the NVD CVE 2.0 response. */
interface NvdFeed {
  totalResults?: number;
  resultsPerPage?: number;
  startIndex?: number;
  vulnerabilities?: NvdVulnerabilityItem[];
}

/* ------------------------------------------------------------------ */
/* Fetch + parse                                                      */
/* ------------------------------------------------------------------ */

const EMPTY_NVD_MAP: ReadonlyMap<string, NvdScore> = new Map();

/**
 * Look up CVSS scores for a list of CVE IDs. Returns a Map from
 * `cveId` to `{ cvssScore, severity }`. CVE IDs that aren't
 * present in NVD's response (e.g. reserved / not-yet-published
 * CVEs) are simply absent from the map — the caller leaves
 * their `cvssScore: 0`.
 *
 * Throws on network error, abort, non-2xx, or shape mismatch. The
 * service layer catches and surfaces `nvdStatus: 'unavailable'`.
 */
export async function fetchNvdForCves(
  cveIds: string[]
): Promise<Map<string, NvdScore>> {
  if (cveIds.length === 0) return new Map(EMPTY_NVD_MAP);

  const uniqueCves = Array.from(new Set(cveIds.map((c) => c.trim()).filter(Boolean)));
  if (uniqueCves.length === 0) return new Map(EMPTY_NVD_MAP);

  const chunks: string[][] = [];
  for (let i = 0; i < uniqueCves.length; i += CHUNK_SIZE) {
    chunks.push(uniqueCves.slice(i, i + CHUNK_SIZE));
  }

  const results = await Promise.allSettled(chunks.map((chunk) => fetchOneChunk(chunk)));

  const merged = new Map<string, NvdScore>();
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
    // layer can set nvdStatus to 'unavailable' with the reason.
    const reasons = results
      .filter((r): r is PromiseRejectedResult => r.status === 'rejected')
      .map((r) => (r.reason instanceof Error ? r.reason.message : String(r.reason)))
      .join('; ');
    throw new Error(`NVD fetch failed for all ${chunks.length} chunk(s): ${reasons}`);
  }

  return merged;
}

async function fetchOneChunk(cveChunk: string[]): Promise<Map<string, NvdScore>> {
  const url = `${NVD_BASE_URL}?cveId=${encodeURIComponent(cveChunk.join(','))}`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

  try {
    const response = await fetch(url, {
      signal: controller.signal,
      headers: { Accept: 'application/json' },
      cache: 'no-store',
    });
    if (!response.ok) {
      throw new Error(`NVD chunk fetch failed: HTTP ${response.status} ${response.statusText}`);
    }
    const body = (await response.json()) as NvdFeed;
    if (!body || !Array.isArray(body.vulnerabilities)) {
      throw new Error('NVD response has unexpected shape (no vulnerabilities array)');
    }
    return new Map(body.vulnerabilities.map(parseNvdItem).filter((x): x is [string, NvdScore] => x !== null));
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Parse a single `vulnerabilities[i]` item. Returns `null` if the
 * item has no usable CVE id (NVD occasionally returns placeholder
 * records) or no CVSS metrics.
 */
export function parseNvdItem(item: NvdVulnerabilityItem): [string, NvdScore] | null {
  const cveId = (item.cve?.id ?? '').trim();
  if (!cveId) return null;
  const score = pickNvdScore(item.cve?.metrics);
  if (score === null) return null;
  return [cveId, score];
}

/**
 * Pick the best CVSS score from an NVD metrics block. Prefers
 * v3.1 (Primary), then v3.0, then v2. Returns `null` if no
 * metrics carry a base score.
 */
export function pickNvdScore(metrics: NvdMetrics | undefined | null): NvdScore | null {
  if (!metrics) return null;
  const v31 = metrics.cvssMetricV31?.[0]?.cvssData;
  if (v31 && typeof v31.baseScore === 'number') {
    return {
      cvssScore: clampCvss(v31.baseScore),
      severity: severityFromNvdBase(v31.baseSeverity, v31.baseScore),
    };
  }
  const v30 = metrics.cvssMetricV30?.[0]?.cvssData;
  if (v30 && typeof v30.baseScore === 'number') {
    return {
      cvssScore: clampCvss(v30.baseScore),
      severity: severityFromNvdBase(v30.baseSeverity, v30.baseScore),
    };
  }
  const v2 = metrics.cvssMetricV2?.[0]?.cvssData;
  if (v2 && typeof v2.baseScore === 'number') {
    return {
      cvssScore: clampCvss(v2.baseScore),
      // v2 responses don't always carry baseSeverity — derive from score.
      severity: severityFromNvdBase(v2.baseSeverity, v2.baseScore),
    };
  }
  return null;
}

/** NVD's baseSeverity comes upper-case ("CRITICAL"). Normalize. */
export function severityFromNvdBase(
  baseSeverity: string | undefined,
  baseScore: number
): Severity {
  switch ((baseSeverity ?? '').toUpperCase()) {
    case 'CRITICAL':
      return 'Critical';
    case 'HIGH':
      return 'High';
    case 'MEDIUM':
      return 'Medium';
    case 'LOW':
      return 'Low';
  }
  // Fallback: derive from score (handles v2 responses without
  // baseSeverity, and any future NVD-shape drift).
  if (baseScore >= 9.0) return 'Critical';
  if (baseScore >= 7.0) return 'High';
  if (baseScore >= 4.0) return 'Medium';
  return 'Low';
}

/** Clamp to the valid CVSS range. Defensive — NVD has been known to return edge values. */
function clampCvss(score: number): number {
  if (Number.isNaN(score)) return 0;
  if (score < 0) return 0;
  if (score > 10) return 10;
  return score;
}

/* ------------------------------------------------------------------ */
/* Enrichment                                                         */
/* ------------------------------------------------------------------ */

/**
 * Apply an NVD map to a list of (already-CISA-normalized) records.
 * Returns a NEW array (the input is not mutated) with `cvssScore`
 * and `severity` overridden from the NVD record when a match
 * exists. Records whose CVE is absent from the NVD response
 * keep their existing CISA-derived values.
 *
 * The NVD severity takes precedence over the CISA-derived
 * severity because NVD's base score is a direct measurement
 * (data-driven) while CISA's severity was a policy
 * decision (KEV records are "at least High"). When NVD is
 * present, the user sees the actual score.
 *
 * Pure function — easy to test.
 */
export function enrichWithNvd(
  records: Vulnerability[],
  nvdMap: ReadonlyMap<string, NvdScore>
): Vulnerability[] {
  return records.map((v) => {
    const score = nvdMap.get(v.cveId);
    if (!score) return v;
    return { ...v, cvssScore: score.cvssScore, severity: score.severity };
  });
}
