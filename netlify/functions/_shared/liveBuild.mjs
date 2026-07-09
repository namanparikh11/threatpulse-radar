/**
 * Shared CISA → NVD → FIRST EPSS live-build pipeline for v5.2.
 *
 * Extracted from the v5.0 / v5.0.1 / v5.0.2 / v5.0.3 dataset
 * function so it can be called from THREE places without
 * duplicating the upstream-fetch logic:
 *
 *   1. `dataset.mjs` — on the "no prebuilt blob yet" bootstrap
 *      path (first visitor / fresh deploy).
 *   2. `refresh-dataset-background.mjs` — on manual refresh.
 *   3. `refresh-dataset-scheduled.mjs` — on the cron tick.
 *
 * The function shape and field-mapping rules are byte-identical
 * to v5.0.3 so the existing acceptance-proxy suite keeps
 * passing without modification.
 *
 * IMPORTANT: this module has NO Netlify-Blobs dependencies. It
 * only knows how to talk to CISA / NVD / FIRST. The lock +
 * blob-write is the refresh orchestrator's job, not this
 * module's.
 */

// ---------------------------------------------------------------------------
// Public upstream URLs (same constants as the v5.0 dataset function).
// ---------------------------------------------------------------------------

export const CISA_KEV_URL =
  'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
export const NVD_BASE_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
export const EPSS_BASE_URL = 'https://api.first.org/data/v1/epss';

// ---------------------------------------------------------------------------
// Tuning. Matches the v5.0 / v5.0.2 / v5.0.3 dataset function exactly.
// ---------------------------------------------------------------------------

export const CHUNK_SIZE = 100;
export const PER_REQUEST_TIMEOUT_MS = 8_000;
export const OVERALL_BUDGET_MS = 24_000;

// ---------------------------------------------------------------------------
// Upstream payload shapes (only the fields we read).
// ---------------------------------------------------------------------------

/** @typedef {{ cveID: string, vendorProject?: string, product?: string, vulnerabilityName?: string, dateAdded?: string, shortDescription?: string, requiredAction?: string, knownRansomwareCampaignUse?: 'Known'|'Unknown' }} CisaRecord */
/** @typedef {{ cve?: { id?: string, metrics?: NvdMetrics } }} NvdItem */
/** @typedef {{ cvssData?: { baseScore?: number, baseSeverity?: string } }} NvdMetric */
/** @typedef {{ cvssMetricV31?: NvdMetric[], cvssMetricV30?: NvdMetric[], cvssMetricV2?: NvdMetric[] }} NvdMetrics */
/** @typedef {{ cve: string, epss: string, percentile: string }} EpssRecord */

// ---------------------------------------------------------------------------
// Entry point. Returns the FetchResult-shaped envelope.
// Throws on CISA failure (the only gating upstream). NVD and
// EPSS failures are captured in the envelope as
// nvdStatus/epssStatus.
// ---------------------------------------------------------------------------

/**
 * @param {object} [opts]
 * @param {number} [opts.startTime] Override the function's clock
 *   (used by the bootstrap path to keep `fetchedAt` consistent
 *   with the request that started the bootstrap).
 */
export async function buildLiveDataset(opts = {}) {
  const overallStart = opts.startTime ?? Date.now();

  // ---- 1. CISA KEV (gating) ----
  let cisaRecords;
  try {
    cisaRecords = await fetchCisaKev();
  } catch (err) {
    const e = new Error(
      err instanceof Error
        ? `CISA KEV fetch failed: ${err.message}`
        : 'CISA KEV fetch failed: unknown error.',
    );
    e.cause = err;
    throw e;
  }

  // ---- 2. NVD + EPSS in parallel (best-effort) ----
  const cveIds = cisaRecords.map((r) => r.cveId);
  const budgetRemaining = () =>
    Math.max(1_000, OVERALL_BUDGET_MS - (Date.now() - overallStart));

  const [nvdResult, epssResult] = await Promise.all([
    safeEnrich('NVD', () => fetchNvdForCves(cveIds), budgetRemaining()),
    safeEnrich('EPSS', () => fetchEpssForCves(cveIds), budgetRemaining()),
  ]);

  // ---- 3. Enrich in the same order as the browser-side code (NVD then EPSS) ----
  const enriched = enrichWithEpss(
    enrichWithNvd(cisaRecords, nvdResult.map),
    epssResult.map,
  );

  return {
    data: enriched,
    source: 'merged',
    fetchedAt: new Date().toISOString(),
    mode: 'live',
    nvdStatus: nvdResult.status,
    nvdReason: nvdResult.reason,
    epssStatus: epssResult.status,
    epssReason: epssResult.reason,
  };
}

// ---------------------------------------------------------------------------
// "Run this enricher but never let it take the whole build down."
// ---------------------------------------------------------------------------

async function safeEnrich(label, fn, budgetMs) {
  const start = Date.now();
  try {
    const map = await withTimeout(fn(), budgetMs, `${label} timed out`);
    return { map, status: label === 'NVD' ? 'nvd' : 'first', reason: undefined };
  } catch (err) {
    return {
      map: new Map(),
      status: 'unavailable',
      reason:
        err instanceof Error
          ? `${label} enrichment failed: ${err.message}`
          : `${label} enrichment failed: unknown error (after ${Date.now() - start} ms)`,
    };
  }
}

function withTimeout(promise, ms, label) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error(`${label} after ${ms} ms`)),
      ms,
    );
    promise.then(
      (v) => {
        clearTimeout(timer);
        resolve(v);
      },
      (e) => {
        clearTimeout(timer);
        reject(e instanceof Error ? e : new Error(String(e)));
      },
    );
  });
}

/**
 * v5.0.2: Run an array of zero-arg async tasks with a hard
 * concurrency limit. Returns a Promise.allSettled-shaped array.
 *   concurrency = 1          → fully serial
 *   concurrency >= tasks.length → fully parallel
 */
async function settledAll(tasks, concurrency) {
  const results = new Array(tasks.length);
  const limit = Math.max(1, Math.min(concurrency, tasks.length));
  let next = 0;
  async function worker() {
    while (true) {
      const i = next++;
      if (i >= tasks.length) return;
      try {
        results[i] = { status: 'fulfilled', value: await tasks[i]() };
      } catch (reason) {
        results[i] = { status: 'rejected', reason };
      }
    }
  }
  const workers = Array.from({ length: limit }, () => worker());
  await Promise.all(workers);
  return results;
}

// ---------------------------------------------------------------------------
// CISA KEV fetch + normalize.
// ---------------------------------------------------------------------------

async function fetchCisaKev() {
  const res = await withTimeout(
    fetch(CISA_KEV_URL, {
      headers: { Accept: 'application/json' },
      cache: 'no-store',
    }),
    PER_REQUEST_TIMEOUT_MS,
    'CISA KEV fetch',
  );
  if (!res.ok) {
    throw new Error(`HTTP ${res.status} ${res.statusText}`);
  }
  const feed = await res.json();
  if (!feed || !Array.isArray(feed.vulnerabilities)) {
    throw new Error('CISA KEV feed has unexpected shape (no vulnerabilities array)');
  }
  return feed.vulnerabilities
    .filter((r) => r && r.cveID)
    .map(normalizeCisaKevRecord);
}

function severityForCisaKev(rec) {
  if (rec.knownRansomwareCampaignUse === 'Known') return 'Critical';
  return 'High';
}

function safeDate(iso) {
  if (!iso) return new Date().toISOString().slice(0, 10);
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return new Date().toISOString().slice(0, 10);
  return d.toISOString().slice(0, 10);
}

function normalizeCisaKevRecord(rec) {
  const cveId = (rec.cveID ?? '').trim();
  const short = (rec.shortDescription ?? '').trim();
  const name = (rec.vulnerabilityName ?? '').trim();
  return {
    id: `kev-${cveId.toLowerCase()}`,
    cveId,
    summary: name || short || cveId,
    description:
      short +
      (short ? ' ' : '') +
      '(CVSS and EPSS are not part of the CISA KEV feed; ' +
      'the dashboard may enrich them from NVD and FIRST EPSS ' +
      'when those services are reachable.)',
    severity: severityForCisaKev(rec),
    cvssScore: 0,
    epssProbability: 0,
    kev: true,
    vendor: (rec.vendorProject ?? '').trim() || 'Unknown',
    product: (rec.product ?? '').trim() || 'Unknown',
    publishedDate: safeDate(rec.dateAdded),
    source: 'CISA KEV',
    recommendedAction:
      (rec.requiredAction ?? '').trim() ||
      'Apply vendor patch per CISA KEV guidance.',
    externalLinks: [
      {
        label: 'CISA KEV',
        url: `https://www.cisa.gov/known-exploited-vulnerabilities-catalog/search?query=${encodeURIComponent(cveId)}`,
      },
      {
        label: 'NVD',
        url: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cveId)}`,
      },
    ],
  };
}

// ---------------------------------------------------------------------------
// NVD batch lookup.
// ---------------------------------------------------------------------------

async function fetchNvdForCves(cveIds) {
  if (cveIds.length === 0) return new Map();
  const uniqueCves = Array.from(
    new Set(cveIds.map((c) => (c ?? '').trim()).filter(Boolean)),
  );
  if (uniqueCves.length === 0) return new Map();

  const chunks = [];
  for (let i = 0; i < uniqueCves.length; i += CHUNK_SIZE) {
    chunks.push(uniqueCves.slice(i, i + CHUNK_SIZE));
  }

  // v5.0.2: server-side only — read once, pass into each chunk.
  // Never sent in the response, never logged.
  const apiKey = process.env.NVD_API_KEY && process.env.NVD_API_KEY.length > 0
    ? process.env.NVD_API_KEY
    : undefined;
  const concurrency = apiKey ? chunks.length : 1;

  const results = await settledAll(
    chunks.map((chunk) => () => fetchOneNvdChunk(chunk, apiKey)),
    concurrency,
  );

  const merged = new Map();
  let allOk = true;
  for (const r of results) {
    if (r.status === 'rejected') {
      allOk = false;
      continue;
    }
    for (const [cve, score] of r.value) merged.set(cve, score);
  }
  if (!allOk && merged.size === 0) {
    const reasons = results
      .filter((r) => r.status === 'rejected')
      .map((r) => (r.reason instanceof Error ? r.reason.message : String(r.reason)));
    const allRateLimited = reasons.length > 0 && reasons.every(
      (msg) => /HTTP 429/.test(msg) || /\b429\b/.test(msg),
    );
    if (allRateLimited) {
      throw new Error(
        'NVD rate limit reached (HTTP 429). NVD CVSS enrichment is ' +
        'unavailable; severity falls back to CISA-derived values ' +
        'for this refresh.',
      );
    }
    const uniqueReasons = Array.from(new Set(reasons));
    throw new Error(
      `NVD fetch failed for all ${chunks.length} chunk(s): ${uniqueReasons.join('; ')}`,
    );
  }
  return merged;
}

async function fetchOneNvdChunk(cveChunk, apiKey) {
  // v5.0.3: pass the optional apiKey as a request HEADER
  // (per NVD's official CVE 2.0 spec), NOT as a URL query parameter.
  const url = `${NVD_BASE_URL}?cveId=${encodeURIComponent(cveChunk.join(','))}`;
  const headers = { Accept: 'application/json' };
  if (apiKey) headers.apiKey = apiKey;
  const res = await withTimeout(
    fetch(url, { headers, cache: 'no-store' }),
    PER_REQUEST_TIMEOUT_MS,
    `NVD chunk fetch (${cveChunk.length} CVEs)`,
  );
  if (!res.ok) throw new Error(`HTTP ${res.status} ${res.statusText}`);
  const body = await res.json();
  if (!body || !Array.isArray(body.vulnerabilities)) {
    throw new Error('NVD response has unexpected shape (no vulnerabilities array)');
  }
  return body.vulnerabilities
    .map(parseNvdItem)
    .filter((x) => x !== null);
}

function parseNvdItem(item) {
  const cveId = (item?.cve?.id ?? '').trim();
  if (!cveId) return null;
  const score = pickNvdScore(item.cve?.metrics);
  if (score === null) return null;
  return [cveId, score];
}

function pickNvdScore(metrics) {
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
      severity: severityFromNvdBase(v2.baseSeverity, v2.baseScore),
    };
  }
  return null;
}

function severityFromNvdBase(baseSeverity, baseScore) {
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
  if (baseScore >= 9.0) return 'Critical';
  if (baseScore >= 7.0) return 'High';
  if (baseScore >= 4.0) return 'Medium';
  return 'Low';
}

function clampCvss(score) {
  if (Number.isNaN(score)) return 0;
  if (score < 0) return 0;
  if (score > 10) return 10;
  return score;
}

function enrichWithNvd(records, nvdMap) {
  return records.map((v) => {
    const score = nvdMap.get(v.cveId);
    if (!score) return v;
    return { ...v, cvssScore: score.cvssScore, severity: score.severity };
  });
}

// ---------------------------------------------------------------------------
// EPSS batch lookup.
// ---------------------------------------------------------------------------

async function fetchEpssForCves(cveIds) {
  if (cveIds.length === 0) return new Map();
  const uniqueCves = Array.from(
    new Set(cveIds.map((c) => (c ?? '').trim()).filter(Boolean)),
  );
  if (uniqueCves.length === 0) return new Map();

  const chunks = [];
  for (let i = 0; i < uniqueCves.length; i += CHUNK_SIZE) {
    chunks.push(uniqueCves.slice(i, i + CHUNK_SIZE));
  }
  const results = await Promise.allSettled(
    chunks.map((chunk) => fetchOneEpssChunk(chunk)),
  );

  const merged = new Map();
  let allOk = true;
  for (const r of results) {
    if (r.status === 'rejected') {
      allOk = false;
      continue;
    }
    for (const [cve, score] of r.value) merged.set(cve, score);
  }
  if (!allOk && merged.size === 0) {
    const reasons = results
      .filter((r) => r.status === 'rejected')
      .map((r) => (r.reason instanceof Error ? r.reason.message : String(r.reason)))
      .join('; ');
    throw new Error(`FIRST EPSS fetch failed for all ${chunks.length} chunk(s): ${reasons}`);
  }
  return merged;
}

async function fetchOneEpssChunk(cveChunk) {
  const url = `${EPSS_BASE_URL}?cve=${encodeURIComponent(cveChunk.join(','))}`;
  const res = await withTimeout(
    fetch(url, { headers: { Accept: 'application/json' }, cache: 'no-store' }),
    PER_REQUEST_TIMEOUT_MS,
    `EPSS chunk fetch (${cveChunk.length} CVEs)`,
  );
  if (!res.ok) throw new Error(`HTTP ${res.status} ${res.statusText}`);
  const body = await res.json();
  if (!body || !Array.isArray(body.data)) {
    throw new Error('FIRST EPSS response has unexpected shape (no data array)');
  }
  return body.data.map(parseEpssRecord);
}

function parseEpssRecord(rec) {
  return [
    rec.cve,
    {
      epss: parseProbability(rec.epss),
      percentile: parseProbability(rec.percentile),
    },
  ];
}

function parseProbability(raw) {
  if (raw == null) return 0;
  const n = Number.parseFloat(raw);
  if (Number.isNaN(n)) return 0;
  if (n < 0) return 0;
  if (n > 1) return 1;
  return n;
}

function enrichWithEpss(records, epssMap) {
  return records.map((v) => {
    const score = epssMap.get(v.cveId);
    if (!score) return v;
    return { ...v, epssProbability: score.epss };
  });
}