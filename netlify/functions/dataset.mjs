/**
 * Netlify Function — `/.netlify/functions/dataset`
 *
 * v5.0 Live Proxy Mode. Server-side aggregator for the public
 * vulnerability feeds. The browser calls only this endpoint and
 * never the upstream feeds directly. The function fetches
 * CISA KEV, NVD CVE 2.0, and FIRST EPSS in parallel, normalizes
 * the records into the same `Vulnerability` shape the client
 * already understands, and returns a JSON envelope that
 * mirrors the `FetchResult` type in
 * `src/services/vulnerabilityService.ts`.
 *
 * Why this exists (v4.1 → v5.0):
 *   The v4.1 docs are source-honest about a real problem: a
 *   static public demo can show fallback / mock mode when the
 *   browser-direct CISA / NVD / EPSS fetches are blocked by
 *   CORS, rate limits, geo restrictions, or upstream outages.
 *   This function gives the dashboard a single CORS-safe
 *   browser-direct endpoint, so the public demo can show real
 *   live data without the user ever hitting a third-party
 *   origin from their browser.
 *
 * Honesty contract (parallels the v4 cache contract):
 *   - CISA is the only gating upstream. If CISA fails, the
 *     function returns HTTP 502 with a `fallbackReason`. The
 *     client treats this as "live fetch failed" and falls back
 *     to the local mock dataset (or a stale localStorage cache).
 *   - NVD and EPSS have their own status fields. A failure of
 *     either does NOT take the whole response down — the
 *     client gets HTTP 200 with `nvdStatus: 'unavailable'` /
 *     `epssStatus: 'unavailable'` and the reason in the
 *     response body. The dashboard surfaces the partial
 *     failure in its existing amber "NVD: unavailable" /
 *     "EPSS: unavailable" pills.
 *   - No API keys, secrets, or tokens are read or shipped. The
 *     function uses only the same anonymous public endpoints
 *     the browser used in v4. The function is the *origin*
 *     change, not a credentials change.
 *   - No scoring is fabricated. CVEs absent from NVD's
 *     response keep `cvssScore: 0`. CVEs absent from EPSS's
 *     response keep `epssProbability: 0`. Same contract as the
 *     browser-direct providers.
 *   - No new data sources. The three feeds are the same three
 *     feeds the v4 dashboard already used. OSV.dev / GHSA /
 *     other aggregators are explicitly v5.1+, not v5.0.
 *
 * Reuse strategy:
 *   The field shapes and normalization rules mirror the
 *   existing browser providers in
 *   `src/services/providers/{cisaKev,nvd,epss}.ts`. The
 *   function is self-contained (no imports from `src/`) so it
 *   can be deployed as a single Netlify Function with no
 *   build step. The `scripts/acceptance-proxy.mjs` suite
 *   asserts that the key URLs and severity rules match the
 *   browser-side code — if either drifts, the test catches it.
 *
 * Runtime constraints:
 *   - Netlify Functions default timeout is 26 s for async
 *     functions. We apply an 8 s per-request timeout and a
 *     24 s overall budget so the function never overruns.
 *   - We use Node 20+'s built-in `fetch` and `AbortController`.
 *     No external dependencies.
 *   - The function is read-only and idempotent. It does not
 *     write to any storage, schedule anything, or authenticate
 *     anyone.
 *
 * Response shape (200):
 *   {
 *     data: Vulnerability[],
 *     source: 'merged',
 *     fetchedAt: string (ISO),
 *     mode: 'live',
 *     nvdStatus: 'nvd' | 'unavailable',
 *     nvdReason?: string,
 *     epssStatus: 'first' | 'unavailable',
 *     epssReason?: string,
 *   }
 *
 * Response shape (502 on CISA failure):
 *   {
 *     mode: 'fallback',
 *     fallbackReason: string,
 *   }
 */

// ---------------------------------------------------------------------------
// Public upstream URLs (same constants as the browser-side providers).
// ---------------------------------------------------------------------------

const CISA_KEV_URL =
  'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const NVD_BASE_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const EPSS_BASE_URL = 'https://api.first.org/data/v1/epss';

// ---------------------------------------------------------------------------
// Tuning.
// ---------------------------------------------------------------------------

const CHUNK_SIZE = 100; // CISA catalog has ~1000 entries; chunk to keep URL length sane.
const PER_REQUEST_TIMEOUT_MS = 8_000; // matches the browser-side provider.
const OVERALL_BUDGET_MS = 24_000; // safety margin under Netlify's 26 s default async limit.

// ---------------------------------------------------------------------------
// Upstream payload shapes (only the fields we read).
// ---------------------------------------------------------------------------

/** @typedef {{ cveID: string, vendorProject?: string, product?: string, vulnerabilityName?: string, dateAdded?: string, shortDescription?: string, requiredAction?: string, knownRansomwareCampaignUse?: 'Known'|'Unknown' }} CisaRecord */
/** @typedef {{ cve?: { id?: string, metrics?: NvdMetrics } }} NvdItem */
/** @typedef {{ cvssData?: { baseScore?: number, baseSeverity?: string } }} NvdMetric */
/** @typedef {{ cvssMetricV31?: NvdMetric[], cvssMetricV30?: NvdMetric[], cvssMetricV2?: NvdMetric[] }} NvdMetrics */
/** @typedef {{ cve: string, epss: string, percentile: string }} EpssRecord */

// ---------------------------------------------------------------------------
// Entry point. Netlify Functions receive a (event, context) pair.
// ---------------------------------------------------------------------------

export default async (request /* Request */) => {
  const overallStart = Date.now();

  // ---- 1. CISA KEV (gating) ----
  let cisaRecords;
  try {
    cisaRecords = await fetchCisaKev();
  } catch (err) {
    return jsonResponse(502, {
      mode: 'fallback',
      fallbackReason:
        err instanceof Error
          ? `CISA KEV fetch failed: ${err.message}`
          : 'CISA KEV fetch failed: unknown error.',
    });
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

  return jsonResponse(200, {
    data: enriched,
    source: 'merged',
    fetchedAt: new Date().toISOString(),
    mode: 'live',
    nvdStatus: nvdResult.status,
    nvdReason: nvdResult.reason,
    epssStatus: epssResult.status,
    epssReason: epssResult.reason,
  });
};

// ---------------------------------------------------------------------------
// HTTP response helper. The function lives at /.netlify/functions/dataset,
// which is same-origin to the deployed app, so CORS is technically not
// required. We still set a permissive header in case someone embeds the
// dashboard in an iframe or proxies the function from another origin.
//
// v5.0.1 — performance hardening: the function previously returned
// `Cache-Control: no-store`, which meant every visitor triggered a
// full CISA → NVD → EPSS pipeline run (the 5–15 s cold path). The
// v5.0.1 response is now `s-maxage=900, stale-while-revalidate=300`:
//
//   - s-maxage=900
//       Netlify's edge cache holds the response for 15 minutes.
//       Within that window, repeat visitors get the cached function
//       response in <100 ms — no upstream fetch, no function run.
//   - stale-while-revalidate=300
//       After the 15 min mark, the cache is "stale" for another
//       5 minutes. Netlify serves the stale response immediately
//       AND triggers a background function invocation to refresh
//       the cache. The next visitor after the refresh hits the
//       fresh cache again. This avoids the "thundering herd"
//       problem of many visitors all waiting on a slow function.
//   - The response has no `max-age` directive, so the browser
//     is not told to cache the JSON locally — but the client uses
//     `cache: 'no-store'` on its fetch anyway. The `s-maxage`
//     directive is what Netlify's edge honors; `max-age` would
//     be a stronger signal we don't want here.
//   - The function's `fetchedAt` field is set inside the function
//     body (`new Date().toISOString()`) at the moment the function
//     actually runs, NOT when the CDN serves the response. The
//     dashboard's "Last refresh" pill therefore shows the time
//     since the *actual* function run, even on CDN-cached
//     responses. The freshness copy remains honest.
//   - The client's "Refresh live data" button appends a unique
//     `?t=<timestamp>` query string when `forceRefresh: true` is
//     passed, so a manual refresh always bypasses the CDN cache
//     and forces a real function run. The button continues to
//     honor its name.
// ---------------------------------------------------------------------------

function jsonResponse(status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'public, s-maxage=900, stale-while-revalidate=300',
      'Access-Control-Allow-Origin': '*',
      'X-Content-Type-Options': 'nosniff',
    },
  });
}

// ---------------------------------------------------------------------------
// "Run this enricher but never let it take the whole function down."
// Returns { map, status, reason }. If the enricher throws or the budget
// elapses, returns an empty map with status='unavailable' and a reason.
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

// ---------------------------------------------------------------------------
// CISA KEV fetch + normalize. Mirrors src/services/providers/cisaKev.ts.
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
// NVD batch lookup. Mirrors src/services/providers/nvd.ts.
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
  const results = await Promise.allSettled(
    chunks.map((chunk) => fetchOneNvdChunk(chunk)),
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
    throw new Error(`NVD fetch failed for all ${chunks.length} chunk(s): ${reasons}`);
  }
  return merged;
}

async function fetchOneNvdChunk(cveChunk) {
  const url = `${NVD_BASE_URL}?cveId=${encodeURIComponent(cveChunk.join(','))}`;
  const res = await withTimeout(
    fetch(url, { headers: { Accept: 'application/json' }, cache: 'no-store' }),
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
// EPSS batch lookup. Mirrors src/services/providers/epss.ts.
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
