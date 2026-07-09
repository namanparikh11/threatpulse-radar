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

/**
 * v5.2.5: Non-enumerable Symbol used to attach partial-failure
 * metadata to the Map returned by `fetchNvdForCves`. The Map
 * itself is still iterated / serialized normally; the Symbol
 * property survives property access (`map[SYMBOL]`) but is
 * hidden from JSON.stringify (so it never ships to the
 * browser) and from Map iteration (so it never mixes with
 * the CVE→score entries).
 *
 * The shape of the attached value:
 *   {
 *     missingCount: number,   // CVEs that 404'd as individual lookups
 *     errorCount:   number,   // chunks that hit a non-404 NVD error
 *     firstReason:  string|null, // first error message (truncated)
 *   }
 */
export const NVD_PARTIAL_META = Symbol.for('threatpulse.nvd.partialMeta');

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
 * @param {boolean} [opts.skipNvd] v5.2.6: short-circuit the NVD
 *   fetch and return the envelope with `nvdStatus: 'unavailable'`.
 *   Used by the refresh orchestrator when the NVD cooldown is
 *   active but no existing good blob is present (e.g. a fresh
 *   deploy that caught NVD mid-rate-limit). The CISA + EPSS
 *   pipeline still runs so visitors still get fresh KEV
 *   records and EPSS scores, just without CVSS scores.
 */
export async function buildLiveDataset(opts = {}) {
  const overallStart = opts.startTime ?? Date.now();
  const skipNvd = opts.skipNvd === true;

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

  // v5.2.6: when skipNvd is true, don't even attempt the NVD
  // fetch — return a synthetic 'unavailable' result so the
  // rest of the pipeline (EPSS enrichment + envelope shape)
  // stays unchanged. The refresh orchestrator's quality guard
  // sees the rate-limited envelope and preserves the existing
  // better blob instead of writing this one.
  const nvdFetchPromise = skipNvd
    ? Promise.resolve({
        map: new Map(),
        status: 'unavailable',
        reason:
          'NVD enrichment skipped (cooldown active); CVSS scores ' +
          'are unavailable for this refresh.',
      })
    : safeEnrich('NVD', () => fetchNvdForCves(cveIds), budgetRemaining());

  const [nvdResult, epssResult] = await Promise.all([
    nvdFetchPromise,
    safeEnrich('EPSS', () => fetchEpssForCves(cveIds), budgetRemaining()),
  ]);

  // v5.2.5: detect partial-failure metadata attached to the
  // NVD Map by `fetchNvdForCves` (Symbol-keyed property; never
  // serialized, never sent to the client). When present, we
  // keep `nvdStatus` as 'nvd' (the data IS enriched for the
  // CVEs that exist in NVD — preserves the UI contract) and
  // upgrade `nvdReason` to a partial-failure summary so the
  // operator / dashboard can see how many CVEs were dropped.
  //
  // v5.2.6: when `skipNvd` is true, the synthetic result has
  // no Symbol metadata — `readNvdPartialMeta` returns null —
  // so the cooldown reason flows through unchanged.
  const nvdPartialMeta = readNvdPartialMeta(nvdResult.map);
  const nvdStatus = nvdResult.status;
  const nvdReason = nvdPartialMeta
    ? formatPartialNvdReason(nvdPartialMeta)
    : nvdResult.reason;

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
    nvdStatus,
    nvdReason,
    epssStatus: epssResult.status,
    epssReason: epssResult.reason,
  };
}

/**
 * v5.2.5: Build a user-facing partial-failure reason for the
 * NVD enrichment step. Kept concise (≤ ~280 chars) because
 * `nvdReason` is shipped in the response body. Includes:
 *   - count of CVEs that 404'd as individual lookups
 *     ("missing from NVD")
 *   - count of batches that hit a non-404 NVD error
 *   - the first truncated error message (status code + URL +
 *     body snippet — never the apiKey)
 */
function formatPartialNvdReason(meta) {
  const parts = [];
  if (meta.missingCount > 0) {
    parts.push(
      `${meta.missingCount} CVE${meta.missingCount === 1 ? '' : 's'} ` +
      `missing from NVD`,
    );
  }
  if (meta.errorCount > 0) {
    parts.push(
      `${meta.errorCount} batch error${meta.errorCount === 1 ? '' : 's'}`,
    );
  }
  let reason = `NVD partial enrichment: ${parts.join('; ')}.`;
  if (meta.firstReason) {
    reason += ` First issue: ${meta.firstReason}`;
  }
  // Hard cap so a pathological error string can't blow up the
  // response envelope.
  return reason.length > 320 ? reason.slice(0, 319) + '…' : reason;
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

  // v5.2.5: each chunk is processed by `tryBatchWithSplit`,
  // which recursively halves a failing batch on HTTP 404 to
  // isolate the offending CVE(s). Per-chunk partial failures
  // return a `{ found, missing, errors }` envelope instead
  // of throwing.
  const results = await settledAll(
    chunks.map((chunk) => () => tryBatchWithSplit(chunk, apiKey, 0)),
    concurrency,
  );

  const merged = new Map();
  let totalOk = true;
  let totalMissing = 0;
  const reasons = [];

  for (const r of results) {
    if (r.status === 'rejected') {
      totalOk = false;
      reasons.push(
        r.reason instanceof Error ? r.reason.message : String(r.reason),
      );
      continue;
    }
    const v = r.value;
    for (const [cve, score] of v.found) merged.set(cve, score);
    totalMissing += v.missing.length;
    if (v.errors.length > 0) {
      totalOk = false;
      reasons.push(...v.errors);
    }
  }

  // All-failure path: nothing came back AND at least one chunk
  // surfaced an error. Preserve the v5.0.2 429-detection and
  // de-duplication behavior so existing diagnostics and tests
  // still match.
  if (!totalOk && merged.size === 0) {
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

  // Partial-failure path: we DID get some data back. Mark the
  // returned Map with the NVD_PARTIAL_META Symbol so the
  // caller (`safeEnrich`) can attach a partial-failure reason
  // to the envelope without breaking the existing "nvd status
  // means enriched" UI contract.
  if (!totalOk || totalMissing > 0) {
    const uniqueReasons = Array.from(new Set(reasons));
    const firstReason = uniqueReasons[0]
      ? truncateForReason(uniqueReasons[0], 240)
      : null;
    Object.defineProperty(merged, NVD_PARTIAL_META, {
      value: {
        missingCount: totalMissing,
        errorCount: uniqueReasons.length,
        firstReason,
      },
      enumerable: false,
      writable: false,
      configurable: false,
    });
  }

  return merged;
}

/**
 * v5.2.5: Recursive partial-fallback wrapper around
 * `fetchOneNvdBatch`. Returns a structured envelope:
 *
 *   { found: Map<cveId, NvdScore>,
 *     missing: string[],       // CVEs that 404'd as individuals
 *     errors:  string[] }      // non-404 batch failures
 *
 * On the happy path (no error), `found` holds the enrichment
 * map and `missing` / `errors` are empty.
 *
 * On a non-2xx response:
 *   - HTTP 404 + chunk.length > 1  → split in half and recurse.
 *     NVD's batch endpoint sometimes rejects a whole batch
 *     when even one CVE ID is unrecognized. Binary-searching
 *     isolates the bad CVE(s); a single-CVE 404 is treated as
 *     "this CVE isn't in NVD" and silently skipped (it stays
 *     at CISA-derived severity).
 *   - HTTP 404 + chunk.length == 1 → treat as `missing`.
 *   - Any other status (429 / 5xx / network) → record the
 *     diagnostic message and do NOT recurse; the parent chunk
 *     loop surfaces the error in the partial-failure metadata
 *     or, if EVERY chunk failed, in the all-failure throw.
 *
 * No recursion depth limit is required: the tree depth is
 * bounded by `Math.ceil(log2(chunk.length))` (≈ 7 for a
 * 100-CVE chunk), so worst-case work is one request per CVE.
 */
async function tryBatchWithSplit(chunk, apiKey, depth) {
  try {
    const map = await fetchOneNvdBatch(chunk, apiKey);
    return { found: map, missing: [], errors: [], depth };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    const status = extractHttpStatus(msg);

    // Only split on 404 — every other failure mode (429 rate
    // limit, 5xx transient, network error, shape mismatch) is
    // upstream-side and recursing wouldn't help.
    if (status === 404) {
      if (chunk.length === 1) {
        // Single-CVE 404 = this CVE isn't in NVD. Just skip it.
        return { found: new Map(), missing: chunk.slice(), errors: [], depth };
      }
      const mid = Math.ceil(chunk.length / 2);
      const left = await tryBatchWithSplit(chunk.slice(0, mid), apiKey, depth + 1);
      const right = await tryBatchWithSplit(chunk.slice(mid), apiKey, depth + 1);
      return {
        found: mergeMaps(left.found, right.found),
        missing: [...left.missing, ...right.missing],
        errors: [...left.errors, ...right.errors],
        depth: Math.max(left.depth, right.depth),
      };
    }

    // Non-404 failure. Record the diagnostic and bubble up so
    // the parent chunk loop can decide whether this is the
    // "all chunks failed" case or a partial one.
    throw err;
  }
}

function mergeMaps(a, b) {
  const merged = new Map(a);
  for (const [k, v] of b) merged.set(k, v);
  return merged;
}

function extractHttpStatus(msg) {
  if (typeof msg !== 'string') return null;
  const m = /HTTP\s+(\d{3})\b/.exec(msg);
  if (!m) return null;
  const n = parseInt(m[1], 10);
  return Number.isFinite(n) ? n : null;
}

function truncateForReason(s, max) {
  if (typeof s !== 'string') return null;
  if (s.length <= max) return s;
  return s.slice(0, max - 1) + '…';
}

/**
 * v5.2.5: Read the partial-failure metadata that
 * `fetchNvdForCves` attaches via the NVD_PARTIAL_META Symbol.
 * Returns `null` if no partial-failure metadata is present
 * (i.e. either full success or full failure — the latter
 * path throws and never returns a Map to inspect).
 *
 * Kept as a small standalone helper so the safeEnrich call
 * site reads top-down and so the acceptance suite can verify
 * the metadata is reachable without going through fetch.
 */
export function readNvdPartialMeta(map) {
  if (!map) return null;
  const meta = map[NVD_PARTIAL_META];
  if (!meta || typeof meta !== 'object') return null;
  return meta;
}

async function fetchOneNvdBatch(cveChunk, apiKey) {
  // v5.2.3: NVD CVE 2.0 uses `cveIds=` (plural) for a
  // comma-separated list of CVE IDs in a single request,
  // max 100 per request. The older `cveId=` (singular)
  // parameter expects a single CVE ID; passing a
  // comma-separated list to it returns HTTP 404. The
  // prebuilt-dataset deploy preview caught this — every
  // chunk was returning "HTTP 404 Not Found".
  //
  // v5.2.5: even with the correct `?cveIds=` parameter,
  // NVD can still return HTTP 404 for a batch when one of
  // the CVE IDs is unknown to NVD (e.g. a CVE that CISA
  // added to KEV before NVD published the record). The
  // outer `tryBatchWithSplit` handles that by recursively
  // halving the failing chunk and isolating the bad CVE(s)
  // as individual lookups; individual 404s become "missing
  // from NVD", not provider failure.
  //
  // v5.0.3 (unchanged): the optional `apiKey` is passed as
  // a request HEADER per NVD's official CVE 2.0 spec, NOT
  // as a URL query parameter. Server-side only. The apiKey
  // is never included in the request URL, the response body,
  // logs, or the error message returned to the caller.
  const url = `${NVD_BASE_URL}?cveIds=${encodeURIComponent(cveChunk.join(','))}`;
  const headers = { Accept: 'application/json' };
  if (apiKey) headers.apiKey = apiKey;

  let res;
  try {
    res = await withTimeout(
      fetch(url, { headers, cache: 'no-store' }),
      PER_REQUEST_TIMEOUT_MS,
      `NVD chunk fetch (${cveChunk.length} CVEs)`,
    );
  } catch (err) {
    // Network / timeout / abort. Include the safe URL (no
    // apiKey; apiKey is a header, not a URL param) so the
    // caller can reproduce the request from the error.
    throw new Error(
      `NVD chunk fetch (${cveChunk.length} CVEs) failed: ` +
      `${err instanceof Error ? err.message : String(err)} | url=${url}`,
    );
  }

  if (!res.ok) {
    // Capture safe diagnostics: HTTP status, NVD's `Warning`
    // header, the JSON `message` field if present, and a
    // truncated body snippet. The URL is always safe to log
    // (it contains only the public CVE IDs).
    const warning = res.headers.get('Warning') || '';
    const headerMsg = res.headers.get('X-Error-Message') || '';
    let bodySnippet = '';
    try {
      const text = await res.text();
      const trimmed = text.replace(/\s+/g, ' ').trim();
      bodySnippet = trimmed.length > 200
        ? trimmed.slice(0, 199) + '…'
        : trimmed;
    } catch {
      // Body unreadable — leave empty.
    }
    let jsonMessage = '';
    try {
      // Some NVD error responses include a JSON `message` field.
      // Try to extract it without leaking the whole body twice.
      const parsed = JSON.parse(bodySnippet);
      if (parsed && typeof parsed.message === 'string') {
        jsonMessage = parsed.message;
      }
    } catch {
      // Not JSON — ignore.
    }
    const parts = [`HTTP ${res.status} ${res.statusText}`];
    parts.push(`url=${url}`);
    if (warning) parts.push(`warning=${warning}`);
    if (headerMsg) parts.push(`header_message=${headerMsg}`);
    if (jsonMessage) parts.push(`nvd_message=${jsonMessage}`);
    if (bodySnippet) parts.push(`body=${bodySnippet}`);
    throw new Error(
      `NVD chunk fetch (${cveChunk.length} CVEs) failed: ${parts.join(' | ')}`,
    );
  }

  const body = await res.json();
  if (!body || !Array.isArray(body.vulnerabilities)) {
    throw new Error(
      `NVD chunk fetch (${cveChunk.length} CVEs) returned unexpected shape ` +
      `(no vulnerabilities array) | url=${url}`,
    );
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