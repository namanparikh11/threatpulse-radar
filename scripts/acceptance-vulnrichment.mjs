// Acceptance tests for the v5.5 CISA Vulnrichment / SSVC
// enrichment pipeline.
//
//   node scripts/acceptance-vulnrichment.mjs
//
// What it covers (per the V5.5 product spec):
//
//   1. CVE → repository path construction (the
//      `2024/6xxx/CVE-2024-6714.json` layout, including
//      5-digit and malformed inputs).
//   2. CISA ADP SSVC parser (filters by provider
//      `CISA-ADP` and metric `type === "ssvc"`, extracts
//      the three documented options, the version, and the
//      assessment timestamp).
//   3. 404 is treated as "missing" for a single CVE — the
//      refresh continues with the remaining CVEs (a 404
//      does NOT fail the whole cycle).
//   4. Incremental cap: a refresh run never attempts more
//      than 50 CVEs, even when the dataset is much larger.
//   5. Concurrency limit: parallel tasks never exceed the
//      configured ceiling.
//   6. Cache survival: a transient error (timeout / 429 /
//      5xx / network) on a CVE that's already in the cache
//      preserves the existing SSVC entry.
//   7. Fresh successful values overwrite stale cached
//      values (no permanent staleness when CISA updates a
//      decision).
//   8. Coverage metadata is accurate: the public
//      `vulnrichmentStatus` and `vulnrichmentCoverage`
//      fields reflect the actual cache state vs. the
//      dataset's CVE list.
//   9. The public response contains NO internal provider
//      errors (no `nvdReason` leak for Vulnrichment, no raw
//      error messages, no internal `lastVulnrichmentRefresh`
//      metadata).
//  10. The vulnerability details drawer renders the SSVC
//      fields + source label.
//  11. No main-table columns were added (the SSVC fields
//      are drawer-only).
//  12. No API keys or secrets are exposed anywhere on the
//      visitor's path.
//
// All previous acceptance scripts (prebuilt / cisa / epss /
// nvd / cache / proxy / softrefresh / lastknowngood) keep
// running unchanged — this file is purely additive.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');

// ---- Real production modules ---------------------------------------

const {
  VULNRICHMENT_BASE_URL,
  VULNRICHMENT_CONCURRENCY,
  VULNRICHMENT_MAX_PER_RUN,
  VULNRICHMENT_STALE_DAYS,
  cveToRepoPath,
  extractSsvcFromAdp,
  mergeSsvcIntoRecord,
  mergeSsvcIntoRecords,
  prioritizeCvesForRefresh,
  vulnrichmentStatusForCoverage,
} = await import('../netlify/functions/_shared/vulnrichment.mjs');

const {
  runVulnrichmentRefresh,
  applyFetchResultToCache,
  computeCoverageForPublic,
} = await import('../netlify/functions/_shared/vulnrichmentRefresh.mjs');

const {
  INTERNAL_BLOB_FIELDS,
} = await import('../netlify/functions/_shared/refresh.mjs');

const {
  VULNRICHMENT_CACHE_KEY,
  VULNRICHMENT_STORE_NAME,
  readVulnrichmentCache,
  writeVulnrichmentCache,
} = await import('../netlify/functions/_shared/store.mjs');

/* ------------------------------------------------------------------ */
/* Test runner                                                        */
/* ------------------------------------------------------------------ */

let passed = 0;
let failed = 0;
const failures = [];

function assert(label, condition, extra = '') {
  if (condition) {
    passed++;
    console.log(`  \u2713 ${label}`);
  } else {
    failed++;
    failures.push({ label, extra });
    console.log(`  \u2717 ${label}${extra ? '  [' + extra + ']' : ''}`);
  }
}

function section(name) {
  console.log(`\n--- ${name} ---`);
}

/* ------------------------------------------------------------------ */
/* 1. CVE → repository path construction                              */
/* ------------------------------------------------------------------ */

section('cveToRepoPath — official cisagov/vulnrichment layout');

assert('CVE-2024-6714 → 2024/6xxx/CVE-2024-6714.json',
  cveToRepoPath('CVE-2024-6714') === '2024/6xxx/CVE-2024-6714.json');

assert('CVE-2024-0043 → 2024/0xxx/CVE-2024-0043.json',
  cveToRepoPath('CVE-2024-0043') === '2024/0xxx/CVE-2024-0043.json');

assert('CVE-2024-9999 → 2024/9xxx/CVE-2024-9999.json',
  cveToRepoPath('CVE-2024-9999') === '2024/9xxx/CVE-2024-9999.json');

assert('CVE-2024-12345 → 2024/12xxx/CVE-2024-12345.json (5-digit, multi-char bucket)',
  cveToRepoPath('CVE-2024-12345') === '2024/12xxx/CVE-2024-12345.json');

assert('CVE-2025-0001 → 2025/0xxx/CVE-2025-0001.json (year prefix preserved)',
  cveToRepoPath('CVE-2025-0001') === '2025/0xxx/CVE-2025-0001.json');

assert('Lowercase input is normalized to uppercase output',
  cveToRepoPath('cve-2024-6714') === '2024/6xxx/CVE-2024-6714.json');

assert('Whitespace is trimmed',
  cveToRepoPath('  CVE-2024-6714  ') === '2024/6xxx/CVE-2024-6714.json');

assert('Null input returns null (not throw)',
  cveToRepoPath(null) === null);

assert('Empty string returns null',
  cveToRepoPath('') === null);

assert('Non-CVE string returns null',
  cveToRepoPath('not-a-cve') === null);

assert('CVE with no number returns null',
  cveToRepoPath('CVE-2024') === null);

assert('CVE with non-numeric year returns null',
  cveToRepoPath('CVE-ABCD-1234') === null);

assert('CVE with too-short number (1-3 digits) returns null',
  // The repository layout requires a bucket prefix ≥ 1 char.
  // 1-3 digit CVE numbers don't have a valid bucket.
  cveToRepoPath('CVE-2024-1') === null &&
  cveToRepoPath('CVE-2024-12') === null &&
  cveToRepoPath('CVE-2024-123') === null);

assert('Number-only input returns null (no CVE- prefix)',
  cveToRepoPath('2024-6714') === null);

assert('Result always starts with the base URL + "/<year>/"',
  // The repository layout is `<year>/<bucket>/<filename>`.
  // Every valid path must start with `<year>/`.
  cveToRepoPath('CVE-2024-6714').startsWith('2024/') &&
  cveToRepoPath('CVE-2025-0001').startsWith('2025/') &&
  cveToRepoPath('CVE-2026-12345').startsWith('2026/'));

assert('Result always ends with the .json extension',
  cveToRepoPath('CVE-2024-6714').endsWith('.json') &&
  cveToRepoPath('CVE-2024-12345').endsWith('.json'));

/* ------------------------------------------------------------------ */
/* 2. CISA ADP SSVC parser                                            */
/* ------------------------------------------------------------------ */

section('extractSsvcFromAdp — strict CISA-ADP SSVC parsing');

const validAdpRecord = {
  containers: {
    cna: { providerMetadata: { shortName: 'cna' } },
    adp: [
      {
        providerMetadata: {
          shortName: 'CISA-ADP',
          dateUpdated: '2024-07-23T00:00:00.000Z',
        },
        metrics: [
          {
            cvssV3_1: { /* unrelated metric */ },
          },
          {
            other: {
              type: 'ssvc',
              content: {
                options: [
                  { Exploitation: 'active' },
                  { Automatable: 'yes' },
                  { 'Technical Impact': 'total' },
                ],
                version: '2.0.3',
                timestamp: '2024-07-23T00:00:00.000Z',
              },
            },
          },
        ],
      },
    ],
  },
};

{
  const out = extractSsvcFromAdp(validAdpRecord);
  assert('valid CISA-ADP SSVC record produces an extracted object',
    out !== null);
  assert('parser extracts ssvcExploitation=active',
    out && out.ssvcExploitation === 'active');
  assert('parser extracts ssvcAutomatable=yes',
    out && out.ssvcAutomatable === 'yes');
  assert('parser extracts ssvcTechnicalImpact=total (note the space in the key)',
    out && out.ssvcTechnicalImpact === 'total');
  assert('parser extracts ssvcVersion',
    out && out.ssvcVersion === '2.0.3');
  assert('parser extracts ssvcAssessedAt (the SSVC content timestamp, not provider dateUpdated)',
    out && out.ssvcAssessedAt === '2024-07-23T00:00:00.000Z');
  assert('parser stamps ssvcSource as "CISA Vulnrichment"',
    out && out.ssvcSource === 'CISA Vulnrichment');
}

assert('parser IGNORES non-CISA-ADP containers',
  extractSsvcFromAdp({
    containers: {
      adp: [
        {
          providerMetadata: { shortName: 'OTHER-VENDOR' },
          metrics: [{ other: { type: 'ssvc', content: { options: [
            { Exploitation: 'active' }, { Automatable: 'yes' }, { 'Technical Impact': 'total' },
          ], version: '1', timestamp: '2024-01-01T00:00:00.000Z' } } }],
        },
      ],
    },
  }) === null);

assert('parser IGNORES non-SSVC metrics on the CISA-ADP container',
  extractSsvcFromAdp({
    containers: {
      adp: [
        {
          providerMetadata: { shortName: 'CISA-ADP' },
          metrics: [
            { cvssV3_1: { baseScore: 9.8 } },
            { other: { type: 'kev' } },
          ],
        },
      ],
    },
  }) === null);

assert('parser returns null when CISA-ADP has no metrics at all',
  extractSsvcFromAdp({
    containers: {
      adp: [{ providerMetadata: { shortName: 'CISA-ADP' } }],
    },
  }) === null);

assert('parser returns null when containers.adp is missing',
  extractSsvcFromAdp({ containers: { cna: {} } }) === null);

assert('parser returns null when containers itself is missing',
  extractSsvcFromAdp({}) === null);

assert('parser returns null on null / non-object input',
  extractSsvcFromAdp(null) === null && extractSsvcFromAdp('not an object') === null);

assert('parser returns null when one of the three required options is missing',
  extractSsvcFromAdp({
    containers: {
      adp: [{
        providerMetadata: { shortName: 'CISA-ADP' },
        metrics: [{ other: { type: 'ssvc', content: { options: [
          { Exploitation: 'active' },
          { Automatable: 'yes' },
          // missing Technical Impact
        ], version: '2.0.3', timestamp: '2024-07-23T00:00:00.000Z' } } }],
      }],
    },
  }) === null);

assert('parser returns null when an option has an unrecognised value',
  extractSsvcFromAdp({
    containers: {
      adp: [{
        providerMetadata: { shortName: 'CISA-ADP' },
        metrics: [{ other: { type: 'ssvc', content: { options: [
          { Exploitation: 'MAYBE' },
          { Automatable: 'yes' },
          { 'Technical Impact': 'total' },
        ], version: '2.0.3', timestamp: '2024-07-23T00:00:00.000Z' } } }],
      }],
    },
  }) === null);

assert('parser accepts all three documented Exploitation values',
  ['none', 'poc', 'active'].every((v) => {
    const r = extractSsvcFromAdp({
      containers: { adp: [{
        providerMetadata: { shortName: 'CISA-ADP' },
        metrics: [{ other: { type: 'ssvc', content: { options: [
          { Exploitation: v },
          { Automatable: 'no' },
          { 'Technical Impact': 'partial' },
        ], version: '2.0.3', timestamp: '2024-01-01T00:00:00.000Z' } } }],
      }] },
    });
    return r && r.ssvcExploitation === v;
  }));

assert('parser accepts all three documented Technical Impact values',
  ['partial', 'total'].every((v) => {
    const r = extractSsvcFromAdp({
      containers: { adp: [{
        providerMetadata: { shortName: 'CISA-ADP' },
        metrics: [{ other: { type: 'ssvc', content: { options: [
          { Exploitation: 'poc' },
          { Automatable: 'yes' },
          { 'Technical Impact': v },
        ], version: '2.0.3', timestamp: '2024-01-01T00:00:00.000Z' } } }],
      }] },
    });
    return r && r.ssvcTechnicalImpact === v;
  }));

assert('parser picks the FIRST CISA-ADP container when multiple are present',
  extractSsvcFromAdp({
    containers: {
      adp: [
        {
          providerMetadata: { shortName: 'CISA-ADP' },
          metrics: [{ other: { type: 'ssvc', content: { options: [
            { Exploitation: 'active' },
            { Automatable: 'yes' },
            { 'Technical Impact': 'total' },
          ], version: '1', timestamp: '2024-01-01T00:00:00.000Z' } } }],
        },
        {
          providerMetadata: { shortName: 'CISA-ADP' },
          metrics: [{ other: { type: 'ssvc', content: { options: [
            { Exploitation: 'none' },
            { Automatable: 'no' },
            { 'Technical Impact': 'partial' },
          ], version: '2', timestamp: '2024-02-01T00:00:00.000Z' } } }],
        },
      ],
    },
  }).ssvcExploitation === 'active');

/* ------------------------------------------------------------------ */
/* 3. 404 / transient semantics — single-CVE fetcher                 */
/* ------------------------------------------------------------------ */

section('fetchOneVulnrichment — 404 vs transient distinction');

function makeMockFetcher(responses) {
  // responses: a function (url) => { status, body? } | 'throw'
  // The fetcher is awaited by the production code with
  // an AbortController. Our mock returns a minimal
  // Response-shaped object; production also calls
  // .json() on the result when status is 2xx.
  return async function fetcher(url, opts) {
    const r = typeof responses === 'function' ? responses(url) : responses;
    if (r === 'throw') throw new Error('network error');
    if (r === 'abort') {
      const e = new Error('aborted');
      e.name = 'AbortError';
      throw e;
    }
    return {
      status: r.status,
      statusText: r.statusText || '',
      ok: r.status >= 200 && r.status < 300,
      json: async () => r.body,
    };
  };
}

const cveGood = 'CVE-2024-6714';

{
  const out = await import('../netlify/functions/_shared/vulnrichment.mjs')
    .then((m) => m.fetchOneVulnrichment(cveGood, {
      fetcher: makeMockFetcher({ status: 200, body: validAdpRecord }),
    }));
  assert('HTTP 200 + valid CISA-ADP record → outcome="ok"',
    out.outcome === 'ok' && out.record === validAdpRecord);
}

{
  const out = await import('../netlify/functions/_shared/vulnrichment.mjs')
    .then((m) => m.fetchOneVulnrichment(cveGood, {
      fetcher: makeMockFetcher({ status: 404, body: {} }),
    }));
  assert('HTTP 404 → outcome="missing" (NOT "transient")',
    out.outcome === 'missing' && out.record === null);
}

{
  const out = await import('../netlify/functions/_shared/vulnrichment.mjs')
    .then((m) => m.fetchOneVulnrichment(cveGood, {
      fetcher: makeMockFetcher({ status: 429, body: {} }),
    }));
  assert('HTTP 429 → outcome="transient"',
    out.outcome === 'transient' && out.record === null);
}

{
  const out = await import('../netlify/functions/_shared/vulnrichment.mjs')
    .then((m) => m.fetchOneVulnrichment(cveGood, {
      fetcher: makeMockFetcher({ status: 503, body: {} }),
    }));
  assert('HTTP 5xx → outcome="transient"',
    out.outcome === 'transient');
}

{
  const out = await import('../netlify/functions/_shared/vulnrichment.mjs')
    .then((m) => m.fetchOneVulnrichment(cveGood, {
      fetcher: makeMockFetcher('throw'),
    }));
  assert('Network error (thrown) → outcome="transient"',
    out.outcome === 'transient');
}

{
  const out = await import('../netlify/functions/_shared/vulnrichment.mjs')
    .then((m) => m.fetchOneVulnrichment(cveGood, {
      fetcher: makeMockFetcher('abort'),
    }));
  assert('AbortError (timeout) → outcome="transient"',
    out.outcome === 'transient');
}

{
  const out = await import('../netlify/functions/_shared/vulnrichment.mjs')
    .then((m) => m.fetchOneVulnrichment('not-a-cve', {
      fetcher: makeMockFetcher({ status: 200, body: {} }),
    }));
  assert('Malformed CVE ID → outcome="missing" (no fetcher call)',
    out.outcome === 'missing');
}

/* ------------------------------------------------------------------ */
/* 4. Incremental cap (max 50 per run)                                */
/* ------------------------------------------------------------------ */

section('Incremental refresh — max 50 CVEs per run');

{
  // Dataset of 200 CVEs, all missing from the cache →
  // toEnrich should be capped at 50.
  const cveList = Array.from({ length: 200 }, (_, i) => ({
    cveId: `CVE-2024-${String(i).padStart(4, '0')}`,
    dateAdded: `2024-01-${String((i % 28) + 1).padStart(2, '0')}T00:00:00.000Z`,
  }));
  const toEnrich = prioritizeCvesForRefresh({ cveList, cache: {} });
  assert('prioritizeCvesForRefresh caps at VULNRICHMENT_MAX_PER_RUN (50)',
    toEnrich.length === VULNRICHMENT_MAX_PER_RUN);
  assert('capped result is exactly 50 entries',
    toEnrich.length === 50);
}

{
  // Dataset of 30 CVEs all missing → toEnrich should be
  // the full 30 (no padding to 50).
  const cveList = Array.from({ length: 30 }, (_, i) => ({
    cveId: `CVE-2024-${String(i).padStart(4, '0')}`,
    dateAdded: '2024-06-01T00:00:00.000Z',
  }));
  const toEnrich = prioritizeCvesForRefresh({ cveList, cache: {} });
  assert('small dataset is not padded up to the cap',
    toEnrich.length === 30);
}

{
  // Dataset of 100 CVEs, 60 already in cache as fresh →
  // toEnrich should be the 40 missing.
  const cveList = Array.from({ length: 100 }, (_, i) => ({
    cveId: `CVE-2024-${String(i).padStart(4, '0')}`,
    dateAdded: '2024-06-01T00:00:00.000Z',
  }));
  const now = Date.now();
  const cache = {};
  for (let i = 0; i < 60; i++) {
    cache[`CVE-2024-${String(i).padStart(4, '0')}`] = {
      ssvc: { ssvcExploitation: 'active' },
      cachedAt: now, // fresh
    };
  }
  const toEnrich = prioritizeCvesForRefresh({ cveList, cache, now });
  assert('fresh cached CVEs are skipped from the to-enrich set',
    toEnrich.length === 40);
  assert('to-enrich set does not include any of the cached CVEs',
    !toEnrich.some((c) => cache[c]));
}

{
  // Cached CVEs older than the staleness window are
  // re-fetched.
  const cveList = [
    { cveId: 'CVE-2024-0001', dateAdded: '2024-01-01T00:00:00.000Z' },
  ];
  const now = Date.now();
  const staleMs = (VULNRICHMENT_STALE_DAYS + 1) * 24 * 60 * 60 * 1000;
  const cache = {
    'CVE-2024-0001': {
      ssvc: { ssvcExploitation: 'active' },
      cachedAt: now - staleMs,
    },
  };
  const toEnrich = prioritizeCvesForRefresh({ cveList, cache, now });
  assert('cached entry older than the staleness window is re-fetched',
    toEnrich.length === 1 && toEnrich[0] === 'CVE-2024-0001');
}

assert('prioritizeCvesForRefresh sorts KEV-newest first',
  prioritizeCvesForRefresh({
    cveList: [
      { cveId: 'CVE-2024-0001', dateAdded: '2024-01-01T00:00:00.000Z' },
      { cveId: 'CVE-2024-0002', dateAdded: '2024-12-31T00:00:00.000Z' },
      { cveId: 'CVE-2024-0003', dateAdded: '2024-06-01T00:00:00.000Z' },
    ],
    cache: {},
  })[0] === 'CVE-2024-0002');

assert('prioritizeCvesForRefresh falls back to a stable sentinel for missing dateAdded',
  prioritizeCvesForRefresh({
    cveList: [
      { cveId: 'CVE-2024-0001', dateAdded: null },
      { cveId: 'CVE-2024-0002', dateAdded: '2024-06-01T00:00:00.000Z' },
    ],
    cache: {},
  })[0] === 'CVE-2024-0002');

/* ------------------------------------------------------------------ */
/* 5. Concurrency limit                                               */
/* ------------------------------------------------------------------ */

section('Concurrency limit — parallel worker never exceeds the cap');

{
  // Track the maximum number of in-flight fetches at any
  // moment and assert it never exceeds the configured
  // concurrency.
  let inFlight = 0;
  let maxInFlight = 0;
  const fetcher = makeMockFetcher(async (url) => {
    inFlight++;
    if (inFlight > maxInFlight) maxInFlight = inFlight;
    // Yield to the event loop to let sibling tasks
    // start; this is what makes the test actually
    // exercise the concurrency limiter.
    await new Promise((r) => setTimeout(r, 5));
    inFlight--;
    return { status: 200, body: validAdpRecord };
  });
  // Adapt the shape: our fetcher returns a Response, but
  // the test mock above returned the resolved object
  // directly. Rebuild it.
  const cveList = Array.from({ length: 30 }, (_, i) => ({
    cveId: `CVE-2024-${String(i).padStart(4, '0')}`,
    dateAdded: '2024-06-01T00:00:00.000Z',
  }));
  const realFetcher = async (url) => {
    inFlight++;
    if (inFlight > maxInFlight) maxInFlight = inFlight;
    await new Promise((r) => setTimeout(r, 5));
    inFlight--;
    return { status: 200, statusText: 'OK', ok: true, json: async () => validAdpRecord };
  };
  // We use a tiny in-memory Blobs stand-in so the
  // orchestrator can complete its write step. The shape
  // mirrors the production contract: get/setJSON/delete.
  const fakeBlobs = new Map();
  const store = {
    get: async (key, opts) => {
      const v = fakeBlobs.get(key);
      if (v == null) return null;
      return opts && opts.type === 'json' ? JSON.parse(v) : v;
    },
    setJSON: async (key, value) => { fakeBlobs.set(key, JSON.stringify(value)); },
    delete: async (key) => { fakeBlobs.delete(key); },
  };
  const result = await runVulnrichmentRefresh({
    store,
    cveList,
    fetcher: realFetcher,
    now: new Date(),
  });
  assert('orchestrator completes successfully with parallel fetches',
    result.status === 'completed');
  assert('orchestrator attempted all 30 CVEs (under the cap)',
    result.attempted === 30);
  assert(`concurrency never exceeded VULNRICHMENT_CONCURRENCY (${VULNRICHMENT_CONCURRENCY})`,
    maxInFlight <= VULNRICHMENT_CONCURRENCY,
    `observed maxInFlight=${maxInFlight}`);
  assert(`concurrency is at least 2 (real parallelism, not serial) — observed ${maxInFlight}`,
    maxInFlight >= 2);
}

/* ------------------------------------------------------------------ */
/* 6. Cache survival on transient failure                             */
/* ------------------------------------------------------------------ */

section('Cache survival — transient error preserves existing SSVC');

{
  // Pre-populate the cache with a STALE record (older
  // than the 7-day staleness window so the orchestrator
  // will include it in the to-enrich set), then run a
  // refresh where the fetch returns a transient error.
  // The existing SSVC entry must be preserved (NOT
  // cleared), the orchestrator must report the transient
  // failure, and the CVE must still count as enriched
  // (because its SSVC record is still in the cache).
  const nowMs = Date.now();
  const tenDaysMs = 10 * 24 * 60 * 60 * 1000;
  const existingSsvc = {
    ssvcExploitation: 'active',
    ssvcAutomatable: 'yes',
    ssvcTechnicalImpact: 'total',
    ssvcVersion: '2.0.3',
    ssvcAssessedAt: '2024-07-01T00:00:00.000Z',
    ssvcSource: 'CISA Vulnrichment',
  };
  const cache = {
    'CVE-2024-0001': { ssvc: existingSsvc, cachedAt: nowMs - tenDaysMs },
  };
  const fetcher = makeMockFetcher({ status: 503, body: {} });
  const cveList = [{ cveId: 'CVE-2024-0001', dateAdded: '2024-01-01T00:00:00.000Z' }];
  const fakeBlobs = new Map();
  const store = {
    get: async (key, opts) => {
      const v = fakeBlobs.get(key);
      if (v == null) return null;
      return opts && opts.type === 'json' ? JSON.parse(v) : v;
    },
    setJSON: async (key, value) => { fakeBlobs.set(key, JSON.stringify(value)); },
    delete: async (key) => { fakeBlobs.delete(key); },
  };
  // Pre-seed the cache in the store.
  await writeVulnrichmentCache(store, { records: cache, updatedAt: new Date().toISOString() });
  const result = await runVulnrichmentRefresh({
    store,
    cveList,
    fetcher,
    now: new Date(nowMs),
    nowFn: () => nowMs,
  });
  assert('refresh status is "completed" even when the only fetch was transient',
    result.status === 'completed');
  assert('orchestrator counts the transient failure',
    result.transient === 1 && result.attempted === 1);
  // The cache must STILL contain the original SSVC record
  // (the original timestamp, NOT updated — a transient
  // failure must not pretend to have refreshed the data).
  const after = await readVulnrichmentCache(store);
  assert('existing SSVC entry is preserved after a transient failure',
    after.records['CVE-2024-0001'] &&
    after.records['CVE-2024-0001'].ssvc.ssvcExploitation === 'active' &&
    after.records['CVE-2024-0001'].cachedAt === nowMs - tenDaysMs);
  assert('coverage still shows the CVE as enriched (1/1) — stale data is still data',
    result.enriched === 1 && result.total === 1);
}

{
  // 404 on a STALE cached entry must NOT delete the
  // positive SSVC record (the spec's defensive contract:
  // "A 404 must never delete an existing positive SSVC
  // record"). The previous version of this test seeded
  // with a fresh entry, so the fetch was skipped and the
  // test was trivially true. This version seeds with a
  // 10-day-old (stale) entry so the 404 actually fires,
  // and the orchestrator's defensive check is exercised.
  const nowMs = Date.now();
  const tenDaysMs = 10 * 24 * 60 * 60 * 1000;
  const cache = {
    'CVE-2024-0001': {
      ssvc: {
        ssvcExploitation: 'poc',
        ssvcAutomatable: 'no',
        ssvcTechnicalImpact: 'partial',
        ssvcVersion: '2.0.3',
        ssvcAssessedAt: '2024-07-01T00:00:00.000Z',
        ssvcSource: 'CISA Vulnrichment',
      },
      cachedAt: nowMs - tenDaysMs,
    },
  };
  const fetcher = makeMockFetcher({ status: 404, body: {} });
  const cveList = [{ cveId: 'CVE-2024-0001', dateAdded: '2024-01-01T00:00:00.000Z' }];
  const fakeBlobs = new Map();
  const store = {
    get: async (key, opts) => {
      const v = fakeBlobs.get(key);
      if (v == null) return null;
      return opts && opts.type === 'json' ? JSON.parse(v) : v;
    },
    setJSON: async (key, value) => { fakeBlobs.set(key, JSON.stringify(value)); },
    delete: async (key) => { fakeBlobs.delete(key); },
  };
  await writeVulnrichmentCache(store, { records: cache, updatedAt: new Date().toISOString() });
  const result = await runVulnrichmentRefresh({
    store,
    cveList,
    fetcher,
    now: new Date(nowMs),
    nowFn: () => nowMs,
  });
  const after = await readVulnrichmentCache(store);
  assert('a 404 on a STALE positive record does NOT delete the positive SSVC (defensive — spec req 4)',
    after.records['CVE-2024-0001'] &&
    after.records['CVE-2024-0001'].ssvc &&
    after.records['CVE-2024-0001'].ssvc.ssvcExploitation === 'poc' &&
    after.records['CVE-2024-0001'].ssvc.ssvcVersion === '2.0.3');
  assert('defensive 404: the 404 still counts as "missing" in the operator envelope',
    result.missing === 1 && result.attempted === 1);
  assert('defensive 404: the positive record still counts as enriched (1/1)',
    result.enriched === 1 && result.total === 1);
}

/* ------------------------------------------------------------------ */
/* 6b. Negative-cache behavior — 404 results are NOT lost              */
/* ------------------------------------------------------------------ */

section('Negative-cache: 404 results get a checkedAt marker; 60-CVE forward progress');

{
  // First sub-test: 404 on a CVE that has NO existing
  // cache entry must write a negative-cache marker.
  const nowMs = Date.now();
  const fetcher = makeMockFetcher({ status: 404, body: {} });
  const cveList = [{ cveId: 'CVE-2024-0001', dateAdded: '2024-01-01T00:00:00.000Z' }];
  const fakeBlobs = new Map();
  const store = {
    get: async (key, opts) => {
      const v = fakeBlobs.get(key);
      if (v == null) return null;
      return opts && opts.type === 'json' ? JSON.parse(v) : v;
    },
    setJSON: async (key, value) => { fakeBlobs.set(key, JSON.stringify(value)); },
    delete: async (key) => { fakeBlobs.delete(key); },
  };
  await writeVulnrichmentCache(store, { records: {}, updatedAt: new Date().toISOString() });
  const result = await runVulnrichmentRefresh({
    store,
    cveList,
    fetcher,
    now: new Date(nowMs),
    nowFn: () => nowMs,
  });
  assert('404 on an uncached CVE is reported as "missing" in the result envelope',
    result.missing === 1 && result.attempted === 1);
  const after = await readVulnrichmentCache(store);
  assert('404 on an uncached CVE writes a negative-cache marker with checkedAt',
    after.records['CVE-2024-0001'] &&
    after.records['CVE-2024-0001'].ssvc === null &&
    after.records['CVE-2024-0001'].status === 'missing' &&
    after.records['CVE-2024-0001'].checkedAt === nowMs &&
    after.records['CVE-2024-0001'].cachedAt === nowMs);
  assert('404 on an uncached CVE does NOT count as enriched',
    result.enriched === 0 && result.total === 1);
}

{
  // Second sub-test: a 404 on a CVE that HAS an existing
  // positive SSVC record must NOT delete the positive
  // record. The marker is a no-op in this case.
  const nowMs = Date.now();
  const tenDaysMs = 10 * 24 * 60 * 60 * 1000;
  const positiveSsvc = {
    ssvcExploitation: 'active',
    ssvcAutomatable: 'yes',
    ssvcTechnicalImpact: 'total',
    ssvcVersion: '2.0.3',
    ssvcAssessedAt: '2024-07-01T00:00:00.000Z',
    ssvcSource: 'CISA Vulnrichment',
  };
  const cache = {
    'CVE-2024-0001': { ssvc: positiveSsvc, cachedAt: nowMs - tenDaysMs },
  };
  const fetcher = makeMockFetcher({ status: 404, body: {} });
  const cveList = [{ cveId: 'CVE-2024-0001', dateAdded: '2024-01-01T00:00:00.000Z' }];
  const fakeBlobs = new Map();
  const store = {
    get: async (key, opts) => {
      const v = fakeBlobs.get(key);
      if (v == null) return null;
      return opts && opts.type === 'json' ? JSON.parse(v) : v;
    },
    setJSON: async (key, value) => { fakeBlobs.set(key, JSON.stringify(value)); },
    delete: async (key) => { fakeBlobs.delete(key); },
  };
  await writeVulnrichmentCache(store, { records: cache, updatedAt: new Date().toISOString() });
  const result = await runVulnrichmentRefresh({
    store,
    cveList,
    fetcher,
    now: new Date(nowMs),
    nowFn: () => nowMs,
  });
  const after = await readVulnrichmentCache(store);
  assert('404 does NOT delete an existing positive SSVC record (defensive — spec req 4)',
    after.records['CVE-2024-0001'] &&
    after.records['CVE-2024-0001'].ssvc &&
    after.records['CVE-2024-0001'].ssvc.ssvcExploitation === 'active' &&
    after.records['CVE-2024-0001'].ssvc.ssvcVersion === '2.0.3');
  assert('defensive 404: the positive record still counts as enriched',
    result.enriched === 1 && result.total === 1);
}

{
  // Third sub-test: the headline regression. 60 uncached
  // CVEs, every fetch returns 404. The first run selects
  // 50 and writes negative-cache markers. The second run
  // must select the REMAINING 10 (not repeat the first 50)
  // because the first 50 are now considered "fresh" by
  // the staleness window.
  const nowMs = Date.now();
  const fetcher = makeMockFetcher({ status: 404, body: {} });
  const cveList = Array.from({ length: 60 }, (_, i) => ({
    cveId: `CVE-2024-${String(i).padStart(4, '0')}`,
    dateAdded: `2024-06-${String((i % 28) + 1).padStart(2, '0')}T00:00:00.000Z`,
  }));
  const fakeBlobs = new Map();
  const store = {
    get: async (key, opts) => {
      const v = fakeBlobs.get(key);
      if (v == null) return null;
      return opts && opts.type === 'json' ? JSON.parse(v) : v;
    },
    setJSON: async (key, value) => { fakeBlobs.set(key, JSON.stringify(value)); },
    delete: async (key) => { fakeBlobs.delete(key); },
  };
  await writeVulnrichmentCache(store, { records: {}, updatedAt: new Date().toISOString() });

  // First run.
  const first = await runVulnrichmentRefresh({
    store,
    cveList,
    fetcher,
    now: new Date(nowMs),
    nowFn: () => nowMs,
  });
  assert('first run with 60 uncached CVEs and 100% 404 attempts exactly 50 (the cap)',
    first.attempted === 50);
  assert('first run reports 50 missing entries',
    first.missing === 50);
  const after1 = await readVulnrichmentCache(store);
  assert('first run wrote 50 negative-cache markers to the store',
    Object.keys(after1.records).length === 50);
  assert('each marker carries checkedAt, status, and ssvc=null',
    Object.values(after1.records).every((e) =>
      e && e.ssvc === null && e.status === 'missing' &&
      typeof e.cachedAt === 'number' && e.cachedAt === nowMs &&
      typeof e.checkedAt === 'number' && e.checkedAt === nowMs));
  assert('first run enriched=0 / total=60 (no SSVC records, all 404)',
    first.enriched === 0 && first.total === 60);

  // Second run — the original 50 must be skipped because
  // their negative-cache markers are fresh.
  const second = await runVulnrichmentRefresh({
    store,
    cveList,
    fetcher,
    now: new Date(nowMs + 1000), // 1 second later, still fresh
    nowFn: () => nowMs + 1000,
  });
  assert('second run attempts only the REMAINING 10, not the first 50',
    second.attempted === 10);
  assert('second run reports 10 more missing entries',
    second.missing === 10);
  const after2 = await readVulnrichmentCache(store);
  assert('second run wrote 10 more negative-cache markers (60 total)',
    Object.keys(after2.records).length === 60);
  assert('coverage is still 0/60 after both runs (all 404)',
    second.enriched === 0 && second.total === 60);

  // Third run: nothing left uncached → 0 attempts.
  const third = await runVulnrichmentRefresh({
    store,
    cveList,
    fetcher,
    now: new Date(nowMs + 2000),
    nowFn: () => nowMs + 2000,
  });
  assert('third run attempts 0 (all 60 are now negative-cached and fresh)',
    third.attempted === 0);

  // Fourth run: jump past the staleness window. The
  // original 60 are now eligible again (a newly published
  // CISA assessment would be picked up).
  const longLater = nowMs + ((VULNRICHMENT_STALE_DAYS + 1) * 24 * 60 * 60 * 1000);
  const fourth = await runVulnrichmentRefresh({
    store,
    cveList,
    fetcher,
    now: new Date(longLater),
    nowFn: () => longLater,
  });
  assert('after the negative-cache TTL expires, the original 60 may be re-selected',
    fourth.attempted === 50);
}

{
  // Fourth sub-test: prioritizeCvesForRefresh alone
  // recognises a fresh negative-cache marker as "skip".
  // 5 CVEs, 2 already cached as fresh missing markers.
  // The other 3 should be selected.
  const cveList = [
    { cveId: 'CVE-2024-0001', dateAdded: '2024-01-01T00:00:00.000Z' },
    { cveId: 'CVE-2024-0002', dateAdded: '2024-02-01T00:00:00.000Z' },
    { cveId: 'CVE-2024-0003', dateAdded: '2024-03-01T00:00:00.000Z' },
    { cveId: 'CVE-2024-0004', dateAdded: '2024-04-01T00:00:00.000Z' },
    { cveId: 'CVE-2024-0005', dateAdded: '2024-05-01T00:00:00.000Z' },
  ];
  const now = Date.now();
  const cache = {
    'CVE-2024-0001': {
      ssvc: null,
      status: 'missing',
      cachedAt: now,
      checkedAt: now,
    },
    'CVE-2024-0003': {
      ssvc: null,
      status: 'missing',
      cachedAt: now,
      checkedAt: now,
    },
  };
  const toEnrich = prioritizeCvesForRefresh({ cveList, cache, now });
  assert('prioritizeCvesForRefresh skips fresh negative-cache markers',
    toEnrich.length === 3 &&
    !toEnrich.includes('CVE-2024-0001') &&
    !toEnrich.includes('CVE-2024-0003') &&
    toEnrich.includes('CVE-2024-0002') &&
    toEnrich.includes('CVE-2024-0004') &&
    toEnrich.includes('CVE-2024-0005'));
}

/* ------------------------------------------------------------------ */
/* 7. Fresh successful values overwrite stale values                  */
/* ------------------------------------------------------------------ */

section('Fresh successful values overwrite stale cached values');

{
  const oldMs = Date.now() - (10 * 24 * 60 * 60 * 1000); // 10 d old
  const newMs = Date.now();
  const oldCache = {
    'CVE-2024-0001': {
      ssvc: {
        ssvcExploitation: 'none',
        ssvcAutomatable: 'no',
        ssvcTechnicalImpact: 'partial',
        ssvcVersion: '2.0.0',
        ssvcAssessedAt: '2024-01-01T00:00:00.000Z',
        ssvcSource: 'CISA Vulnrichment',
      },
      cachedAt: oldMs,
    },
  };
  const newAdp = JSON.parse(JSON.stringify(validAdpRecord));
  // Mutate to a different decision so we can prove the
  // overwrite actually happened.
  newAdp.containers.adp[0].metrics[1].other.content.options = [
    { Exploitation: 'active' },
    { Automatable: 'yes' },
    { 'Technical Impact': 'total' },
  ];
  newAdp.containers.adp[0].metrics[1].other.content.version = '2.0.3';
  newAdp.containers.adp[0].metrics[1].other.content.timestamp = '2024-08-01T00:00:00.000Z';
  const fetcher = makeMockFetcher({ status: 200, body: newAdp });
  const cveList = [{ cveId: 'CVE-2024-0001', dateAdded: '2024-01-01T00:00:00.000Z' }];
  const fakeBlobs = new Map();
  const store = {
    get: async (key, opts) => {
      const v = fakeBlobs.get(key);
      if (v == null) return null;
      return opts && opts.type === 'json' ? JSON.parse(v) : v;
    },
    setJSON: async (key, value) => { fakeBlobs.set(key, JSON.stringify(value)); },
    delete: async (key) => { fakeBlobs.delete(key); },
  };
  await writeVulnrichmentCache(store, { records: oldCache, updatedAt: new Date(oldMs).toISOString() });
  await runVulnrichmentRefresh({
    store,
    cveList,
    fetcher,
    now: new Date(newMs),
    nowFn: () => newMs,
  });
  const after = await readVulnrichmentCache(store);
  assert('stale cached SSVC is overwritten with the fresh value',
    after.records['CVE-2024-0001'].ssvc.ssvcExploitation === 'active' &&
    after.records['CVE-2024-0001'].ssvc.ssvcVersion === '2.0.3');
  assert('cache timestamp is updated to the current time',
    after.records['CVE-2024-0001'].cachedAt === newMs);
}

/* ------------------------------------------------------------------ */
/* 8. Coverage metadata is accurate                                   */
/* ------------------------------------------------------------------ */

section('Coverage metadata — vulnrichmentStatus + vulnrichmentCoverage');

assert('0 enriched / 0 total → unavailable',
  vulnrichmentStatusForCoverage(0, 0) === 'unavailable');

assert('0 enriched / 100 total → unavailable',
  vulnrichmentStatusForCoverage(0, 100) === 'unavailable');

assert('50 enriched / 100 total → partial',
  vulnrichmentStatusForCoverage(50, 100) === 'partial');

assert('100 enriched / 100 total → available',
  vulnrichmentStatusForCoverage(100, 100) === 'available');

assert('computeCoverageForPublic counts only the CVEs in the dataset',
  (() => {
    const cache = {
      'CVE-2024-0001': { ssvc: { ssvcExploitation: 'active' }, cachedAt: 1 },
      'CVE-2024-0002': { ssvc: { ssvcExploitation: 'poc' }, cachedAt: 1 },
      'CVE-2024-0003': { ssvc: { ssvcExploitation: 'none' }, cachedAt: 1 },
    };
    const cveList = [
      { cveId: 'CVE-2024-0001' },
      { cveId: 'CVE-2024-0002' },
      // CVE-2024-0003 is in the cache but NOT in the
      // dataset — it must NOT count.
    ];
    const cov = computeCoverageForPublic(cache, cveList);
    return cov.enriched === 2 && cov.total === 2 && cov.status === 'available';
  })());

assert('computeCoverageForPublic handles empty cache',
  (() => {
    const cov = computeCoverageForPublic({}, [
      { cveId: 'CVE-2024-0001' },
    ]);
    return cov.enriched === 0 && cov.total === 1 && cov.status === 'unavailable';
  })());

assert('computeCoverageForPublic handles empty dataset',
  (() => {
    const cov = computeCoverageForPublic({
      'CVE-2024-0001': { ssvc: { ssvcExploitation: 'active' }, cachedAt: 1 },
    }, []);
    return cov.enriched === 0 && cov.total === 0 && cov.status === 'unavailable';
  })());

/* ------------------------------------------------------------------ */
/* 9. Read-time merge (pure)                                          */
/* ------------------------------------------------------------------ */

section('mergeSsvcIntoRecord / mergeSsvcIntoRecords — pure merge');

{
  const record = { cveId: 'CVE-2024-0001', cvssScore: 7.5 };
  const ssvc = {
    ssvcExploitation: 'active',
    ssvcAutomatable: 'yes',
    ssvcTechnicalImpact: 'total',
    ssvcVersion: '2.0.3',
    ssvcAssessedAt: '2024-08-01T00:00:00.000Z',
    ssvcSource: 'CISA Vulnrichment',
  };
  const merged = mergeSsvcIntoRecord(record, ssvc);
  assert('merged record has all six SSVC fields',
    merged.ssvcExploitation === 'active' &&
    merged.ssvcAutomatable === 'yes' &&
    merged.ssvcTechnicalImpact === 'total' &&
    merged.ssvcVersion === '2.0.3' &&
    merged.ssvcAssessedAt === '2024-08-01T00:00:00.000Z' &&
    merged.ssvcSource === 'CISA Vulnrichment');
  assert('merged record preserves the original fields (no overwrite of cvssScore)',
    merged.cvssScore === 7.5 && merged.cveId === 'CVE-2024-0001');
  assert('merge does NOT mutate the input record',
    record.ssvcExploitation === undefined);
  assert('merge on null ssvc returns the original reference (no allocation)',
    mergeSsvcIntoRecord(record, null) === record);
}

{
  const records = [
    { cveId: 'CVE-2024-0001', cvssScore: 7.5 },
    { cveId: 'CVE-2024-0002', cvssScore: 8.0 },
    { cveId: 'CVE-2024-0003', cvssScore: 6.0 },
  ];
  const ssvcByCve = {
    'CVE-2024-0002': { ssvcExploitation: 'active' },
  };
  const merged = mergeSsvcIntoRecords(records, ssvcByCve);
  assert('only the matched CVE gets SSVC fields',
    merged[0].ssvcExploitation === undefined &&
    merged[1].ssvcExploitation === 'active' &&
    merged[2].ssvcExploitation === undefined);
  assert('merge preserves array length and order',
    merged.length === 3 &&
    merged[0].cveId === 'CVE-2024-0001' &&
    merged[1].cveId === 'CVE-2024-0002' &&
    merged[2].cveId === 'CVE-2024-0003');
}

assert('applyFetchResultToCache is a no-op for transient on a missing entry',
  (() => {
    const before = {};
    const after = applyFetchResultToCache(before, 'CVE-2024-0001', 'transient', null, Date.now());
    return Object.keys(after).length === 0;
  })());

assert('applyFetchResultToCache preserves an existing entry on transient',
  (() => {
    const existing = { ssvc: { ssvcExploitation: 'poc' }, cachedAt: 100 };
    const before = { 'CVE-2024-0001': existing };
    const after = applyFetchResultToCache(before, 'CVE-2024-0001', 'transient', null, Date.now());
    return after['CVE-2024-0001'] === existing;
  })());

assert('applyFetchResultToCache writes a negative-cache marker on "missing" for an uncached CVE',
  (() => {
    const now = Date.now();
    const before = {};
    const after = applyFetchResultToCache(before, 'CVE-2024-0001', 'missing', null, now);
    const e = after['CVE-2024-0001'];
    return e && e.ssvc === null && e.status === 'missing' &&
      e.cachedAt === now && e.checkedAt === now;
  })());

assert('applyFetchResultToCache preserves an existing positive record on "missing" (defensive — spec req 4)',
  (() => {
    const existing = { ssvc: { ssvcExploitation: 'poc' }, cachedAt: 100 };
    const before = { 'CVE-2024-0001': existing };
    const after = applyFetchResultToCache(before, 'CVE-2024-0001', 'missing', null, Date.now());
    return after['CVE-2024-0001'] === existing;
  })());

assert('applyFetchResultToCache refreshes a stale negative-cache marker with a fresh "missing" outcome',
  (() => {
    const now = Date.now();
    const staleMarker = { ssvc: null, status: 'missing', cachedAt: 1, checkedAt: 1 };
    const before = { 'CVE-2024-0001': staleMarker };
    const after = applyFetchResultToCache(before, 'CVE-2024-0001', 'missing', null, now);
    const e = after['CVE-2024-0001'];
    return e && e.ssvc === null && e.status === 'missing' &&
      e.cachedAt === now && e.checkedAt === now;
  })());

/* ------------------------------------------------------------------ */
/* 10. Public response contains no internal provider errors           */
/* ------------------------------------------------------------------ */

section('Public response: no internal provider errors, no secrets, no API keys');

const datasetSrc = readFileSync(
  join(root, 'netlify', 'functions', 'dataset.mjs'),
  'utf8',
);
const vulnrichmentSrc = readFileSync(
  join(root, 'netlify', 'functions', '_shared', 'vulnrichment.mjs'),
  'utf8',
);
const vulnrichmentRefreshSrc = readFileSync(
  join(root, 'netlify', 'functions', '_shared', 'vulnrichmentRefresh.mjs'),
  'utf8',
);
const refreshSrc = readFileSync(
  join(root, 'netlify', 'functions', '_shared', 'refresh.mjs'),
  'utf8',
);
const storeSrc = readFileSync(
  join(root, 'netlify', 'functions', '_shared', 'store.mjs'),
  'utf8',
);
const serviceSrc = readFileSync(
  join(root, 'src', 'services', 'vulnerabilityService.ts'),
  'utf8',
);
const typeSrc = readFileSync(
  join(root, 'src', 'types', 'vulnerability.ts'),
  'utf8',
);
const drawerSrc = readFileSync(
  join(root, 'src', 'components', 'DetailDrawer.tsx'),
  'utf8',
);
const dashboardSrc = readFileSync(
  join(root, 'src', 'pages', 'DashboardPage.tsx'),
  'utf8',
);

assert('INTERNAL_BLOB_FIELDS includes "lastVulnrichmentRefresh" (operator-only)',
  INTERNAL_BLOB_FIELDS.has('lastVulnrichmentRefresh'));

assert('dataset.mjs uses publicEnvelope() to strip internal fields',
  /publicEnvelope\(/.test(datasetSrc));

assert('dataset.mjs adds vulnrichmentStatus and vulnrichmentCoverage to the response',
  /vulnrichmentStatus/.test(datasetSrc) &&
  /vulnrichmentCoverage/.test(datasetSrc));

assert('dataset.mjs does NOT include any VULNRICHMENT_API_KEY reference',
  !/VULNRICHMENT_API_KEY/.test(datasetSrc));

assert('vulnrichment.mjs does NOT read any secrets or env vars',
  !/process\.env/.test(vulnrichmentSrc) &&
  !/VITE_/.test(vulnrichmentSrc));

assert('vulnrichmentRefresh.mjs does NOT read any secrets or env vars',
  !/process\.env/.test(vulnrichmentRefreshSrc) &&
  !/VITE_/.test(vulnrichmentRefreshSrc));

assert('vulnerabilityService.ts does NOT call any Vulnrichment endpoint directly',
  // The browser-direct path must stay clean — only the
  // proxy (dataset.mjs) calls the upstream.
  !/raw\.githubusercontent\.com/.test(serviceSrc) &&
  !/cisagov\/vulnrichment/.test(serviceSrc));

assert('the Vulnrichment cache lives in a SEPARATE blob store (tpr-vulnrichment)',
  VULNRICHMENT_STORE_NAME === 'tpr-vulnrichment' &&
  /VULNRICHMENT_STORE_NAME\s*=\s*['"]tpr-vulnrichment['"]/.test(storeSrc));

assert('the Vulnrichment cache key is named "cache" (single key in the store)',
  VULNRICHMENT_CACHE_KEY === 'cache');

assert('Vulnerability type adds all six ssvc* fields',
  /ssvcExploitation\?/.test(typeSrc) &&
  /ssvcAutomatable\?/.test(typeSrc) &&
  /ssvcTechnicalImpact\?/.test(typeSrc) &&
  /ssvcVersion\?/.test(typeSrc) &&
  /ssvcAssessedAt\?/.test(typeSrc) &&
  /ssvcSource\?/.test(typeSrc));

assert('Vulnerability type exports SsvcExploitation / SsvcAutomatable / SsvcTechnicalImpact unions',
  /export\s+type\s+SsvcExploitation/.test(typeSrc) &&
  /export\s+type\s+SsvcAutomatable/.test(typeSrc) &&
  /export\s+type\s+SsvcTechnicalImpact/.test(typeSrc));

assert('Vulnerability type exports VulnrichmentStatus and VulnrichmentCoverage',
  /export\s+type\s+VulnrichmentStatus/.test(typeSrc) &&
  /export\s+interface\s+VulnrichmentCoverage/.test(typeSrc));

assert('FetchResult adds vulnrichmentStatus and vulnrichmentCoverage envelope fields',
  /vulnrichmentStatus\?\s*:\s*VulnrichmentStatus/.test(serviceSrc) &&
  /vulnrichmentCoverage\?\s*:\s*VulnrichmentCoverage/.test(serviceSrc));

/* ------------------------------------------------------------------ */
/* 11. UI drawer renders SSVC fields + source label                   */
/* ------------------------------------------------------------------ */

section('UI: DetailDrawer renders the CISA decision context section');

assert('DetailDrawer defines an SsvcContext component',
  /function\s+SsvcContext\s*\(/.test(drawerSrc));

assert('DetailDrawer renders a "CISA decision context" section title',
  /CISA decision context/.test(drawerSrc));

assert('DetailDrawer shows the empty-state copy when no SSVC record exists',
  /No CISA Vulnrichment assessment available/.test(drawerSrc));

assert('DetailDrawer renders Exploitation / Automatable / Technical impact labels',
  /Exploitation/.test(drawerSrc) &&
  /Automatable/.test(drawerSrc) &&
  /Technical impact/.test(drawerSrc));

assert('DetailDrawer shows the "Assessed" date using formatAbsolute',
  /Assessed/.test(drawerSrc) && /formatAbsolute/.test(drawerSrc));

assert('DetailDrawer shows the source label "CISA Vulnrichment"',
  /CISA Vulnrichment/.test(drawerSrc) && /Source/.test(drawerSrc));

assert('DetailDrawer uses the ClipboardList icon for the SSVC section',
  /ClipboardList/.test(drawerSrc));

/* ------------------------------------------------------------------ */
/* 12. No main-table columns added                                    */
/* ------------------------------------------------------------------ */

section('UI: no new main-table columns; SSVC is drawer-only');

const tableSrc = readFileSync(
  join(root, 'src', 'components', 'VulnerabilityTable.tsx'),
  'utf8',
);

assert('VulnerabilityTable source does NOT mention any ssvc* field',
  !/ssvcExploitation|ssvcAutomatable|ssvcTechnicalImpact|ssvcVersion|ssvcAssessedAt|ssvcSource/.test(tableSrc),
  'expected no SSVC fields in the main table component');

assert('DashboardPage does NOT mention any ssvc* field',
  !/ssvcExploitation|ssvcAutomatable|ssvcTechnicalImpact|ssvcVersion|ssvcAssessedAt|ssvcSource/.test(dashboardSrc),
  'expected no SSVC fields in the dashboard page');

/* ------------------------------------------------------------------ */
/* 13. Source-level: orchestrator wires Vulnrichment into the         */
/*     main 'completed' path                                           */
/* ------------------------------------------------------------------ */

section('Orchestrator wires Vulnrichment into the completed path');

assert('refresh.mjs imports runVulnrichmentRefresh from vulnrichmentRefresh.mjs',
  /import[\s\S]{0,200}runVulnrichmentRefresh[\s\S]{0,200}from\s+['"]\.\/vulnrichmentRefresh\.mjs['"]/.test(refreshSrc));

assert('refresh.mjs imports getVulnrichmentStore from store.mjs',
  /getVulnrichmentStore/.test(refreshSrc));

assert('refresh.mjs calls runVulnrichmentRefresh inside runRefresh',
  /runVulnrichmentRefresh\(/.test(refreshSrc));

assert('refresh.mjs writes lastVulnrichmentRefresh on the main envelope',
  /lastVulnrichmentRefresh\s*:/.test(refreshSrc));

assert('refresh.mjs wraps the vulnrichment call in try/catch (defensive)',
  // The orchestrator must not let a Vulnrichment cycle
  // break the main build's 'completed' status.
  /runVulnrichmentRefresh[\s\S]{0,800}try/.test(refreshSrc) ||
  /runVulnrichmentRefresh[\s\S]{0,2000}catch/.test(refreshSrc),
  'expected the runVulnrichmentRefresh call to be wrapped in a try/catch');

/* ------------------------------------------------------------------ */
/* 14. The base URL points to the cisagov/vulnrichment repo           */
/* ------------------------------------------------------------------ */

section('Base URL points to the official cisagov/vulnrichment repo');

assert('VULNRICHMENT_BASE_URL is the official raw GitHub URL',
  VULNRICHMENT_BASE_URL === 'https://raw.githubusercontent.com/cisagov/vulnrichment/develop');

/* ------------------------------------------------------------------ */
/* Summary                                                            */
/* ------------------------------------------------------------------ */

console.log();
if (failed === 0) {
  console.log(`VULNRICHMENT TESTS PASSED  (${passed}/${passed})`);
} else {
  console.log(
    `VULNRICHMENT TESTS FAILED  (${failed} of ${passed + failed} failed)`,
  );
  for (const f of failures) {
    console.log(`  - ${f.label}${f.extra ? '  [' + f.extra + ']' : ''}`);
  }
  process.exit(1);
}
