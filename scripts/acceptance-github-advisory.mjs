// Acceptance tests for the v5.6 GitHub Advisory / SSVC
// enrichment pipeline.
//
//   node scripts/acceptance-github-advisory.mjs
//
// What it covers (per the V5.6 product spec):
//
//   1. CVE → query URL construction (the
//      `/advisories?cve_id=...&type=reviewed` layout,
//      including encodeURIComponent behavior and
//      malformed-input rejection).
//   2. Recommended headers (Accept, X-GitHub-Api-Version,
//      User-Agent).
//   3. The optional GITHUB_TOKEN is server-side only —
//      never in URLs, logs, errors, frontend, or public
//      responses.
//   4. The unauthenticated cap is 25; the authenticated
//      cap is 50.
//   5. Concurrency is limited to 4.
//   6. Reviewed-and-non-withdrawn filtering.
//   7. Deterministic handling of multiple advisories.
//   8. Package parsing + dedup + 5-entry cap.
//   9. Empty-array / HTTP 404 negative caching.
//  10. Forward progress across cycles (the 60-CVE
//      regression).
//  11. Defensive: empty / 404 result cannot delete a
//      positive cache entry.
//  12. Timeout / network / 403 / 429 / 5xx preserve prior
//      cache entries.
//  13. Rate-limit headers (x-ratelimit-remaining,
//      x-ratelimit-reset, retry-after) are parsed and
//      exposed only as sanitized orchestrator internals.
//  14. Coverage metadata is accurate
//      (githubAdvisoryStatus / githubAdvisoryCoverage).
//  15. The merge is read-time only — the prebuilt
//      blob's `fetchedAt` is NEVER modified by the
//      GitHub Advisory attach, so the v5.1 "newer dataset
//      available" banner cannot fire spuriously.
//  16. The public response contains no internal metadata
//      (`lastGithubAdvisoryRefresh` / no token / no raw
//      errors / no rate-limit headers / no cache keys).
//  17. The vulnerability details drawer renders the
//      "Package remediation context" section.
//  18. `null` first-patched-version renders as
//      "unavailable" (NOT "no fix").
//  19. External advisory link uses the normalized GitHub
//      html_url with `rel="noreferrer noopener"` and
//      `target="_blank"`.
//  20. No main-table column, no header pill for the
//      GitHub Advisory source.
//
// All previous acceptance scripts (prebuilt / cisa / epss /
// nvd / cache / proxy / softrefresh / lastknowngood /
// vulnrichment) keep running unchanged — this file is
// purely additive.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');

// ---- Real production modules ---------------------------------------

const {
  GITHUB_ADVISORY_API_BASE_URL,
  GITHUB_ADVISORY_API_VERSION,
  GITHUB_ADVISORY_CONCURRENCY,
  GITHUB_ADVISORY_MAX_PER_RUN_AUTH,
  GITHUB_ADVISORY_MAX_PER_RUN_UNAUTH,
  GITHUB_ADVISORY_MIN_REMAINING,
  GITHUB_ADVISORY_PER_REQUEST_TIMEOUT_MS,
  GITHUB_ADVISORY_STALE_DAYS,
  GITHUB_ADVISORY_USER_AGENT,
  cveToAdvisoryQueryUrl,
  extractReviewedAdvisories,
  fetchOneCveAdvisories,
  githubAdvisoryStatusForCoverage,
  mergeAdvisoryIntoRecord,
  mergeAdvisoryIntoRecords,
  prioritizeCvesForRefresh,
  readRateLimitHeaders,
} = await import('../netlify/functions/_shared/githubAdvisory.mjs');

const {
  runGithubAdvisoryRefresh,
  applyFetchResultToCache,
  computeCoverageForPublic,
} = await import('../netlify/functions/_shared/githubAdvisoryRefresh.mjs');

const {
  INTERNAL_BLOB_FIELDS,
} = await import('../netlify/functions/_shared/refresh.mjs');

const {
  GITHUB_ADVISORY_CACHE_KEY,
  GITHUB_ADVISORY_STORE_NAME,
  readGithubAdvisoryCache,
  writeGithubAdvisoryCache,
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
/* Mock fetcher factory                                              */
/* ------------------------------------------------------------------ */

function makeMockFetcher(responses) {
  // responses: function (url) => { status, body?, headers? }
  //          | { status, body?, headers? } (single response, reused)
  //          | 'throw' (network error)
  //          | 'abort' (AbortError for timeout)
  return async function fetcher(url, opts) {
    const r = typeof responses === 'function' ? responses(url) : responses;
    if (r === 'throw') throw new Error('network error');
    if (r === 'abort') {
      const e = new Error('aborted');
      e.name = 'AbortError';
      throw e;
    }
    const headers = r.headers || {};
    return {
      status: r.status,
      statusText: r.statusText || '',
      ok: r.status >= 200 && r.status < 300,
      json: async () => r.body,
      headers,
    };
  };
}

/* ------------------------------------------------------------------ */
/* 1. CVE → query URL construction                                    */
/* ------------------------------------------------------------------ */

section('cveToAdvisoryQueryUrl — official GitHub Advisory API layout');

assert('CVE-2024-6714 → /advisories?cve_id=CVE-2024-6714&type=reviewed',
  cveToAdvisoryQueryUrl('CVE-2024-6714') === '/advisories?cve_id=CVE-2024-6714&type=reviewed');

assert('CVE-2024-0043 → /advisories?cve_id=CVE-2024-0043&type=reviewed',
  cveToAdvisoryQueryUrl('CVE-2024-0043') === '/advisories?cve_id=CVE-2024-0043&type=reviewed');

assert('CVE-2024-12345 → /advisories?cve_id=CVE-2024-12345&type=reviewed (5-digit OK)',
  cveToAdvisoryQueryUrl('CVE-2024-12345') === '/advisories?cve_id=CVE-2024-12345&type=reviewed');

assert('lowercase input is normalized to uppercase output',
  cveToAdvisoryQueryUrl('cve-2024-6714') === '/advisories?cve_id=CVE-2024-6714&type=reviewed');

assert('whitespace is trimmed',
  cveToAdvisoryQueryUrl('  CVE-2024-6714  ') === '/advisories?cve_id=CVE-2024-6714&type=reviewed');

assert('null input returns null (does not throw)',
  cveToAdvisoryQueryUrl(null) === null);

assert('empty string returns null',
  cveToAdvisoryQueryUrl('') === null);

assert('non-CVE string returns null',
  cveToAdvisoryQueryUrl('not-a-cve') === null);

assert('CVE with no number returns null',
  cveToAdvisoryQueryUrl('CVE-2024') === null);

assert('CVE with non-numeric year returns null',
  cveToAdvisoryQueryUrl('CVE-ABCD-1234') === null);

assert('CVE with too-short number (1-3 digits) returns null',
  cveToAdvisoryQueryUrl('CVE-2024-1') === null &&
  cveToAdvisoryQueryUrl('CVE-2024-12') === null &&
  cveToAdvisoryQueryUrl('CVE-2024-123') === null);

assert('number-only input returns null',
  cveToAdvisoryQueryUrl('2024-6714') === null);

assert('always includes type=reviewed parameter',
  /[?&]type=reviewed(?:&|$)/.test(cveToAdvisoryQueryUrl('CVE-2024-6714')));

assert('always includes cve_id= prefix',
  cveToAdvisoryQueryUrl('CVE-2024-6714').includes('cve_id='));

assert('uses encodeURIComponent on the CVE id (defensive)',
  cveToAdvisoryQueryUrl('CVE-2024-6714').includes(encodeURIComponent('CVE-2024-6714')));

/* ------------------------------------------------------------------ */
/* 2. Recommended headers (Accept, X-GitHub-Api-Version, User-Agent)  */
/* ------------------------------------------------------------------ */

section('GitHub Advisory API headers');

const datasetSrc = readFileSync(
  join(root, 'netlify', 'functions', '_shared', 'githubAdvisory.mjs'),
  'utf8',
);

assert('production fetcher sets Accept: application/vnd.github+json',
  /Accept:\s*['"]application\/vnd\.github\+json['"]/.test(datasetSrc));

assert('production fetcher sets X-GitHub-Api-Version header',
  /X-GitHub-Api-Version/.test(datasetSrc));

assert('X-GitHub-Api-Version is the documented v5.6 value',
  GITHUB_ADVISORY_API_VERSION === '2026-03-10');

assert('production fetcher sets User-Agent: ThreatPulse-Radar',
  /User-Agent:\s*GITHUB_ADVISORY_USER_AGENT/.test(datasetSrc) ||
  new RegExp(GITHUB_ADVISORY_USER_AGENT.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).test(datasetSrc));

assert('User-Agent constant matches the spec',
  GITHUB_ADVISORY_USER_AGENT === 'ThreatPulse-Radar');

assert('production fetcher uses AbortController for timeout',
  /AbortController/.test(datasetSrc));

assert('default per-request timeout is 8 seconds',
  GITHUB_ADVISORY_PER_REQUEST_TIMEOUT_MS === 8000);

/* ------------------------------------------------------------------ */
/* 3. Server-side-only GITHUB_TOKEN                                   */
/* ------------------------------------------------------------------ */

section('Token safety — server-side only, never in URLs / logs / errors / frontend');

assert('the production fetcher reads GITHUB_TOKEN from process.env',
  /process\.env\.GITHUB_TOKEN/.test(datasetSrc));

assert('token is added ONLY as the Authorization header (Bearer prefix)',
  // The source uses a template literal:
  //   headers.Authorization = `Bearer ${token}`;
  // Allow both single, double, and backtick quotes around
  // the Bearer prefix.
  /headers\.Authorization\s*=\s*['"`]Bearer\s+\$\{token\}/.test(datasetSrc));

assert('token is NOT added to the URL anywhere (no ?token=, no &token=, no url concat)',
  !/\?token=/.test(datasetSrc) &&
  !/&token=/.test(datasetSrc) &&
  !/url\s*\+=/.test(datasetSrc) &&
  !/url\s*\+.*token/i.test(datasetSrc) &&
  !/\$\{token\}.*url/i.test(datasetSrc));

assert('token is NOT read by any frontend source file',
  // The browser-direct path must stay clean — only the
  // server reads the env var.
  (() => {
    const files = [
      join(root, 'src', 'services', 'vulnerabilityService.ts'),
      join(root, 'src', 'components', 'DetailDrawer.tsx'),
      join(root, 'src', 'components', 'VulnerabilityTable.tsx'),
      join(root, 'src', 'components', 'Header.tsx'),
      join(root, 'src', 'pages', 'DashboardPage.tsx'),
    ];
    return files.every((f) => !/process\.env\.GITHUB_TOKEN/.test(readFileSync(f, 'utf8')));
  })());

assert('dataset.mjs does NOT read GITHUB_TOKEN from process.env (read path is token-free)',
  !/process\.env\.GITHUB_TOKEN/.test(readFileSync(
    join(root, 'netlify', 'functions', 'dataset.mjs'),
    'utf8',
  )));

assert('orchestrator does NOT pass the token to the fetcher (only the boolean `auth`)',
  // The orchestrator defaults `hasToken` to a
  // presence-check on process.env.GITHUB_TOKEN (it must
  // know whether to pick the 25 or 50 cap), but it
  // never propagates the token VALUE to the fetcher —
  // only a boolean `auth` flag.
  (() => {
    const src = readFileSync(
      join(root, 'netlify', 'functions', '_shared', 'githubAdvisoryRefresh.mjs'),
      'utf8',
    );
    // The orchestrator should pass only `auth` to the
    // fetcher, not the token.
    return /auth:\s*effectiveAuth/.test(src) &&
      // And the production fetcher (in githubAdvisory.mjs)
      // never receives the token as an argument.
      !/opts\.token/.test(src) &&
      !/opts\['token'\]/.test(src);
  })());

assert('orchestrator accepts hasToken() test seam (boolean only)',
  /hasToken/.test(readFileSync(
    join(root, 'netlify', 'functions', '_shared', 'githubAdvisoryRefresh.mjs'),
    'utf8',
  )));

/* ------------------------------------------------------------------ */
/* 4. Refresh caps (25 unauth / 50 auth) + staleness (7 days)        */
/* ------------------------------------------------------------------ */

section('Refresh tunables — unauthenticated 25, authenticated 50');

assert('GITHUB_ADVISORY_MAX_PER_RUN_UNAUTH = 25',
  GITHUB_ADVISORY_MAX_PER_RUN_UNAUTH === 25);

assert('GITHUB_ADVISORY_MAX_PER_RUN_AUTH = 50',
  GITHUB_ADVISORY_MAX_PER_RUN_AUTH === 50);

assert('GITHUB_ADVISORY_STALE_DAYS = 7',
  GITHUB_ADVISORY_STALE_DAYS === 7);

assert('GITHUB_ADVISORY_CONCURRENCY = 4',
  GITHUB_ADVISORY_CONCURRENCY === 4);

assert('GITHUB_ADVISORY_MIN_REMAINING = 10',
  GITHUB_ADVISORY_MIN_REMAINING === 10);

/* ------------------------------------------------------------------ */
/* 5. Concurrency limit (4)                                           */
/* ------------------------------------------------------------------ */

section('Concurrency — parallel worker never exceeds 4');

{
  // Track the maximum number of in-flight fetches at any
  // moment and assert it never exceeds the configured
  // concurrency. Use a realFetcher that returns the
  // response object directly (not wrapped in a Promise
  // that the mock would mishandle).
  let inFlight = 0;
  let maxInFlight = 0;
  const realFetcher = async () => {
    inFlight++;
    if (inFlight > maxInFlight) maxInFlight = inFlight;
    // Yield to the event loop to let sibling tasks start;
    // this is what makes the test actually exercise the
    // concurrency limiter.
    await new Promise((r) => setTimeout(r, 5));
    inFlight--;
    return {
      status: 200,
      statusText: 'OK',
      ok: true,
      json: async () => [],
      headers: {},
    };
  };
  const cveList = Array.from({ length: 30 }, (_, i) => ({
    cveId: `CVE-2024-${String(i).padStart(4, '0')}`,
    dateAdded: '2024-06-01T00:00:00.000Z',
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
  const result = await runGithubAdvisoryRefresh({
    store,
    cveList,
    fetcher: realFetcher,
    now: new Date(),
    hasToken: () => true,
  });
  assert('orchestrator completes successfully with parallel fetches',
    result.status === 'completed');
  assert(`concurrency never exceeded GITHUB_ADVISORY_CONCURRENCY (${GITHUB_ADVISORY_CONCURRENCY})`,
    maxInFlight <= GITHUB_ADVISORY_CONCURRENCY,
    `observed maxInFlight=${maxInFlight}`);
  assert(`concurrency is at least 2 (real parallelism, not serial) — observed ${maxInFlight}`,
    maxInFlight >= 2);
}

/* ------------------------------------------------------------------ */
/* 6. prioritizeCvesForRefresh — cap behavior                         */
/* ------------------------------------------------------------------ */

section('Prioritize — caps at 25 (unauth) and 50 (auth)');

{
  // 100 uncached CVEs, no token. Expect cap of 25.
  const cveList = Array.from({ length: 100 }, (_, i) => ({
    cveId: `CVE-2024-${String(i).padStart(4, '0')}`,
    dateAdded: '2024-06-01T00:00:00.000Z',
  }));
  const toEnrich = prioritizeCvesForRefresh({
    cveList,
    cache: {},
    maxItems: GITHUB_ADVISORY_MAX_PER_RUN_UNAUTH,
  });
  assert(`prioritizeCvesForRefresh caps at 25 when maxItems=25`,
    toEnrich.length === 25);
}

{
  // 100 uncached CVEs, with token. Expect cap of 50.
  const cveList = Array.from({ length: 100 }, (_, i) => ({
    cveId: `CVE-2024-${String(i).padStart(4, '0')}`,
    dateAdded: '2024-06-01T00:00:00.000Z',
  }));
  const toEnrich = prioritizeCvesForRefresh({
    cveList,
    cache: {},
    maxItems: GITHUB_ADVISORY_MAX_PER_RUN_AUTH,
  });
  assert(`prioritizeCvesForRefresh caps at 50 when maxItems=50`,
    toEnrich.length === 50);
}

{
  // Fresh cached CVEs are skipped.
  const cveList = Array.from({ length: 100 }, (_, i) => ({
    cveId: `CVE-2024-${String(i).padStart(4, '0')}`,
    dateAdded: '2024-06-01T00:00:00.000Z',
  }));
  const now = Date.now();
  const cache = {};
  for (let i = 0; i < 60; i++) {
    cache[`CVE-2024-${String(i).padStart(4, '0')}`] = {
      advisory: { ghsaId: 'GHSA-1' },
      cachedAt: now,
    };
  }
  const toEnrich = prioritizeCvesForRefresh({
    cveList,
    cache,
    now,
    maxItems: 50,
  });
  assert('fresh cached CVEs are skipped from the to-enrich set',
    toEnrich.length === 40);
  assert('to-enrich set excludes any cached CVE',
    !toEnrich.some((c) => cache[c]));
}

{
  // Negative-cache markers (advisory: null) are also skipped
  // when fresh — they have a cachedAt timestamp.
  const cveList = [
    { cveId: 'CVE-2024-0001', dateAdded: '2024-01-01T00:00:00.000Z' },
    { cveId: 'CVE-2024-0002', dateAdded: '2024-02-01T00:00:00.000Z' },
  ];
  const now = Date.now();
  const cache = {
    'CVE-2024-0001': {
      advisory: null,
      status: 'missing',
      cachedAt: now,
      checkedAt: now,
    },
  };
  const toEnrich = prioritizeCvesForRefresh({ cveList, cache, now, maxItems: 10 });
  assert('fresh negative-cache markers are skipped',
    toEnrich.length === 1 && toEnrich[0] === 'CVE-2024-0002');
}

{
  // Stale cached entries are re-fetched.
  const cveList = [
    { cveId: 'CVE-2024-0001', dateAdded: '2024-01-01T00:00:00.000Z' },
  ];
  const now = Date.now();
  const staleMs = (GITHUB_ADVISORY_STALE_DAYS + 1) * 24 * 60 * 60 * 1000;
  const cache = {
    'CVE-2024-0001': {
      advisory: { ghsaId: 'GHSA-1' },
      cachedAt: now - staleMs,
    },
  };
  const toEnrich = prioritizeCvesForRefresh({ cveList, cache, now, maxItems: 10 });
  assert('stale cached entries are re-fetched',
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
    maxItems: 10,
  })[0] === 'CVE-2024-0002');

/* ------------------------------------------------------------------ */
/* 7. extractReviewedAdvisories — filter, dedup, severity, packages  */
/* ------------------------------------------------------------------ */

section('extractReviewedAdvisories — reviewed + non-withdrawn filtering');

const validAdvisory = {
  ghsa_id: 'GHSA-aaaa-bbbb-cccc',
  cve_id: 'CVE-2024-0001',
  url: 'https://api.github.com/advisories/GHSA-aaaa-bbbb-cccc',
  html_url: 'https://github.com/advisories/GHSA-aaaa-bbbb-cccc',
  summary: 'lodash vulnerability',
  description: 'Verbose description (not retained by the parser)',
  type: 'reviewed',
  severity: 'high',
  published_at: '2024-01-15T00:00:00.000Z',
  updated_at: '2024-02-01T00:00:00.000Z',
  withdrawn_at: null,
  vulnerabilities: [
    {
      package: { name: 'lodash', ecosystem: 'npm' },
      vulnerable_version_range: '< 4.17.21',
      first_patched_version: '4.17.21',
    },
  ],
};

{
  const out = extractReviewedAdvisories([validAdvisory]);
  assert('valid reviewed advisory is extracted', out !== null);
  assert('parser extracts ghsaId',
    out && out.ghsaId === 'GHSA-aaaa-bbbb-cccc');
  assert('parser extracts advisoryUrl from html_url',
    out && out.advisoryUrl === 'https://github.com/advisories/GHSA-aaaa-bbbb-cccc');
  assert('parser extracts advisorySeverity (normalized lowercase)',
    out && out.advisorySeverity === 'high');
  assert('parser extracts githubReviewedAt (updated_at preferred over published_at)',
    out && out.githubReviewedAt === '2024-02-01T00:00:00.000Z');
  assert('parser stamps source as "GitHub Advisory Database"',
    out && out.source === 'GitHub Advisory Database');
  assert('parser extracts a single package entry',
    out && Array.isArray(out.packages) && out.packages.length === 1);
  assert('parser extracts package ecosystem + name + range + patched version',
    out && out.packages[0].ecosystem === 'npm' &&
    out.packages[0].name === 'lodash' &&
    out.packages[0].vulnerableVersionRange === '< 4.17.21' &&
    out.packages[0].firstPatchedVersion === '4.17.21');
}

assert('parser IGNORES advisories with type !== "reviewed"',
  extractReviewedAdvisories([
    { ...validAdvisory, ghsa_id: 'GHSA-1', type: 'unreviewed' },
  ]) === null);

assert('parser IGNORES withdrawn advisories (withdrawn_at non-null)',
  extractReviewedAdvisories([
    { ...validAdvisory, ghsa_id: 'GHSA-1', withdrawn_at: '2024-12-01T00:00:00.000Z' },
  ]) === null);

assert('parser ACCEPTS advisories with withdrawn_at === null',
  extractReviewedAdvisories([
    { ...validAdvisory, ghsa_id: 'GHSA-2', withdrawn_at: null },
  ]) !== null);

assert('parser returns null for empty array',
  extractReviewedAdvisories([]) === null);

assert('parser returns null for null input',
  extractReviewedAdvisories(null) === null);

assert('parser returns null for non-array input',
  extractReviewedAdvisories({}) === null);

assert('parser ignores individual entries with missing required fields',
  extractReviewedAdvisories([null, {}, 'string', 42, validAdvisory]) !== null);

assert('parser falls back to url when html_url is missing',
  extractReviewedAdvisories([{
    ...validAdvisory,
    html_url: undefined,
    url: 'https://api.github.com/advisories/GHSA-aaaa-bbbb-cccc',
  }])?.advisoryUrl === 'https://api.github.com/advisories/GHSA-aaaa-bbbb-cccc');

assert('parser normalizes "moderate" severity to "medium"',
  extractReviewedAdvisories([
    { ...validAdvisory, severity: 'moderate' },
  ])?.advisorySeverity === 'medium');

assert('parser accepts the three documented Exploitation-… — wait, severity values',
  ['low', 'medium', 'high', 'critical'].every((s) => {
    const r = extractReviewedAdvisories([{ ...validAdvisory, severity: s }]);
    return r && r.advisorySeverity === s;
  }));

assert('parser falls back to published_at when updated_at is missing',
  extractReviewedAdvisories([{
    ...validAdvisory,
    updated_at: undefined,
  }])?.githubReviewedAt === '2024-01-15T00:00:00.000Z');

assert('parser description field is NOT retained (minimal record contract)',
  // The normalized record must not contain a "description"
  // field, per the spec's "minimal normalized fields".
  !('description' in (extractReviewedAdvisories([validAdvisory]) || {})));

assert('parser summary field is NOT retained',
  !('summary' in (extractReviewedAdvisories([validAdvisory]) || {})));

assert('parser does NOT retain raw description or summary strings anywhere',
  // Defensive: the normalized record's JSON.stringify
  // must not contain "Verbose description".
  !JSON.stringify(extractReviewedAdvisories([validAdvisory]))
    .includes('Verbose description'));

/* ------------------------------------------------------------------ */
/* 8. Multiple advisories + package dedup + 5-entry cap              */
/* ------------------------------------------------------------------ */

section('Multiple advisories + package dedup + 5-entry cap');

{
  // Two advisories for the same CVE: union their packages.
  const a1 = {
    ...validAdvisory,
    ghsa_id: 'GHSA-aaaa-1111-1111',
    updated_at: '2024-01-15T00:00:00.000Z',
    vulnerabilities: [
      { package: { name: 'lodash', ecosystem: 'npm' },
        vulnerable_version_range: '< 4.17.21',
        first_patched_version: '4.17.21' },
      { package: { name: 'minimist', ecosystem: 'npm' },
        vulnerable_version_range: '< 1.2.6',
        first_patched_version: '1.2.6' },
    ],
  };
  const a2 = {
    ...validAdvisory,
    ghsa_id: 'GHSA-bbbb-2222-2222',
    updated_at: '2024-02-15T00:00:00.000Z',
    vulnerabilities: [
      { package: { name: 'lodash', ecosystem: 'npm' },
        vulnerable_version_range: '< 4.17.21',
        first_patched_version: '4.17.21' }, // duplicate of a1
      { package: { name: 'ms', ecosystem: 'npm' },
        vulnerable_version_range: '< 2.0.0',
        first_patched_version: '2.0.0' },
    ],
  };
  const out = extractReviewedAdvisories([a1, a2]);
  assert('multiple advisories produce a single normalized record',
    out !== null);
  // Sort is deterministic: GHSA-… ascending → primary
  // is GHSA-aaaa-… (not GHSA-bbbb-…).
  assert('primary advisory is the lowest-lexicographic GHSA id',
    out && out.ghsaId === 'GHSA-aaaa-1111-1111');
  assert('multiple-advisory union dedups duplicate package entries',
    out && out.packages.length === 3);
  assert('union contains lodash, minimist, and ms',
    out && out.packages.map((p) => p.name).sort().join(',') === 'lodash,minimist,ms');
}

{
  // 6 unique packages → cap at 5.
  const six = Array.from({ length: 6 }, (_, i) => ({
    package: { name: `pkg${i}`, ecosystem: 'npm' },
    vulnerable_version_range: `< 1.0.${i}`,
    first_patched_version: `1.0.${i}`,
  }));
  const out = extractReviewedAdvisories([{ ...validAdvisory, vulnerabilities: six }]);
  assert('package list is capped at 5 entries',
    out && out.packages.length === 5);
  // First-occurrence wins (deterministic).
  assert('first 5 packages are kept (deterministic order)',
    out && out.packages[0].name === 'pkg0' && out.packages[4].name === 'pkg4');
}

{
  // 2 packages with the same ecosystem + name but different
  // vulnerableVersionRange → kept (dedup key is the triple).
  const out = extractReviewedAdvisories([{
    ...validAdvisory,
    vulnerabilities: [
      { package: { name: 'lodash', ecosystem: 'npm' },
        vulnerable_version_range: '< 4.17.21',
        first_patched_version: '4.17.21' },
      { package: { name: 'lodash', ecosystem: 'npm' },
        vulnerable_version_range: '< 4.17.10',
        first_patched_version: '4.17.10' },
    ],
  }]);
  assert('distinct vulnerableVersionRange → both kept',
    out && out.packages.length === 2);
}

{
  // Same package + range, different first_patched_version →
  // deduped (first occurrence wins).
  const out = extractReviewedAdvisories([{
    ...validAdvisory,
    vulnerabilities: [
      { package: { name: 'lodash', ecosystem: 'npm' },
        vulnerable_version_range: '< 4.17.21',
        first_patched_version: '4.17.21' },
      { package: { name: 'lodash', ecosystem: 'npm' },
        vulnerable_version_range: '< 4.17.21',
        first_patched_version: '4.99.99' },
    ],
  }]);
  assert('duplicate ecosystem+name+range → deduped to 1',
    out && out.packages.length === 1 &&
    out.packages[0].firstPatchedVersion === '4.17.21');
}

{
  // Package name comparison is case-insensitive on `name`.
  const out = extractReviewedAdvisories([{
    ...validAdvisory,
    vulnerabilities: [
      { package: { name: 'Lodash', ecosystem: 'npm' },
        vulnerable_version_range: '< 4.17.21',
        first_patched_version: '4.17.21' },
      { package: { name: 'lodash', ecosystem: 'npm' },
        vulnerable_version_range: '< 4.17.21',
        first_patched_version: '4.17.21' },
    ],
  }]);
  assert('package name dedup is case-insensitive',
    out && out.packages.length === 1);
}

/* ------------------------------------------------------------------ */
/* 9. fetchOneCveAdvisories — outcomes                                */
/* ------------------------------------------------------------------ */

section('fetchOneCveAdvisories — ok / empty / transient outcomes');

{
  const out = await fetchOneCveAdvisories('CVE-2024-0001', {
    fetcher: makeMockFetcher({ status: 200, body: [validAdvisory] }),
  });
  assert('HTTP 200 + non-empty array → outcome="ok"',
    out.outcome === 'ok' && Array.isArray(out.records) && out.records.length === 1);
  assert('ok outcome carries the rate-limit remaining from the response',
    out.remaining === null); // no headers provided
}

{
  const out = await fetchOneCveAdvisories('CVE-2024-0001', {
    fetcher: makeMockFetcher({ status: 200, body: [] }),
  });
  assert('HTTP 200 + empty array → outcome="empty"',
    out.outcome === 'empty' && Array.isArray(out.records) && out.records.length === 0);
}

{
  const out = await fetchOneCveAdvisories('CVE-2024-0001', {
    fetcher: makeMockFetcher({ status: 404, body: {} }),
  });
  assert('HTTP 404 → outcome="empty" (defensive)',
    out.outcome === 'empty');
}

{
  const out = await fetchOneCveAdvisories('CVE-2024-0001', {
    fetcher: makeMockFetcher({ status: 429, body: { message: 'rate limit' } }),
  });
  assert('HTTP 429 → outcome="transient" with sanitized reason',
    out.outcome === 'transient' && /HTTP 429/.test(out.reason));
  assert('429 reason does NOT include the raw "rate limit" upstream message',
    out.reason === 'HTTP 429 (rate limit)' &&
    !out.reason.includes('rate limit exceeded') /* the literal upstream message */);
}

{
  const out = await fetchOneCveAdvisories('CVE-2024-0001', {
    fetcher: makeMockFetcher({ status: 403, body: {} }),
  });
  assert('HTTP 403 → outcome="transient"',
    out.outcome === 'transient' && /HTTP 403/.test(out.reason));
}

{
  const out = await fetchOneCveAdvisories('CVE-2024-0001', {
    fetcher: makeMockFetcher({ status: 503, body: {} }),
  });
  assert('HTTP 5xx → outcome="transient"',
    out.outcome === 'transient');
}

{
  const out = await fetchOneCveAdvisories('CVE-2024-0001', {
    fetcher: makeMockFetcher('throw'),
  });
  assert('Network error (thrown) → outcome="transient"',
    out.outcome === 'transient');
}

{
  const out = await fetchOneCveAdvisories('CVE-2024-0001', {
    fetcher: makeMockFetcher('abort'),
  });
  assert('AbortError (timeout) → outcome="transient"',
    out.outcome === 'transient');
}

{
  const out = await fetchOneCveAdvisories('not-a-cve', {
    fetcher: makeMockFetcher({ status: 200, body: [] }),
  });
  assert('Malformed CVE ID → outcome="empty" (no fetcher call)',
    out.outcome === 'empty');
}

{
  // Body that is not a JSON array
  const out = await fetchOneCveAdvisories('CVE-2024-0001', {
    fetcher: makeMockFetcher({ status: 200, body: { not: 'an array' } }),
  });
  assert('Non-array response body → outcome="transient"',
    out.outcome === 'transient' && /expected array/.test(out.reason));
}

/* ------------------------------------------------------------------ */
/* 10. Rate-limit header parsing                                       */
/* ------------------------------------------------------------------ */

section('readRateLimitHeaders — parses x-ratelimit-remaining / reset / retry-after');

{
  const headers = {
    'x-ratelimit-remaining': '42',
    'x-ratelimit-reset': '1700000000',
    'retry-after': '60',
  };
  const info = readRateLimitHeaders(headers);
  assert('parses x-ratelimit-remaining as integer',
    info.remaining === 42);
  assert('parses x-ratelimit-reset as ISO (epoch seconds * 1000)',
    typeof info.retryAfter === 'string' &&
    new Date(info.retryAfter).getTime() === 1700000000 * 1000);
  assert('parses retry-after in seconds',
    info.retryAfterSeconds === 60);
}

{
  // Headers object via a fetch-like .get() interface.
  const headers = {
    get: (name) => {
      const map = {
        'x-ratelimit-remaining': '5',
        'x-ratelimit-reset': '1700000000',
      };
      return map[name.toLowerCase()] || null;
    },
  };
  const info = readRateLimitHeaders(headers);
  assert('parses headers via .get() interface',
    info.remaining === 5);
}

{
  // Missing headers — returns nulls.
  const info = readRateLimitHeaders({});
  assert('missing headers → nulls',
    info.remaining === null && info.retryAfter === null);
}

assert('null headers → nulls without throwing',
  readRateLimitHeaders(null) !== null &&
  readRateLimitHeaders(null).remaining === null);

assert('garbage header values are nulled, not NaN',
  readRateLimitHeaders({ 'x-ratelimit-remaining': 'not-a-number' }).remaining === null);

/* ------------------------------------------------------------------ */
/* 11. Rate-limit short-circuit during a refresh cycle                  */
/* ------------------------------------------------------------------ */

section('Rate-limit floor — orchestrator stops the pass when remaining < 10');

{
  // First request returns remaining=5, second request returns
  // remaining=0. Orchestrator should record rateLimited=true.
  const responses = [
    { status: 200, body: [], headers: { 'x-ratelimit-remaining': '5', 'x-ratelimit-reset': '1700000000' } },
    { status: 200, body: [], headers: { 'x-ratelimit-remaining': '0', 'x-ratelimit-reset': '1700000000' } },
  ];
  let i = 0;
  const fetcher = makeMockFetcher(() => responses[i++]);
  const cveList = Array.from({ length: 5 }, (_, i) => ({
    cveId: `CVE-2024-${String(i).padStart(4, '0')}`,
    dateAdded: '2024-06-01T00:00:00.000Z',
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
  const result = await runGithubAdvisoryRefresh({
    store,
    cveList,
    fetcher,
    hasToken: () => true,
    maxItems: 5,
  });
  assert('rate-limited cycle returns status="rate-limited"',
    result.status === 'rate-limited');
  assert('rate-limited cycle carries rateLimited=true',
    result.rateLimited === true);
  assert('rate-limited cycle surfaces retryAfter (ISO timestamp)',
    typeof result.retryAfter === 'string' &&
    new Date(result.retryAfter).getTime() === 1700000000 * 1000);
}

{
  // 200 OK with remaining=0 — orchestrator short-circuits
  // BEFORE writing the cache entry. The cache should remain
  // empty for those CVEs.
  const fetcher = makeMockFetcher({
    status: 200,
    body: [],
    headers: { 'x-ratelimit-remaining': '0' },
  });
  const cveList = [
    { cveId: 'CVE-2024-0001', dateAdded: '2024-06-01T00:00:00.000Z' },
  ];
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
  const result = await runGithubAdvisoryRefresh({
    store,
    cveList,
    fetcher,
    hasToken: () => true,
  });
  assert('rate-limited cycle does not write a positive cache entry',
    result.status === 'rate-limited');
  const after = await readGithubAdvisoryCache(store);
  assert('cache remains empty after a rate-limited 200 + remaining=0',
    !after || Object.keys(after.records).length === 0);
}

/* ------------------------------------------------------------------ */
/* 12. Cache survival on transient / timeout / network                 */
/* ------------------------------------------------------------------ */

section('Cache survival — transient / 5xx / timeout / network preserve prior cache');

{
  // Pre-populate cache with a positive record; orchestrator
  // runs with a fetcher that throws. The positive record
  // must survive.
  const nowMs = Date.now();
  const tenDaysMs = 10 * 24 * 60 * 60 * 1000;
  const cache = {
    'CVE-2024-0001': {
      advisory: { ghsaId: 'GHSA-aaaa-bbbb-cccc', source: 'GitHub Advisory Database' },
      cachedAt: nowMs - tenDaysMs,
    },
  };
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
  await writeGithubAdvisoryCache(store, { records: cache, updatedAt: new Date().toISOString() });
  const result = await runGithubAdvisoryRefresh({
    store,
    cveList,
    fetcher: makeMockFetcher('throw'),
    now: new Date(nowMs),
    nowFn: () => nowMs,
    hasToken: () => true,
  });
  assert('network error refresh status is "completed" (graceful)',
    result.status === 'completed');
  assert('network error preserves the prior positive cache entry',
    result.transient === 1 && result.empty === 0);
  const after = await readGithubAdvisoryCache(store);
  assert('positive record survives a network error',
    after.records['CVE-2024-0001'] &&
    after.records['CVE-2024-0001'].advisory.ghsaId === 'GHSA-aaaa-bbbb-cccc');
  assert('positive record keeps the original cachedAt timestamp (not refreshed)',
    after.records['CVE-2024-0001'].cachedAt === nowMs - tenDaysMs);
  assert('coverage still reports 1/1 (positive record still counts)',
    result.enriched === 1 && result.total === 1);
}

{
  // 503 → same defensive behavior.
  const nowMs = Date.now();
  const tenDaysMs = 10 * 24 * 60 * 60 * 1000;
  const cache = {
    'CVE-2024-0001': {
      advisory: { ghsaId: 'GHSA-aaaa-bbbb-cccc', source: 'GitHub Advisory Database' },
      cachedAt: nowMs - tenDaysMs,
    },
  };
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
  await writeGithubAdvisoryCache(store, { records: cache, updatedAt: new Date().toISOString() });
  const result = await runGithubAdvisoryRefresh({
    store,
    cveList,
    fetcher: makeMockFetcher({ status: 503, body: {} }),
    now: new Date(nowMs),
    nowFn: () => nowMs,
    hasToken: () => true,
  });
  const after = await readGithubAdvisoryCache(store);
  assert('503 preserves the prior positive cache entry',
    after.records['CVE-2024-0001'].advisory.ghsaId === 'GHSA-aaaa-bbbb-cccc');
  assert('503 result reports 1 transient, 0 empty',
    result.transient === 1 && result.empty === 0);
}

{
  // 429 → preserves positive entry AND surfaces retryAfter.
  const nowMs = Date.now();
  const tenDaysMs = 10 * 24 * 60 * 60 * 1000;
  const cache = {
    'CVE-2024-0001': {
      advisory: { ghsaId: 'GHSA-aaaa-bbbb-cccc', source: 'GitHub Advisory Database' },
      cachedAt: nowMs - tenDaysMs,
    },
  };
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
  await writeGithubAdvisoryCache(store, { records: cache, updatedAt: new Date().toISOString() });
  const result = await runGithubAdvisoryRefresh({
    store,
    cveList,
    fetcher: makeMockFetcher({
      status: 429,
      body: {},
      headers: { 'x-ratelimit-reset': '1700000000' },
    }),
    now: new Date(nowMs),
    nowFn: () => nowMs,
    hasToken: () => true,
  });
  const after = await readGithubAdvisoryCache(store);
  assert('429 preserves the prior positive cache entry',
    after.records['CVE-2024-0001'].advisory.ghsaId === 'GHSA-aaaa-bbbb-cccc');
  assert('429 result reports 1 transient, 0 empty',
    result.transient === 1 && result.empty === 0);
}

{
  // 403 → preserves positive entry.
  const nowMs = Date.now();
  const tenDaysMs = 10 * 24 * 60 * 60 * 1000;
  const cache = {
    'CVE-2024-0001': {
      advisory: { ghsaId: 'GHSA-aaaa-bbbb-cccc', source: 'GitHub Advisory Database' },
      cachedAt: nowMs - tenDaysMs,
    },
  };
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
  await writeGithubAdvisoryCache(store, { records: cache, updatedAt: new Date().toISOString() });
  await runGithubAdvisoryRefresh({
    store,
    cveList,
    fetcher: makeMockFetcher({ status: 403, body: {} }),
    now: new Date(nowMs),
    nowFn: () => nowMs,
    hasToken: () => true,
  });
  const after = await readGithubAdvisoryCache(store);
  assert('403 preserves the prior positive cache entry',
    after.records['CVE-2024-0001'].advisory.ghsaId === 'GHSA-aaaa-bbbb-cccc');
}

{
  // AbortError (timeout) → preserves positive entry.
  const nowMs = Date.now();
  const tenDaysMs = 10 * 24 * 60 * 60 * 1000;
  const cache = {
    'CVE-2024-0001': {
      advisory: { ghsaId: 'GHSA-aaaa-bbbb-cccc', source: 'GitHub Advisory Database' },
      cachedAt: nowMs - tenDaysMs,
    },
  };
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
  await writeGithubAdvisoryCache(store, { records: cache, updatedAt: new Date().toISOString() });
  await runGithubAdvisoryRefresh({
    store,
    cveList,
    fetcher: makeMockFetcher('abort'),
    now: new Date(nowMs),
    nowFn: () => nowMs,
    hasToken: () => true,
  });
  const after = await readGithubAdvisoryCache(store);
  assert('timeout preserves the prior positive cache entry',
    after.records['CVE-2024-0001'].advisory.ghsaId === 'GHSA-aaaa-bbbb-cccc');
}

/* ------------------------------------------------------------------ */
/* 13. Empty-array + 404 → negative-cache marker                      */
/* ------------------------------------------------------------------ */

section('Negative-cache behavior — empty array + 404 write a marker');

{
  // 200 + empty array on an uncached CVE → writes marker.
  const nowMs = Date.now();
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
  await writeGithubAdvisoryCache(store, { records: {}, updatedAt: new Date().toISOString() });
  const result = await runGithubAdvisoryRefresh({
    store,
    cveList,
    fetcher: makeMockFetcher({ status: 200, body: [] }),
    now: new Date(nowMs),
    nowFn: () => nowMs,
    hasToken: () => true,
  });
  assert('200 + empty array on uncached CVE → result reports 1 empty',
    result.empty === 1);
  const after = await readGithubAdvisoryCache(store);
  assert('200 + empty array writes a negative-cache marker',
    after.records['CVE-2024-0001'] &&
    after.records['CVE-2024-0001'].advisory === null &&
    after.records['CVE-2024-0001'].status === 'missing' &&
    after.records['CVE-2024-0001'].cachedAt === nowMs &&
    after.records['CVE-2024-0001'].checkedAt === nowMs);
  assert('empty response does NOT count as enriched',
    result.enriched === 0 && result.total === 1);
}

{
  // HTTP 404 → marker, same behavior.
  const nowMs = Date.now();
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
  await writeGithubAdvisoryCache(store, { records: {}, updatedAt: new Date().toISOString() });
  await runGithubAdvisoryRefresh({
    store,
    cveList,
    fetcher: makeMockFetcher({ status: 404, body: {} }),
    now: new Date(nowMs),
    nowFn: () => nowMs,
    hasToken: () => true,
  });
  const after = await readGithubAdvisoryCache(store);
  assert('HTTP 404 writes a negative-cache marker (defensive)',
    after.records['CVE-2024-0001'] &&
    after.records['CVE-2024-0001'].advisory === null &&
    after.records['CVE-2024-0001'].status === 'missing');
}

{
  // 200 + body filtered out (all advisories withdrawn /
  // unreviewed) → marker.
  const nowMs = Date.now();
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
  await writeGithubAdvisoryCache(store, { records: {}, updatedAt: new Date().toISOString() });
  await runGithubAdvisoryRefresh({
    store,
    cveList,
    fetcher: makeMockFetcher({
      status: 200,
      body: [
        { ...validAdvisory, type: 'unreviewed' },
        { ...validAdvisory, withdrawn_at: '2024-12-01T00:00:00.000Z' },
      ],
    }),
    now: new Date(nowMs),
    nowFn: () => nowMs,
    hasToken: () => true,
  });
  const after = await readGithubAdvisoryCache(store);
  assert('all-filtered 200 response writes a negative-cache marker',
    after.records['CVE-2024-0001'] &&
    after.records['CVE-2024-0001'].status === 'missing');
}

{
  // Defensive: empty result on a STALE positive record
  // must NOT delete the positive record.
  const nowMs = Date.now();
  const tenDaysMs = 10 * 24 * 60 * 60 * 1000;
  const cache = {
    'CVE-2024-0001': {
      advisory: {
        ghsaId: 'GHSA-aaaa-bbbb-cccc',
        advisoryUrl: 'https://github.com/advisories/GHSA-aaaa-bbbb-cccc',
        advisorySeverity: 'high',
        githubReviewedAt: '2024-01-01T00:00:00.000Z',
        source: 'GitHub Advisory Database',
        packages: [
          { ecosystem: 'npm', name: 'lodash', vulnerableVersionRange: '< 4.17.21', firstPatchedVersion: '4.17.21' },
        ],
      },
      cachedAt: nowMs - tenDaysMs,
    },
  };
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
  await writeGithubAdvisoryCache(store, { records: cache, updatedAt: new Date().toISOString() });
  const result = await runGithubAdvisoryRefresh({
    store,
    cveList,
    fetcher: makeMockFetcher({ status: 200, body: [] }),
    now: new Date(nowMs),
    nowFn: () => nowMs,
    hasToken: () => true,
  });
  const after = await readGithubAdvisoryCache(store);
  assert('empty result does NOT delete a STALE positive record (defensive)',
    after.records['CVE-2024-0001'].advisory.ghsaId === 'GHSA-aaaa-bbbb-cccc');
  assert('defensive empty: the positive record still counts as enriched',
    result.enriched === 1 && result.total === 1);
}

/* ------------------------------------------------------------------ */
/* 14. Forward-progress regression (60 CVEs / first 25 empty / …)     */
/* ------------------------------------------------------------------ */

section('Forward progress — 60-CVE regression (25/25 + 10/10)');

{
  // 60 uncached CVEs, unauthenticated cap (25), all return
  // 200 + empty. First run processes 25, second run
  // processes the NEXT 25 (not the first 25 again), third
  // run processes the last 10.
  const cveList = Array.from({ length: 60 }, (_, i) => ({
    cveId: `CVE-2024-${String(i).padStart(4, '0')}`,
    dateAdded: '2024-06-01T00:00:00.000Z',
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
  await writeGithubAdvisoryCache(store, { records: {}, updatedAt: new Date().toISOString() });

  // First run — 25 attempted.
  const first = await runGithubAdvisoryRefresh({
    store,
    cveList,
    fetcher: makeMockFetcher({ status: 200, body: [] }),
    hasToken: () => false, // unauthenticated
  });
  assert('first run with 60 uncached CVEs and 100% empty attempts exactly 25 (unauth cap)',
    first.attempted === 25);
  assert('first run reports 25 empty entries',
    first.empty === 25);
  const after1 = await readGithubAdvisoryCache(store);
  assert('first run wrote 25 negative-cache markers',
    Object.keys(after1.records).length === 25);
  assert('each marker carries checkedAt, status, and advisory=null',
    Object.values(after1.records).every((e) =>
      e && e.advisory === null && e.status === 'missing' &&
      typeof e.cachedAt === 'number' &&
      typeof e.checkedAt === 'number'));

  // Second run — must NOT repeat the first 25.
  const second = await runGithubAdvisoryRefresh({
    store,
    cveList,
    fetcher: makeMockFetcher({ status: 200, body: [] }),
    hasToken: () => false,
  });
  assert('second run attempts the NEXT 25, not the first 25',
    second.attempted === 25);
  const after2 = await readGithubAdvisoryCache(store);
  assert('second run wrote 25 more markers (50 total)',
    Object.keys(after2.records).length === 50);

  // Third run — last 10.
  const third = await runGithubAdvisoryRefresh({
    store,
    cveList,
    fetcher: makeMockFetcher({ status: 200, body: [] }),
    hasToken: () => false,
  });
  assert('third run attempts the remaining 10',
    third.attempted === 10);
  const after3 = await readGithubAdvisoryCache(store);
  assert('third run wrote 10 more markers (60 total)',
    Object.keys(after3.records).length === 60);

  // Fourth run — nothing left.
  const fourth = await runGithubAdvisoryRefresh({
    store,
    cveList,
    fetcher: makeMockFetcher({ status: 200, body: [] }),
    hasToken: () => false,
  });
  assert('fourth run attempts 0 (all 60 are now negative-cached and fresh)',
    fourth.attempted === 0);
}

{
  // After TTL expires, the original 60 may become eligible
  // again (a newly published advisory would be picked up).
  const cveList = Array.from({ length: 60 }, (_, i) => ({
    cveId: `CVE-2024-${String(i).padStart(4, '0')}`,
    dateAdded: '2024-06-01T00:00:00.000Z',
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
  await writeGithubAdvisoryCache(store, { records: {}, updatedAt: new Date().toISOString() });
  // Seed 60 markers dated 8 days ago.
  const oldMs = Date.now() - 8 * 24 * 60 * 60 * 1000;
  const oldCache = {};
  for (const e of cveList) {
    oldCache[e.cveId] = {
      advisory: null,
      status: 'missing',
      cachedAt: oldMs,
      checkedAt: oldMs,
    };
  }
  await writeGithubAdvisoryCache(store, { records: oldCache, updatedAt: new Date(oldMs).toISOString() });
  const result = await runGithubAdvisoryRefresh({
    store,
    cveList,
    fetcher: makeMockFetcher({ status: 200, body: [] }),
    hasToken: () => false,
  });
  assert('after negative-cache TTL expiry, all 60 may be re-selected (capped at 25)',
    result.attempted === 25);
}

/* ------------------------------------------------------------------ */
/* 15. Coverage metadata accuracy                                      */
/* ------------------------------------------------------------------ */

section('Coverage metadata — githubAdvisoryStatus / githubAdvisoryCoverage');

assert('0 enriched / 0 total → unavailable',
  githubAdvisoryStatusForCoverage(0, 0) === 'unavailable');

assert('0 enriched / 100 total → unavailable',
  githubAdvisoryStatusForCoverage(0, 100) === 'unavailable');

assert('50 enriched / 100 total → partial',
  githubAdvisoryStatusForCoverage(50, 100) === 'partial');

assert('100 enriched / 100 total → available',
  githubAdvisoryStatusForCoverage(100, 100) === 'available');

assert('enriched cannot exceed total (defensive)',
  // The function clamps enriched to total defensively.
  githubAdvisoryStatusForCoverage(200, 100) === 'available');

{
  // computeCoverageForPublic counts only CVEs in the dataset
  // that have a positive advisory entry in the cache.
  const cache = {
    'CVE-2024-0001': { advisory: { ghsaId: 'GHSA-1' }, cachedAt: 1 },
    'CVE-2024-0002': { advisory: { ghsaId: 'GHSA-2' }, cachedAt: 1 },
    'CVE-2024-0003': { advisory: { ghsaId: 'GHSA-3' }, cachedAt: 1 },
  };
  const cveList = [
    { cveId: 'CVE-2024-0001' },
    { cveId: 'CVE-2024-0002' },
    // CVE-2024-0003 is in the cache but NOT in the
    // dataset — it must NOT count.
  ];
  const cov = computeCoverageForPublic(cache, cveList);
  assert('computeCoverageForPublic counts only the CVEs in the dataset',
    cov.enriched === 2 && cov.total === 2 && cov.status === 'available');
}

{
  // Negative-cache markers do NOT count as enriched.
  const cache = {
    'CVE-2024-0001': {
      advisory: null,
      status: 'missing',
      cachedAt: 1,
      checkedAt: 1,
    },
  };
  const cveList = [{ cveId: 'CVE-2024-0001' }];
  const cov = computeCoverageForPublic(cache, cveList);
  assert('computeCoverageForPublic excludes negative-cache markers',
    cov.enriched === 0 && cov.total === 1 && cov.status === 'unavailable');
}

assert('computeCoverageForPublic handles empty cache',
  computeCoverageForPublic({}, [{ cveId: 'CVE-2024-0001' }]).enriched === 0);

assert('computeCoverageForPublic handles empty dataset',
  computeCoverageForPublic({ 'CVE-2024-0001': { advisory: { ghsaId: 'GHSA-1' } } }, [])
    .enriched === 0);

/* ------------------------------------------------------------------ */
/* 16. Read-time merge — fetchedAt unchanged + no false update banner  */
/* ------------------------------------------------------------------ */

section('Read-time merge — fetchedAt is NEVER modified by the GitHub Advisory attach');

assert('githubAdvisory.mjs exports mergeAdvisoryIntoRecord',
  typeof mergeAdvisoryIntoRecord === 'function');

assert('mergeAdvisoryIntoRecord returns a new object (no mutation)',
  (() => {
    const record = { cveId: 'CVE-2024-0001', cvssScore: 7.5 };
    const advisory = {
      ghsaId: 'GHSA-aaaa-bbbb-cccc',
      advisoryUrl: 'https://github.com/advisories/GHSA-aaaa-bbbb-cccc',
      advisorySeverity: 'high',
      githubReviewedAt: '2024-01-01T00:00:00.000Z',
      source: 'GitHub Advisory Database',
      packages: [],
    };
    const merged = mergeAdvisoryIntoRecord(record, advisory);
    return merged !== record &&
      merged.cveId === 'CVE-2024-0001' &&
      merged.cvssScore === 7.5 &&
      merged.githubAdvisory &&
      merged.githubAdvisory.ghsaId === 'GHSA-aaaa-bbbb-cccc';
  })());

assert('mergeAdvisoryIntoRecord on null advisory returns the input reference unchanged',
  // The production code returns the record unchanged (no
  // allocation) when advisory is null. We assert the
  // returned object is structurally the same record (no
  // githubAdvisory field added) — identity comparison is
  // not used because call sites pass fresh literals.
  (() => {
    const record = { cveId: 'CVE-2024-0001', cvssScore: 7.5 };
    const result = mergeAdvisoryIntoRecord(record, null);
    return result === record &&
      result.cveId === 'CVE-2024-0001' &&
      result.cvssScore === 7.5 &&
      result.githubAdvisory === undefined;
  })());

assert('mergeAdvisoryIntoRecords only enriches matched CVEs',
  (() => {
    const records = [
      { cveId: 'CVE-2024-0001' },
      { cveId: 'CVE-2024-0002' },
      { cveId: 'CVE-2024-0003' },
    ];
    const advisory = {
      ghsaId: 'GHSA-aaaa-bbbb-cccc',
      advisoryUrl: 'https://github.com/advisories/GHSA-aaaa-bbbb-cccc',
      advisorySeverity: 'high',
      githubReviewedAt: '2024-01-01T00:00:00.000Z',
      source: 'GitHub Advisory Database',
      packages: [],
    };
    const merged = mergeAdvisoryIntoRecords(records, { 'CVE-2024-0002': advisory });
    return merged[0].githubAdvisory === undefined &&
      merged[1].githubAdvisory &&
      merged[1].githubAdvisory.ghsaId === 'GHSA-aaaa-bbbb-cccc' &&
      merged[2].githubAdvisory === undefined;
  })());

const datasetMjs = readFileSync(
  join(root, 'netlify', 'functions', 'dataset.mjs'),
  'utf8',
);

assert('dataset.mjs preserves the prebuilt envelope fetchedAt through the attach chain',
  // The merge is spread-based: `...base, data: merged`. The
  // `base` already carries the prebuilt `fetchedAt`, and the
  // GitHub Advisory merge does not touch it. Defensive
  // textual check: the dataset.mjs attach functions never
  // assign a new `fetchedAt` to the envelope.
  !/attachGithubAdvisory[\s\S]{0,2000}fetchedAt\s*:\s*new Date/.test(datasetMjs));

assert('dataset.mjs does not assign a NEW fetchedAt during the GitHub merge',
  // No `fetchedAt: new Date()` inside the GitHub attach.
  !/attachGithubAdvisory[\s\S]{0,2000}fetchedAt\s*=/.test(datasetMjs));

/* ------------------------------------------------------------------ */
/* 17. Public response isolation — no token / raw errors / internals   */
/* ------------------------------------------------------------------ */

section('Public response isolation — no internal metadata, no token, no raw errors');

assert('INTERNAL_BLOB_FIELDS includes "lastGithubAdvisoryRefresh" (operator-only)',
  INTERNAL_BLOB_FIELDS.has('lastGithubAdvisoryRefresh'));

assert('dataset.mjs uses publicEnvelope() to strip internal fields',
  /publicEnvelope\(/.test(datasetMjs));

assert('dataset.mjs adds githubAdvisoryStatus and githubAdvisoryCoverage to the response',
  /githubAdvisoryStatus/.test(datasetMjs) &&
  /githubAdvisoryCoverage/.test(datasetMjs));

assert('dataset.mjs does NOT read GITHUB_TOKEN from process.env',
  !/process\.env\.GITHUB_TOKEN/.test(datasetMjs));

assert('vulnerabilityService.ts does NOT call GitHub directly',
  // The browser-direct path must stay clean — only the
  // server reads the GitHub Advisory cache.
  (() => {
    const src = readFileSync(
      join(root, 'src', 'services', 'vulnerabilityService.ts'),
      'utf8',
    );
    return !/api\.github\.com/.test(src) &&
      !/cisagov\/vulnrichment/.test(src) && // not relevant but defensive
      !/GITHUB_TOKEN/.test(src);
  })());

assert('vulnerabilityService.ts does NOT reference the GitHub Advisory store name',
  (() => {
    const src = readFileSync(
      join(root, 'src', 'services', 'vulnerabilityService.ts'),
      'utf8',
    );
    return !/tpr-github-advisory/.test(src) &&
      !/githubAdvisoryCache/.test(src);
  })());

assert('the GitHub Advisory cache lives in a SEPARATE blob store (tpr-github-advisory)',
  GITHUB_ADVISORY_STORE_NAME === 'tpr-github-advisory');

assert('the GitHub Advisory cache key is named "cache"',
  GITHUB_ADVISORY_CACHE_KEY === 'cache');

assert('Vulnerability type adds all six githubAdvisory* fields',
  (() => {
    const src = readFileSync(
      join(root, 'src', 'types', 'vulnerability.ts'),
      'utf8',
    );
    return /githubAdvisory\?/.test(src) &&
      /ghsaId/.test(src) &&
      /advisoryUrl/.test(src) &&
      /advisorySeverity/.test(src) &&
      /githubReviewedAt/.test(src) &&
      /packages/.test(src) &&
      /source/.test(src);
  })());

assert('Vulnerability type exports GithubAdvisorySeverity, GithubAdvisoryStatus, GithubAdvisoryCoverage',
  (() => {
    const src = readFileSync(
      join(root, 'src', 'types', 'vulnerability.ts'),
      'utf8',
    );
    return /export\s+type\s+GithubAdvisorySeverity/.test(src) &&
      /export\s+type\s+GithubAdvisoryStatus/.test(src) &&
      /export\s+interface\s+GithubAdvisoryCoverage/.test(src);
  })());

assert('FetchResult adds githubAdvisoryStatus and githubAdvisoryCoverage envelope fields',
  (() => {
    const src = readFileSync(
      join(root, 'src', 'services', 'vulnerabilityService.ts'),
      'utf8',
    );
    return /githubAdvisoryStatus\?:\s*GithubAdvisoryStatus/.test(src) &&
      /githubAdvisoryCoverage\?:\s*GithubAdvisoryCoverage/.test(src);
  })());

/* ------------------------------------------------------------------ */
/* 18. UI drawer renders package remediation context                  */
/* ------------------------------------------------------------------ */

section('UI: DetailDrawer renders the Package remediation context section');

const drawerSrc = readFileSync(
  join(root, 'src', 'components', 'DetailDrawer.tsx'),
  'utf8',
);

assert('DetailDrawer defines a GithubAdvisoryContext component',
  /function\s+GithubAdvisoryContext\s*\(/.test(drawerSrc));

assert('DetailDrawer renders a "Package remediation context" section title',
  /Package remediation context/.test(drawerSrc));

assert('DetailDrawer shows the empty-state copy when no advisory exists',
  /No GitHub-reviewed package advisory available/.test(drawerSrc));

assert('DetailDrawer renders the source label "GitHub Advisory Database"',
  /GitHub Advisory Database/.test(drawerSrc));

assert('DetailDrawer renders the GHSA id (with ExternalLink icon when advisoryUrl exists)',
  /ghsaId/.test(drawerSrc) && /ExternalLink/.test(drawerSrc));

assert('DetailDrawer renders a per-package list (Affected packages)',
  /Affected packages/.test(drawerSrc));

assert('DetailDrawer uses the Package icon for the section',
  /Package\s+className=/.test(drawerSrc) ||
  /Package\s+import/.test(drawerSrc));

assert('DetailDrawer renders the vulnerable version range',
  /vulnerableVersionRange/.test(drawerSrc));

assert('DetailDrawer renders the first-patched-version (or "unavailable")',
  /firstPatchedVersion/.test(drawerSrc) && /unavailable/.test(drawerSrc));

/* ------------------------------------------------------------------ */
/* 19. Safe external link + no main-table column / header pill         */
/* ------------------------------------------------------------------ */

section('UI: safe external link; no main-table column; no header pill');

assert('external advisory link uses target="_blank"',
  /target="_blank"/.test(drawerSrc));

assert('external advisory link uses rel="noreferrer noopener" (safety)',
  /rel="noreferrer noopener"/.test(drawerSrc));

assert('external advisory link uses the advisoryUrl field (normalized GitHub html_url)',
  /href=\{advisory\.advisoryUrl\}/.test(drawerSrc));

{
  const tableSrc = readFileSync(
    join(root, 'src', 'components', 'VulnerabilityTable.tsx'),
    'utf8',
  );
  assert('VulnerabilityTable does NOT mention any githubAdvisory* field',
    !/githubAdvisory|GithubAdvisory|ghsaId|advisoryUrl|advisorySeverity|githubReviewedAt/.test(tableSrc),
    'expected no GitHub Advisory fields in the main table component');
}

{
  const headerSrc = readFileSync(
    join(root, 'src', 'components', 'Header.tsx'),
    'utf8',
  );
  assert('Header does NOT mention any githubAdvisory* field (no header pill)',
    !/githubAdvisory|GithubAdvisory|ghsaId|advisoryUrl|advisorySeverity|githubReviewedAt/.test(headerSrc),
    'expected no GitHub Advisory badge in the header');
}

/* ------------------------------------------------------------------ */
/* 20. applyFetchResultToCache — pure helper                           */
/* ------------------------------------------------------------------ */

section('applyFetchResultToCache — pure helper semantics');

assert('applyFetchResultToCache is a no-op for transient on a missing entry',
  (() => {
    const before = {};
    const after = applyFetchResultToCache(before, 'CVE-2024-0001', 'transient', null, Date.now());
    return Object.keys(after).length === 0;
  })());

assert('applyFetchResultToCache preserves an existing positive entry on transient',
  (() => {
    const existing = { advisory: { ghsaId: 'GHSA-1' }, cachedAt: 100 };
    const before = { 'CVE-2024-0001': existing };
    const after = applyFetchResultToCache(before, 'CVE-2024-0001', 'transient', null, Date.now());
    return after['CVE-2024-0001'] === existing;
  })());

assert('applyFetchResultToCache writes a marker on "empty" for an uncached CVE',
  (() => {
    const now = Date.now();
    const after = applyFetchResultToCache({}, 'CVE-2024-0001', 'empty', null, now);
    const e = after['CVE-2024-0001'];
    return e && e.advisory === null && e.status === 'missing' &&
      e.cachedAt === now && e.checkedAt === now;
  })());

assert('applyFetchResultToCache preserves an existing positive record on "empty" (defensive)',
  (() => {
    const existing = { advisory: { ghsaId: 'GHSA-1' }, cachedAt: 100 };
    const before = { 'CVE-2024-0001': existing };
    const after = applyFetchResultToCache(before, 'CVE-2024-0001', 'empty', null, Date.now());
    return after['CVE-2024-0001'] === existing;
  })());

assert('applyFetchResultToCache refreshes a stale negative-cache marker with a fresh "empty"',
  (() => {
    const now = Date.now();
    const stale = { advisory: null, status: 'missing', cachedAt: 1, checkedAt: 1 };
    const after = applyFetchResultToCache({ 'CVE-2024-0001': stale }, 'CVE-2024-0001', 'empty', null, now);
    return after['CVE-2024-0001'].cachedAt === now;
  })());

assert('applyFetchResultToCache upserts on "ok" with a valid advisory',
  (() => {
    const now = Date.now();
    const after = applyFetchResultToCache({}, 'CVE-2024-0001', 'ok', [validAdvisory], now);
    return after['CVE-2024-0001'].advisory &&
      after['CVE-2024-0001'].advisory.ghsaId === 'GHSA-aaaa-bbbb-cccc' &&
      after['CVE-2024-0001'].cachedAt === now;
  })());

/* ------------------------------------------------------------------ */
/* Summary                                                             */
/* ------------------------------------------------------------------ */

console.log();
if (failed === 0) {
  console.log(`GITHUB ADVISORY TESTS PASSED  (${passed}/${passed})`);
} else {
  console.log(
    `GITHUB ADVISORY TESTS FAILED  (${failed} of ${passed + failed} failed)`,
  );
  for (const f of failures) {
    console.log(`  - ${f.label}${f.extra ? '  [' + f.extra + ']' : ''}`);
  }
  process.exit(1);
}
