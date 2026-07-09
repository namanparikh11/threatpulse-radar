// Acceptance tests for the NVD CVSS enrichment integration (v3).
// Runs without a framework, without DOM, without a build step.
//   node scripts/acceptance-nvd.mjs
//
// What it covers:
//   1. The NVD response parser (parseNvdItem, pickNvdScore,
//      severityFromNvdBase) handles v3.1, v3.0, v2 metrics and
//      edge cases (missing fields, malformed values, clamping).
//   2. `enrichWithNvd` merges NVD CVSS + severity into CISA records
//      without mutating the input, leaves non-matching CVEs at 0,
//      and never fabricates scores.
//   3. The filter / sort pipeline works correctly on enriched
//      records (severity filter, CVSS sort).
//   4. The service-layer orchestration wires NVD between CISA
//      and EPSS (verified by reading the source).
//
// The v1 15 / v2 CISA 28 / v2.5 EPSS 39 tests keep running
// untouched; this file is purely additive.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');

/**
 * Strip JS-style comments from a source string so the
 * tests below can check the code, not the comments. Used
 * by the v5.2.4 cveIds= URL assertions to avoid matching
 * explanatory doc text that mentions the deprecated
 * `cveId=` parameter historically.
 */
function stripComments(s) {
  return s
    .replace(/\/\*[\s\S]*?\*\//g, '')   // /* ... */ block comments
    .replace(/^\s*\/\/.*$/gm, '')       // // line comments (line start)
    .replace(/\s+\/\/.*$/gm, '');      // // trailing-line comments
}

/* ------------------------------------------------------------------ */
/* Re-implementation of the production logic, in plain JS.            */
/* Kept in lockstep with src/services/providers/nvd.ts.               */
/* ------------------------------------------------------------------ */

function severityFromNvdBase(baseSeverity, baseScore) {
  switch ((baseSeverity ?? '').toUpperCase()) {
    case 'CRITICAL': return 'Critical';
    case 'HIGH':     return 'High';
    case 'MEDIUM':   return 'Medium';
    case 'LOW':      return 'Low';
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

function parseNvdItem(item) {
  const cveId = (item?.cve?.id ?? '').trim();
  if (!cveId) return null;
  const score = pickNvdScore(item.cve?.metrics);
  if (score === null) return null;
  return [cveId, score];
}

function buildMapFromResponse(body) {
  if (!body || !Array.isArray(body.vulnerabilities)) {
    throw new Error('NVD response has unexpected shape (no vulnerabilities array)');
  }
  return new Map(
    body.vulnerabilities
      .map(parseNvdItem)
      .filter((x) => x !== null)
  );
}

function enrichWithNvd(records, nvdMap) {
  return records.map((v) => {
    const score = nvdMap.get(v.cveId);
    if (!score) return v;
    return { ...v, cvssScore: score.cvssScore, severity: score.severity };
  });
}

/* ------------------------------------------------------------------ */
/* Test helpers                                                       */
/* ------------------------------------------------------------------ */

let passed = 0;
let failed = 0;
const failures = [];

function assert(label, cond, extra) {
  if (cond) {
    console.log(`  ✓ ${label}`);
    passed += 1;
  } else {
    console.log(`  ✗ ${label}  -- ${extra ?? ''}`);
    failed += 1;
    failures.push({ label, extra });
    process.exitCode = 1;
  }
}

function section(title) {
  console.log(`\n--- ${title} ---`);
}

/* ------------------------------------------------------------------ */
/* Synthetic CISA-normalized input (mirror of cisaKev.ts output)     */
/* ------------------------------------------------------------------ */

function makeCisaRecord(cveId, { severity = 'High', cvssScore = 0 } = {}) {
  return {
    id: `kev-${cveId.toLowerCase()}`,
    cveId,
    summary: `Some vuln ${cveId}`,
    description: `desc for ${cveId}`,
    severity,
    cvssScore,
    epssProbability: 0,
    kev: true,
    vendor: 'TestVendor',
    product: 'TestProduct',
    publishedDate: '2024-01-15',
    source: 'CISA KEV',
    recommendedAction: 'Patch.',
    externalLinks: [],
  };
}

const SAMPLE_CISA = [
  'CVE-2024-3400',   // v3.1 10.0 / CRITICAL
  'CVE-2024-1709',   // v3.0 9.8 / CRITICAL
  'CVE-2017-0144',   // v2 8.1 / HIGH
  'CVE-2023-50164',  // v3.1 7.5 / HIGH
  'CVE-2099-9999',   // Not in NVD response — must stay at 0.
].map((cveId) => makeCisaRecord(cveId));

/* ------------------------------------------------------------------ */
/* Tests                                                             */
/* ------------------------------------------------------------------ */

console.log(`\nNVD CVSS enrichment: 5 synthetic CISA records, 4 NVD responses\n`);

section('Severity derivation (severityFromNvdBase)');
{
  assert('CRITICAL baseSeverity → Critical',
    severityFromNvdBase('CRITICAL', 9.0) === 'Critical');
  assert('HIGH baseSeverity → High',
    severityFromNvdBase('HIGH', 7.0) === 'High');
  assert('MEDIUM baseSeverity → Medium',
    severityFromNvdBase('MEDIUM', 5.0) === 'Medium');
  assert('LOW baseSeverity → Low',
    severityFromNvdBase('LOW', 2.0) === 'Low');
  assert('lowercase baseSeverity is normalized to upper',
    severityFromNvdBase('critical', 9.0) === 'Critical');
  assert('missing baseSeverity falls back to score-based mapping',
    severityFromNvdBase(undefined, 9.5) === 'Critical' &&
      severityFromNvdBase(undefined, 7.5) === 'High' &&
      severityFromNvdBase(undefined, 5.0) === 'Medium' &&
      severityFromNvdBase(undefined, 2.0) === 'Low');
}

section('Score clamping (clampCvss)');
{
  assert('NaN score → 0',
    clampCvss(NaN) === 0);
  assert('negative score → 0',
    clampCvss(-1) === 0);
  assert('score > 10 → 10',
    clampCvss(11) === 10);
  assert('valid score passes through',
    clampCvss(7.5) === 7.5);
}

section('Score picker (pickNvdScore)');
{
  // v3.1 preferred over v3.0 and v2.
  const m = {
    cvssMetricV31: [{ cvssData: { baseScore: 10.0, baseSeverity: 'CRITICAL' } }],
    cvssMetricV30: [{ cvssData: { baseScore: 9.0,  baseSeverity: 'CRITICAL' } }],
    cvssMetricV2:  [{ cvssData: { baseScore: 8.0 } }],
  };
  const s = pickNvdScore(m);
  assert('v3.1 takes priority when all three present',
    s && s.cvssScore === 10.0 && s.severity === 'Critical');
}
{
  // v3.0 used when v3.1 absent.
  const m = {
    cvssMetricV30: [{ cvssData: { baseScore: 9.8, baseSeverity: 'CRITICAL' } }],
    cvssMetricV2:  [{ cvssData: { baseScore: 8.0 } }],
  };
  const s = pickNvdScore(m);
  assert('falls back to v3.0 when v3.1 absent',
    s && s.cvssScore === 9.8 && s.severity === 'Critical');
}
{
  // v2 used when v3 absent; severity derived from score.
  const m = {
    cvssMetricV2: [{ cvssData: { baseScore: 8.1 } }],
  };
  const s = pickNvdScore(m);
  assert('falls back to v2 with score-derived severity',
    s && s.cvssScore === 8.1 && s.severity === 'High');
}
{
  // v2 with baseSeverity present is honored.
  const m = {
    cvssMetricV2: [{ cvssData: { baseScore: 4.5, baseSeverity: 'MEDIUM' } }],
  };
  const s = pickNvdScore(m);
  assert('v2 baseSeverity honored when present',
    s && s.cvssScore === 4.5 && s.severity === 'Medium');
}
{
  // Empty metrics → null.
  const s = pickNvdScore({});
  assert('empty metrics → null',
    s === null);
  const s2 = pickNvdScore(null);
  assert('null metrics → null',
    s2 === null);
  const s3 = pickNvdScore(undefined);
  assert('undefined metrics → null',
    s3 === null);
}
{
  // Metrics with no baseScore in any version → null.
  const s = pickNvdScore({
    cvssMetricV31: [{ cvssData: {} }],
    cvssMetricV30: [{ cvssData: {} }],
  });
  assert('metrics without baseScore → null',
    s === null);
}

section('Response shape validation (buildMapFromResponse)');
{
  const body = {
    totalResults: 2,
    vulnerabilities: [
      {
        cve: {
          id: 'CVE-2024-3400',
          metrics: {
            cvssMetricV31: [{ cvssData: { baseScore: 10.0, baseSeverity: 'CRITICAL' } }],
          },
        },
      },
      {
        cve: {
          id: 'CVE-2024-1709',
          metrics: {
            cvssMetricV30: [{ cvssData: { baseScore: 9.8, baseSeverity: 'CRITICAL' } }],
          },
        },
      },
    ],
  };
  const m = buildMapFromResponse(body);
  assert('valid response builds a 2-entry Map',
    m instanceof Map && m.size === 2);
  assert('Map lookup by cveId works',
    m.get('CVE-2024-3400').cvssScore === 10.0 &&
      m.get('CVE-2024-1709').cvssScore === 9.8);
}
{
  let threw = false;
  try { buildMapFromResponse(null); } catch { threw = true; }
  assert('null body throws',
    threw);
}
{
  let threw = false;
  try { buildMapFromResponse({}); } catch { threw = true; }
  assert('missing vulnerabilities array throws',
    threw);
}
{
  // Item without cve.id is skipped, not throwing.
  const m = buildMapFromResponse({
    vulnerabilities: [
      { cve: { id: 'CVE-2024-3400', metrics: { cvssMetricV31: [{ cvssData: { baseScore: 9.0, baseSeverity: 'CRITICAL' } }] } } },
      { cve: {} },
      { notacve: {} },
    ],
  });
  assert('items without cve.id are silently skipped',
    m.size === 1 && m.has('CVE-2024-3400'));
}

section('Enrichment tests (enrichWithNvd)');
{
  const nvdMap = buildMapFromResponse({
    vulnerabilities: [
      { cve: { id: 'CVE-2024-3400', metrics: { cvssMetricV31: [{ cvssData: { baseScore: 10.0, baseSeverity: 'CRITICAL' } }] } } },
      { cve: { id: 'CVE-2024-1709', metrics: { cvssMetricV30: [{ cvssData: { baseScore: 9.8, baseSeverity: 'CRITICAL' } }] } } },
      { cve: { id: 'CVE-2017-0144', metrics: { cvssMetricV2:  [{ cvssData: { baseScore: 8.1 } }] } } },
      { cve: { id: 'CVE-2023-50164', metrics: { cvssMetricV31: [{ cvssData: { baseScore: 7.5, baseSeverity: 'HIGH' } }] } } },
    ],
  });
  const enriched = enrichWithNvd(SAMPLE_CISA, nvdMap);
  assert('enriched array has same length as input',
    enriched.length === SAMPLE_CISA.length);
  assert('CVE-2024-3400 gets CVSS 10.0 + Critical from v3.1',
    enriched[0].cvssScore === 10.0 && enriched[0].severity === 'Critical',
    `cvss=${enriched[0].cvssScore} sev=${enriched[0].severity}`);
  assert('CVE-2024-1709 gets CVSS 9.8 + Critical from v3.0',
    enriched[1].cvssScore === 9.8 && enriched[1].severity === 'Critical');
  assert('CVE-2017-0144 gets CVSS 8.1 + High from v2 (score-derived)',
    enriched[2].cvssScore === 8.1 && enriched[2].severity === 'High');
  assert('CVE-2023-50164 gets CVSS 7.5 + High from v3.1',
    enriched[3].cvssScore === 7.5 && enriched[3].severity === 'High');
  assert('CVE-2099-9999 keeps cvssScore=0 and CISA severity (no fabrication)',
    enriched[4].cvssScore === 0 && enriched[4].severity === 'High',
    `cvss=${enriched[4].cvssScore} sev=${enriched[4].severity}`);
  assert('enrichment does not mutate the input array',
    SAMPLE_CISA[0].cvssScore === 0 &&
      SAMPLE_CISA[0].severity === 'High',
    `original cvss=${SAMPLE_CISA[0].cvssScore} sev=${SAMPLE_CISA[0].severity}`);
  assert('enrichment preserves all other fields',
    enriched[0].cveId === 'CVE-2024-3400' &&
      enriched[0].kev === true &&
      enriched[0].epssProbability === 0,
    `cveId=${enriched[0].cveId} kev=${enriched[0].kev}`);
}
{
  // NVD severity overrides CISA severity when present.
  const cisaRecord = makeCisaRecord('CVE-2024-3400', { severity: 'Low', cvssScore: 0 });
  const nvdMap = buildMapFromResponse({
    vulnerabilities: [
      { cve: { id: 'CVE-2024-3400', metrics: { cvssMetricV31: [{ cvssData: { baseScore: 10.0, baseSeverity: 'CRITICAL' } }] } } },
    ],
  });
  const enriched = enrichWithNvd([cisaRecord], nvdMap);
  assert('NVD severity overrides CISA-derived severity',
    enriched[0].severity === 'Critical' && enriched[0].cvssScore === 10.0);
}
{
  // Empty NVD map → all records unchanged.
  const enriched = enrichWithNvd(SAMPLE_CISA, new Map());
  assert('empty NVD map leaves all records unchanged',
    enriched.every((v) => v.cvssScore === 0));
}
{
  // Empty input array → empty output.
  const enriched = enrichWithNvd([], new Map());
  assert('empty input array returns empty output',
    Array.isArray(enriched) && enriched.length === 0);
}

section('Filter / sort pipeline tests on enriched records');
{
  function applyFilters(vulns, { severity = 'All', minCvss = 0, kevOnly = false } = {}) {
    return vulns.filter((v) => {
      if (kevOnly && !v.kev) return false;
      if (severity !== 'All' && v.severity !== severity) return false;
      if (v.cvssScore < minCvss) return false;
      return true;
    });
  }
  const nvdMap = buildMapFromResponse({
    vulnerabilities: [
      { cve: { id: 'CVE-2024-3400', metrics: { cvssMetricV31: [{ cvssData: { baseScore: 10.0, baseSeverity: 'CRITICAL' } }] } } },
      { cve: { id: 'CVE-2024-1709', metrics: { cvssMetricV30: [{ cvssData: { baseScore: 9.8, baseSeverity: 'CRITICAL' } }] } } },
      { cve: { id: 'CVE-2017-0144', metrics: { cvssMetricV2:  [{ cvssData: { baseScore: 8.1 } }] } } },
      { cve: { id: 'CVE-2023-50164', metrics: { cvssMetricV31: [{ cvssData: { baseScore: 7.5, baseSeverity: 'HIGH' } }] } } },
    ],
  });
  const enriched = enrichWithNvd(SAMPLE_CISA, nvdMap);
  {
    // Severity filter now actually works (the CISA-only test had
    // to use a static CISA-derived severity; NVD can override).
    const r = applyFilters(enriched, { severity: 'Critical' });
    assert('severity = Critical returns the two 9.8/10.0 rows on enriched records',
      r.length === 2 &&
        r.every((v) => v.severity === 'Critical') &&
        r.map((v) => v.cveId).join(',') === 'CVE-2024-3400,CVE-2024-1709',
      `got ${r.map((v) => v.cveId).join(',')}`);
  }
  {
    // CVE-2099-9999 is not in the NVD response, so it keeps its
    // CISA-derived severity (High) and CVSS (0). The severity filter
    // still includes it — that's the honest behavior, not a bug.
    const r = applyFilters(enriched, { severity: 'High' });
    assert('severity = High returns 3 rows: 2 NVD-enriched (7.5/8.1) + 1 CISA-only (CVE-2099-9999 keeps CISA severity)',
      r.length === 3 &&
        r.every((v) => v.severity === 'High') &&
        r.map((v) => v.cveId).sort().join(',') === 'CVE-2017-0144,CVE-2023-50164,CVE-2099-9999',
      `got ${r.map((v) => v.cveId + '@' + v.cvssScore + '/' + v.severity).join(',')}`);
  }
  {
    // CVSS-based filter (the v1 EPSS slider analog) works on real values.
    const r = applyFilters(enriched, { minCvss: 9.0 });
    assert('CVSS slider >= 9.0 on enriched records returns the two 9.8/10.0 rows',
      r.length === 2 &&
        r.every((v) => v.cvssScore >= 9.0));
  }
  {
    // minCvss > 0 excludes the un-enriched record (CVE-2099-9999 stays at 0).
    const r = applyFilters(enriched, { minCvss: 0.5 });
    assert('CVSS slider >= 0.5 (above the un-enriched 0.0) returns the 4 NVD-enriched rows only',
      r.length === 4 &&
        r.every((v) => v.cvssScore >= 0.5));
  }
  {
    const r = applyFilters(enriched, { minCvss: 7.5 });
    assert('CVSS slider >= 7.5 returns the 4 rows with CVSS >= 7.5 (none dropped at 7.5)',
      r.length === 4 &&
        r.every((v) => v.cvssScore >= 7.5));
  }
}

section('Service-layer wiring (source-code assertions)');
{
  const serviceSrc = readFileSync(join(root, 'src', 'services', 'vulnerabilityService.ts'), 'utf8');
  const nvdSrc = readFileSync(join(root, 'src', 'services', 'providers', 'nvd.ts'), 'utf8');
  const headerSrc = readFileSync(join(root, 'src', 'components', 'Header.tsx'), 'utf8');
  const dashboardSrc = readFileSync(join(root, 'src', 'pages', 'DashboardPage.tsx'), 'utf8');

  assert('service imports fetchNvdForCves + enrichWithNvd',
    /import\s*\{[^}]*\bfetchNvdForCves\b[^}]*\}/.test(serviceSrc) &&
      /import\s*\{[^}]*\benrichWithNvd\b[^}]*\}/.test(serviceSrc) &&
      /from\s*['"]\.\/providers\/nvd['"]/.test(serviceSrc),
    'NVD imports not found in service');

  assert('FetchResult has nvdStatus and nvdReason optional fields',
    /nvdStatus\?:\s*NvdStatus/.test(serviceSrc) &&
      /nvdReason\?:\s*string/.test(serviceSrc),
    'nvdStatus / nvdReason fields not found');

  assert('service catches NVD fetch errors and sets nvdStatus=unavailable',
    /fetchNvdForCves[\s\S]{0,800}catch[\s\S]{0,400}unavailable/.test(serviceSrc),
    'NVD catch + unavailable path not found');

  assert('live path runs CISA then NVD then EPSS (in that order)',
    // Use position-based check: each call's character index must
    // increase. The service has lots of comments + try/catch
    // blocks between them, so a fixed-character-distance regex
    // is too brittle.
    (() => {
      const i1 = serviceSrc.indexOf('fetchCisaKev()');
      const i2 = serviceSrc.indexOf('fetchNvdForCves(');
      const i3 = serviceSrc.indexOf('fetchEpssForCves(');
      return i1 > 0 && i1 < i2 && i2 < i3;
    })(),
    'CISA → NVD → EPSS ordering not found');

  assert('NVD provider chunks CVEs (CHUNK_SIZE constant exists)',
    /const\s+CHUNK_SIZE\s*=/.test(nvdSrc),
    'CHUNK_SIZE not found');

  assert('NVD provider chunks at 100 CVEs per request (NVD API limit)',
    /CHUNK_SIZE\s*=\s*100\b/.test(nvdSrc),
    'expected CHUNK_SIZE = 100 (NVD API max per request)');

  assert('v5.2.4: browser-direct NVD batch URL uses ?cveIds= (plural)',
    // v5.2.4 parity with the v5.2.3 server-side fix.
    // NVD's `cveIds=` (plural) accepts a comma-separated list,
    // max 100 per request. The deprecated `cveId=` (singular)
    // expects a single CVE ID and returns HTTP 404 when given
    // a comma-separated list. This provider's only batch path
    // is `fetchOneChunk(cveChunk: string[])` — no single-CVE
    // path exists — so the URL must unconditionally use
    // `?cveIds=`.
    (() => {
      const code = stripComments(nvdSrc);
      return /\?cveIds=\$\{encodeURIComponent\([^)]*\.join\(['"],['"]\)\)\}/.test(code);
    })(),
    'expected browser NVD batch URL to use `?cveIds=${encodeURIComponent(...)}`');

  assert('v5.2.4: browser-direct NVD batch URL does NOT use the deprecated ?cveId= (singular)',
    // The browser provider has no single-CVE path, so any
    // `?cveId=` followed by an encodeURIComponent is a batch
    // URL — and the singular parameter is wrong for batches.
    (() => {
      const code = stripComments(nvdSrc);
      return !/\?cveId=\$\{encodeURIComponent/.test(code);
    })(),
    'expected browser NVD to NOT use the deprecated `?cveId=` parameter');

  assert('v5.2.4: browser-direct NVD never sends NVD_API_KEY (browser has no key)',
    // The browser provider must not import process.env, must
    // not read any env var, and must not set the apiKey request
    // header. The key is server-side only (v5.0.2 / v5.0.3).
    !/process\.env/.test(nvdSrc) &&
      !/apiKey/.test(nvdSrc) &&
      !/NVD_API_KEY/.test(nvdSrc),
    'expected browser NVD provider to have no NVD_API_KEY reference at all');

  assert('NVD provider uses AbortController timeout',
    /AbortController[\s\S]{0,300}abort/.test(nvdSrc),
    'AbortController not found');

  assert('NVD provider URL is the official NVD endpoint',
    /services\.nvd\.nist\.gov\/rest\/json\/cves\/2\.0/.test(nvdSrc),
    'NVD URL not found');

  assert('NVD provider has pickNvdScore with v3.1/v3.0/v2 preference',
    /cvssMetricV31[\s\S]{0,200}cvssMetricV30[\s\S]{0,200}cvssMetricV2/.test(nvdSrc),
    'v3.1 / v3.0 / v2 metric preference not found');

  assert('header shows NVD pill when nvdStatus="nvd"',
    /nvdStatus\s*===\s*['"]nvd['"][\s\S]*?StatusPill/.test(headerSrc),
    'NVD-nvd pill not found in header');

  assert('header shows warn-tone NVD pill when nvdStatus="unavailable"',
    /nvdStatus\s*===\s*['"]unavailable['"][\s\S]*?StatusPill/.test(headerSrc),
    'NVD-unavailable pill not found in header');

  assert('header source label mentions NVD when nvdStatus="nvd"',
    // The label is now built dynamically (parts.push) — verify
    // the NVD string is pushed in the conditional that checks
    // nvdStatus.
    (() => {
      const fnStart = headerSrc.indexOf('function describeSource(');
      if (fnStart < 0) return false;
      // Find the closing brace — accept either LF or CRLF line endings.
      const tail = headerSrc.slice(fnStart);
      const m = tail.match(/\n\s*\}\s*\n/);
      if (!m) return false;
      const fnEnd = fnStart + m.index + m[0].length;
      const fnBody = headerSrc.slice(fnStart, fnEnd);
      return /nvdStatus\s*===\s*['"]nvd['"][\s\S]*?parts\.push\(\s*['"]NVD['"]\s*\)/.test(fnBody);
    })(),
    'NVD-aware source label not found in header');

  assert('dashboard shows NvdUnavailableBanner when live + nvdStatus=unavailable',
    /NvdUnavailableBanner/.test(dashboardSrc) &&
      /nvdStatus\s*===\s*['"]unavailable['"]/.test(dashboardSrc),
    'NvdUnavailableBanner wiring not found in DashboardPage');

  assert('CISA description no longer claims NVD/FIRST EPSS are unwired',
    !/populated when NVD \/ FIRST EPSS are wired in/.test(
      readFileSync(join(root, 'src', 'services', 'providers', 'cisaKev.ts'), 'utf8')
    ),
    'stale description note still present in cisaKev.ts');

  assert('Header source label reflects BOTH nvdStatus and epssStatus (v3.1 honesty fix)',
    // The full describeSource matrix — each (nvdStatus, epssStatus)
    // combination must produce a label that only mentions providers
    // that actually contributed. The simplest check: when EPSS
    // is unavailable but NVD loaded, the label must NOT contain
    // "FIRST EPSS".
    (() => {
      const headerSrc2 = readFileSync(join(root, 'src', 'components', 'Header.tsx'), 'utf8');
      // Find the describeSource function and read the next ~30 lines.
      // Accept either LF or CRLF line endings.
      const fnStart = headerSrc2.indexOf('function describeSource(');
      if (fnStart < 0) return false;
      const tail = headerSrc2.slice(fnStart);
      const m = tail.match(/\n\s*\}\s*\n/);
      if (!m) return false;
      const fnEnd = fnStart + m.index + m[0].length;
      const fnBody = headerSrc2.slice(fnStart, fnEnd);
      // The fix is in the function body: it must check epssStatus
      // (not just nvdStatus) before adding 'FIRST EPSS' to the
      // label. Pre-fix, the label always said "FIRST EPSS" when
      // nvdStatus==='nvd', regardless of epssStatus.
      return /epssStatus/.test(fnBody)
        && /['"]FIRST EPSS['"]/.test(fnBody)
        && /parts\.push/.test(fnBody);
    })(),
    'describeSource in Header.tsx does not reflect epssStatus');
}

/* ------------------------------------------------------------------ */
/* Summary                                                            */
/* ------------------------------------------------------------------ */

console.log();
if (failed === 0) {
  console.log(`NVD TESTS PASSED  (${passed}/${passed})`);
} else {
  console.log(`NVD TESTS FAILED  (${failed} of ${passed + failed} failed)`);
  for (const f of failures) {
    console.log(`  - ${f.label}${f.extra ? '  [' + f.extra + ']' : ''}`);
  }
}
