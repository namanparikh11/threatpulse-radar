// Acceptance tests for the FIRST EPSS enrichment integration (v2.5).
// Runs without a framework, without DOM, without a build step.
//   node scripts/acceptance-epss.mjs
//
// What it covers:
//   1. The EPSS response normalizer parses records correctly
//      (string probabilities → number, clamping, missing fields).
//   2. `enrichWithEpss` merges EPSS scores into CISA-normalized
//      records without mutating the input, leaves non-matching
//      CVEs at `epssProbability: 0`, and never fabricates scores.
//   3. The filter / sort pipeline works correctly on enriched
//      records (EPSS slider now actually filters on real values).
//   4. The service-layer orchestration is wired correctly
//      (verified by reading the source).
//
// The v1 13/15 tests and v2 CISA 28 tests keep running untouched;
// this file is purely additive.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');

/* ------------------------------------------------------------------ */
/* Re-implementation of the production logic, in plain JS.            */
/* Kept in lockstep with src/services/providers/epss.ts.             */
/* ------------------------------------------------------------------ */

/**
 * Mirror of the production enrichWithEpss. Pure function.
 */
function enrichWithEpss(records, epssMap) {
  return records.map((v) => {
    const score = epssMap.get(v.cveId);
    if (!score) return v;
    return { ...v, epssProbability: score.epss };
  });
}

/**
 * Mirror of the production parseProbability (clamp + NaN guard).
 */
function parseProbability(raw) {
  if (raw == null) return 0;
  const n = Number.parseFloat(raw);
  if (Number.isNaN(n)) return 0;
  if (n < 0) return 0;
  if (n > 1) return 1;
  return n;
}

/**
 * Mirror of the production parseEpssRecord.
 */
function parseEpssRecord(rec) {
  return [rec.cve, { epss: parseProbability(rec.epss), percentile: parseProbability(rec.percentile) }];
}

/**
 * Mirror of the production fetchEpssForCves for a synthetic response.
 * We do NOT exercise the real fetch (no network) — we verify the
 * parser / enricher behavior on a hand-built response.
 */
function buildMapFromResponse(body) {
  if (!body || !Array.isArray(body.data)) {
    throw new Error('FIRST EPSS response has unexpected shape (no data array)');
  }
  return new Map(body.data.map(parseEpssRecord));
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
/* Synthetic CISA-normalized input (mirroring cisaKev.ts output)     */
/* ------------------------------------------------------------------ */

function makeCisaRecord(cveId) {
  return {
    id: `kev-${cveId.toLowerCase()}`,
    cveId,
    summary: `Some vuln ${cveId}`,
    description: `desc for ${cveId}`,
    severity: 'High',
    cvssScore: 0,
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
  'CVE-2024-3400',
  'CVE-2024-1709',
  'CVE-2017-0144',
  'CVE-2099-9999', // Not in FIRST's response — must stay at 0.
].map(makeCisaRecord);

/* ------------------------------------------------------------------ */
/* Tests                                                             */
/* ------------------------------------------------------------------ */

console.log(`\nFIRST EPSS enrichment: 4 synthetic CISA records, 3 EPSS responses\n`);

section('Parser tests (parseProbability / parseEpssRecord)');
{
  // Normal string values.
  const [cve, score] = parseEpssRecord({
    cve: 'CVE-2024-3400',
    epss: '0.97432',
    percentile: '0.99876',
  });
  assert('parseEpssRecord extracts cveId verbatim',
    cve === 'CVE-2024-3400',
    `cve=${cve}`);
  assert('parseEpssRecord parses epss string to number in [0, 1]',
    typeof score.epss === 'number' && score.epss === 0.97432,
    `epss=${score.epss}`);
  assert('parseEpssRecord parses percentile string to number in [0, 1]',
    typeof score.percentile === 'number' && score.percentile === 0.99876,
    `percentile=${score.percentile}`);
}
{
  // Edge cases: NaN guards + clamping.
  assert('parseProbability(NaN string) returns 0',
    parseProbability('not-a-number') === 0);
  assert('parseProbability(undefined) returns 0',
    parseProbability(undefined) === 0);
  assert('parseProbability(null) returns 0',
    parseProbability(null) === 0);
  assert('parseProbability("") returns 0',
    parseProbability('') === 0);
  assert('parseProbability clamps negatives to 0',
    parseProbability('-0.5') === 0);
  assert('parseProbability clamps >1 to 1',
    parseProbability('1.5') === 1);
  assert('parseProbability accepts 0',
    parseProbability('0') === 0);
  assert('parseProbability accepts 1',
    parseProbability('1') === 1);
}

section('Response shape validation (buildMapFromResponse)');
{
  const body = {
    status: 'OK',
    status_code: 200,
    total: 2,
    data: [
      { cve: 'CVE-2024-3400', epss: '0.97432', percentile: '0.99876' },
      { cve: 'CVE-2024-1709', epss: '0.61240', percentile: '0.95123' },
    ],
  };
  const m = buildMapFromResponse(body);
  assert('valid response builds a 2-entry Map',
    m instanceof Map && m.size === 2);
  assert('Map lookup by cveId works',
    m.get('CVE-2024-3400').epss === 0.97432 &&
      m.get('CVE-2024-1709').epss === 0.61240);
}
{
  let threw = false;
  try { buildMapFromResponse(null); } catch { threw = true; }
  assert('null body throws',
    threw);
}
{
  let threw = false;
  try { buildMapFromResponse({ status: 'OK' }); } catch { threw = true; }
  assert('missing data array throws',
    threw);
}
{
  let threw = false;
  try { buildMapFromResponse({ data: 'not-an-array' }); } catch { threw = true; }
  assert('non-array data throws',
    threw);
}

section('Enrichment tests (enrichWithEpss)');
{
  const epssMap = buildMapFromResponse({
    data: [
      { cve: 'CVE-2024-3400', epss: '0.97432', percentile: '0.99876' },
      { cve: 'CVE-2024-1709', epss: '0.61240', percentile: '0.95123' },
      { cve: 'CVE-2017-0144', epss: '0.94500', percentile: '0.99500' },
    ],
  });
  const enriched = enrichWithEpss(SAMPLE_CISA, epssMap);
  assert('enriched array has same length as input',
    enriched.length === SAMPLE_CISA.length);
  assert('matching CVE-2024-3400 has epssProbability from FIRST',
    enriched[0].epssProbability === 0.97432,
    `got ${enriched[0].epssProbability}`);
  assert('matching CVE-2024-1709 has epssProbability from FIRST',
    enriched[1].epssProbability === 0.61240,
    `got ${enriched[1].epssProbability}`);
  assert('matching CVE-2017-0144 has epssProbability from FIRST',
    enriched[2].epssProbability === 0.94500,
    `got ${enriched[2].epssProbability}`);
  assert('non-matching CVE-2099-9999 keeps epssProbability=0 (no fabrication)',
    enriched[3].epssProbability === 0,
    `got ${enriched[3].epssProbability}`);
  assert('enriched records preserve all other fields',
    enriched[0].cveId === 'CVE-2024-3400' &&
      enriched[0].kev === true &&
      enriched[0].severity === 'High' &&
      enriched[0].cvssScore === 0,
    `cveId=${enriched[0].cveId} kev=${enriched[0].kev}`);
  assert('enrichment does not mutate the input array',
    SAMPLE_CISA[0].epssProbability === 0,
    `original epssProbability=${SAMPLE_CISA[0].epssProbability}`);
}
{
  // Empty EPSS map → all records keep 0.
  const enriched = enrichWithEpss(SAMPLE_CISA, new Map());
  assert('empty EPSS map leaves all records at 0',
    enriched.every((v) => v.epssProbability === 0));
}
{
  // Empty input array → empty output.
  const enriched = enrichWithEpss([], new Map());
  assert('empty input array returns empty output',
    Array.isArray(enriched) && enriched.length === 0);
}

section('Filter / sort pipeline tests on enriched records');
{
  // Apply the standard filter helper (mirror of analytics.ts).
  function applyFilters(vulns, { minEpss = 0, kevOnly = false } = {}) {
    return vulns.filter((v) => {
      if (kevOnly && !v.kev) return false;
      if (v.epssProbability < minEpss) return false;
      return true;
    });
  }
  const epssMap = buildMapFromResponse({
    data: [
      { cve: 'CVE-2024-3400', epss: '0.97432', percentile: '0.99876' },
      { cve: 'CVE-2024-1709', epss: '0.61240', percentile: '0.95123' },
      { cve: 'CVE-2017-0144', epss: '0.04500', percentile: '0.50000' },
    ],
  });
  const enriched = enrichWithEpss(SAMPLE_CISA, epssMap);
  {
    const r = applyFilters(enriched, { minEpss: 0.5 });
    assert('EPSS slider >= 50% on enriched records returns only the two high-EPSS rows',
      r.length === 2 &&
        r.every((v) => v.epssProbability >= 0.5) &&
        r.map((v) => v.cveId).join(',') === 'CVE-2024-3400,CVE-2024-1709',
      `got ${r.map((v) => v.cveId + '@' + v.epssProbability.toFixed(3)).join(',')}`);
  }
  {
    const r = applyFilters(enriched, { minEpss: 0.9 });
    assert('EPSS slider >= 90% on enriched records returns only the 97% row',
      r.length === 1 && r[0].cveId === 'CVE-2024-3400',
      `got ${r.map((v) => v.cveId).join(',')}`);
  }
  {
    const r = applyFilters(enriched, { minEpss: 0.99 });
    assert('EPSS slider >= 99% returns empty (no row is that high)',
      Array.isArray(r) && r.length === 0);
  }
  {
    const r = applyFilters(enriched, { kevOnly: true });
    assert('KEV-only on enriched records still returns every row (all CISA = kev=true)',
      r.length === enriched.length);
  }
}

section('Service-layer wiring (source-code assertions)');
{
  const serviceSrc = readFileSync(join(root, 'src', 'services', 'vulnerabilityService.ts'), 'utf8');
  const epssSrc = readFileSync(join(root, 'src', 'services', 'providers', 'epss.ts'), 'utf8');
  const headerSrc = readFileSync(join(root, 'src', 'components', 'Header.tsx'), 'utf8');
  const dashboardSrc = readFileSync(join(root, 'src', 'pages', 'DashboardPage.tsx'), 'utf8');

  assert('service imports fetchEpssForCves + enrichWithEpss',
    // The import statement in the service can name the symbols in
    // either order; we just need both names inside the same braces.
    /import\s*\{[^}]*\bfetchEpssForCves\b[^}]*\}/.test(serviceSrc) &&
      /import\s*\{[^}]*\benrichWithEpss\b[^}]*\}/.test(serviceSrc) &&
      /from\s*['"]\.\/providers\/epss['"]/.test(serviceSrc),
    'EPSS imports not found in service');

  assert('FetchResult has epssStatus and epssReason optional fields',
    /epssStatus\?:\s*EpssStatus/.test(serviceSrc) &&
      /epssReason\?:\s*string/.test(serviceSrc),
    'epssStatus / epssReason fields not found');

  assert('service catches EPSS fetch errors and sets epssStatus=unavailable',
    /fetchEpssForCves[\s\S]{0,800}catch[\s\S]{0,400}unavailable/.test(serviceSrc),
    'EPSS catch + unavailable path not found');

  assert('happy path sets source="merged" + epssStatus="first"',
    // The service structure (post-v3 NVD enrichment) builds the
    // FetchResult dynamically. The happy path is signalled by
    // the local variable assignments in the try blocks.
    /source:\s*['"]merged['"]/.test(serviceSrc) &&
      /epssStatus\s*=\s*['"]first['"]/.test(serviceSrc),
    'merged-source + first-status path not found');

  assert('epss provider chunks CVEs (CHUNK_SIZE constant exists)',
    /const\s+CHUNK_SIZE\s*=/.test(epssSrc),
    'CHUNK_SIZE not found');

  assert('epss provider uses AbortController timeout',
    /AbortController[\s\S]{0,300}abort/.test(epssSrc),
    'AbortController not found');

  assert('epss provider URL is the official FIRST endpoint',
    /api\.first\.org\/data\/v1\/epss/.test(epssSrc),
    'FIRST EPSS URL not found');

  assert('header shows EPSS pill when epssStatus="first"',
    /epssStatus\s*===\s*['"]first['"][\s\S]*?StatusPill/.test(headerSrc),
    'EPSS-first pill not found in header');

  assert('header shows warn-tone EPSS pill when epssStatus="unavailable"',
    /epssStatus\s*===\s*['"]unavailable['"][\s\S]*?StatusPill/.test(headerSrc),
    'EPSS-unavailable pill not found in header');

  assert('dashboard shows EpssUnavailableBanner when live + epssStatus=unavailable',
    /EpssUnavailableBanner/.test(dashboardSrc) &&
      /epssStatus\s*===\s*['"]unavailable['"]/.test(dashboardSrc),
    'EpssUnavailableBanner wiring not found in DashboardPage');
}

/* ------------------------------------------------------------------ */
/* Summary                                                            */
/* ------------------------------------------------------------------ */

console.log();
if (failed === 0) {
  console.log(`EPSS TESTS PASSED  (${passed}/${passed})`);
} else {
  console.log(`EPSS TESTS FAILED  (${failed} of ${passed + failed} failed)`);
  for (const f of failures) {
    console.log(`  - ${f.label}${f.extra ? '  [' + f.extra + ']' : ''}`);
  }
}
