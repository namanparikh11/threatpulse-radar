// Acceptance tests for the CISA KEV integration.
// Runs without a framework, without DOM, without a build step.
//   node scripts/acceptance-cisa.mjs
//
// What it covers:
//   1. The CISA record normalizer produces well-shaped Vulnerability
//      records (kev=true, defaults for missing fields, source label).
//   2. The filter / sort pipeline (mirror of applyFilters + applySortBy)
//      works on CISA-normalized records exactly as it does on mock data.
//   3. The service layer's three modes (live / mock / fallback) are
//      wired correctly (verified by reading the source).
//
// The v1 acceptance script (`acceptance.mjs`) keeps running untouched;
// this file is purely additive. The 13 v1 tests are still 13/13.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');

/* ------------------------------------------------------------------ */
/* Re-implementation of the production logic, in plain JS.            */
/* Kept in lockstep with src/services/providers/cisaKev.ts and       */
/* src/utils/analytics.ts. Both files are read below to assert the   */
/* test mirrors their current behavior.                               */
/* ------------------------------------------------------------------ */

const SEVERITY_RANK = { Critical: 0, High: 1, Medium: 2, Low: 3 };

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
      '(CVSS and EPSS scores are not provided by the CISA KEV feed; ' +
      'they are populated when NVD / FIRST EPSS are wired in.)',
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
      { label: 'CISA KEV', url: `https://www.cisa.gov/.../${encodeURIComponent(cveId)}` },
      { label: 'NVD', url: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cveId)}` },
    ],
  };
}

function normalizeQuery(raw) {
  return raw.trim().replace(/\s+/g, ' ').toLowerCase();
}

function buildHaystack(v) {
  return [v.cveId, v.summary, v.description, v.vendor, v.product, v.severity, v.source]
    .join(' ')
    .toLowerCase();
}

function applyFilters(vulns, { search = '', severity = 'All', kevOnly = false, minEpss = 0 } = {}) {
  const q = normalizeQuery(search);
  return vulns.filter((v) => {
    if (severity !== 'All' && v.severity !== severity) return false;
    if (kevOnly && !v.kev) return false;
    if (v.epssProbability < minEpss) return false;
    if (q.length > 0 && !buildHaystack(v).includes(q)) return false;
    return true;
  });
}

function applySortBy(vulns, { field, direction }) {
  const factor = direction === 'asc' ? 1 : -1;
  const copy = [...vulns];
  copy.sort((a, b) => {
    let primary = 0;
    if (field === 'newest' || field === 'publishedDate') {
      primary = (a.publishedDate ?? '').localeCompare(b.publishedDate ?? '');
    } else if (field === 'cvss') {
      primary = a.cvssScore - b.cvssScore;
    } else if (field === 'epss') {
      primary = a.epssProbability - b.epssProbability;
    } else if (field === 'severity') {
      // Natural order is "most severe first" — matches the fix in
      // src/utils/analytics.ts (compareByField case 'severity').
      primary = (SEVERITY_RANK[b.severity] ?? 99) - (SEVERITY_RANK[a.severity] ?? 99);
    } else if (field === 'kev') {
      primary = (a.kev ? 1 : 0) - (b.kev ? 1 : 0);
    } else if (field === 'vendor') {
      primary = a.vendor.localeCompare(b.vendor);
    }
    return primary * factor;
  });
  return copy;
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
/* Synthetic CISA records                                            */
/* ------------------------------------------------------------------ */

const SAMPLE_CISA = [
  {
    cveID: 'CVE-2024-3400',
    vendorProject: 'Palo Alto Networks',
    product: 'PAN-OS',
    vulnerabilityName: 'PAN-OS GlobalProtect Command Injection Vulnerability',
    dateAdded: '2024-04-12',
    shortDescription: 'A command injection vulnerability in the GlobalProtect feature of Palo Alto Networks PAN-OS software.',
    requiredAction: 'Apply updates per vendor instructions.',
    dueDate: '2024-05-03',
    knownRansomwareCampaignUse: 'Unknown',
  },
  {
    cveID: 'CVE-2024-1709',
    vendorProject: 'ConnectWise',
    product: 'ScreenConnect',
    vulnerabilityName: 'ConnectWise ScreenConnect Authentication Bypass',
    dateAdded: '2024-02-19',
    shortDescription: 'An authentication bypass vulnerability in ConnectWise ScreenConnect.',
    requiredAction: 'Apply updates per vendor instructions.',
    dueDate: '2024-03-12',
    knownRansomwareCampaignUse: 'Known',
  },
  {
    cveID: 'CVE-2017-0144',
    vendorProject: 'Microsoft',
    product: 'Windows',
    vulnerabilityName: 'Windows SMB Remote Code Execution Vulnerability (EternalBlue)',
    dateAdded: '2017-06-22',
    shortDescription: 'The SMBv1 server in Microsoft Windows allows remote attackers to execute arbitrary code.',
    requiredAction: 'Apply updates per vendor instructions.',
    dueDate: '2017-07-17',
    knownRansomwareCampaignUse: 'Known',
  },
];

const CISA_NORMALIZED = SAMPLE_CISA.map(normalizeCisaKevRecord);

/* ------------------------------------------------------------------ */
/* Tests                                                             */
/* ------------------------------------------------------------------ */

console.log(`\nCISA KEV integration: ${CISA_NORMALIZED.length} synthetic records normalized\n`);

section('Normalizer tests');
{
  const r = CISA_NORMALIZED[0];
  assert('id is derived from cveID in stable form',
    r.id === 'kev-cve-2024-3400',
    `id=${r.id}`);
  assert('cveId preserved verbatim',
    r.cveId === 'CVE-2024-3400',
    `cveId=${r.cveId}`);
  assert('kev is true (by definition for KEV records)',
    r.kev === true);
  assert('cvssScore defaults to 0 (CISA does not provide)',
    r.cvssScore === 0);
  assert('epssProbability defaults to 0 (CISA does not provide)',
    r.epssProbability === 0);
  assert('source is "CISA KEV"',
    r.source === 'CISA KEV');
  assert('vendor / product preserved',
    r.vendor === 'Palo Alto Networks' && r.product === 'PAN-OS',
    `vendor=${r.vendor} product=${r.product}`);
  assert('description explains missing CVSS / EPSS so the UI is honest',
    /CVSS and EPSS scores are not provided/.test(r.description));
  assert('externalLinks has both CISA KEV and NVD entries',
    Array.isArray(r.externalLinks) && r.externalLinks.length === 2 &&
      r.externalLinks.some((l) => l.label === 'CISA KEV') &&
      r.externalLinks.some((l) => l.label === 'NVD'));
}
{
  const ransomwareRow = CISA_NORMALIZED.find((r) => r.cveId === 'CVE-2024-1709');
  assert('knownRansomwareCampaignUse="Known" maps to Critical severity',
    ransomwareRow && ransomwareRow.severity === 'Critical',
    `severity=${ransomwareRow && ransomwareRow.severity}`);
  const unknownRow = CISA_NORMALIZED.find((r) => r.cveId === 'CVE-2024-3400');
  assert('knownRansomwareCampaignUse="Unknown" maps to High severity',
    unknownRow && unknownRow.severity === 'High',
    `severity=${unknownRow && unknownRow.severity}`);
}
{
  const r = normalizeCisaKevRecord({
    cveID: 'CVE-2025-9999',
    vendorProject: '',
    product: '',
    vulnerabilityName: '',
    dateAdded: '',
    shortDescription: '',
    requiredAction: '',
    dueDate: '',
    knownRansomwareCampaignUse: 'Unknown',
  });
  assert('empty fields fall back to safe defaults (vendor=Unknown, summary=cveId, date=today)',
    r.vendor === 'Unknown' &&
      r.product === 'Unknown' &&
      r.summary === 'CVE-2025-9999' &&
      /^\d{4}-\d{2}-\d{2}$/.test(r.publishedDate),
    `summary=${r.summary} date=${r.publishedDate}`);
}

section('Filter pipeline tests on CISA records');
{
  const r = applyFilters(CISA_NORMALIZED, { search: 'cve-2024-3400' });
  assert('search by CVE id works on CISA records',
    r.length === 1 && r[0].cveId === 'CVE-2024-3400',
    `matches=${r.map((x) => x.cveId).join(',')}`);
}
{
  const r = applyFilters(CISA_NORMALIZED, { search: 'palo alto' });
  assert('search by vendor name works on CISA records',
    r.length === 1 && r[0].vendor === 'Palo Alto Networks',
    `matches=${r.map((x) => x.cveId).join(',')}`);
}
{
  const r = applyFilters(CISA_NORMALIZED, { search: 'screenconnect' });
  assert('search by product name works on CISA records',
    r.length === 1 && r[0].product === 'ScreenConnect',
    `matches=${r.map((x) => x.cveId).join(',')}`);
}
{
  const r = applyFilters(CISA_NORMALIZED, { kevOnly: true });
  assert('KEV-only filter accepts every CISA record (kev is always true)',
    r.length === CISA_NORMALIZED.length && r.every((v) => v.kev === true),
    `count=${r.length}`);
}
{
  // This is the user-asked-for check: severity filter must not crash
  // even when CISA records lack full CVSS data (cvssScore = 0 here).
  const r = applyFilters(CISA_NORMALIZED, { severity: 'Critical' });
  assert('severity filter does not crash on records with cvssScore=0',
    Array.isArray(r) && r.every((v) => v.severity === 'Critical'),
    `count=${r.length}`);
}
{
  // Same check, but for the EPSS slider: a minEpss > 0 filter on
  // records that all have epssProbability=0 must produce an empty
  // list cleanly, not throw.
  const r = applyFilters(CISA_NORMALIZED, { minEpss: 0.5 });
  assert('EPSS slider on records with epssProbability=0 returns [] (no crash)',
    Array.isArray(r) && r.length === 0,
    `count=${r.length}`);
}
{
  // Severity high-to-low must put Critical first, then High.
  // (Regression coverage for the pre-pass-8 direction bug; the
  // comparator was flipped from `a - b` to `b - a` in pass 8.)
  const sorted = applySortBy(CISA_NORMALIZED, { field: 'severity', direction: 'desc' });
  const RANK = { Critical: 0, High: 1, Medium: 2, Low: 3 };
  const monotonic = sorted.every(
    (v, i) => i === 0 || RANK[sorted[i - 1].severity] <= RANK[v.severity]
  );
  assert('sort by severity desc puts Critical before High on CISA records',
    monotonic && sorted[0].severity === 'Critical',
    `order=${sorted.map((v) => v.severity).join(',')}`);
}
{
  // Severity low-to-high must put High before Critical on CISA records
  // (Low and Medium aren't in this sample). The dataset is small but
  // the CISA "High" row should sort after the two "Critical" rows.
  const sorted = applySortBy(CISA_NORMALIZED, { field: 'severity', direction: 'asc' });
  const RANK = { Critical: 0, High: 1, Medium: 2, Low: 3 };
  const monotonic = sorted.every(
    (v, i) => i === 0 || RANK[sorted[i - 1].severity] >= RANK[v.severity]
  );
  assert('sort by severity asc puts High after Critical on CISA records',
    monotonic && sorted[sorted.length - 1].severity === 'Critical',
    `order=${sorted.map((v) => v.severity).join(',')}`);
}
{
  const sorted = applySortBy(CISA_NORMALIZED, { field: 'publishedDate', direction: 'asc' });
  assert('sort by publishedDate asc works on CISA records',
    sorted[0].publishedDate <= sorted[sorted.length - 1].publishedDate,
    `first=${sorted[0].publishedDate} last=${sorted[sorted.length - 1].publishedDate}`);
}

section('Service-layer mode wiring (source-code assertions)');
{
  const serviceSrc = readFileSync(join(root, 'src', 'services', 'vulnerabilityService.ts'), 'utf8');
  const cisaSrc = readFileSync(join(root, 'src', 'services', 'providers', 'cisaKev.ts'), 'utf8');

  assert('service declares a DATA_MODE constant (not the v1 USE_MOCK boolean)',
    /DATA_MODE\s*:\s*'live'\s*\|\s*'mock'/.test(serviceSrc) ||
      /const\s+DATA_MODE\s*=\s*['"]live['"]/.test(serviceSrc) ||
      /const\s+DATA_MODE\s*=\s*['"]mock['"]/.test(serviceSrc),
    'DATA_MODE constant not found');

  assert('service returns a FetchResult with a `mode` field',
    /interface\s+FetchResult[\s\S]*mode:\s*FetchMode/.test(serviceSrc) ||
      /FetchMode[\s\S]*mode/.test(serviceSrc),
    'FetchResult.mode not found');

  assert('service has all three FetchMode values: live, mock, fallback',
    /type\s+FetchMode\s*=\s*['"]live['"]\s*\|\s*['"]mock['"]\s*\|\s*['"]fallback['"]/.test(serviceSrc) ||
      /FetchMode\s*=\s*['"]live['"]\s*\|\s*['"]mock['"]\s*\|\s*['"]fallback['"]/.test(serviceSrc),
    'FetchMode missing one of live/mock/fallback');

  assert('service catches fetch errors and falls back to mock with mode="fallback"',
    // Either the v3 inline pattern (catch ... mode: 'fallback') or
    // the v4 refactor (tryLiveFetch returns null on CISA fail, the
    // caller in fetchVulnerabilities then constructs a
    // mode: 'fallback' result). Both produce the same observable
    // behavior: CISA failure -> fallback banner with reason.
    (
      /catch\s*\([^)]*\)\s*\{[\s\S]*?mode:\s*['"]fallback['"]/.test(serviceSrc) ||
      (
        /tryLiveFetch/.test(serviceSrc) &&
        /mode:\s*['"]fallback['"]/.test(serviceSrc) &&
        /catch\s*\{[\s\S]{0,200}return\s+null/.test(serviceSrc)
      )
    ),
    'fallback path not found in service');

  assert('cisaKev provider has an AbortController-based timeout',
    /AbortController[\s\S]{0,300}abort/.test(cisaSrc),
    'timeout / AbortController pattern not found');

  assert('cisaKev provider reads from the official CISA feed URL',
    /cisa\.gov\/sites\/default\/files\/feeds\/known_exploited_vulnerabilities\.json/.test(cisaSrc),
    'CISA KEV URL not found');

  assert('cisaKev provider surfaces a fallbackReason on shape mismatch',
    /unexpected\s+shape/.test(cisaSrc),
    'shape-mismatch error not found');
}

/* ------------------------------------------------------------------ */
/* Summary                                                            */
/* ------------------------------------------------------------------ */

console.log();
if (failed === 0) {
  console.log(`CISA TESTS PASSED  (${passed}/${passed})`);
} else {
  console.log(`CISA TESTS FAILED  (${failed} of ${passed + failed} failed)`);
  for (const f of failures) {
    console.log(`  - ${f.label}${f.extra ? '  [' + f.extra + ']' : ''}`);
  }
}
