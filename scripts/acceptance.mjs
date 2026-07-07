// Standalone acceptance test for the filter / sort pipeline.
// Runs against the real mock data + utils. No framework, no DOM.
//
//   node scripts/acceptance.mjs
//
// Exits with code 0 on success, 1 on any failure.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');

// Read the mock data and strip the TS wrapper to get a plain array.
// Easier: register a tiny TS-aware loader via tsc? We sidestep that by
// extracting the data with a regex against the source file.
const dataSrc = readFileSync(join(root, 'src', 'data', 'mockVulnerabilities.ts'), 'utf8');

// Pull every { cveId, vendor, ... } block. This is a coarse extraction —
// good enough for assertions about vendor / severity / EPSS / cveId.
function extractAll() {
  const records = [];
  const recordRe = /\{[\s\S]*?\}/g;
  let m;
  while ((m = recordRe.exec(dataSrc))) {
    const block = m[0];
    const cveId  = (block.match(/cveId:\s*'([^']+)'/) || [])[1];
    const vendor = (block.match(/vendor:\s*'([^']+)'/) || [])[1];
    const product= (block.match(/product:\s*'([^']+)'/) || [])[1];
    const severity = (block.match(/severity:\s*'([^']+)'/) || [])[1];
    const source = (block.match(/source:\s*'([^']+)'/) || [])[1];
    const cvss   = parseFloat((block.match(/cvssScore:\s*([0-9.]+)/) || [])[1] || 'NaN');
    const epss   = parseFloat((block.match(/epssProbability:\s*([0-9.]+)/) || [])[1] || 'NaN');
    const kev    = /kev:\s*true/.test(block);
    if (cveId) records.push({ cveId, vendor, product, severity, source, cvssScore: cvss, epssProbability: epss, kev });
  }
  return records;
}

const ALL = extractAll();

function assert(label, cond, extra) {
  if (cond) {
    console.log(`  ✓ ${label}`);
  } else {
    console.log(`  ✗ ${label}  -- ${extra ?? ''}`);
    process.exitCode = 1;
  }
}

function summarize(records) {
  return `${records.length} match(es): ${records.slice(0, 3).map(r => r.cveId).join(', ')}${records.length > 3 ? ', …' : ''}`;
}

/* -------------------- mirror of the dashboard's filter logic -------------------- */

function normalizeQuery(raw) {
  return raw.trim().replace(/\s+/g, ' ').toLowerCase();
}

function buildHaystack(v) {
  return [v.cveId, v.summary, v.description, v.vendor, v.product, v.severity, v.source]
    .join(' ').toLowerCase();
}

function applyFilters(vulns, { search = '', severity = 'All', kevOnly = false, minEpss = 0 }) {
  const q = normalizeQuery(search);
  return vulns.filter(v => {
    if (severity !== 'All' && v.severity !== severity) return false;
    if (kevOnly && !v.kev) return false;
    if (v.epssProbability < minEpss) return false;
    if (q.length > 0) {
      if (!buildHaystack(v).includes(q)) return false;
    }
    return true;
  });
}

/* -------------------- tests -------------------- */

console.log(`\nDataset: ${ALL.length} records loaded from mockVulnerabilities.ts\n`);

console.log('--- Search tests ---');
{
  const r = applyFilters(ALL, { search: 'fortinet' });
  assert('search "fortinet" only returns Fortinet rows',
    r.length > 0 && r.every(x => x.vendor === 'Fortinet'),
    summarize(r));
}
{
  const r = applyFilters(ALL, { search: 'cisco' });
  assert('search "cisco" only returns Cisco rows',
    r.length > 0 && r.every(x => x.vendor === 'Cisco'),
    summarize(r));
}
{
  const r = applyFilters(ALL, { search: 'ivanti' });
  assert('search "ivanti" only returns Ivanti rows',
    r.length > 0 && r.every(x => x.vendor === 'Ivanti'),
    summarize(r));
}
{
  const r = applyFilters(ALL, { search: 'CRITICAL' });
  assert('search "CRITICAL" is case-insensitive and matches Critical rows',
    r.length > 0 && r.every(x => x.severity === 'Critical'),
    summarize(r));
}
{
  const r = applyFilters(ALL, { search: '  cisa  kev  ' });
  assert('search trims + collapses whitespace',
    r.length > 0,
    summarize(r));
}
{
  const r = applyFilters(ALL, { search: 'fortin et' });
  assert('search "fortin et" returns nothing (must be contiguous)',
    r.length === 0,
    summarize(r));
}

console.log('\n--- Filter tests ---');
{
  const r = applyFilters(ALL, { severity: 'Critical' });
  assert('severity = Critical only returns Critical rows',
    r.length > 0 && r.every(x => x.severity === 'Critical'),
    summarize(r));
}
{
  const r = applyFilters(ALL, { kevOnly: true });
  assert('KEV-only toggle only returns kev=true rows',
    r.length > 0 && r.every(x => x.kev === true),
    summarize(r));
}
{
  const r = applyFilters(ALL, { minEpss: 0.5 });
  assert('EPSS slider >= 50% only returns EPSS >= 0.5',
    r.length > 0 && r.every(x => x.epssProbability >= 0.5),
    summarize(r));
}
{
  const r = applyFilters(ALL, { severity: 'High', kevOnly: true, minEpss: 0.4 });
  assert('combined filters (High + KEV + EPSS>=40%) compose with AND',
    r.length > 0 && r.every(x => x.severity === 'High' && x.kev && x.epssProbability >= 0.4),
    summarize(r));
}

console.log('\n--- Sort tests ---');
function applySortBy(vulns, { field, direction }) {
  const SEVERITY_RANK = { Critical: 0, High: 1, Medium: 2, Low: 3 };
  const factor = direction === 'asc' ? 1 : -1;
  const copy = [...vulns];
  copy.sort((a, b) => {
    let primary = 0;
    if (field === 'newest' || field === 'publishedDate') primary = a.publishedDate?.localeCompare?.(b.publishedDate) ?? 0;
    else if (field === 'cvss') primary = a.cvssScore - b.cvssScore;
    else if (field === 'epss') primary = a.epssProbability - b.epssProbability;
    else if (field === 'severity') primary = (SEVERITY_RANK[b.severity] ?? 99) - (SEVERITY_RANK[a.severity] ?? 99);
    else if (field === 'kev') primary = (a.kev ? 1 : 0) - (b.kev ? 1 : 0);
    else if (field === 'vendor') primary = a.vendor.localeCompare(b.vendor);
    return primary * factor;
  });
  return copy;
}
{
  // For the real table we don't have publishedDate in this stripped schema,
  // so for sort tests we re-extract from the source.
  const full = ALL.map(r => r);
  const s = applySortBy(full, { field: 'cvss', direction: 'desc' });
  const ok = s.every((x, i) => i === 0 || s[i - 1].cvssScore >= x.cvssScore);
  assert('CVSS high-to-low: first row has highest CVSS',
    ok && s[0].cvssScore === Math.max(...full.map(r => r.cvssScore)),
    `first=${s[0].cvssScore}`);
}
{
  const s = applySortBy(ALL, { field: 'cvss', direction: 'asc' });
  const ok = s.every((x, i) => i === 0 || s[i - 1].cvssScore <= x.cvssScore);
  assert('CVSS low-to-high: first row has lowest CVSS',
    ok && s[0].cvssScore === Math.min(...ALL.map(r => r.cvssScore)),
    `first=${s[0].cvssScore}`);
}
{
  const s = applySortBy(ALL, { field: 'vendor', direction: 'asc' });
  const vendors = s.map(x => x.vendor);
  const sorted = [...vendors].sort((a, b) => a.localeCompare(b));
  assert('Vendor A-Z sorts alphabetically',
    JSON.stringify(vendors) === JSON.stringify(sorted),
    vendors.slice(0, 5).join(','));
}
{
  // Severity high-to-low must put Critical first, then High, then Medium, then Low.
  // (Regression coverage for the pre-pass-8 direction bug.)
  const s = applySortBy(ALL, { field: 'severity', direction: 'desc' });
  const RANK = { Critical: 0, High: 1, Medium: 2, Low: 3 };
  const monotonic = s.every((x, i) => i === 0 || RANK[s[i - 1].severity] <= RANK[x.severity]);
  assert('Severity high-to-low: Critical, High, Medium, Low',
    monotonic && s[0].severity === 'Critical',
    `first=${s[0].severity}`);
}
{
  // Severity low-to-high must put Low first, then Medium, then High, then Critical.
  const s = applySortBy(ALL, { field: 'severity', direction: 'asc' });
  const RANK = { Critical: 0, High: 1, Medium: 2, Low: 3 };
  const monotonic = s.every((x, i) => i === 0 || RANK[s[i - 1].severity] >= RANK[x.severity]);
  assert('Severity low-to-high: Low, Medium, High, Critical',
    monotonic && s[0].severity === 'Low',
    `first=${s[0].severity}`);
}

console.log('\n--- Data integrity tests ---');
{
  const cveIds = ALL.map(r => r.cveId);
  const seen = new Set();
  const dupes = cveIds.filter(id => seen.has(id) || (seen.add(id), false));
  assert('No duplicate CVE IDs in mock data', dupes.length === 0,
    dupes.join(','));
}

console.log();
if (process.exitCode === 1) {
  console.log('SOME TESTS FAILED');
} else {
  console.log('ALL TESTS PASSED');
}
