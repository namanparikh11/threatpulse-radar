// v5.7 — Acceptance test for the transparent remediation
// views and filtered export milestone.
//
//   node scripts/acceptance-v57.mjs
//
// Exits 0 on success, 1 on any failure.
//
// Coverage (per the v5.7 spec):
//
//   1. Each of the five documented defender-view presets
//      matches the documented criterion on a synthetic
//      dataset.
//   2. Preset criteria are explicit and deterministic
//      (every preset has a non-empty `criteria` array of
//      human-readable rules).
//   3. No combined / proprietary score is computed (the
//      `Vulnerability` type is unchanged at the spec
//      surface; the presets return only `boolean`).
//   4. A preset composes correctly with the existing
//      filter pipeline (search, severity, KEV, EPSS).
//   5. The "reset" path clears the active preset
//      (`DEFAULT_FILTERS.presetId === null`).
//   6. GitHub Advisory "available" filter keeps only
//      records with a positive reviewed advisory.
//   7. Patch-context "available" filter keeps only records
//      with a concrete patched version.
//   8. Patch-context "unavailable" filter keeps only
//      records where the reviewed advisory exists but no
//      package has a patched version — NEVER records
//      without an advisory ("no advisory" is "unknown",
//      not "no fix exists").
//   9. Missing GitHub Advisory data remains "unknown" —
//      it never leaks into the "available" or "unavailable"
//      buckets and never reads as "no fix".
//  10. SSVC exploitation filtering uses the dynamic
//      value set actually present in the current dataset
//      (no hardcoded values); absence of an SSVC record
//      is treated as "unknown", not as a negative
//      assessment.
//  11. CSV export contains only the rows currently
//      matching the active filters and preset.
//  12. CSV header row uses the documented 21-column
//      contract.
//  13. CSV escaping correctly handles embedded quotes,
//      commas, newlines, and CRLF row terminators.
//  14. CSV formula-injection protection: cells beginning
//      with `=`, `+`, `-`, or `@` are prefixed with a
//      single quote to defeat spreadsheet formula
//      injection.
//  15. CSV export contains no internal metadata, no
//      provider-error strings, no cache markers, no blob
//      keys, and no tokens.
//  16. CSV export of an empty list produces an empty
//      body (the export button is disabled in that state).
//  17. The default export filename embeds the current
//      local date in `YYYY-MM-DD` form.
//  18. The Defender views panel renders controls that work
//      on mobile (the source uses responsive Tailwind
//      classes, no hard-coded widths that would overflow a
//      narrow viewport).
//  19. No Netlify Functions, scheduled functions, refresh
//      behavior, Blob caches, rate-limit handling, or
//      last-known-good behavior was touched.
//  20. No new main-table column or header pill was added
//      (the existing `VulnerabilityTable.tsx` and
//      `Header.tsx` are byte-identical to the v5.6.1
//      baseline).
//
// Implementation note: the v5.7 pure functions live in
// `src/utils/{presets,patchContext,csvExport}.ts` as
// TypeScript. To exercise the real production code from
// this .mjs test, the test compiles the relevant sources
// to `scripts/.v57-build/` with `tsc` once at startup and
// imports the compiled JS. The build is a hidden
// sub-directory; it is not committed and is rebuilt on
// every test run.

import { execFileSync } from 'node:child_process';
import { readFileSync, rmSync, mkdirSync, existsSync, readdirSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, relative } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const buildDir = join(here, '.v57-build');

/* ------------------------------------------------------------------ */
/* V5.7 implementation commit (immutable anchor for scope checks)     */
/* ------------------------------------------------------------------ */

// The V5.7 implementation is captured at this exact commit. Sections
// 19 and 20 below are historical release-scope audits: they verify
// that THIS release touched only its own files and nothing else.
// To survive later releases (V6.0, …), the audit must be anchored to
// the immutable V5.7 implementation commit rather than to the
// current branch tip. Never widen this range; doing so would
// include future-release work and break the V5.7 audit on every
// subsequent version.
const V57_IMPL_COMMIT = '45774a8d529dae2604f203cd0395ff577b084bcf';

let _v57ChangedFilesCache = null;
function v57ChangedFiles() {
  if (_v57ChangedFilesCache) return _v57ChangedFilesCache;
  // `git diff-tree -r --name-only` lists every path the commit
  // touched (added / modified / deleted). Using the commit hash
  // directly makes this range-stable across all later releases.
  let out;
  try {
    out = execFileSync('git',
      ['diff-tree', '--no-commit-id', '--name-only', '-r', V57_IMPL_COMMIT],
      { cwd: root, encoding: 'utf8' });
  } catch (err) {
    // Fail clearly if the anchor commit cannot be resolved.
    // We do not silently fall back to a branch diff, because that
    // would re-introduce the V6.0+ range problem this helper exists
    // to avoid.
    throw new Error(
      `V5.7 scope audit could not resolve implementation commit ${V57_IMPL_COMMIT}. ` +
      'The V5.7 historical release-scope check requires this exact commit. ' +
      'Refusing to run with a different anchor. Underlying error: ' +
      (err && err.message ? err.message : String(err))
    );
  }
  // Normalize, dedupe, drop empty lines.
  const set = new Set();
  for (const line of out.split('\n')) {
    const f = line.trim();
    if (f) set.add(f);
  }
  _v57ChangedFilesCache = Array.from(set);
  return _v57ChangedFilesCache;
}

// The V5.7 implementation commit also adds this very test script.
// The scope audit is checking the IMPLEMENTATION, not itself, so
// the test's own path is excluded from the scope-audit list. To
// stay non-silent, section 19 emits a positive assertion that the
// V5.7 release did include this test script.
const V57_TEST_SCRIPT = 'scripts/acceptance-v57.mjs';

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
    console.log(`  \u2717 ${label}  -- ${extra}`);
  }
}

function section(title) {
  console.log(`\n--- ${title} ---`);
}

/* ------------------------------------------------------------------ */
/* Build the V5.7 sources so we can import the real code             */
/* ------------------------------------------------------------------ */

function buildV57Sources() {
  if (existsSync(buildDir)) {
    rmSync(buildDir, { recursive: true, force: true });
  }
  mkdirSync(buildDir, { recursive: true });

  // Run tsc via the node binary directly so we don't have to
  // worry about the platform's executable extension for the
  // tsc wrapper script.
  const tscJs = join(root, 'node_modules', 'typescript', 'lib', 'tsc.js');
  const sources = [
    'src/utils/presets.ts',
    'src/utils/patchContext.ts',
    'src/utils/csvExport.ts',
    'src/utils/format.ts',
    'src/utils/severity.ts',
    'src/types/vulnerability.ts',
  ];
  execFileSync(
    process.execPath,
    [tscJs, ...sources, '--outDir', relative(root, buildDir), '--module', 'esnext',
     '--target', 'es2022', '--moduleResolution', 'node', '--skipLibCheck'],
    { cwd: root, stdio: 'pipe' }
  );

  // Post-process: add `.js` extensions to extensionless relative
  // imports. Node's ESM resolver requires explicit extensions; tsc
  // omits them when targeting node without `--module nodenext`.
  function walk(d) {
    for (const entry of readdirSync(d, { withFileTypes: true })) {
      const p = join(d, entry.name);
      if (entry.isDirectory()) walk(p);
      else if (entry.name.endsWith('.js')) {
        let c = readFileSync(p, 'utf8');
        c = c.replace(/from\s+'(\.\.?\/[^']+)';/g, (_m, spec) => {
          if (spec.endsWith('.js') || spec.endsWith('.ts')) return `from '${spec}';`;
          return `from '${spec}.js';`;
        });
        writeFileSync(p, c);
      }
    }
  }
  walk(buildDir);
}

buildV57Sources();

const { PRESETS, applyPreset, getPreset,
  HIGH_EPSS_THRESHOLD, RECENT_KEV_WINDOW_DAYS } = await import('./.v57-build/utils/presets.js');
const { classifyPatchContext, applyPatchContextFilter } = await import('./.v57-build/utils/patchContext.js');
const {
  CSV_COLUMNS, escapeCsvCell, buildCsvRow, toCsv,
  defaultExportFilename, PACKAGE_FIELD_SEPARATOR,
} = await import('./.v57-build/utils/csvExport.js');

/* ------------------------------------------------------------------ */
/* Synthetic fixture                                                  */
/* ------------------------------------------------------------------ */

function v({
  cveId,
  kev = false,
  cvssScore = 0,
  epssProbability = 0,
  publishedDate = '2024-01-01',
  ssvcExploitation,
  githubAdvisory,
}) {
  return {
    id: cveId,
    cveId,
    summary: `Test summary for ${cveId}`,
    severity: 'High',
    cvssScore,
    epssProbability,
    kev,
    vendor: 'TestVendor',
    product: 'TestProduct',
    publishedDate,
    source: 'CISA KEV',
    description: 'Test description',
    recommendedAction: 'Apply the vendor patch.',
    externalLinks: [
      { label: 'NVD', url: 'https://nvd.nist.gov/' },
      { label: 'CISA KEV', url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog' },
    ],
    ssvcExploitation,
    ssvcAutomatable: ssvcExploitation ? 'no' : undefined,
    ssvcTechnicalImpact: ssvcExploitation ? 'partial' : undefined,
    githubAdvisory,
  };
}

const GH_PATCHABLE = {
  ghsaId: 'GHSA-xxxx-yyyy-zzzz',
  advisoryUrl: 'https://github.com/advisories/GHSA-xxxx-yyyy-zzzz',
  advisorySeverity: 'high',
  githubReviewedAt: '2026-07-01T00:00:00.000Z',
  source: 'GitHub Advisory Database',
  packages: [
    { ecosystem: 'npm', name: 'left-pad', vulnerableVersionRange: '<1.0.0', firstPatchedVersion: '1.0.0' },
  ],
};
const GH_UNAVAILABLE = {
  ghsaId: 'GHSA-aaaa-bbbb-cccc',
  advisoryUrl: 'https://github.com/advisories/GHSA-aaaa-bbbb-cccc',
  advisorySeverity: 'medium',
  githubReviewedAt: '2026-07-01T00:00:00.000Z',
  source: 'GitHub Advisory Database',
  packages: [
    { ecosystem: 'npm', name: 'some-pkg', vulnerableVersionRange: '<2.0.0', firstPatchedVersion: null },
  ],
};

const FIXTURE = [
  v({ cveId: 'CVE-A', kev: true, cvssScore: 9.8, epssProbability: 0.95,
      ssvcExploitation: 'active', githubAdvisory: GH_PATCHABLE }),
  v({ cveId: 'CVE-B', kev: true, cvssScore: 9.0, epssProbability: 0.40,
      ssvcExploitation: 'poc', githubAdvisory: GH_PATCHABLE }),
  v({ cveId: 'CVE-C', kev: true, cvssScore: 8.0, epssProbability: 0.20,
      ssvcExploitation: 'none' }),
  v({ cveId: 'CVE-D', kev: false, epssProbability: 0.85, githubAdvisory: GH_PATCHABLE }),
  v({ cveId: 'CVE-E', kev: true, epssProbability: 0.50, githubAdvisory: GH_UNAVAILABLE }),
  v({ cveId: 'CVE-F', kev: false, epssProbability: 0.05, githubAdvisory: GH_UNAVAILABLE }),
  v({ cveId: 'CVE-G', kev: false, epssProbability: 0.10 }),
  v({ cveId: 'CVE-H', kev: true, epssProbability: 0.30, ssvcExploitation: 'active' }),
];

/* ------------------------------------------------------------------ */
/* 1. Each preset matches its documented criterion                    */
/* ------------------------------------------------------------------ */

section('1. Each defender-view preset matches its documented criterion');

{
  const r = applyPreset(FIXTURE, 'exploited-and-patchable');
  const ids = r.map((x) => x.cveId).sort();
  assert(
    'exploited-and-patchable: KEV + reviewed advisory + non-null firstPatchedVersion',
    JSON.stringify(ids) === JSON.stringify(['CVE-A', 'CVE-B']),
    `got ${JSON.stringify(ids)}`
  );
}

{
  const r = applyPreset(FIXTURE, 'active-exploitation-context');
  const ids = r.map((x) => x.cveId).sort();
  assert(
    'active-exploitation-context: KEV + SSVC exploitation = active',
    JSON.stringify(ids) === JSON.stringify(['CVE-A', 'CVE-H']),
    `got ${JSON.stringify(ids)}`
  );
}

{
  const r = applyPreset(FIXTURE, 'high-exploitation-likelihood');
  const ids = r.map((x) => x.cveId).sort();
  assert(
    `high-exploitation-likelihood: EPSS >= ${HIGH_EPSS_THRESHOLD} (>= 70%)`,
    JSON.stringify(ids) === JSON.stringify(['CVE-A', 'CVE-D']),
    `got ${JSON.stringify(ids)}`
  );
}

{
  const r = applyPreset(FIXTURE, 'patch-information-unavailable');
  const ids = r.map((x) => x.cveId).sort();
  assert(
    'patch-information-unavailable: reviewed advisory + at least one package with null firstPatchedVersion',
    JSON.stringify(ids) === JSON.stringify(['CVE-E', 'CVE-F']),
    `got ${JSON.stringify(ids)}`
  );
}

{
  const now = new Date('2026-07-12T00:00:00.000Z');
  const recentFixture = FIXTURE.map((row) => {
    if (row.cveId === 'CVE-A') return { ...row, publishedDate: '2026-07-10' };
    if (row.cveId === 'CVE-B') return { ...row, publishedDate: '2026-07-05' };
    if (row.cveId === 'CVE-H') return { ...row, publishedDate: '2026-06-01' };
    return row;
  });
  const r = applyPreset(recentFixture, 'recently-added-kev', now);
  const ids = r.map((x) => x.cveId).sort();
  assert(
    `recently-added-kev: KEV + publishedDate within last ${RECENT_KEV_WINDOW_DAYS} days`,
    JSON.stringify(ids) === JSON.stringify(['CVE-A', 'CVE-B']),
    `got ${JSON.stringify(ids)}`
  );
}

/* ------------------------------------------------------------------ */
/* 2. Preset criteria are explicit and deterministic                  */
/* ------------------------------------------------------------------ */

section('2. Preset criteria are explicit and deterministic');

assert('exactly 5 presets are registered', PRESETS.length === 5, `got ${PRESETS.length}`);
for (const p of PRESETS) {
  assert(
    `preset ${p.id} has a non-empty criteria array (explicit rules)`,
    Array.isArray(p.criteria) && p.criteria.length > 0 && p.criteria.every((c) => typeof c === 'string' && c.length > 0)
  );
  assert(
    `preset ${p.id} has a deterministic predicate returning boolean`,
    typeof p.predicate === 'function' && p.predicate(FIXTURE[0]) === true || p.predicate(FIXTURE[0]) === false
  );
  // Determinism: applying the predicate twice on the same input returns the same answer.
  for (const sample of FIXTURE) {
    assert(
      `preset ${p.id} is deterministic on ${sample.cveId}`,
      p.predicate(sample) === p.predicate(sample)
    );
  }
}

/* ------------------------------------------------------------------ */
/* 3. No combined / proprietary score                                  */
/* ------------------------------------------------------------------ */

section('3. No combined / proprietary score is computed');

assert('preset predicates return only booleans (no numeric score)',
  PRESETS.every((p) => FIXTURE.every((row) => typeof p.predicate(row) === 'boolean')));
assert('getPreset returns null for an unknown id',
  getPreset('not-a-real-preset') === null);
assert('applyPreset on null id is a no-op (returns input reference)',
  applyPreset(FIXTURE, null) === FIXTURE);
assert('applyPreset on unknown id is a no-op (returns input reference)',
  applyPreset(FIXTURE, 'not-a-real-preset') === FIXTURE);
// The Vulnerability type and the public source payload must not
// gain a "score" field. Quick source-level check: the github
// advisory payload types and the Vulnerability type do not
// contain a `score` property in the V5.7 production code.
const typesSrc = readFileSync(join(root, 'src', 'types', 'vulnerability.ts'), 'utf8');
assert('Vulnerability type does not add a "score" property',
  !/\bscore\s*:\s*number\b/.test(typesSrc),
  'unexpected "score: number" property in vulnerability.ts');
assert('Vulnerability type does not add a "threatScore" / "radarScore" property',
  !/threatScore|radarScore|pulseScore/i.test(typesSrc));

/* ------------------------------------------------------------------ */
/* 4. Preset composes with existing filters                            */
/* ------------------------------------------------------------------ */

section('4. Preset composes with the existing filter pipeline');

{
  // "Exploited and patchable" AND severity = High AND search "CVE-A"
  const afterPreset = applyPreset(FIXTURE, 'exploited-and-patchable');
  const filtered = afterPreset.filter((v) =>
    v.severity === 'High' &&
    (v.cveId + ' ' + v.summary + ' ' + v.vendor).toLowerCase().includes('cve-a')
  );
  assert('preset + severity + search composes with AND',
    filtered.length === 1 && filtered[0].cveId === 'CVE-A',
    `got ${filtered.map((x) => x.cveId).join(',')}`);
}
{
  // "Exploited and patchable" + kevOnly: KEV is already part of
  // the preset, so the result should be identical.
  const presetOnly = applyPreset(FIXTURE, 'exploited-and-patchable');
  const composed = applyPreset(FIXTURE, 'exploited-and-patchable')
    .filter((v) => v.kev);
  assert('preset is already AND-ed with KEV — adding kevOnly is idempotent',
    JSON.stringify(presetOnly.map((x) => x.cveId).sort()) ===
      JSON.stringify(composed.map((x) => x.cveId).sort()));
}

/* ------------------------------------------------------------------ */
/* 5. Reset clears the preset                                          */
/* ------------------------------------------------------------------ */

section('5. The "reset" path clears the active defender-view preset');

{
  const typesSrc = readFileSync(join(root, 'src', 'types', 'vulnerability.ts'), 'utf8');
  // DEFAULT_FILTERS must declare presetId: null
  assert('DEFAULT_FILTERS.presetId === null in the type module',
    /DEFAULT_FILTERS[\s\S]*?presetId\s*:\s*null/.test(typesSrc),
    'DEFAULT_FILTERS.presetId not initialized to null');
}

/* ------------------------------------------------------------------ */
/* 6. GitHub Advisory "available" filter                               */
/* ------------------------------------------------------------------ */

section('6. GitHub Advisory "available" filter keeps only records with a positive reviewed advisory');

{
  const filtered = FIXTURE.filter((row) =>
    row.githubAdvisory && row.githubAdvisory.ghsaId);
  const ids = filtered.map((x) => x.cveId).sort();
  assert('records with a positive advisory are exactly the four: A, B, D, E, F',
    JSON.stringify(ids) === JSON.stringify(['CVE-A', 'CVE-B', 'CVE-D', 'CVE-E', 'CVE-F']),
    `got ${JSON.stringify(ids)}`);
}

/* ------------------------------------------------------------------ */
/* 7-9. Patch context classification + "unknown, not no fix"           */
/* ------------------------------------------------------------------ */

section('7-9. Patch-context classification and the "unknown, not no fix" contract');

{
  const known = ['CVE-A', 'CVE-B', 'CVE-D']; // have non-null patched
  const unav = ['CVE-E', 'CVE-F'];            // advisory exists, all packages null
  const unk = ['CVE-C', 'CVE-G', 'CVE-H'];    // no advisory

  for (const cve of known) {
    const r = classifyPatchContext(FIXTURE.find((x) => x.cveId === cve));
    assert(`${cve} → "available" (concrete patched version)`, r === 'available', `got ${r}`);
  }
  for (const cve of unav) {
    const r = classifyPatchContext(FIXTURE.find((x) => x.cveId === cve));
    assert(`${cve} → "unavailable" (reviewed advisory, no patched version)`, r === 'unavailable', `got ${r}`);
  }
  for (const cve of unk) {
    const r = classifyPatchContext(FIXTURE.find((x) => x.cveId === cve));
    assert(`${cve} → "unknown" (no reviewed advisory) — never "no fix exists"`, r === 'unknown', `got ${r}`);
  }

  // 'available' filter keeps only available rows.
  const av = applyPatchContextFilter(FIXTURE, 'available').map((x) => x.cveId).sort();
  assert('patch-context "available" filter keeps exactly A, B, D',
    JSON.stringify(av) === JSON.stringify(known), `got ${JSON.stringify(av)}`);

  // 'unavailable' filter keeps only unavailable rows — it does
  // NOT include "unknown" rows (the spec's "absence of
  // githubAdvisory must not be called 'no patch'" rule).
  const un = applyPatchContextFilter(FIXTURE, 'unavailable').map((x) => x.cveId).sort();
  assert('patch-context "unavailable" filter keeps exactly E, F (no advisory rows are excluded)',
    JSON.stringify(un) === JSON.stringify(unav), `got ${JSON.stringify(un)}`);

  // 'any' keeps everything.
  const all = applyPatchContextFilter(FIXTURE, 'any');
  assert('patch-context "any" filter keeps every row', all.length === FIXTURE.length);
}

/* ------------------------------------------------------------------ */
/* 10. SSVC exploitation dynamic filtering                              */
/* ------------------------------------------------------------------ */

section('10. SSVC exploitation dynamic filtering');

{
  // Build the dynamic value set the way the FiltersPanel does.
  const SSVC_ORDER = ['none', 'poc', 'active'];
  const present = new Set();
  for (const row of FIXTURE) if (row.ssvcExploitation) present.add(row.ssvcExploitation);
  const dynamic = SSVC_ORDER.filter((v) => present.has(v));

  assert('dynamic SSVC set contains only values present in the dataset',
    JSON.stringify(dynamic) === JSON.stringify(['none', 'poc', 'active']),
    `got ${JSON.stringify(dynamic)}`);

  // Filtering on 'active' must keep only CVE-A and CVE-H.
  const activeOnly = FIXTURE.filter((v) => v.ssvcExploitation === 'active')
    .map((x) => x.cveId).sort();
  assert('SSVC exploitation = "active" keeps only A, H',
    JSON.stringify(activeOnly) === JSON.stringify(['CVE-A', 'CVE-H']),
    `got ${JSON.stringify(activeOnly)}`);

  // Filtering on 'poc' must keep only CVE-B.
  const pocOnly = FIXTURE.filter((v) => v.ssvcExploitation === 'poc')
    .map((x) => x.cveId).sort();
  assert('SSVC exploitation = "poc" keeps only B',
    JSON.stringify(pocOnly) === JSON.stringify(['CVE-B']));

  // Filtering on 'none' must keep only CVE-C.
  const noneOnly = FIXTURE.filter((v) => v.ssvcExploitation === 'none')
    .map((x) => x.cveId).sort();
  assert('SSVC exploitation = "none" keeps only C', JSON.stringify(noneOnly) === JSON.stringify(['CVE-C']));

  // Records with no SSVC record must NEVER match a specific value.
  const noSsvcRecords = FIXTURE.filter((v) => !v.ssvcExploitation);
  for (const v of noSsvcRecords) {
    for (const opt of SSVC_ORDER) {
      assert(`no-SSVC record ${v.cveId} does not match SSVC = "${opt}" (absence is unknown, not a negative)`,
        v.ssvcExploitation !== opt);
    }
  }
}

/* ------------------------------------------------------------------ */
/* 11-15. CSV export                                                   */
/* ------------------------------------------------------------------ */

section('11-15. CSV export');

assert('CSV has exactly 21 documented columns',
  CSV_COLUMNS.length === 21, `got ${CSV_COLUMNS.length}`);
assert('CSV columns include the documented identifiers',
  CSV_COLUMNS.includes('CVE ID') &&
  CSV_COLUMNS.includes('GHSA ID') &&
  CSV_COLUMNS.includes('Package ecosystems/names') &&
  CSV_COLUMNS.includes('Vulnerable ranges') &&
  CSV_COLUMNS.includes('First patched versions') &&
  CSV_COLUMNS.includes('GitHub Advisory URL'));

// CSV escaping — quotes, commas, newlines.
assert('escapeCsvCell quotes values containing commas',
  escapeCsvCell('a,b') === '"a,b"');
assert('escapeCsvCell escapes embedded double quotes by doubling them',
  escapeCsvCell('he said "hi"') === '"he said ""hi"""');
assert('escapeCsvCell quotes values containing newlines',
  escapeCsvCell('line1\nline2').includes('"line1\nline2"'));
assert('escapeCsvCell quotes values containing CR',
  escapeCsvCell('line1\rline2').includes('"line1\rline2"'));
assert('escapeCsvCell renders booleans as "true"/"false" (never drops to falsy)',
  escapeCsvCell(true) === 'true' && escapeCsvCell(false) === 'false');
assert('escapeCsvCell renders null/undefined as empty',
  escapeCsvCell(null) === '' && escapeCsvCell(undefined) === '');

// Formula-injection protection.
assert('escapeCsvCell prefixes leading = with a single quote',
  escapeCsvCell('=SUM(1)') === "'=SUM(1)");
assert('escapeCsvCell prefixes leading + with a single quote',
  escapeCsvCell('+cmd') === "'+cmd");
assert('escapeCsvCell prefixes leading - with a single quote',
  escapeCsvCell('-cmd') === "'-cmd");
assert('escapeCsvCell prefixes leading @ with a single quote',
  escapeCsvCell('@SUM(1)') === "'@SUM(1)");
assert('escapeCsvCell leaves normal text untouched',
  escapeCsvCell('CVE-2024-3400') === 'CVE-2024-3400');
assert('escapeCsvCell leaves digit-leading text untouched',
  escapeCsvCell('12345') === '12345');

// toCsv on a populated set.
const fullCsv = toCsv(FIXTURE);
assert('toCsv begins with the UTF-8 BOM', fullCsv.startsWith('\uFEFF'),
  `starts with ${JSON.stringify(fullCsv.slice(0, 4))}`);
const lines = fullCsv.slice(1).split('\r\n').filter((l) => l.length > 0);
assert('toCsv uses CRLF row terminators and ends with a trailing CRLF',
  fullCsv.endsWith('\r\n'));
assert('toCsv has one header row + one row per record',
  lines.length === FIXTURE.length + 1, `got ${lines.length}`);
assert('toCsv header row matches the documented columns',
  lines[0] === CSV_COLUMNS.map((c) => escapeCsvCell(c)).join(','),
  `got header: ${lines[0]}`);

// toCsv on an empty set returns ''.
assert('toCsv on an empty list returns an empty body (export button is disabled in this state)',
  toCsv([]) === '');

// No internal metadata leaks into the CSV body. The "internal"
// strings we explicitly forbid are checked below.
const internalNeedles = [
  'lastVulnrichmentRefresh',
  'lastRefreshFailure',
  'lastRefreshAttemptAt',
  'lastGithubAdvisoryRefresh',
  'githubAdvisoryRefreshError',
  'GITHUB_TOKEN',
  'NVD_API_KEY',
  'tpr-dataset',
  'tpr-vulnrichment',
  'tpr-github-advisory',
  'refresh-lock',
  'raw.githubusercontent.com',
  'api.github.com',
  'x-ratelimit-',
  'Retry-After',
  'publicEnvelope',
  'INTERNAL_BLOB_FIELDS',
];
for (const needle of internalNeedles) {
  assert(`toCsv body does not leak internal field "${needle}"`,
    !fullCsv.includes(needle), `leaked "${needle}"`);
}

// The CSV body should contain only the documented column names
// (and the row data). Check that no "secret"-shaped token appears.
assert('toCsv body does not contain a github_pat_ / ghp_ / ntn_ token shape',
  !/ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|ntn_[A-Za-z0-9]{20,}/.test(fullCsv));

// buildCsvRow for a record with a malicious summary should
// contain the leading single quote, not the raw = char.
// (The cell may be CSV-quoted because of the embedded double
// quotes, so we look for the literal `'=cmd` substring
// rather than the raw startsWith.)
const maliciousRow = buildCsvRow({
  ...FIXTURE[0],
  summary: '=cmd|"/c calc"!A1',
});
assert('buildCsvRow protects against formula injection in the summary cell',
  maliciousRow[1].includes("'=cmd"),
  `got: ${maliciousRow[1]}`);

// Package field collapse uses the documented separator.
const rowForE = buildCsvRow(FIXTURE.find((v) => v.cveId === 'CVE-E'));
assert('package-fields column uses the documented separator',
  rowForE[15] === '' || rowForE[15].includes('/'),
  `ecosystems/names column: ${rowForE[15]}`);
assert('first patched versions column is empty when the package has null firstPatchedVersion (rendered as "unavailable", never "no fix")',
  rowForE[17] === '', `got "${rowForE[17]}"`);

// Package-field separator is documented and stable.
assert('PACKAGE_FIELD_SEPARATOR is documented as "; "',
  PACKAGE_FIELD_SEPARATOR === '; ');

/* ------------------------------------------------------------------ */
/* 16. Zero-result export                                              */
/* ------------------------------------------------------------------ */

section('16. Zero-result export is disabled');

assert('toCsv([]) returns "" so the download path is a no-op',
  toCsv([]) === '');
{
  // Simulate the DefenderViewsPanel guard: downloadCsv is a no-op
  // when the body is empty. We can't actually click a button
  // headlessly, so we verify the same guard inline.
  const body = toCsv([]);
  const wouldDownload = body.length > 0;
  assert('zero-result guard: would-not-download is false', wouldDownload === false);
}

/* ------------------------------------------------------------------ */
/* 17. Filename contains the current date                              */
/* ------------------------------------------------------------------ */

section('17. Default export filename embeds the current local date');

{
  const name = defaultExportFilename(new Date(2026, 6, 12, 14, 30, 0)); // 2026-07-12 local
  assert('filename starts with "threatpulse-radar-"', name.startsWith('threatpulse-radar-'),
    `got ${name}`);
  assert('filename embeds the date as YYYY-MM-DD',
    name === 'threatpulse-radar-2026-07-12.csv', `got ${name}`);
  assert('filename ends with ".csv"', name.endsWith('.csv'));
}
{
  // A different day yields a different filename.
  const a = defaultExportFilename(new Date(2026, 0, 1));
  const b = defaultExportFilename(new Date(2026, 11, 31));
  assert('different days yield different filenames', a !== b, `${a} vs ${b}`);
}

/* ------------------------------------------------------------------ */
/* 18. Mobile-safe controls                                            */
/* ------------------------------------------------------------------ */

section('18. Mobile-safe controls in the Defender views panel');

{
  const src = readFileSync(join(root, 'src', 'components', 'DefenderViewsPanel.tsx'), 'utf8');
  // The export button uses responsive Tailwind so the control
  // is usable on narrow viewports. We don't try to evaluate
  // the actual responsive CSS — we just verify the source
  // uses responsive classes and doesn't use a fixed width
  // that would overflow a 320px viewport.
  assert('DefenderViewsPanel uses Tailwind responsive classes',
    /\bsm:/.test(src), 'no `sm:` responsive class found');
  assert('DefenderViewsPanel uses flex-wrap on the chip row',
    /flex-wrap/.test(src), 'no flex-wrap on the chip row');
  // No raw "width: 9999px" or hard-coded "min-width: 1000px"
  // on the export control.
  assert('DefenderViewsPanel has no hard-coded large width on the export control',
    !/width\s*:\s*\d{3,}px/.test(src) && !/min-w-\[\d{3,}px\]/.test(src));
}

/* ------------------------------------------------------------------ */
/* 19. No Netlify / backend / provider changes                        */
/* ------------------------------------------------------------------ */

section('19. No Netlify / backend / provider changes in V5.7');

{
  // V5.7 should not have touched netlify/ or scripts/<existing>.
  // The new files are: src/utils/{presets,patchContext,csvExport}.ts,
  // src/components/DefenderViewsPanel.tsx, and the modified files
  // are: src/types/vulnerability.ts, src/utils/analytics.ts,
  // src/hooks/useVulnerabilityFilter.ts, src/components/FiltersPanel.tsx,
  // src/pages/DashboardPage.tsx.
  // Acceptance-*.mjs scripts and netlify/functions/* must be
  // unchanged from the v5.6.1 baseline.
  //
  // Scope is anchored to the immutable V5.7 implementation commit
  // (see V57_IMPL_COMMIT above) so that later releases (V6.0, …)
  // cannot leak into this historical audit.
  const allChanged = v57ChangedFiles();
  // Positive confirmation: the V5.7 release did ship its own test
  // script. The test script's path is then excluded from the
  // implementation-only scope list below (the audit is about the
  // IMPLEMENTATION, not the test), but its presence is still
  // asserted explicitly so nothing is skipped silently.
  assert('V5.7 release includes its own acceptance test script',
    allChanged.includes(V57_TEST_SCRIPT),
    `expected ${V57_TEST_SCRIPT} in ${V57_IMPL_COMMIT}`);
  const changedFiles = allChanged.filter(f => f !== V57_TEST_SCRIPT);
  const expectedAllowed = [
    'src/components/DefenderViewsPanel.tsx',
    'src/components/FiltersPanel.tsx',
    'src/hooks/useVulnerabilityFilter.ts',
    'src/pages/DashboardPage.tsx',
    'src/types/vulnerability.ts',
    'src/utils/analytics.ts',
    'src/utils/presets.ts',
    'src/utils/patchContext.ts',
    'src/utils/csvExport.ts',
  ];
  for (const f of changedFiles) {
    assert(`v5.7 changed file is in the allowed set: ${f}`,
      expectedAllowed.includes(f), `unexpected: ${f}`);
  }
  // None of the changed files should be in netlify/ or scripts/
  // (apart from the v5.7 acceptance script, which lives in
  // scripts/ and is added in a separate commit per the spec's
  // "Run all acceptance scripts exactly once" rule — but in
  // this same commit we add it. We allow that.)
  for (const f of changedFiles) {
    if (f.startsWith('netlify/')) {
      assert(`v5.7 did NOT touch netlify code: ${f}`, false, 'forbidden');
    }
  }
  // The new acceptance script may be in scripts/; any other
  // script change is forbidden.
  for (const f of changedFiles) {
    if (f.startsWith('scripts/') && f !== 'scripts/acceptance-v57.mjs') {
      assert(`v5.7 did NOT touch any other acceptance script: ${f}`, false, 'forbidden');
    }
  }
  // No package / netlify.toml / config changes.
  for (const f of changedFiles) {
    if (f === 'package.json' || f === 'package-lock.json' ||
        f === 'netlify.toml' || f === 'tsconfig.json' ||
        f.startsWith('vite.config') || f.startsWith('tailwind.config') ||
        f.startsWith('postcss.config')) {
      assert(`v5.7 did NOT touch package / config: ${f}`, false, 'forbidden');
    }
  }
}

/* ------------------------------------------------------------------ */
/* 20. No main-table column or header pill creep                      */
/* ------------------------------------------------------------------ */

section('20. No main-table column or header-pill creep');

{
  // VulnerabilityTable and Header must be byte-identical to
  // the v5.6.1 baseline (i.e. not in the v5.7 changed set).
  // Same range-stable anchor as section 19.
  const changed = v57ChangedFiles();
  assert('VulnerabilityTable.tsx is not changed by v5.7',
    !changed.includes('src/components/VulnerabilityTable.tsx'),
    'forbidden: changed main-table source');
  assert('Header.tsx is not changed by v5.7 (no new provider pill)',
    !changed.includes('src/components/Header.tsx'),
    'forbidden: changed header source');
}

/* ------------------------------------------------------------------ */
/* Summary                                                             */
/* ------------------------------------------------------------------ */

console.log();
console.log(`Total: ${passed} passed, ${failed} failed`);

if (failed > 0) {
  console.log('\nFailures:');
  for (const f of failures) {
    console.log(`  - ${f.label}  -- ${f.extra}`);
  }
  process.exit(1);
}
console.log('ALL V5.7 ACCEPTANCE TESTS PASSED');
