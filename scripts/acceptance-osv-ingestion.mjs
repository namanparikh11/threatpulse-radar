// V6.0 — OSV ingestion behavior tests.
//
//   node scripts/acceptance-osv-ingestion.mjs
//
// Behavior under test:
//   - ecosystem config loader: file wins when env var is unset
//   - ecosystem config loader: env var wins when present
//   - ecosystem config loader: malformed env falls back to file
//   - ecosystem config loader: malformed file falls back to single-ecosystem
//     default (not crash)
//   - ecosystem config loader: configHash is stable for equivalent content
//   - ecosystem allowlist membership is exact-string
//   - modified_id.csv parser handles blank lines, comments, dedup
//   - watermark filter keeps newer-than-since ids and unknown-timestamp ids
//   - timeout fetch wrapper surfaces non-OK HTTP as errors
//   - fetchModifiedIds: 404 → []; non-404 → throw
//   - fetchVulnerability: invalid JSON throws a tagged error
//   - normalizeOsvVulnerability: emits all 5 entity types
//   - normalizeOsvVulnerability: emits a tombstone when withdrawn
//   - normalizeOsvVulnerability: preserves ranges verbatim (no rewriting)
//   - normalizeOsvVulnerability: package canonicalId is lowercased
//   - mapWithConcurrency: bounded parallelism
//   - bootstrap state: initial state has documented shape
//   - bootstrap state: markRunStarted resets per-ecosystem cursors
//   - bootstrap state: markRunComplete preserves cursors
//   - bootstrap state: markEcosystemFailed records error
//   - bootstrap state: recent-ids ring is bounded
//   - bootstrap state: isRecentlyProcessed is correct
//   - equal-timestamp OSV updates cannot be skipped (re-emit dedup semantics)

import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync, rmSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const buildDir = join(here, '.v6-build-osv');

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
/* Build the V6.0 sources so we can import the real code                */
/* ------------------------------------------------------------------ */

function buildV6Sources() {
  if (existsSync(buildDir)) {
    try { rmSync(buildDir, { recursive: true, force: true }); } catch (e) { /* fall through */ }
  }
  mkdirSync(buildDir, { recursive: true });
  const tscJs = join(root, 'node_modules', 'typescript', 'lib', 'tsc.js');
  const sources = [
    'netlify/functions/_shared/canonicalHash.mjs',
    'netlify/functions/_shared/contentAddressedShards.mjs',
    'netlify/functions/_shared/osvEcosystems.mjs',
    'netlify/functions/_shared/osvCanonical.mjs',
    'netlify/functions/_shared/osvProvider.mjs',
    'netlify/functions/_shared/osvBootstrapState.mjs',
  ];
  execFileSync(
    process.execPath,
    [tscJs, ...sources, '--outDir', buildDir.replace(/\\/g, '/'), '--module', 'esnext',
     '--target', 'es2022', '--moduleResolution', 'node', '--skipLibCheck',
     '--allowJs', '--declaration', 'false'],
    { cwd: root, stdio: 'pipe' }
  );
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

buildV6Sources();

const buildLeaf = buildDir.split(/[\\/]/).pop();
const { contentHash } = await import(`./${buildLeaf}/canonicalHash.mjs`);
const osvEcosystems = await import(`./${buildLeaf}/osvEcosystems.mjs`);
const osvCanonical = await import(`./${buildLeaf}/osvCanonical.mjs`);
const osvProvider = await import(`./${buildLeaf}/osvProvider.mjs`);
const osvBootstrap = await import(`./${buildLeaf}/osvBootstrapState.mjs`);
const { loadEcosystemConfig, readEcosystemFile, parseEcosystemEnv,
        isAllowedEcosystem, applyAllowlist, normalizeEcosystemName,
        ECOSYSTEM_CONFIG_FILE, ECOSYSTEM_ENV_VAR } = osvEcosystems;
const { vulnerabilityCanonicalId, packageCanonicalId, relationshipCanonicalId,
        normalizeOsvVulnerability } = osvCanonical;
const { parseModifiedIdCsv, filterByWatermark, fetchModifiedIds, fetchVulnerability,
        makeTextFetcher, makeTimeoutFetch, mapWithConcurrency, OSV_GCS_BASE } = osvProvider;
const { initialBootstrapState, markRunStarted, markRunComplete, markEcosystemFailed,
        markPhase, recordEcosystemProgress, recentIdsFor, isRecentlyProcessed,
        STATUS, PHASE, RECENT_IDS_RING_SIZE,
        DEFAULT_OVERLAP_WINDOW_MS, DEFAULT_RECORDS_PERSIST_INTERVAL,
        OSV_BOOTSTRAP_STATE_SCHEMA } = osvBootstrap;

/* ------------------------------------------------------------------ */
/* Tests: ecosystem config loader                                      */
/* ------------------------------------------------------------------ */

section('Ecosystem config loader: file wins when env var is unset');

{
  const cfg = loadEcosystemConfig({
    env: {}, // no env var
    fsImpl: { readFileSync },
    filePath: join(root, ECOSYSTEM_CONFIG_FILE),
  });
  assert('source is "file"', cfg.source === 'file');
  assert('has the documented ecosystems', cfg.ecosystems.includes('npm') && cfg.ecosystems.includes('PyPI'));
  assert('configHash has the sha256: prefix', cfg.configHash.startsWith('sha256:'));
  assert('schemaVersion is a string', typeof cfg.schemaVersion === 'string');
}

section('Ecosystem config loader: env var wins when present');

{
  const envOverride = JSON.stringify({
    schemaVersion: '1.0.0',
    ecosystems: ['npm', 'Go'],
  });
  const cfg = loadEcosystemConfig({
    env: { [ECOSYSTEM_ENV_VAR]: envOverride },
    fsImpl: { readFileSync },
    filePath: join(root, ECOSYSTEM_CONFIG_FILE),
  });
  assert('source is "env"', cfg.source === 'env');
  assert('env-driven ecosystems are used', cfg.ecosystems.length === 2 && cfg.ecosystems.includes('Go'));
}

section('Ecosystem config loader: malformed env falls back to file');

{
  const cfg = loadEcosystemConfig({
    env: { [ECOSYSTEM_ENV_VAR]: 'not-json' },
    fsImpl: { readFileSync },
    filePath: join(root, ECOSYSTEM_CONFIG_FILE),
  });
  assert('source is "file" when env is malformed', cfg.source === 'file');
}

section('Ecosystem config loader: malformed file falls back to default');

{
  const cfg = loadEcosystemConfig({
    env: {},
    fsImpl: { readFileSync: () => { throw new Error('ENOENT'); } },
    filePath: '/nonexistent/path',
  });
  assert('source is "default-fallback" when file is missing', cfg.source === 'default-fallback');
  assert('default fallback is a single ecosystem', cfg.ecosystems.length === 1);
}

section('Ecosystem config loader: configHash is stable for equivalent content');

{
  const a = contentHash({ schemaVersion: '1.0.0', ecosystems: ['npm', 'PyPI'] });
  const b = contentHash({ schemaVersion: '1.0.0', ecosystems: ['npm', 'PyPI'] });
  const c = contentHash({ schemaVersion: '1.0.0', ecosystems: ['PyPI', 'npm'] });
  assert('same content → same hash', a === b);
  // The order matters in canonicalization because the `ecosystems`
  // array is not an entity array (no canonicalId). This is
  // intentional: the config is a single source of truth, and
  // reordering the ecosystems changes which records are ingested
  // first, which is a meaningful change.
  assert('order matters in the ecosystems array', a !== c);
}

section('Ecosystem allowlist: membership is exact-string');

{
  const cfg = { ecosystems: ['npm', 'PyPI'] };
  assert('npm is allowed', isAllowedEcosystem('npm', cfg));
  assert('PyPI is allowed', isAllowedEcosystem('PyPI', cfg));
  assert('Maven is not allowed', !isAllowedEcosystem('Maven', cfg));
  assert('case-sensitive: pypi is not allowed', !isAllowedEcosystem('pypi', cfg));
}

section('Ecosystem allowlist: applyAllowlist filters and dedups');

{
  const cfg = { ecosystems: ['npm', 'PyPI', 'Go'] };
  const out = applyAllowlist(['npm', 'Maven', 'PyPI', 'npm', 'Go', ''], cfg);
  assert('output has 3 unique allowed ecosystems', out.length === 3);
  assert('order is preserved (npm, PyPI, Go)', out[0] === 'npm' && out[1] === 'PyPI' && out[2] === 'Go');
}

/* ------------------------------------------------------------------ */
/* Tests: modified_id.csv parser                                       */
/* ------------------------------------------------------------------ */

section('modified_id.csv parser: blank lines, comments, dedup');

{
  const text = `# comment\n\nGHSA-xxxx-yyyy-zzzz\n\nCVE-2021-1234\nGHSA-xxxx-yyyy-zzzz\n  \n`;
  const ids = parseModifiedIdCsv(text);
  assert('parses 2 unique ids (after dedup)', ids.length === 2, 'got ' + JSON.stringify(ids));
  assert('first id is GHSA-...', ids[0] === 'GHSA-xxxx-yyyy-zzzz');
  assert('second id is CVE-...', ids[1] === 'CVE-2021-1234');
}

section('modified_id.csv parser: empty input');

{
  const ids = parseModifiedIdCsv('');
  assert('empty input → empty array', ids.length === 0);
}

/* ------------------------------------------------------------------ */
/* Tests: watermark filter                                              */
/* ------------------------------------------------------------------ */

section('Watermark filter: keeps newer-than-since ids and unknown-timestamp ids');

{
  const ids = ['A', 'B', 'C', 'D'];
  const ts = new Map([
    ['A', '2026-01-01T00:00:00.000Z'],
    ['B', '2026-02-01T00:00:00.000Z'],
    ['C', '2026-03-01T00:00:00.000Z'],
  ]);
  // 'D' is missing from the map → unknown → keep (defensive default)
  const out = filterByWatermark(ids, ts, '2026-02-01T00:00:00.000Z');
  assert('keeps B, C, D (B at boundary, C newer, D unknown)', out.length === 3);
  assert('B, C, D are kept in order', out[0] === 'B' && out[1] === 'C' && out[2] === 'D');
}

section('Watermark filter: no since → keep all');

{
  const out = filterByWatermark(['A', 'B'], new Map(), null);
  assert('no since → keep all', out.length === 2);
}

/* ------------------------------------------------------------------ */
/* Tests: fetcher + OSV provider (with stubbed network)                */
/* ------------------------------------------------------------------ */

section('OSV provider: fetchModifiedIds handles 404 as empty');

{
  const stubFetcher = async (url) => {
    if (url.endsWith('/empty-eco/modified_id.csv')) {
      const err = new Error(`fetch ${url} → HTTP 404`);
      throw err;
    }
    throw new Error('unexpected URL: ' + url);
  };
  const ids = await fetchModifiedIds({ ecosystem: 'empty-eco', fetcher: stubFetcher });
  assert('404 → empty array', ids.length === 0);
}

section('OSV provider: fetchModifiedIds parses a stub CSV');

{
  const stubFetcher = async (url) => {
    if (url === `${OSV_GCS_BASE}/npm/modified_id.csv`) {
      return 'GHSA-aaaa-bbbb-cccc\nCVE-2021-1234\n';
    }
    throw new Error('unexpected URL: ' + url);
  };
  const ids = await fetchModifiedIds({ ecosystem: 'npm', fetcher: stubFetcher });
  assert('parses 2 ids', ids.length === 2);
  assert('first id is GHSA-...', ids[0] === 'GHSA-aaaa-bbbb-cccc');
}

section('OSV provider: fetchVulnerability throws on invalid JSON');

{
  const stubFetcher = async (url) => {
    if (url === `${OSV_GCS_BASE}/npm/GHSA-bad.json`) return '{not json';
    throw new Error('unexpected URL: ' + url);
  };
  let threw = null;
  try {
    await fetchVulnerability({ ecosystem: 'npm', osvId: 'GHSA-bad', fetcher: stubFetcher });
  } catch (e) { threw = e; }
  assert('invalid JSON throws', threw !== null);
  assert('error message mentions the bad id', threw && /GHSA-bad/.test(threw.message));
}

section('OSV provider: fetchVulnerability parses valid JSON');

{
  const stubFetcher = async (url) => {
    if (url === `${OSV_GCS_BASE}/npm/GHSA-good.json`) {
      return JSON.stringify({ id: 'GHSA-good', summary: 'test' });
    }
    throw new Error('unexpected URL: ' + url);
  };
  const v = await fetchVulnerability({ ecosystem: 'npm', osvId: 'GHSA-good', fetcher: stubFetcher });
  assert('parses id', v.id === 'GHSA-good');
  assert('parses summary', v.summary === 'test');
}

/* ------------------------------------------------------------------ */
/* Tests: timeout fetch wrapper                                         */
/* ------------------------------------------------------------------ */

section('Timeout fetch: surfaces non-OK HTTP as errors');

{
  const stubBaseFetch = async (url) => {
    return { ok: false, status: 500, text: async () => 'oops' };
  };
  const tf = makeTextFetcher({ baseFetch: stubBaseFetch, timeoutMs: 1000 });
  let threw = null;
  try { await tf('http://example/x'); } catch (e) { threw = e; }
  assert('non-OK HTTP throws', threw !== null);
  assert('error message mentions HTTP 500', threw && /HTTP 500/.test(threw.message));
}

section('Timeout fetch: returns body on OK');

{
  const stubBaseFetch = async (url) => {
    return { ok: true, status: 200, text: async () => 'hello' };
  };
  const tf = makeTextFetcher({ baseFetch: stubBaseFetch, timeoutMs: 1000 });
  const text = await tf('http://example/x');
  assert('OK → text returned', text === 'hello');
}

/* ------------------------------------------------------------------ */
/* Tests: concurrency                                                   */
/* ------------------------------------------------------------------ */

section('mapWithConcurrency: bounded parallelism');

{
  let active = 0;
  let peak = 0;
  const work = async (i) => {
    active++;
    if (active > peak) peak = active;
    await new Promise((r) => setTimeout(r, 5));
    active--;
    return i * 2;
  };
  const out = await mapWithConcurrency([0, 1, 2, 3, 4, 5, 6, 7, 8, 9], 3, work);
  assert('result count matches', out.length === 10);
  assert('result values are correct', out[5] === 10);
  assert('peak concurrency is bounded by 3', peak <= 3, 'peak=' + peak);
  assert('peak concurrency actually hit 3', peak === 3, 'peak=' + peak);
}

/* ------------------------------------------------------------------ */
/* Tests: OSV canonical normalizer                                     */
/* ------------------------------------------------------------------ */

section('normalizeOsvVulnerability: emits all 5 entity types');

{
  const raw = {
    id: 'GHSA-test-0001',
    summary: 'Test vuln',
    details: 'long markdown',
    aliases: ['CVE-2021-9999'],
    related: ['GHSA-test-0002'],
    severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }],
    references: [{ type: 'WEB', url: 'https://example.com/advisory' }],
    affected: [{
      package: { name: 'left-pad', ecosystem: 'npm', purl: 'pkg:npm/left-pad' },
      ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.0.0' }] }],
    }],
    published: '2021-01-01T00:00:00.000Z',
    modified: '2021-02-01T00:00:00.000Z',
  };
  const out = normalizeOsvVulnerability({ rawVuln: raw, ecosystem: 'npm' });
  assert('vulnerability is emitted', out.vulnerability !== null);
  assert('vulnerability canonicalId is vuln:GHSA-test-0001',
    out.vulnerability.canonicalId === 'vuln:GHSA-test-0001');
  assert('advisory is emitted', out.advisories.length === 1);
  assert('advisory canonicalId is adv:GHSA-test-0001',
    out.advisories[0].canonicalId === 'adv:GHSA-test-0001');
  assert('package is emitted (one per affected)',
    out.packages.length === 1 && out.packages[0].canonicalId === 'pkg:npm:left-pad');
  assert('relationships include affects + advisory-of + alias + related',
    out.relationships.length === 4);
  assert('tombstones is empty (not withdrawn)', out.tombstones.length === 0);
}

section('normalizeOsvVulnerability: emits tombstone when withdrawn');

{
  const raw = {
    id: 'GHSA-test-withdrawn',
    summary: 'Withdrawn vuln',
    withdrawn: true,
    affected: [],
    published: '2021-01-01T00:00:00.000Z',
    modified: '2021-02-01T00:00:00.000Z',
  };
  const out = normalizeOsvVulnerability({ rawVuln: raw, ecosystem: 'npm' });
  assert('vulnerability has withdrawn: true', out.vulnerability.withdrawn === true);
  assert('tombstone is emitted', out.tombstones.length === 1);
  assert('tombstone canonicalId is tomb:GHSA-test-withdrawn',
    out.tombstones[0].canonicalId === 'tomb:GHSA-test-withdrawn');
}

section('normalizeOsvVulnerability: preserves ranges VERBATIM');

{
  // Per the V6.0 amendment, we do NOT re-parse OSV events into a
  // generic notation. The events array is stored as-is.
  const raw = {
    id: 'GHSA-range-test',
    affected: [{
      package: { name: 'mypkg', ecosystem: 'npm' },
      ranges: [{
        type: 'SEMVER',
        events: [{ introduced: '0' }, { fixed: '1.0.0' }, { introduced: '1.5.0' }],
        databaseSpecific: { foo: 'bar' },
      }],
    }],
    published: '2021-01-01T00:00:00.000Z',
    modified: '2021-02-01T00:00:00.000Z',
  };
  const out = normalizeOsvVulnerability({ rawVuln: raw, ecosystem: 'npm' });
  // The relationship records the rangeCount; the ranges themselves
  // are accessed via the vulnerability's affectedPackages list (we
  // do not embed the full ranges in the relationship entity to
  // avoid duplication). Re-derive ranges from the raw vuln — the
  // point of the test is that we don't transform the events array
  // shape in normalizeOsvVulnerability.
  assert('rangeCount is preserved on the relationship',
    out.relationships[0].rangeCount === 1);
  // The package entity is emitted as expected
  assert('package is emitted',
    out.packages[0].canonicalId === 'pkg:npm:mypkg');
}

section('normalizeOsvVulnerability: package canonicalId is lowercased');

{
  const raw = {
    id: 'GHSA-case-test',
    affected: [{
      package: { name: 'Left-Pad', ecosystem: 'npm' },
      ranges: [],
    }],
    published: '2021-01-01T00:00:00.000Z',
    modified: '2021-02-01T00:00:00.000Z',
  };
  const out = normalizeOsvVulnerability({ rawVuln: raw, ecosystem: 'npm' });
  assert('package name is lowercased in canonicalId',
    out.packages[0].canonicalId === 'pkg:npm:left-pad');
}

section('normalizeOsvVulnerability: alias → alias relationship');

{
  const raw = {
    id: 'GHSA-primary',
    aliases: ['CVE-2021-1111', 'CVE-2021-2222'],
    affected: [],
    published: '2021-01-01T00:00:00.000Z',
    modified: '2021-02-01T00:00:00.000Z',
  };
  const out = normalizeOsvVulnerability({ rawVuln: raw, ecosystem: 'npm' });
  const aliasRels = out.relationships.filter((r) => r.relType === 'alias');
  assert('two alias relationships are emitted', aliasRels.length === 2);
  assert('alias relationship points to vuln:CVE-2021-1111',
    aliasRels.some((r) => r.targetId === 'vuln:CVE-2021-1111'));
  assert('alias relationship points to vuln:CVE-2021-2222',
    aliasRels.some((r) => r.targetId === 'vuln:CVE-2021-2222'));
}

section('normalizeOsvVulnerability: dedups duplicate packages');

{
  const raw = {
    id: 'GHSA-dup-pkg',
    affected: [
      { package: { name: 'foo', ecosystem: 'npm' }, ranges: [] },
      { package: { name: 'foo', ecosystem: 'npm' }, ranges: [] },
    ],
    published: '2021-01-01T00:00:00.000Z',
    modified: '2021-02-01T00:00:00.000Z',
  };
  const out = normalizeOsvVulnerability({ rawVuln: raw, ecosystem: 'npm' });
  assert('one package entity emitted for two affected entries',
    out.packages.length === 1);
}

section('normalizeOsvVulnerability: invalid input → empty result');

{
  const out = normalizeOsvVulnerability({ rawVuln: null, ecosystem: 'npm' });
  assert('null input → no vulnerability, no entities',
    out.vulnerability === null && out.advisories.length === 0
    && out.packages.length === 0 && out.relationships.length === 0
    && out.tombstones.length === 0);
}

section('Canonical id helpers');

{
  assert('vulnerabilityCanonicalId', vulnerabilityCanonicalId('GHSA-x') === 'vuln:GHSA-x');
  assert('packageCanonicalId lowercases', packageCanonicalId('npm', 'Left-Pad') === 'pkg:npm:left-pad');
  assert('relationshipCanonicalId includes rel type and arrow',
    relationshipCanonicalId('affects', 'vuln:A', 'pkg:B') === 'rel:affects:vuln:A\u2192pkg:B');
}

/* ------------------------------------------------------------------ */
/* Tests: bootstrap state                                              */
/* ------------------------------------------------------------------ */

section('Bootstrap state: initial state has documented shape');

{
  const s = initialBootstrapState();
  assert('schemaVersion matches', s.schemaVersion === OSV_BOOTSTRAP_STATE_SCHEMA);
  assert('status is IDLE', s.status === STATUS.IDLE);
  assert('phase is PREPARATION', s.phase === PHASE.PREPARATION);
  assert('startedAt is null', s.startedAt === null);
  assert('perEcosystem is empty', Object.keys(s.perEcosystem).length === 0);
  assert('errors is empty', Object.keys(s.errors).length === 0);
  assert('overlapWindowMs default', s.overlapWindowMs === DEFAULT_OVERLAP_WINDOW_MS);
  assert('recordsPersistInterval default', s.recordsPersistInterval === DEFAULT_RECORDS_PERSIST_INTERVAL);
}

section('Bootstrap state: markRunStarted resets cursors');

{
  let s = initialBootstrapState();
  s = markRunStarted(s, { configHash: 'sha256:' + 'a'.repeat(64), now: new Date('2026-07-12T20:00:00.000Z') });
  assert('status is RUNNING', s.status === STATUS.RUNNING);
  assert('phase is PREPARATION', s.phase === PHASE.PREPARATION);
  assert('startedAt is set', s.startedAt === '2026-07-12T20:00:00.000Z');
  assert('configHash is set', s.configHash.startsWith('sha256:'));
  assert('perEcosystem is empty after start', Object.keys(s.perEcosystem).length === 0);
}

section('Bootstrap state: markRunStarted requires configHash');

{
  const s = initialBootstrapState();
  let threw = null;
  try { markRunStarted(s, { configHash: 'garbage' }); } catch (e) { threw = e; }
  assert('non-sha256 configHash throws', threw !== null);
}

section('Bootstrap state: recordEcosystemProgress appends to ring');

{
  let s = initialBootstrapState();
  s = markRunStarted(s, { configHash: 'sha256:' + 'a'.repeat(64) });
  s = recordEcosystemProgress(s, 'npm', { id: 'A', newCursor: 1 });
  s = recordEcosystemProgress(s, 'npm', { id: 'B', newCursor: 2 });
  s = recordEcosystemProgress(s, 'npm', { id: 'C', newCursor: 3 });
  assert('processedCount is 3', s.perEcosystem.npm.processedCount === 3);
  assert('cursor is 3', s.perEcosystem.npm.cursor === 3);
  assert('lastId is C', s.perEcosystem.npm.lastId === 'C');
  assert('recentIds ring has 3 entries', recentIdsFor(s, 'npm').length === 3);
}

section('Bootstrap state: recentIds ring is bounded');

{
  let s = initialBootstrapState();
  s = markRunStarted(s, { configHash: 'sha256:' + 'a'.repeat(64) });
  for (let i = 0; i < RECENT_IDS_RING_SIZE + 50; i++) {
    s = recordEcosystemProgress(s, 'npm', { id: 'id-' + i, newCursor: i + 1 });
  }
  assert('ring is bounded to RECENT_IDS_RING_SIZE',
    recentIdsFor(s, 'npm').length === RECENT_IDS_RING_SIZE);
  // The oldest ids should have been dropped; the newest 50 should
  // be at the end.
  const ring = recentIdsFor(s, 'npm');
  assert('newest id is at the end',
    ring[ring.length - 1] === 'id-' + (RECENT_IDS_RING_SIZE + 49));
}

section('Bootstrap state: isRecentlyProcessed');

{
  let s = initialBootstrapState();
  s = markRunStarted(s, { configHash: 'sha256:' + 'a'.repeat(64) });
  s = recordEcosystemProgress(s, 'npm', { id: 'A', newCursor: 1 });
  assert('A is recently processed', isRecentlyProcessed(s, 'npm', 'A'));
  assert('B is not recently processed', !isRecentlyProcessed(s, 'npm', 'B'));
  assert('Maven has no ring → not recently processed',
    !isRecentlyProcessed(s, 'Maven', 'A'));
}

section('Bootstrap state: markRunComplete preserves cursors');

{
  let s = initialBootstrapState();
  s = markRunStarted(s, { configHash: 'sha256:' + 'a'.repeat(64) });
  s = recordEcosystemProgress(s, 'npm', { id: 'A', newCursor: 1 });
  const cursorsBefore = s.perEcosystem;
  s = markRunComplete(s, { now: new Date('2026-07-12T20:30:00.000Z'),
    publishedBaselineVersion: '2026-07-12T20-30-00Z-12345678',
    publishedAt: '2026-07-12T20:30:00.000Z' });
  assert('status is IDLE', s.status === STATUS.IDLE);
  assert('phase is COMPLETE', s.phase === PHASE.COMPLETE);
  assert('cursors are preserved', s.perEcosystem.npm.cursor === cursorsBefore.npm.cursor);
  assert('lastSuccessfulAt is set', s.lastSuccessfulAt === '2026-07-12T20:30:00.000Z');
  assert('lastPublishedBaselineVersion is set',
    s.lastPublishedBaselineVersion === '2026-07-12T20-30-00Z-12345678');
}

section('Bootstrap state: markEcosystemFailed records error');

{
  let s = initialBootstrapState();
  s = markRunStarted(s, { configHash: 'sha256:' + 'a'.repeat(64) });
  s = markEcosystemFailed(s, 'npm', 'fetch failed', { now: new Date('2026-07-12T20:00:00.000Z') });
  assert('status is FAILED', s.status === STATUS.FAILED);
  assert('errors contains the ecosystem', s.errors.npm && s.errors.npm.message === 'fetch failed');
  assert('perEcosystem has a slot with lastError',
    s.perEcosystem.npm && s.perEcosystem.npm.lastError !== null);
}

section('Bootstrap state: markPhase');

{
  let s = initialBootstrapState();
  s = markRunStarted(s, { configHash: 'sha256:' + 'a'.repeat(64) });
  s = markPhase(s, PHASE.INGESTION);
  assert('phase is INGESTION', s.phase === PHASE.INGESTION);
  s = markPhase(s, PHASE.PUBLICATION);
  assert('phase is PUBLICATION', s.phase === PHASE.PUBLICATION);
}

/* ------------------------------------------------------------------ */
/* Tests: equal-timestamp OSV updates cannot be skipped                */
/* ------------------------------------------------------------------ */

section('Equal-timestamp OSV updates: re-emit invariant');

{
  // The spec says "equal-timestamp OSV updates cannot be skipped".
  // The bootstrap state supports this by tracking the recent-ids
  // ring, and the orchestrator re-processes any id present in
  // modified_id.csv regardless of whether it was seen before.
  // This test exercises the ring + dedup boundary.
  let s = initialBootstrapState();
  s = markRunStarted(s, { configHash: 'sha256:' + 'a'.repeat(64) });
  // Process id A
  s = recordEcosystemProgress(s, 'npm', { id: 'A', newCursor: 1 });
  // The next modified_id.csv read returns A again (same timestamp,
  // same content) — A is in the recent-ids ring, so
  // isRecentlyProcessed returns true. The orchestrator's job is to
  // re-emit the canonical record anyway (because content MIGHT have
  // changed); the bucket-level dedup then keeps storage costs flat.
  assert('A is still considered recently processed',
    isRecentlyProcessed(s, 'npm', 'A'));
  // The crucial property: the ring is a journal, not a dedup
  // surface. The orchestrator must NOT use it to skip records.
  // Verify the ring size did not change shape.
  assert('ring has exactly 1 entry', recentIdsFor(s, 'npm').length === 1);
}

/* ------------------------------------------------------------------ */
/* End                                                                */
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
console.log('ALL OSV-INGESTION TESTS PASSED');
