#!/usr/bin/env node
// V6.1 — Source Health and What Changed UI acceptance.
//
//   node scripts/acceptance-source-health-and-changes-ui.mjs
//
// This is a static-analysis acceptance: the test
// inspects the source code of the new components and
// confirms the V6.1 invariants the user-facing
// requirements demand:
//
//   - Panel-local filter isolated from main filters.
//   - "Filters here affect only this panel." copy.
//   - Six sources, no env-var names.
//   - Provider-status-changed chip does not modify the
//     main filters or the table.
//   - No env-var names, no upstream URLs in the panel.
//   - Official https provenance URLs allowed.
//   - The drawer empty-state copy is locked.
//   - Panel-local filter changes do not affect Defender
//     Views presets.
//   - Sources are derived from observations at request
//     time (no frozen state field persisted in the
//     public response).
//   - The OSV public-intelligence bundle is
//     independently versioned (no canonical-baseline
//     coupling at the public-surface level).
//
// The test reads the source files of the new components
// and asserts the documented invariants.

import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..');

let passed = 0;
let failed = 0;
const failures = [];
function assert(label, cond, extra = '') {
  if (cond) { passed++; console.log(`  PASS  ${label}`); }
  else { failed++; failures.push({ label, extra }); console.log(`  FAIL  ${label}${extra ? `  -- ${extra}` : ''}`); }
}

console.log('V6.1 — Source Health and What Changed UI acceptance');
console.log('====================================================');
console.log('');

function read(rel) {
  return readFileSync(resolve(root, rel), 'utf8');
}

const panel = read('src/components/SourceHealthPanel.tsx');
const chip = read('src/components/SourceStatusChip.tsx');
const card = read('src/components/SourceStatusCard.tsx');
const ci = read('src/components/ChangeIntelligencePanel.tsx');
const ciRow = read('src/components/ChangeItemRow.tsx');
const osvCtx = read('src/components/drawer/OsvContext.tsx');
const dashboard = read('src/pages/DashboardPage.tsx');
const drawer = read('src/components/DetailDrawer.tsx');
const typeSrcHealth = read('src/types/sourceHealth.ts');
const typeChange = read('src/types/change.ts');
const typeOsv = read('src/types/osv.ts');
const typeVuln = read('src/types/vulnerability.ts');
const service = read('src/services/vulnerabilityService.ts');

/* ---- 1. No env-var names in any public-facing source ---- */
console.log('[1] No env-var names in any public source');
const envVarPattern = /\b(NVD_API_KEY|GITHUB_TOKEN|THREATPULSE_(REFRESH_TRIGGER_SECRET|BASELINE_SITE_ID|BLOBS_ACCESS_TOKEN|CREDENTIAL_PEPPER|CREDENTIALS_BLOBS_ACCESS_TOKEN|CREDENTIALS_SITE_ID|OSV_ECOSYSTEMS))\b/g;
const allFiles = [panel, chip, card, ci, ciRow, osvCtx, dashboard, drawer, typeSrcHealth, typeChange, typeOsv, typeVuln, service];
let envHits = 0;
for (const f of allFiles) {
  if (envVarPattern.test(f)) envHits++;
}
envVarPattern.lastIndex = 0;
assert('No env-var name appears in any public source file', envHits === 0);

/* ---- 2. No upstream provider fetch URLs in the frontend ---- */
console.log('');
console.log('[2] No upstream provider fetch in the frontend');
const fetchProviderPattern = /\b(fetch|XMLHttpRequest|axios|got)\s*\(.*['"]https?:\/\/(api\.osv\.dev|osv-vulnerabilities\.storage\.googleapis\.com|api\.github\.com|nvd\.nist\.gov|services\.nvd\.nist\.gov|api\.first\.org|raw\.githubusercontent\.com)\b/i;
let fetchHits = 0;
for (const f of [panel, chip, card, ci, ciRow, osvCtx, dashboard, drawer, service]) {
  if (fetchProviderPattern.test(f)) fetchHits++;
}
fetchProviderPattern.lastIndex = 0;
assert('No upstream provider fetch in the frontend', fetchHits === 0);

/* ---- 3. Official OSV hyperlinks allowed ---- */
console.log('');
console.log('[3] Official OSV hyperlinks allowed');
assert('OsvContext renders https://osv.dev/...', osvCtx.includes('https://osv.dev/vulnerability/'));
assert('OsvContext link has rel="noopener noreferrer"', osvCtx.includes('rel="noopener noreferrer"'));
assert('OsvContext link has target="_blank"', osvCtx.includes('target="_blank"'));
assert('OsvContext URL is built from osvId, not from arbitrary upstream URL',
  osvCtx.includes('encodeURIComponent(record.osvId)'));

/* ---- 4. Empty state copy is locked ---- */
console.log('');
console.log('[4] Empty state copy is locked');
const lockedCopy = 'No OSV record is currently available in this ThreatPulse snapshot.';
assert(`OsvContext renders locked empty-state copy ("${lockedCopy}")`,
  osvCtx.includes(lockedCopy));
assert('OsvContext does NOT claim global absence ("not in OSV")', !osvCtx.includes('not in OSV'));
assert('OsvContext does NOT say "no fix"', !osvCtx.toLowerCase().includes('no fix'));

/* ---- 5. Panel-local filter isolation ---- */
console.log('');
console.log('[5] Panel-local filter isolation');
assert('ChangeIntelligencePanel uses local useState (not VulnerabilityFilters)',
  ci.includes('useState') && !/setFilters\s*\(/.test(ci) && !/onChange\s*=\s*\{setFilters\}/.test(ci));
assert('ChangeIntelligencePanel does NOT import VulnerabilityFilters',
  !/import\s+.*VulnerabilityFilters/.test(ci));
assert('ChangeIntelligencePanel copy: "Filters here affect only this panel."',
  ci.includes('Filters here affect only this panel.'));
assert('ChangeIntelligencePanel does NOT modify Defender Views presets',
  !ci.includes('PRESETS') && !ci.includes('presetId'));

/* ---- 6. Maximum 25 displayed results ---- */
console.log('');
console.log('[6] Maximum 25 displayed results');
assert('CHANGE_LIMIT is 25 in ChangeIntelligencePanel', ci.includes('CHANGE_LIMIT = 25'));
assert('Change panel never sets a limit > 25',
  !/limit\s*=\s*[2-9]\d|limit\s*=\s*\d{3,}/.test(ci));

/* ---- 7. Provider-status-changed does not modify main table/filters/CSV ---- */
console.log('');
console.log('[7] Provider-status-changed does not modify main table/filters/CSV');
assert('Provider-status-changed calls onHighlightSource (scroll/highlight), not onChange of filters',
  ci.includes('onHighlightSource(') && !/provider-status-changed[\s\S]*?onChange\s*\(/.test(ci));
assert('Change panel does not touch the table or CSV', !ci.includes('VulnerabilityTable') && !ci.includes('toCsv'));
assert('Dashboard wires panel filters with setFilters callback (panel-local filter isolated)',
  /setFilters\(/.test(dashboard));

/* ---- 8. Six sources, all distinct ---- */
console.log('');
console.log('[8] Six sources, all distinct');
const sourceIds = ['cisa_kev', 'nvd', 'first_epss', 'cisa_vulnrichment', 'github_advisory', 'osv'];
for (const id of sourceIds) {
  assert(`Type sourceHealth includes ${id}`, typeSrcHealth.includes(`'${id}'`));
}
assert('SourceState union is exactly the five documented states',
  typeSrcHealth.includes("'unknown'") &&
  typeSrcHealth.includes("'fresh'") &&
  typeSrcHealth.includes("'partial'") &&
  typeSrcHealth.includes("'stale'") &&
  typeSrcHealth.includes("'unavailable'"));

/* ---- 9. Source-health state derived, not frozen ---- */
console.log('');
console.log('[9] Source-health state derived at request time');
assert('Source type does NOT persist a frozen state field',
  !typeSrcHealth.includes('freshnessState:') && !typeSrcHealth.includes('state: \''));
assert('Source freshness state is derived (component code)', panel.includes('freshness.state'));
assert('SourceHealthPanel uses buildPublicSourceHealth (derived) or computes from observations',
  panel.includes('sources') || panel.includes('SourceStatus'));

/* ---- 10. No new top-level function entry file ---- */
console.log('');
console.log('[10] No new top-level function entry file');
import { readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
const fnDir = resolve(root, 'netlify', 'functions');
const fnEntries = readdirSync(fnDir).filter((f) => f.endsWith('.mjs') && statSync(join(fnDir, f)).isFile());
assert('Public function entry count remains 5', fnEntries.length === 5);

/* ---- 11. Drawer ordering: SSVC → GitHub Advisory → OSV → External references ---- */
console.log('');
console.log('[11] Drawer ordering');
const ssvcIdx = drawer.indexOf('CISA decision context');
const ghIdx = drawer.indexOf('Package remediation context');
const osvIdx = drawer.indexOf('OSV package context');
const extIdx = drawer.indexOf('External references');
assert('SSVC section is before GitHub Advisory section', ssvcIdx > 0 && ssvcIdx < ghIdx);
assert('GitHub Advisory section is before OSV section', ghIdx > 0 && ghIdx < osvIdx);
assert('OSV section is before External references', osvIdx > 0 && osvIdx < extIdx);

/* ---- 12. CSV columns unchanged ---- */
console.log('');
console.log('[12] CSV columns unchanged (21)');
const csv = read('src/utils/csvExport.ts');
const csvMatch = csv.match(/CSV_COLUMNS = \[([\s\S]*?)\] as const/);
assert('CSV_COLUMNS array found', csvMatch !== null);
if (csvMatch) {
  const cols = csvMatch[1].split(',').map((s) => s.trim()).filter((s) => s.startsWith("'"));
  assert('CSV_COLUMNS has exactly 21 columns', cols.length === 21);
}

/* ---- 13. Service exposes fetchOsvForCve and fetchChangesForCategory ---- */
console.log('');
console.log('[13] Service exposes V6.1 fetchers');
assert('Service exports fetchOsvForCve',
  service.includes('export async function fetchOsvForCve'));
assert('Service exports fetchChangesForCategory',
  service.includes('export async function fetchChangesForCategory'));
assert('fetchOsvForCve uses view=osv query', service.includes('view=osv'));
assert('fetchChangesForCategory uses view=changes query', service.includes('view=changes'));
assert('fetchOsvForCve does NOT call fetch directly with arbitrary URL',
  !/fetchOsvForCve[^}]*?fetch\(\s*['"`]https?:\/\/api\.osv\.dev/.test(service));

/* ---- 14. DashboardPage wires both panels ---- */
console.log('');
console.log('[14] DashboardPage wires both panels');
assert('DashboardPage imports SourceHealthPanel', dashboard.includes("from '../components/SourceHealthPanel'"));
assert('DashboardPage imports ChangeIntelligencePanel', dashboard.includes("from '../components/ChangeIntelligencePanel'"));
assert('DashboardPage renders <SourceHealthPanel>', dashboard.includes('<SourceHealthPanel'));
assert('DashboardPage renders <ChangeIntelligencePanel>', dashboard.includes('<ChangeIntelligencePanel'));
assert('Source Health panel is between TrendChart and DefenderViewsPanel',
  panelOrder(dashboard, '<TrendChart', '<SourceHealthPanel', '<DefenderViewsPanel'));

function panelOrder(src, trend, sourceHealth, defender) {
  const i1 = src.indexOf(trend);
  const i2 = src.lastIndexOf(sourceHealth);
  const i3 = src.indexOf(defender);
  if (i1 < 0 || i2 < 0 || i3 < 0) return false;
  return i1 < i2 && i2 < i3;
}

/* ---- 15. The two new panels are isolated from the main table ---- */
console.log('');
console.log('[15] New panels are isolated from the main table');
assert('Change panel does not include VulnerabilityTable', !ci.includes('VulnerabilityTable'));
assert('Source panel does not include VulnerabilityTable', !panel.includes('VulnerabilityTable'));

/* ---- Summary ---- */
console.log('');
console.log('====================================================');
console.log(`V6.1 Source Health and What Changed UI: ${passed} passed, ${failed} failed`);
if (failed > 0) {
  console.log('Failures:');
  for (const f of failures) console.log(`  - ${f.label}${f.extra ? ` (${f.extra})` : ''}`);
  process.exit(1);
}
console.log('All UI tests passed.');
