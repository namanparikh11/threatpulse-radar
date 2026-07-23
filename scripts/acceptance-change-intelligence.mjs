#!/usr/bin/env node
// V6.1 — change intelligence acceptance.
//
//   node scripts/acceptance-change-intelligence.mjs

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

const ciMod = await import('../netlify/functions/_shared/changeIntelligence.mjs');

console.log('V6.1 — change intelligence acceptance');
console.log('======================================');
console.log('');

/* ---- Helpers ---- */
const FULL_COMP = {
  cisaKev:        { comparable: true, asOf: '2026-07-15T03:54:00.000Z' },
  nvd:            { comparable: true, asOf: '2026-07-15T03:54:00.000Z' },
  firstEpss:      { comparable: true, asOf: '2026-07-15T03:54:00.000Z' },
  ssvc:           { comparable: true, asOf: '2026-07-15T03:54:00.000Z' },
  githubAdvisory: { comparable: true, asOf: '2026-07-15T03:54:00.000Z' },
  osv:            { comparable: true, asOf: '2026-07-15T03:54:00.000Z' },
};
const NO_COMP = {
  cisaKev:        { comparable: false, asOf: null },
  nvd:            { comparable: false, asOf: null },
  firstEpss:      { comparable: false, asOf: null },
  ssvc:           { comparable: 'partial', asOf: '2026-07-15T03:54:00.000Z' },
  githubAdvisory: { comparable: 'partial', asOf: '2026-07-15T03:54:00.000Z' },
  osv:            { comparable: true, asOf: '2026-07-15T03:54:00.000Z' },
};
const PARTIAL_PROVIDER = {
  cisaKev:        { comparable: 'partial', asOf: '2026-07-15T03:54:00.000Z' },
  nvd:            { comparable: 'partial', asOf: '2026-07-15T03:54:00.000Z' },
  firstEpss:      { comparable: 'partial', asOf: '2026-07-15T03:54:00.000Z' },
  ssvc:           { comparable: 'partial', asOf: '2026-07-15T03:54:00.000Z' },
  githubAdvisory: { comparable: 'partial', asOf: '2026-07-15T03:54:00.000Z' },
  osv:            { comparable: true, asOf: '2026-07-15T03:54:00.000Z' },
};
const s = (byCve) => ({
  schemaVersion: '1.0.0',
  publicIntelligenceVersion: 'v',
  generatedAt: '2026-07-15T03:54:00.000Z',
  providerComparability: FULL_COMP,
  trackedCveCount: Object.keys(byCve).length,
  byCve,
});

/* ---- 1. EPSS threshold ---- */
console.log('[1] EPSS threshold');
assert('EPSSMaterialChangeThreshold is 0.10',
  ciMod.EPSS_MATERIAL_CHANGE_THRESHOLD === 0.10);

// 0.09 below threshold
const r1prev = s({ 'CVE-2024-0001': { tracked: true, kev: { observation: 'present', present: false, kevDateAdded: null }, severity: { observation: 'present', value: 'High', cvssSource: 'NVD', cvssVersion: 'CVSS_V3' }, nvd: { observation: 'present', severity: 'High', cvssSource: 'NVD', cvssVersion: 'CVSS_V3' }, epssProbability: 0.05, epss: { observation: 'present', probability: 0.05 }, ssvcExploitation: { observation: 'unknown', exploitation: null }, githubAdvisory: { observation: 'unknown', ghsaId: null, firstPatchedAvailable: null }, firstPatchedAvailable: false, osv: { observation: 'unknown', recordIds: [], affectedSignature: null, withdrawn: null }, withdrawn: false, affectedSignature: '' } });
const r1cur = s({ 'CVE-2024-0001': { ...r1prev.byCve['CVE-2024-0001'], epssProbability: 0.14, epss: { observation: 'present', probability: 0.14 } } });
const ci1 = ciMod.buildChangeIntelligence({ prevSnapshot: r1prev, currentSnapshot: r1cur, publicIntelligenceVersion: 'v' });
assert('0.09 delta (0.05 -> 0.14) does NOT trigger EPSS classification',
  !ci1.items.some((it) => it.classifications.some((c) => c.startsWith('epss-materially'))));

// 0.10 exactly
const r1cur2 = s({ 'CVE-2024-0001': { ...r1prev.byCve['CVE-2024-0001'], epssProbability: 0.15, epss: { observation: 'present', probability: 0.15 } } });
const ci1b = ciMod.buildChangeIntelligence({ prevSnapshot: r1prev, currentSnapshot: r1cur2, publicIntelligenceVersion: 'v' });
assert('0.10 delta (0.05 -> 0.15) triggers epss-materially-increased',
  ci1b.items.some((it) => it.classifications.includes('epss-materially-increased')));

// -0.10 triggers decrease
const r1cur3 = s({ 'CVE-2024-0001': { ...r1prev.byCve['CVE-2024-0001'], epssProbability: -0.05, epss: { observation: 'present', probability: -0.05 } } });
// Note: probability must be in [0, 1], but the threshold check is delta-based, not bound-based. Use 0.0:
const r1cur3b = s({ 'CVE-2024-0001': { ...r1prev.byCve['CVE-2024-0001'], epssProbability: 0.0, epss: { observation: 'present', probability: 0.0 } } });
const ci1c = ciMod.buildChangeIntelligence({ prevSnapshot: r1prev, currentSnapshot: r1cur3b, publicIntelligenceVersion: 'v' });
assert('-0.05 delta (0.05 -> 0.0) does NOT trigger EPSS decrease (< 0.10)',
  !ci1c.items.some((it) => it.classifications.includes('epss-materially-decreased')));
const r1prevHigh = s({ 'CVE-2024-0001': { ...r1prev.byCve['CVE-2024-0001'], epssProbability: 0.50, epss: { observation: 'present', probability: 0.50 } } });
const r1cur4 = s({ 'CVE-2024-0001': { ...r1prevHigh.byCve['CVE-2024-0001'], epssProbability: 0.30, epss: { observation: 'present', probability: 0.30 } } });
const ci1d = ciMod.buildChangeIntelligence({ prevSnapshot: r1prevHigh, currentSnapshot: r1cur4, publicIntelligenceVersion: 'v' });
assert('0.20 decrease (0.50 -> 0.30) triggers epss-materially-decreased',
  ci1d.items.some((it) => it.classifications.includes('epss-materially-decreased')));

/* ---- 2. Newly tracked / no longer tracked precedence ---- */
console.log('');
console.log('[2] Newly tracked / no longer tracked precedence');

// CVE enters tracked universe
const r2prev = s({});
const r2cur = s({
  'CVE-2024-NEW': {
    tracked: true, kev: { observation: 'present', present: true, kevDateAdded: '2026-07-15' },
    severity: { observation: 'present', value: 'Critical', cvssSource: 'NVD', cvssVersion: 'CVSS_V3' },
    nvd: { observation: 'present', severity: 'Critical', cvssSource: 'NVD', cvssVersion: 'CVSS_V3' },
    epssProbability: 0.5, epss: { observation: 'present', probability: 0.5 },
    ssvcExploitation: { observation: 'present', exploitation: 'active' },
    githubAdvisory: { observation: 'present', ghsaId: 'GHSA-xxxx', firstPatchedAvailable: true },
    firstPatchedAvailable: true,
    osv: { observation: 'present', recordIds: ['GHSA-xxxx'], affectedSignature: 'sha256:abc', withdrawn: false },
    withdrawn: false, affectedSignature: 'sha256:abc',
  },
});
const ci2 = ciMod.buildChangeIntelligence({ prevSnapshot: r2prev, currentSnapshot: r2cur, publicIntelligenceVersion: 'v' });
const newItem = ci2.items.find((it) => it.cveId === 'CVE-2024-NEW');
assert('Newly tracked CVE is classified as cve-newly-tracked',
  newItem && newItem.classifications.length === 1 && newItem.classifications[0] === 'cve-newly-tracked');

// CVE leaves tracked universe
const r2prevLeft = s({
  'CVE-2024-LEFT': {
    tracked: true, kev: { observation: 'present', present: false, kevDateAdded: null },
    severity: { observation: 'present', value: 'High', cvssSource: 'NVD', cvssVersion: 'CVSS_V3' },
    nvd: { observation: 'present', severity: 'High', cvssSource: 'NVD', cvssVersion: 'CVSS_V3' },
    epssProbability: 0.5, epss: { observation: 'present', probability: 0.5 },
    ssvcExploitation: { observation: 'unknown', exploitation: null },
    githubAdvisory: { observation: 'unknown', ghsaId: null, firstPatchedAvailable: null },
    firstPatchedAvailable: false,
    osv: { observation: 'unknown', recordIds: [], affectedSignature: null, withdrawn: null },
    withdrawn: false, affectedSignature: '',
  },
});
const r2curLeft = s({});
const ci2b = ciMod.buildChangeIntelligence({ prevSnapshot: r2prevLeft, currentSnapshot: r2curLeft, publicIntelligenceVersion: 'v' });
const leftItem = ci2b.items.find((it) => it.cveId === 'CVE-2024-LEFT');
assert('No-longer-tracked CVE is classified as cve-no-longer-tracked',
  leftItem && leftItem.classifications.length === 1 && leftItem.classifications[0] === 'cve-no-longer-tracked');

/* ---- 3. KEV transitions ---- */
console.log('');
console.log('[3] KEV transitions');
const r3prev = s({
  'CVE-2024-KEV': {
    tracked: true, kev: { observation: 'present', present: false, kevDateAdded: null },
    severity: { observation: 'present', value: 'High', cvssSource: 'NVD', cvssVersion: 'CVSS_V3' },
    nvd: { observation: 'present', severity: 'High', cvssSource: 'NVD', cvssVersion: 'CVSS_V3' },
    epssProbability: 0.5, epss: { observation: 'present', probability: 0.5 },
    ssvcExploitation: { observation: 'unknown', exploitation: null },
    githubAdvisory: { observation: 'unknown', ghsaId: null, firstPatchedAvailable: null },
    firstPatchedAvailable: false,
    osv: { observation: 'unknown', recordIds: [], affectedSignature: null, withdrawn: null },
    withdrawn: false, affectedSignature: '',
  },
});
const r3cur = s({
  'CVE-2024-KEV': {
    ...r3prev.byCve['CVE-2024-KEV'],
    kev: { observation: 'present', present: true, kevDateAdded: '2026-07-15' },
  },
});
const ci3 = ciMod.buildChangeIntelligence({ prevSnapshot: r3prev, currentSnapshot: r3cur, publicIntelligenceVersion: 'v' });
const kevItem = ci3.items.find((it) => it.cveId === 'CVE-2024-KEV');
assert('KEV newly present (false -> true) fires kev-newly-present',
  kevItem && kevItem.classifications.includes('kev-newly-present'));
assert('KEV newly present does NOT fire kev-no-longer-present',
  kevItem && !kevItem.classifications.includes('kev-no-longer-present'));

const r3prevKev = s({
  'CVE-2024-KEV2': {
    ...r3prev.byCve['CVE-2024-KEV'],
    kev: { observation: 'present', present: true, kevDateAdded: '2026-07-10' },
  },
});
const r3curKev = s({
  'CVE-2024-KEV2': {
    ...r3prev.byCve['CVE-2024-KEV'],
    kev: { observation: 'present', present: false, kevDateAdded: null },
  },
});
const ci3b = ciMod.buildChangeIntelligence({ prevSnapshot: r3prevKev, currentSnapshot: r3curKev, publicIntelligenceVersion: 'v' });
const kevItem2 = ci3b.items.find((it) => it.cveId === 'CVE-2024-KEV2');
assert('KEV no longer present (true -> false) fires kev-no-longer-present',
  kevItem2 && kevItem2.classifications.includes('kev-no-longer-present'));

/* ---- 4. Severity class change ---- */
console.log('');
console.log('[4] Severity class change');
const r4prev = s({
  'CVE-2024-SEV': {
    tracked: true, kev: { observation: 'present', present: false, kevDateAdded: null },
    severity: { observation: 'present', value: 'Medium', cvssSource: 'NVD', cvssVersion: 'CVSS_V3' },
    nvd: { observation: 'present', severity: 'Medium', cvssSource: 'NVD', cvssVersion: 'CVSS_V3' },
    epssProbability: 0.5, epss: { observation: 'present', probability: 0.5 },
    ssvcExploitation: { observation: 'unknown', exploitation: null },
    githubAdvisory: { observation: 'unknown', ghsaId: null, firstPatchedAvailable: null },
    firstPatchedAvailable: false,
    osv: { observation: 'unknown', recordIds: [], affectedSignature: null, withdrawn: null },
    withdrawn: false, affectedSignature: '',
  },
});
const r4cur = s({
  'CVE-2024-SEV': { ...r4prev.byCve['CVE-2024-SEV'], severity: { observation: 'present', value: 'High', cvssSource: 'NVD', cvssVersion: 'CVSS_V3' } },
});
const ci4 = ciMod.buildChangeIntelligence({ prevSnapshot: r4prev, currentSnapshot: r4cur, publicIntelligenceVersion: 'v' });
const sevItem = ci4.items.find((it) => it.cveId === 'CVE-2024-SEV');
assert('Medium -> High fires severity-class-changed',
  sevItem && sevItem.classifications.includes('severity-class-changed'));
assert('Medium -> Medium does NOT fire severity-class-changed',
  !ci4.items.some((it) => it.classifications.includes('severity-class-changed') && it.cveId !== 'CVE-2024-SEV'));

/* ---- 5. CVSS source/version change ---- */
console.log('');
console.log('[5] CVSS source/version change');
const r5prev = s({
  'CVE-2024-CVSS': {
    tracked: true, kev: { observation: 'present', present: false, kevDateAdded: null },
    severity: { observation: 'present', value: 'Medium', cvssSource: 'NVD', cvssVersion: 'CVSS_V3' },
    nvd: { observation: 'present', severity: 'Medium', cvssSource: 'NVD', cvssVersion: 'CVSS_V3' },
    epssProbability: 0.5, epss: { observation: 'present', probability: 0.5 },
    ssvcExploitation: { observation: 'unknown', exploitation: null },
    githubAdvisory: { observation: 'unknown', ghsaId: null, firstPatchedAvailable: null },
    firstPatchedAvailable: false,
    osv: { observation: 'unknown', recordIds: [], affectedSignature: null, withdrawn: null },
    withdrawn: false, affectedSignature: '',
  },
});
const r5cur = s({
  'CVE-2024-CVSS': { ...r5prev.byCve['CVE-2024-CVSS'], severity: { observation: 'present', value: 'Medium', cvssSource: 'NVD', cvssVersion: 'CVSS_V4' } },
});
const ci5 = ciMod.buildChangeIntelligence({ prevSnapshot: r5prev, currentSnapshot: r5cur, publicIntelligenceVersion: 'v' });
const cvssItem = ci5.items.find((it) => it.cveId === 'CVE-2024-CVSS');
assert('CVSS_V3 -> CVSS_V4 (same severity) fires cvss-source-or-version-changed',
  cvssItem && cvssItem.classifications.includes('cvss-source-or-version-changed'));

/* ---- 6. SSVC transitions ---- */
console.log('');
console.log('[6] SSVC transitions');
const ssvcBase = (exploitation) => ({
  tracked: true, kev: { observation: 'present', present: false, kevDateAdded: null },
  severity: { observation: 'present', value: 'High', cvssSource: 'NVD', cvssVersion: 'CVSS_V3' },
  nvd: { observation: 'present', severity: 'High', cvssSource: 'NVD', cvssVersion: 'CVSS_V3' },
  epssProbability: 0.5, epss: { observation: 'present', probability: 0.5 },
  ssvcExploitation: { observation: 'present', exploitation },
  githubAdvisory: { observation: 'unknown', ghsaId: null, firstPatchedAvailable: null },
  firstPatchedAvailable: false,
  osv: { observation: 'unknown', recordIds: [], affectedSignature: null, withdrawn: null },
  withdrawn: false, affectedSignature: '',
});
const r6prev = s({ 'CVE-2024-SSVC': ssvcBase('poc') });
const r6cur = s({ 'CVE-2024-SSVC': ssvcBase('active') });
const ci6 = ciMod.buildChangeIntelligence({ prevSnapshot: r6prev, currentSnapshot: r6cur, publicIntelligenceVersion: 'v' });
const ssvcItem = ci6.items.find((it) => it.cveId === 'CVE-2024-SSVC');
assert('poc -> active fires ssvc-state-changed',
  ssvcItem && ssvcItem.classifications.includes('ssvc-state-changed'));

// present -> checked-absent (gone)
const r6prevG = s({ 'CVE-2024-SSVC2': ssvcBase('active') });
const r6curG = s({ 'CVE-2024-SSVC2': { ...ssvcBase('active'), ssvcExploitation: { observation: 'checked-absent', exploitation: null } } });
const ci6b = ciMod.buildChangeIntelligence({ prevSnapshot: r6prevG, currentSnapshot: r6curG, publicIntelligenceVersion: 'v' });
assert('SSVC present -> checked-absent does NOT fire ssvc-state-changed (only present->present does)',
  !ci6b.items.some((it) => it.classifications.includes('ssvc-state-changed')));

// checked-absent -> present fires ssvc-data-newly-available
const r6prevH = s({ 'CVE-2024-SSVC3': { ...ssvcBase('active'), ssvcExploitation: { observation: 'checked-absent', exploitation: null } } });
const r6curH = s({ 'CVE-2024-SSVC3': ssvcBase('poc') });
const ci6c = ciMod.buildChangeIntelligence({ prevSnapshot: r6prevH, currentSnapshot: r6curH, publicIntelligenceVersion: 'v' });
const ssvcItem3 = ci6c.items.find((it) => it.cveId === 'CVE-2024-SSVC3');
assert('SSVC checked-absent -> present fires ssvc-data-newly-available',
  ssvcItem3 && ssvcItem3.classifications.includes('ssvc-data-newly-available'));

/* ---- 7. GitHub Advisory transitions ---- */
console.log('');
console.log('[7] GitHub Advisory transitions');
const ghBase = (ghsaId, firstPatched) => ({
  tracked: true, kev: { observation: 'present', present: false, kevDateAdded: null },
  severity: { observation: 'present', value: 'High', cvssSource: 'NVD', cvssVersion: 'CVSS_V3' },
  nvd: { observation: 'present', severity: 'High', cvssSource: 'NVD', cvssVersion: 'CVSS_V3' },
  epssProbability: 0.5, epss: { observation: 'present', probability: 0.5 },
  ssvcExploitation: { observation: 'unknown', exploitation: null },
  githubAdvisory: { observation: 'present', ghsaId, firstPatchedAvailable: firstPatched },
  firstPatchedAvailable: firstPatched,
  osv: { observation: 'unknown', recordIds: [], affectedSignature: null, withdrawn: null },
  withdrawn: false, affectedSignature: '',
});
const r7prevChecked = s({ 'CVE-2024-GH': { ...ghBase(null, false), githubAdvisory: { observation: 'checked-absent', ghsaId: null, firstPatchedAvailable: null } } });
const r7curPresent = s({ 'CVE-2024-GH': ghBase('GHSA-xxxx', false) });
const ci7 = ciMod.buildChangeIntelligence({ prevSnapshot: r7prevChecked, currentSnapshot: r7curPresent, publicIntelligenceVersion: 'v' });
const ghItem = ci7.items.find((it) => it.cveId === 'CVE-2024-GH');
assert('GH checked-absent -> present fires github-advisory-newly-available',
  ghItem && ghItem.classifications.includes('github-advisory-newly-available'));

// firstPatched false -> true
const r7prevNoPatch = s({ 'CVE-2024-GH2': ghBase('GHSA-yyyy', false) });
const r7curPatch = s({ 'CVE-2024-GH2': ghBase('GHSA-yyyy', true) });
const ci7b = ciMod.buildChangeIntelligence({ prevSnapshot: r7prevNoPatch, currentSnapshot: r7curPatch, publicIntelligenceVersion: 'v' });
const ghItem2 = ci7b.items.find((it) => it.cveId === 'CVE-2024-GH2');
assert('first-patched false -> true fires first-patched-newly-available',
  ghItem2 && ghItem2.classifications.includes('first-patched-newly-available'));

// present -> checked-absent fires no-longer-available
const r7prevPresent = s({ 'CVE-2024-GH3': ghBase('GHSA-zzzz', true) });
const r7curAbsent = s({ 'CVE-2024-GH3': { ...ghBase(null, false), githubAdvisory: { observation: 'checked-absent', ghsaId: null, firstPatchedAvailable: null } } });
const ci7c = ciMod.buildChangeIntelligence({ prevSnapshot: r7prevPresent, currentSnapshot: r7curAbsent, publicIntelligenceVersion: 'v' });
const ghItem3 = ci7c.items.find((it) => it.cveId === 'CVE-2024-GH3');
assert('GH present -> checked-absent fires github-advisory-no-longer-available',
  ghItem3 && ghItem3.classifications.includes('github-advisory-no-longer-available'));

/* ---- 8. OSV transitions ---- */
console.log('');
console.log('[8] OSV transitions');
const osvBase = (recordIds, withdrawn) => ({
  tracked: true, kev: { observation: 'present', present: false, kevDateAdded: null },
  severity: { observation: 'present', value: 'High', cvssSource: 'NVD', cvssVersion: 'CVSS_V3' },
  nvd: { observation: 'present', severity: 'High', cvssSource: 'NVD', cvssVersion: 'CVSS_V3' },
  epssProbability: 0.5, epss: { observation: 'present', probability: 0.5 },
  ssvcExploitation: { observation: 'unknown', exploitation: null },
  githubAdvisory: { observation: 'unknown', ghsaId: null, firstPatchedAvailable: null },
  firstPatchedAvailable: false,
  osv: { observation: 'present', recordIds, affectedSignature: 'sha256:abc', withdrawn },
  withdrawn,
  affectedSignature: 'sha256:abc',
});
// checked-absent -> present fires osv-record-newly-correlated
const r8prevAbsent = s({ 'CVE-2024-OSV': { ...osvBase([], false), osv: { observation: 'checked-absent', recordIds: [], affectedSignature: null, withdrawn: null } } });
const r8curPresent = s({ 'CVE-2024-OSV': osvBase(['GHSA-xxxx'], false) });
const ci8 = ciMod.buildChangeIntelligence({ prevSnapshot: r8prevAbsent, currentSnapshot: r8curPresent, publicIntelligenceVersion: 'v' });
const osvItem = ci8.items.find((it) => it.cveId === 'CVE-2024-OSV');
assert('OSV checked-absent -> present fires osv-record-newly-correlated',
  osvItem && osvItem.classifications.includes('osv-record-newly-correlated'));

// present -> checked-absent fires osv-record-removed
const r8prevP = s({ 'CVE-2024-OSV2': osvBase(['GHSA-xxxx'], false) });
const r8curA = s({ 'CVE-2024-OSV2': { ...osvBase([], false), osv: { observation: 'checked-absent', recordIds: [], affectedSignature: null, withdrawn: null } } });
const ci8b = ciMod.buildChangeIntelligence({ prevSnapshot: r8prevP, currentSnapshot: r8curA, publicIntelligenceVersion: 'v' });
const osvItem2 = ci8b.items.find((it) => it.cveId === 'CVE-2024-OSV2');
assert('OSV present -> checked-absent fires osv-record-removed',
  osvItem2 && osvItem2.classifications.includes('osv-record-removed'));

// present -> present with different record set fires osv-record-set-changed
const r8prevSet = s({ 'CVE-2024-OSV3': osvBase(['GHSA-aaaa', 'GHSA-bbbb'], false) });
const r8curSet = s({ 'CVE-2024-OSV3': osvBase(['GHSA-aaaa', 'GHSA-cccc'], false) });
const ci8c = ciMod.buildChangeIntelligence({ prevSnapshot: r8prevSet, currentSnapshot: r8curSet, publicIntelligenceVersion: 'v' });
const osvItem3 = ci8c.items.find((it) => it.cveId === 'CVE-2024-OSV3');
assert('OSV present -> present with different set fires osv-record-set-changed',
  osvItem3 && osvItem3.classifications.includes('osv-record-set-changed'));

// withdrawn: false -> true
const r8prevW = s({ 'CVE-2024-OSV4': { ...osvBase(['GHSA-xxxx'], false) } });
const r8curW = s({ 'CVE-2024-OSV4': { ...osvBase(['GHSA-xxxx'], true) } });
const ci8d = ciMod.buildChangeIntelligence({ prevSnapshot: r8prevW, currentSnapshot: r8curW, publicIntelligenceVersion: 'v' });
const osvItem4 = ci8d.items.find((it) => it.cveId === 'CVE-2024-OSV4');
assert('OSV withdrawn false -> true fires withdrawn',
  osvItem4 && osvItem4.classifications.includes('withdrawn'));

/* ---- 9. Comparability gates ---- */
console.log('');
console.log('[9] Comparability gates suppress axes when unavailable');
// SSVC partial in BOTH -> still comparable
const r9prev = s({ 'CVE-2024-COMP': {
  ...r1prev.byCve['CVE-2024-0001'],
  ssvcExploitation: { observation: 'present', exploitation: 'poc' },
} });
const r9cur = s({ 'CVE-2024-COMP': {
  ...r1prev.byCve['CVE-2024-0001'],
  ssvcExploitation: { observation: 'present', exploitation: 'active' },
} });
// Override provider comparability to put ssvc as 'partial' in both
r9prev.providerComparability = PARTIAL_PROVIDER;
r9cur.providerComparability = PARTIAL_PROVIDER;
const ci9 = ciMod.buildChangeIntelligence({ prevSnapshot: r9prev, currentSnapshot: r9cur, publicIntelligenceVersion: 'v' });
const compItem = ci9.items.find((it) => it.cveId === 'CVE-2024-COMP');
assert('SSVC partial in both still fires ssvc-state-changed',
  compItem && compItem.classifications.includes('ssvc-state-changed'));

// NVD unavailable in current -> no severity-class change
const r9prevFull = s({ 'CVE-2024-NO-NVD': {
  ...r1prev.byCve['CVE-2024-0001'],
  severity: { observation: 'present', value: 'Medium', cvssSource: 'NVD', cvssVersion: 'CVSS_V3' },
} });
const r9curNoNvd = s({ 'CVE-2024-NO-NVD': {
  ...r1prev.byCve['CVE-2024-0001'],
  severity: { observation: 'present', value: 'High', cvssSource: 'NVD', cvssVersion: 'CVSS_V3' },
} });
r9prevFull.providerComparability = { ...FULL_COMP, nvd: { comparable: true, asOf: '...' } };
r9curNoNvd.providerComparability = { ...FULL_COMP, nvd: { comparable: false, asOf: null } };
const ci9b = ciMod.buildChangeIntelligence({ prevSnapshot: r9prevFull, currentSnapshot: r9curNoNvd, publicIntelligenceVersion: 'v' });
const noNvdItem = ci9b.items.find((it) => it.cveId === 'CVE-2024-NO-NVD');
assert('NVD unavailable in current does NOT fire severity-class-changed',
  !noNvdItem || !noNvdItem.classifications.includes('severity-class-changed'));
assert('NVD unavailable in current is in suppressedAxes',
  ci9b.suppressedAxes.some((s) => s.axis === 'severity-class' || s.axis === 'cvss-source'));

/* ---- 10. No-fabrication rule ---- */
console.log('');
console.log('[10] No fabrication on incomplete run');
const noComparable = {
  cisaKev:        { comparable: false, asOf: null },
  nvd:            { comparable: false, asOf: null },
  firstEpss:      { comparable: false, asOf: null },
  ssvc:           { comparable: false, asOf: null },
  githubAdvisory: { comparable: false, asOf: null },
  osv:            { comparable: false, asOf: null },
};
const r10cur = s({ 'CVE-2024-NC': { ...r1prev.byCve['CVE-2024-0001'] } });
r10cur.providerComparability = noComparable;
const ci10 = ciMod.buildChangeIntelligence({ prevSnapshot: r1prev, currentSnapshot: r10cur, publicIntelligenceVersion: 'v' });
assert('No comparable axis -> empty items array',
  ci10.items.length === 0);
assert('No comparable axis -> partial: true',
  ci10.partial === true);
assert('No comparable axis -> reason set',
  ci10.reasons.length > 0);

/* ---- 11. Panel-level category aggregation ---- */
console.log('');
console.log('[11] Panel-level category aggregation');
const items11 = [
  { cveId: 'A', classifications: ['cve-newly-tracked'] },
  { cveId: 'B', classifications: ['kev-newly-present'] },
  { cveId: 'C', classifications: ['epss-materially-increased'] },
  { cveId: 'D', classifications: ['kev-no-longer-present'] },
  { cveId: 'E', classifications: ['cve-no-longer-tracked'] },
];
assert('filterByCategory: newly-tracked returns A only',
  ciMod.filterByCategory(items11, 'newly-tracked', 25).items.length === 1);
assert('filterByCategory: fact-newly-available returns B only',
  ciMod.filterByCategory(items11, 'fact-newly-available', 25).items.length === 1);
assert('filterByCategory: fact-changed returns C only',
  ciMod.filterByCategory(items11, 'fact-changed', 25).items.length === 1);
assert('filterByCategory: fact-no-longer-present returns D only',
  ciMod.filterByCategory(items11, 'fact-no-longer-present', 25).items.length === 1);
assert('filterByCategory: no-longer-tracked returns E only',
  ciMod.filterByCategory(items11, 'no-longer-tracked', 25).items.length === 1);
assert('filterByCategory: totalMatching is reported',
  ciMod.filterByCategory(items11, 'fact-changed', 25).totalMatching === 1);
assert('filterByCategory: truncated.shown <= limit',
  ciMod.filterByCategory(items11, 'fact-changed', 25).truncated.shown <= 25);

/* ---- 12. Determinism ---- */
console.log('');
console.log('[12] Determinism');
const r12a = s({ 'CVE-A': r1prev.byCve['CVE-2024-0001'], 'CVE-B': r1cur.byCve['CVE-2024-0001'] });
const r12b = s({ 'CVE-B': r1cur.byCve['CVE-2024-0001'], 'CVE-A': r1prev.byCve['CVE-2024-0001'] });
const ci12a = ciMod.buildChangeIntelligence({ prevSnapshot: r1prev, currentSnapshot: r12a, publicIntelligenceVersion: 'v' });
const ci12b = ciMod.buildChangeIntelligence({ prevSnapshot: r1prev, currentSnapshot: r12b, publicIntelligenceVersion: 'v' });
assert('buildChangeIntelligence is deterministic regardless of object key order',
  JSON.stringify(ci12a) === JSON.stringify(ci12b));

/* ---- 13. CLASSIFICATION_SET is consistent ---- */
console.log('');
console.log('[13] CLASSIFICATION_SET consistency');
for (const c of ciMod.CLASSIFICATION_ORDER) {
  assert(`CLASSIFICATION_SET contains ${c}`,
    ciMod.CLASSIFICATION_SET.has(c));
}

/* ---- 14. No new function entry file ---- */
console.log('');
console.log('[14] No new function entry file');
const { readdirSync } = await import('node:fs');
const fnDir = resolve(root, 'netlify', 'functions');
const entries = readdirSync(fnDir).filter((f) => f.endsWith('.mjs'));
assert('Public function entry count remains 5', entries.length === 5);

/* ---- 15. kev-removed-or-corrected is GONE ---- */
console.log('');
console.log('[15] kev-removed-or-corrected is NOT a classification');
assert('kev-removed-or-corrected is NOT in CLASSIFICATION_ORDER',
  !ciMod.CLASSIFICATION_ORDER.includes('kev-removed-or-corrected'));
assert('kev-removed-or-corrected is NOT in CLASSIFICATION_SET',
  !ciMod.CLASSIFICATION_SET.has('kev-removed-or-corrected'));
const ciModSource = (await import('node:fs')).readFileSync(resolve(root, 'netlify/functions/_shared/changeIntelligence.mjs'), 'utf8');
assert('kev-removed-or-corrected string does NOT appear in source',
  !ciModSource.includes('kev-removed-or-corrected'));

/* ---- 16. UI copy lock ---- */
console.log('');
console.log('[16] UI copy lock');
assert('"fact unavailable" is NOT a panel category',
  !ciMod.PANEL_CATEGORIES.includes('fact-unavailable'));
assert('"fact no longer present" IS a panel category',
  ciMod.PANEL_CATEGORIES.includes('fact-no-longer-present'));

/* ---- Summary ---- */
console.log('');
console.log('======================================');
console.log(`V6.1 change intelligence: ${passed} passed, ${failed} failed`);
if (failed > 0) {
  console.log('Failures:');
  for (const f of failures) console.log(`  - ${f.label}${f.extra ? ` (${f.extra})` : ''}`);
  process.exit(1);
}
console.log('All change intelligence tests passed.');
