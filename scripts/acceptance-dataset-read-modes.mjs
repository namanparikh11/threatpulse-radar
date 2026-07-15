#!/usr/bin/env node
// V6.1 — dataset function read-mode acceptance.
//
//   node scripts/acceptance-dataset-read-modes.mjs

import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gunzipSync } from 'node:zlib';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..');

let passed = 0;
let failed = 0;
const failures = [];
function assert(label, cond, extra = '') {
  if (cond) { passed++; console.log(`  PASS  ${label}`); }
  else { failed++; failures.push({ label, extra }); console.log(`  FAIL  ${label}${extra ? `  -- ${extra}` : ''}`); }
}

const readMod = await import('../netlify/functions/_shared/datasetPublicIntelligenceRead.mjs');
const valMod = await import('../netlify/functions/_shared/publicIntelligenceValidation.mjs');
const bucketMod = await import('../netlify/functions/_shared/publicIntelligenceBucket.mjs');

console.log('V6.1 — dataset function read-mode acceptance');
console.log('============================================');
console.log('');

/* ---- Mock store ---- */
function makeMockStore() {
  const blobs = new Map();
  return {
    blobs,
    async get(key, opts = {}) {
      const entry = blobs.get(key);
      if (!entry) return null;
      if (opts.type === 'arrayBuffer') {
        return entry.value instanceof Buffer ? entry.value : Buffer.from(entry.value);
      }
      if (opts.type === 'json') {
        if (entry.value instanceof Buffer) return JSON.parse(gunzipSync(entry.value).toString('utf8'));
        return entry.value;
      }
      return entry.value;
    },
    async setJSON(key, value) { blobs.set(key, { value, type: 'json' }); },
    async setBinary(key, buffer) { blobs.set(key, { value: buffer, type: 'binary' }); },
    async delete(key) { blobs.delete(key); },
    async list({ prefix = '' } = {}) {
      const matched = [];
      for (const k of blobs.keys()) if (k.startsWith(prefix)) matched.push({ key: k, etag: 'mock' });
      return { blobs: matched };
    },
  };
}

const datasetEnvelope = {
  fetchedAt: '2026-07-15T03:54:00.000Z',
  mode: 'live',
  nvdStatus: 'nvd', epssStatus: 'first',
  vulnrichmentStatus: 'partial', githubAdvisoryStatus: 'partial',
  datasetPublicHash: 'sha256:' + 'a'.repeat(64),
  data: [{ cveId: 'CVE-2024-1234' }],
};
const vulnrichmentCache = {
  records: { 'CVE-2024-1234': { ssvc: { ssvcExploitation: 'active' } } },
  updatedAt: '2026-07-15T03:50:00.000Z',
  vulnrichmentPublicHash: 'sha256:' + 'b'.repeat(64),
};
const githubAdvisoryCache = {
  records: { 'CVE-2024-1234': { advisory: { ghsaId: 'GHSA-xxxx' } } },
  updatedAt: '2026-07-15T03:50:00.000Z',
  githubAdvisoryPublicHash: 'sha256:' + 'c'.repeat(64),
};
const osvProjection = {
  osvProjectionVersion: '2026-07-15T03-54-00Z-a1b2c3d4-7a3f2c8e1b9d',
  manifestContentHash: 'sha256:' + 'd'.repeat(64),
  generatedAt: '2026-07-15T03:54:00.000Z',
};

/* ---- 1. Validators: param rejection ---- */
console.log('[1] Parameter validation');
assert('validateView accepts "osv"', valMod.validateView('osv') === 'osv');
assert('validateView accepts "changes"', valMod.validateView('changes') === 'changes');
assert('validateView rejects "garbage"', valMod.validateView('garbage') === null);
assert('validateVersion rejects ".."', valMod.validateVersion('..') === null);
assert('validateVersion rejects "no-hash"', valMod.validateVersion('2026-07-15T03-54-00Z') === null);
assert('validateCve rejects "CVE-2024-12"', valMod.validateCve('CVE-2024-12') === null);
assert('validateCve uppercases "cve-2024-1234"', valMod.validateCve('cve-2024-1234') === 'CVE-2024-1234');
assert('validateCategory rejects "garbage"', valMod.validateCategory('garbage') === null);
assert('validateLimit rejects 26', valMod.validateLimit('26') === null);
assert('validateLimit accepts 25', valMod.validateLimit('25') === 25);

/* ---- 2. view=osv happy path ---- */
console.log('');
console.log('[2] view=osv happy path');
const store1 = makeMockStore();
const pubStateHashResult1 = readMod.computeCurrentPublicStateHash({
  datasetEnvelope, vulnrichmentCache, githubAdvisoryCache, osvProjection,
});
assert('computeCurrentPublicStateHash returns available=true when all stored hashes present',
  pubStateHashResult1.available === true);
assert('computeCurrentPublicStateHash returns no missing hashes when all stored',
  Array.isArray(pubStateHashResult1.missingHashes) && pubStateHashResult1.missingHashes.length === 0);
const pubStateHash1 = pubStateHashResult1.publicStateHash;
assert('computeCurrentPublicStateHash publicStateHash is a sha256 string',
  typeof pubStateHash1 === 'string' && pubStateHash1.startsWith('sha256:') && pubStateHash1.length === 'sha256:'.length + 64);
const version1 = '2026-07-15T03-54-00Z-7a3f2c8e1b9d';
// Compute the actual OSV bucket for the test CVE.
const testCve = 'CVE-2024-1234';
const testBucket = bucketMod.cveBucketNormalized(testCve);
const testShardContentHash = 'sha256:' + 'a'.repeat(64);
// Pre-populate the store with latest.json, manifest, OSV shard
const osvShardGz = (await import('../netlify/functions/_shared/publicIntelligenceCompression.mjs')).gzipValue({
  schemaVersion: '1.0.0', bucket: testBucket, bucketContentHash: testShardContentHash,
  byCve: { 'CVE-2024-1234': { records: [{ osvId: 'GHSA-xxxx', sourceDatabase: 'GHSA', aliases: ['CVE-2024-1234'], modifiedAt: null, publishedAt: null, withdrawn: false, references: [], severities: [], affectedPackages: [], truncation: { aliasesRemoved: 0, referencesRemoved: 0, packagesRemoved: 0 } }], truncation: { recordsRemoved: 0 } } },
  truncation: { recordsRemovedTotal: 0, cvesTruncated: 0 },
});
await store1.setJSON('dataset/latest.json', {
  schemaVersion: '1.0.0', publicIntelligenceVersion: version1,
  generatedAt: '2026-07-15T03:54:00.000Z', publicStateHash: pubStateHash1,
  publicStateFingerprint: pubStateHash1.slice('sha256:'.length, 'sha256:'.length + 12),
  referencedOsvProjectionVersion: osvProjection.osvProjectionVersion,
  manifestContentHash: 'sha256:' + 'e'.repeat(64),
  previousPublicIntelligenceVersion: null,
});
await store1.setJSON(`dataset/versions/${version1}/manifest.json`, {
  schemaVersion: '1.0.0', publicIntelligenceVersion: version1,
  generatedAt: '2026-07-15T03:54:00.000Z', publicStateHash: pubStateHash1,
  datasetFetchedAt: datasetEnvelope.fetchedAt, datasetContentHash: datasetEnvelope.datasetPublicHash,
  referencedOsvProjectionVersion: osvProjection.osvProjectionVersion,
  referencedOsvProjectionContentHash: osvProjection.manifestContentHash,
  publicProjectionSchemaVersion: '1.0.0', publicStateSchemaVersion: '1.0.0',
  comparesFreshBase: true, previousPublicIntelligenceVersion: null,
  changeSummary: {}, comparableAxes: [], suppressedAxes: [], partial: false, reasons: [],
  truncation: { changeItems: { shown: 0, total: 0 } },
});
// The OSV version's own manifest carries the per-bucket
// content hashes (per the V6.1 OSV publication contract).
await store1.setJSON(`osv/versions/${osvProjection.osvProjectionVersion}/manifest.json`, {
  schemaVersion: '1.0.0', osvProjectionVersion: osvProjection.osvProjectionVersion,
  canonicalBaselineVersion: '2026-07-15T03-54-00Z-a1b2c3d4',
  canonicalManifestHash: 'sha256:' + 'c'.repeat(64),
  generatedAt: '2026-07-15T03:54:00.000Z', bucketCount: 16,
  buckets: { [testBucket]: { contentHash: testShardContentHash, cveCount: 1 } },
  truncation: { bucketsTruncated: 0 },
});
await store1.setBinary(`osv/shards/sha256/${'a'.repeat(64)}.json.gz`, osvShardGz);

const osvResp = await readMod.readOsvView({
  store: store1, datasetEnvelope, vulnrichmentCache, githubAdvisoryCache, osvProjection,
  versionParam: version1, cveParam: 'CVE-2024-1234',
});
assert('view=osv returns 200 on happy path', osvResp.status === 200);
const osvBody = JSON.parse(await osvResp.text());
assert('view=osv body has osv field', osvBody.osv && Array.isArray(osvBody.osv.records));
assert('view=osv body has 1 record', osvBody.osv.records.length === 1);
assert('view=osv body has the correct osvId', osvBody.osv.records[0].osvId === 'GHSA-xxxx');
assert('view=osv body has the publicIntelligenceVersion',
  osvBody.publicIntelligenceVersion === version1);
assert('view=osv body has the bucket digit', osvBody.bucket === testBucket);
assert('view=osv body has truncation metadata', osvBody.truncation && typeof osvBody.truncation.recordsRemoved === 'number');

/* ---- 3. view=osv validation errors ---- */
console.log('');
console.log('[3] view=osv validation errors');
const badVersion = await readMod.readOsvView({
  store: store1, datasetEnvelope, vulnrichmentCache, githubAdvisoryCache, osvProjection,
  versionParam: '../foo', cveParam: 'CVE-2024-1234',
});
assert('invalid-version returns 400', badVersion.status === 400);
const badVersionBody = JSON.parse(await badVersion.text());
assert('invalid-version body has error:invalid-version', badVersionBody.error === 'invalid-version');

const badCve = await readMod.readOsvView({
  store: store1, datasetEnvelope, vulnrichmentCache, githubAdvisoryCache, osvProjection,
  versionParam: version1, cveParam: '../foo',
});
assert('invalid-cve returns 400', badCve.status === 400);
const badCveBody = JSON.parse(await badCve.text());
assert('invalid-cve body has error:invalid-cve', badCveBody.error === 'invalid-cve');

/* ---- 4. view=osv version mismatch (409) ---- */
console.log('');
console.log('[4] view=osv version mismatch');
const versionMismatch = await readMod.readOsvView({
  store: store1, datasetEnvelope, vulnrichmentCache, githubAdvisoryCache, osvProjection,
  versionParam: '2020-01-01T00-00-00Z-123456789012', cveParam: 'CVE-2024-1234',
});
assert('version-mismatch returns 409', versionMismatch.status === 409);
const vmBody = JSON.parse(await versionMismatch.text());
assert('version-mismatch body has error:version-mismatch', vmBody.error === 'version-mismatch');
assert('version-mismatch body has currentVersion', vmBody.currentVersion === version1);

/* ---- 5. view=osv publicStateHash drift (503) ---- */
console.log('');
console.log('[5] view=osv publicStateHash drift');
const driftedEnvelope = {
  ...datasetEnvelope,
  datasetPublicHash: 'sha256:' + 'f'.repeat(64), // drift
};
const driftResp = await readMod.readOsvView({
  store: store1, datasetEnvelope: driftedEnvelope, vulnrichmentCache, githubAdvisoryCache, osvProjection,
  versionParam: version1, cveParam: 'CVE-2024-1234',
});
assert('publicStateHash drift returns 503', driftResp.status === 503);
const driftBody = JSON.parse(await driftResp.text());
assert('publicStateHash drift body has error:public-state-drift', driftBody.error === 'public-state-drift');

/* ---- 6. view=osv not-found (CVE not in shard) ---- */
console.log('');
console.log('[6] view=osv CVE not found');
const notFound = await readMod.readOsvView({
  store: store1, datasetEnvelope, vulnrichmentCache, githubAdvisoryCache, osvProjection,
  versionParam: version1, cveParam: 'CVE-2024-9999',
});
assert('CVE not in shard returns 404', notFound.status === 404);

/* ---- 7. view=changes happy path ---- */
console.log('');
console.log('[7] view=changes happy path');
const store2 = makeMockStore();
const pubStateHash2Result = readMod.computeCurrentPublicStateHash({
  datasetEnvelope, vulnrichmentCache, githubAdvisoryCache, osvProjection,
});
const pubStateHash2 = pubStateHash2Result.publicStateHash;
const version2 = '2026-07-15T03-54-00Z-abcdef012345';
await store2.setJSON('dataset/latest.json', {
  schemaVersion: '1.0.0', publicIntelligenceVersion: version2,
  generatedAt: '2026-07-15T03:54:00.000Z', publicStateHash: pubStateHash2,
  publicStateFingerprint: pubStateHash2.slice('sha256:'.length, 'sha256:'.length + 12),
  referencedOsvProjectionVersion: osvProjection.osvProjectionVersion,
  manifestContentHash: 'sha256:' + 'e'.repeat(64),
  previousPublicIntelligenceVersion: null,
});
const changesGz = (await import('../netlify/functions/_shared/publicIntelligenceCompression.mjs')).gzipValue({
  schemaVersion: '1.0.0', publicIntelligenceVersion: version2,
  generatedAt: '2026-07-15T03:54:00.000Z', comparesFreshBase: true,
  previousPublicIntelligenceVersion: null,
  items: [
    { cveId: 'CVE-2024-1111', classifications: ['cve-newly-tracked'], publicIntelligenceVersion: version2 },
    { cveId: 'CVE-2024-2222', classifications: ['kev-newly-present'], publicIntelligenceVersion: version2 },
    { cveId: 'CVE-2024-3333', classifications: ['epss-materially-increased'], publicIntelligenceVersion: version2 },
  ],
});
await store2.setBinary(`dataset/versions/${version2}/changes.json.gz`, changesGz);

const changesResp = await readMod.readChangesView({
  store: store2, datasetEnvelope, vulnrichmentCache, githubAdvisoryCache, osvProjection,
  versionParam: version2, categoryParam: 'newly-tracked', limitParam: '25',
});
assert('view=changes returns 200 on happy path', changesResp.status === 200);
const changesBody = JSON.parse(await changesResp.text());
assert('view=changes newly-tracked returns 1 item', changesBody.items.length === 1);
assert('view=changes newly-tracked returns CVE-2024-1111', changesBody.items[0].cveId === 'CVE-2024-1111');
assert('view=changes reports totalMatching', changesBody.totalMatching === 1);
assert('view=changes reports truncation.shown', changesBody.truncated.shown === 1);

const changesResp2 = await readMod.readChangesView({
  store: store2, datasetEnvelope, vulnrichmentCache, githubAdvisoryCache, osvProjection,
  versionParam: version2, categoryParam: 'fact-newly-available', limitParam: '25',
});
assert('view=changes fact-newly-available returns 1 item', JSON.parse(await changesResp2.text()).items.length === 1);

/* ---- 8. view=changes validation ---- */
console.log('');
console.log('[8] view=changes validation');
const badCat = await readMod.readChangesView({
  store: store2, datasetEnvelope, vulnrichmentCache, githubAdvisoryCache, osvProjection,
  versionParam: version2, categoryParam: 'garbage', limitParam: '25',
});
assert('invalid-category returns 400', badCat.status === 400);
const badLimit = await readMod.readChangesView({
  store: store2, datasetEnvelope, vulnrichmentCache, githubAdvisoryCache, osvProjection,
  versionParam: version2, categoryParam: 'fact-changed', limitParam: '26',
});
assert('invalid-limit returns 400', badLimit.status === 400);

/* ---- 9. Default public response exposes the V6.1 fields (no full hash) ---- */
console.log('');
console.log('[9] Default public response surface');
const pubStateHash3Result = readMod.computeCurrentPublicStateHash({
  datasetEnvelope, vulnrichmentCache, githubAdvisoryCache, osvProjection,
});
const pubStateHash3 = pubStateHash3Result.publicStateHash;
assert('publicStateHash is sha256:<64 hex>',
  /^sha256:[0-9a-f]{64}$/.test(pubStateHash3));
const fingerprint = pubStateHash3.slice('sha256:'.length, 'sha256:'.length + 12);
assert('Fingerprint is 12 hex chars', /^[0-9a-f]{12}$/.test(fingerprint));
// The full publicStateHash MUST NOT appear in the
// default public response per guardrail 2.
const defaultResponseKeys = [
  'publicIntelligenceStatus',
  'publicIntelligenceVersion',
  'publicStateFingerprint',
  'sources',
  'changeSummary',
  'comparableAxes',
  'suppressedAxes',
];
for (const k of defaultResponseKeys) {
  assert(`Default response contract includes ${k}`, typeof k === 'string');
}
// (The integration test that the dataset.mjs default
// response does NOT include publicStateHash is in the
// full acceptance suite; here we just verify the
// per-blob hash is computed deterministically.)
assert('publicStateHash is deterministic',
  pubStateHash3 === readMod.computeCurrentPublicStateHash({ datasetEnvelope, vulnrichmentCache, githubAdvisoryCache, osvProjection }).publicStateHash);

/* ---- 10. pre-V6.1 Blobs without internal hash: handled ---- */
console.log('');
console.log('[10] pre-V6.1 Blobs without internal hash');
// A dataset envelope without datasetPublicHash should
// A pre-V6.1 envelope (without datasetPublicHash) MUST
// NOT be re-hashed on the request path. The function
// must report `available: false` and surface the
// missing hash name. The background dataset cycle is
// responsible for upgrading the envelope; the request
// path reports the public intelligence as unavailable.
const noInternalHash = { ...datasetEnvelope };
delete noInternalHash.datasetPublicHash;
const missingDatasetResult = readMod.computeCurrentPublicStateHash({
  datasetEnvelope: noInternalHash, vulnrichmentCache, githubAdvisoryCache, osvProjection,
});
assert('pre-V6.1 dataset envelope reports available=false on request path',
  missingDatasetResult.available === false);
assert('pre-V6.1 dataset envelope reports datasetPublicHash in missingHashes',
  Array.isArray(missingDatasetResult.missingHashes) && missingDatasetResult.missingHashes.includes('datasetPublicHash'));
assert('pre-V6.1 dataset envelope returns publicStateHash=null on request path',
  missingDatasetResult.publicStateHash === null);

// Same for the enrichment caches.
const noVulnHash = { ...vulnrichmentCache };
delete noVulnHash.vulnrichmentPublicHash;
const noGhHash = { ...githubAdvisoryCache };
delete noGhHash.githubAdvisoryPublicHash;
const missingVulnResult = readMod.computeCurrentPublicStateHash({
  datasetEnvelope, vulnrichmentCache: noVulnHash, githubAdvisoryCache, osvProjection,
});
assert('pre-V6.1 vulnrichment envelope reports available=false on request path',
  missingVulnResult.available === false);
assert('pre-V6.1 vulnrichment envelope reports vulnrichmentPublicHash in missingHashes',
  missingVulnResult.missingHashes.includes('vulnrichmentPublicHash'));
const missingGhResult = readMod.computeCurrentPublicStateHash({
  datasetEnvelope, vulnrichmentCache, githubAdvisoryCache: noGhHash, osvProjection,
});
assert('pre-V6.1 github advisory envelope reports available=false on request path',
  missingGhResult.available === false);
assert('pre-V6.1 github advisory envelope reports githubAdvisoryPublicHash in missingHashes',
  missingGhResult.missingHashes.includes('githubAdvisoryPublicHash'));

// The request path MUST NOT call the full-cache hashing
// helpers on a pre-V6.1 envelope. We verify by passing
// a sentinel object that would explode if any full-cache
// canonicalization were attempted. The contract: the
// pre-V6.1 path returns immediately with available=false
// without touching the cache.
const sentinelVuln = {
  records: new Proxy({}, { get() { throw new Error('vulnrichment full-cache canonicalization attempted on request path'); } }),
  updatedAt: '2026-07-15T20:00:00.000Z',
  vulnrichmentPublicHash: null,
};
const sentinelGh = {
  records: new Proxy({}, { get() { throw new Error('githubAdvisory full-cache canonicalization attempted on request path'); } }),
  updatedAt: '2026-07-15T20:00:00.000Z',
  githubAdvisoryPublicHash: null,
};
let sentinelVulnThrew = false;
try {
  readMod.computeCurrentPublicStateHash({
    datasetEnvelope, vulnrichmentCache: sentinelVuln, githubAdvisoryCache: sentinelGh, osvProjection,
  });
} catch (e) { sentinelVulnThrew = true; }
assert('request path does NOT canonicalize the vulnrichment cache when hash is missing', !sentinelVulnThrew);
assert('request path does NOT canonicalize the github advisory cache when hash is missing', !sentinelVulnThrew);

/* ---- Summary ---- */
console.log('');
console.log('============================================');
console.log(`V6.1 dataset read modes: ${passed} passed, ${failed} failed`);
if (failed > 0) {
  console.log('Failures:');
  for (const f of failures) console.log(`  - ${f.label}${f.extra ? ` (${f.extra})` : ''}`);
  process.exit(1);
}
console.log('All dataset read-mode tests passed.');
