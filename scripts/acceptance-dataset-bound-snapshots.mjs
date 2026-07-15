#!/usr/bin/env node
// V6.1 — dataset-bound public-intelligence snapshot acceptance.
//
// Targeted test for:
//   - Source-health observation persistence and derived
//     state decision tree (5 mutually-exclusive states).
//   - Public per-CVE observation snapshot building.
//   - Per-Blob public hash computation (dataset, Vulnrichment,
//     GitHub Advisory).
//   - Composite publicStateHash composition.
//   - Dataset-bound publication, atomicity, skip-unchanged.
//   - Three-version retention.
//
//   node scripts/acceptance-dataset-bound-snapshots.mjs

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { gzipSync, gunzipSync } from 'node:zlib';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..');

let passed = 0;
let failed = 0;
const failures = [];
function assert(label, cond, extra = '') {
  if (cond) { passed++; console.log(`  PASS  ${label}`); }
  else { failed++; failures.push({ label, extra }); console.log(`  FAIL  ${label}${extra ? `  -- ${extra}` : ''}`); }
}

const shMod = await import('../netlify/functions/_shared/sourceHealth.mjs');
const snapMod = await import('../netlify/functions/_shared/publicSnapshot.mjs');
const pubMod = await import('../netlify/functions/_shared/datasetBoundPublish.mjs');
const hashMod = await import('../netlify/functions/_shared/publicIntelligenceHash.mjs');

console.log('V6.1 — dataset-bound snapshot acceptance');
console.log('==========================================');
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
    async setJSON(key, value) {
      blobs.set(key, { value, type: 'json' });
    },
    async setBinary(key, buffer) {
      blobs.set(key, { value: buffer, type: 'binary' });
    },
    async delete(key) { blobs.delete(key); },
    async list({ prefix = '' } = {}) {
      const matched = [];
      for (const k of blobs.keys()) if (k.startsWith(prefix)) matched.push({ key: k, etag: 'mock' });
      return { blobs: matched };
    },
  };
}

/* ---- 1. Source-health decision tree ---- */
console.log('[1] Source-health state derivation (mutually exclusive)');

// 1.1 unknown: no observation, no hard failure
assert('unknown: no observation, no hard failure',
  shMod.deriveSourceState({
    lastSuccessfulFetchAt: null,
    lastAttemptedFetchAt: null,
    lastAttemptOutcome: null,
    usableCoverage: 0, totalCoverage: 0, thresholdMinutes: 90, sanitizedReason: null,
  }) === 'unknown');

// 1.2 unavailable: no observation, hard failure, has attempt
assert('unavailable: no observation, hard failure, has attempt',
  shMod.deriveSourceState({
    lastSuccessfulFetchAt: null,
    lastAttemptedFetchAt: '2026-07-15T03:30:00.000Z',
    lastAttemptOutcome: 'hard-failure',
    usableCoverage: 0, totalCoverage: 100, thresholdMinutes: 90, sanitizedReason: 'CISA KEV was unreachable',
  }) === 'unavailable');

// 1.3 unknown trumps unavailable when no attempt
assert('unknown beats unavailable when no attempt recorded',
  shMod.deriveSourceState({
    lastSuccessfulFetchAt: null,
    lastAttemptedFetchAt: null,
    lastAttemptOutcome: 'hard-failure',
    usableCoverage: 0, totalCoverage: 0, thresholdMinutes: 90, sanitizedReason: null,
  }) === 'unknown');

// 1.4 stale: observation older than threshold
const now = new Date('2026-07-15T05:00:00.000Z');
const twoHoursAgo = new Date(now.getTime() - 120 * 60 * 1000).toISOString();
assert('stale: observation older than threshold',
  shMod.deriveSourceState({
    lastSuccessfulFetchAt: twoHoursAgo,
    lastAttemptedFetchAt: twoHoursAgo,
    lastAttemptOutcome: 'success',
    usableCoverage: 100, totalCoverage: 100, thresholdMinutes: 90, sanitizedReason: null,
  }, now) === 'stale');

// 1.5 fresh: recent, complete coverage, no degrade
const tenMinAgo = new Date(now.getTime() - 10 * 60 * 1000).toISOString();
assert('fresh: recent, complete coverage, no degrade',
  shMod.deriveSourceState({
    lastSuccessfulFetchAt: tenMinAgo,
    lastAttemptedFetchAt: tenMinAgo,
    lastAttemptOutcome: 'success',
    usableCoverage: 100, totalCoverage: 100, thresholdMinutes: 90, sanitizedReason: null,
  }, now) === 'fresh');

// 1.6 partial: incomplete coverage
assert('partial: recent, incomplete coverage',
  shMod.deriveSourceState({
    lastSuccessfulFetchAt: tenMinAgo,
    lastAttemptedFetchAt: tenMinAgo,
    lastAttemptOutcome: 'success',
    usableCoverage: 50, totalCoverage: 100, thresholdMinutes: 90, sanitizedReason: 'Incremental backfill in progress.',
  }, now) === 'partial');

// 1.7 partial: hard failure after usable observation
assert('partial: hard failure after usable observation preserves usability',
  shMod.deriveSourceState({
    lastSuccessfulFetchAt: tenMinAgo,
    lastAttemptedFetchAt: new Date(now.getTime() - 1 * 60 * 1000).toISOString(),
    lastAttemptOutcome: 'hard-failure',
    usableCoverage: 100, totalCoverage: 100, thresholdMinutes: 90,
    sanitizedReason: 'Most recent attempt: degraded. The displayed data is from the last successful run.',
  }, now) === 'partial');

// 1.8 soft-partial: recent, soft partial outcome, complete coverage
assert('partial: recent, soft-partial, complete coverage',
  shMod.deriveSourceState({
    lastSuccessfulFetchAt: tenMinAgo,
    lastAttemptedFetchAt: tenMinAgo,
    lastAttemptOutcome: 'soft-partial',
    usableCoverage: 100, totalCoverage: 100, thresholdMinutes: 90, sanitizedReason: null,
  }, now) === 'partial');

/* ---- 2. buildPublicSourceHealth ---- */
console.log('');
console.log('[2] buildPublicSourceHealth');
const publicHealth = shMod.buildPublicSourceHealth({
  cisa_kev: {
    lastSuccessfulFetchAt: tenMinAgo,
    lastAttemptedFetchAt: tenMinAgo,
    lastAttemptOutcome: 'success',
    usableCoverage: 100, totalCoverage: 100, thresholdMinutes: 90, sanitizedReason: null,
  },
  nvd: {
    lastSuccessfulFetchAt: twoHoursAgo,
    lastAttemptedFetchAt: tenMinAgo,
    lastAttemptOutcome: 'success',
    usableCoverage: 100, totalCoverage: 100, thresholdMinutes: 90, sanitizedReason: null,
  },
  first_epss: {
    lastSuccessfulFetchAt: tenMinAgo,
    lastAttemptedFetchAt: tenMinAgo,
    lastAttemptOutcome: 'success',
    usableCoverage: 100, totalCoverage: 100, thresholdMinutes: 90, sanitizedReason: null,
  },
  cisa_vulnrichment: {
    lastSuccessfulFetchAt: tenMinAgo,
    lastAttemptedFetchAt: tenMinAgo,
    lastAttemptOutcome: 'soft-partial',
    usableCoverage: 50, totalCoverage: 100, thresholdMinutes: 14 * 24 * 60, sanitizedReason: 'Incremental backfill in progress.',
  },
  github_advisory: {
    lastSuccessfulFetchAt: tenMinAgo,
    lastAttemptedFetchAt: tenMinAgo,
    lastAttemptOutcome: 'soft-partial',
    usableCoverage: 80, totalCoverage: 100, thresholdMinutes: 14 * 24 * 60, sanitizedReason: 'Incremental backfill in progress.',
  },
  osv: {
    lastSuccessfulFetchAt: tenMinAgo,
    lastAttemptedFetchAt: tenMinAgo,
    lastAttemptOutcome: 'success',
    usableCoverage: 100, totalCoverage: 100, thresholdMinutes: 180, sanitizedReason: null,
  },
}, now);
assert('public health has 6 sources', publicHealth.length === 6);
const cisaKevHealth = publicHealth.find((s) => s.id === 'cisa_kev');
assert('CISA KEV state is fresh', cisaKevHealth.freshness.state === 'fresh');
const nvdHealth = publicHealth.find((s) => s.id === 'nvd');
assert('NVD state is stale (2h ago, 90 min threshold)', nvdHealth.freshness.state === 'stale');
const ssvcHealth = publicHealth.find((s) => s.id === 'cisa_vulnrichment');
assert('SSVC state is partial', ssvcHealth.freshness.state === 'partial');
assert('SSVC has partialReason (sanitized)',
  typeof ssvcHealth.freshness.partialReason === 'string' && ssvcHealth.freshness.partialReason.length > 0);
// No env-var names exposed
const hasEnvVar = publicHealth.some((s) => JSON.stringify(s).match(/NVD_API_KEY|GITHUB_TOKEN|THREATPULSE_/));
assert('No env-var names in public source-health', !hasEnvVar);
// provenanceUrl must be https
const badProvenance = publicHealth.find((s) => !s.provenanceUrl.startsWith('https://'));
assert('All provenance URLs are https', !badProvenance);

/* ---- 3. buildSourceHealthBlob ---- */
console.log('');
console.log('[3] buildSourceHealthBlob');
const blob = shMod.buildSourceHealthBlob({
  cisa_kev: { lastSuccessfulFetchAt: tenMinAgo, lastAttemptedFetchAt: tenMinAgo, lastAttemptOutcome: 'success', usableCoverage: 100, totalCoverage: 100, thresholdMinutes: 90, sanitizedReason: null },
}, now);
assert('Blob has schemaVersion', blob.schemaVersion === '1.0.0');
assert('Blob has 6 sources', blob.sources.length === 6);
// Observation-only fields, no derived state
const sample = blob.sources[0];
assert('Blob sources are observations, not derived state',
  !('state' in sample) && !('freshness' in sample));

/* ---- 4. buildPublicSnapshot ---- */
console.log('');
console.log('[4] buildPublicSnapshot');
const datasetEnvelope = {
  fetchedAt: '2026-07-15T03:54:00.000Z',
  mode: 'live',
  nvdStatus: 'nvd',
  epssStatus: 'first',
  vulnrichmentStatus: 'partial',
  githubAdvisoryStatus: 'partial',
  data: [
    { cveId: 'CVE-2024-1234', kev: true, kevDateAdded: '2026-07-10', severity: 'High', cvssSource: 'NVD', cvssVersion: 'CVSS_V3', cvssScore: 7.5, epssProbability: 0.48, ssvcExploitation: 'active', githubAdvisory: { ghsaId: 'GHSA-xxxx' } },
    { cveId: 'CVE-2024-5678', kev: false, severity: 'Medium', cvssSource: 'NVD', cvssVersion: 'CVSS_V3', cvssScore: 5.0, epssProbability: 0.12 },
  ],
};
const vulnrichmentCache = {
  records: {
    'CVE-2024-1234': { ssvc: { ssvcExploitation: 'active' }, cachedAt: 1 },
    'CVE-2024-9999': { ssvc: null, status: 'missing', cachedAt: 1, checkedAt: 1 },
  },
  updatedAt: '2026-07-15T03:50:00.000Z',
};
const githubAdvisoryCache = {
  records: {
    'CVE-2024-1234': { advisory: { ghsaId: 'GHSA-xxxx', packages: [{ firstPatchedVersion: '1.0.0' }] }, cachedAt: 1 },
    'CVE-2024-8888': { advisory: null, status: 'missing', cachedAt: 1, checkedAt: 1 },
  },
  updatedAt: '2026-07-15T03:50:00.000Z',
};
const osvProjection = {
  osvProjectionVersion: '2026-07-15T03-54-00Z-a1b2c3d4-7a3f2c8e1b9d',
  manifestContentHash: 'sha256:' + 'a'.repeat(64),
  generatedAt: '2026-07-15T03:54:00.000Z',
  byCve: {
    'CVE-2024-1234': { records: [{ osvId: 'GHSA-xxxx', sourceDatabase: 'GHSA', withdrawn: false, aliases: ['CVE-2024-1234'], affectedPackages: [] }], truncation: { recordsRemoved: 0 } },
  },
};
const snapshot = snapMod.buildPublicSnapshot({ datasetEnvelope, vulnrichmentCache, githubAdvisoryCache, osvProjection, now });
assert('Snapshot has 2 CVEs', snapshot.trackedCveCount === 2);
assert('Snapshot has providerComparability block',
  snapshot.providerComparability && snapshot.providerComparability.cisaKev);
assert('CISA KEV comparable true when mode=live',
  snapshot.providerComparability.cisaKev.comparable === true);
assert('SSVC comparable partial when status=partial',
  snapshot.providerComparability.ssvc.comparable === 'partial');
assert('OSV comparable true when projection present',
  snapshot.providerComparability.osv.comparable === true);
const cve1 = snapshot.byCve['CVE-2024-1234'];
assert('CVE-2024-1234 KEV observation is present',
  cve1.kev.observation === 'present' && cve1.kev.present === true);
assert('CVE-2024-1234 SSVC observation is present',
  cve1.ssvcExploitation.observation === 'present' && cve1.ssvcExploitation.exploitation === 'active');
assert('CVE-2024-1234 GitHub Advisory observation is present',
  cve1.githubAdvisory.observation === 'present' && cve1.githubAdvisory.ghsaId === 'GHSA-xxxx');
assert('CVE-2024-1234 firstPatchedAvailable is true',
  cve1.firstPatchedAvailable === true);
assert('CVE-2024-1234 OSV observation is present with one record id',
  cve1.osv.observation === 'present' && cve1.osv.recordIds.length === 1);
assert('CVE-2024-5678 SSVC observation is unknown (no cache entry)',
  snapshot.byCve['CVE-2024-5678'].ssvcExploitation.observation === 'unknown');

/* ---- 5. derivePublicState ---- */
console.log('');
console.log('[5] derivePublicState composite');
const state1 = pubMod.derivePublicState({ datasetEnvelope, vulnrichmentCache, githubAdvisoryCache, osvProjection });
assert('derivePublicState returns all four hashes', state1.datasetPublicHash && state1.vulnrichmentPublicHash && state1.githubAdvisoryPublicHash);
assert('publicStateHash is deterministic', state1.publicStateHash === pubMod.derivePublicState({ datasetEnvelope, vulnrichmentCache, githubAdvisoryCache, osvProjection }).publicStateHash);
// Cache change -> new publicStateHash
const state2 = pubMod.derivePublicState({
  datasetEnvelope,
  vulnrichmentCache: { ...vulnrichmentCache, records: { ...vulnrichmentCache.records, 'CVE-2024-NEW': { ssvc: { ssvcExploitation: 'poc' } } } },
  githubAdvisoryCache,
  osvProjection,
});
assert('Cache change produces a new publicStateHash', state1.publicStateHash !== state2.publicStateHash);
// Internal-only change -> SAME publicStateHash (V6.1 invariant: the
// internal hash metadata fields do not affect the public content
// hash; only the publicly projected fields do).
const state3 = pubMod.derivePublicState({
  datasetEnvelope: { ...datasetEnvelope, datasetPublicHash: 'sha256:' + 'f'.repeat(64) },
  vulnrichmentCache, githubAdvisoryCache, osvProjection,
});
assert('Internal-only change does NOT change publicStateHash',
  state1.publicStateHash === state3.publicStateHash);
// OSV projection change -> new publicStateHash
const state4 = pubMod.derivePublicState({
  datasetEnvelope, vulnrichmentCache, githubAdvisoryCache,
  osvProjection: { ...osvProjection, manifestContentHash: 'sha256:' + 'b'.repeat(64) },
});
assert('OSV projection hash change produces new publicStateHash',
  state1.publicStateHash !== state4.publicStateHash);

/* ---- 6. publishDatasetBound ---- */
console.log('');
console.log('[6] publishDatasetBound (mock store)');
const store1 = makeMockStore();
const pub1 = await pubMod.publishDatasetBound(store1, {
  datasetEnvelope, vulnrichmentCache, githubAdvisoryCache, osvProjection, now,
});
assert('First publish succeeds and is not skipped',
  pub1 && pub1.skipped === false);
assert('First publish produces a publicIntelligenceVersion',
  typeof pub1.publicIntelligenceVersion === 'string' && /-/.test(pub1.publicIntelligenceVersion));
assert('publicStateFingerprint is 12 hex chars',
  /^[0-9a-f]{12}$/.test(pub1.publicStateFingerprint));
assert('latest.json is written',
  store1.blobs.has('dataset/latest.json'));
const manifestKey = `dataset/versions/${pub1.publicIntelligenceVersion}/manifest.json`;
assert('Manifest is written', store1.blobs.has(manifestKey));
const snapshotKey = `dataset/versions/${pub1.publicIntelligenceVersion}/public-snapshot.json.gz`;
assert('Public snapshot is written gzipped', store1.blobs.has(snapshotKey));
const sourceHealthKey = `dataset/versions/${pub1.publicIntelligenceVersion}/source-health.json.gz`;
assert('Source-health observations are written gzipped', store1.blobs.has(sourceHealthKey));

const manifest1 = await store1.get(manifestKey, { type: 'json' });
assert('Manifest has publicStateHash', /^sha256:[0-9a-f]{64}$/.test(manifest1.publicStateHash));
assert('Manifest has datasetContentHash',
  /^sha256:[0-9a-f]{64}$/.test(manifest1.datasetContentHash));
assert('Manifest has referencedOsvProjectionVersion',
  manifest1.referencedOsvProjectionVersion === osvProjection.osvProjectionVersion);
assert('Manifest has empty changeItems truncation',
  manifest1.truncation.changeItems.shown === 0 && manifest1.truncation.changeItems.total === 0);

/* ---- 7. Skip-unchanged on identical input ---- */
console.log('');
console.log('[7] skip-unchanged on identical input');
const store2 = makeMockStore();
await pubMod.publishDatasetBound(store2, {
  datasetEnvelope, vulnrichmentCache, githubAdvisoryCache, osvProjection, now,
});
const latestBefore = await store2.get('dataset/latest.json', { type: 'json' });
// Re-publish with the SAME state
const pub2 = await pubMod.publishDatasetBound(store2, {
  datasetEnvelope, vulnrichmentCache, githubAdvisoryCache, osvProjection, now,
});
assert('Re-publish with identical state is skipped',
  pub2 && pub2.skipped === true && pub2.reason === 'dataset-bound-unchanged');
const latestAfter = await store2.get('dataset/latest.json', { type: 'json' });
assert('latest.json is unchanged after skip',
  JSON.stringify(latestBefore) === JSON.stringify(latestAfter));

/* ---- 8. New public state on cache change ---- */
console.log('');
console.log('[8] new publicStateHash on cache change');
const store3 = makeMockStore();
const pub3a = await pubMod.publishDatasetBound(store3, {
  datasetEnvelope, vulnrichmentCache, githubAdvisoryCache, osvProjection, now,
});
assert('First publish produces a publicStateHash',
  pub3a.publicStateHash);
const pub3b = await pubMod.publishDatasetBound(store3, {
  datasetEnvelope,
  vulnrichmentCache: { ...vulnrichmentCache, records: { ...vulnrichmentCache.records, 'CVE-2024-NEW2': { ssvc: { ssvcExploitation: 'poc' } } } },
  githubAdvisoryCache,
  osvProjection,
  now,
});
assert('Cache change produces a new publicStateHash',
  pub3a.publicStateHash !== pub3b.publicStateHash);
assert('Different publicIntelligenceVersion on cache change',
  pub3a.publicIntelligenceVersion !== pub3b.publicIntelligenceVersion);

/* ---- 9. INTERNAL_BLOB_FIELDS includes the new fields ---- */
console.log('');
console.log('[9] INTERNAL_BLOB_FIELDS includes new hash fields');
const refreshMod = await import('../netlify/functions/_shared/refresh.mjs');
assert('INTERNAL_BLOB_FIELDS includes datasetPublicHash',
  refreshMod.INTERNAL_BLOB_FIELDS.has('datasetPublicHash'));
assert('INTERNAL_BLOB_FIELDS includes vulnrichmentPublicHash',
  refreshMod.INTERNAL_BLOB_FIELDS.has('vulnrichmentPublicHash'));
assert('INTERNAL_BLOB_FIELDS includes githubAdvisoryPublicHash',
  refreshMod.INTERNAL_BLOB_FIELDS.has('githubAdvisoryPublicHash'));
assert('INTERNAL_BLOB_FIELDS includes lastPublicIntelligenceRefresh',
  refreshMod.INTERNAL_BLOB_FIELDS.has('lastPublicIntelligenceRefresh'));

/* ---- 10. No new function entry file ---- */
console.log('');
console.log('[10] No new function entry file');
const { readdirSync } = await import('node:fs');
const fnDir = resolve(root, 'netlify', 'functions');
const entries = readdirSync(fnDir).filter((f) => f.endsWith('.mjs'));
const expected = new Set([
  'dataset.mjs',
  'refresh-dataset-scheduled.mjs',
  'refresh-dataset-background.mjs',
  'refresh-baseline-scheduled.mjs',
  'refresh-baseline-background.mjs',
]);
assert('Public function entry count remains 5', entries.length === 5);
assert('Public function entries match expected set',
  [...expected].every((e) => entries.includes(e)) && entries.length === 5);

/* ---- 11. Public snapshot file structure ---- */
console.log('');
console.log('[11] Public snapshot blob structure');
const snapshotGz = store1.blobs.get(snapshotKey).value;
const snapshotJson = gunzipSync(snapshotGz).toString('utf8');
const snapshotParsed = JSON.parse(snapshotJson);
assert('Snapshot has schemaVersion', snapshotParsed.schemaVersion === '1.0.0');
assert('Snapshot has byCve', typeof snapshotParsed.byCve === 'object');
assert('Snapshot has providerComparability', typeof snapshotParsed.providerComparability === 'object');
assert('Snapshot has trackedCveCount', snapshotParsed.trackedCveCount === 2);

/* ---- Summary ---- */
console.log('');
console.log('==========================================');
console.log(`V6.1 dataset-bound: ${passed} passed, ${failed} failed`);
if (failed > 0) {
  console.log('Failures:');
  for (const f of failures) console.log(`  - ${f.label}${f.extra ? ` (${f.extra})` : ''}`);
  process.exit(1);
}
console.log('All dataset-bound tests passed.');
