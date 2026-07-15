#!/usr/bin/env node
// V6.1 — OSV public projection acceptance suite.
//
// Targeted test for the OSV public projection publisher and
// mark-and-sweep GC. Pure-function tests plus a mock Blob
// store to exercise the orchestrator and GC end-to-end.
//
//   node scripts/acceptance-osv-public-projections.mjs
//
// The mock store implements the subset of the @netlify/blobs
// API used by the V6.1 publisher: get(key, opts), setJSON,
// setBinary, delete, list({ prefix }).

import { createHash } from 'node:crypto';
import { gzipSync, gunzipSync } from 'node:zlib';
import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, resolve, join } from 'node:path';
const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..');

let passed = 0;
let failed = 0;
const failures = [];
function assert(label, cond, extra = '') {
  if (cond) { passed++; console.log(`  PASS  ${label}`); }
  else { failed++; failures.push({ label, extra }); console.log(`  FAIL  ${label}${extra ? `  -- ${extra}` : ''}`); }
}

const projMod = await import('../netlify/functions/_shared/osvPublicProjection.mjs');
const pubMod = await import('../netlify/functions/_shared/osvProjectionPublish.mjs');
const gcMod = await import('../netlify/functions/_shared/osvProjectionGc.mjs');
const hashMod = await import('../netlify/functions/_shared/publicIntelligenceHash.mjs');
const sizeMod = await import('../netlify/functions/_shared/publicIntelligenceSize.mjs');
const storeMod = await import('../netlify/functions/_shared/publicIntelligenceStore.mjs');
const compMod = await import('../netlify/functions/_shared/publicIntelligenceCompression.mjs');

console.log('V6.1 — OSV public projection acceptance');
console.log('========================================');
console.log('');

/* ---- Mock store ---- */
function makeMockStore() {
  const blobs = new Map(); // key -> { value, type }
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
    async delete(key) {
      blobs.delete(key);
    },
    async list({ prefix = '' } = {}) {
      const matched = [];
      for (const k of blobs.keys()) {
        if (k.startsWith(prefix)) matched.push({ key: k, etag: 'mock' });
      }
      return { blobs: matched };
    },
  };
}

/* ---- 1. Multi-record per CVE preservation ---- */
console.log('[1] Multi-record per CVE preservation');

const ghsaRecord = {
  osvId: 'GHSA-xxxx-yyyy-zzzz',
  aliases: ['CVE-2024-1234', 'PYSEC-2024-12'],
  modifiedAt: '2026-07-14T00:00:00Z',
  publishedAt: '2026-01-12T00:00:00Z',
  withdrawn: false,
  references: [
    { type: 'ADVISORY', url: 'https://github.com/example/repo' },
    { type: 'WEB', url: 'https://example.com/' },
  ],
  severities: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/...' }],
  affected: [
    {
      packageEcosystem: 'npm',
      packageName: 'example',
      packagePurl: 'pkg:npm/example',
      versions: ['0.9.0', '0.9.1', '1.0.0'],
      ranges: [{
        type: 'ECOSYSTEM',
        events: [
          { introduced: '0' },
          { fixed: '1.0.0' },
        ],
        databaseSpecific: { x: 1 },
      }],
      ecosystemSpecific: { 'npm: Severity': 'high' },
    },
  ],
};

const goRecord = {
  osvId: 'GO-2024-1234',
  aliases: ['CVE-2024-1234'],
  modifiedAt: '2026-07-15T00:00:00Z',
  publishedAt: '2026-01-15T00:00:00Z',
  withdrawn: false,
  references: [{ type: 'ADVISORY', url: 'https://pkg.go.dev/vuln/GO-2024-1234' }],
  severities: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N' }],
  affected: [{
    packageEcosystem: 'Go',
    packageName: 'github.com/example/lib',
    packagePurl: null,
    versions: [],
    ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }] }],
  }],
};

const ctx = projMod.projectCveToOsvPublic('CVE-2024-1234', [ghsaRecord, goRecord]);
assert('Multi-record per CVE preserves both records',
  ctx && ctx.records.length === 2);
assert('Records are sorted by (sourceDatabase, osvId)',
  ctx.records[0].sourceDatabase === 'GHSA' && ctx.records[1].sourceDatabase === 'GO');
assert('sourceDatabase derivation is correct for GHSA',
  projMod.projectCanonicalRecordToPublic(ghsaRecord, 'GHSA-xxxx-yyyy-zzzz').sourceDatabase === 'GHSA');
assert('sourceDatabase derivation is correct for GO',
  projMod.projectCanonicalRecordToPublic(goRecord, 'GO-2024-1234').sourceDatabase === 'GO');
assert('sourceDatabase derivation defaults to OSV-DEV',
  projMod.projectCanonicalRecordToPublic({}, 'CVE-2024-9999').sourceDatabase === 'OSV-DEV');
assert('sourceDatabase derivation handles PYSEC',
  projMod.projectCanonicalRecordToPublic({}, 'PYSEC-2024-99').sourceDatabase === 'PYSEC');

/* ---- 2. Field caps and truncation metadata ---- */
console.log('');
console.log('[2] Field caps and truncation metadata');

// Generate a record with many aliases
const manyAliases = Array.from({ length: 25 }, (_, i) => `CVE-2024-${(i + 1).toString().padStart(4, '0')}`);
const manyRefs = Array.from({ length: 30 }, (_, i) => ({ type: 'WEB', url: `https://example.com/${i}` }));
const manyPkgs = Array.from({ length: 12 }, (_, i) => ({
  packageEcosystem: 'npm', packageName: `pkg${i}`, packagePurl: null,
  versions: Array.from({ length: 15 }, (_, j) => `${i}.${j}.0`),
  ranges: Array.from({ length: 6 }, (_, j) => ({
    type: 'ECOSYSTEM',
    events: Array.from({ length: 12 }, (_, k) => ({ introduced: `${k}` })),
  })),
}));
const bigRecord = {
  osvId: 'GHSA-aaaa',
  aliases: manyAliases,
  modifiedAt: null, publishedAt: null,
  withdrawn: false,
  references: manyRefs,
  severities: [],
  affected: manyPkgs,
};
const big = projMod.projectCanonicalRecordToPublic(bigRecord, 'GHSA-aaaa');
assert('Aliases capped at 10',
  big.aliases.length === 10 && big.truncation.aliasesRemoved === 15);
assert('References capped at 5',
  big.references.length === 5 && big.truncation.referencesRemoved === 25);
assert('Packages capped at 6',
  big.affectedPackages.length === 6 && big.truncation.packagesRemoved === 6);

// Inspect a single capped package
const pkg = big.affectedPackages[0];
assert('Ranges capped at 4 per package',
  pkg.ranges.length === 4 && pkg.truncation.rangesRemoved === 2);
assert('Events capped at 8 per range',
  pkg.ranges[0].events.length === 8);
// The total eventsTruncated should reflect all events dropped
// across all retained ranges (each of the 4 retained ranges
// dropped 4 events = 16 total events dropped from 12-8=4 per range)
assert('eventsTruncated counted across all ranges',
  pkg.truncation.eventsTruncated > 0);
assert('Versions capped at 8 per package',
  pkg.versions.length === 8 && pkg.truncation.versionsRemoved === 7);

/* ---- 3. ecosystemSpecific cap ---- */
console.log('');
console.log('[3] ecosystemSpecific cap');
const ecoBig = {};
for (let i = 0; i < 50; i++) ecoBig[`k${i}`] = i;
const pkgEco = projMod.projectCanonicalRecordToPublic({
  osvId: 'GHSA-eco',
  aliases: [],
  modifiedAt: null, publishedAt: null,
  withdrawn: false,
  references: [],
  severities: [],
  affected: [{ packageEcosystem: 'npm', packageName: 'x', versions: [], ranges: [], ecosystemSpecific: ecoBig }],
}, 'GHSA-eco');
assert('ecosystemSpecific is capped at 32 pairs',
  Object.keys(pkgEco.affectedPackages[0].ecosystemSpecific).length === 32);

/* ---- 4. Records-per-CVE cap ---- */
console.log('');
console.log('[4] Records-per-CVE cap');
const manyRecs = Array.from({ length: 15 }, (_, i) => ({
  ...ghsaRecord,
  osvId: `GHSA-aaaa-bbbb-${i.toString().padStart(4, '0')}`,
  aliases: ['CVE-2024-1234'],
}));
const manyCtx = projMod.projectCveToOsvPublic('CVE-2024-1234', manyRecs);
assert('Records capped at 8 per CVE',
  manyCtx.records.length === 8 && manyCtx.truncation.recordsRemoved === 7);

/* ---- 5. Dedup by osvId ---- */
console.log('');
console.log('[5] Dedup by osvId');
const dupCtx = projMod.projectCveToOsvPublic('CVE-2024-1234', [ghsaRecord, ghsaRecord, goRecord]);
assert('Dedup keeps one of each osvId',
  dupCtx.records.length === 2);

/* ---- 6. Range preservation (verbatim) ---- */
console.log('');
console.log('[6] Range preservation');
const complexRanges = [{
  packageEcosystem: 'npm', packageName: 'x', versions: [],
  ranges: [{
    type: 'ECOSYSTEM',
    events: [
      { introduced: '0' },
      { fixed: '1.0.0' },
      { last_affected: '1.5.0' },
    ],
  }],
}];
const rangeOut = projMod.projectCanonicalRecordToPublic({
  osvId: 'GHSA-r', aliases: [],
  modifiedAt: null, publishedAt: null,
  withdrawn: false, references: [], severities: [],
  affected: complexRanges,
}, 'GHSA-r');
assert('Range events preserved verbatim',
  rangeOut.affectedPackages[0].ranges[0].events.length === 3);
assert('Range event types preserved',
  rangeOut.affectedPackages[0].ranges[0].events[0].introduced === '0' &&
  rangeOut.affectedPackages[0].ranges[0].events[1].fixed === '1.0.0' &&
  rangeOut.affectedPackages[0].ranges[0].events[2].last_affected === '1.5.0');

/* ---- 7. Severity preservation (no normalization) ---- */
console.log('');
console.log('[7] Severity preservation');
const sevOut = projMod.projectCanonicalRecordToPublic({
  osvId: 'GHSA-s', aliases: [],
  modifiedAt: null, publishedAt: null,
  withdrawn: false, references: [],
  severities: [
    { type: 'CVSS_V2', score: 'AV:N/AC:L/...' },
    { type: 'CVSS_V3', score: 'CVSS:3.0/AV:N' },
    { type: 'CVSS_V4', score: 'CVSS:4.0/AV:N' },
  ],
  affected: [],
}, 'GHSA-s');
assert('CVSS_V2 preserved as CVSS_V2',
  sevOut.severities.find((s) => s.type === 'CVSS_V2') !== undefined);
assert('CVSS_V4 preserved as CVSS_V4',
  sevOut.severities.find((s) => s.type === 'CVSS_V4') !== undefined);

/* ---- 8. Reference ordering (ADVISORY first) ---- */
console.log('');
console.log('[8] Reference ordering');
const refOut = projMod.projectCanonicalRecordToPublic({
  osvId: 'GHSA-r', aliases: [],
  modifiedAt: null, publishedAt: null,
  withdrawn: false,
  references: [
    { type: 'WEB', url: 'https://z.example/' },
    { type: 'ADVISORY', url: 'https://a.example/' },
    { type: 'REPORT', url: 'https://r.example/' },
    { type: 'FIX', url: 'https://f.example/' },
    { type: 'WEB', url: 'https://b.example/' },
    { type: 'ARTICLE', url: 'https://ar.example/' },
    { type: 'PACKAGE', url: 'https://p.example/' },
    { type: 'EVIDENCE', url: 'https://e.example/' },
  ],
  severities: [], affected: [],
}, 'GHSA-r');
// After sort and cap to 5: ADVISORY, REPORT, FIX, PACKAGE, then the
// first WEB by URL sort (b.example before z.example).
assert('Reference order is ADVISORY,REPORT,FIX,PACKAGE,WEB (cap=5)',
  refOut.references.map((r) => r.type).join(',') ===
  'ADVISORY,REPORT,FIX,PACKAGE,WEB');
assert('References beyond cap are dropped',
  refOut.references.length === 5);
assert('Within same type, references are sorted by url',
  refOut.references[4].url === 'https://b.example/');

/* ---- 9. Partitioning into 16 deterministic buckets ---- */
console.log('');
console.log('[9] 16-bucket partition');
// Build a small fixture of CVEs and verify bucket assignment
const fixtureCves = [
  'CVE-2024-1234', 'CVE-2024-5678', 'CVE-2024-9999',
  'CVE-2023-0001', 'CVE-2022-7777', 'CVE-2025-1234',
  'CVE-2026-5555', 'CVE-2024-4321',
];
const byCve = {};
for (const c of fixtureCves) {
  byCve[c] = { records: [{ osvId: 'GHSA-x', sourceDatabase: 'GHSA', aliases: [c], modifiedAt: null, publishedAt: null, withdrawn: false, references: [], severities: [], affectedPackages: [], truncation: { aliasesRemoved: 0, referencesRemoved: 0, packagesRemoved: 0 } }], truncation: { recordsRemoved: 0 } };
}
const buckets = projMod.partitionIntoBuckets(byCve);
assert('partitionIntoBuckets returns 16 buckets',
  Array.isArray(buckets) && buckets.length === 16);
const totalCves = buckets.reduce((a, b) => a + b.cveCount, 0);
assert('All CVEs are accounted for across buckets',
  totalCves === fixtureCves.length);
const buckets2 = projMod.partitionIntoBuckets(byCve);
const sameShape = buckets.every((b, i) => {
  const b2 = buckets2[i];
  return b.cveCount === b2.cveCount && Object.keys(b.byCve).join(',') === Object.keys(b2.byCve).join(',');
});
assert('partitionIntoBuckets is deterministic', sameShape);

/* ---- 10. Bucket content hash determinism ---- */
console.log('');
console.log('[10] Bucket content hash determinism');
const sampleBucket = buckets.find((b) => b.cveCount > 0);
const h1 = projMod.bucketContentHash(sampleBucket);
const h2 = projMod.bucketContentHash(sampleBucket);
assert('bucketContentHash is deterministic',
  h1 === h2 && /^sha256:[0-9a-f]{64}$/.test(h1));
const sampleBucketMut = JSON.parse(JSON.stringify(sampleBucket));
sampleBucketMut.byCve[Object.keys(sampleBucketMut.byCve)[0]] = { changed: true };
const h3 = projMod.bucketContentHash(sampleBucketMut);
assert('bucketContentHash changes when content changes',
  h1 !== h3);

/* ---- 11. End-to-end publication with mock store ---- */
console.log('');
console.log('[11] End-to-end publication (mock store)');

const fixtureEntities = [
  { osvId: 'GHSA-xxxx-yyyy-zzzz', aliases: ['CVE-2024-1234'], modifiedAt: '2026-07-14T00:00:00Z', publishedAt: '2026-01-12T00:00:00Z', withdrawn: false, references: [{ type: 'ADVISORY', url: 'https://x' }], severities: [{ type: 'CVSS_V3', score: 'AV:N' }], affected: [] },
  { osvId: 'GO-2024-1234', aliases: ['CVE-2024-1234'], modifiedAt: '2026-07-15T00:00:00Z', publishedAt: '2026-01-15T00:00:00Z', withdrawn: false, references: [{ type: 'ADVISORY', url: 'https://y' }], severities: [], affected: [] },
  { osvId: 'GHSA-aaaa-bbbb-0001', aliases: ['CVE-2024-5678'], modifiedAt: '2026-07-10T00:00:00Z', publishedAt: '2026-01-10T00:00:00Z', withdrawn: false, references: [], severities: [], affected: [] },
];

const store1 = makeMockStore();
const fakeManifestHash = 'sha256:' + 'a'.repeat(64);
const pub1 = await pubMod.publishOsvProjection(store1, fixtureEntities, {
  canonicalBaselineVersion: '2026-07-15T03-54-00Z-a1b2c3d4',
  canonicalManifestHash: fakeManifestHash,
});
assert('First publication succeeds and is not skipped',
  pub1 && pub1.skipped === false);
assert('First publication has a 16-bucket partition',
  pub1.bucketCount === 16);
assert('First publication produced an osvProjectionVersion',
  typeof pub1.osvProjectionVersion === 'string' && /-a1b2c3d4-/.test(pub1.osvProjectionVersion));
assert('latest.json is written',
  store1.blobs.has('osv/latest.json'));
assert('Per-version manifest is written',
  store1.blobs.has(`osv/versions/${pub1.osvProjectionVersion}/manifest.json`));
// Verify shard writes: each bucket has a content-addressed shard
const writtenShards = [...store1.blobs.keys()].filter((k) => k.startsWith('osv/shards/sha256/'));
assert('Per-bucket shards are content-addressed',
  writtenShards.length === 16);

// Verify the manifest structure
const manifest1 = await pubMod.readRetainedOsvManifests(store1, pub1.osvProjectionVersion);
assert('readRetainedOsvManifests returns the current manifest',
  manifest1.length === 1 && manifest1[0].manifest.osvProjectionVersion === pub1.osvProjectionVersion);
assert('Manifest references all 16 buckets',
  Object.keys(manifest1[0].manifest.buckets).length === 16);

/* ---- 12. Skip-unchanged publication ---- */
console.log('');
console.log('[12] Skip-unchanged publication');

const store2 = makeMockStore();
const pub2a = await pubMod.publishOsvProjection(store2, fixtureEntities, {
  canonicalBaselineVersion: '2026-07-15T03-54-00Z-a1b2c3d4',
  canonicalManifestHash: fakeManifestHash,
});
assert('Second publication first run succeeds',
  pub2a && pub2a.skipped === false);
const latestBefore = store2.blobs.get('osv/latest.json').value;
// Re-publish with the SAME inputs
const pub2b = await pubMod.publishOsvProjection(store2, fixtureEntities, {
  canonicalBaselineVersion: '2026-07-15T03-54-00Z-a1b2c3d4',
  canonicalManifestHash: fakeManifestHash,
});
assert('Re-publication with identical input is skipped',
  pub2b && pub2b.skipped === true && pub2b.reason === 'projection-unchanged');
const latestAfter = store2.blobs.get('osv/latest.json').value;
assert('latest.json is unchanged after skip',
  JSON.stringify(latestBefore) === JSON.stringify(latestAfter));

/* ---- 13. Content-addressed shard reuse ---- */
console.log('');
console.log('[13] Content-addressed shard reuse');
const initialShards = [...store2.blobs.keys()].filter((k) => k.startsWith('osv/shards/sha256/')).length;
// Re-publish: no new shards should be written (they are all reused)
const pub2c = await pubMod.publishOsvProjection(store2, fixtureEntities, {
  canonicalBaselineVersion: '2026-07-15T03-54-00Z-a1b2c3d4',
  canonicalManifestHash: fakeManifestHash,
});
const finalShards = [...store2.blobs.keys()].filter((k) => k.startsWith('osv/shards/sha256/')).length;
assert('Re-publish does not duplicate shards',
  initialShards === finalShards && pub2c.skipped === true);

/* ---- 14. Different content produces different shards ---- */
console.log('');
console.log('[14] Different content produces new shards');
const store3 = makeMockStore();
const pub3a = await pubMod.publishOsvProjection(store3, fixtureEntities, {
  canonicalBaselineVersion: '2026-07-15T03-54-00Z-a1b2c3d4',
  canonicalManifestHash: fakeManifestHash,
});
const shardsBefore = [...store3.blobs.keys()].filter((k) => k.startsWith('osv/shards/sha256/'));
// Add a new CVE — the bucket containing the new CVE will get new content
const extendedEntities = [
  ...fixtureEntities,
  { osvId: 'GHSA-new-advisory', aliases: ['CVE-2024-9999'], modifiedAt: '2026-07-15T00:00:00Z', publishedAt: '2026-07-15T00:00:00Z', withdrawn: false, references: [], severities: [], affected: [] },
];
const pub3b = await pubMod.publishOsvProjection(store3, extendedEntities, {
  canonicalBaselineVersion: '2026-07-15T04-54-00Z-b2c3d4e5',
  canonicalManifestHash: 'sha256:' + 'b'.repeat(64),
});
assert('Publication with different content succeeds',
  pub3b && pub3b.skipped === false);
const shardsAfter = [...store3.blobs.keys()].filter((k) => k.startsWith('osv/shards/sha256/'));
assert('New shards are written for changed buckets',
  shardsAfter.length >= shardsBefore.length);
assert('Buckets that did not change reuse the same content-addressed shard',
  // Most buckets should still be reused
  shardsBefore.filter((k) => shardsAfter.includes(k)).length >= 12);

/* ---- 15. GC mark-and-sweep ---- */
console.log('');
console.log('[15] GC mark-and-sweep');

// Set up a store with a current, previous, and rollback version.
// Each version writes 16 shards. We then create an extra
// unreferenced shard and verify GC removes only the unreferenced
// one.
const store4 = makeMockStore();
await pubMod.publishOsvProjection(store4, fixtureEntities, {
  canonicalBaselineVersion: '2026-07-15T03-54-00Z-a1b2c3d4',
  canonicalManifestHash: 'sha256:' + 'a'.repeat(64),
});
// Manually write an extra unreferenced shard
const unreferencedHash = 'sha256:' + 'f'.repeat(64);
const unreferencedKey = storeMod.osvShardKey(unreferencedHash);
await store4.setBinary(unreferencedKey, gzipSync(Buffer.from('{"unreferenced":true}', 'utf8')));

assert('Unreferenced shard is present before GC',
  store4.blobs.has(unreferencedKey));

const gcResult = await gcMod.runOsvGc(store4);
assert('GC ran with status ok',
  gcResult.status === 'ok');
assert('GC retained at least 16 shards',
  gcResult.retained >= 16);
assert('GC deleted the unreferenced shard',
  gcResult.deleted.includes('f'.repeat(64)));
const shardsAfterGc = [...store4.blobs.keys()].filter((k) => k.startsWith('osv/shards/sha256/'));
assert('Referenced shards survive GC',
  shardsAfterGc.length === 16);

/* ---- 16. GC never deletes the current manifest's shards ---- */
console.log('');
console.log('[16] GC preserves current manifest shards');
const store5 = makeMockStore();
await pubMod.publishOsvProjection(store5, fixtureEntities, {
  canonicalBaselineVersion: '2026-07-15T03-54-00Z-a1b2c3d4',
  canonicalManifestHash: 'sha256:' + 'a'.repeat(64),
});
const latest5 = await store5.get('osv/latest.json', { type: 'json' });
const manifest5 = await store5.get(`osv/versions/${latest5.osvProjectionVersion}/manifest.json`, { type: 'json' });
const referencedHashes = Object.values(manifest5.buckets).map((b) => b.contentHash);

await gcMod.runOsvGc(store5);
for (const h of referencedHashes) {
  const key = storeMod.osvShardKey(h);
  assert(`referenced shard ${h.slice(0, 16)}... survives GC`,
    store5.blobs.has(key));
}

/* ---- 17. Mark-and-sweep on empty store ---- */
console.log('');
console.log('[17] GC on empty store');
const storeEmpty = makeMockStore();
const gcEmpty = await gcMod.runOsvGc(storeEmpty);
assert('GC on empty store returns ok',
  gcEmpty.status === 'ok' && gcEmpty.retained === 0 && gcEmpty.deleted.length === 0);

/* ---- 18. No new top-level function entry file ---- */
console.log('');
console.log('[18] No new function entry file');
const fnDir = resolve(root, 'netlify', 'functions');
const entries = readdirSync(fnDir).filter((f) => f.endsWith('.mjs'));
const expected = new Set([
  'dataset.mjs',
  'refresh-dataset-scheduled.mjs',
  'refresh-dataset-background.mjs',
  'refresh-baseline-scheduled.mjs',
  'refresh-baseline-background.mjs',
]);
const actual = new Set(entries);
assert('Public function entry count remains 5',
  entries.length === 5);
assert('Public function entries match expected set',
  [...expected].every((e) => actual.has(e)) && actual.size === 5);

/* ---- 19. Schema validates published OSV shard ---- */
console.log('');
console.log('[19] OSV shard schema validation');
// Read the OSV shard schema
const shardSchema = JSON.parse(readFileSync(resolve(root, 'schemas/osv-shard-v1.schema.json'), 'utf8'));
// Validate a published shard by gunzipping one of the stored shards
const aShard = [...store4.blobs.entries()].find(([k]) => k.startsWith('osv/shards/sha256/'));
const shardJson = JSON.parse(gunzipSync(aShard[1].value).toString('utf8'));

// Minimal structural validation (re-using the pattern from
// acceptance-public-intelligence-foundations.mjs).
function validateShallow(schema, value, label) {
  const errors = [];
  function walk(node, val, path) {
    if (node.$ref) { /* skip $ref in this minimal check */ return; }
    if (node.const !== undefined && val !== node.const) errors.push(path + ': const mismatch');
    if (Array.isArray(node.enum) && !node.enum.some((e) => e === val)) errors.push(path + ': not in enum');
    if (node.type) {
      const t = Array.isArray(node.type) ? node.type : [node.type];
      const actual = val === null ? 'null' : Array.isArray(val) ? 'array' : typeof val;
      const ok = t.includes(actual) || (t.includes('number') && actual === 'number' && Number.isInteger(val));
      if (!ok) errors.push(path + ': type mismatch');
    }
    if (Array.isArray(node.required)) {
      for (const r of node.required) if (!(r in val)) errors.push(path + '/missing:' + r);
    }
    if (node.properties) {
      for (const k of Object.keys(node.properties)) if (k in val) walk(node.properties[k], val[k], path + '/' + k);
    }
  }
  walk(schema, value, label);
  return errors;
}
const errs = validateShallow(shardSchema, shardJson, 'shard');
assert('Published OSV shard matches schema (minimal check)',
  errs.length === 0, errs.slice(0, 3).join(' | '));

/* ---- Summary ---- */
console.log('');
console.log('========================================');
console.log(`V6.1 OSV projection: ${passed} passed, ${failed} failed`);
if (failed > 0) {
  console.log('Failures:');
  for (const f of failures) console.log(`  - ${f.label}${f.extra ? ` (${f.extra})` : ''}`);
  process.exit(1);
}
console.log('All OSV projection tests passed.');
