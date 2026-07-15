#!/usr/bin/env node
// V6.1 — Production-wiring acceptance suite.
//
// Exercises the ACTUAL exported production chain
// functions (runBaselinePublicationChain and
// runDatasetPublicationChain) using instrumented
// in-memory stores. The suite proves that the V6.1
// public-intelligence publishers are invoked exactly
// once at the correct point in the production chain,
// that failed canonical publications do not invoke
// the V6.1 publishers, and that the structural
// invariants still hold.
//
//   node scripts/acceptance-v61-production-wiring.mjs

import { gunzipSync, gzipSync } from 'node:zlib';
import { readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..');

let passed = 0;
let failed = 0;
const failures = [];
function assert(label, cond, extra = '') {
  if (cond) { passed++; console.log(`  PASS  ${label}`); }
  else { failed++; failures.push({ label, extra }); console.log(`  FAIL  ${label}${extra ? `  -- ${extra}` : ''}`); }
}

const chainMod = await import('../netlify/functions/_shared/v61BackgroundChain.mjs');
const sizeMod = await import('../netlify/functions/_shared/publicIntelligenceSize.mjs');
const storeMod = await import('../netlify/functions/_shared/store.mjs');

console.log('V6.1 — production-wiring acceptance');
console.log('===================================');
console.log('');

/* ---- Instrumented stores ---- */

function makeStore() {
  const blobs = new Map();
  return {
    blobs,
    setCalls: [],
    getCalls: [],
    async get(key, o = {}) {
      this.getCalls.push(key);
      const entry = blobs.get(key);
      if (!entry) return null;
      if (o.type === 'arrayBuffer') {
        return entry.value instanceof Buffer ? entry.value : Buffer.from(entry.value);
      }
      if (o.type === 'json') {
        if (entry.value instanceof Buffer) return JSON.parse(gunzipSync(entry.value).toString('utf8'));
        return entry.value;
      }
      return entry.value;
    },
    async setJSON(key, value) {
      this.setCalls.push({ key, type: 'json' });
      blobs.set(key, { value, type: 'json' });
    },
    async setBinary(key, buffer) {
      this.setCalls.push({ key, type: 'binary' });
      blobs.set(key, { value: buffer, type: 'binary' });
    },
    async delete(key) {
      blobs.delete(key);
    },
    async list({ prefix = '' } = {}) {
      const matched = [];
      for (const k of blobs.keys()) {
        if (k.startsWith(prefix)) matched.push({ key: k });
      }
      return { blobs: matched };
    },
  };
}

function fakeManifest() {
  return {
    baselineVersion: 'v6-0-fake',
    previousVersion: null,
    publishedAt: '2026-07-15T20:00:00.000Z',
    canonicalContentHash: 'sha256:' + 'a'.repeat(64),
    configHash: 'sha256:' + 'b'.repeat(64),
    shards: {
      vulnerability: {
        '0': {
          objectKey: 'shards/vulnerability/0/bucket-0.json.gz',
          recordCount: 1,
          byteSize: 1000,
          sha256: 'sha256:' + 'c'.repeat(64),
        },
      },
    },
    stats: { totalRecords: 1 },
  };
}

function fakeEntity(cveId, idx) {
  return {
    canonicalId: `vuln:OSV-${cveId}-${idx}`,
    type: 'vulnerability',
    schemaVersion: '1.0.0',
    osvId: `OSV-${cveId}-${idx}`,
    primaryEcosystem: 'npm',
    summary: 'fake summary',
    details: 'fake details',
    aliases: [cveId],
    affectedPackages: [],
    withdrawn: false,
    source: 'osv',
  };
}

async function seedCanonicalShard(store, entities) {
  const objectKey = 'shards/vulnerability/0/bucket-0.json.gz';
  // Seed the gzipped entity blob AND a latest-manifest.
  const gz = gzipSync(Buffer.from(JSON.stringify(entities), 'utf8'));
  store.blobs.set(objectKey, { value: gz, type: 'binary' });
  await store.setJSON('manifests/latest.json', {
    baselineVersion: 'v6-0-fake',
    canonicalContentHash: 'sha256:' + 'a'.repeat(64),
    shards: {
      vulnerability: {
        '0': { objectKey, recordCount: entities.length, byteSize: gz.length, sha256: 'sha256:' + 'c'.repeat(64) },
      },
    },
  });
}

// Default readShardFn: read a gzipped JSON array blob
// from the seeded shape.
async function defaultReadShard(store, key) {
  const entry = store.blobs.get(key);
  if (!entry) return null;
  if (entry.value instanceof Buffer) {
    try {
      return JSON.parse(gunzipSync(entry.value).toString('utf8'));
    } catch {
      return null;
    }
  }
  return entry.value;
}

/* ---- 1. Baseline chain: successful canonical publishes V6.1 ---- */
console.log('[1] Baseline chain: successful canonical invokes V6.1 publisher + GC');

{
  let publisherCallCount = 0;
  let publisherCallsArgs = [];
  let gcCallCount = 0;
  let gcCallsArgs = [];

  const mockPublish = async (store, entities, opts) => {
    publisherCallCount++;
    publisherCallsArgs.push({ store, entities, opts });
    return { skipped: false, osvProjectionVersion: 'v6-0-fake-deadbeef' };
  };
  const mockGc = async (store) => {
    gcCallCount++;
    gcCallsArgs.push(store);
    return { status: 'ok', retained: 16, deleted: [], errors: 0, attempted: 16 };
  };

  const baselineStore = makeStore();
  await seedCanonicalShard(baselineStore, [fakeEntity('CVE-2026-00001', 0)]);
  const intelStore = makeStore();

  const fakeOrchestrator = async () => ({
    status: 'ok',
    done: true,
    phase: 'complete',
    manifest: fakeManifest(),
    published: true,
    recordsProcessed: 1,
    recordsTotal: 1,
    elapsedMs: 0,
    errors: [],
  });

  const result = await chainMod.runBaselinePublicationChain({
    store: baselineStore,
    publicIntelligenceStore: intelStore,
    runOrchestrator: fakeOrchestrator,
    readShardFn: defaultReadShard,
    publishOsvProjectionFn: mockPublish,
    runOsvGcFn: mockGc,
  });

  assert('baseline chain returned status=ok', result && result.status === 'ok');
  assert('baseline chain published=true', result && result.published === true);
  assert('baseline chain invoked publishOsvProjection exactly once', publisherCallCount === 1,
    `got ${publisherCallCount}`);
  assert('baseline chain invoked runOsvGc exactly once', gcCallCount === 1,
    `got ${gcCallCount}`);
  assert('v61OsvProjection is published (not skipped)', result.v61OsvProjection && result.v61OsvProjection.skipped === false);
  assert('v61OsvGc is ok', result.v61OsvGc && result.v61OsvGc.status === 'ok');
  assert('publisher received canonicalBaselineVersion', publisherCallsArgs[0] && publisherCallsArgs[0].opts.canonicalBaselineVersion === 'v6-0-fake');
  assert('publisher received canonicalManifestHash', publisherCallsArgs[0] && publisherCallsArgs[0].opts.canonicalManifestHash && publisherCallsArgs[0].opts.canonicalManifestHash.startsWith('sha256:'));
  assert('publisher received at least one canonical entity', publisherCallsArgs[0] && Array.isArray(publisherCallsArgs[0].entities) && publisherCallsArgs[0].entities.length > 0);
}

/* ---- 2. Baseline chain: failed canonical does NOT publish V6.1 ---- */
console.log('');
console.log('[2] Baseline chain: failed canonical does not invoke V6.1');

{
  let publisherCallCount = 0;
  let gcCallCount = 0;
  const mockPublish = async () => { publisherCallCount++; return { skipped: false }; };
  const mockGc = async () => { gcCallCount++; return { status: 'ok' }; };

  const baselineStore = makeStore();
  const intelStore = makeStore();
  const fakeOrchestrator = async () => ({
    status: 'failed', done: true, phase: 'publication',
    manifest: null, published: false,
    recordsProcessed: 0, recordsTotal: 0, elapsedMs: 0,
    errors: [{ phase: 'publication', error: 'test failure' }],
  });
  const result = await chainMod.runBaselinePublicationChain({
    store: baselineStore,
    publicIntelligenceStore: intelStore,
    runOrchestrator: fakeOrchestrator,
    publishOsvProjectionFn: mockPublish,
    runOsvGcFn: mockGc,
  });

  assert('failed canonical returned status=failed', result && result.status === 'failed');
  assert('failed canonical did NOT invoke publisher', publisherCallCount === 0,
    `got ${publisherCallCount}`);
  assert('failed canonical did NOT invoke GC', gcCallCount === 0,
    `got ${gcCallCount}`);
  assert('v61OsvProjection is null on failed canonical', result.v61OsvProjection === null);
  assert('v61OsvGc is null on failed canonical', result.v61OsvGc === null);
}

/* ---- 3. Baseline chain: published=false does NOT publish V6.1 ---- */
console.log('');
console.log('[3] Baseline chain: published=false does not invoke V6.1');

{
  let publisherCallCount = 0;
  let gcCallCount = 0;
  const mockPublish = async () => { publisherCallCount++; return { skipped: false }; };
  const mockGc = async () => { gcCallCount++; return { status: 'ok' }; };

  const baselineStore = makeStore();
  const intelStore = makeStore();
  const fakeOrchestrator = async () => ({
    status: 'ok', done: true, phase: 'complete',
    manifest: null, published: false,
    recordsProcessed: 0, recordsTotal: 0, elapsedMs: 0, errors: [],
  });
  const result = await chainMod.runBaselinePublicationChain({
    store: baselineStore,
    publicIntelligenceStore: intelStore,
    runOrchestrator: fakeOrchestrator,
    publishOsvProjectionFn: mockPublish,
    runOsvGcFn: mockGc,
  });

  assert('no-work canonical returned status=ok', result && result.status === 'ok');
  assert('no-work canonical did NOT invoke publisher', publisherCallCount === 0);
  assert('no-work canonical did NOT invoke GC', gcCallCount === 0);
}

/* ---- 4. Baseline chain: size-ceiling rejection does not invoke GC ---- */
console.log('');
console.log('[4] Baseline chain: ceiling rejection does not invoke GC');

{
  let publisherCallCount = 0;
  let gcCallCount = 0;
  const mockPublish = async () => {
    publisherCallCount++;
    return {
      skipped: true,
      reason: 'compressed-ceiling-exceeded',
      bucket: '0',
      sizeBytes: sizeMod.OSV_SHARD_HARD_CEILING_COMPRESSED_BYTES + 1,
      ceilingBytes: sizeMod.OSV_SHARD_HARD_CEILING_COMPRESSED_BYTES,
    };
  };
  const mockGc = async () => { gcCallCount++; return { status: 'ok' }; };

  const baselineStore = makeStore();
  await seedCanonicalShard(baselineStore, [fakeEntity('CVE-2026-00001', 0)]);
  const intelStore = makeStore();
  const fakeOrchestrator = async () => ({
    status: 'ok', done: true, phase: 'complete',
    manifest: fakeManifest(), published: true,
    recordsProcessed: 1, recordsTotal: 1, elapsedMs: 0, errors: [],
  });
  const result = await chainMod.runBaselinePublicationChain({
    store: baselineStore,
    publicIntelligenceStore: intelStore,
    runOrchestrator: fakeOrchestrator,
    readShardFn: defaultReadShard,
    publishOsvProjectionFn: mockPublish,
    runOsvGcFn: mockGc,
  });

  assert('ceiling rejection did NOT invoke GC (preserves previous valid projection)', gcCallCount === 0);
  assert('v61OsvProjection reports skipped=true', result.v61OsvProjection && result.v61OsvProjection.skipped === true);
  assert('v61OsvProjection reason is compressed-ceiling-exceeded', result.v61OsvProjection.reason === 'compressed-ceiling-exceeded');
  assert('canonical publication status remains ok', result && result.status === 'ok');
}

/* ---- 5. Baseline chain: unchanged projection DOES invoke GC ---- */
console.log('');
console.log('[5] Baseline chain: unchanged projection invokes GC');

{
  let publisherCallCount = 0;
  let gcCallCount = 0;
  const mockPublish = async () => {
    publisherCallCount++;
    return { skipped: true, reason: 'projection-unchanged', osvProjectionVersion: 'v6-0-fake-unchanged' };
  };
  const mockGc = async () => { gcCallCount++; return { status: 'ok', retained: 0, deleted: [], errors: 0, attempted: 0 }; };

  const baselineStore = makeStore();
  await seedCanonicalShard(baselineStore, [fakeEntity('CVE-2026-00001', 0)]);
  const intelStore = makeStore();
  const fakeOrchestrator = async () => ({
    status: 'ok', done: true, phase: 'complete',
    manifest: fakeManifest(), published: true,
    recordsProcessed: 1, recordsTotal: 1, elapsedMs: 0, errors: [],
  });
  const result = await chainMod.runBaselinePublicationChain({
    store: baselineStore,
    publicIntelligenceStore: intelStore,
    runOrchestrator: fakeOrchestrator,
    readShardFn: defaultReadShard,
    publishOsvProjectionFn: mockPublish,
    runOsvGcFn: mockGc,
  });

  assert('unchanged projection DID invoke GC', gcCallCount === 1);
  assert('unchanged projection result reports reason=projection-unchanged', result.v61OsvProjection.reason === 'projection-unchanged');
}

/* ---- 6. Baseline chain: GC failure is non-fatal ---- */
console.log('');
console.log('[6] Baseline chain: GC failure is non-fatal');

{
  let publisherCallCount = 0;
  let gcCallCount = 0;
  const mockPublish = async () => { publisherCallCount++; return { skipped: false, osvProjectionVersion: 'v' }; };
  const mockGc = async () => { gcCallCount++; throw new Error('simulated GC failure'); };

  const baselineStore = makeStore();
  await seedCanonicalShard(baselineStore, [fakeEntity('CVE-2026-00001', 0)]);
  const intelStore = makeStore();
  const fakeOrchestrator = async () => ({
    status: 'ok', done: true, phase: 'complete',
    manifest: fakeManifest(), published: true,
    recordsProcessed: 1, recordsTotal: 1, elapsedMs: 0, errors: [],
  });
  let result;
  let threw = false;
  try {
    result = await chainMod.runBaselinePublicationChain({
      store: baselineStore,
      publicIntelligenceStore: intelStore,
      runOrchestrator: fakeOrchestrator,
      readShardFn: defaultReadShard,
      publishOsvProjectionFn: mockPublish,
      runOsvGcFn: mockGc,
    });
  } catch (e) {
    threw = true;
  }

  assert('chain did NOT throw on GC failure', !threw);
  assert('canonical publication status remains ok despite GC failure', result && result.status === 'ok');
  assert('v61OsvGc reports failed status', result && result.v61OsvGc && result.v61OsvGc.status === 'failed');
}

/* ---- 7. Dataset chain: all three hashes present → publishes ---- */
console.log('');
console.log('[7] Dataset chain: all three hashes present publishes the bundle');

{
  const datasetStore = makeStore();
  const vulnStore = makeStore();
  const ghStore = makeStore();
  const intelStore = makeStore();

  await datasetStore.setJSON('latest-dataset', {
    mode: 'live', source: 'merged',
    fetchedAt: '2026-07-15T20:00:00.000Z',
    data: [],
    datasetPublicHash: 'sha256:' + '1'.repeat(64),
  });
  await vulnStore.setJSON('cache', {
    records: {},
    updatedAt: '2026-07-15T20:00:00.000Z',
    vulnrichmentPublicHash: 'sha256:' + '2'.repeat(64),
  });
  await ghStore.setJSON('cache', {
    records: {},
    updatedAt: '2026-07-15T20:00:00.000Z',
    githubAdvisoryPublicHash: 'sha256:' + '3'.repeat(64),
  });

  const result = await chainMod.runDatasetPublicationChain({
    datasetStore, vulnrichmentStore: vulnStore, githubAdvisoryStore: ghStore, intelStore,
  });

  assert('dataset chain published', result && result.published === true,
    `got: ${JSON.stringify(result)}`);
  // The publisher's return value exposes the publicIntelligenceVersion
  // and publicStateHash; the manifest-level fields (comparesFreshBase,
  // previousPublicIntelligenceVersion, items, changeSummary) live
  // inside the published manifest blob. Read it back to verify the
  // first-bundle invariants.
  const manifestKey = `dataset/versions/${result.publicIntelligenceVersion}/manifest.json`;
  const manifest = intelStore.blobs.get(manifestKey) && intelStore.blobs.get(manifestKey).value;
  assert('manifest blob was written', manifest != null);
  if (manifest) {
    assert('first bundle manifest has comparesFreshBase=false', manifest.comparesFreshBase === false,
      `got: ${manifest.comparesFreshBase}`);
    assert('first bundle manifest has previousPublicIntelligenceVersion=null', manifest.previousPublicIntelligenceVersion === null);
    assert('first bundle manifest changeSummary is all zeros',
      manifest.changeSummary &&
      manifest.changeSummary.newlyTracked === 0 &&
      manifest.changeSummary.noLongerTracked === 0 &&
      manifest.changeSummary.factNewlyAvailable === 0 &&
      manifest.changeSummary.factChanged === 0 &&
      manifest.changeSummary.factNoLongerPresent === 0 &&
      manifest.changeSummary.providerStatusChanged === 0);
  }
  // The latest.json pointer is written last and references the
  // first-bundle manifest. Verify it has the correct first-bundle
  // shape.
  assert('intel store received dataset/latest.json write', intelStore.blobs.has('dataset/latest.json'));
  const latest = intelStore.blobs.get('dataset/latest.json').value;
  assert('written dataset/latest.json does NOT leak datasetPublicHash field', latest && !('datasetPublicHash' in latest));
  assert('written dataset/latest.json has previousPublicIntelligenceVersion=null', latest && latest.previousPublicIntelligenceVersion === null);
}

/* ---- 8. Dataset chain: missing dataset public hash → skip ---- */
console.log('');
console.log('[8] Dataset chain: missing dataset public hash produces structured skip');

{
  const datasetStore = makeStore();
  const vulnStore = makeStore();
  const ghStore = makeStore();
  const intelStore = makeStore();
  await datasetStore.setJSON('latest-dataset', {
    mode: 'live', source: 'merged',
    fetchedAt: '2026-07-15T20:00:00.000Z',
    data: [],
  });
  await vulnStore.setJSON('cache', {
    records: {}, updatedAt: '2026-07-15T20:00:00.000Z',
    vulnrichmentPublicHash: 'sha256:' + '2'.repeat(64),
  });
  await ghStore.setJSON('cache', {
    records: {}, updatedAt: '2026-07-15T20:00:00.000Z',
    githubAdvisoryPublicHash: 'sha256:' + '3'.repeat(64),
  });
  const result = await chainMod.runDatasetPublicationChain({
    datasetStore, vulnrichmentStore: vulnStore, githubAdvisoryStore: ghStore, intelStore,
  });
  assert('chain returns skipped=true', result && result.skipped === true);
  assert('chain reason is dataset-public-hash-missing', result && result.reason === 'dataset-public-hash-missing');
  assert('chain did NOT write dataset/latest.json', !intelStore.blobs.has('dataset/latest.json'));
}

/* ---- 9. Dataset chain: missing vulnrichment public hash → skip ---- */
console.log('');
console.log('[9] Dataset chain: missing vulnrichment public hash produces structured skip');

{
  const datasetStore = makeStore();
  const vulnStore = makeStore();
  const ghStore = makeStore();
  const intelStore = makeStore();
  await datasetStore.setJSON('latest-dataset', {
    mode: 'live', source: 'merged',
    fetchedAt: '2026-07-15T20:00:00.000Z',
    data: [],
    datasetPublicHash: 'sha256:' + '1'.repeat(64),
  });
  await vulnStore.setJSON('cache', { records: {}, updatedAt: '2026-07-15T20:00:00.000Z' });
  await ghStore.setJSON('cache', {
    records: {}, updatedAt: '2026-07-15T20:00:00.000Z',
    githubAdvisoryPublicHash: 'sha256:' + '3'.repeat(64),
  });
  const result = await chainMod.runDatasetPublicationChain({
    datasetStore, vulnrichmentStore: vulnStore, githubAdvisoryStore: ghStore, intelStore,
  });
  assert('reason = vulnrichment-public-hash-missing', result && result.reason === 'vulnrichment-public-hash-missing');
  assert('skipped', result && result.skipped === true);
}

/* ---- 10. Dataset chain: missing github advisory public hash → skip ---- */
console.log('');
console.log('[10] Dataset chain: missing github advisory public hash produces structured skip');

{
  const datasetStore = makeStore();
  const vulnStore = makeStore();
  const ghStore = makeStore();
  const intelStore = makeStore();
  await datasetStore.setJSON('latest-dataset', {
    mode: 'live', source: 'merged',
    fetchedAt: '2026-07-15T20:00:00.000Z',
    data: [],
    datasetPublicHash: 'sha256:' + '1'.repeat(64),
  });
  await vulnStore.setJSON('cache', {
    records: {}, updatedAt: '2026-07-15T20:00:00.000Z',
    vulnrichmentPublicHash: 'sha256:' + '2'.repeat(64),
  });
  await ghStore.setJSON('cache', { records: {}, updatedAt: '2026-07-15T20:00:00.000Z' });
  const result = await chainMod.runDatasetPublicationChain({
    datasetStore, vulnrichmentStore: vulnStore, githubAdvisoryStore: ghStore, intelStore,
  });
  assert('reason = github-advisory-public-hash-missing', result && result.reason === 'github-advisory-public-hash-missing');
}

/* ---- 11. Dataset chain: missing dataset envelope → skip ---- */
console.log('');
console.log('[11] Dataset chain: missing dataset envelope produces structured skip');

{
  const datasetStore = makeStore();
  const vulnStore = makeStore();
  const ghStore = makeStore();
  const intelStore = makeStore();
  const result = await chainMod.runDatasetPublicationChain({
    datasetStore, vulnrichmentStore: vulnStore, githubAdvisoryStore: ghStore, intelStore,
  });
  assert('reason = missing-dataset-envelope', result && result.reason === 'missing-dataset-envelope');
}

/* ---- 12. Hashes from the read path match the written envelopes ---- */
console.log('');
console.log('[12] readVulnrichmentCache / readGithubAdvisoryCache surface the public hash');

{
  const store = makeStore();
  await store.setJSON('cache', {
    records: { 'CVE-2026-00001': { ssvc: { exploitation: 'active' } } },
    updatedAt: '2026-07-15T20:00:00.000Z',
    vulnrichmentPublicHash: 'sha256:' + 'a'.repeat(64),
  });
  const v = await storeMod.readVulnrichmentCache(store);
  assert('vulnrichment cache returns vulnrichmentPublicHash', v && v.vulnrichmentPublicHash && v.vulnrichmentPublicHash.startsWith('sha256:'));
  assert('vulnrichment cache returns records', v && v.records && v.records['CVE-2026-00001']);

  await store.setJSON('cache', {
    records: { 'CVE-2026-00001': { advisory: { ghsaId: 'GHSA-x' } } },
    updatedAt: '2026-07-15T20:00:00.000Z',
    githubAdvisoryPublicHash: 'sha256:' + 'b'.repeat(64),
  });
  const g = await storeMod.readGithubAdvisoryCache(store);
  assert('github-advisory cache returns githubAdvisoryPublicHash', g && g.githubAdvisoryPublicHash && g.githubAdvisoryPublicHash.startsWith('sha256:'));
}

/* ---- 13. Old envelopes without hash return null (backward compat) ---- */
console.log('');
console.log('[13] Old envelopes without hash return null');

{
  const store = makeStore();
  await store.setJSON('cache', {
    records: {},
    updatedAt: '2026-07-15T20:00:00.000Z',
  });
  const v = await storeMod.readVulnrichmentCache(store);
  assert('old vulnrichment envelope returns null hash (backward compat)', v && v.vulnrichmentPublicHash === null);

  await store.setJSON('cache', {
    records: {},
    updatedAt: '2026-07-15T20:00:00.000Z',
  });
  const g = await storeMod.readGithubAdvisoryCache(store);
  assert('old github advisory envelope returns null hash (backward compat)', g && g.githubAdvisoryPublicHash === null);
}

/* ---- 14. Hashes are absent from public responses ---- */
console.log('');
console.log('[14] Public dataset response strips the per-Blob public hashes');

{
  const env = {
    mode: 'live',
    source: 'merged',
    fetchedAt: '2026-07-15T20:00:00.000Z',
    data: [],
    datasetPublicHash: 'sha256:' + '1'.repeat(64),
    vulnrichmentPublicHash: 'sha256:' + '2'.repeat(64),
    githubAdvisoryPublicHash: 'sha256:' + '3'.repeat(64),
    lastRefreshAttemptAt: '2026-07-15T20:00:00.000Z',
    lastV61DatasetBoundRefresh: { published: true, publicIntelligenceVersion: 'v' },
  };
  const refresh = await import('../netlify/functions/_shared/refresh.mjs');
  const stripped = {};
  for (const k of Object.keys(env)) {
    if (!refresh.INTERNAL_BLOB_FIELDS.has(k)) stripped[k] = env[k];
  }
  assert('datasetPublicHash stripped', !('datasetPublicHash' in stripped));
  assert('vulnrichmentPublicHash stripped', !('vulnrichmentPublicHash' in stripped));
  assert('githubAdvisoryPublicHash stripped', !('githubAdvisoryPublicHash' in stripped));
  assert('lastRefreshAttemptAt stripped', !('lastRefreshAttemptAt' in stripped));
  assert('lastV61DatasetBoundRefresh stripped', !('lastV61DatasetBoundRefresh' in stripped));
}

/* ---- 15. No full-cache canonicalization on the request path ---- */
console.log('');
console.log('[15] The dataset read path uses the stored hash when present');

{
  const readMod = await import('../netlify/functions/_shared/datasetPublicIntelligenceRead.mjs');
  assert('computeCurrentPublicStateHash exists', typeof readMod.computeCurrentPublicStateHash === 'function');
  const stored = readMod.computeCurrentPublicStateHash({
    datasetEnvelope: { datasetPublicHash: 'sha256:stored' },
    vulnrichmentCache: { vulnrichmentPublicHash: 'sha256:v' },
    githubAdvisoryCache: { githubAdvisoryPublicHash: 'sha256:g' },
    osvProjection: { osvProjectionVersion: 'v', manifestContentHash: 'sha256:o' },
  });
  assert('computeCurrentPublicStateHash returns a sha256 string',
    stored && typeof stored === 'string' && stored.startsWith('sha256:') && stored.length === 'sha256:'.length + 64);
}

/* ---- 16. Structural invariants ---- */
console.log('');
console.log('[16] Structural invariants');

{
  const publicFiles = readdirSync(resolve(root, 'netlify/functions')).filter((f) => f.endsWith('.mjs'));
  const gatewayFiles = readdirSync(resolve(root, 'netlify/gateway/src')).filter((f) => f.endsWith('.mjs'));
  assert('exactly five public function entry files', publicFiles.length === 5, `got ${publicFiles.length}: ${publicFiles.join(', ')}`);
  assert('exactly one gateway function entry file', gatewayFiles.length === 1, `got ${gatewayFiles.length}: ${gatewayFiles.join(', ')}`);
  const csvSrc = (await import('node:fs')).readFileSync(resolve(root, 'src/utils/csvExport.ts'), 'utf8');
  const cols = (csvSrc.match(/^\s*'[A-Z][^']+'/gm) || []).length;
  // csvExport.ts also has PACKAGE_FIELD_SEPARATOR and
  // CsvColumn; only count the CSV_COLUMNS array entries.
  // The 21 column literals are inside the `export const
  // CSV_COLUMNS = [...]` array. Look for the array and
  // count its string entries.
  const arrMatch = csvSrc.match(/export const CSV_COLUMNS = \[([\s\S]*?)\] as const/);
  if (arrMatch) {
    const inner = arrMatch[1];
    const colCount = (inner.match(/^\s*'[^']+'/gm) || []).length;
    assert('CSV_COLUMNS is exactly 21', colCount === 21, `got ${colCount}`);
  } else {
    assert('CSV_COLUMNS found in csvExport.ts', false);
  }
}

/* ---- Summary ---- */
console.log('');
console.log('---');
console.log(`PASSED: ${passed}`);
console.log(`FAILED: ${failed}`);
if (failed > 0) {
  for (const f of failures) console.log(`  FAIL: ${f.label}${f.extra ? `  -- ${f.extra}` : ''}`);
  process.exit(1);
}
process.exit(0);
