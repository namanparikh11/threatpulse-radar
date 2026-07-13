// V6.0 — Consumer client behavior tests.
//
//   node scripts/acceptance-consumer-client.mjs
//
// Behavior under test:
//   - verifyManifest: valid/tampered/missing-hash/empty
//   - FsBaselineStore: writeManifest, readManifest, readVersionManifest
//   - FsBaselineStore: writeShard, readShard, hasShard
//   - FsBaselineStore: writeDelta, readDelta
//   - FsBaselineStore: getCurrentVersion
//   - FsBaselineStore: clear
//   - FsBaselineStore: listLocalShards
//   - FsBaselineStore: rejects missing rootDir
//   - ConsumerClient: requires gatewayUrl, credential, store
//   - ConsumerClient.sync: fetches manifest, writes it, fetches
//     missing shards, reuses existing ones
//   - ConsumerClient.sync: skips shard fetch when skipShardFetch
//   - ConsumerClient.sync: rejects on manifest hash mismatch
//   - ConsumerClient.syncDelta: fetches delta, writes it
//   - ConsumerClient.syncDelta: rejects on targetManifestHash mismatch
//   - ConsumerClient.snapshot: decodes base64 shards, writes them
//   - ConsumerClient.snapshot: rejects on manifest hash mismatch
//   - V6.0 invariant: the credential is never written to disk by
//     the consumer (the store only sees opaque keys)

import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync, rmSync, mkdtempSync, readdirSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join, sep } from 'node:path';
import { tmpdir } from 'node:os';
import { gzipSync, gunzipSync } from 'node:zlib';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const buildDir = join(here, '.v6-build-consumer');

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
/* Build the canonicalHash + contentAddressedShards for the test        */
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
    'netlify/functions/_shared/baselineStore.mjs',
    'netlify/functions/_shared/baselinePublish.mjs',
  ];
  execFileSync(
    process.execPath,
    [tscJs, ...sources, '--outDir', buildDir.replace(/\\/g, '/'), '--rootDir', '.',
     '--module', 'esnext', '--target', 'es2022', '--moduleResolution', 'node',
     '--skipLibCheck', '--allowJs', '--declaration', 'false'],
    { cwd: root, stdio: 'pipe' }
  );
}

buildV6Sources();
const buildLeaf = buildDir.split(/[\\/]/).pop();

// Import the consumer client (pure ESM, no build needed)
const consumerMod = await import(pathToFileURL(join(root, 'client', 'consumer-client.mjs')).href);
const { ConsumerClient, FsBaselineStore, verifyManifest } = consumerMod;

// Import the buildVersionManifest helper to make a valid manifest
const { buildVersionManifest } = await import(`./${buildLeaf}/netlify/functions/_shared/baselinePublish.mjs`);
const { contentHash, deriveBaselineVersion } = await import(`./${buildLeaf}/netlify/functions/_shared/canonicalHash.mjs`);

/* ------------------------------------------------------------------ */
/* Test helpers                                                         */
/* ------------------------------------------------------------------ */

function makeTmpRoot() {
  return mkdtempSync(join(tmpdir(), 'v6-consumer-test-'));
}

function makeValidManifest({ version = 'v1', shards = {}, previousVersion = null } = {}) {
  const m = buildVersionManifest({
    version,
    previousVersion,
    publishedAt: '2026-07-12T20:30:00.000Z',
    configHash: 'sha256:' + 'a'.repeat(64),
    shards,
    sourceStatus: { osv: { status: 'ok', recordCount: 5, fetchedAt: '2026-07-12T20:30:00.000Z' } },
  });
  return m;
}

function makeValidCredential() {
  // Doesn't need to be a real HMAC credential — the test stub
  // fetcher doesn't validate it. The real gateway does.
  return `tpr_test-key-${'A'.repeat(43)}`;
}

function makeStubFetcher({ manifest = null, deltas = {}, snapshots = {}, shards = {} } = {}) {
  return {
    async fetchJson(url, init = {}) {
      const u = new URL(url);
      if (u.pathname === '/private/v1/manifest' && manifest) return manifest;
      if (u.pathname.startsWith('/private/v1/manifest/') && manifest) {
        const v = decodeURIComponent(u.pathname.split('/').pop());
        if (manifest.baselineVersion === v) return manifest;
        throw new Error(`fetch ${url} → HTTP 404`);
      }
      if (u.pathname === '/private/v1/delta') {
        const from = u.searchParams.get('from');
        const to = u.searchParams.get('to');
        const d = deltas[`${from}__to__${to}`];
        if (d) return d;
        throw new Error(`fetch ${url} → HTTP 404`);
      }
      if (u.pathname === '/private/v1/snapshot') {
        const v = u.searchParams.get('version');
        const s = snapshots[v];
        if (s) return s;
        throw new Error(`fetch ${url} → HTTP 404`);
      }
      if (u.pathname === '/private/v1/sources') return { sources: [] };
      throw new Error(`fetch ${url} → HTTP 404 (unmocked)`);
    },
    async fetchBinary(url, init = {}) {
      const u = new URL(url);
      if (u.pathname === '/private/v1/shard') {
        const key = u.searchParams.get('key');
        if (shards[key]) return shards[key];
        throw new Error(`fetch ${url} → HTTP 404`);
      }
      throw new Error(`fetch ${url} → HTTP 404 (unmocked)`);
    },
    async fetchText(url, init = {}) {
      throw new Error('fetchText not used in tests');
    },
  };
}

/* ------------------------------------------------------------------ */
/* Tests: verifyManifest                                                */
/* ------------------------------------------------------------------ */

section('verifyManifest: valid manifest');

{
  const m = makeValidManifest();
  assert('valid manifest verifies', verifyManifest(m) === true);
}

section('verifyManifest: tampered manifest');

{
  const m = makeValidManifest();
  m.shards = { foo: {} };
  assert('tampered manifest does NOT verify', verifyManifest(m) === false);
}

section('verifyManifest: missing canonicalContentHash');

{
  const m = makeValidManifest();
  delete m.canonicalContentHash;
  assert('missing hash does NOT verify', verifyManifest(m) === false);
}

section('verifyManifest: changing deltaHash does not invalidate');

{
  const m1 = makeValidManifest();
  const m2 = { ...m1, deltaHash: 'sha256:' + 'b'.repeat(64) };
  assert('verifyManifest ignores deltaHash changes', verifyManifest(m2) === true);
}

/* ------------------------------------------------------------------ */
/* Tests: FsBaselineStore                                              */
/* ------------------------------------------------------------------ */

section('FsBaselineStore: writeManifest, readManifest, readVersionManifest');

{
  const root = makeTmpRoot();
  const store = new FsBaselineStore({ rootDir: root });
  const m = makeValidManifest();
  await store.writeManifest(m);
  const read = await store.readManifest();
  assert('readManifest returns the same version', read.baselineVersion === m.baselineVersion);
  assert('readManifest is content-identical', JSON.stringify(read) === JSON.stringify(m));
  const v = await store.readVersionManifest(m.baselineVersion);
  assert('readVersionManifest returns the same manifest', v.baselineVersion === m.baselineVersion);
  const vMissing = await store.readVersionManifest('nonexistent');
  assert('readVersionManifest returns null for unknown', vMissing === null);
  await store.clear();
}

section('FsBaselineStore: writeShard, readShard, hasShard');

{
  const root = makeTmpRoot();
  const store = new FsBaselineStore({ rootDir: root });
  const gz = gzipSync(Buffer.from('["a","b"]', 'utf8'));
  await store.writeShard('objects/sha256/abc.json.gz', gz);
  assert('hasShard returns true after write', await store.hasShard('objects/sha256/abc.json.gz') === true);
  const read = await store.readShard('objects/sha256/abc.json.gz');
  assert('readShard returns the canonical list', JSON.stringify(read) === JSON.stringify(['a', 'b']));
  assert('hasShard returns false for unknown', await store.hasShard('objects/sha256/zzz.json.gz') === false);
  assert('readShard returns null for unknown', await store.readShard('objects/sha256/zzz.json.gz') === null);
  await store.clear();
}

section('FsBaselineStore: writeDelta, readDelta');

{
  const root = makeTmpRoot();
  const store = new FsBaselineStore({ rootDir: root });
  const d = { schemaVersion: '1.0.0', baseVersion: 'v0', targetVersion: 'v1', upserts: [], tombstones: [] };
  await store.writeDelta('v0', 'v1', d);
  const read = await store.readDelta('v0', 'v1');
  assert('readDelta returns the same delta', read.baseVersion === 'v0' && read.targetVersion === 'v1');
  const missing = await store.readDelta('v0', 'v2');
  assert('readDelta returns null for unknown', missing === null);
  await store.clear();
}

section('FsBaselineStore: getCurrentVersion and listLocalShards');

{
  const root = makeTmpRoot();
  const store = new FsBaselineStore({ rootDir: root });
  assert('getCurrentVersion is null when empty', await store.getCurrentVersion() === null);
  await store.writeManifest(makeValidManifest());
  assert('getCurrentVersion reflects the active version', await store.getCurrentVersion() === 'v1');
  assert('listLocalShards is empty when no shards', (await store.listLocalShards()).length === 0);
  await store.writeShard('objects/sha256/aaa.json.gz', gzipSync(Buffer.from('[]', 'utf8')));
  await store.writeShard('objects/sha256/bbb.json.gz', gzipSync(Buffer.from('[]', 'utf8')));
  const list = await store.listLocalShards();
  assert('listLocalShards returns 2 entries', list.length === 2);
  assert('listLocalShards has the right keys', list.includes('objects/sha256/aaa.json.gz') && list.includes('objects/sha256/bbb.json.gz'));
  await store.clear();
}

section('FsBaselineStore: clear removes everything');

{
  const root = makeTmpRoot();
  const store = new FsBaselineStore({ rootDir: root });
  await store.writeManifest(makeValidManifest());
  await store.writeShard('objects/sha256/aaa.json.gz', gzipSync(Buffer.from('[]', 'utf8')));
  await store.clear();
  assert('directory is removed', !existsSync(root));
  assert('readManifest is null after clear', await store.readManifest() === null);
}

section('FsBaselineStore: rejects missing rootDir');

{
  let threw = null;
  try { new FsBaselineStore({}); } catch (e) { threw = e; }
  assert('missing rootDir throws', threw !== null);
  threw = null;
  try { new FsBaselineStore({ rootDir: '' }); } catch (e) { threw = e; }
  assert('empty rootDir throws', threw !== null);
}

/* ------------------------------------------------------------------ */
/* Tests: ConsumerClient construction                                    */
/* ------------------------------------------------------------------ */

section('ConsumerClient: requires gatewayUrl, credential, store');

{
  let threw = null;
  try { new ConsumerClient({}); } catch (e) { threw = e; }
  assert('empty args throws', threw !== null);

  threw = null;
  try { new ConsumerClient({ gatewayUrl: 'https://x', credential: 'foo', store: {} }); } catch (e) { threw = e; }
  assert('bad credential prefix throws', threw !== null);

  const root = makeTmpRoot();
  threw = null;
  try { new ConsumerClient({ gatewayUrl: 'https://x', credential: 'tpr_aaa', store: null }); } catch (e) { threw = e; }
  assert('null store throws', threw !== null);
  await new FsBaselineStore({ rootDir: root }).clear();
}

/* ------------------------------------------------------------------ */
/* Tests: ConsumerClient.sync                                          */
/* ------------------------------------------------------------------ */

section('ConsumerClient.sync: fetches manifest, writes it, fetches missing shards');

{
  const root = makeTmpRoot();
  const store = new FsBaselineStore({ rootDir: root });
  const m = makeValidManifest({
    shards: {
      vulnerability: {
        ab: { objectKey: 'objects/sha256/aaa.json.gz', sha256: 'sha256:' + 'a'.repeat(64), byteSize: 100, recordCount: 5 },
        cd: { objectKey: 'objects/sha256/bbb.json.gz', sha256: 'sha256:' + 'b'.repeat(64), byteSize: 200, recordCount: 10 },
      },
    },
  });
  const fetcher = makeStubFetcher({
    manifest: m,
    shards: {
      'objects/sha256/aaa.json.gz': gzipSync(Buffer.from('[1,2,3]', 'utf8')),
      'objects/sha256/bbb.json.gz': gzipSync(Buffer.from('[4,5,6]', 'utf8')),
    },
  });
  const client = new ConsumerClient({ gatewayUrl: 'https://gw.test', credential: makeValidCredential(), store, fetcher });
  const result = await client.sync();
  assert('sync returns the new version', result.version === 'v1');
  assert('sync reports 2 shards added', result.shardsAdded === 2);
  assert('sync reports 0 shards reused', result.shardsReused === 0);
  assert('manifest is written to local store',
    (await store.readManifest()).baselineVersion === 'v1');
  assert('shard a is local', await store.hasShard('objects/sha256/aaa.json.gz'));
  assert('shard b is local', await store.hasShard('objects/sha256/bbb.json.gz'));
  await store.clear();
}

section('ConsumerClient.sync: reuses existing shards');

{
  const root = makeTmpRoot();
  const store = new FsBaselineStore({ rootDir: root });
  // Pre-populate one shard
  await store.writeShard('objects/sha256/aaa.json.gz', gzipSync(Buffer.from('[1,2,3]', 'utf8')));
  const m = makeValidManifest({
    shards: {
      vulnerability: {
        ab: { objectKey: 'objects/sha256/aaa.json.gz', sha256: 'sha256:' + 'a'.repeat(64), byteSize: 100, recordCount: 5 },
        cd: { objectKey: 'objects/sha256/bbb.json.gz', sha256: 'sha256:' + 'b'.repeat(64), byteSize: 200, recordCount: 10 },
      },
    },
  });
  const fetcher = makeStubFetcher({
    manifest: m,
    shards: {
      // aaa intentionally missing from the fetcher — if sync tries
      // to re-fetch it, the test fails.
      'objects/sha256/bbb.json.gz': gzipSync(Buffer.from('[4,5,6]', 'utf8')),
    },
  });
  const client = new ConsumerClient({ gatewayUrl: 'https://gw.test', credential: makeValidCredential(), store, fetcher });
  const result = await client.sync();
  assert('one shard reused', result.shardsReused === 1);
  assert('one shard added', result.shardsAdded === 1);
  await store.clear();
}

section('ConsumerClient.sync: rejects on manifest hash mismatch');

{
  const root = makeTmpRoot();
  const store = new FsBaselineStore({ rootDir: root });
  const m = makeValidManifest();
  m.canonicalContentHash = 'sha256:' + 'z'.repeat(64); // tamper
  const fetcher = makeStubFetcher({ manifest: m });
  const client = new ConsumerClient({ gatewayUrl: 'https://gw.test', credential: makeValidCredential(), store, fetcher });
  let threw = null;
  try { await client.sync(); } catch (e) { threw = e; }
  assert('tampered manifest throws', threw !== null);
  assert('error message mentions verification', /verification/i.test(threw.message));
  assert('manifest is NOT written to local store', await store.readManifest() === null);
  await store.clear();
}

section('ConsumerClient.sync: skipShardFetch bypasses shard I/O');

{
  const root = makeTmpRoot();
  const store = new FsBaselineStore({ rootDir: root });
  const m = makeValidManifest({
    shards: { vulnerability: { ab: { objectKey: 'objects/sha256/aaa.json.gz', sha256: 'sha256:' + 'a'.repeat(64), byteSize: 100, recordCount: 5 } } },
  });
  const fetcher = makeStubFetcher({ manifest: m });
  const client = new ConsumerClient({ gatewayUrl: 'https://gw.test', credential: makeValidCredential(), store, fetcher, skipShardFetch: true });
  const result = await client.sync();
  assert('manifest is written', (await store.readManifest()).baselineVersion === 'v1');
  assert('shard is NOT written (skipShardFetch=true)', await store.hasShard('objects/sha256/aaa.json.gz') === false);
  await store.clear();
}

/* ------------------------------------------------------------------ */
/* Tests: ConsumerClient.syncDelta                                     */
/* ------------------------------------------------------------------ */

section('ConsumerClient.syncDelta: fetches and writes a valid delta');

{
  const root = makeTmpRoot();
  const store = new FsBaselineStore({ rootDir: root });
  const previousVersion = makeValidManifest({ version: 'v0' });
  const currentVersion = makeValidManifest({ version: 'v1', previousVersion: 'v0' });
  const delta = {
    schemaVersion: '1.0.0',
    baseVersion: 'v0',
    baseManifestHash: previousVersion.canonicalContentHash,
    targetVersion: 'v1',
    targetManifestHash: currentVersion.canonicalContentHash,
    upserts: [{ canonicalId: 'vuln:new', type: 'vulnerability' }],
    tombstones: [],
    generatedAt: '2026-07-12T20:30:00.000Z',
    deltaSha256: 'sha256:' + 'a'.repeat(64),
  };
  const fetcher = makeStubFetcher({
    manifest: currentVersion,
    deltas: { 'v0__to__v1': delta },
  });
  const client = new ConsumerClient({ gatewayUrl: 'https://gw.test', credential: makeValidCredential(), store, fetcher });
  const r = await client.syncDelta({ fromVersion: 'v0' });
  assert('syncDelta returns the right fromVersion', r.fromVersion === 'v0');
  assert('syncDelta returns the right toVersion', r.toVersion === 'v1');
  assert('delta is written to local store', (await store.readDelta('v0', 'v1')) !== null);
  assert('manifest is updated to v1', (await store.readManifest()).baselineVersion === 'v1');
  await store.clear();
}

section('ConsumerClient.syncDelta: rejects on targetManifestHash mismatch');

{
  const root = makeTmpRoot();
  const store = new FsBaselineStore({ rootDir: root });
  const previousVersion = makeValidManifest({ version: 'v0' });
  const currentVersion = makeValidManifest({ version: 'v1', previousVersion: 'v0' });
  const delta = {
    schemaVersion: '1.0.0',
    baseVersion: 'v0',
    baseManifestHash: previousVersion.canonicalContentHash,
    targetVersion: 'v1',
    targetManifestHash: 'sha256:' + 'z'.repeat(64), // wrong
    upserts: [],
    tombstones: [],
  };
  const fetcher = makeStubFetcher({
    manifest: currentVersion,
    deltas: { 'v0__to__v1': delta },
  });
  const client = new ConsumerClient({ gatewayUrl: 'https://gw.test', credential: makeValidCredential(), store, fetcher });
  let threw = null;
  try { await client.syncDelta({ fromVersion: 'v0' }); } catch (e) { threw = e; }
  assert('hash mismatch throws', threw !== null && /hash/i.test(threw.message));
  await store.clear();
}

/* ------------------------------------------------------------------ */
/* Tests: ConsumerClient.snapshot                                      */
/* ------------------------------------------------------------------ */

section('ConsumerClient.snapshot: decodes base64 shards and writes them');

{
  const root = makeTmpRoot();
  const store = new FsBaselineStore({ rootDir: root });
  const m = makeValidManifest({
    shards: {
      vulnerability: {
        ab: { objectKey: 'objects/sha256/aaa.json.gz', sha256: 'sha256:' + 'a'.repeat(64), byteSize: 100, recordCount: 5 },
      },
    },
  });
  const gz = gzipSync(Buffer.from('[1,2,3]', 'utf8'));
  const snapshot = {
    manifest: m,
    shards: { 'objects/sha256/aaa.json.gz': gz.toString('base64') },
    encoding: { shards: 'base64-gzip' },
  };
  const fetcher = makeStubFetcher({ snapshots: { v1: snapshot } });
  const client = new ConsumerClient({ gatewayUrl: 'https://gw.test', credential: makeValidCredential(), store, fetcher });
  const r = await client.snapshot({ version: 'v1' });
  assert('snapshot reports the right version', r.version === 'v1');
  assert('snapshot reports shardsWritten=1', r.shardsWritten === 1);
  assert('shard is local and decodes to the canonical list',
    JSON.stringify(await store.readShard('objects/sha256/aaa.json.gz')) === JSON.stringify([1, 2, 3]));
  assert('manifest is local', (await store.readManifest()).baselineVersion === 'v1');
  await store.clear();
}

section('ConsumerClient.snapshot: rejects on manifest hash mismatch');

{
  const root = makeTmpRoot();
  const store = new FsBaselineStore({ rootDir: root });
  const m = makeValidManifest();
  m.canonicalContentHash = 'sha256:' + 'z'.repeat(64); // tamper
  const snapshot = { manifest: m, shards: {}, encoding: { shards: 'base64-gzip' } };
  const fetcher = makeStubFetcher({ snapshots: { v1: snapshot } });
  const client = new ConsumerClient({ gatewayUrl: 'https://gw.test', credential: makeValidCredential(), store, fetcher });
  let threw = null;
  try { await client.snapshot({ version: 'v1' }); } catch (e) { threw = e; }
  assert('tampered snapshot manifest throws', threw !== null);
  await store.clear();
}

section('ConsumerClient.snapshot: uses current version when version not passed');

{
  const root = makeTmpRoot();
  const store = new FsBaselineStore({ rootDir: root });
  const m = makeValidManifest();
  await store.writeManifest(m);
  const snapshot = { manifest: m, shards: {}, encoding: { shards: 'base64-gzip' } };
  const fetcher = makeStubFetcher({ snapshots: { v1: snapshot } });
  const client = new ConsumerClient({ gatewayUrl: 'https://gw.test', credential: makeValidCredential(), store, fetcher });
  const r = await client.snapshot();
  assert('snapshot reads the current version when version is omitted', r.version === 'v1');
  await store.clear();
}

/* ------------------------------------------------------------------ */
/* Tests: getCurrentVersion                                            */
/* ------------------------------------------------------------------ */

section('ConsumerClient.getCurrentVersion');

{
  const root = makeTmpRoot();
  const store = new FsBaselineStore({ rootDir: root });
  const client = new ConsumerClient({ gatewayUrl: 'https://gw.test', credential: makeValidCredential(), store, fetcher: makeStubFetcher() });
  assert('null when no manifest is local', await client.getCurrentVersion() === null);
  await store.writeManifest(makeValidManifest());
  assert('returns v1 after writeManifest', await client.getCurrentVersion() === 'v1');
  await store.clear();
}

/* ------------------------------------------------------------------ */
/* Tests: V6.0 invariant                                                */
/* ------------------------------------------------------------------ */

section('V6.0 invariant: credential is never persisted to disk by the consumer');

{
  const root = makeTmpRoot();
  const store = new FsBaselineStore({ rootDir: root });
  const credential = makeValidCredential();
  const m = makeValidManifest();
  const fetcher = makeStubFetcher({ manifest: m, shards: {} });
  const client = new ConsumerClient({ gatewayUrl: 'https://gw.test', credential, store, fetcher });
  await client.sync();
  // Walk the local rootDir and verify the credential string does
  // not appear anywhere.
  const walk = (dir) => {
    const out = [];
    if (!existsSync(dir)) return out;
    for (const name of readdirSync(dir)) {
      const p = join(dir, name);
      const stat = readFileSync(p, { flag: 'r' });
      out.push(p);
    }
    return out;
  };
  // Read all files and check
  const readAllText = (dir) => {
    const out = [];
    const recur = (d) => {
      if (!existsSync(d)) return;
      for (const name of readdirSync(d, { withFileTypes: true })) {
        const p = join(d, name.name);
        if (name.isDirectory()) recur(p);
        else if (name.isFile()) {
          const txt = readFileSync(p, 'utf8');
          out.push(txt);
        }
      }
    };
    recur(dir);
    return out;
  };
  const allText = readAllText(root);
  const leaked = allText.some((t) => t.includes(credential));
  assert('credential is not present in any local file', !leaked);
  // Also check the random secret part is not present
  const parsed = credential.split('_');
  const secret = parsed[parsed.length - 1];
  const leakedSecret = allText.some((t) => t.includes(secret));
  assert('random secret half is not present in any local file', !leakedSecret);
  await store.clear();
}

console.log();
console.log(`Total: ${passed} passed, ${failed} failed`);

if (failed > 0) {
  console.log('\nFailures:');
  for (const f of failures) {
    console.log(`  - ${f.label}  -- ${f.extra}`);
  }
  process.exit(1);
}
console.log('ALL CONSUMER-CLIENT TESTS PASSED');
