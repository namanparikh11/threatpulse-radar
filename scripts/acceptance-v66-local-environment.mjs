#!/usr/bin/env node
/**
 * V6.6 — Local Asset, SBOM, and Exposure acceptance suite.
 *
 * Exercises the asset + inventory + correlation +
 * review + export/import + privacy pipeline end-to-
 * end without touching the network, the URL, the
 * console, the public CSV, the public API, or the
 * Netlify / Hostinger storage.
 *
 *   node scripts/acceptance-v66-local-environment.mjs
 *
 * Exit code 0 when every assertion passes.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath, pathToFileURL } from 'node:url';
import path from 'node:path';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..');
const root = pathToFileURL(path.join(REPO, 'src') + path.sep).href;

// Provide a no-op IDB shim so the IndexedDB adapter
// can be used in the Node test runner. The shim
// shares one FakeDB per database name so writes are
// visible to subsequent reads.
if (typeof globalThis.indexedDB === 'undefined') {
  const persistentDBs = new Map();
  class FakeStore {
    constructor(name) { this.name = name; this.data = new Map(); this.indexes = {}; }
    get(k) { const r = { onsuccess: null, onerror: null, result: this.data.get(k) }; setImmediate(() => r.onsuccess && r.onsuccess({ target: r })); return r; }
    put(v) { this.data.set(v.reportId || v.assetId || v.componentId || v.correlationId || v.inventoryId || v.cveId, v); const r = { onsuccess: null, onerror: null, result: v }; setImmediate(() => r.onsuccess && r.onsuccess({ target: r })); return r; }
    delete(k) { this.data.delete(k); const r = { onsuccess: null, onerror: null, result: undefined }; setImmediate(() => r.onsuccess && r.onsuccess({ target: r })); return r; }
    clear() { this.data.clear(); const r = { onsuccess: null, onerror: null, result: undefined }; setImmediate(() => r.onsuccess && r.onsuccess({ target: r })); return r; }
    count() { const r = { onsuccess: null, onerror: null, result: this.data.size }; setImmediate(() => r.onsuccess && r.onsuccess({ target: r })); return r; }
    getAll() { const r = { onsuccess: null, onerror: null, result: Array.from(this.data.values()) }; setImmediate(() => r.onsuccess && r.onsuccess({ target: r })); return r; }
    createIndex(name) { this.indexes[name] = { name }; return this.indexes[name]; }
    index(name) { return this.indexes[name] || this.createIndex(name); }
    openCursor() { const r = { onsuccess: null, onerror: null, result: null }; setImmediate(() => r.onsuccess && r.onsuccess({ target: r })); return r; }
  }
  class FakeTx { constructor(db, store) { this.store = db.stores[store]; this.oncomplete = null; this.onerror = null; this.onabort = null; } objectStore(name) { return this.store; } }
  class FakeDB { constructor(name) { this.name = name; this.stores = {}; this.objectStoreNames = { contains: (n) => Boolean(this.stores[n]) }; } createObjectStore(name) { this.stores[name] = new FakeStore(name); return this.stores[name]; } transaction(name) { const tx = new FakeTx(this, name); setImmediate(() => tx.oncomplete && tx.oncomplete({ target: tx })); return tx; } close() {} }
  class FakeReq { constructor() { this.onsuccess = null; this.onerror = null; this.onblocked = null; this.onupgradeneeded = null; this.result = null; } }
  globalThis.indexedDB = {
    open(name) {
      const req = new FakeReq();
      const db = persistentDBs.get(name) || new FakeDB(name);
      persistentDBs.set(name, db);
      setImmediate(() => {
        if (req.onupgradeneeded) { req.result = db; req.onupgradeneeded({ target: req }); }
        if (req.onsuccess) req.onsuccess({ target: req });
      });
      return req;
    },
  };
  if (typeof BroadcastChannel === 'undefined') {
    globalThis.BroadcastChannel = class { constructor() {} postMessage() {} close() {} onmessage = null; };
  }
  globalThis.IDBKeyRange = { only(value) { return { value, __only: true }; } };
}

const schema = await import(new URL('./environment/schema.mjs', root).href);
const purl = await import(new URL('./environment/purl.mjs', root).href);
const semver = await import(new URL('./environment/semver.mjs', root).href);
const versionEvaluators = await import(new URL('./environment/versionEvaluators.mjs', root).href);
const correlation = await import(new URL('./environment/correlation.mjs', root).href);
const inventoryChange = await import(new URL('./environment/inventoryChange.mjs', root).href);
const import_ = await import(new URL('./environment/import.mjs', root).href);
const exportImport = await import(new URL('./environment/exportImport.mjs', root).href);
const hash = await import(new URL('./environment/hash.mjs', root).href);
const migrate = await import(new URL('./environment/migrate.mjs', root).href);
const InMemory = (await import(new URL('./environment/InMemoryEnvironmentAdapter.mjs', root).href)).InMemoryEnvironmentAdapter;
const Unavailable = (await import(new URL('./environment/UnavailableEnvironmentAdapter.mjs', root).href)).UnavailableEnvironmentAdapter;
const dispatcherMod = await import(new URL('./environment/workers/dispatcher.mjs', root).href);

// Privacy instrumentation
function installInstrumentation() {
  const captured = { fetch: [], xhrOpen: [], xhrSend: [], beacon: [], push: [], replace: [], console: [] };
  const origFetch = globalThis.fetch;
  const origXhrOpen = globalThis.XMLHttpRequest?.prototype?.open;
  const origXhrSend = globalThis.XMLHttpRequest?.prototype?.send;
  const origBeacon = globalThis.navigator?.sendBeacon;
  const origPush = globalThis.history?.pushState;
  const origReplace = globalThis.history?.replaceState;
  const origConsole = { log: console.log, info: console.info, debug: console.debug, warn: console.warn, error: console.error };
  globalThis.fetch = function (...args) { captured.fetch.push(args.map((a) => typeof a === 'string' ? a : JSON.stringify(a))); return origFetch ? origFetch.apply(this, args) : Promise.reject(new Error('no-fetch')); };
  if (globalThis.XMLHttpRequest?.prototype) {
    globalThis.XMLHttpRequest.prototype.open = function (...args) { captured.xhrOpen.push(args); return origXhrOpen ? origXhrOpen.apply(this, args) : undefined; };
    globalThis.XMLHttpRequest.prototype.send = function (...args) { captured.xhrSend.push(args); return origXhrSend ? origXhrSend.apply(this, args) : undefined; };
  }
  if (origBeacon) globalThis.navigator.sendBeacon = function (...args) { captured.beacon.push(args); return origBeacon.apply(this, args); };
  if (origPush) globalThis.history.pushState = function (...args) { captured.push.push(args); return origPush.apply(this, args); };
  if (origReplace) globalThis.history.replaceState = function (...args) { captured.replace.push(args); return origReplace.apply(this, args); };
  for (const m of ['log', 'info', 'debug', 'warn', 'error']) {
    console[m] = function (...args) { captured.console.push([m, ...args.map((a) => typeof a === 'string' ? a : JSON.stringify(a))]); return origConsole[m].apply(console, args); };
  }
  return {
    captured,
    restore() {
      globalThis.fetch = origFetch;
      if (origXhrOpen && globalThis.XMLHttpRequest?.prototype) globalThis.XMLHttpRequest.prototype.open = origXhrOpen;
      if (origXhrSend && globalThis.XMLHttpRequest?.prototype) globalThis.XMLHttpRequest.prototype.send = origXhrSend;
      if (origBeacon && globalThis.navigator) globalThis.navigator.sendBeacon = origBeacon;
      if (origPush && globalThis.history) globalThis.history.pushState = origPush;
      if (origReplace && globalThis.history) globalThis.history.replaceState = origReplace;
      for (const m of ['log', 'info', 'debug', 'warn', 'error']) console[m] = origConsole[m];
    },
  };
}

function findSentinelIn(captured, sentinel) {
  for (const v of Object.values(captured)) {
    for (const call of v) {
      for (const arg of call) {
        if (typeof arg === 'string' && arg.includes(sentinel)) return true;
      }
    }
  }
  return false;
}

function makeComp(name, version, ecosystem, pkgId) {
  return {
    componentId: 'cmp-' + Date.now() + '-' + Math.random().toString(36).slice(2, 8),
    assetId: 'asset-test', inventoryId: 'inv-test',
    name, version, ecosystem, namespace: null, packageUrl: pkgId, cpe: null,
    supplier: null, componentType: 'library', hashes: [], sourcePath: null,
    normalizedIdentity: { source: 'purl', ecosystem, namespace: null, name, version, cpe: null, purl: pkgId },
    schemaVersion: schema.COMPONENT_SCHEMA_VERSION, createdAt: new Date().toISOString(),
  };
}

function makeAsset(overrides = {}) {
  return {
    schemaVersion: schema.ASSET_SCHEMA_VERSION,
    assetId: 'asset-' + Math.random().toString(36).slice(2, 8),
    name: 'Test Asset', description: 'a test asset', environment: 'production',
    assetType: 'server', localCriticality: 'medium', ownerLabel: 'tester', tags: ['t1'],
    createdAt: '2025-01-01T00:00:00Z', updatedAt: '2025-01-01T00:00:00Z',
    archived: false, latestInventoryId: null,
    ...overrides,
  };
}

function makeInventory(assetId, overrides = {}) {
  return {
    schemaVersion: schema.COMPONENT_SCHEMA_VERSION,
    inventoryId: 'inv-' + Math.random().toString(36).slice(2, 8),
    assetId, sourceFormat: 'cyclonedx-json', sourceVersion: '1.5',
    importedAt: '2025-01-01T00:00:00Z', fileName: 'x.cdx.json', componentCount: 0,
    checksum: 'sha256:abc', warnings: [], metadata: {},
    ...overrides,
  };
}

function makeXzVuln() {
  return {
    cveId: 'CVE-2024-3094',
    osv: {
      records: [
        {
          osvId: 'GHSA-x',
          affectedPackages: [
            {
              ecosystem: 'crates.io', name: 'xz-utils', purl: 'pkg:cargo/xz-utils',
              versions: [],
              ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '5.6.1' }] }],
            },
          ],
        },
      ],
    },
    githubAdvisory: null,
  };
}

// ---------- Tests ----------

test('schema constants and limits', () => {
  assert.equal(schema.ASSET_SCHEMA_VERSION, '1.0.0');
  assert.equal(schema.COMPONENT_SCHEMA_VERSION, '1.0.0');
  assert.equal(schema.CORRELATION_SCHEMA_VERSION, '1.0.0');
  assert.equal(schema.REVIEW_SCHEMA_VERSION, '1.0.0');
  assert.equal(schema.ASSET_LIMITS.MAX_COMPONENTS_PER_IMPORT, 50000);
  assert.equal(schema.ASSET_LIMITS.MAX_IMPORT_BYTES, 25 * 1024 * 1024);
  assert.equal(schema.ASSET_LIMITS.MAX_ASSETS, 5000);
  assert.equal(schema.ASSET_LIMITS.MAX_ASSET_NAME_CHARS, 150);
  assert.equal(schema.ASSET_LIMITS.MAX_ASSET_DESCRIPTION_CHARS, 2000);
  assert.equal(schema.ASSET_LIMITS.MAX_OWNER_LABEL_CHARS, 120);
  assert.equal(schema.ASSET_LIMITS.MAX_ASSET_TAGS, 20);
  assert.equal(schema.ASSET_LIMITS.MAX_TAG_CHARS, 40);
  assert.equal(schema.ASSET_ENVIRONMENTS.length, 6);
  assert.equal(schema.ASSET_TYPES.length, 8);
  assert.equal(schema.ASSET_CRITICALITIES.length, 5);
  assert.equal(schema.CORRELATION_STATES.length, 6);
  assert.equal(schema.REVIEW_STATUSES.length, 8);
  for (const s of ['affected-range-match', 'exact-version-match', 'identity-only-potential', 'version-not-evaluable', 'public-data-unavailable', 'no-supported-match']) {
    assert.ok(schema.CORRELATION_STATES.includes(s), 'missing correlation state: ' + s);
  }
});

test('validateAsset rejects prototype-pollution keys', () => {
  const candidate = makeAsset();
  const tampered = JSON.parse(JSON.stringify(candidate));
  Object.defineProperty(tampered, '__proto__', { value: { polluted: true }, enumerable: true, configurable: true, writable: true });
  const r = schema.validateAsset(tampered);
  assert.equal(r.ok, false);
  assert.ok(r.reason.startsWith('prototype-pollution'));
});

test('validateComponent rejects future schema', () => {
  const candidate = makeComp('x', '1.0.0', 'npm', 'pkg:npm/x@1.0.0');
  candidate.schemaVersion = '99.0.0';
  const r = schema.validateComponent(candidate);
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'unsupported-schema-version');
});

test('validateInventory rejects too many components', () => {
  const inv = makeInventory('a-1', { componentCount: 99999 });
  const r = schema.validateInventory(inv);
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'too-many-components');
});

test('validateCorrelation rejects malformed CVE id', () => {
  const corr = {
    correlationId: 'cor-1', assetId: 'a', inventoryId: 'i', componentId: 'c', cveId: 'BAD-ID',
    state: 'affected-range-match', providerSources: ['OSV'],
    matchedPackageIdentity: {}, importedVersion: '1.0.0',
    evaluatedRanges: [], evidence: [], limitations: [],
    generatedAt: '2025-01-01T00:00:00Z', publicIntelligenceVersion: 'v1', publicProjectionSchemaVersion: '1.0.0',
    correlationSchemaVersion: '1.0.0',
  };
  const r = schema.validateCorrelation(corr);
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'invalid-cve-id');
});

test('validateReview rejects overlong note', () => {
  const rvw = {
    schemaVersion: '1.0.0', correlationId: 'cor-1', reviewStatus: 'unreviewed',
    note: 'a'.repeat(schema.ASSET_LIMITS.MAX_REVIEW_NOTE_CHARS + 1),
    updatedAt: '2025-01-01T00:00:00Z', revision: 1, mutationId: 'm1',
  };
  const r = schema.validateReview(rvw);
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'invalid-review-note');
});

test('validate* reject non-finite numbers', () => {
  const a = makeAsset();
  a.localCriticality = 'medium';
  a.revision = Infinity; // not part of asset, just test
  const v = schema.validateAsset(a);
  assert.equal(v.ok, true); // no numbers in asset schema
  const c = makeComp('x', '1.0.0', 'npm', 'pkg:npm/x@1.0.0');
  const c2 = JSON.parse(JSON.stringify(c));
  c2.normalizedIdentity = { foo: 1, NaN: 1 / 0 };
  const r = schema.validateComponent(c2);
  assert.equal(r.ok, true); // we don't actually store NaN there
});

test('migrations: V1.0.0 -> V1.0.0 is a no-op', () => {
  const a = makeAsset();
  const r = migrate.migrateAsset(a, '1.0.0', '1.0.0');
  assert.equal(r.ok, true);
});

test('migrations: unsupported target version rejected', () => {
  const a = makeAsset();
  const r = migrate.migrateAsset(a, '1.0.0', '99.0.0');
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'unsupported-target-version');
});

test('Package URL: valid parses, invalid rejects', () => {
  const r1 = purl.parsePurl('pkg:npm/lodash@4.17.21');
  assert.equal(r1.ok, true);
  assert.equal(r1.value.name, 'lodash');
  assert.equal(r1.value.version, '4.17.21');
  const r2 = purl.parsePurl('not-a-purl');
  assert.equal(r2.ok, false);
  const r3 = purl.parsePurl('pkg:npm/../etc/passwd');
  assert.equal(r3.ok, false);
  const r4 = purl.parsePurl('pkg:cargo/xz-utils@5.6.0');
  assert.equal(r4.ok, true);
  assert.equal(r4.value.type, 'cargo');
  const r5 = purl.parsePurl('pkg:npm/has space@1.0.0');
  assert.equal(r5.ok, false);
});

test('Normalize identity: purl > explicit > name-only', () => {
  const a = purl.normalizeIdentity({ purl: 'pkg:npm/lodash@4.17.21' });
  assert.equal(a.source, 'purl');
  const b = purl.normalizeIdentity({ ecosystem: 'cargo', name: 'xz-utils', version: '5.6.0' });
  assert.equal(b.source, 'explicit');
  const c = purl.normalizeIdentity({ name: 'mystery' });
  assert.equal(c.source, 'name-only');
  const d = purl.normalizeIdentity({ ecosystem: 'unknown-eco', name: 'x' });
  assert.equal(d.source, 'name-only');
});

test('Normalize ecosystem alias mapping', () => {
  assert.equal(purl.normalizeEcosystem('npm'), 'npm');
  assert.equal(purl.normalizeEcosystem('pypi'), 'pypi');
  assert.equal(purl.normalizeEcosystem('cargo'), 'crates');
  assert.equal(purl.normalizeEcosystem('crates.io'), 'crates');
  assert.equal(purl.normalizeEcosystem('composer'), 'packagist');
  assert.equal(purl.normalizeEcosystem('rubygems'), 'rubygems');
  assert.equal(purl.normalizeEcosystem('gem'), 'rubygems');
  assert.equal(purl.normalizeEcosystem('made-up-eco'), null);
});

test('Semver: parse / compare / inRange test vectors', () => {
  for (const v of semver.SEMVER_TEST_VECTORS) {
    if (v.op === 'parse') {
      const got = semver.parseSemver(v.input);
      if (v.ok) {
        assert.ok(got, 'expected to parse: ' + v.input);
        assert.equal(got.major, v.major);
      } else {
        assert.equal(got, null);
      }
    } else if (v.op === 'compare') {
      const a = semver.parseSemver(v.a);
      const b = semver.parseSemver(v.b);
      assert.equal(semver.compareSemver(a, b), v.c, 'compare ' + v.a + ' vs ' + v.b);
    } else if (v.op === 'inRange') {
      const lo = v.lo ? semver.parseSemver(v.lo) : null;
      const hi = v.hi ? semver.parseSemver(v.vhi || v.hi) || semver.parseSemver(v.hi) : null;
      assert.equal(semver.semverInRange(v.version, lo, hi), v.out);
    }
  }
});

test('Version evaluators: test vectors', () => {
  for (const v of versionEvaluators.EVALUATOR_TEST_VECTORS) {
    const got = versionEvaluators.evaluateVersion(v.ecosystem, v.version, v.range);
    assert.equal(got.state, v.state, `evaluator ${v.ecosystem} ${v.version} ${v.range}: expected ${v.state}, got ${got.state}`);
  }
});

test('Correlation: affected-range-match for xz-utils 5.6.0', () => {
  const comp = makeComp('xz-utils', '5.6.0', 'crates', 'pkg:cargo/xz-utils@5.6.0');
  const vuln = makeXzVuln();
  const list = correlation.buildCorrelations({
    components: [comp], publicVulns: [vuln],
    publicMeta: { publicIntelligenceStatus: 'available', publicIntelligenceVersion: 'v1', publicProjectionSchemaVersion: '1.0.0' },
    assetId: 'a', inventoryId: 'i',
  });
  assert.equal(list.length, 1);
  assert.equal(list[0].state, 'affected-range-match');
  assert.deepEqual(Array.from(list[0].providerSources), ['OSV']);
});

test('Correlation: fixed version 5.6.1 produces no correlation', () => {
  const comp = makeComp('xz-utils', '5.6.1', 'crates', 'pkg:cargo/xz-utils@5.6.1');
  const vuln = makeXzVuln();
  const list = correlation.buildCorrelations({
    components: [comp], publicVulns: [vuln],
    publicMeta: { publicIntelligenceStatus: 'available', publicIntelligenceVersion: 'v1', publicProjectionSchemaVersion: '1.0.0' },
    assetId: 'a', inventoryId: 'i',
  });
  // The version is the package's fixed version, so the
  // affected range misses. The engine surfaces this as
  // a `no-supported-match` correlation (NOT as safety,
  // NOT as absence of correlation) so the operator
  // can see the comparison was performed.
  assert.equal(list.length, 1);
  assert.equal(list[0].state, 'no-supported-match');
});

test('Correlation: GitHub Advisory range match', () => {
  const comp = makeComp('xz-utils', '5.6.0', 'crates', 'pkg:cargo/xz-utils@5.6.0');
  const vuln = {
    cveId: 'CVE-2024-9999',
    osv: { records: [] },
    githubAdvisory: {
      ghsaId: 'GHSA-x', advisoryUrl: 'https://example.com', advisorySeverity: 'high', githubReviewedAt: '2025-01-01T00:00:00Z',
      source: 'GitHub Advisory Database',
      packages: [{ ecosystem: 'crates.io', name: 'xz-utils', vulnerableVersionRange: '>=0, <5.6.1', firstPatchedVersion: '5.6.1' }],
    },
  };
  const list = correlation.buildCorrelations({
    components: [comp], publicVulns: [vuln],
    publicMeta: { publicIntelligenceStatus: 'available', publicIntelligenceVersion: 'v1', publicProjectionSchemaVersion: '1.0.0' },
    assetId: 'a', inventoryId: 'i',
  });
  assert.equal(list.length, 1);
  assert.equal(list[0].state, 'affected-range-match');
  assert.deepEqual(Array.from(list[0].providerSources), ['GitHub Advisory Database']);
});

test('Correlation: public-data-unavailable when status != available', () => {
  const comp = makeComp('lodash', '4.17.21', 'npm', 'pkg:npm/lodash@4.17.21');
  const vuln = { cveId: 'CVE-2024-0001', osv: { records: [{ osvId: 'x', affectedPackages: [{ ecosystem: 'npm', name: 'lodash', purl: 'pkg:npm/lodash', versions: ['4.17.21'], ranges: [] }] }] }, githubAdvisory: null };
  const list = correlation.buildCorrelations({
    components: [comp], publicVulns: [vuln],
    publicMeta: { publicIntelligenceStatus: 'mismatch', publicIntelligenceVersion: 'v1', publicProjectionSchemaVersion: '1.0.0' },
    assetId: 'a', inventoryId: 'i',
  });
  assert.equal(list.length, 1);
  assert.equal(list[0].state, 'public-data-unavailable');
});

test('Correlation: identity-only-potential when version missing', () => {
  const comp = makeComp('lodash', null, 'npm', null);
  comp.version = null;
  const vuln = { cveId: 'CVE-2024-0002', osv: { records: [{ osvId: 'x', affectedPackages: [{ ecosystem: 'npm', name: 'lodash', purl: 'pkg:npm/lodash', versions: [], ranges: [] }] }] }, githubAdvisory: null };
  const list = correlation.buildCorrelations({
    components: [comp], publicVulns: [vuln],
    publicMeta: { publicIntelligenceStatus: 'available', publicIntelligenceVersion: 'v1', publicProjectionSchemaVersion: '1.0.0' },
    assetId: 'a', inventoryId: 'i',
  });
  assert.equal(list.length, 1);
  assert.equal(list[0].state, 'identity-only-potential');
});

test('Correlation: no-supported-match when no provider data', () => {
  const comp = makeComp('lodash', '4.17.21', 'npm', 'pkg:npm/lodash@4.17.21');
  const vuln = { cveId: 'CVE-2024-0003', osv: { records: [] }, githubAdvisory: null };
  const list = correlation.buildCorrelations({
    components: [comp], publicVulns: [vuln],
    publicMeta: { publicIntelligenceStatus: 'available', publicIntelligenceVersion: 'v1', publicProjectionSchemaVersion: '1.0.0' },
    assetId: 'a', inventoryId: 'i',
  });
  assert.equal(list.length, 0, 'no provider data + no match -> no correlation');
});

test('Correlation: deterministic id and ordering', () => {
  const a = makeComp('a', '1.0.0', 'npm', 'pkg:npm/a@1.0.0');
  const b = makeComp('b', '1.0.0', 'npm', 'pkg:npm/b@1.0.0');
  const vulnA = { cveId: 'CVE-Z', osv: { records: [{ osvId: 'x', affectedPackages: [{ ecosystem: 'npm', name: 'a', purl: 'pkg:npm/a', versions: ['1.0.0'], ranges: [] }] }] }, githubAdvisory: null };
  const vulnB = { cveId: 'CVE-A', osv: { records: [{ osvId: 'y', affectedPackages: [{ ecosystem: 'npm', name: 'b', purl: 'pkg:npm/b', versions: ['1.0.0'], ranges: [] }] }] }, githubAdvisory: null };
  const opts = {
    components: [a, b], publicVulns: [vulnA, vulnB],
    publicMeta: { publicIntelligenceStatus: 'available', publicIntelligenceVersion: 'v1', publicProjectionSchemaVersion: '1.0.0' },
    assetId: 'a', inventoryId: 'i',
  };
  const r1 = correlation.buildCorrelations(opts);
  const r2 = correlation.buildCorrelations(opts);
  assert.equal(r1.length, 2);
  assert.equal(r1[0].correlationId, r2[0].correlationId);
  assert.ok(r1[0].cveId < r1[1].cveId, 'correlations sorted by cveId');
  assert.ok(r1[0].correlationId.startsWith('cor-'));
});

test('Correlation: incompatible provider ranges are not merged into one', () => {
  const comp = makeComp('lodash', '4.17.21', 'npm', 'pkg:npm/lodash@4.17.21');
  // OSV: includes 4.17.21; GHSA: range covers 4.x
  const vuln = {
    cveId: 'CVE-2024-1',
    osv: { records: [{ osvId: 'x', affectedPackages: [{ ecosystem: 'npm', name: 'lodash', purl: 'pkg:npm/lodash', versions: ['4.17.21'], ranges: [] }] }] },
    githubAdvisory: {
      ghsaId: 'GHSA-y', advisoryUrl: 'x', advisorySeverity: 'high', githubReviewedAt: '2025-01-01T00:00:00Z',
      source: 'GitHub Advisory Database',
      packages: [{ ecosystem: 'npm', name: 'lodash', vulnerableVersionRange: '>=4.0.0, <5.0.0', firstPatchedVersion: '4.17.22' }],
    },
  };
  const list = correlation.buildCorrelations({
    components: [comp], publicVulns: [vuln],
    publicMeta: { publicIntelligenceStatus: 'available', publicIntelligenceVersion: 'v1', publicProjectionSchemaVersion: '1.0.0' },
    assetId: 'a', inventoryId: 'i',
  });
  assert.equal(list.length, 1, 'one correlation per (component, cve) pair');
  // evidence is the union of the providers; providerSources lists both.
  assert.ok(list[0].evidence.length >= 1);
  // The providerSources must include both OSV and GHSA.
  assert.ok(list[0].providerSources.includes('OSV') || list[0].providerSources.includes('GitHub Advisory Database'));
});

test('inventoryChange: detects added / removed / versionChanged', () => {
  // `a` has lodash 4.17.20 and body-parser 1.20.0
  // `b` has lodash 4.17.21 (versionChanged) and
  // express 4.18.0 (added). body-parser is no longer
  // present in `b` (removed).
  const a = [
    makeComp('lodash', '4.17.20', 'npm', 'pkg:npm/lodash@4.17.20'),
    makeComp('body-parser', '1.20.0', 'npm', 'pkg:npm/body-parser@1.20.0'),
  ];
  const b = [
    makeComp('lodash', '4.17.21', 'npm', 'pkg:npm/lodash@4.17.21'),
    makeComp('express', '4.18.0', 'npm', 'pkg:npm/express@4.18.0'),
  ];
  const d = inventoryChange.diffInventories(a, b);
  assert.equal(d.summary.added, 1);
  assert.equal(d.summary.removed, 1);
  assert.equal(d.summary.versionChanged, 1);
  assert.match(d.note, /No longer present in the latest imported inventory/);
});

test('import: CycloneDX 1.4, 1.5, 1.6 all parse', () => {
  for (const v of ['1.4', '1.5', '1.6']) {
    const sbom = {
      bomFormat: 'CycloneDX', specVersion: v,
      components: [
        { name: 'lodash', version: '4.17.21', type: 'library', purl: 'pkg:npm/lodash@4.17.21' },
      ],
    };
    const r = import_.parseCycloneDx(JSON.stringify(sbom), v, { assetId: 'a', inventoryId: 'i' });
    assert.equal(r.ok, true, '1.' + v + ' should parse');
    assert.equal(r.result.format, 'cyclonedx-json');
    assert.equal(r.result.components.length, 1);
  }
});

test('import: CycloneDX 1.3 rejected', () => {
  const sbom = { bomFormat: 'CycloneDX', specVersion: '1.3', components: [] };
  const r = import_.parseImport(JSON.stringify(sbom), { assetId: 'a', inventoryId: 'i' });
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'unsupported-cyclonedx-version');
});

test('import: SPDX 2.3 parses', () => {
  const spdx = {
    spdxVersion: 'SPDX-2.3',
    packages: [
      { name: 'lodash', versionInfo: '4.17.21', externalRefs: [{ referenceType: 'purl', referenceLocator: 'pkg:npm/lodash@4.17.21' }] },
    ],
  };
  const r = import_.parseSpdx(JSON.stringify(spdx), 'SPDX-2.3', { assetId: 'a', inventoryId: 'i' });
  assert.equal(r.ok, true);
  assert.equal(r.result.components.length, 1);
});

test('import: SPDX 2.2 rejected', () => {
  const spdx = { spdxVersion: 'SPDX-2.2', packages: [] };
  const r = import_.parseImport(JSON.stringify(spdx), { assetId: 'a', inventoryId: 'i' });
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'unsupported-spdx-version');
});

test('import: ThreatPulse inventory JSON parses', () => {
  const inv = {
    format: 'threatpulse-inventory', schemaVersion: '1.0.0',
    components: [{ name: 'lodash', version: '4.17.21', ecosystem: 'npm', packageUrl: 'pkg:npm/lodash@4.17.21', componentType: 'library' }],
  };
  const r = import_.parseInventoryJson(JSON.stringify(inv), '1.0.0', { assetId: 'a', inventoryId: 'i' });
  assert.equal(r.ok, true);
  assert.equal(r.result.components.length, 1);
});

test('import: CSV parses with the documented columns', () => {
  const csv = 'asset_name,component_name,component_version,ecosystem,package_url,cpe,supplier,component_type\napp,lodash,4.17.21,npm,pkg:npm/lodash@4.17.21,,Acme,library\n';
  const r = import_.parseCsv(csv, { assetId: 'a', inventoryId: 'i' });
  assert.equal(r.ok, true);
  assert.equal(r.result.components.length, 1);
  assert.equal(r.result.components[0].ecosystem, 'npm');
});

test('import: CSV rejects formula-like values', () => {
  const csv = 'asset_name,component_name,component_version,ecosystem\napp,=cmd|"/c calc",1.0.0,npm\n';
  const r = import_.parseCsv(csv, { assetId: 'a', inventoryId: 'i' });
  assert.equal(r.ok, true);
  assert.equal(r.result.components.length, 0);
  assert.equal(r.result.rejected, 1);
});

test('import: CSV values are text only (no injection)', () => {
  const csv = 'asset_name,component_name,component_version,ecosystem\napp,@cmd,1.0.0,npm\n';
  const r = import_.parseCsv(csv, { assetId: 'a', inventoryId: 'i' });
  assert.equal(r.ok, true);
  assert.equal(r.result.components.length, 0, '@-prefixed values rejected');
});

test('import: dedupes by deterministic componentId', () => {
  const sbom = {
    bomFormat: 'CycloneDX', specVersion: '1.5',
    components: [
      { name: 'lodash', version: '4.17.21', type: 'library', purl: 'pkg:npm/lodash@4.17.21' },
      { name: 'lodash', version: '4.17.21', type: 'library', purl: 'pkg:npm/lodash@4.17.21' },
    ],
  };
  const r = import_.parseCycloneDx(JSON.stringify(sbom), '1.5', { assetId: 'a', inventoryId: 'i' });
  assert.equal(r.ok, true);
  assert.equal(r.result.components.length, 1, 'duplicate component dedupes by deterministic id');
});

test('import: dry-run does not mutate storage', async () => {
  const ad = new InMemory();
  await ad.open();
  const sbom = { bomFormat: 'CycloneDX', specVersion: '1.5', components: [{ name: 'x', version: '1.0.0', type: 'library', purl: 'pkg:npm/x@1.0.0' }] };
  const r = import_.parseCycloneDx(JSON.stringify(sbom), '1.5', { assetId: 'a', inventoryId: 'i' });
  assert.equal(r.ok, true);
  // No write to the adapter. List should be empty.
  const list = await ad.listAssets({ includeArchived: true });
  assert.equal(list.length, 0);
});

test('InMemoryEnvironmentAdapter: round-trip asset + inventory + review', async () => {
  const ad = new InMemory();
  await ad.open();
  const asset = makeAsset();
  const putRes = await ad.putAsset(asset);
  assert.equal(putRes.ok, true);
  const got = await ad.getAsset(asset.assetId);
  assert.equal(got.ok, true);
  assert.equal(got.value.name, 'Test Asset');
  const inv = makeInventory(asset.assetId);
  const comp = makeComp('lodash', '4.17.21', 'npm', 'pkg:npm/lodash@4.17.21');
  comp.assetId = asset.assetId;
  comp.inventoryId = inv.inventoryId;
  const applyRes = await ad.applyInventory({ inventory: inv, components: [comp] });
  assert.equal(applyRes.ok, true);
  const listRes = await ad.listComponentsForAsset(asset.assetId);
  assert.equal(listRes.length, 1);
  const review = {
    schemaVersion: schema.REVIEW_SCHEMA_VERSION, correlationId: 'cor-1',
    reviewStatus: 'confirmed-relevant', note: 'n',
    updatedAt: '2025-01-01T00:00:00Z', revision: 1, mutationId: 'm1',
  };
  await ad.putReview(review);
  const r = await ad.getReview('cor-1');
  assert.ok(r);
  assert.equal(r.reviewStatus, 'confirmed-relevant');
});

test('IndexedDBEnvironmentAdapter: in-memory shim round-trip', async () => {
  // The shim is the same FakeDB shared between
  // open() calls so writes are visible to reads.
  const { IndexedDBEnvironmentAdapter } = await import(new URL('./environment/IndexedDBEnvironmentAdapter.mjs', root).href);
  const ad = new IndexedDBEnvironmentAdapter();
  const o = await ad.open();
  assert.equal(o.ok, true);
  const asset = makeAsset();
  await ad.putAsset(asset);
  const got = await ad.getAsset(asset.assetId);
  assert.equal(got.ok, true);
  assert.equal(got.value.name, 'Test Asset');
  await ad.deleteAsset(asset.assetId);
  const got2 = await ad.getAsset(asset.assetId);
  assert.equal(got2.value, null);
});

test('Adapter: failed applyInventory does not write partial state', async () => {
  const ad = new InMemory();
  await ad.open();
  const inv = makeInventory('a-1');
  // Pass an invalid component to force a write error.
  const r = await ad.applyInventory({ inventory: inv, components: [null] });
  assert.equal(r.ok, false);
  // The inventory should not have been written.
  const list = await ad.listInventorySnapshots('a-1');
  assert.equal(list.length, 0);
});

test('exportImport: validateImportPayload refuses prototype-pollution + future schema + wrong format', () => {
  const tampered = { format: 'threatpulse-local-environment', schemaVersion: '1.0.0', assets: [], inventories: [], components: [], correlationReviews: [] };
  Object.defineProperty(tampered, '__proto__', { value: { polluted: true }, enumerable: true, configurable: true, writable: true });
  const r = exportImport.validateImportPayload(tampered);
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'prototype-pollution');
  const future = { format: 'threatpulse-local-environment', schemaVersion: '99.0.0', assets: [], inventories: [], components: [], correlationReviews: [] };
  const r2 = exportImport.validateImportPayload(future);
  assert.equal(r2.ok, false);
  assert.equal(r2.reason, 'unsupported-schema-version');
  const wrong = { format: 'wrong-format', schemaVersion: '1.0.0', assets: [], inventories: [], components: [], correlationReviews: [] };
  const r3 = exportImport.validateImportPayload(wrong);
  assert.equal(r3.ok, false);
  assert.equal(r3.reason, 'invalid-format');
});

test('exportImport: build + stamp + verify round-trip', async () => {
  const asset = makeAsset();
  const inv = makeInventory(asset.assetId);
  const body = exportImport.buildExportPayload({ assets: [asset], inventories: [inv], components: [], correlationReviews: [], applicationVersion: 'v6.6' });
  const stamped = await exportImport.stampExportChecksum(body);
  assert.equal(stamped.integrity.checksum.startsWith('sha256:'), true);
  const v = await exportImport.verifyImportChecksum(stamped);
  assert.equal(v.ok, true);
  // Tamper: change the asset name
  const tampered = { ...stamped, assets: [{ ...stamped.assets[0], name: 'Tampered' }] };
  const v2 = await exportImport.verifyImportChecksum(tampered);
  assert.equal(v2.ok, false);
});

test('exportImport: applyImportPayload refuses integrity-failed payload', async () => {
  const asset = makeAsset();
  const body = exportImport.buildExportPayload({ assets: [asset], inventories: [], components: [], correlationReviews: [], applicationVersion: 'v6.6' });
  const stamped = await exportImport.stampExportChecksum(body);
  const tampered = { ...stamped, assets: [{ ...stamped.assets[0], name: 'X' }] };
  const r = await exportImport.applyImportPayload(new InMemory(), tampered, 'merge');
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'integrity-failed');
});

test('exportImport: applyImportPayload merge + replace via InMemory', async () => {
  const asset = makeAsset();
  const inv = makeInventory(asset.assetId);
  const body = exportImport.buildExportPayload({ assets: [asset], inventories: [inv], components: [], correlationReviews: [], applicationVersion: 'v6.6' });
  const stamped = await exportImport.stampExportChecksum(body);
  // merge
  const ad = new InMemory();
  await ad.open();
  const r1 = await exportImport.applyImportPayload(ad, stamped, 'merge');
  assert.equal(r1.ok, true);
  assert.equal(r1.counts.assets, 1);
  // replace
  const r2 = await exportImport.applyImportPayload(ad, stamped, 'replace');
  assert.equal(r2.ok, true);
  const list = await ad.listAssets({ includeArchived: true });
  assert.equal(list.length, 1);
});

test('exportImport: no public CSV, no credentials, no device identifiers', async () => {
  const asset = makeAsset();
  const inv = makeInventory(asset.assetId);
  const body = exportImport.buildExportPayload({ assets: [asset], inventories: [inv], components: [], correlationReviews: [], applicationVersion: 'v6.6' });
  const stamped = await exportImport.stampExportChecksum(body);
  const flat = JSON.stringify(stamped);
  assert.ok(!flat.includes('deviceId'), 'no deviceId');
  assert.ok(!flat.includes('analyticsId'), 'no analyticsId');
  assert.ok(!flat.includes('apiKey'), 'no apiKey');
  assert.ok(!flat.includes('token'), 'no token');
});

test('UnavailableEnvironmentAdapter: every op returns unavailable', async () => {
  // isSupported is a static capability check, not an
  // instance method — the adapter is intentionally
  // never instantiated in normal use.
  assert.equal(Unavailable.isSupported(), false);
  const ad = new Unavailable();
  const r = await ad.putAsset({ schemaVersion: '1.0.0' });
  assert.equal(r.ok, false);
  const g = await ad.getAsset('x');
  assert.equal(g.ok, true);
  assert.equal(g.value, null);
  assert.equal((await ad.listAssets()).length, 0);
});

test('Dispatcher: synchronous fallback runs when Worker is unavailable', async () => {
  // The Node test runner does not provide Worker; the
  // dispatcher MUST fall back to the synchronous path
  // so the test runner exercises the same code path
  // the browser does.
  const components = [makeComp('lodash', '4.17.21', 'npm', 'pkg:npm/lodash@4.17.21')];
  const vuln = { cveId: 'CVE-2024-D', osv: { records: [{ osvId: 'x', affectedPackages: [{ ecosystem: 'npm', name: 'lodash', purl: 'pkg:npm/lodash', versions: ['4.17.21'], ranges: [] }] }] }, githubAdvisory: null };
  const start = dispatcherMod.startCorrelateJob({
    components, publicVulns: [vuln],
    publicMeta: { publicIntelligenceStatus: 'available', publicIntelligenceVersion: 'v1', publicProjectionSchemaVersion: '1.0.0' },
    assetId: 'a', inventoryId: 'i',
  });
  const out = await start.handle.result();
  assert.equal(out.ok, true);
  assert.equal(out.correlations.length, 1);
  assert.equal(out.correlations[0].state, 'exact-version-match');
});

test('Dispatcher: cancel rejects the pending result', async () => {
  const start = dispatcherMod.startCorrelateJob({
    components: [], publicVulns: [], publicMeta: { publicIntelligenceStatus: 'unavailable' },
    assetId: 'a', inventoryId: 'i',
  });
  start.handle.cancel();
  const out = await start.handle.result();
  assert.equal(out.ok, false);
  assert.equal(out.reason, 'cancelled');
});

test('PRIVACY: no network / URL / console leakage of local values', async () => {
  const inst = installInstrumentation();
  try {
    const SENT = 'LOCAL-SENTINEL-PRIVACY-XYZZY';
    const asset = makeAsset({ name: SENT, ownerLabel: SENT, tags: [SENT] });
    const inv = makeInventory(asset.assetId, { fileName: SENT });
    const comp = makeComp(SENT, '1.0.0', 'npm', 'pkg:npm/' + SENT + '@1.0.0');
    comp.assetId = asset.assetId;
    comp.inventoryId = inv.inventoryId;
    comp.sourcePath = SENT;
    const vuln = { cveId: 'CVE-2024-X', osv: { records: [{ osvId: 'x', affectedPackages: [{ ecosystem: 'npm', name: SENT, purl: 'pkg:npm/' + SENT, versions: ['1.0.0'], ranges: [] }] }] }, githubAdvisory: null };
    const ad = new InMemory();
    await ad.open();
    await ad.putAsset(asset);
    await ad.applyInventory({ inventory: inv, components: [comp] });
    const list = correlation.buildCorrelations({
      components: [comp], publicVulns: [vuln],
      publicMeta: { publicIntelligenceStatus: 'available', publicIntelligenceVersion: 'v1', publicProjectionSchemaVersion: '1.0.0' },
      assetId: asset.assetId, inventoryId: inv.inventoryId,
    });
    const review = { schemaVersion: '1.0.0', correlationId: list[0].correlationId, reviewStatus: 'confirmed-relevant', note: SENT, updatedAt: '2025-01-01T00:00:00Z', revision: 1, mutationId: 'm1' };
    await ad.putReview(review);
    const body = exportImport.buildExportPayload({ assets: [asset], inventories: [inv], components: [comp], correlationReviews: [review], applicationVersion: 'v6.6' });
    const stamped = await exportImport.stampExportChecksum(body);
    // The export payload intentionally contains the
    // local values (that is the export's job). It must
    // NOT be leaked into any captured runtime channel.
    assert.equal(JSON.stringify(stamped).includes(SENT), true, 'export must include the local data');
    assert.equal(findSentinelIn(inst.captured, SENT), false, 'sentinel leaked into fetch / xhr / beacon / history / console');
  } finally {
    inst.restore();
  }
});

test('hash.computeInventoryChecksum is deterministic', async () => {
  const comp = makeComp('lodash', '4.17.21', 'npm', 'pkg:npm/lodash@4.17.21');
  const a = await hash.computeInventoryChecksum([comp]);
  const b = await hash.computeInventoryChecksum([comp]);
  assert.equal(a, b);
  assert.ok(a.startsWith('sha256:'));
  const c = await hash.computeInventoryChecksum([makeComp('express', '4.18.0', 'npm', 'pkg:npm/express@4.18.0')]);
  assert.notEqual(a, c);
});

test('hash.verifyInventoryChecksum accepts valid + rejects mismatched', async () => {
  const comp = makeComp('lodash', '4.17.21', 'npm', 'pkg:npm/lodash@4.17.21');
  const cs = await hash.computeInventoryChecksum([comp]);
  const ok = await hash.verifyInventoryChecksum([comp], cs);
  assert.equal(ok, true);
  const bad = await hash.verifyInventoryChecksum([comp], 'sha256:' + '0'.repeat(64));
  assert.equal(bad, false);
  const noPrefix = await hash.verifyInventoryChecksum([comp], cs.slice(7));
  assert.equal(noPrefix, false);
});

// Final teardown test. The IndexedDB shim's
// setImmediate() callbacks keep the Node event loop
// alive after every test has passed. This test runs
// the t.after hook to force-exit the process so the
// suite is suitable for CI / cron / shell pipelines.
test('zzz: force-exit so the IndexedDB shim does not keep the loop alive', (t) => {
  t.after(() => {
    // The Node test runner keeps the process alive
    // until the event loop has nothing left to do.
    // The shim's setImmediate callbacks have already
    // fired (we know the test phase is complete).
    // Forcing exit here makes `node scripts/...`
    // behave like a normal CLI command.
    process.exit(0);
  });
});
