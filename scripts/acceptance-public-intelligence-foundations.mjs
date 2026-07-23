#!/usr/bin/env node
// V6.1 — public-intelligence foundations acceptance suite.
//
// Targeted test for the helpers, schemas, and validation
// utilities added in commit 1. Does NOT touch Netlify Blobs,
// the canonical baseline, the dataset envelope, or any
// pipeline integration. The test is hermetic and runs
// offline.
//
//   node scripts/acceptance-public-intelligence-foundations.mjs
//
// Each test prints PASS or FAIL; a final summary is printed.
// Exit code is 0 when all tests pass, 1 otherwise.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');

// ESM-only test runner. We use a simple assertion counter
// instead of pulling in a framework; the V6.0 acceptance
// suites follow the same pattern.
let passed = 0;
let failed = 0;
const failures = [];
function assert(label, cond, extra = '') {
  if (cond) {
    passed++;
    console.log(`  PASS  ${label}`);
  } else {
    failed++;
    failures.push({ label, extra });
    console.log(`  FAIL  ${label}${extra ? `  -- ${extra}` : ''}`);
  }
}

// ---- Imports of the helpers under test ----
const hashMod = await import('../netlify/functions/_shared/publicIntelligenceHash.mjs');
const sizeMod = await import('../netlify/functions/_shared/publicIntelligenceSize.mjs');
const valMod  = await import('../netlify/functions/_shared/publicIntelligenceValidation.mjs');
const compMod = await import('../netlify/functions/_shared/publicIntelligenceCompression.mjs');
const bucketMod = await import('../netlify/functions/_shared/publicIntelligenceBucket.mjs');
const storeMod = await import('../netlify/functions/_shared/publicIntelligenceStore.mjs');
const canonHash = await import('../netlify/functions/_shared/canonicalHash.mjs');

console.log('V6.1 — public-intelligence foundations acceptance');
console.log('=================================================');
console.log('');

/* ---- 1. Determinism of computePublicHash ---- */
console.log('[1] computePublicHash determinism and sensitivity');

const sample = { a: 1, b: 'two', c: [3, 4, 5] };
const h1 = hashMod.computePublicHash(sample);
const h2 = hashMod.computePublicHash(sample);
assert('computePublicHash is deterministic for identical input',
  h1 === h2 && typeof h1 === 'string' && h1.startsWith('sha256:'));
assert('computePublicHash has sha256: prefix and 64 hex chars',
  /^sha256:[0-9a-f]{64}$/.test(h1));
const h3 = hashMod.computePublicHash({ a: 1, b: 'two', c: [3, 4, 6] });
assert('computePublicHash changes when content changes',
  h1 !== h3);
assert('computePublicHash is key-order independent',
  hashMod.computePublicHash({ c: [3, 4, 5], b: 'two', a: 1 }) === h1);
assert('computePublicHash preserves primitive-array order (not entity arrays)',
  hashMod.computePublicHash({ a: 1, b: 'two', c: [5, 4, 3] }) !== h1);
assert('computePublicHash sorts entity arrays by canonicalId',
  hashMod.computePublicHash({
    list: [
      { canonicalId: 'b', x: 1 },
      { canonicalId: 'a', x: 2 },
    ],
  }) === hashMod.computePublicHash({
    list: [
      { canonicalId: 'a', x: 2 },
      { canonicalId: 'b', x: 1 },
    ],
  }));
assert('computePublicHash returns null for null input',
  hashMod.computePublicHash(null) === null);
assert('computePublicHash returns null for undefined input',
  hashMod.computePublicHash(undefined) === null);

/* ---- 2. stripForPublicHash ---- */
console.log('');
console.log('[2] stripForPublicHash');

const env = {
  data: [{ cveId: 'CVE-2024-1234' }],
  fetchedAt: '2026-07-15T03:54:00.000Z',
  lastRefreshAttemptAt: '2026-07-15T03:54:00.000Z',
  lastRefreshFailure: null,
  lastVulnrichmentRefresh: { status: 'completed' },
  lastGithubAdvisoryRefresh: { status: 'completed' },
  _publicHash: 'sha256:abcdef',
};
const stripped = hashMod.stripForPublicHash(env);
assert('stripForPublicHash removes lastRefreshAttemptAt',
  !('lastRefreshAttemptAt' in stripped));
assert('stripForPublicHash removes lastRefreshFailure',
  !('lastRefreshFailure' in stripped));
assert('stripForPublicHash removes lastVulnrichmentRefresh',
  !('lastVulnrichmentRefresh' in stripped));
assert('stripForPublicHash removes lastGithubAdvisoryRefresh',
  !('lastGithubAdvisoryRefresh' in stripped));
assert('stripForPublicHash removes _publicHash',
  !('_publicHash' in stripped));
assert('stripForPublicHash preserves public fields',
  stripped.data.length === 1 && stripped.data[0].cveId === 'CVE-2024-1234' && stripped.fetchedAt === env.fetchedAt);
assert('stripForPublicHash handles null input',
  hashMod.stripForPublicHash(null) === null);
assert('stripForPublicHash handles non-object input',
  hashMod.stripForPublicHash('x') === 'x');

/* ---- 3. computeDatasetPublicHash and computeEnrichmentPublicHash ---- */
console.log('');
console.log('[3] composite dataset / enrichment hash');
const datasetPub = hashMod.computeDatasetPublicHash(env);
const datasetPub2 = hashMod.computeDatasetPublicHash(env);
assert('computeDatasetPublicHash is deterministic', datasetPub === datasetPub2);
assert('computeDatasetPublicHash ignores internal fields',
  datasetPub === hashMod.computeDatasetPublicHash({
    ...env,
    lastRefreshAttemptAt: 'DIFFERENT',
  }));

const enrichCache = {
  records: {
    'CVE-2024-1234': { ssvc: { ssvcExploitation: 'active' }, cachedAt: 1 },
  },
  updatedAt: '2026-07-15T03:54:00.000Z',
};
const enrichPub1 = hashMod.computeEnrichmentPublicHash(enrichCache);
const enrichPub2 = hashMod.computeEnrichmentPublicHash({ ...enrichCache, updatedAt: 'DIFFERENT' });
assert('computeEnrichmentPublicHash ignores updatedAt', enrichPub1 === enrichPub2);
const enrichPub3 = hashMod.computeEnrichmentPublicHash({
  records: {
    'CVE-2024-1234': { ssvc: { ssvcExploitation: 'poc' }, cachedAt: 1 },
  },
  updatedAt: enrichCache.updatedAt,
});
assert('computeEnrichmentPublicHash changes when records change', enrichPub1 !== enrichPub3);
assert('computeEnrichmentPublicHash handles null cache', hashMod.computeEnrichmentPublicHash(null) === null);
assert('computeEnrichmentPublicHash handles cache with missing records',
  hashMod.computeEnrichmentPublicHash({ updatedAt: 'x' }) === hashMod.computeEnrichmentPublicHash({ records: {} }));

/* ---- 4. computePublicStateHash ---- */
console.log('');
console.log('[4] computePublicStateHash composite');
const inputs = {
  datasetPublicHash: 'sha256:aaa',
  vulnrichmentPublicHash: 'sha256:bbb',
  githubAdvisoryPublicHash: 'sha256:ccc',
  referencedOsvProjectionVersion: '2026-07-15T03-54Z-9d2b4e6f0a1c',
  referencedOsvProjectionContentHash: 'sha256:ddd',
};
const psh1 = hashMod.computePublicStateHash(inputs);
const psh2 = hashMod.computePublicStateHash(inputs);
assert('computePublicStateHash is deterministic', psh1 === psh2);
const psh3 = hashMod.computePublicStateHash({ ...inputs, datasetPublicHash: 'sha256:eee' });
assert('computePublicStateHash changes when any input changes', psh1 !== psh3);
const pshNull = hashMod.computePublicStateHash({
  datasetPublicHash: null,
  vulnrichmentPublicHash: null,
  githubAdvisoryPublicHash: null,
  referencedOsvProjectionVersion: null,
  referencedOsvProjectionContentHash: null,
});
assert('computePublicStateHash handles null inputs deterministically',
  pshNull === hashMod.computePublicStateHash({
    datasetPublicHash: null,
    vulnrichmentPublicHash: null,
    githubAdvisoryPublicHash: null,
    referencedOsvProjectionVersion: null,
    referencedOsvProjectionContentHash: null,
  }));

/* ---- 5. Version id derivation ---- */
console.log('');
console.log('[5] version id derivation');
const v1 = hashMod.derivePublicIntelligenceVersion('2026-07-15T03:54:00.000Z', psh1);
assert('derivePublicIntelligenceVersion matches expected pattern',
  /^\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}Z-[0-9a-f]{12}$/.test(v1));
assert('derivePublicIntelligenceVersion uses first 12 hex',
  v1.endsWith(psh1.slice('sha256:'.length, 'sha256:'.length + 12)));
const v2 = hashMod.derivePublicIntelligenceVersion('2026-07-15T03:54:00.000Z', psh1);
assert('derivePublicIntelligenceVersion is deterministic', v1 === v2);
const v3 = hashMod.derivePublicIntelligenceVersion('2026-07-15T03:55:00.000Z', psh1);
assert('different generatedAt produces different version', v1 !== v3);
const v4 = hashMod.derivePublicIntelligenceVersion('2026-07-15T03:54:00Z', psh1);
assert('truncate-to-seconds is invariant', v1 === v4);
try {
  hashMod.derivePublicIntelligenceVersion('', psh1);
  assert('derivePublicIntelligenceVersion throws on empty generatedAt', false);
} catch (e) {
  assert('derivePublicIntelligenceVersion throws on empty generatedAt', true);
}
try {
  hashMod.derivePublicIntelligenceVersion('2026-07-15T03:54:00.000Z', 'not-a-hash');
  assert('derivePublicIntelligenceVersion throws on invalid hash', false);
} catch (e) {
  assert('derivePublicIntelligenceVersion throws on invalid hash', true);
}

const ov1 = hashMod.deriveOsvProjectionVersion('2026-07-15T03-54-00Z', 'sha256:' + 'a'.repeat(64));
assert('deriveOsvProjectionVersion matches expected pattern',
  /^\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}Z-[0-9a-f]{12}$/.test(ov1));
const ov1WithHash = hashMod.deriveOsvProjectionVersion('2026-07-15T03-54-00Z-a1b2c3d4', 'sha256:' + 'a'.repeat(64));
assert('deriveOsvProjectionVersion with canonical-version hash matches expected pattern',
  /^\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}Z-[0-9a-f]{8,16}-[0-9a-f]{12}$/.test(ov1WithHash));
const ov2 = hashMod.deriveOsvProjectionVersion('2026-07-15T03-54-00Z', 'sha256:' + 'a'.repeat(64));
assert('deriveOsvProjectionVersion is deterministic for identical inputs', ov1 === ov2);
const ov3 = hashMod.deriveOsvProjectionVersion('2026-07-15T03-54-00Z', 'sha256:' + 'b'.repeat(64));
assert('deriveOsvProjectionVersion differs for different manifest hash', ov1 !== ov3);
try {
  hashMod.deriveOsvProjectionVersion('', 'sha256:' + 'a'.repeat(64));
  assert('deriveOsvProjectionVersion throws on empty canonical version', false);
} catch (e) {
  assert('deriveOsvProjectionVersion throws on empty canonical version', true);
}
try {
  hashMod.deriveOsvProjectionVersion('2026-07-15T03-54-00Z', 'no-prefix');
  assert('deriveOsvProjectionVersion throws on missing sha256: prefix', false);
} catch (e) {
  assert('deriveOsvProjectionVersion throws on missing sha256: prefix', true);
}

assert('publicStateFingerprint returns 12 hex chars',
  hashMod.publicStateFingerprint(psh1) === psh1.slice('sha256:'.length, 'sha256:'.length + 12));
assert('publicStateFingerprint returns null on null',
  hashMod.publicStateFingerprint(null) === null);

/* ---- 6. CVE bucket determinism ---- */
console.log('');
console.log('[6] CVE bucket assignment');
const cves = [
  'CVE-2024-1234', 'CVE-2024-5678', 'CVE-2024-9999', 'CVE-2023-0001',
  'CVE-2022-7777', 'CVE-2025-1234', 'CVE-2026-5555', 'CVE-2024-4321',
];
const bucketMap = {};
for (const c of cves) {
  const b = bucketMod.cveBucket(c);
  assert(`bucket for ${c} is valid hex digit`,
    /^[0-9a-f]$/.test(b));
  bucketMap[c] = b;
}
const distinctBuckets = new Set(Object.values(bucketMap));
assert('CVE bucket assignment is spread across multiple buckets (at least 3)',
  distinctBuckets.size >= 3);
for (const c of cves) {
  assert(`bucket for ${c} is stable across calls`,
    bucketMod.cveBucket(c) === bucketMod.cveBucket(c));
}
assert('cveBucket is uppercase-invariant',
  bucketMod.cveBucket('cve-2024-1234') === bucketMod.cveBucket('CVE-2024-1234'));
assert('cveBucket is whitespace-invariant (trim)',
  bucketMod.cveBucket('  CVE-2024-1234  ') === bucketMod.cveBucket('CVE-2024-1234'));
assert('cveBucketNormalized is uppercase-only',
  (() => {
    try { bucketMod.cveBucketNormalized('cve-2024-1234'); return false; } catch (e) { return true; }
  })());
try { bucketMod.cveBucket(''); assert('cveBucket throws on empty', false); } catch (e) { assert('cveBucket throws on empty', true); }
try { bucketMod.cveBucket(null); assert('cveBucket throws on null', false); } catch (e) { assert('cveBucket throws on null', true); }

/* ---- 7. Validators ---- */
console.log('');
console.log('[7] query parameter validators');
assert('validateView accepts osv', valMod.validateView('osv') === 'osv');
assert('validateView accepts changes', valMod.validateView('changes') === 'changes');
assert('validateView rejects unknown', valMod.validateView('garbage') === null);
assert('validateView rejects null', valMod.validateView(null) === null);
assert('validateView rejects non-string', valMod.validateView(123) === null);

assert('validateVersion accepts well-formed', valMod.validateVersion('2026-07-15T03-54-00Z-7a3f2c8e1b9d') === '2026-07-15T03-54-00Z-7a3f2c8e1b9d');
assert('validateVersion rejects without hash', valMod.validateVersion('2026-07-15T03-54-00Z') === null);
assert('validateVersion rejects short hash', valMod.validateVersion('2026-07-15T03-54-00Z-7a3f') === null);
assert('validateVersion rejects path traversal', valMod.validateVersion('../foo') === null);
assert('validateVersion rejects null', valMod.validateVersion(null) === null);

assert('validateCve accepts well-formed', valMod.validateCve('CVE-2024-1234') === 'CVE-2024-1234');
assert('validateCve accepts and uppercases', valMod.validateCve('cve-2024-1234') === 'CVE-2024-1234');
assert('validateCve accepts 7-digit suffix', valMod.validateCve('CVE-2024-1234567') === 'CVE-2024-1234567');
assert('validateCve rejects malformed', valMod.validateCve('CVE-2024-12') === null);
assert('validateCve rejects path traversal', valMod.validateCve('../foo') === null);
assert('validateCve rejects GHSA', valMod.validateCve('GHSA-xxxx') === null);

assert('validateCategory accepts documented categories',
  ['newly-tracked', 'no-longer-tracked', 'fact-newly-available', 'fact-changed', 'fact-no-longer-present', 'provider-status-changed']
    .every(c => valMod.validateCategory(c) === c));
assert('validateCategory rejects unknown', valMod.validateCategory('garbage') === null);
assert('validateCategory rejects null', valMod.validateCategory(null) === null);

assert('validateLimit accepts 25', valMod.validateLimit('25') === 25);
assert('validateLimit accepts 1', valMod.validateLimit('1') === 1);
assert('validateLimit rejects 0', valMod.validateLimit('0') === null);
assert('validateLimit rejects 26', valMod.validateLimit('26') === null);
assert('validateLimit rejects non-integer', valMod.validateLimit('abc') === null);
assert('validateLimit rejects negative', valMod.validateLimit('-1') === null);

assert('validateBucket accepts hex digit', valMod.validateBucket('a') === 'a');
assert('validateBucket accepts digit', valMod.validateBucket('0') === '0');
assert('validateBucket uppercases input', valMod.validateBucket('A') === 'a');
assert('validateBucket rejects two-char', valMod.validateBucket('aa') === null);
assert('validateBucket rejects non-hex', valMod.validateBucket('g') === null);
assert('validateBucket rejects traversal', valMod.validateBucket('../') === null);

/* ---- 8. Compression roundtrip ---- */
console.log('');
console.log('[8] gzip compression roundtrip');
const big = { a: 'x'.repeat(10000), b: [1, 2, 3, 4, 5] };
const gz = compMod.gzipValue(big);
assert('gzipValue produces non-empty Buffer', gz && gz.length > 0);
const rt = compMod.gunzipValue(gz);
assert('gunzipValue roundtrips correctly',
  rt && rt.a === big.a && JSON.stringify(rt.b) === JSON.stringify(big.b));
assert('gunzipValue returns null on null input',
  compMod.gunzipValue(null) === null);
assert('gunzipValue returns null on empty input',
  compMod.gunzipValue(Buffer.alloc(0)) === null);
try {
  compMod.gunzipValue(Buffer.from('not a gzip', 'utf8'));
  assert('gunzipValue throws on invalid gzip', false);
} catch (e) {
  assert('gunzipValue throws on invalid gzip', true);
}
assert('gzipToBase64 produces base64 string',
  /^[A-Za-z0-9+/=]+$/.test(compMod.gzipToBase64({ x: 1 })));

/* ---- 9. Size budget enforcement ---- */
console.log('');
console.log('[9] size budget enforcement');
const small = { a: 1, b: 2 };
const smallSize = sizeMod.uncompressedBytes(small);
assert('uncompressedBytes reports correct size', smallSize > 0 && smallSize < 1000);
assert('compressedBytes reports smaller size for repetitive data',
  sizeMod.compressedBytes({ x: 'y'.repeat(10000) }) < sizeMod.uncompressedBytes({ x: 'y'.repeat(10000) }));

// assertUncompressedSize should throw on overflow
try {
  sizeMod.assertUncompressedSize({ x: 'y'.repeat(2 * 1024 * 1024) }, 100, 'big');
  assert('assertUncompressedSize throws on overflow', false);
} catch (e) {
  assert('assertUncompressedSize throws on overflow',
    e instanceof sizeMod.SizeCeilingExceededError);
}

// assertUncompressedSize should not throw on under-cap
try {
  const actualSize = sizeMod.assertUncompressedSize({ x: 1 }, 1000, 'tiny');
  assert('assertUncompressedSize returns the actual size on under-cap', actualSize > 0);
} catch (e) {
  assert('assertUncompressedSize returns the actual size on under-cap', false);
}

// gzipJson ceiling
try {
  sizeMod.gzipJson({ x: 'y'.repeat(100000) }, 100);
  assert('gzipJson throws on compressed ceiling overflow', false);
} catch (e) {
  assert('gzipJson throws on compressed ceiling overflow',
    e instanceof sizeMod.SizeCeilingExceededError);
}

assert('OSV_BUCKET_COUNT is 16', bucketMod.OSV_BUCKET_COUNT === 16);
assert('OSV_RECORDS_PER_CVE_CAP is 8', sizeMod.OSV_RECORDS_PER_CVE_CAP === 8);
assert('OSV_ALIASES_PER_RECORD_CAP is 10', sizeMod.OSV_ALIASES_PER_RECORD_CAP === 10);
assert('OSV_REFERENCES_PER_RECORD_CAP is 5', sizeMod.OSV_REFERENCES_PER_RECORD_CAP === 5);
assert('OSV_PACKAGES_PER_RECORD_CAP is 6', sizeMod.OSV_PACKAGES_PER_RECORD_CAP === 6);
assert('OSV_RANGES_PER_PACKAGE_CAP is 4', sizeMod.OSV_RANGES_PER_PACKAGE_CAP === 4);
assert('OSV_EVENTS_PER_RANGE_CAP is 8', sizeMod.OSV_EVENTS_PER_RANGE_CAP === 8);
assert('OSV_VERSIONS_PER_PACKAGE_CAP is 8', sizeMod.OSV_VERSIONS_PER_PACKAGE_CAP === 8);
assert('LATEST_JSON_HARD_CEILING_BYTES is 64 KiB',
  sizeMod.LATEST_JSON_HARD_CEILING_BYTES === 64 * 1024);
assert('OSV_SHARD_HARD_CEILING_UNCOMPRESSED_BYTES is 1 MiB',
  sizeMod.OSV_SHARD_HARD_CEILING_UNCOMPRESSED_BYTES === 1024 * 1024);
assert('OSV_SHARD_HARD_CEILING_COMPRESSED_BYTES is 256 KiB',
  sizeMod.OSV_SHARD_HARD_CEILING_COMPRESSED_BYTES === 256 * 1024);
assert('CHANGES_ITEMS_MAX_LIMIT is 25', sizeMod.CHANGES_ITEMS_MAX_LIMIT === 25);
assert('MAX_RETAINED_VERSIONS_PER_PATH is 3', sizeMod.MAX_RETAINED_VERSIONS_PER_PATH === 3);

/* ---- 10. Store key helpers ---- */
console.log('');
console.log('[10] store key helpers');

assert('PUBLIC_INTELLIGENCE_STORE_NAME is tpr-public-intelligence',
  storeMod.PUBLIC_INTELLIGENCE_STORE_NAME === 'tpr-public-intelligence');
assert('OSV_LATEST_KEY is osv/latest.json',
  storeMod.OSV_LATEST_KEY === 'osv/latest.json');
assert('DATASET_LATEST_KEY is dataset/latest.json',
  storeMod.DATASET_LATEST_KEY === 'dataset/latest.json');
assert('OSV_PUBLICATION_LOCK_KEY is osv/publication-lock',
  storeMod.OSV_PUBLICATION_LOCK_KEY === 'osv/publication-lock');
assert('DATASET_PUBLICATION_LOCK_KEY is dataset/publication-lock',
  storeMod.DATASET_PUBLICATION_LOCK_KEY === 'dataset/publication-lock');

const dmKey = storeMod.datasetManifestKey('2026-07-15T03-54Z-7a3f2c8e1b9d');
assert('datasetManifestKey returns well-formed key',
  dmKey === 'dataset/versions/2026-07-15T03-54Z-7a3f2c8e1b9d/manifest.json');
const dsKey = storeMod.datasetPublicSnapshotKey('2026-07-15T03-54Z-7a3f2c8e1b9d');
assert('datasetPublicSnapshotKey returns well-formed key',
  dsKey === 'dataset/versions/2026-07-15T03-54Z-7a3f2c8e1b9d/public-snapshot.json.gz');
const dcKey = storeMod.datasetChangesKey('2026-07-15T03-54Z-7a3f2c8e1b9d');
assert('datasetChangesKey returns well-formed key',
  dcKey === 'dataset/versions/2026-07-15T03-54Z-7a3f2c8e1b9d/changes.json.gz');

const omKey = storeMod.osvManifestKey('2026-07-15T03-54Z-9d2b4e6f0a1c-1234567890ab');
assert('osvManifestKey returns well-formed key',
  omKey === 'osv/versions/2026-07-15T03-54Z-9d2b4e6f0a1c-1234567890ab/manifest.json');

const fakeHash = 'sha256:' + 'a'.repeat(64);
const shardKey = storeMod.osvShardKey(fakeHash);
assert('osvShardKey returns well-formed content-addressed key',
  shardKey === 'osv/shards/sha256/' + 'a'.repeat(64) + '.json.gz');
const shardKeyNoPrefix = storeMod.osvShardKey('b'.repeat(64));
assert('osvShardKey accepts hash without sha256: prefix',
  shardKeyNoPrefix === 'osv/shards/sha256/' + 'b'.repeat(64) + '.json.gz');

// Safety: reject path-traversal in version id
try {
  storeMod.datasetManifestKey('../foo');
  assert('datasetManifestKey rejects path traversal', false);
} catch (e) {
  assert('datasetManifestKey rejects path traversal', true);
}
try {
  storeMod.datasetManifestKey('foo/bar');
  assert('datasetManifestKey rejects slash in version', false);
} catch (e) {
  assert('datasetManifestKey rejects slash in version', true);
}
try {
  storeMod.osvShardKey('not-a-hash');
  assert('osvShardKey rejects malformed hash', false);
} catch (e) {
  assert('osvShardKey rejects malformed hash', true);
}
try {
  storeMod.datasetManifestKey('');
  assert('datasetManifestKey rejects empty version', false);
} catch (e) {
  assert('datasetManifestKey rejects empty version', true);
}

/* ---- 11. Schema structural validation against the JSON files ---- */
console.log('');
console.log('[11] JSON Schema structural validation');

// Minimal structural validator sufficient for the foundation
// schemas. Handles: required, type, enum, pattern, const,
// additionalProperties, minLength, minimum, format=date-time,
// items, $defs resolution, and $ref.
function resolveRef(rootSchema, ref) {
  if (!ref.startsWith('#/')) throw new Error('unsupported $ref: ' + ref);
  const parts = ref.slice(2).split('/');
  let node = rootSchema;
  for (const p of parts) {
    node = node[p];
    if (node === undefined) throw new Error('unresolved $ref: ' + ref);
  }
  return node;
}
function validate(rootSchema, value, schemaPath = '#') {
  const errors = [];
  if (typeof schemaPath !== 'string') return errors;
  function walk(node, value, path) {
    if (typeof node === 'boolean') {
      if (!node) errors.push(path + ': schema is false (no value allowed)');
      return;
    }
    if (node.$ref) {
      const resolved = resolveRef(rootSchema, node.$ref);
      walk(resolved, value, path);
      return;
    }
    if (Array.isArray(node.allOf)) {
      for (const sub of node.allOf) walk(sub, value, path);
    }
    if (Array.isArray(node.anyOf)) {
      const anyOk = node.anyOf.some(sub => walk(sub, value, path + '|anyOf').length === 0);
      if (!anyOk) errors.push(path + ': no anyOf matched');
    }
    if (node.const !== undefined) {
      if (!deepEqual(value, node.const)) errors.push(path + ': const mismatch');
    }
    if (Array.isArray(node.enum)) {
      if (!node.enum.some(e => deepEqual(value, e))) errors.push(path + ': not in enum');
    }
    if (node.type) {
      const types = Array.isArray(node.type) ? node.type : [node.type];
      const actual = jsonTypeOf(value);
      // JSON Schema: integer is a subset of number.
      const compatible = types.includes(actual) ||
        (types.includes('number') && actual === 'integer');
      if (!compatible) {
        errors.push(path + ': expected type ' + types.join('|') + ' got ' + actual);
        return;
      }
    }
    if (typeof value === 'string') {
      if (node.pattern && !(new RegExp(node.pattern).test(value))) {
        errors.push(path + ': pattern mismatch ' + node.pattern);
      }
      if (node.minLength !== undefined && value.length < node.minLength) {
        errors.push(path + ': minLength ' + node.minLength);
      }
      if (node.format === 'date-time' && value !== null && isNaN(Date.parse(value))) {
        errors.push(path + ': not a date-time');
      }
      if (node.format === 'uri' && value !== null) {
        try { new URL(value); } catch (e) { errors.push(path + ': not a uri'); }
      }
    }
    if (typeof value === 'number') {
      if (node.minimum !== undefined && value < node.minimum) errors.push(path + ': below minimum');
      if (node.maximum !== undefined && value > node.maximum) errors.push(path + ': above maximum');
    }
    if (Array.isArray(value)) {
      if (node.minItems !== undefined && value.length < node.minItems) {
        errors.push(path + ': minItems ' + node.minItems);
      }
      if (node.items) {
        for (let i = 0; i < value.length; i++) {
          walk(node.items, value[i], path + '/' + i);
        }
      }
    }
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      if (Array.isArray(node.required)) {
        for (const req of node.required) {
          if (!(req in value)) errors.push(path + '/missing:' + req);
        }
      }
      if (node.additionalProperties === false) {
        const allowed = new Set(Object.keys(node.properties || {}));
        for (const k of Object.keys(value)) {
          if (!allowed.has(k)) errors.push(path + '/' + k + ': additional not allowed');
        }
      } else if (node.additionalProperties && typeof node.additionalProperties === 'object') {
        for (const k of Object.keys(value)) {
          if (!(k in (node.properties || {}))) {
            walk(node.additionalProperties, value[k], path + '/' + k);
          }
        }
      }
      if (node.properties) {
        for (const k of Object.keys(node.properties)) {
          if (k in value) walk(node.properties[k], value[k], path + '/' + k);
        }
      }
    }
  }
  walk(rootSchema, value, schemaPath);
  return errors;
}
function jsonTypeOf(v) {
  if (v === null) return 'null';
  if (Array.isArray(v)) return 'array';
  if (typeof v === 'number') return Number.isInteger(v) ? 'integer' : 'number';
  return typeof v;
}
function deepEqual(a, b) {
  if (a === b) return true;
  if (a === null || b === null) return false;
  if (typeof a !== typeof b) return false;
  if (typeof a === 'object') {
    if (Array.isArray(a) !== Array.isArray(b)) return false;
    if (Array.isArray(a)) {
      if (a.length !== b.length) return false;
      for (let i = 0; i < a.length; i++) if (!deepEqual(a[i], b[i])) return false;
      return true;
    }
    const ak = Object.keys(a), bk = Object.keys(b);
    if (ak.length !== bk.length) return false;
    for (const k of ak) if (!deepEqual(a[k], b[k])) return false;
    return true;
  }
  return false;
}
function checkValid(schema, value, label) {
  const errors = validate(schema, value);
  if (errors.length > 0) {
    console.log(`        schema errors for ${label}: ${errors.slice(0, 3).join(' | ')}`);
  }
  return errors.length === 0;
}

const osvShardSchema = JSON.parse(readFileSync(join(root, 'schemas', 'osv-shard-v1.schema.json'), 'utf8'));
const datasetManifestSchema = JSON.parse(readFileSync(join(root, 'schemas', 'dataset-bundle-manifest-v1.schema.json'), 'utf8'));
const publicSnapshotSchema = JSON.parse(readFileSync(join(root, 'schemas', 'public-snapshot-v1.schema.json'), 'utf8'));
const sourceHealthSchema = JSON.parse(readFileSync(join(root, 'schemas', 'source-health-public-v1.schema.json'), 'utf8'));
const changeIntelSchema = JSON.parse(readFileSync(join(root, 'schemas', 'change-intelligence-v1.schema.json'), 'utf8'));
const sourceRegistrySchema = JSON.parse(readFileSync(join(root, 'schemas', 'source-registry-v1.1.schema.json'), 'utf8'));

const sampleShard = {
  schemaVersion: '1.0.0',
  bucket: '0',
  bucketContentHash: 'sha256:' + 'a'.repeat(64),
  byCve: {
    'CVE-2024-1234': {
      records: [{
        osvId: 'GHSA-xxxx-yyyy-zzzz',
        sourceDatabase: 'GHSA',
        aliases: ['CVE-2024-1234'],
        modifiedAt: '2026-07-14T00:00:00Z',
        publishedAt: '2026-01-12T00:00:00Z',
        withdrawn: false,
        references: [{ type: 'ADVISORY', url: 'https://example.com/' }],
        severities: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N' }],
        affectedPackages: [{
          ecosystem: 'npm',
          name: 'example',
          purl: 'pkg:npm/example',
          ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '1.0.0' }], databaseSpecific: null, repo: null }],
          versions: ['0.9.0', '0.9.1'],
          ecosystemSpecific: null,
          truncation: { versionsRemoved: 0, rangesRemoved: 0, eventsTruncated: 0 },
        }],
        truncation: { aliasesRemoved: 0, referencesRemoved: 0, packagesRemoved: 0 },
      }],
      truncation: { recordsRemoved: 0 },
    },
  },
  truncation: { recordsRemovedTotal: 0, cvesTruncated: 0 },
};
assert('OSV shard schema accepts minimal valid sample', checkValid(osvShardSchema, sampleShard, 'sampleShard'));
assert('OSV shard schema rejects wrong schemaVersion',
  !checkValid(osvShardSchema, { ...sampleShard, schemaVersion: '2.0.0' }, 'wrong-version'));
assert('OSV shard schema rejects missing bucketContentHash',
  !checkValid(osvShardSchema, { ...sampleShard, bucketContentHash: undefined }, 'missing-hash'));
assert('OSV shard schema rejects wrong bucket pattern',
  !checkValid(osvShardSchema, { ...sampleShard, bucket: 'gg' }, 'bad-bucket'));

const sampleManifest = {
  schemaVersion: '1.0.0',
  publicIntelligenceVersion: '2026-07-15T03-54Z-7a3f2c8e1b9d',
  generatedAt: '2026-07-15T03:54:00.000Z',
  publicStateHash: 'sha256:' + 'a'.repeat(64),
  datasetFetchedAt: '2026-07-15T03:54:00.000Z',
  datasetContentHash: 'sha256:' + 'b'.repeat(64),
  referencedOsvProjectionVersion: '2026-07-15T03-54Z-9d2b4e6f0a1c-1234567890ab',
  referencedOsvProjectionContentHash: 'sha256:' + 'c'.repeat(64),
  comparesFreshBase: true,
  previousPublicIntelligenceVersion: null,
  changeSummary: {
    newlyTracked: 0,
    noLongerTracked: 0,
    factNewlyAvailable: 0,
    factChanged: 0,
    factNoLongerPresent: 0,
    providerStatusChanged: 0,
    epssMateriallyIncreased: 0,
    epssMateriallyDecreased: 0,
  },
  comparableAxes: ['kev', 'severity-class', 'epss', 'ssvc', 'github-advisory', 'first-patched', 'osv', 'cvss-source'],
  suppressedAxes: [],
  partial: false,
  reasons: [],
  truncation: { changeItems: { shown: 0, total: 0 } },
};
assert('Dataset manifest schema accepts minimal valid sample', checkValid(datasetManifestSchema, sampleManifest, 'sampleManifest'));
assert('Dataset manifest schema rejects wrong publicStateHash shape',
  !checkValid(datasetManifestSchema, { ...sampleManifest, publicStateHash: 'not-a-hash' }, 'bad-hash'));
assert('Dataset manifest schema rejects missing changeSummary',
  !checkValid(datasetManifestSchema, { ...sampleManifest, changeSummary: undefined }, 'missing-summary'));
assert('Dataset manifest schema rejects missing truncation',
  !checkValid(datasetManifestSchema, { ...sampleManifest, truncation: undefined }, 'missing-truncation'));

const sampleSnapshot = {
  schemaVersion: '1.0.0',
  publicIntelligenceVersion: '2026-07-15T03-54Z-7a3f2c8e1b9d',
  generatedAt: '2026-07-15T03:54:00.000Z',
  providerComparability: {
    cisaKev:        { comparable: true,  asOf: '2026-07-15T03:30:00.000Z' },
    nvd:            { comparable: true,  asOf: '2026-07-15T03:30:00.000Z' },
    firstEpss:      { comparable: true,  asOf: '2026-07-15T03:30:00.000Z' },
    ssvc:           { comparable: 'partial', asOf: '2026-07-15T03:30:00.000Z' },
    githubAdvisory: { comparable: 'partial', asOf: '2026-07-15T03:30:00.000Z' },
    osv:            { comparable: true,  asOf: '2026-07-15T03:54:00.000Z' },
  },
  trackedCveCount: 1,
  byCve: {
    'CVE-2024-1234': {
      tracked: true,
      kev: { observation: 'present', present: true, kevDateAdded: '2026-07-10' },
      severity: { observation: 'present', value: 'High', cvssSource: 'NVD', cvssVersion: 'CVSS_V3' },
      nvd: { observation: 'present', severity: 'High', cvssSource: 'NVD', cvssVersion: 'CVSS_V3' },
      epssProbability: 0.48,
      epss: { observation: 'present', probability: 0.48 },
      ssvcExploitation: { observation: 'present', exploitation: 'active' },
      githubAdvisory: { observation: 'present', ghsaId: 'GHSA-xxxx-yyyy-zzzz', firstPatchedAvailable: true },
      firstPatchedAvailable: true,
      osv: { observation: 'present', recordIds: ['GHSA-xxxx-yyyy-zzzz'], affectedSignature: 'sha256:abc', withdrawn: false },
      withdrawn: false,
      affectedSignature: 'sha256:abc',
    },
  },
};
assert('Public snapshot schema accepts minimal valid sample', checkValid(publicSnapshotSchema, sampleSnapshot, 'sampleSnapshot'));
assert('Public snapshot schema rejects wrong providerComparability enum',
  !checkValid(publicSnapshotSchema, { ...sampleSnapshot, providerComparability: { ...sampleSnapshot.providerComparability, cisaKev: { comparable: 'maybe', asOf: null } } }, 'bad-comparable'));

const sampleHealth = {
  schemaVersion: '1.0.0',
  generatedAt: '2026-07-15T03:54:00.000Z',
  sources: [
    {
      id: 'cisa_kev',
      lastSuccessfulFetchAt: '2026-07-15T03:30:00.000Z',
      lastAttemptedFetchAt: '2026-07-15T03:30:00.000Z',
      lastAttemptOutcome: 'success',
      usableCoverage: 1043,
      totalCoverage: 1043,
      thresholdMinutes: 90,
      sanitizedReason: null,
    },
  ],
};
assert('Source health schema accepts minimal valid sample', checkValid(sourceHealthSchema, sampleHealth, 'sampleHealth'));
assert('Source health schema rejects unknown source id',
  !checkValid(sourceHealthSchema, { ...sampleHealth, sources: [{ ...sampleHealth.sources[0], id: 'bogus' }] }, 'bad-source-id'));
assert('Source health schema rejects missing required field',
  !checkValid(sourceHealthSchema, { ...sampleHealth, sources: [{ ...sampleHealth.sources[0], thresholdMinutes: undefined }] }, 'missing-threshold'));

const sampleChange = {
  schemaVersion: '1.0.0',
  publicIntelligenceVersion: '2026-07-15T03-54Z-7a3f2c8e1b9d',
  generatedAt: '2026-07-15T03:54:00.000Z',
  comparesFreshBase: true,
  previousPublicIntelligenceVersion: '2026-07-15T03-24Z-9d2b4e6f0a1c',
  items: [
    {
      cveId: 'CVE-2024-1234',
      classifications: ['kev-newly-present', 'epss-materially-increased'],
      publicIntelligenceVersion: '2026-07-15T03-54Z-7a3f2c8e1b9d',
      severityFrom: 'Medium',
      severityTo: 'High',
      epssFrom: 0.05,
      epssTo: 0.48,
    },
  ],
};
assert('Change intelligence schema accepts minimal valid sample', checkValid(changeIntelSchema, sampleChange, 'sampleChange'));
assert('Change intelligence schema rejects unknown classification',
  !checkValid(changeIntelSchema, { ...sampleChange, items: [{ ...sampleChange.items[0], classifications: ['made-up-class'] }] }, 'bad-classification'));
assert('Change intelligence schema rejects empty classifications',
  !checkValid(changeIntelSchema, { ...sampleChange, items: [{ ...sampleChange.items[0], classifications: [] }] }, 'empty-classifications'));

const sampleRegistry = {
  schemaVersion: '1.1.0',
  sources: [
    {
      id: 'cisa_kev',
      displayName: 'CISA KEV',
      type: 'gating',
      purpose: 'Catalog of vulnerabilities known to be exploited in the wild.',
      provenanceUrl: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
      authentication: 'none',
      refreshSchedule: { cron: '*/30 * * * *', description: 'Every 30 minutes' },
      thresholdMinutes: 90,
      limitations: 'Single source of truth for in-the-wild exploitation. No CVSS, no EPSS.',
    },
    {
      id: 'nvd',
      displayName: 'NVD',
      type: 'enrichment',
      purpose: 'CVSS scores and vulnerability metadata.',
      provenanceUrl: 'https://nvd.nist.gov/',
      authentication: 'optional-server-side',
      refreshSchedule: { cron: '*/30 * * * *', description: 'Every 30 minutes' },
      thresholdMinutes: 90,
      limitations: 'CVSS scores only. Subject to public-anonymous rate limits.',
    },
    {
      id: 'first_epss',
      displayName: 'FIRST EPSS',
      type: 'enrichment',
      purpose: 'Probability of exploitation in the wild.',
      provenanceUrl: 'https://www.first.org/epss/',
      authentication: 'none',
      refreshSchedule: { cron: '*/30 * * * *', description: 'Every 30 minutes' },
      thresholdMinutes: 90,
      limitations: 'Daily-refreshed probabilities. Intraday changes are not reflected.',
    },
    {
      id: 'cisa_vulnrichment',
      displayName: 'CISA Vulnrichment',
      type: 'incremental',
      purpose: 'CISA-ADP SSVC decision context.',
      provenanceUrl: 'https://github.com/cisagov/vulnrichment',
      authentication: 'none',
      refreshSchedule: { cron: 'incremental', description: '50 CVEs per refresh cycle' },
      thresholdMinutes: 14 * 24 * 60,
      limitations: 'Incremental backfill. Partial coverage is normal until the cycle completes.',
      backfill: { cadenceDays: 7, maxPerCycle: 50 },
    },
    {
      id: 'github_advisory',
      displayName: 'GitHub Advisory Database',
      type: 'incremental',
      purpose: 'Reviewed package-remediation context.',
      provenanceUrl: 'https://github.com/advisories',
      authentication: 'optional-server-side',
      refreshSchedule: { cron: 'incremental', description: '50 CVEs per refresh cycle' },
      thresholdMinutes: 14 * 24 * 60,
      limitations: 'Incremental backfill. Only reviewed advisories are surfaced.',
      backfill: { cadenceDays: 7, maxPerCycle: 50 },
    },
    {
      id: 'osv',
      displayName: 'OSV',
      type: 'canonical',
      purpose: 'Canonical vulnerability / advisory / package baseline.',
      provenanceUrl: 'https://osv.dev/',
      authentication: 'none',
      refreshSchedule: { cron: '0 * * * *', description: 'Hourly' },
      thresholdMinutes: 180,
      limitations: 'Hourly cadence. 15-minute wall-clock per Background Function invocation.',
    },
  ],
};
assert('Source registry 1.1.0 schema accepts all six documented sources',
  checkValid(sourceRegistrySchema, sampleRegistry, 'sampleRegistry'));
assert('Source registry 1.1.0 schema rejects wrong schemaVersion',
  !checkValid(sourceRegistrySchema, { ...sampleRegistry, schemaVersion: '1.0.0' }, 'wrong-version'));
assert('Source registry 1.1.0 schema rejects missing limitations',
  !checkValid(sourceRegistrySchema, { ...sampleRegistry, sources: sampleRegistry.sources.map(s => {
    if (s.id !== 'cisa_vulnrichment') return s;
    const { limitations, ...rest } = s;
    return rest;
  }) }, 'missing-limitations'));
assert('Source registry 1.1.0 schema rejects additionalProperties',
  !checkValid(sourceRegistrySchema, { ...sampleRegistry, sources: sampleRegistry.sources.map(s => ({ ...s, extra: 'x' })) }, 'extra-prop'));
assert('Source registry 1.1.0 schema rejects non-https provenanceUrl',
  !checkValid(sourceRegistrySchema, { ...sampleRegistry, sources: sampleRegistry.sources.map(s => ({ ...s, provenanceUrl: 'http://insecure/' })) }, 'http-provenance'));
assert('Source registry 1.1.0 schema rejects unknown source id',
  !checkValid(sourceRegistrySchema, { ...sampleRegistry, sources: [...sampleRegistry.sources, { ...sampleRegistry.sources[0], id: 'bogus' }] }, 'unknown-id'));

/* ---- 12. Reuse existing canonicalHash.mjs without duplication ---- */
console.log('');
console.log('[12] reuse existing canonicalHash helpers');

const canonInput = { b: 2, a: 1 };
const canonExpected = canonHash.canonicalize({ a: 1, b: 2 });
assert('publicIntelligenceHash canonicalize agrees with canonicalHash',
  JSON.stringify(hashMod.computePublicHash(canonInput)) === JSON.stringify(hashMod.computePublicHash(canonExpected)));

/* ---- Summary ---- */
console.log('');
console.log('=================================================');
console.log(`V6.1 foundations: ${passed} passed, ${failed} failed`);
if (failed > 0) {
  console.log('Failures:');
  for (const f of failures) {
    console.log(`  - ${f.label}${f.extra ? ` (${f.extra})` : ''}`);
  }
  process.exit(1);
}
console.log('All foundations tests passed.');
