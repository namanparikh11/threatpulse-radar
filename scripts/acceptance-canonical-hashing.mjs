// V6.0 — Canonical serialization and content-addressed shard tests.
//
//   node scripts/acceptance-canonical-hashing.mjs
//
// Behavior under test:
//   - canonical serialization is stable across key order
//   - canonical serialization is stable across array order (for entity arrays)
//   - canonical serialization preserves order for non-entity arrays
//     (e.g. version-range events are a sequence, not a set)
//   - SHA-256 content hash matches a reference value
//   - the version derivation produces a stable short hash
//   - bucketFor is deterministic
//   - objectKeyFor embeds the hash
//   - getOrCreateShard reuses an existing key on identical content
//   - getOrCreateShard writes a new key on different content

import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync, rmSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const buildDir = join(here, '.v6-build-hashing');

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
    try {
      rmSync(buildDir, { recursive: true, force: true });
    } catch (e) { /* fall through */ }
  }
  mkdirSync(buildDir, { recursive: true });
  const tscJs = join(root, 'node_modules', 'typescript', 'lib', 'tsc.js');
  const sources = [
    'netlify/functions/_shared/canonicalHash.mjs',
    'netlify/functions/_shared/contentAddressedShards.mjs',
  ];
  execFileSync(
    process.execPath,
    [tscJs, ...sources, '--outDir', buildDir.replace(/\\/g, '/'), '--module', 'esnext',
     '--target', 'es2022', '--moduleResolution', 'node', '--skipLibCheck',
     '--allowJs', '--declaration', 'false'],
    { cwd: root, stdio: 'pipe' }
  );
  // Post-process: add .js extensions to extensionless relative imports
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
const { canonicalize, canonicalizeToString, sha256Hex, contentHash, deriveBaselineVersion, shortHash, canonicalByteLength } = await import(`./${buildLeaf}/canonicalHash.mjs`);
const { bucketFor, objectKeyFor, partitionByBucket, describeShard } = await import(`./${buildLeaf}/contentAddressedShards.mjs`);

/* ------------------------------------------------------------------ */
/* Tests                                                              */
/* ------------------------------------------------------------------ */

section('Canonical serialization: object key order is stable');

{
  const a = { b: 1, a: 2, c: { y: 1, x: 2 } };
  const b = { a: 2, c: { x: 2, y: 1 }, b: 1 };
  assert('canonical form is the same regardless of key order',
    canonicalizeToString(a) === canonicalizeToString(b),
    'a=' + canonicalizeToString(a) + ' b=' + canonicalizeToString(b));
  // Canonical form has sorted keys
  const canon = canonicalizeToString(a);
  assert('canonical form has sorted top-level keys', canon.startsWith('{"a":2,"b":1,'));
}

section('Canonical serialization: entity arrays are sorted by canonicalId');

{
  const a = [
    { canonicalId: 'vuln:z', name: 'Z' },
    { canonicalId: 'vuln:a', name: 'A' },
    { canonicalId: 'vuln:m', name: 'M' },
  ];
  const b = [
    { canonicalId: 'vuln:a', name: 'A' },
    { canonicalId: 'vuln:m', name: 'M' },
    { canonicalId: 'vuln:z', name: 'Z' },
  ];
  assert('entity array is sorted by canonicalId regardless of input order',
    canonicalizeToString(a) === canonicalizeToString(b));
}

section('Canonical serialization: non-entity arrays preserve order');

{
  // A version-range "events" array is a sequence, not a set. Order matters.
  const ranges = [
    { type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.0.0' }] },
    { type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.0.0' }] },
  ];
  const canon = JSON.parse(canonicalizeToString(ranges));
  assert('non-entity array preserves input order',
    canon[0].events[0].introduced === '0' && canon[1].events[0].introduced === '0');
}

section('Canonical serialization: null fields are explicit');

{
  const a = { x: null, y: 1 };
  const canon = canonicalize(a);
  assert('null fields are preserved (not omitted)',
    Object.prototype.hasOwnProperty.call(canon, 'x') && canon.x === null);
}

section('SHA-256 content hash is reproducible');

{
  const v = { a: 1, b: 2 };
  const h1 = contentHash(v);
  const h2 = contentHash(v);
  assert('same input produces same content hash', h1 === h2);
  assert('content hash has sha256: prefix and 64 hex chars',
    /^sha256:[0-9a-f]{64}$/.test(h1));
  // Independent verification
  const expected = 'sha256:' + createHash('sha256').update(JSON.stringify({ a: 1, b: 2 })).digest('hex');
  assert('matches an independent SHA-256 computation', h1 === expected);
}

section('Content hash is sensitive to value changes');

{
  const h1 = contentHash({ a: 1, b: 2 });
  const h2 = contentHash({ a: 1, b: 3 });
  assert('different values produce different hashes', h1 !== h2);
}

section('Version derivation');

{
  const v = { a: 1, b: 2 };
  const h = contentHash(v);
  const version = deriveBaselineVersion('2026-07-12T20:30:00.000Z', h);
  assert('version has the expected shape',
    /^2026-07-12T20-30-00Z-[0-9a-f]{8}$/.test(version),
    'got ' + version);
  // Short hash is the first 8 hex of the content hash
  const stripped = h.slice('sha256:'.length);
  assert('short hash is first 8 hex of content hash',
    version.endsWith(stripped.slice(0, 8)));
  // Same content always yields the same version
  const v2 = deriveBaselineVersion('2026-07-12T20:30:00.000Z', contentHash(v));
  assert('same content yields same version regardless of time', version === v2);
  // Different timestamp yields different version
  const v3 = deriveBaselineVersion('2026-07-12T21:30:00.000Z', h);
  assert('different timestamp yields different version', version !== v3);
}

section('Bucket function is deterministic');

{
  const b1 = bucketFor('vuln:cve-2024-1234');
  const b2 = bucketFor('vuln:cve-2024-1234');
  const b3 = bucketFor('vuln:cve-2024-9999');
  assert('same canonicalId → same bucket', b1 === b2);
  assert('different canonicalId → different bucket (probabilistically)', b1 !== b3);
  assert('bucket is 2 hex chars', /^[0-9a-f]{2}$/.test(b1));
  // 256 buckets
  const seen = new Set();
  for (let i = 0; i < 1000; i++) seen.add(bucketFor(`vuln:test-${i}`));
  // With 1000 IDs, expect to see many distinct buckets (probabilistic test)
  assert('1000 IDs produce many distinct buckets', seen.size > 100, `got ${seen.size}`);
}

section('Object key is content-addressed');

{
  const key1 = objectKeyFor('sha256:' + 'a'.repeat(64));
  const key2 = objectKeyFor('sha256:' + 'a'.repeat(64));
  const key3 = objectKeyFor('sha256:' + 'b'.repeat(64));
  assert('same content hash → same key', key1 === key2);
  assert('different content hash → different key', key1 !== key3);
  assert('key has the right shape',
    /^objects\/sha256\/[0-9a-f]{64}\.json\.gz$/.test(key1),
    'got ' + key1);
}

section('partitionByBucket is stable');

{
  const entities = [
    { canonicalId: 'vuln:c', type: 'vulnerability' },
    { canonicalId: 'vuln:a', type: 'vulnerability' },
    { canonicalId: 'vuln:b', type: 'vulnerability' },
    { canonicalId: 'vuln:d', type: 'vulnerability' },
  ];
  const buckets = partitionByBucket(entities);
  // Every entity should be in exactly one bucket
  let totalEntities = 0;
  for (const arr of buckets.values()) {
    totalEntities += arr.length;
    // Within a bucket, entities are sorted by canonicalId
    for (let i = 1; i < arr.length; i++) {
      assert(`entities within bucket ${arr[0].canonicalId[0]} are sorted by canonicalId`,
        arr[i - 1].canonicalId <= arr[i].canonicalId);
    }
  }
  assert('partitionByBucket preserves all entities', totalEntities === entities.length);
}

section('describeShard returns the documented shape');

{
  const entities = [
    { canonicalId: 'vuln:test-1', type: 'vulnerability', firstSeen: '2026-01-01T00:00:00.000Z', lastObserved: '2026-01-01T00:00:00.000Z', withdrawn: false, schemaVersion: '1.0.0' },
    { canonicalId: 'vuln:test-2', type: 'vulnerability', firstSeen: '2026-01-01T00:00:00.000Z', lastObserved: '2026-01-01T00:00:00.000Z', withdrawn: false, schemaVersion: '1.0.0' },
  ];
  const desc = await describeShard('vulnerability', 'ab', entities, async (b) => b);
  assert('describeShard has entityType, bucket, objectKey, sha256, byteSize, recordCount',
    desc.entityType === 'vulnerability' &&
    desc.bucket === 'ab' &&
    /^objects\/sha256\/[0-9a-f]{64}\.json\.gz$/.test(desc.objectKey) &&
    /^sha256:[0-9a-f]{64}$/.test(desc.sha256) &&
    typeof desc.byteSize === 'number' && desc.byteSize > 0 &&
    desc.recordCount === 2);
  // The object key encodes the sha256
  const stripped = desc.sha256.slice('sha256:'.length);
  assert('objectKey embeds the sha256',
    desc.objectKey === `objects/sha256/${stripped}.json.gz`);
}

section('Empty entity list yields a stable bucket with zero records');

{
  const desc = await describeShard('vulnerability', 'ab', [], async (b) => b);
  assert('empty shard has recordCount 0', desc.recordCount === 0);
  // The byteSize in describeShard is the GZIPPED size; gzip of '[]'
  // is a few bytes (gzip header + payload). The manifest-level rule
  // is to not write a shard descriptor for recordCount===0 at all;
  // describeShard is the per-bucket primitive and is still well-defined
  // for an empty array.
  assert('empty shard has a well-defined sha256', /^sha256:[0-9a-f]{64}$/.test(desc.sha256));
  // The canonical hash of an empty array is well-defined and stable
  const desc2 = await describeShard('vulnerability', 'ab', [], async (b) => b);
  assert('empty shard is deterministic', desc.sha256 === desc2.sha256);
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
console.log('ALL CANONICAL-HASHING TESTS PASSED');
