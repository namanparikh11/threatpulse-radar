#!/usr/bin/env node
// V6.1 — Release-limits acceptance suite.
//
// Targeted tests for the V6.1 OSV projection publisher's
// hard size-ceiling enforcement. Verifies the structured
// failure contract:
//
//   - Oversized uncompressed bucket returns
//     { skipped: true, reason: 'uncompressed-ceiling-exceeded', bucket, sizeBytes, ceilingBytes, osvProjectionVersion }
//     and the function NEVER throws SizeCeilingExceededError
//     (canonical baseline must remain successful).
//   - Oversized compressed bucket returns
//     { skipped: true, reason: 'compressed-ceiling-exceeded', bucket, sizeBytes, ceilingBytes, osvProjectionVersion }
//     and the function NEVER throws SizeCeilingExceededError.
//   - On either rejection, no osv/latest.json is written,
//     no manifest is written, and no oversized shard is
//     written. The previous valid osv/latest.json (if any)
//     is byte-identical after the rejection.
//   - The next valid projection (with smaller data) can
//     publish successfully — i.e. the rejection is
//     contained.
//   - Field-level truncation metadata is honest: when
//     records are dropped to honor the per-record caps,
//     the byCve payload records the drop count rather than
//     silently discarding.
//
//   node scripts/acceptance-v61-release-limits.mjs

import { createHash } from 'node:crypto';
import { gunzipSync } from 'node:zlib';
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

const projMod = await import('../netlify/functions/_shared/osvPublicProjection.mjs');
const pubMod = await import('../netlify/functions/_shared/osvProjectionPublish.mjs');
const sizeMod = await import('../netlify/functions/_shared/publicIntelligenceSize.mjs');
const compMod = await import('../netlify/functions/_shared/publicIntelligenceCompression.mjs');
const bucketMod = await import('../netlify/functions/_shared/publicIntelligenceBucket.mjs');

console.log('V6.1 — release-limits acceptance');
console.log('================================');
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

/* ---- Fixtures ---- */

// Build a single canonical OSV entity (matching the shape
// expected by buildOsvProjection) at the documented per-record
// field caps: 10 aliases, 5 references, 6 affected packages,
// 4 ranges/package, 8 events/range, 8 versions/package.
//
// The `defeatCompression` flag injects high-entropy bytes
// in aliases/references/details so the gzipped bucket does
// not collapse below 256 KiB. The uncompressed size is
// still bounded by the per-record caps; only the
// gzipped/incompressible behavior changes.
function buildFatCanonicalEntity(cveId, idx, defeatCompression = false) {
  const osvId = `OSV-${cveId}-${idx}`;
  const rng = defeatCompression ? makeRng(`${cveId}-${idx}`) : null;
  const aliases = [];
  for (let a = 0; a < 10; a++) {
    let alias = `GHSA-${cveId}-alias${a}-${idx}`;
    if (defeatCompression) alias += '-' + rng.b64(96);
    aliases.push(alias);
  }
  const references = [];
  for (let r = 0; r < 5; r++) {
    let url = `https://github.com/advisories/GHSA-${cveId}-ref${r}-${idx}`;
    if (defeatCompression) url += '?q=' + rng.b64(192);
    references.push({
      type: r === 0 ? 'ADVISORY' : 'REPORT',
      url,
    });
  }
  const affected = [];
  for (let p = 0; p < 6; p++) {
    const ranges = [];
    for (let rg = 0; rg < 4; rg++) {
      const events = [];
      for (let e = 0; e < 8; e++) {
        events.push({
          introduced: `>=1.${e + idx}.0`,
          fixed: `>=1.${e + idx + 1}.0`,
        });
      }
      const rangeObj = { type: 'SEMVER', events };
      // Inject random bytes into range-level
      // databaseSpecific. The public projection
      // preserves this field (capped at
      // OSV_ECO_SPECIFIC_MAX_PAIRS = 32). 32 pairs of
      // ~64 random chars each = ~4 KiB per range. With
      // 6 packages x 4 ranges x 8 records, the bucket
      // ends up well into the high-hundreds of KiB
      // uncompressed, with the random portion unable to
      // be compressed by gzip.
      if (defeatCompression) {
        const dbSpec = {};
        for (let k = 0; k < 32; k++) {
          dbSpec[`k${k}-${rng.b64(8)}`] = rng.b64(64);
        }
        rangeObj.databaseSpecific = dbSpec;
      }
      ranges.push(rangeObj);
    }
    const versions = [];
    for (let v = 0; v < 8; v++) versions.push(`1.${v}.${idx}.${p}`);
    const pkgObj = {
      packageEcosystem: 'npm',
      packageName: `some-org/some-package-with-a-long-name-${p}-${idx}-${cveId}`,
      ranges,
      versions,
    };
    // Inject random bytes into package-level
    // ecosystemSpecific. Also preserved (capped at 32).
    if (defeatCompression) {
      const ecoSpec = {};
      for (let k = 0; k < 16; k++) {
        ecoSpec[`k${k}-${rng.b64(8)}`] = rng.b64(64);
      }
      pkgObj.ecosystemSpecific = ecoSpec;
    }
    affected.push(pkgObj);
  }
  return {
    osvId,
    aliases: [cveId, ...aliases],
    references,
    affected,
  };
}

// Deterministic pseudo-random generator (no crypto). Same
// seed → same output. Used to inject high-entropy bytes
// into fixture data so gzip cannot collapse the bucket
// below the 256 KiB compressed ceiling. The `b64`
// generator uses a 64-char alphabet so the resulting
// string has full byte-range entropy and is genuinely
// incompressible (hex strings compress too well because
// they have only 16 unique chars).
const B64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
function makeRng(seed) {
  let s = 0;
  for (let i = 0; i < seed.length; i++) s = (s * 31 + seed.charCodeAt(i)) >>> 0;
  return {
    hex(n) {
      let out = '';
      for (let i = 0; i < n; i++) {
        s = (s * 1664525 + 1013904223) >>> 0;
        out += ((s >>> 24) & 0xf).toString(16);
      }
      return out;
    },
    b64(n) {
      let out = '';
      for (let i = 0; i < n; i++) {
        s = (s * 1664525 + 1013904223) >>> 0;
        out += B64_ALPHABET[(s >>> 24) & 0x3f];
      }
      return out;
    },
  };
}

// Build N canonical entities for a given CVE id (up to 8
// records per CVE — the documented cap). When
// `defeatCompression` is true, the fixture injects
// high-entropy bytes so gzip cannot collapse the
// resulting bucket.
function buildFatEntitiesForCve(cveId, recordCount, defeatCompression = false) {
  return Array.from({ length: recordCount }, (_, i) =>
    buildFatCanonicalEntity(cveId, i, defeatCompression),
  );
}

// Find CVE IDs that bucket to a specific target digit. We
// scan sequentially; ~1 in 16 IDs match a given target.
function findCvesForBucket(target, count) {
  const out = [];
  let n = 1;
  while (out.length < count) {
    const cveId = `CVE-2026-${String(n).padStart(5, '0')}`;
    if (bucketMod.cveBucket(cveId) === target) out.push(cveId);
    n++;
    if (n > 1_000_000) break;
  }
  return out;
}

/* ---- 1. Uncompressed ceiling rejection ---- */
console.log('[1] Uncompressed ceiling rejection');

// Find 250 CVEs that bucket to "0" so that bucket "0"
// receives all 250 CVEs and each CVE has 8 records at the
// field caps. The resulting bucket should easily exceed
// the 1 MiB uncompressed ceiling.
const cvesForBucket0 = findCvesForBucket('0', 250);
assert('found 250 CVE IDs bucketed to "0"', cvesForBucket0.length === 250);
const fatEntities = [];
for (const cveId of cvesForBucket0) {
  for (const ent of buildFatEntitiesForCve(cveId, 8)) {
    fatEntities.push(ent);
  }
}
assert('built 2000 canonical entities (250 CVEs x 8 records)', fatEntities.length === 2000);

// Pre-publish a valid small projection so we can later
// verify the previous latest.json is byte-identical after
// a rejection.
const smallStore = makeMockStore();
const smallResult = await pubMod.publishOsvProjection(smallStore, [
  ...buildFatEntitiesForCve('CVE-2026-00001', 2),
  ...buildFatEntitiesForCve('CVE-2026-00002', 2),
], {
  canonicalBaselineVersion: 'v6-0-pre',
  canonicalManifestHash: 'sha256:aaaaaaaaaaaaaaaa',
});
assert('small projection published successfully', smallResult && smallResult.skipped === false);
assert('small projection wrote osv/latest.json', smallStore.blobs.has('osv/latest.json'));
const previousLatestBytes = JSON.stringify(smallStore.blobs.get('osv/latest.json').value);

// Now attempt the oversized publication.
const overStore = makeMockStore();
// Carry over the previous latest.json so we can verify it's preserved.
overStore.blobs.set('osv/latest.json', { value: JSON.parse(previousLatestBytes), type: 'json' });
const overResult = await pubMod.publishOsvProjection(overStore, fatEntities, {
  canonicalBaselineVersion: 'v6-0-huge',
  canonicalManifestHash: 'sha256:bbbbbbbbbbbbbbbb',
});
assert('oversized uncompressed projection returns structured skipped result',
  overResult && overResult.skipped === true,
  `got: ${JSON.stringify(overResult)}`);
assert('rejection reason is uncompressed-ceiling-exceeded',
  overResult && overResult.reason === 'uncompressed-ceiling-exceeded',
  `got: ${overResult && overResult.reason}`);
assert('rejection identifies the offending bucket digit',
  overResult && overResult.bucket === '0',
  `got: ${overResult && overResult.bucket}`);
assert('rejection reports sizeBytes',
  overResult && typeof overResult.sizeBytes === 'number' && overResult.sizeBytes > 0);
assert('rejection reports ceilingBytes = 1 MiB',
  overResult && overResult.ceilingBytes === sizeMod.OSV_SHARD_HARD_CEILING_UNCOMPRESSED_BYTES);
assert('rejection includes the projection version id',
  overResult && typeof overResult.osvProjectionVersion === 'string' && overResult.osvProjectionVersion.length > 0);

// Verify that osv/latest.json was NOT updated.
const afterLatestJson = overStore.blobs.get('osv/latest.json');
const afterLatestString = JSON.stringify(afterLatestJson && afterLatestJson.value);
assert('osv/latest.json byte-identical to previous after rejection',
  afterLatestString === previousLatestBytes,
  `expected ${previousLatestBytes.slice(0, 80)}..., got ${afterLatestString && afterLatestString.slice(0, 80)}...`);

// Verify no new manifest was written for the rejected version.
const rejectedVersionManifestKey = `osv/versions/${overResult.osvProjectionVersion}/manifest.json`;
assert('no manifest written for the rejected version',
  !overStore.blobs.has(rejectedVersionManifestKey));

// Verify no oversized shard was written under any
// content-addressed key.
const shardKeys = [...overStore.blobs.keys()].filter((k) => k.startsWith('osv/shards/sha256/'));
assert('no oversized shard was written',
  shardKeys.length === 0,
  `shard keys present: ${shardKeys.join(', ')}`);

/* ---- 2. Compressed ceiling rejection ---- */
console.log('');
console.log('[2] Compressed ceiling rejection');

// We need a bucket that fits the uncompressed ceiling but
// exceeds the compressed ceiling. The compressed ceiling
// is 256 KiB. We can use the same 250-CVE fat fixture but
// FORCE the uncompressed check to pass (i.e. the bucket
// must be < 1 MiB uncompressed) yet > 256 KiB compressed.
// This is the harder case because gzip is good. The
// realistic test is: try the same fixture but bypass the
// uncompressed check by stubbing. Since the production
// code path checks uncompressed first, the compressed
// rejection can be triggered either by:
//   (a) an entity set where ONE bucket is between
//       1 MiB and 256 KiB compressed (very narrow band), or
//   (b) a unit test that exercises the inner compressed
//       check directly.
// We use (b) here: write the same fixture but with a
// fewer CVE count so the uncompressed ceiling is met
// (single bucket < 1 MiB uncompressed) but compressed
// still > 256 KiB. This requires enough records to push
// gzipped size past 256 KiB even after compression.
//
// Empirically, the same 250-CVE fixture is ~20 MB
// uncompressed and ~300 KB compressed. To get
// uncompressed < 1 MiB AND compressed > 256 KiB, we need
// a band that's only achievable with a small but
// high-entropy bucket. We test it by reducing the record
// count per CVE from 8 to 1 (so per-CVE data is small)
// but using 250 CVEs — the cumulative bucket should still
// hit hundreds of KiB compressed due to the per-CVE
// header overhead.
//
// To make this deterministic, we call buildOsvProjection
// directly to inspect bucket sizes, and then call
// publishOsvProjection with a hand-crafted smaller fixture
// (under the uncompressed ceiling) that we know will
// produce a compressed oversize via a custom path.
//
// We use `defeatCompression: true` so the gzipped bucket
// does not collapse below the 256 KiB compressed ceiling
// (the natural data is too repetitive for gzip to
// demonstrate the compressed-ceiling code path).
//
// Strategy: use 1 CVE with 8 records, each carrying
// random bytes in range-level databaseSpecific and
// package-level ecosystemSpecific. The per-pair size
// and pair count are tuned so that uncompressed is
// between 600 KiB and 1 MiB (passes the uncompressed
// check) but compressed remains above 256 KiB (the
// random bytes are incompressible, so the gzipped size
// stays near the uncompressed size).
const smallFatEntities = [];
for (const cveId of cvesForBucket0.slice(0, 1)) {
  for (const ent of buildFatEntitiesForCve(cveId, 8, true)) {
    smallFatEntities.push(ent);
  }
}
const inspect = pubMod.buildOsvProjection(smallFatEntities, {
  canonicalBaselineVersion: 'v6-0-inspect',
  canonicalManifestHash: 'sha256:cccccccccccccccc',
});
const b0 = inspect.buckets.find((b) => b.bucket === '0');
const b0Uncompressed = sizeMod.uncompressedBytes(b0);
const b0Compressed = sizeMod.compressedBytes(b0);
console.log(`     inspect: bucket 0 uncompressed=${b0Uncompressed} compressed=${b0Compressed}`);
assert('inspect uncompressed within 1 MiB ceiling',
  b0Uncompressed <= sizeMod.OSV_SHARD_HARD_CEILING_UNCOMPRESSED_BYTES,
  `uncompressed=${b0Uncompressed}`);
assert('inspect compressed exceeds 256 KiB ceiling',
  b0Compressed > sizeMod.OSV_SHARD_HARD_CEILING_COMPRESSED_BYTES,
  `compressed=${b0Compressed} ceiling=${sizeMod.OSV_SHARD_HARD_CEILING_COMPRESSED_BYTES}`);

// Now publish and verify the compressed-ceiling rejection.
const overStore2 = makeMockStore();
overStore2.blobs.set('osv/latest.json', { value: JSON.parse(previousLatestBytes), type: 'json' });
const overResult2 = await pubMod.publishOsvProjection(overStore2, smallFatEntities, {
  canonicalBaselineVersion: 'v6-0-huge2',
  canonicalManifestHash: 'sha256:dddddddddddddddd',
});
assert('compressed-oversize projection returns structured skipped result',
  overResult2 && overResult2.skipped === true,
  `got: ${JSON.stringify(overResult2)}`);
assert('rejection reason is compressed-ceiling-exceeded',
  overResult2 && overResult2.reason === 'compressed-ceiling-exceeded',
  `got: ${overResult2 && overResult2.reason}`);
assert('rejection identifies the offending bucket',
  overResult2 && typeof overResult2.bucket === 'string' && overResult2.bucket.length === 1);
assert('rejection reports sizeBytes (compressed) > 256 KiB',
  overResult2 && overResult2.sizeBytes > sizeMod.OSV_SHARD_HARD_CEILING_COMPRESSED_BYTES);
assert('rejection reports ceilingBytes = 256 KiB',
  overResult2 && overResult2.ceilingBytes === sizeMod.OSV_SHARD_HARD_CEILING_COMPRESSED_BYTES);

// Verify osv/latest.json preserved byte-identical.
const afterLatest2 = overStore2.blobs.get('osv/latest.json');
const afterLatest2String = JSON.stringify(afterLatest2 && afterLatest2.value);
assert('osv/latest.json byte-identical to previous after compressed rejection',
  afterLatest2String === previousLatestBytes);

// Verify no manifest for the rejected version.
const rejected2ManifestKey = `osv/versions/${overResult2.osvProjectionVersion}/manifest.json`;
assert('no manifest written for the rejected version (compressed)',
  !overStore2.blobs.has(rejected2ManifestKey));

/* ---- 3. Successful publication after rejection ---- */
console.log('');
console.log('[3] Successful publication after rejection');

// Reuse the over-sized store. After a rejection, a smaller
// (in-bounds) publication should still succeed.
const recoveryStore = makeMockStore();
recoveryStore.blobs.set('osv/latest.json', { value: JSON.parse(previousLatestBytes), type: 'json' });
const recovery = await pubMod.publishOsvProjection(recoveryStore, [
  ...buildFatEntitiesForCve('CVE-2026-00001', 1),
  ...buildFatEntitiesForCve('CVE-2026-00002', 1),
  ...buildFatEntitiesForCve('CVE-2026-00003', 1),
], {
  canonicalBaselineVersion: 'v6-0-recover',
  canonicalManifestHash: 'sha256:eeeeeeeeeeeeeeee',
});
assert('recovery projection publishes successfully after a prior rejection',
  recovery && recovery.skipped === false);
assert('recovery wrote osv/latest.json with new version',
  recoveryStore.blobs.has('osv/latest.json'));
const recoveryLatest = recoveryStore.blobs.get('osv/latest.json').value;
assert('recovery latest.json version is the new one',
  recoveryLatest && recoveryLatest.osvProjectionVersion === recovery.osvProjectionVersion);

/* ---- 4. Field-level truncation metadata is honest ---- */
console.log('');
console.log('[4] Field-level truncation metadata is honest');

// Use a CVE that has 12 records (exceeds the 8-record cap)
// to force a truncation event. Verify the byCve payload
// reports recordsRemoved, and the kept records equal the
// cap (8).
const manyRecords = buildFatEntitiesForCve('CVE-2026-00007', 12);
const truncationResult = pubMod.buildOsvProjection(manyRecords, {
  canonicalBaselineVersion: 'v6-0-trunc',
  canonicalManifestHash: 'sha256:ffffffffffffffff',
});
const truncationBucket = truncationResult.buckets.find((b) => b.bucket === '0' || b.cveCount > 0) || truncationResult.buckets[0];
// Find the bucket containing CVE-2026-00007.
let cveBucketEntry = null;
for (const b of truncationResult.buckets) {
  if (b.byCve && b.byCve['CVE-2026-00007']) { cveBucketEntry = b; break; }
}
assert('found the bucket containing the over-cap CVE',
  cveBucketEntry !== null);
if (cveBucketEntry) {
  const cveEntry = cveBucketEntry.byCve['CVE-2026-00007'];
  assert('over-cap CVE has honest truncation metadata',
    cveEntry.truncation && typeof cveEntry.truncation.recordsRemoved === 'number' && cveEntry.truncation.recordsRemoved > 0,
    `truncation=${JSON.stringify(cveEntry.truncation)}`);
  assert('over-cap CVE kept records <= 8 (the documented cap)',
    Array.isArray(cveEntry.records) && cveEntry.records.length <= 8,
    `kept=${cveEntry.records && cveEntry.records.length}`);
  assert('recordsRemoved = input - kept',
    cveEntry.truncation.recordsRemoved === 12 - cveEntry.records.length,
    `removed=${cveEntry.truncation.recordsRemoved} kept=${cveEntry.records.length}`);
  // The whole 12-record input was truncated; no records
  // were silently discarded beyond the documented cap.
  assert('no silent dropping beyond the cap (4 records removed, 8 kept)',
    cveEntry.truncation.recordsRemoved === 4 && cveEntry.records.length === 8);
}

/* ---- 5. The publisher NEVER throws on size ceiling ---- */
console.log('');
console.log('[5] The publisher never throws on size ceiling');

const overStore3 = makeMockStore();
let threw = false;
let caught = null;
try {
  await pubMod.publishOsvProjection(overStore3, fatEntities, {
    canonicalBaselineVersion: 'v6-0-throwcheck',
    canonicalManifestHash: 'sha256:9999999999999999',
  });
} catch (e) {
  threw = true;
  caught = e;
}
assert('publisher does not throw on uncompressed oversize', !threw,
  `caught: ${caught && caught.message}`);
assert('publisher does not throw SizeCeilingExceededError',
  !threw || !(caught instanceof sizeMod.SizeCeilingExceededError),
  `caught: ${caught && caught.name}`);

/* ---- 6. Previous latest.json preserved with no prior data ---- */
console.log('');
console.log('[6] First-run rejection with no prior latest.json');

const freshStore = makeMockStore();
// No prior latest.json. The function should still return
// a structured result and NOT create a latest.json.
const freshResult = await pubMod.publishOsvProjection(freshStore, fatEntities, {
  canonicalBaselineVersion: 'v6-0-firstrun',
  canonicalManifestHash: 'sha256:1111111111111111',
});
assert('first-run rejection returns structured result',
  freshResult && freshResult.skipped === true);
assert('first-run rejection does not create osv/latest.json',
  !freshStore.blobs.has('osv/latest.json'));

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
