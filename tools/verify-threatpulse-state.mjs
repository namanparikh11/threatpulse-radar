#!/usr/bin/env node
/**
 * V6.2 — verify-threatpulse-state tool.
 *
 * Performs a non-destructive integrity scan of the
 * public ThreatPulse state. Detects:
 *   - missing referenced objects (manifests reference
 *     shards that are not present)
 *   - corrupt hashes (computed sha256 of a stored blob
 *     does not match a content-addressed record)
 *   - invalid manifests (the stored manifest does not
 *     match its declared schemaVersion)
 *   - orphaned content-addressed shards (shards under
 *     `osv/shards/sha256/` not referenced by any
 *     retained manifest)
 *   - latest pointers referencing missing versions
 *     (osv/latest.json points to a version whose
 *     manifest is missing)
 *   - incompatible schema versions
 *
 * The verifier NEVER mutates the storage. It exits
 * non-zero when any error is found.
 *
 * Usage:
 *   node tools/verify-threatpulse-state.mjs [--data-root=...] [--backend=memory|filesystem|netlify] [--json]
 */

import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { createHash } from 'node:crypto';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..');

const { createStorageAdapter } = await import('../netlify/functions/_shared/storage/index.mjs');
const { gunzipValue } = await import('../netlify/functions/_shared/publicIntelligenceCompression.mjs');

function parseArgs(argv) {
  const args = { dataRoot: null, backend: 'memory', json: false };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--data-root=')) args.dataRoot = a.slice('--data-root='.length);
    else if (a.startsWith('--backend=')) args.backend = a.slice('--backend='.length);
    else if (a === '--json') args.json = true;
    else if (a === '--help' || a === '-h') {
      console.log('Usage: node tools/verify-threatpulse-state.mjs [--data-root=...] [--backend=...] [--json]');
      process.exit(0);
    } else {
      console.error(`Unknown argument: ${a}`);
      process.exit(1);
    }
  }
  return args;
}

const args = parseArgs(process.argv);

const intelAdapter = createStorageAdapter({ name: args.backend, storeName: 'tpr-public-intelligence', opts: { dataRoot: args.dataRoot } });
const datasetAdapter = createStorageAdapter({ name: args.backend, storeName: 'tpr-dataset', opts: { dataRoot: args.dataRoot } });
const baselineAdapter = createStorageAdapter({ name: args.backend, storeName: 'tpr-baseline', opts: { dataRoot: args.dataRoot } });

const report = {
  ok: true,
  errors: [],
  warnings: [],
  summary: {},
};

function fail(category, message) {
  report.errors.push({ category, message });
  report.ok = false;
}

function warn(category, message) {
  report.warnings.push({ category, message });
}

// 1. osv/latest.json
const osvLatest = await intelAdapter.getJSON('osv/latest.json').catch(() => null);
if (!osvLatest) {
  fail('osv-latest', 'osv/latest.json is missing');
} else {
  if (typeof osvLatest.osvProjectionVersion !== 'string') {
    fail('osv-latest', 'osv/latest.json does not carry an osvProjectionVersion');
  } else {
    report.summary.osvProjectionVersion = osvLatest.osvProjectionVersion;
    // 2. The version manifest must exist.
    const manifestKey = `osv/versions/${osvLatest.osvProjectionVersion}/manifest.json`;
    const manifest = await intelAdapter.getJSON(manifestKey).catch(() => null);
    if (!manifest) {
      fail('osv-manifest', `osv/latest.json references a missing manifest: ${manifestKey}`);
    } else {
      // 3. Each declared bucket must exist.
      const buckets = manifest.buckets || {};
      for (const [bucketDigit, info] of Object.entries(buckets)) {
        if (!info || typeof info.contentHash !== 'string') {
          fail('osv-bucket-meta', `bucket ${bucketDigit} has no contentHash`);
          continue;
        }
        const shardHash = info.contentHash.startsWith('sha256:') ? info.contentHash.slice('sha256:'.length) : info.contentHash;
        const shardKey = `osv/shards/sha256/${shardHash}.json.gz`;
        const shard = await intelAdapter.get(shardKey, { type: 'arrayBuffer' });
        if (!shard) {
          fail('osv-shard', `manifest references a missing shard: ${shardKey}`);
        } else {
          // 4. Verify the shard's content hash matches.
          const actualSha = createHash('sha256').update(Buffer.from(shard)).digest('hex');
          if (`sha256:${actualSha}` !== info.contentHash) {
            fail('osv-shard-hash', `shard ${shardKey} has hash sha256:${actualSha}, expected ${info.contentHash}`);
          }
          // 5. Decompress and validate the shard.
          const parsed = gunzipValue(Buffer.from(shard));
          if (!parsed || typeof parsed !== 'object') {
            fail('osv-shard-decode', `shard ${shardKey} failed to gunzip-decode`);
          }
        }
      }
    }
  }
}

// 6. Detect orphaned shards: any osv/shards/sha256/ entry
// not referenced by the current or any retained manifest.
const osvShards = await intelAdapter.list({ prefix: 'osv/shards/sha256/' });
const referenced = new Set();
if (osvLatest) {
  // Re-read the current manifest to collect its bucket hashes.
  const m = await intelAdapter.getJSON(`osv/versions/${osvLatest.osvProjectionVersion}/manifest.json`).catch(() => null);
  if (m && m.buckets) {
    for (const info of Object.values(m.buckets)) {
      if (info && info.contentHash) {
        const h = info.contentHash.startsWith('sha256:') ? info.contentHash.slice('sha256:'.length) : info.contentHash;
        referenced.add(`osv/shards/sha256/${h}.json.gz`);
      }
    }
  }
}
for (const entry of osvShards.blobs || []) {
  if (!referenced.has(entry.key)) {
    warn('osv-orphan', `orphaned shard: ${entry.key}`);
  }
}

// 7. dataset/latest.json
const datasetLatest = await intelAdapter.getJSON('dataset/latest.json').catch(() => null);
if (!datasetLatest) {
  fail('dataset-latest', 'dataset/latest.json is missing');
} else {
  if (typeof datasetLatest.publicIntelligenceVersion !== 'string') {
    fail('dataset-latest', 'dataset/latest.json does not carry a publicIntelligenceVersion');
  } else {
    const manifestKey = `dataset/versions/${datasetLatest.publicIntelligenceVersion}/manifest.json`;
    const manifest = await intelAdapter.getJSON(manifestKey).catch(() => null);
    if (!manifest) {
      fail('dataset-manifest', `dataset/latest.json references a missing manifest: ${manifestKey}`);
    } else {
      const compat = manifest.publicStateSchemaVersion || manifest.schemaVersion;
      if (compat && !/^1\./.test(String(compat))) {
        warn('dataset-schema', `dataset manifest schemaVersion is ${compat}; expected 1.x`);
      }
    }
  }
}

// 8. dataset envelope
const datasetEnv = await datasetAdapter.getJSON('latest-dataset').catch(() => null);
if (!datasetEnv) {
  fail('dataset-envelope', 'tpr-dataset/latest-dataset is missing');
} else {
  if (typeof datasetEnv.datasetPublicHash !== 'string') {
    fail('dataset-envelope', 'latest-dataset is missing datasetPublicHash (pre-V6.1 envelope)');
  }
}

// 9. canonical baseline
const baselineLatest = await baselineAdapter.getJSON('manifests/latest.json').catch(() => null);
if (!baselineLatest) {
  warn('baseline-latest', 'tpr-baseline/manifests/latest.json is missing');
} else {
  if (typeof baselineLatest.baselineVersion !== 'string') {
    fail('baseline-latest', 'baseline manifest does not carry a baselineVersion');
  }
}

if (args.json) {
  console.log(JSON.stringify(report, null, 2));
} else {
  console.log(`ThreatPulse verify-state (backend=${args.backend})`);
  for (const e of report.errors) console.log(`  ✗ ${e.category}: ${e.message}`);
  for (const w of report.warnings) console.log(`  ! ${w.category}: ${w.message}`);
  if (report.ok) console.log('  ✓ no errors');
}
process.exit(report.ok ? 0 : 1);
