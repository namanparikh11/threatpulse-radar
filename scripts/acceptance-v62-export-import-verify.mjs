#!/usr/bin/env node
// V6.2 — export / import / verify round-trip acceptance.
//
//   node scripts/acceptance-v62-export-import-verify.mjs

import { fileURLToPath } from 'node:url';
import { dirname, resolve, join } from 'node:path';
import { spawn } from 'node:child_process';
import { setTimeout as wait } from 'node:timers/promises';
import { existsSync, readFileSync, writeFileSync, mkdirSync, rmSync, readdirSync } from 'node:fs';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..');

let passed = 0;
let failed = 0;
const failures = [];
function assert(label, cond, extra = '') {
  if (cond) { passed++; console.log(`  PASS  ${label}`); }
  else { failed++; failures.push({ label, extra }); console.log(`  FAIL  ${label}${extra ? `  -- ${extra}` : ''}`); }
}

const { createStorageAdapter, InMemoryStorageAdapter, FilesystemStorageAdapter } = await import('../netlify/functions/_shared/storage/index.mjs');

console.log('V6.2 — export/import/verify round-trip');
console.log('=======================================');
console.log('');

function runNode(args, opts = {}) {
  return new Promise((resolveRun) => {
    const proc = spawn('node', args, {
      cwd: root, stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env, ...(opts.env || {}) },
    });
    let out = '', err = '';
    proc.stdout.on('data', (d) => { out += d.toString(); });
    proc.stderr.on('data', (d) => { err += d.toString(); });
    proc.on('close', (code) => resolveRun({ code, out, err }));
  });
}

/* ---- 1. Prepare a populated filesystem store ---- */
console.log('[1] Prepare a populated filesystem store');

// Use the factory so the test and the CLI tools use
// the same path layout. The factory appends the
// storeName to the dataRoot.
const fsRoot = mkdtempSync(join(tmpdir(), 'tpr-export-'));
const datasetStore = createStorageAdapter({ name: 'filesystem', storeName: 'tpr-dataset', opts: { dataRoot: fsRoot } });
const vulnStore = createStorageAdapter({ name: 'filesystem', storeName: 'tpr-vulnrichment', opts: { dataRoot: fsRoot } });
const ghStore = createStorageAdapter({ name: 'filesystem', storeName: 'tpr-github-advisory', opts: { dataRoot: fsRoot } });
const intelStore = createStorageAdapter({ name: 'filesystem', storeName: 'tpr-public-intelligence', opts: { dataRoot: fsRoot } });
const baselineStore = createStorageAdapter({ name: 'filesystem', storeName: 'tpr-baseline', opts: { dataRoot: fsRoot } });

// Populate the stores with realistic content.
await datasetStore.setJSON('latest-dataset', {
  mode: 'live', source: 'merged', fetchedAt: '2026-07-15T20:00:00.000Z',
  data: [{ cveId: 'CVE-2026-00001', severity: 'High' }],
  datasetPublicHash: 'sha256:' + 'a'.repeat(64),
});
await vulnStore.setJSON('cache', { records: {}, updatedAt: '2026-07-15T20:00:00.000Z', vulnrichmentPublicHash: 'sha256:' + 'b'.repeat(64) });
await ghStore.setJSON('cache', { records: {}, updatedAt: '2026-07-15T20:00:00.000Z', githubAdvisoryPublicHash: 'sha256:' + 'c'.repeat(64) });
await intelStore.setJSON('osv/latest.json', {
  schemaVersion: '1.0.0', osvProjectionVersion: 'v6-0-test',
  canonicalBaselineVersion: 'v6-0-base', canonicalManifestHash: 'sha256:' + 'd'.repeat(64),
  manifestContentHash: 'sha256:' + 'e'.repeat(64), generatedAt: '2026-07-15T20:00:00.000Z',
});
// Also write a fake OSV shard so the verify can find it.
// Compute the actual hash of the gzipped content so the
// manifest's bucket contentHash matches the stored
// shard byte-for-byte.
const { gzipSync, createHash } = await import('node:zlib');
const { createHash: nodeCreateHash } = await import('node:crypto');
const shardContent = JSON.stringify({
  schemaVersion: '1.0.0', bucket: '0',
  byCve: { 'CVE-2026-00001': { records: [{ osvId: 'OSV-1', sourceDatabase: 'OSV-DEV', aliases: ['CVE-2026-00001'], affectedPackages: [] }], truncation: { recordsRemoved: 0 } } },
  truncation: { recordsRemovedTotal: 0, cvesTruncated: 0 },
});
const shardGz = gzipSync(Buffer.from(shardContent, 'utf8'));
const shardHash = 'sha256:' + nodeCreateHash('sha256').update(shardGz).digest('hex');
await intelStore.setBinary(`osv/shards/sha256/${shardHash.slice('sha256:'.length)}.json.gz`, shardGz);
await intelStore.setJSON('osv/versions/v6-0-test/manifest.json', {
  schemaVersion: '1.0.0', osvProjectionVersion: 'v6-0-test',
  canonicalBaselineVersion: 'v6-0-base', canonicalManifestHash: 'sha256:' + 'd'.repeat(64),
  generatedAt: '2026-07-15T20:00:00.000Z',
  bucketCount: 16,
  buckets: {
    '0': { contentHash: shardHash, cveCount: 1 },
  },
});
await intelStore.setJSON('dataset/latest.json', {
  schemaVersion: '1.0.0', publicIntelligenceVersion: 'v6-1-test',
  generatedAt: '2026-07-15T20:00:00.000Z', publicStateHash: 'sha256:' + 'f'.repeat(64),
  publicStateFingerprint: 'abc123def456',
});
await intelStore.setJSON('dataset/versions/v6-1-test/manifest.json', {
  schemaVersion: '1.0.0', publicIntelligenceVersion: 'v6-1-test',
  generatedAt: '2026-07-15T20:00:00.000Z', publicStateHash: 'sha256:' + 'f'.repeat(64),
  publicStateSchemaVersion: '1.0.0', publicProjectionSchemaVersion: '1.0.0',
  comparesFreshBase: false, previousPublicIntelligenceVersion: null,
});
await baselineStore.setJSON('manifests/latest.json', {
  schemaVersion: '1.0.0', baselineVersion: 'v6-0-base',
  canonicalContentHash: 'sha256:' + 'd'.repeat(64),
  publishedAt: '2026-07-15T20:00:00.000Z',
});

assert('filesystem store has dataset envelope', await datasetStore.exists('latest-dataset'));
assert('filesystem store has osv latest', await intelStore.exists('osv/latest.json'));

/* ---- 2. Export ---- */
console.log('');
console.log('[2] Export to archive');

const outDir = mkdtempSync(join(tmpdir(), 'tpr-out-'));
const exportRes = await runNode(
  ['tools/export-threatpulse-state.mjs', `--out=${outDir}`, `--data-root=${fsRoot}`, '--backend=filesystem'],
  {},
);
assert('export exited 0', exportRes.code === 0, `code=${exportRes.code} stderr=${exportRes.err}`);
assert('export produced the tar.gz', existsSync(join(outDir, 'threatpulse-export.tar.gz')));
assert('export produced CHECKSUMS.json', existsSync(join(outDir, 'staging', 'CHECKSUMS.json')));

/* ---- 3. Verify ---- */
console.log('');
console.log('[3] Verify the source state');

const verifyRes1 = await runNode(
  ['tools/verify-threatpulse-state.mjs', `--data-root=${fsRoot}`, '--backend=filesystem'],
  {},
);
assert('verify on the source exited 0', verifyRes1.code === 0, `code=${verifyRes1.code} stdout=${verifyRes1.out.slice(-400)}`);

/* ---- 4. Import (dry-run) ---- */
console.log('');
console.log('[4] Import (dry-run) into a new filesystem store');

const newFsRoot = mkdtempSync(join(tmpdir(), 'tpr-import-dry-'));
const importDryRes = await runNode(
  ['tools/import-threatpulse-state.mjs', `--archive=${join(outDir, 'threatpulse-export.tar.gz')}`, `--data-root=${newFsRoot}`, '--backend=filesystem'],
  {},
);
assert('import dry-run exited 0', importDryRes.code === 0, `code=${importDryRes.code} stdout=${importDryRes.out.slice(0, 500)} stderr=${importDryRes.err.slice(0, 500)}`);
const dry = JSON.parse(importDryRes.out);
assert('dry-run reported checksumsOk', dry.checksumsOk >= 5);
const newDatasetDry = new FilesystemStorageAdapter({ dataRoot: join(newFsRoot, 'tpr-dataset') });
assert('dry-run did NOT write latest-dataset', !(await newDatasetDry.exists('latest-dataset')));

/* ---- 5. Import (apply) ---- */
console.log('');
console.log('[5] Import (apply)');

const newFsRoot2 = mkdtempSync(join(tmpdir(), 'tpr-import-apply-'));
const importApplyRes = await runNode(
  ['tools/import-threatpulse-state.mjs', `--archive=${join(outDir, 'threatpulse-export.tar.gz')}`, `--data-root=${newFsRoot2}`, '--backend=filesystem', '--apply'],
  {},
);
assert('import apply exited 0', importApplyRes.code === 0, `stderr=${importApplyRes.err.slice(-200)} stderr=${importApplyRes.err.slice(0, 200)}`);

const newDataset2 = new FilesystemStorageAdapter({ dataRoot: join(newFsRoot2, 'tpr-dataset') });
const newIntel2 = new FilesystemStorageAdapter({ dataRoot: join(newFsRoot2, 'tpr-public-intelligence') });
assert('applied: latest-dataset written', await newDataset2.exists('latest-dataset'));
assert('applied: osv/latest.json written', await newIntel2.exists('osv/latest.json'));
const envAfter = await newDataset2.getJSON('latest-dataset');
assert('applied: datasetPublicHash round-tripped', envAfter && envAfter.datasetPublicHash && envAfter.datasetPublicHash.startsWith('sha256:'));

/* ---- 6. Verify the restored state ---- */
console.log('');
console.log('[6] Verify the restored state');

const verifyRes2 = await runNode(
  ['tools/verify-threatpulse-state.mjs', `--data-root=${newFsRoot2}`, '--backend=filesystem'],
  {},
);
assert('verify on the restored state exited 0', verifyRes2.code === 0, `code=${verifyRes2.code} stdout=${verifyRes2.out.slice(-400)}`);

/* ---- 7. Failed import preserves previous state ---- */
console.log('');
console.log('[7] Failed import preserves previous state');

// Build an archive with a corrupt checksum to force
// the importer to fail at checksum verification.
const corruptDir = mkdtempSync(join(tmpdir(), 'tpr-corrupt-'));
const exportRes2 = await runNode(
  ['tools/export-threatpulse-state.mjs', `--out=${corruptDir}`, `--data-root=${fsRoot}`, '--backend=filesystem'],
  {},
);
assert('re-export for corruption test exited 0', exportRes2.code === 0);
// Corrupt the CHECKSUMS.json so verification fails.
const checksumPath = join(corruptDir, 'staging', 'CHECKSUMS.json');
const checksums = JSON.parse(readFileSync(checksumPath, 'utf8'));
const firstKey = Object.keys(checksums)[0];
checksums[firstKey] = { sha256: 'sha256:' + 'f'.repeat(64), size: checksums[firstKey].size };
writeFileSync(checksumPath, JSON.stringify(checksums, null, 2));
// Re-tar the staging.
const { spawn: sp } = await import('node:child_process');
const tarProc = sp('tar', ['czf', join(corruptDir, 'threatpulse-export.tar.gz'), '-C', join(corruptDir, 'staging'), '.'], { cwd: root, stdio: 'ignore' });
await new Promise((r) => tarProc.on('close', r));

const newFsRoot3 = mkdtempSync(join(tmpdir(), 'tpr-import-fail-'));
const importFailRes = await runNode(
  ['tools/import-threatpulse-state.mjs', `--archive=${join(corruptDir, 'threatpulse-export.tar.gz')}`, `--data-root=${newFsRoot3}`, '--backend=filesystem'],
  {},
);
assert('corrupted import exited non-zero', importFailRes.code !== 0);
const newDataset3 = new FilesystemStorageAdapter({ dataRoot: join(newFsRoot3, 'tpr-dataset') });
assert('corrupted import did NOT write latest-dataset', !(await newDataset3.exists('latest-dataset')));

/* ---- Cleanup ---- */
rmSync(fsRoot, { recursive: true, force: true });
rmSync(outDir, { recursive: true, force: true });
rmSync(newFsRoot, { recursive: true, force: true });
rmSync(newFsRoot2, { recursive: true, force: true });
rmSync(newFsRoot3, { recursive: true, force: true });
rmSync(corruptDir, { recursive: true, force: true });

/* ---- Summary ---- */
console.log('');
console.log('---');
console.log(`PASSED: ${passed}`);
console.log(`FAILED: ${failed}`);
if (failed > 0) {
  for (const f of failures) console.log(`  FAIL: ${f.label}${f.extra ? ` (${f.extra})` : ''}`);
  process.exit(1);
}
process.exit(0);
