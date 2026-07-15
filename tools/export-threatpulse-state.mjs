#!/usr/bin/env node
/**
 * V6.2 — export-threatpulse-state tool.
 *
 * Exports the public ThreatPulse state to a portable
 * tar-compatible directory. The export is suitable for
 * backup, transfer between deployments, or audit. It
 * contains:
 *   - dataset envelope
 *   - canonical baseline manifest
 *   - public-intelligence OSV projection (manifest +
 *     shards)
 *   - public-intelligence dataset bundle (manifest +
 *     snapshot + source-health + changes)
 *   - enrichment caches (Vulnrichment, GitHub Advisory)
 *   - schema / version metadata
 *   - checksums (sha256 of every exported blob)
 *
 * The export NEVER contains:
 *   - secrets
 *   - raw provider API keys
 *   - private credentials (the gateway subtree keeps
 *     those out of band)
 *
 * Usage:
 *   node tools/export-threatpulse-state.mjs --out=DIR [--data-root=...] [--backend=memory|netlify|filesystem]
 */

import { promises as fsp, mkdirSync, existsSync, writeFileSync, statSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { pipeline } from 'node:stream/promises';
import { createReadStream } from 'node:fs';
import { createWriteStream } from 'node:fs';
import { createGzip } from 'node:zlib';
import { Readable } from 'node:stream';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..');

const { createStorageAdapter } = await import('../netlify/functions/_shared/storage/index.mjs');

function parseArgs(argv) {
  const args = { out: null, dataRoot: null, backend: 'memory' };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--out=')) args.out = resolve(a.slice('--out='.length));
    else if (a.startsWith('--data-root=')) args.dataRoot = a.slice('--data-root='.length);
    else if (a.startsWith('--backend=')) args.backend = a.slice('--backend='.length);
    else if (a === '--help' || a === '-h') {
      console.log('Usage: node tools/export-threatpulse-state.mjs --out=DIR [--data-root=...] [--backend=memory|netlify|filesystem]');
      process.exit(0);
    } else {
      console.error(`Unknown argument: ${a}`);
      process.exit(1);
    }
  }
  if (!args.out) {
    console.error('--out=DIR is required');
    process.exit(1);
  }
  return args;
}

const args = parseArgs(process.argv);

if (!existsSync(args.out)) {
  mkdirSync(args.out, { recursive: true });
}
const stagingDir = join(args.out, 'staging');
if (!existsSync(stagingDir)) {
  mkdirSync(stagingDir, { recursive: true });
}

const backend = args.backend;
const dataRoot = args.dataRoot;
const datasetAdapter = createStorageAdapter({ name: backend, storeName: 'tpr-dataset', opts: { dataRoot } });
const baselineAdapter = createStorageAdapter({ name: backend, storeName: 'tpr-baseline', opts: { dataRoot } });
const vulnAdapter = createStorageAdapter({ name: backend, storeName: 'tpr-vulnrichment', opts: { dataRoot } });
const ghAdapter = createStorageAdapter({ name: backend, storeName: 'tpr-github-advisory', opts: { dataRoot } });
const intelAdapter = createStorageAdapter({ name: backend, storeName: 'tpr-public-intelligence', opts: { dataRoot } });

const checksums = new Map();

async function exportKey(adapter, key, outPath) {
  const value = await adapter.get(key);
  if (value === null || value === undefined) return false;
  const buf = Buffer.isBuffer(value) ? value : Buffer.from(value);
  // For JSON values, write pretty-printed for audit.
  let payload = buf;
  try {
    const parsed = JSON.parse(buf.toString('utf8'));
    payload = Buffer.from(JSON.stringify(parsed, null, 2), 'utf8');
  } catch { /* not JSON; write as-is */ }
  mkdirSync(dirname(outPath), { recursive: true });
  writeFileSync(outPath, payload);
  // The checksum is computed over the bytes that were
  // actually written to disk (i.e. the pretty-printed
  // JSON, if applicable), so the importer can verify
  // byte-for-byte.
  const sha = createHash('sha256').update(payload).digest('hex');
  checksums.set(key, { sha256: sha, size: payload.length });
  return true;
}

async function exportBinaryKey(adapter, key, outPath) {
  const value = await adapter.get(key, { type: 'arrayBuffer' });
  if (value === null || value === undefined) return false;
  const buf = Buffer.isBuffer(value) ? value : Buffer.from(value);
  mkdirSync(dirname(outPath), { recursive: true });
  writeFileSync(outPath, buf);
  const sha = createHash('sha256').update(buf).digest('hex');
  checksums.set(key, { sha256: sha, size: buf.length });
  return true;
}

const present = [];
const absent = [];

async function maybeExport(adapter, key, outPath, source, isBinary = false) {
  const ok = isBinary
    ? await exportBinaryKey(adapter, key, outPath)
    : await exportKey(adapter, key, outPath);
  if (ok) {
    present.push({ key, source });
    // Update the checksum entry to record the source
    // so the import tool can disambiguate keys that
    // collide across adapters (e.g. both
    // tpr-vulnrichment and tpr-github-advisory use
    // the same `cache` key).
    const entry = checksums.get(key);
    if (entry) {
      entry.source = source;
      entry.path = outPath.slice(stagingDir.length + 1);
    }
  } else {
    absent.push({ key, source });
  }
}

console.error(`[export] backend=${backend} out=${args.out}`);

await maybeExport(datasetAdapter, 'latest-dataset', join(stagingDir, 'dataset', 'latest-dataset.json'), 'dataset');
await maybeExport(vulnAdapter, 'cache', join(stagingDir, 'cache', 'vulnrichment.json'), 'vulnrichment');
await maybeExport(ghAdapter, 'cache', join(stagingDir, 'cache', 'github-advisory.json'), 'github-advisory');
// Canonical baseline
await maybeExport(baselineAdapter, 'manifests/latest.json', join(stagingDir, 'baseline', 'manifest-latest.json'), 'baseline');
// Public intelligence
await maybeExport(intelAdapter, 'osv/latest.json', join(stagingDir, 'public-intelligence', 'osv-latest.json'), 'osv-latest');
await maybeExport(intelAdapter, 'dataset/latest.json', join(stagingDir, 'public-intelligence', 'dataset-latest.json'), 'dataset-latest');
// List the OSV shards. The shard files are exported
// into the tar under their full relative path so the
// importer can reconstruct the original directory
// layout from the checksum entry's `path` field.
const osvList = await intelAdapter.list({ prefix: 'osv/shards/sha256/' });
for (const entry of osvList.blobs || []) {
  // The shard lives under osv/shards/sha256/<hash>.json.gz
  // in the source. We write it to the matching path in
  // the staging directory.
  const fileName = entry.key.split('/').pop();
  const targetPath = join(stagingDir, 'public-intelligence', 'osv-shards', fileName);
  await maybeExport(intelAdapter, entry.key, targetPath, `osv-shard:${entry.key}`, true);
}
// List the dataset bundle
const datasetList = await intelAdapter.list({ prefix: 'dataset/versions/' });
for (const entry of datasetList.blobs || []) {
  // Keep the dataset/versions/ prefix in the tar entry
  // name so the importer can reconstruct the layout.
  await maybeExport(intelAdapter, entry.key, join(stagingDir, 'public-intelligence', 'dataset-versions', entry.key.split('/').slice(2).join('__')), `dataset-version:${entry.key}`, true);
}

// Write the checksums file and the metadata.
const metadata = {
  schemaVersion: 'export-v1',
  generatedAt: new Date().toISOString(),
  backend,
  present,
  absent,
  checksums: Object.fromEntries(checksums),
};
writeFileSync(join(stagingDir, 'METADATA.json'), JSON.stringify(metadata, null, 2));
writeFileSync(join(stagingDir, 'CHECKSUMS.json'), JSON.stringify(Object.fromEntries(checksums), null, 2));

// Bundle the staging directory into a single .tar.gz
// archive for portability.
const archivePath = join(args.out, 'threatpulse-export.tar.gz');
await tarGz(stagingDir, archivePath);

console.error(`[export] present=${present.length} absent=${absent.length} archive=${archivePath}`);
console.log(JSON.stringify({ present: present.length, absent: absent.length, archive: archivePath }, null, 2));
process.exit(0);

async function tarGz(srcDir, outFile) {
  // Build a tar stream of the directory contents and
  // gzip it. Uses the standard `tar` long-name extension
  // (name prefix 100 + length).
  const entries = await listFiles(srcDir);
  const tarChunks = [];
  for (const abs of entries) {
    const rel = abs.slice(srcDir.length + 1).replace(/\\/g, '/');
    const st = statSync(abs);
    const header = makeTarHeader(rel, st.size, st.mtime.getTime() / 1000 | 0);
    tarChunks.push(header);
    const content = (await fsp.readFile(abs));
    // Pad to 512-byte block boundary.
    const pad = (512 - (st.size % 512)) % 512;
    tarChunks.push(content);
    if (pad > 0) tarChunks.push(Buffer.alloc(pad, 0));
  }
  // End-of-archive: two 512-byte zero blocks.
  tarChunks.push(Buffer.alloc(1024, 0));
  const tarBuf = Buffer.concat(tarChunks);
  const gz = createGzip();
  const src = Readable.from(tarBuf);
  const dst = createWriteStream(outFile);
  await pipeline(src, gz, dst);
}

async function listFiles(dir) {
  const out = [];
  async function walk(d) {
    const entries = await fsp.readdir(d, { withFileTypes: true });
    for (const e of entries) {
      const p = join(d, e.name);
      if (e.isDirectory()) await walk(p);
      else out.push(p);
    }
  }
  await walk(dir);
  out.sort();
  return out;
}

function makeTarHeader(name, size, mtime) {
  // Standard ustar header. 512-byte block.
  const buf = Buffer.alloc(512, 0);
  // name (100 bytes). Use the prefix extension for long names.
  let nameField = name;
  if (name.length > 100) {
    const idx = name.indexOf('/');
    const prefix = idx >= 0 ? name.slice(0, idx) : '';
    const remainder = idx >= 0 ? name.slice(idx + 1) : name;
    if (prefix.length <= 155 && remainder.length <= 100) {
      buf.write(prefix, 0, 155, 'utf8');
      nameField = remainder;
    } else {
      nameField = name.slice(0, 100);
    }
  }
  buf.write(nameField, 0, 100, 'utf8');
  // mode
  buf.write('0000644', 100, 8, 'utf8');
  // uid
  buf.write('0000000', 108, 8, 'utf8');
  // gid
  buf.write('0000000', 116, 8, 'utf8');
  // size (12 octal)
  buf.write(size.toString(8).padStart(11, '0') + ' ', 124, 12, 'utf8');
  // mtime (12 octal)
  buf.write(mtime.toString(8).padStart(11, '0') + ' ', 136, 12, 'utf8');
  // checksum placeholder (8 spaces)
  buf.write('        ', 148, 8, 'utf8');
  // typeflag (regular file)
  buf.write('0', 156, 1, 'utf8');
  // ustar magic
  buf.write('ustar\0', 257, 6, 'utf8');
  // ustar version
  buf.write('00', 263, 2, 'utf8');
  // uname
  buf.write('root', 265, 4, 'utf8');
  // gname
  buf.write('root', 297, 4, 'utf8');
  // Compute checksum.
  let sum = 0;
  for (const b of buf) sum += b;
  buf.write(sum.toString(8).padStart(6, '0') + '\0 ', 148, 8, 'utf8');
  return buf;
}
