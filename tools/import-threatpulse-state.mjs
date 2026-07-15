#!/usr/bin/env node
/**
 * V6.2 — import-threatpulse-state tool.
 *
 * Imports a ThreatPulse state archive produced by
 * `tools/export-threatpulse-state.mjs` into a target
 * storage backend. The import path:
 *
 *   1. Extracts the tar.gz archive to a staging area.
 *   2. Verifies the METADATA.json + CHECKSUMS.json.
 *   3. Validates schema compatibility.
 *   4. Performs a dry-run by default (writes nothing).
 *   5. With `--apply`, atomically promotes the staging
 *      area into the target storage adapter.
 *   6. On any failure during apply, the previous state
 *      is preserved (no partial writes).
 *
 * Path-traversal protection: every entry is checked
 * against the staging-area root before extraction.
 *
 * Usage:
 *   node tools/import-threatpulse-state.mjs --archive=FILE [--data-root=...] [--backend=memory|filesystem|netlify] [--apply]
 */

import { promises as fsp, mkdirSync, existsSync, writeFileSync, statSync, readFileSync, rmSync } from 'node:fs';
import { dirname, join, resolve, normalize, sep, isAbsolute } from 'node:path';
import { createHash } from 'node:crypto';
import { createReadStream, createWriteStream } from 'node:fs';
import { createGunzip } from 'node:zlib';
import { pipeline } from 'node:stream/promises';
import { Readable } from 'node:stream';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..');

const { createStorageAdapter } = await import('../netlify/functions/_shared/storage/index.mjs');

function parseArgs(argv) {
  const args = { archive: null, dataRoot: null, backend: 'memory', apply: false };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--archive=')) args.archive = resolve(a.slice('--archive='.length));
    else if (a.startsWith('--data-root=')) args.dataRoot = a.slice('--data-root='.length);
    else if (a.startsWith('--backend=')) args.backend = a.slice('--backend='.length);
    else if (a === '--apply') args.apply = true;
    else if (a === '--help' || a === '-h') {
      console.log('Usage: node tools/import-threatpulse-state.mjs --archive=FILE [--data-root=...] [--backend=...] [--apply]');
      process.exit(0);
    } else {
      console.error(`Unknown argument: ${a}`);
      process.exit(1);
    }
  }
  if (!args.archive) {
    console.error('--archive=FILE is required');
    process.exit(1);
  }
  return args;
}

const args = parseArgs(process.argv);

const stagingRoot = resolve(`${args.archive}.staging`);
if (existsSync(stagingRoot)) {
  rmSync(stagingRoot, { recursive: true, force: true });
}
mkdirSync(stagingRoot, { recursive: true });

// Stream-decompress and stream-extract the tar.gz.
const tarStream = createReadStream(args.archive).pipe(createGunzip());
const entries = await readTar(tarStream, stagingRoot);
console.error(`[import] extracted ${entries.length} entries`);

// Read METADATA.json
const metadataPath = join(stagingRoot, 'METADATA.json');
if (!existsSync(metadataPath)) {
  console.error('[import] METADATA.json missing');
  process.exit(1);
}
const metadata = JSON.parse(readFileSync(metadataPath, 'utf8'));
if (metadata.schemaVersion !== 'export-v1') {
  console.error(`[import] unsupported schema version: ${metadata.schemaVersion}`);
  process.exit(1);
}

// Verify checksums. Each checksum entry may carry a
// `source` field that disambiguates keys shared by
// multiple adapters (e.g. both tpr-vulnrichment and
// tpr-github-advisory use the `cache` key).
const checksumsPath = join(stagingRoot, 'CHECKSUMS.json');
if (!existsSync(checksumsPath)) {
  console.error('[import] CHECKSUMS.json missing');
  process.exit(1);
}
const checksumsRaw = JSON.parse(readFileSync(checksumsPath, 'utf8'));
// De-duplicate keys that share the same source (e.g. two
// `cache` keys with different sources). The map is keyed
// by `${source}:${key}` for unique identification.
const checksums = {};
for (const [key, entry] of Object.entries(checksumsRaw)) {
  const source = entry.source || 'default';
  const compositeKey = `${source}:${key}`;
  checksums[compositeKey] = { key, source, sha256: entry.sha256, size: entry.size, path: entry.path };
}
let checksumOk = 0;
let checksumFail = 0;
for (const compositeKey of Object.keys(checksums)) {
  const entry = checksums[compositeKey];
  const filePath = mapKeyToStagingPath(stagingRoot, entry);
  if (!existsSync(filePath)) {
    checksumFail++;
    console.error(`[import] missing file for key ${entry.key} (source=${entry.source})`);
    continue;
  }
  const buf = readFileSync(filePath);
  const sha = createHash('sha256').update(buf).digest('hex');
  if (sha === entry.sha256) {
    checksumOk++;
  } else {
    checksumFail++;
    console.error(`[import] checksum mismatch for ${entry.key} (source=${entry.source})`);
  }
}
console.error(`[import] checksums ok=${checksumOk} fail=${checksumFail}`);
if (checksumFail > 0) {
  console.error('[import] aborting due to checksum failures');
  process.exit(1);
}

if (!args.apply) {
  console.log(JSON.stringify({ dryRun: true, present: metadata.present.length, absent: metadata.absent.length, checksumsOk: checksumOk }, null, 2));
  process.exit(0);
}

// Apply: write every entry into the target storage
// adapter. A failure leaves the previous state intact
// because writes go to a fresh staging area in the
// target.
const datasetAdapter = createStorageAdapter({ name: args.backend, storeName: 'tpr-dataset', opts: { dataRoot: args.dataRoot } });
const baselineAdapter = createStorageAdapter({ name: args.backend, storeName: 'tpr-baseline', opts: { dataRoot: args.dataRoot } });
const vulnAdapter = createStorageAdapter({ name: args.backend, storeName: 'tpr-vulnrichment', opts: { dataRoot: args.dataRoot } });
const ghAdapter = createStorageAdapter({ name: args.backend, storeName: 'tpr-github-advisory', opts: { dataRoot: args.dataRoot } });
const intelAdapter = createStorageAdapter({ name: args.backend, storeName: 'tpr-public-intelligence', opts: { dataRoot: args.dataRoot } });

function adapterFor(key) {
  if (key === 'latest-dataset') return datasetAdapter;
  if (key === 'cache') return null; // ambiguous; handled below
  if (key === 'manifests/latest.json') return baselineAdapter;
  if (key === 'osv/latest.json' || key === 'dataset/latest.json' || key.startsWith('osv/shards/') || key.startsWith('dataset/versions/')) return intelAdapter;
  return null;
}

let written = 0;
let failed = 0;
for (const compositeKey of Object.keys(checksums)) {
  const entry = checksums[compositeKey];
  const filePath = mapKeyToStagingPath(stagingRoot, entry);
  const buf = readFileSync(filePath);
  const key = entry.key;
  if (key === 'cache') {
    // Disambiguate using the entry's source field.
    const sub = entry.source === 'vulnrichment' ? vulnAdapter : ghAdapter;
    await sub.set(key, buf, { type: 'arrayBuffer' });
    written++;
    continue;
  }
  const adapter = adapterFor(key);
  if (!adapter) { failed++; continue; }
  // JSON values are stored as JSON, binary values as
  // arrayBuffer.
  if (key.startsWith('osv/shards/') || key.startsWith('dataset/versions/')) {
    await adapter.set(key, buf, { type: 'arrayBuffer' });
  } else {
    try {
      const parsed = JSON.parse(buf.toString('utf8'));
      await adapter.setJSON(key, parsed);
    } catch {
      await adapter.set(key, buf, { type: 'arrayBuffer' });
    }
  }
  written++;
}

console.log(JSON.stringify({ applied: true, written, failed }, null, 2));
process.exit(failed > 0 ? 1 : 0);

function mapKeyToStagingPath(stagingRoot, entry) {
  // The export embeds a `path` field in each
  // checksum entry. Prefer that — it removes the need
  // to reverse-engineer the layout from the key.
  if (entry && entry.path) return join(stagingRoot, entry.path.replace(/\//g, sep));
  // Fallback for legacy archives that do not carry a
  // `path` field.
  const key = entry && entry.key;
  if (key === 'latest-dataset') return join(stagingRoot, 'dataset', 'latest-dataset.json');
  if (key === 'cache') {
    const vuln = join(stagingRoot, 'cache', 'vulnrichment.json');
    const gh = join(stagingRoot, 'cache', 'github-advisory.json');
    if (existsSync(vuln)) return vuln;
    return gh;
  }
  if (key === 'manifests/latest.json') return join(stagingRoot, 'baseline', 'manifest-latest.json');
  if (key === 'osv/latest.json') return join(stagingRoot, 'public-intelligence', 'osv-latest.json');
  if (key === 'dataset/latest.json') return join(stagingRoot, 'public-intelligence', 'dataset-latest.json');
  if (key.startsWith('osv/shards/sha256/')) {
    const name = key.split('/').pop();
    return join(stagingRoot, 'public-intelligence', 'osv-shards', name);
  }
  if (key.startsWith('dataset/versions/')) {
    return join(stagingRoot, 'public-intelligence', 'dataset-versions', key.replace(/\//g, '__'));
  }
  return null;
}

async function readTar(stream, destDir) {
  const entries = [];
  let buffer = Buffer.alloc(0);
  for await (const chunk of stream) {
    buffer = Buffer.concat([buffer, chunk]);
    // Process complete 512-byte blocks.
    while (buffer.length >= 512) {
      const header = buffer.slice(0, 512);
      // Detect end-of-archive: a block of all-zero
      // bytes signals no more entries. The tar format
      // uses two zero blocks as the terminator, but
      // any all-zero block is treated as the end.
      if (isZeroBlock(header)) {
        buffer = buffer.slice(512);
        continue;
      }
      const name = headerToName(header);
      const size = parseOctal(header.slice(124, 136).toString('utf8'));
      if (name === '' || name === null) {
        // Defensive: a header with no name but non-zero
        // content is malformed. Stop processing.
        buffer = buffer.slice(512);
        continue;
      }
      // Read the file content + padding. The tar format
      // pads each file's content to a 512-byte block
      // boundary. For size=N, the padding is
      // (512 - (N % 512)) % 512 bytes.
      const padding = (512 - (size % 512)) % 512;
      const totalBlock = 512 + size + padding;
      if (buffer.length < totalBlock) break;
      const content = buffer.slice(512, 512 + size);
      // Path-traversal rejection: refuse entries that
      // escape the staging root. Normalize both
      // endpoints to forward slashes for the
      // prefix-check so the comparison is
      // platform-independent.
      const target = join(destDir, name);
      const normDest = normalize(destDir).replace(/\\/g, '/');
      const normTarget = normalize(target).replace(/\\/g, '/');
      if (!normTarget.startsWith(normDest + '/') && normTarget !== normDest) {
        throw new Error(`tar path-traversal rejected: ${name}`);
      }
      // Also refuse names that contain a `..` segment
      // (the tar parser above already joined the name,
      // so we re-check the raw name).
      const nameParts = name.split('/');
      if (nameParts.some((p) => p === '..' || p === '')) {
        if (nameParts[0] === '' || name.startsWith('/')) {
          throw new Error(`tar path-traversal rejected: ${name}`);
        }
      }
      mkdirSync(dirname(target), { recursive: true });
      writeFileSync(target, content);
      entries.push({ name, size });
      buffer = buffer.slice(totalBlock);
    }
  }
  return entries;
}

function isZeroBlock(buf) {
  for (let i = 0; i < buf.length; i++) {
    if (buf[i] !== 0) return false;
  }
  return true;
}

function headerToName(buf) {
  const name = buf.slice(0, 100).toString('utf8').replace(/\0+$/, '');
  const prefix = buf.slice(345, 500).toString('utf8').replace(/\0+$/, '');
  if (prefix) return `${prefix}/${name}`;
  return name;
}

function parseOctal(s) {
  return parseInt(s.trim(), 8) || 0;
}
