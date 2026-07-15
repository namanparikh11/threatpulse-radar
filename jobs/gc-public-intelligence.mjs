#!/usr/bin/env node
/**
 * V6.2 — gc-public-intelligence job.
 *
 * Runs the V6.1 mark-and-sweep GC over the public-
 * intelligence OSV shards. Best-effort: failures are
 * logged and a non-zero exit code is returned, but the
 * previous latest.json is never invalidated by GC.
 *
 * Usage:
 *   node jobs/gc-public-intelligence.mjs [--json] [--data-root=...] [--dry-run]
 *
 * Exit codes:
 *   0  GC ran cleanly
 *   1  invalid arguments
 *   4  storage failure
 *   5  GC failure
 */

import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..');

const { logLine, EXIT_CODES, resolveStorage } = await import('./_lib.mjs');
const { runOsvGc } = await import('../netlify/functions/_shared/osvProjectionGc.mjs');

function parseArgs(argv) {
  const args = { json: false, dataRoot: null, dryRun: false };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json') args.json = true;
    else if (a.startsWith('--data-root=')) args.dataRoot = a.slice('--data-root='.length);
    else if (a === '--dry-run') args.dryRun = true;
    else if (a === '--help' || a === '-h') {
      console.log('Usage: node jobs/gc-public-intelligence.mjs [--json] [--data-root=...] [--dry-run]');
      process.exit(0);
    } else {
      console.error(`Unknown argument: ${a}`);
      process.exit(EXIT_CODES.INVALID_ARGS);
    }
  }
  return args;
}

const args = parseArgs(process.argv);

let storage;
try {
  storage = await resolveStorage({ dataRoot: args.dataRoot });
} catch (err) {
  logLine('gc.storage.unavailable', { message: err && err.message ? err.message : String(err) });
  process.exit(EXIT_CODES.STORAGE_FAILURE);
}

// The public-intelligence store lives in its own
// namespace; create an adapter for it.
const { createStorageAdapter } = await import('../netlify/functions/_shared/storage/index.mjs');
const intelStore = createStorageAdapter({
  name: storage.backend,
  storeName: 'tpr-public-intelligence',
  opts: { dataRoot: storage.dataRoot },
});

logLine('gc.start', { store: storage.backend, dryRun: args.dryRun });

let result;
try {
  result = await runOsvGc(intelStore);
} catch (err) {
  logLine('gc.failed', { message: err && err.message ? err.message : String(err) });
  process.exit(EXIT_CODES.PUBLICATION_FAILURE);
}

if (args.dryRun) {
  logLine('gc.dry-run', { retained: result.retained, attempted: result.attempted });
  console.log(`ThreatPulse gc-public-intelligence (dry-run)`);
  console.log(`  retained: ${result.retained}`);
  console.log(`  attempted: ${result.attempted}`);
  console.log(`  would-delete: 0 (dry-run)`);
  process.exit(EXIT_CODES.SUCCESS);
}

logLine('gc.done', {
  retained: result.retained,
  attempted: result.attempted,
  deleted: Array.isArray(result.deleted) ? result.deleted.length : 0,
  status: result.status,
});

if (args.json) {
  console.log(JSON.stringify(result, null, 2));
} else {
  console.log(`ThreatPulse gc-public-intelligence (${result.status})`);
  console.log(`  retained: ${result.retained}`);
  console.log(`  deleted: ${Array.isArray(result.deleted) ? result.deleted.length : 0}`);
}

process.exit(result.status === 'ok' ? EXIT_CODES.SUCCESS : EXIT_CODES.PUBLICATION_FAILURE);
