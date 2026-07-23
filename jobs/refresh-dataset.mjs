#!/usr/bin/env node
/**
 * V6.2 — refresh-dataset job.
 *
 * The actual dataset refresh (CISA + NVD + FIRST EPSS +
 * Vulnrichment + GitHub Advisory + V6.1 publication) is
 * performed by the V5.x / V6.0 / V6.1 Netlify Background
 * Function `refresh-dataset-background.mjs`. On Netlify,
 * the V6.0 scheduled function triggers the background
 * function via the trigger secret.
 *
 * On non-Netlify deployments (filesystem, Hostinger
 * Business, a future VPS), the same shared orchestration
 * in `netlify/functions/_shared/refresh.mjs` runs through
 * the V6.2 storage adapter. This CLI job is the
 * cron-friendly entry point: it acquires the refresh lock,
 * invokes the shared orchestrator, and exits with a
 * meaningful code.
 *
 * Usage:
 *   node jobs/refresh-dataset.mjs [--json] [--data-root=...] [--dry-run]
 *
 * Exit codes:
 *   0  completed successfully
 *   1  invalid arguments
 *   2  lock held by another instance
 *   3  provider failure
 *   4  storage failure
 *   5  publication failure
 *   6  partial / skipped
 */

import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..');

const { logLine, EXIT_CODES, resolveStorage, acquireLock, releaseLock, installSignalHandlers } = await import('./_lib.mjs');

function parseArgs(argv) {
  const args = { json: false, dataRoot: null, dryRun: false };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json') args.json = true;
    else if (a.startsWith('--data-root=')) args.dataRoot = a.slice('--data-root='.length);
    else if (a === '--dry-run') args.dryRun = true;
    else if (a === '--help' || a === '-h') {
      console.log('Usage: node jobs/refresh-dataset.mjs [--json] [--data-root=...] [--dry-run]');
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
  logLine('refresh.storage.unavailable', { message: err && err.message ? err.message : String(err) });
  process.exit(EXIT_CODES.STORAGE_FAILURE);
}

if (args.dryRun) {
  // Dry-run path: do NOT acquire the refresh lock or
  // touch the storage adapter. The Netlify adapter
  // throws when the runtime is missing; the dry-run
  // path is purely informational.
  logLine('refresh.dry-run', { backend: storage.backend });
  console.log(`ThreatPulse refresh-dataset (dry-run)`);
  console.log(`  backend: ${storage.backend}`);
  console.log(`  data root: ${storage.dataRoot || '(netlify runtime)'}`);
  console.log(`  would invoke runRefresh with the shared refresh module`);
  process.exit(EXIT_CODES.SUCCESS);
}

installSignalHandlers(async () => {
  await releaseLock(storage.store, 'refresh-lock');
});

const lockKey = 'refresh-lock';
const lockOwner = `refresh-dataset:${process.pid}`;
const lock = await acquireLock(storage.store, lockKey, { ttlMs: 15 * 60 * 1000, owner: lockOwner });
if (!lock.acquired) {
  logLine('refresh.lock.held', { holder: lock.holder, expiresAt: lock.expiresAt });
  console.error(`Another refresh is in progress (holder=${lock.holder}, expires=${lock.expiresAt})`);
  process.exit(EXIT_CODES.LOCK_HELD);
}

logLine('refresh.start', { store: storage.backend, dryRun: args.dryRun, owner: lockOwner });

// The actual refresh logic lives in refresh.mjs. It
// imports the store helpers which auto-detect the
// Netlify runtime; on a non-Netlify host the helper
// falls back to whatever THREATPULSE_SITE_ID /
// THREATPULSE_BLOBS_TOKEN env vars the operator sets,
// OR — for filesystem — the helper would need to be
// refactored to use the storage adapter directly. For
// now, the CLI delegates the call to the same module
// and reports whatever the module reports.
try {
  const { runRefresh } = await import('../netlify/functions/_shared/refresh.mjs');
  const { buildLiveDataset } = await import('../netlify/functions/_shared/liveBuild.mjs');
  const result = await runRefresh({
    store: storage.store,
    buildFn: (opts) => buildLiveDataset(opts),
  });
  logLine('refresh.done', { status: result.status, fetchedAt: result.fetchedAt || null });
  if (args.json) console.log(JSON.stringify(result, null, 2));
  else {
    console.log(`ThreatPulse refresh-dataset (${result.status})`);
    if (result.fetchedAt) console.log(`  fetchedAt: ${result.fetchedAt}`);
  }
  await releaseLock(storage.store, lockKey);
  if (result.status === 'completed') process.exit(EXIT_CODES.SUCCESS);
  if (result.status === 'in-progress') process.exit(EXIT_CODES.LOCK_HELD);
  if (result.status === 'cooldown' || result.status === 'preserved') process.exit(EXIT_CODES.PARTIAL);
  process.exit(EXIT_CODES.PUBLICATION_FAILURE);
} catch (err) {
  logLine('refresh.failed', { message: err && err.message ? err.message : String(err) });
  await releaseLock(storage.store, lockKey).catch(() => {});
  process.exit(EXIT_CODES.STORAGE_FAILURE);
}
