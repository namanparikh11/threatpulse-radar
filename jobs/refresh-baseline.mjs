#!/usr/bin/env node
/**
 * V6.2 — refresh-baseline job.
 *
 * The canonical baseline refresh is performed by the
 * V6.0 Netlify Background Function
 * `refresh-baseline-background.mjs`. The background
 * function runs the OSV orchestrator in a loop bounded
 * by the 15-minute Netlify Background Function ceiling.
 *
 * This CLI job is the cron-friendly entry point for
 * non-Netlify deployments: it acquires the
 * publication lock, runs one orchestrator iteration
 * via the V6.2 storage adapter, and exits with a
 * meaningful code. Operators running on a system with
 * a longer wall-clock budget can chain multiple CLI
 * invocations in a loop (or call the same function
 * with `--loop`).
 *
 * Usage:
 *   node jobs/refresh-baseline.mjs [--json] [--data-root=...] [--dry-run]
 *
 * Exit codes:
 *   0  orchestrator reported done=true
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
      console.log('Usage: node jobs/refresh-baseline.mjs [--json] [--data-root=...] [--dry-run]');
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
  storage = await resolveStorage({ dataRoot: args.dataRoot, storeName: 'tpr-baseline' });
} catch (err) {
  logLine('refresh-baseline.storage.unavailable', { message: err && err.message ? err.message : String(err) });
  process.exit(EXIT_CODES.STORAGE_FAILURE);
}

installSignalHandlers(async () => {
  await releaseLock(storage.store, 'publication-lock');
});

const lockKey = 'publication-lock';
const lockOwner = `refresh-baseline:${process.pid}`;
const lock = await acquireLock(storage.store, lockKey, { ttlMs: 15 * 60 * 1000, owner: lockOwner });
if (!lock.acquired) {
  logLine('refresh-baseline.lock.held', { holder: lock.holder, expiresAt: lock.expiresAt });
  console.error(`Another publication is in progress (holder=${lock.holder}, expires=${lock.expiresAt})`);
  process.exit(EXIT_CODES.LOCK_HELD);
}

logLine('refresh-baseline.start', { store: storage.backend, dryRun: args.dryRun, owner: lockOwner });

if (args.dryRun) {
  logLine('refresh-baseline.dry-run', { owner: lockOwner });
  console.log(`ThreatPulse refresh-baseline (dry-run)`);
  console.log(`  backend: ${storage.backend}`);
  console.log(`  data root: ${storage.dataRoot || '(netlify runtime)'}`);
  await releaseLock(storage.store, lockKey);
  process.exit(EXIT_CODES.SUCCESS);
}

try {
  // The V6.0 OSV orchestrator runs one iteration. It
  // uses the same V6.2 storage adapter. The orchestrator
  // returns { done, phase, manifest, published, ... }.
  const { runOsvBackground } = await import('../netlify/functions/_shared/osvBackground.mjs');
  const { runBaselinePublicationChain } = await import('../netlify/functions/_shared/v61BackgroundChain.mjs');
  const orchestratorArgs = { store: storage.store };
  const orchestratorResult = await runOsvBackground(orchestratorArgs);
  // If the orchestrator reported a successful
  // publication, run the V6.1 chain (OSV projection +
  // GC). This mirrors the wiring in the Netlify
  // background function.
  let chainResult = null;
  if (orchestratorResult && orchestratorResult.published && orchestratorResult.manifest) {
    chainResult = await runBaselinePublicationChain({ store: storage.store, runOrchestrator: async () => orchestratorResult });
  }
  logLine('refresh-baseline.done', {
    status: orchestratorResult.status,
    done: orchestratorResult.done,
    published: orchestratorResult.published,
    recordsProcessed: orchestratorResult.recordsProcessed,
    v61OsvProjection: chainResult && chainResult.v61OsvProjection ? chainResult.v61OsvProjection.skipped === false ? 'published' : `skipped:${chainResult.v61OsvProjection.reason}` : 'not-run',
  });
  await releaseLock(storage.store, lockKey);
  if (args.json) {
    console.log(JSON.stringify({ orchestrator: orchestratorResult, chain: chainResult && { v61OsvProjection: chainResult.v61OsvProjection, v61OsvGc: chainResult.v61OsvGc } }, null, 2));
  } else {
    console.log(`ThreatPulse refresh-baseline (${orchestratorResult.status})`);
    console.log(`  done: ${orchestratorResult.done}`);
    console.log(`  published: ${orchestratorResult.published}`);
    console.log(`  recordsProcessed: ${orchestratorResult.recordsProcessed}`);
    if (chainResult && chainResult.v61OsvProjection) {
      const s = chainResult.v61OsvProjection;
      console.log(`  v61 OSV projection: ${s.skipped === false ? 'published' : `skipped:${s.reason}`}`);
    }
  }
  if (orchestratorResult.status === 'failed') process.exit(EXIT_CODES.PUBLICATION_FAILURE);
  if (!orchestratorResult.done) process.exit(EXIT_CODES.PARTIAL);
  process.exit(EXIT_CODES.SUCCESS);
} catch (err) {
  logLine('refresh-baseline.failed', { message: err && err.message ? err.message : String(err) });
  await releaseLock(storage.store, lockKey).catch(() => {});
  process.exit(EXIT_CODES.STORAGE_FAILURE);
}
