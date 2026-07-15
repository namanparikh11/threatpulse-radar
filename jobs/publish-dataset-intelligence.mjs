#!/usr/bin/env node
/**
 * V6.2 — publish-dataset-intelligence job.
 *
 * Runs the V6.1 dataset-bound public-intelligence
 * publication chain. The chain migrates any pre-V6.1
 * legacy cache envelopes to carry their precomputed
 * public hashes, then publishes the V6.1 bundle.
 *
 * Usage:
 *   node jobs/publish-dataset-intelligence.mjs [--json] [--data-root=...] [--dry-run]
 *
 * Exit codes:
 *   0  published successfully
 *   1  invalid arguments
 *   2  lock held by another instance
 *   4  storage failure
 *   5  publication failure
 *   6  partial / skipped (a hash is missing; next run upgrades)
 */

import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..');

const { logLine, EXIT_CODES, resolveStorage, acquireLock, releaseLock, installSignalHandlers } = await import('./_lib.mjs');
const { runDatasetPublicationChain } = await import('../netlify/functions/_shared/v61BackgroundChain.mjs');
const { createStorageAdapter } = await import('../netlify/functions/_shared/storage/index.mjs');
const { getVulnrichmentStore, getGithubAdvisoryStore, LATEST_DATASET_KEY } = await import('../netlify/functions/_shared/store.mjs');

function parseArgs(argv) {
  const args = { json: false, dataRoot: null, dryRun: false };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json') args.json = true;
    else if (a.startsWith('--data-root=')) args.dataRoot = a.slice('--data-root='.length);
    else if (a === '--dry-run') args.dryRun = true;
    else if (a === '--help' || a === '-h') {
      console.log('Usage: node jobs/publish-dataset-intelligence.mjs [--json] [--data-root=...] [--dry-run]');
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
  logLine('publish-intel.storage.unavailable', { message: err && err.message ? err.message : String(err) });
  process.exit(EXIT_CODES.STORAGE_FAILURE);
}

installSignalHandlers(async () => {
  // The V6.1 chain uses dataset-publication-lock; release
  // it on signal.
  try { await releaseLock(intelStore, 'dataset/publication-lock'); } catch {}
});

const intelStore = createStorageAdapter({
  name: storage.backend,
  storeName: 'tpr-public-intelligence',
  opts: { dataRoot: storage.dataRoot },
});

const datasetStore = storage.store;
const vulnStore = getVulnrichmentStore();
const ghStore = getGithubAdvisoryStore();

const lockKey = 'dataset/publication-lock';
const lockOwner = `publish-dataset-intel:${process.pid}`;
const lock = await acquireLock(intelStore, lockKey, { ttlMs: 15 * 60 * 1000, owner: lockOwner });
if (!lock.acquired) {
  logLine('publish-intel.lock.held', { holder: lock.holder, expiresAt: lock.expiresAt });
  console.error(`Another publication is in progress (holder=${lock.holder}, expires=${lock.expiresAt})`);
  process.exit(EXIT_CODES.LOCK_HELD);
}

logLine('publish-intel.start', { store: storage.backend, dryRun: args.dryRun, owner: lockOwner });

if (args.dryRun) {
  logLine('publish-intel.dry-run', { owner: lockOwner });
  console.log(`ThreatPulse publish-dataset-intelligence (dry-run)`);
  console.log(`  backend: ${storage.backend}`);
  console.log(`  would invoke runDatasetPublicationChain`);
  await releaseLock(intelStore, lockKey);
  process.exit(EXIT_CODES.SUCCESS);
}

try {
  const result = await runDatasetPublicationChain({
    datasetStore, vulnrichmentStore: vulnStore, githubAdvisoryStore: ghStore, intelStore,
  });
  await releaseLock(intelStore, lockKey);
  logLine('publish-intel.done', { published: result.published === true, skipped: result.skipped === true, reason: result.reason || null });
  if (args.json) console.log(JSON.stringify(result, null, 2));
  else {
    if (result.published === true) {
      console.log(`ThreatPulse publish-dataset-intelligence (published)`);
      console.log(`  publicIntelligenceVersion: ${result.publicIntelligenceVersion}`);
    } else if (result.skipped) {
      console.log(`ThreatPulse publish-dataset-intelligence (skipped: ${result.reason})`);
      process.exit(EXIT_CODES.PARTIAL);
    } else {
      console.log(`ThreatPulse publish-dataset-intelligence (no-result)`);
      process.exit(EXIT_CODES.PUBLICATION_FAILURE);
    }
  }
  process.exit(EXIT_CODES.SUCCESS);
} catch (err) {
  logLine('publish-intel.failed', { message: err && err.message ? err.message : String(err) });
  await releaseLock(intelStore, lockKey).catch(() => {});
  process.exit(EXIT_CODES.STORAGE_FAILURE);
}
