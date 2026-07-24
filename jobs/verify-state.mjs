#!/usr/bin/env node
/**
 * V6.2 — verify-state job.
 *
 * Reports the current state of the public-intelligence,
 * dataset, and enrichment stores. Useful for cron
 * diagnostics and for confirming a fresh deployment
 * before scheduling regular refreshes.
 *
 * Usage:
 *   node jobs/verify-state.mjs [--json] [--data-root=...]
 *
 * Exit codes:
 *   0  every required artifact is present
 *   1  invalid arguments
 *   4  storage failure
 *   6  partial state (some artifacts missing)
 */

import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..');

const { logLine, EXIT_CODES, resolveStorage } = await import('./_lib.mjs');
const { runLogRetention } = await import('../hostinger/log-retention.mjs');

function parseArgs(argv) {
  const args = { json: false, dataRoot: null, noLogRetention: false };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json') args.json = true;
    else if (a.startsWith('--data-root=')) args.dataRoot = a.slice('--data-root='.length);
    else if (a === '--no-log-retention') args.noLogRetention = true;
    else if (a === '--help' || a === '-h') {
      console.log('Usage: node jobs/verify-state.mjs [--json] [--data-root=...] [--no-log-retention]');
      process.exit(0);
    }
    else {
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
  logLine('verify-state.storage.unavailable', { message: err && err.message ? err.message : String(err) });
  process.exit(EXIT_CODES.STORAGE_FAILURE);
}

const report = { ok: true, missing: [], present: [], store: { backend: storage.backend, dataRoot: storage.dataRoot || null }, logRetention: null };

// V6.9 — bounded 30-day application-log retention
// runs as a pre-flight step. The retention pass is
// best-effort: a failure here is logged but does NOT
// cause the verify-state job to report a failure
// (the verify-state job's purpose is to confirm data
// store integrity, not log retention). Use
// `--no-log-retention` to skip the pass for ad-hoc
// debugging.
if (!args.noLogRetention) {
  const logDir = process.env.THREATPULSE_LOG_DIR
    || (process.env.HOME
      ? `${process.env.HOME}/threatpulse-logs`
      : './logs');
  try {
    const lr = await runLogRetention({ logDir, retentionDays: 30 });
    report.logRetention = {
      logDir: lr.logDir,
      retentionDays: lr.retentionDays,
      scanned: lr.scanned,
      deleted: lr.deleted,
      errors: lr.errors,
      reason: lr.reason,
      ok: lr.ok,
    };
    logLine('verify-state.log-retention', {
      scanned: lr.scanned,
      deleted: lr.deleted,
      errors: lr.errors,
      reason: lr.reason || 'ok',
    });
  } catch (err) {
    // runLogRetention is documented to never throw;
    // this catch is a defence-in-depth guard only.
    logLine('verify-state.log-retention.error', {
      message: err && err.message ? err.message : 'unknown',
    });
  }
}

async function probe(label, key) {
  try {
    const v = await storage.store.getJSON(key);
    if (v === null || v === undefined) {
      report.missing.push({ label, key });
      report.ok = false;
    } else {
      report.present.push({ label, key });
    }
  } catch (err) {
    report.missing.push({ label, key, error: err && err.message ? err.message : String(err) });
    report.ok = false;
  }
}

try {
  await probe('dataset envelope', 'latest-dataset');
  await probe('vulnrichment cache', 'cache'); // tpr-vulnrichment
  await probe('github advisory cache', 'cache'); // tpr-github-advisory
  // The public-intelligence store is a separate
  // namespace; check it independently.
  const { createStorageAdapter } = await import('../netlify/functions/_shared/storage/index.mjs');
  const intelStore = createStorageAdapter({
    name: storage.backend,
    storeName: 'tpr-public-intelligence',
    opts: { dataRoot: storage.dataRoot },
  });
  const intelLatest = await intelStore.getJSON('osv/latest.json');
  if (intelLatest && typeof intelLatest === 'object') {
    report.present.push({ label: 'osv latest pointer', key: 'osv/latest.json' });
  } else {
    report.missing.push({ label: 'osv latest pointer', key: 'osv/latest.json' });
  }
  const datasetIntelLatest = await intelStore.getJSON('dataset/latest.json');
  if (datasetIntelLatest && typeof datasetIntelLatest === 'object') {
    report.present.push({ label: 'dataset public intelligence latest', key: 'dataset/latest.json' });
  } else {
    report.missing.push({ label: 'dataset public intelligence latest', key: 'dataset/latest.json' });
  }
} catch (err) {
  logLine('verify-state.probe.error', { message: err && err.message ? err.message : String(err) });
  process.exit(EXIT_CODES.STORAGE_FAILURE);
}

if (args.json) {
  console.log(JSON.stringify(report, null, 2));
} else {
  console.log(`ThreatPulse verify-state (backend=${report.store.backend})`);
  for (const p of report.present) console.log(`  ✓ ${p.label} (${p.key})`);
  for (const m of report.missing) console.log(`  ✗ ${m.label} (${m.key})${m.error ? ` — ${m.error}` : ''}`);
}

logLine('verify-state.done', {
  present: report.present.length,
  missing: report.missing.length,
  ok: report.ok,
});

process.exit(report.ok ? EXIT_CODES.SUCCESS : EXIT_CODES.PARTIAL);
