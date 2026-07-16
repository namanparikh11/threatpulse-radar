#!/usr/bin/env node
/**
 * V6.3 — Hostinger cron entrypoint: public-intelligence
 * garbage collection.
 *
 * Cron expression (recommended): hourly, 5 minutes
 * after the dataset-publish.
 *
 *   5 * * * *  cd /home/<user>/threatpulse-radar && THREATPULSE_DATA_ROOT=/home/<user>/threatpulse-state node hostinger/cron-gc.mjs >> /home/<user>/threatpulse-logs/gc.log 2>&1
 */

import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..');

import { LOCK_NAMES } from './locks.mjs';
import { runCronJob } from './cron-runner.mjs';

function spawnV62Job(scriptRel, env = {}) {
  return new Promise((resolveJob) => {
    const proc = spawn('node', [resolve(root, scriptRel)], {
      cwd: root, stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env, ...env },
    });
    let out = ''; let err = '';
    proc.stdout.on('data', (d) => { out += d.toString(); });
    proc.stderr.on('data', (d) => { err += d.toString(); });
    proc.on('error', (e) => resolveJob({ code: 1, out, err: err + '\n' + (e && e.message || String(e)) }));
    proc.on('close', (code) => resolveJob({ code, out, err }));
  });
}

function mapV62CodeToStatus(code) {
  if (code === 0) return { status: 'ok' };
  if (code === 1) return { status: 'invalid-args' };
  if (code === 2) return { status: 'lock-held' };
  if (code === 3) return { status: 'provider-failure' };
  if (code === 4) return { status: 'storage-failure' };
  if (code === 5) return { status: 'publication-failure' };
  if (code === 6) return { status: 'partial' };
  return { status: 'error', code };
}

runCronJob({
  name: LOCK_NAMES.PUBLIC_INTEL_GC,
  job: async ({ logger, config }) => {
    logger.info({ msg: 'gc.invoking-v62-module' });
    const r = await spawnV62Job('jobs/gc-public-intelligence.mjs', {
      THREATPULSE_STORAGE_BACKEND: config.backend,
      THREATPULSE_DATA_ROOT: config.dataRoot,
    });
    logger.info({ msg: 'gc.v62-result', code: r.code });
    return mapV62CodeToStatus(r.code);
  },
}).then((code) => process.exit(code)).catch((err) => {
  console.error(JSON.stringify({ error: 'cron.unhandled', message: err && err.message ? err.message : String(err) }));
  process.exit(1);
});
