#!/usr/bin/env node
/**
 * V6.3 — Hostinger cron entrypoint: backup creation.
 *
 * Cron expression (recommended): `40 2 * * *` (daily at 02:40).
 *
 *   0 2 * * *  cd /home/<user>/threatpulse-radar && THREATPULSE_DATA_ROOT=/home/<user>/threatpulse-state THREATPULSE_BACKUP_DIR=/home/<user>/threatpulse-backups node hostinger/cron-backup.mjs >> /home/<user>/threatpulse-logs/backup.log 2>&1
 *
 * The backup command is also exposed as
 * `npm run backup:hostinger`; the cron entrypoint
 * simply wraps it with the Hostinger lock.
 */

import { resolve } from 'node:path';
import { LOCK_NAMES } from './locks.mjs';
import { runCronJob } from './cron-runner.mjs';
import { spawnV62Job } from './cron-spawn.mjs';

function mapBackupCodeToStatus(code, stdout) {
  if (code === 0) {
    let report = null;
    try { report = JSON.parse(stdout); } catch { /* noop */ }
    return { status: 'ok', archive: report && report.archive, sizeBytes: report && report.sizeBytes };
  }
  if (code === 4) return { status: 'storage-failure' };
  if (code === 1) return { status: 'invalid-args' };
  return { status: 'error', code };
}

runCronJob({
  name: LOCK_NAMES.BACKUP_IMPORT,
  job: async ({ logger, config }) => {
    logger.info({ msg: 'backup.invoking-hostinger-backup' });
    const r = await spawnV62Job('hostinger/backup.mjs', {
      THREATPULSE_STORAGE_BACKEND: config.backend,
      THREATPULSE_DATA_ROOT: config.dataRoot,
      THREATPULSE_BACKUP_DIR: process.env.THREATPULSE_BACKUP_DIR || resolve(config.dataRoot, '..', 'threatpulse-backups'),
    }, { extraArgs: ['--json'], logger });
    logger.info({ msg: 'backup.result', code: r.code, timedOut: r.timedOut, outBytes: r.out.length, errBytes: r.err.length });
    return mapBackupCodeToStatus(r.code, r.out);
  },
}).then((code) => process.exit(code)).catch((err) => {
  console.error(JSON.stringify({ error: 'cron.unhandled', message: err && err.message ? err.message : String(err) }));
  process.exit(1);
});
