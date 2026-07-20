#!/usr/bin/env node
/**
 * V6.3 — Hostinger cron entrypoint: dataset refresh.
 *
 * Acquires the dataset-refresh lock at the Hostinger
 * level, then runs the V6.2 `jobs/refresh-dataset.mjs`
 * CLI as a child process with the same environment
 * (THREATPULSE_STORAGE_BACKEND, THREATPULSE_DATA_ROOT).
 * The subprocess uses the V6.2 lock; the Hostinger
 * lock prevents a SECOND cron invocation from
 * entering the protected section while the V6.2
 * refresh is in progress.
 *
 * Cron expression (recommended): `0,30 * * * *` (on the hour and half-hour).
 *
 *   (every 30 minutes) cd /home/<user>/threatpulse-radar && THREATPULSE_DATA_ROOT=/home/<user>/threatpulse-state node hostinger/cron-refresh-dataset.mjs >> /home/<user>/threatpulse-logs/refresh-dataset.log 2>&1
 */

import { LOCK_NAMES } from './locks.mjs';
import { runCronJob } from './cron-runner.mjs';
import { spawnV62Job, mapV62CodeToStatus } from './cron-spawn.mjs';

runCronJob({
  name: LOCK_NAMES.DATASET_REFRESH,
  job: async ({ logger, config }) => {
    logger.info({ msg: 'refresh-dataset.invoking-v62-module' });
    const r = await spawnV62Job('jobs/refresh-dataset.mjs', {
      THREATPULSE_STORAGE_BACKEND: config.backend,
      THREATPULSE_DATA_ROOT: config.dataRoot,
    }, { logger });
    logger.info({ msg: 'refresh-dataset.v62-result', code: r.code, timedOut: r.timedOut });
    return mapV62CodeToStatus(r.code);
  },
}).then((code) => process.exit(code)).catch((err) => {
  console.error(JSON.stringify({ error: 'cron.unhandled', message: err && err.message ? err.message : String(err) }));
  process.exit(1);
});
