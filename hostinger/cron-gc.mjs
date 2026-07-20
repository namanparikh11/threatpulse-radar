#!/usr/bin/env node
/**
 * V6.3 — Hostinger cron entrypoint: public-intelligence
 * garbage collection.
 *
 * Cron expression (recommended): `25 * * * *` (hourly at :25).
 *
 *   5 * * * *  cd /home/<user>/threatpulse-radar && THREATPULSE_DATA_ROOT=/home/<user>/threatpulse-state node hostinger/cron-gc.mjs >> /home/<user>/threatpulse-logs/gc.log 2>&1
 */

import { LOCK_NAMES } from './locks.mjs';
import { runCronJob } from './cron-runner.mjs';
import { spawnV62Job, mapV62CodeToStatus } from './cron-spawn.mjs';

runCronJob({
  name: LOCK_NAMES.PUBLIC_INTEL_GC,
  job: async ({ logger, config }) => {
    logger.info({ msg: 'gc.invoking-v62-module' });
    const r = await spawnV62Job('jobs/gc-public-intelligence.mjs', {
      THREATPULSE_STORAGE_BACKEND: config.backend,
      THREATPULSE_DATA_ROOT: config.dataRoot,
    }, { logger });
    logger.info({ msg: 'gc.v62-result', code: r.code, timedOut: r.timedOut });
    return mapV62CodeToStatus(r.code);
  },
}).then((code) => process.exit(code)).catch((err) => {
  console.error(JSON.stringify({ error: 'cron.unhandled', message: err && err.message ? err.message : String(err) }));
  process.exit(1);
});
