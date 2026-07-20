#!/usr/bin/env node
/**
 * V6.3 — Hostinger cron entrypoint: dataset-bound
 * public-intelligence publication.
 *
 * Cron expression (recommended): `20,50 * * * *` (every 30 minutes at :20 and :50).
 *
 *   15,45 * * * *  cd /home/<user>/threatpulse-radar && THREATPULSE_DATA_ROOT=/home/<user>/threatpulse-state node hostinger/cron-publish-dataset.mjs >> /home/<user>/threatpulse-logs/publish-dataset.log 2>&1
 */

import { LOCK_NAMES } from './locks.mjs';
import { runCronJob } from './cron-runner.mjs';
import { spawnV62Job, mapV62CodeToStatus } from './cron-spawn.mjs';

runCronJob({
  name: LOCK_NAMES.DATASET_PUBLISH,
  job: async ({ logger, config }) => {
    logger.info({ msg: 'publish-dataset.invoking-v62-module' });
    const r = await spawnV62Job('jobs/publish-dataset-intelligence.mjs', {
      THREATPULSE_STORAGE_BACKEND: config.backend,
      THREATPULSE_DATA_ROOT: config.dataRoot,
    }, { logger });
    logger.info({ msg: 'publish-dataset.v62-result', code: r.code, timedOut: r.timedOut });
    return mapV62CodeToStatus(r.code);
  },
}).then((code) => process.exit(code)).catch((err) => {
  console.error(JSON.stringify({ error: 'cron.unhandled', message: err && err.message ? err.message : String(err) }));
  process.exit(1);
});
