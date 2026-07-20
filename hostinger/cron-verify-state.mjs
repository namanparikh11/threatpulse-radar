#!/usr/bin/env node
/**
 * V6.3 — Hostinger cron entrypoint: state verification.
 *
 * Cron expression (recommended): `30 6 * * *` (daily at 06:30).
 *
 *   30 6 * * *  cd /home/<user>/threatpulse-radar && THREATPULSE_DATA_ROOT=/home/<user>/threatpulse-state node hostinger/cron-verify-state.mjs >> /home/<user>/threatpulse-logs/verify-state.log 2>&1
 *
 * The verify-state exit codes:
 *   0   every required artifact is present
 *   6   partial (some artifacts missing)
 *   4   storage failure
 *
 * The cron job propagates the same exit code to the
 * Hostinger control panel, which surfaces it as a
 * "failed" run. Operators wire this to email
 * notifications or a monitoring webhook.
 */

import { LOCK_NAMES } from './locks.mjs';
import { runCronJob } from './cron-runner.mjs';
import { spawnV62Job } from './cron-spawn.mjs';

function mapV62CodeToStatus(code, stdout) {
  if (code === 0) {
    let report = null;
    try { report = JSON.parse(stdout); } catch { /* noop */ }
    return { status: 'ok', present: report && Array.isArray(report.present) ? report.present.length : null, missing: report && Array.isArray(report.missing) ? report.missing.length : null };
  }
  if (code === 6) {
    let report = null;
    try { report = JSON.parse(stdout); } catch { /* noop */ }
    return { status: 'partial', missing: report && Array.isArray(report.missing) ? report.missing.map((m) => m.label || m.key) : null };
  }
  if (code === 4) return { status: 'storage-failure' };
  if (code === 1) return { status: 'invalid-args' };
  return { status: 'error', code };
}

runCronJob({
  name: LOCK_NAMES.STATE_VERIFY,
  job: async ({ logger, config }) => {
    logger.info({ msg: 'verify-state.invoking-v62-module' });
    const r = await spawnV62Job('jobs/verify-state.mjs', {
      THREATPULSE_STORAGE_BACKEND: config.backend,
      THREATPULSE_DATA_ROOT: config.dataRoot,
    }, { extraArgs: ['--json'], logger });
    logger.info({ msg: 'verify-state.v62-result', code: r.code, timedOut: r.timedOut });
    return mapV62CodeToStatus(r.code, r.out);
  },
}).then((code) => process.exit(code)).catch((err) => {
  console.error(JSON.stringify({ error: 'cron.unhandled', message: err && err.message ? err.message : String(err) }));
  process.exit(1);
});
