/**
 * V6.3 — Hostinger cron runner.
 *
 * A small wrapper that:
 *   1. resolves the Hostinger config
 *   2. acquires the job's lock (or exits 2 if held)
 *   3. installs SIGINT/SIGTERM handlers that release
 *      the lock and exit 130
 *   4. invokes the supplied async fn with a context
 *      object containing the logger + storage
 *   5. releases the lock on success and on failure
 *   6. prints a sanitized one-line operator summary
 *      on stdout, exits 0 on success / 2 on lock /
 *      non-zero on failure
 *
 * The wrapper is the single entry point for every
 * V6.3 cron job. The job entrypoints in this folder
 * are 3-line shims that call `runCronJob` with the
 * right lock name and job function.
 */

import { resolveHostingerConfig, sanitizeError, maskHomePath } from './_lib.mjs';
import { createLogger, dailyLogPath } from './logger.mjs';
import { acquireCronLock, releaseCronLock } from './locks.mjs';

export const CRON_EXIT = Object.freeze({
  SUCCESS: 0,
  INVALID_ARGS: 1,
  LOCK_HELD: 2,
  PROVIDER_FAILURE: 3,
  STORAGE_FAILURE: 4,
  PUBLICATION_FAILURE: 5,
  PARTIAL: 6,
});

/**
 * Run a single cron job under a lock. Returns an
 * exit code but NEVER calls `process.exit`. The
 * caller is responsible for exiting the process
 * (the standalone cron entrypoints do that; the
 * embedded scheduler does not).
 *
 *   options.name           lock name (must be in
 *                          LOCK_NAMES)
 *   options.job            async function (ctx) →
 *                          { status, ... }
 *   options.owner          string; default =
 *                          `${name}:${pid}`
 *   options.ttlMs          lock TTL in ms; default
 *                          15 minutes
 *   options.argv, options.env, options.cwd
 *                          override the default
 *                          process values (used by
 *                          the test suite)
 *   options.installSignals when true (default),
 *                          install SIGINT/SIGTERM
 *                          handlers that release
 *                          the lock and call
 *                          `process.exit(130)`. The
 *                          embedded scheduler
 *                          passes `false` because
 *                          the application owns
 *                          the signal handlers and
 *                          the scheduler is stopped
 *                          via `stop()`, not via
 *                          a signal.
 */
export async function runJob(options) {
  const { name, job, owner, ttlMs, installSignals = true, argv = process.argv, env = process.env, cwd = process.cwd() } = options;
  if (!name) {
    return { exitCode: CRON_EXIT.INVALID_ARGS, summary: { status: 'invalid-args', reason: 'missing-name' } };
  }
  if (typeof job !== 'function') {
    return { exitCode: CRON_EXIT.INVALID_ARGS, summary: { status: 'invalid-args', reason: 'missing-job' } };
  }
  const cfg = resolveHostingerConfig({ argv, env, cwd });
  const logFile = dailyLogPath(cfg.logDir);
  const logger = createLogger({ component: `cron.${name}`, filePath: logFile, debug: !cfg.isProduction });
  const lockOwner = owner || `${name}:${process.pid}`;
  const lockTtl = Number.isFinite(ttlMs) ? ttlMs : 15 * 60 * 1000;
  logger.info({ msg: 'cron.start', lockName: name, owner: lockOwner, ttlMs: lockTtl, dataRoot: maskHomePath(cfg.dataRoot) });
  const lock = await acquireCronLock({
    locksDir: cfg.locksDir, name, ttlMs: lockTtl, owner: lockOwner, pid: process.pid,
  });
  if (!lock.acquired) {
    logger.warn({ msg: 'cron.lock.held', holder: lock.holder, expiresAt: lock.expiresAt, reason: lock.reason });
    return { exitCode: CRON_EXIT.LOCK_HELD, summary: { status: 'lock-held', holder: lock.holder || null, expiresAt: lock.expiresAt || null, reason: lock.reason || null } };
  }
  // Signal handlers (only when the caller wants
  // them). The embedded scheduler passes
  // `installSignals: false` so the application's
  // own SIGINT/SIGTERM handler is the single
  // owner of the process lifecycle.
  let stopping = false;
  const cleanup = async () => {
    try { await releaseCronLock({ locksDir: cfg.locksDir, name, owner: lockOwner }); } catch { /* noop */ }
  };
  const onSignal = async (sig) => {
    if (stopping) return;
    stopping = true;
    logger.warn({ msg: 'cron.signal', signal: sig });
    await cleanup();
    process.exit(130);
  };
  if (installSignals) {
    process.on('SIGINT', onSignal);
    process.on('SIGTERM', onSignal);
  }
  let exitCode = CRON_EXIT.SUCCESS;
  let summary = { status: 'ok' };
  try {
    const result = await job({ logger, config: cfg, locksDir: cfg.locksDir });
    if (result && typeof result === 'object' && typeof result.status === 'string') {
      summary = result;
    }
    logger.info({ msg: 'cron.done', status: summary.status, ...summary });
    // Map status to exit code.
    if (summary.status === 'ok' || summary.status === 'completed' || summary.status === 'success') {
      exitCode = CRON_EXIT.SUCCESS;
    } else if (summary.status === 'lock-held') {
      exitCode = CRON_EXIT.LOCK_HELD;
    } else if (summary.status === 'provider-failure' || summary.status === 'provider-failed') {
      exitCode = CRON_EXIT.PROVIDER_FAILURE;
    } else if (summary.status === 'storage-failure') {
      exitCode = CRON_EXIT.STORAGE_FAILURE;
    } else if (summary.status === 'publication-failure' || summary.status === 'publish-failed') {
      exitCode = CRON_EXIT.PUBLICATION_FAILURE;
    } else if (summary.status === 'partial' || summary.status === 'skipped' || summary.status === 'preserved') {
      exitCode = CRON_EXIT.PARTIAL;
    } else {
      exitCode = CRON_EXIT.SUCCESS;
    }
  } catch (err) {
    logger.error({ msg: 'cron.error', error: sanitizeError(err) });
    summary = { status: 'error', error: err && err.message ? String(err.message).slice(0, 200) : String(err) };
    exitCode = CRON_EXIT.STORAGE_FAILURE;
  } finally {
    await cleanup();
  }
  return { exitCode, summary };
}

/**
 * Run a single cron job under a lock and exit the
 * process with the canonical exit code. This is the
 * legacy V6.3 entrypoint used by the standalone
 * cron command files. The embedded scheduler uses
 * `runJob` directly so it can stay alive across
 * many executions.
 */
export async function runCronJob(options) {
  const { exitCode, summary } = await runJob(options);
  console.log(JSON.stringify({ cron: options.name, ...summary, exitCode, ts: new Date().toISOString() }));
  return exitCode;
}
