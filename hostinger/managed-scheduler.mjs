/**
 * V6.3 — Managed Hostinger scheduler.
 *
 * The Hostinger Business managed Node.js application
 * plan does NOT expose Cron Jobs. The standalone
 * hostinger/cron-*.mjs entrypoints therefore cannot
 * be launched by an OS scheduler on a managed
 * deployment. This module provides an opt-in,
 * in-process scheduler that the Hostinger
 * application starts AFTER the HTTP server is
 * listening.
 *
 * The scheduler is disabled by default. Enable it
 * with `THREATPULSE_MANAGED_SCHEDULER=1`. The
 * optional `THREATPULSE_MANAGED_SCHEDULER_BOOTSTRAP=1`
 * flag controls whether a missing-dataset refresh is
 * scheduled once shortly after startup (the bootstrap
 * is the only deviation from a pure repeating
 * schedule; the bootstrap is invoked at most once per
 * process lifetime).
 *
 * Design invariants (enforced by the code and by the
 * V6.3 acceptance suite):
 *
 *   1. The scheduler NEVER calls `process.exit`. The
 *      application owns the process lifecycle.
 *   2. The scheduler NEVER adds a public HTTP route.
 *      All trigger paths are local timers and local
 *      filesystem locks.
 *   3. The scheduler NEVER duplicates a timer. After
 *      each execution exactly ONE next-occurrence
 *      timer is scheduled.
 *   4. The scheduler NEVER drifts. Every timer is a
 *      bounded `setTimeout` to a UTC wall-clock
 *      target. The next occurrence is recomputed
 *      after every execution.
 *   5. The scheduler is idempotent. Calling `start`
 *      twice is a no-op. Calling `stop` when not
 *      started is a no-op.
 *   6. The scheduler is process-local. Cross-process
 *      exclusion is provided by the existing
 *      mkdir-based cron locks in `./locks.mjs`.
 *   7. The scheduler NEVER blocks the HTTP server.
 *      Each job is dispatched as a background task.
 *   8. Job failures are logged in sanitized form.
 *      No secret value ever enters a log message.
 *   9. The scheduler is opt-in. When
 *      `THREATPULSE_MANAGED_SCHEDULER` is unset or
 *      has any value other than `1`, the scheduler
 *      is a no-op and the application runs exactly
 *      as it did before.
 *
 * Schedules (UTC):
 *
 *   dataset refresh:        minute 0 and 30 of every hour
 *   baseline refresh:       minute 10 of every hour
 *   dataset publish:       minute 20 and 50 of every hour
 *   public-intel GC:       minute 25 of every hour
 *   state verify:           06:30 UTC daily
 *   backup:                 02:40 UTC daily
 *
 * Testability:
 *
 *   The scheduler accepts a `now()` clock function
 *   and a `timerApi = { setTimeout, clearTimeout }`
 *   object. Production calls use the real Node.js
 *   `setTimeout` / `clearTimeout`. Tests inject a
 *   fake clock and a fake timer to advance time
 *   deterministically.
 */

import { fileURLToPath } from 'node:url';
import { dirname, resolve, join } from 'node:path';
import { existsSync } from 'node:fs';
import { LOCK_NAMES } from './locks.mjs';
import { runJob } from './cron-runner.mjs';
import { spawnV62Job, mapV62CodeToStatus } from './cron-spawn.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..');

/**
 * The V6.3 Hostinger plan schedule. Every entry is
 * a UTC occurrence description.
 *
 *   type: 'minutes-of-hour' → fires on the listed
 *         minutes of every hour (UTC)
 *   type: 'daily'            → fires once per day at
 *         the documented UTC HH:MM
 */
export const MANAGED_SCHEDULE = Object.freeze([
  Object.freeze({ name: LOCK_NAMES.DATASET_REFRESH,  label: 'dataset-refresh',  scriptRel: 'jobs/refresh-dataset.mjs',         type: 'minutes-of-hour', minutes: [0, 30] }),
  Object.freeze({ name: LOCK_NAMES.BASELINE_REFRESH, label: 'baseline-refresh', scriptRel: 'jobs/refresh-baseline.mjs',        type: 'minutes-of-hour', minutes: [10] }),
  Object.freeze({ name: LOCK_NAMES.DATASET_PUBLISH,  label: 'dataset-publish',  scriptRel: 'jobs/publish-dataset-intelligence.mjs', type: 'minutes-of-hour', minutes: [20, 50] }),
  Object.freeze({ name: LOCK_NAMES.PUBLIC_INTEL_GC,  label: 'public-intel-gc',  scriptRel: 'jobs/gc-public-intelligence.mjs',  type: 'minutes-of-hour', minutes: [25] }),
  Object.freeze({ name: LOCK_NAMES.STATE_VERIFY,     label: 'state-verify',     scriptRel: 'jobs/verify-state.mjs',             type: 'daily',           hour: 6,  minute: 30 }),
  Object.freeze({ name: LOCK_NAMES.BACKUP_IMPORT,    label: 'backup',           scriptRel: 'hostinger/backup.mjs',              type: 'daily',           hour: 2,  minute: 40, extraArgs: [] }),
]);

/**
 * True when the `THREATPULSE_MANAGED_SCHEDULER`
 * environment variable is the literal string `1`.
 * Every other value (unset, empty, `true`, `yes`,
 * `on`, anything else) keeps the scheduler
 * disabled. The strict equality avoids accidental
 * activation through a misconfigured
 * `THREATPULSE_MANAGED_SCHEDULER=true` in a
 * service that already uses `0`/`1` elsewhere.
 */
export function isManagedSchedulerEnabled(env = process.env) {
  return env && env.THREATPULSE_MANAGED_SCHEDULER === '1';
}

/**
 * True when the bootstrap (a single dataset refresh
 * shortly after startup when the dataset is missing)
 * is enabled. Same strict-equality semantics as
 * `isManagedSchedulerEnabled`.
 */
export function isManagedSchedulerBootstrapEnabled(env = process.env) {
  return env && env.THREATPULSE_MANAGED_SCHEDULER_BOOTSTRAP === '1';
}

/**
 * Calculate the next UTC Date at which a schedule
 * entry fires. The function is pure and depends
 * only on `now`. The returned Date is the FIRST
 * occurrence strictly after `now` (so a job that
 * fires at the same minute as `now` is treated as
 * already-elapsed and the next occurrence is the
 * following slot).
 *
 * For 'minutes-of-hour' the algorithm finds the
 * smallest minute in the list that is > current
 * minute; if none exists, the first minute of the
 * next hour is returned.
 *
 * For 'daily' the algorithm finds the next
 * occurrence of HH:MM. If today's slot is in the
 * future, today is returned; otherwise tomorrow.
 */
export function nextOccurrenceUtc(entry, now = new Date()) {
  if (!entry || typeof entry !== 'object') {
    throw new Error('nextOccurrenceUtc: entry is required');
  }
  const year = now.getUTCFullYear();
  const month = now.getUTCMonth();
  const day = now.getUTCDate();
  const hour = now.getUTCHours();
  const minute = now.getUTCMinutes();
  const second = now.getUTCSeconds();
  const millisecond = now.getUTCMilliseconds();
  if (entry.type === 'minutes-of-hour') {
    const minutes = Array.isArray(entry.minutes) ? entry.minutes.slice().sort((a, b) => a - b) : [];
    if (minutes.length === 0) {
      throw new Error(`nextOccurrenceUtc: minutes-of-hour entry ${entry.label} has no minutes`);
    }
    for (const m of minutes) {
      if (m > minute) {
        return new Date(Date.UTC(year, month, day, hour, m, 0, 0));
      }
    }
    // Wrap to the first minute of the next hour.
    const next = new Date(Date.UTC(year, month, day, hour, minute, second, millisecond));
    next.setUTCHours(hour + 1, minutes[0], 0, 0);
    return next;
  }
  if (entry.type === 'daily') {
    const h = entry.hour;
    const m = entry.minute;
    if (typeof h !== 'number' || typeof m !== 'number') {
      throw new Error(`nextOccurrenceUtc: daily entry ${entry.label} missing hour/minute`);
    }
    // Today's slot at HH:MM:00.000 UTC.
    const today = new Date(Date.UTC(year, month, day, h, m, 0, 0));
    if (today.getTime() > now.getTime()) return today;
    // Otherwise tomorrow.
    return new Date(Date.UTC(year, month, day + 1, h, m, 0, 0));
  }
  throw new Error(`nextOccurrenceUtc: unknown type for ${entry.label}`);
}

/**
 * Test the equality of two `Date` instances at
 * minute resolution (UTC). Used by the test suite
 * to avoid comparing real-time Date construction
 * (which differs by milliseconds across runs).
 */
export function sameUtcMinute(a, b) {
  if (!(a instanceof Date) || !(b instanceof Date)) return false;
  return a.getUTCFullYear() === b.getUTCFullYear()
    && a.getUTCMonth() === b.getUTCMonth()
    && a.getUTCDate() === b.getUTCDate()
    && a.getUTCHours() === b.getUTCHours()
    && a.getUTCMinutes() === b.getUTCMinutes();
}

/**
 * Build the callable job function for a schedule
 * entry. The function acquires no lock of its own;
 * `runJob` acquires the canonical Hostinger cron
 * lock and emits the sanitized log records. The
 * job body spawns the V6.2 job as a child process
 * using the shared `spawnV62Job` helper.
 */
function buildJob(entry) {
  return async ({ logger, config }) => {
    logger.info({ msg: 'managed-scheduler.invoking-v62-module', scheduleLabel: entry.label });
    const r = await spawnV62Job(entry.scriptRel, {
      THREATPULSE_STORAGE_BACKEND: config.backend,
      THREATPULSE_DATA_ROOT: config.dataRoot,
    }, { extraArgs: entry.extraArgs || [], logger });
    logger.info({ msg: 'managed-scheduler.v62-result', scheduleLabel: entry.label, code: r.code, timedOut: r.timedOut });
    return mapV62CodeToStatus(r.code);
  };
}

/**
 * Look up the filesystem path the V6.2 storage
 * adapter considers the "current dataset". When
 * the file exists, bootstrap is suppressed. When
 * the file is missing, bootstrap schedules one
 * dataset-refresh job shortly after startup.
 *
 * The exact filename is what
 * `netlify/functions/dataset.mjs` reads first; the
 * portable CLI uses the same convention. The
 * location is `$THREATPULSE_DATA_ROOT/dataset/latest.json`
 * — see docs/v6-2-portability.md and
 * `netlify/functions/_shared/store.mjs` for the
 * authoritative contract.
 */
export function datasetPathForConfig(config) {
  if (!config || !config.dataRoot) return null;
  return join(config.dataRoot, 'dataset', 'latest.json');
}

export function datasetExists(config) {
  const p = datasetPathForConfig(config);
  if (!p) return false;
  try { return existsSync(p); } catch { return false; }
}

/**
 * Create a managed scheduler controller.
 *
 *   config         the resolved Hostinger config
 *                  (from `resolveHostingerConfig`)
 *   logger         the Hostinger application logger
 *                  (a function that accepts
 *                  `{ component, filePath, debug }`
 *                  and returns the standard logger)
 *   options.env    override `process.env` (tests)
 *   options.now    override `Date.now` clock (tests)
 *   options.timerApi
 *                  { setTimeout, clearTimeout }
 *                  override; tests inject a fake
 *                  timer
 *   options.bootstrapDelayMs
 *                  override the bootstrap delay
 *                  (default 15_000 ms in production
 *                  so the HTTP server has time to
 *                  finish `listen` and accept the
 *                  first connection before the
 *                  refresh fires)
 *
 * Returned controller:
 *   .isEnabled()   boolean
 *   .isBootstrapEnabled()   boolean
 *   .start()       idempotent; schedules every
 *                  entry's first occurrence
 *   .stop()        clears every active timer and
 *                  waits for any in-flight job to
 *                  finish within `graceMs`
 *                  (default 5_000); idempotent
 *   .nextFor(label)  returns the next Date for a
 *                  schedule entry (or null)
 *   .activeTimers()  number of currently scheduled
 *                  timers
 *   .bootstrapState() one of: 'idle' | 'scheduled'
 *                  | 'running' | 'done' | 'skipped'
 *   .snapshot()    read-only status used by tests
 *                  and by /health introspection
 */
export function createManagedScheduler(config, logger, options = {}) {
  const env = options.env || process.env;
  const enabled = isManagedSchedulerEnabled(env);
  const bootstrapEnabled = isManagedSchedulerBootstrapEnabled(env);
  const now = options.now || (() => new Date());
  const timerApi = options.timerApi || { setTimeout, clearTimeout };
  const bootstrapDelayMs = Number.isFinite(options.bootstrapDelayMs) ? options.bootstrapDelayMs : 15_000;
  const graceMs = Number.isFinite(options.graceMs) ? options.graceMs : 5_000;

  // Map<label, NodeJS.Timeout | fakeHandle>
  const timers = new Map();
  // Set<Promise<void>> for in-flight jobs.
  const inFlight = new Set();
  // Track whether stop() has been called.
  let stopped = false;
  let started = false;
  // Bootstrap state.
  let bootstrapState = enabled && bootstrapEnabled ? 'idle' : 'skipped';

  function logInfo(fields) { try { logger.info(fields); } catch { /* noop */ } }
  function logWarn(fields) { try { logger.warn(fields); } catch { /* noop */ } }
  function logError(fields) { try { logger.error(fields); } catch { /* noop */ } }

  function scheduleOne(entry) {
    if (stopped) return null;
    // Clear any existing timer for this label.
    const existing = timers.get(entry.label);
    if (existing != null) {
      try { timerApi.clearTimeout(existing); } catch { /* noop */ }
      timers.delete(entry.label);
    }
    const target = nextOccurrenceUtc(entry, now());
    const delay = Math.max(0, target.getTime() - now().getTime());
    const handle = timerApi.setTimeout(() => {
      // Drop the timer reference BEFORE awaiting so
      // a reschedule during runOnce does not double-
      // arm.
      timers.delete(entry.label);
      runOnce(entry).catch((err) => {
        logError({ msg: 'managed-scheduler.unhandled', scheduleLabel: entry.label, error: err && err.message ? err.message : String(err) });
      });
    }, delay);
    if (handle && typeof handle.unref === 'function') {
      try { handle.unref(); } catch { /* noop */ }
    }
    timers.set(entry.label, handle);
    logInfo({ msg: 'managed-scheduler.scheduled', scheduleLabel: entry.label, target: target.toISOString(), delayMs: delay });
    return { target, handle };
  }

  async function runOnce(entry) {
    if (stopped) return { status: 'skipped' };
    const promise = (async () => {
      try {
        const { exitCode, summary } = await runJob({
          name: entry.name,
          job: buildJob(entry),
          // The application owns SIGINT/SIGTERM; the
          // scheduler must not install handlers that
          // exit the whole process.
          installSignals: false,
          // Pass through so the runner reads the same
          // env + cwd as the application.
          env,
          argv: process.argv,
          cwd: process.cwd(),
        });
        logInfo({ msg: 'managed-scheduler.done', scheduleLabel: entry.label, exitCode, status: summary && summary.status });
        return { status: summary && summary.status, exitCode };
      } catch (err) {
        logError({ msg: 'managed-scheduler.error', scheduleLabel: entry.label, error: err && err.message ? err.message : String(err) });
        return { status: 'error' };
      } finally {
        if (!stopped) {
          // Reschedule the next occurrence regardless
          // of success / failure / lock-held. A
          // lock-held skip is still a successful
          // attempt and the next slot is correct.
          scheduleOne(entry);
        }
      }
    })();
    inFlight.add(promise);
    promise.finally(() => inFlight.delete(promise));
    return promise;
  }

  function scheduleBootstrap() {
    if (!enabled) return;
    if (!bootstrapEnabled) {
      bootstrapState = 'skipped';
      return;
    }
    if (bootstrapState !== 'idle') return;
    if (datasetExists(config)) {
      bootstrapState = 'skipped';
      logInfo({ msg: 'managed-scheduler.bootstrap.skipped', reason: 'dataset-exists' });
      return;
    }
    bootstrapState = 'scheduled';
    const handle = timerApi.setTimeout(async () => {
      if (stopped) {
        bootstrapState = 'skipped';
        return;
      }
      bootstrapState = 'running';
      const entry = MANAGED_SCHEDULE.find((e) => e.name === LOCK_NAMES.DATASET_REFRESH);
      if (!entry) {
        bootstrapState = 'skipped';
        return;
      }
      try {
        await runOnce(entry);
        // After a successful bootstrap, do not
        // re-schedule bootstrap on a subsequent
        // process restart until the dataset is
        // missing again. The bootstrap is a one-
        // shot per process; restart behaviour is
        // handled by the next-process re-check.
        bootstrapState = 'done';
      } catch (err) {
        logError({ msg: 'managed-scheduler.bootstrap.error', error: err && err.message ? err.message : String(err) });
        bootstrapState = 'skipped';
      }
    }, bootstrapDelayMs);
    if (handle && typeof handle.unref === 'function') {
      try { handle.unref(); } catch { /* noop */ }
    }
    // Note: the bootstrap handle is NOT tracked in
    // `timers` because it is a one-shot. `stop()`
    // still clears it via a dedicated reference.
    bootstrapHandle = handle;
    logInfo({ msg: 'managed-scheduler.bootstrap.scheduled', delayMs: bootstrapDelayMs });
  }

  let bootstrapHandle = null;

  return {
    isEnabled: () => enabled,
    isBootstrapEnabled: () => bootstrapEnabled,
    start() {
      if (!enabled) return { started: false, reason: 'disabled' };
      if (started) return { started: true, reason: 'already-started', activeTimers: timers.size };
      started = true;
      stopped = false;
      for (const entry of MANAGED_SCHEDULE) {
        scheduleOne(entry);
      }
      scheduleBootstrap();
      logInfo({ msg: 'managed-scheduler.started', activeTimers: timers.size, bootstrap: bootstrapState });
      return { started: true, activeTimers: timers.size, bootstrap: bootstrapState };
    },
    async stop({ graceMs: stopGraceMs } = {}) {
      if (stopped) return { stopped: true, reason: 'already-stopped' };
      stopped = true;
      // Clear every scheduled timer.
      for (const [label, handle] of timers.entries()) {
        try { timerApi.clearTimeout(handle); } catch { /* noop */ }
      }
      timers.clear();
      // Clear the bootstrap one-shot if armed.
      if (bootstrapHandle != null) {
        try { timerApi.clearTimeout(bootstrapHandle); } catch { /* noop */ }
        bootstrapHandle = null;
      }
      // Wait for in-flight jobs to finish within
      // the bounded grace period.
      const limit = Number.isFinite(stopGraceMs) ? stopGraceMs : graceMs;
      if (inFlight.size > 0) {
        const all = Promise.allSettled([...inFlight]);
        const timeout = new Promise((resolveTimeout) => {
          const h = timerApi.setTimeout(() => resolveTimeout('timeout'), limit);
          if (h && typeof h.unref === 'function') {
            try { h.unref(); } catch { /* noop */ }
          }
        });
        await Promise.race([all, timeout]);
      }
      logInfo({ msg: 'managed-scheduler.stopped', inFlightRemaining: inFlight.size });
      return { stopped: true, activeTimers: 0, inFlightRemaining: inFlight.size };
    },
    nextFor(label) {
      const entry = MANAGED_SCHEDULE.find((e) => e.label === label);
      if (!entry) return null;
      return nextOccurrenceUtc(entry, now());
    },
    activeTimers: () => timers.size,
    bootstrapState: () => bootstrapState,
    scheduleSnapshot() {
      return MANAGED_SCHEDULE.map((e) => ({
        label: e.label,
        nextAt: nextOccurrenceUtc(e, now()).toISOString(),
        armed: timers.has(e.label),
      }));
    },
    // Exposed for tests only. Production code must
    // not call these directly.
    _runOnce: runOnce,
    _scheduleOne: scheduleOne,
    _isStarted: () => started,
    _isStopped: () => stopped,
  };
}
