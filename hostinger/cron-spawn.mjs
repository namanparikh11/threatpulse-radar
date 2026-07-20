/**
 * V6.3 — Shared V6.2 job spawner for Hostinger cron
 * entrypoints AND the managed scheduler.
 *
 * The Hostinger Business runtime hosts a managed
 * Node.js application that can fork subprocesses
 * for short-lived jobs (refresh, baseline, publish,
 * GC, verify, backup). The same spawner is used by:
 *
 *   - hostinger/cron-refresh-dataset.mjs
 *   - hostinger/cron-refresh-baseline.mjs
 *   - hostinger/cron-publish-dataset.mjs
 *   - hostinger/cron-gc.mjs
 *   - hostinger/cron-verify-state.mjs
 *   - hostinger/cron-backup.mjs
 *   - hostinger/managed-scheduler.mjs (the embedded
 *     in-process scheduler for managed-hosting plans
 *     that do not expose an OS-level cron)
 *
 * Spawning the V6.2 jobs (jobs/*.mjs) as child
 * processes gives every invocation the same code
 * path, the same environment contract, and the
 * same exit-code semantics. The spawner captures
 * stdout and stderr to bounded buffers so the
 * parent can summarize the run without leaking
 * large output into a logger. Buffer sizes are
 * documented below.
 *
 * ## Executable resolution
 *
 * The Hostinger managed-Node application dashboard
 * launches `hostinger/app.mjs` with a specific
 * Node executable, but the same PATH is NOT made
 * available to subsequent `child_process.spawn`
 * calls. A bare `spawn("node", ...)` therefore
 * fails with `ENOENT` because `node` is not on the
 * child-process PATH.
 *
 * The fix is to use the absolute path of the
 * currently running Node executable
 * (`process.execPath`) as the child executable.
 * `process.execPath` is the path that started THIS
 * process; it is always present, does not depend
 * on PATH, and matches the runtime version. This
 * is the default and is used in production.
 *
 * The `execPath` parameter is injectable so the
 * test suite can use a fake spawn that records
 * the executable without depending on a real
 * binary. An empty, missing, or non-string
 * injection is rejected safely.
 *
 * The function NEVER reads secret values; the
 * `env` parameter is a plain object whose keys are
 * standard Hostinger runtime env var names. Values
 * are forwarded as-is. Callers MUST NOT pass
 * credentials through this path.
 */

import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..');

// Bounded buffer sizes. The Hostinger log channel is
// finite; capturing the entire stdout/stderr of a
// long-running provider refresh could blow the log
// allocation. 64 KiB per stream is enough to capture
// every documented one-line summary plus several
// kilobytes of operator-readable progress lines.
const MAX_CAPTURE_BYTES = 64 * 1024;

/**
 * True when `p` is a non-empty absolute filesystem
 * path string. The function is the source of
 * truth for the executable-validity check used
 * before every spawn.
 */
function isValidExecPath(p) {
  if (typeof p !== 'string') return false;
  if (p.length === 0) return false;
  // Reject shell metacharacters that would only
  // be relevant with shell: true, which we never
  // set. The check is defense in depth.
  if (/[\s'"\\;|&`<>$()]/.test(p)) return false;
  return true;
}

/**
 * Sanitize a spawn-failure error for the operator
 * log channel. The function records:
 *
 *   - `error.code`           (ENOENT, EACCES, EPERM, ...)
 *   - `error.spawnable`      whether the failure
 *                            happened before the
 *                            child started
 *   - `error.runtimeExecutable` the string
 *                            `"process.execPath"`
 *                            (the production default)
 *                            or the override label
 *   - `error.message`        the original error
 *                            message (capped at 200
 *                            characters)
 *
 * The function NEVER includes:
 *   - the absolute executable path
 *   - environment-variable values
 *   - the operator's home directory
 *   - credentials
 *   - provider response bodies
 */
function sanitizeSpawnError(err, scriptRel, runtimeExecutableLabel) {
  if (!err) return { code: 'unknown', spawnable: true, runtimeExecutable: runtimeExecutableLabel || 'process.execPath' };
  const out = {
    code: err.code ? String(err.code) : 'unknown',
    spawnable: true,
    runtimeExecutable: runtimeExecutableLabel || 'process.execPath',
    jobLabel: scriptRel || null,
    phase: 'spawn',
  };
  let msg = err.message || String(err);
  if (typeof msg === 'string' && msg.length > 200) msg = msg.slice(0, 200) + '... (truncated)';
  out.message = msg;
  return out;
}

/**
 * Spawn a V6.2 job (`jobs/<scriptRel>.mjs`) as a
 * child process and capture stdout/stderr into
 * bounded buffers. The function returns a
 * `{ code, out, err, truncated, timedOut,
 *    spawnError }` object.
 *
 *   - `code` is the process exit code (number) or
 *     1 if the spawn itself failed.
 *   - `out` / `err` are the captured buffers as
 *     strings (UTF-8). When the buffer exceeded
 *     `MAX_CAPTURE_BYTES`, the buffer ends with a
 *     sentinel `… [truncated]`.
 *   - `truncated` is true if either buffer was
 *     truncated.
 *   - `timedOut` is true if the optional `timeoutMs`
 *     elapsed; the child was killed and `code`
 *     reflects the signal.
 *   - `spawnError` is the sanitized error record
 *     when the spawn itself failed (e.g. ENOENT);
 *     `null` otherwise.
 *
 * The function never throws. It always resolves.
 *
 *   scriptRel      path relative to repo root, e.g.
 *                  `jobs/refresh-dataset.mjs`
 *   env            object of env vars to forward in
 *                  addition to `process.env`
 *   extraArgs      array of args to pass to the
 *                  child (e.g. `--json`, `--dry-run`)
 *   timeoutMs      optional kill-after timeout
 *   cwd            override the cwd (default: repo
 *                  root)
 *   logger         optional logger; receives
 *                  structured spawn-failure events
 *   execPath       override the executable (tests
 *                  only). Production leaves it
 *                  unset and the function uses
 *                  `process.execPath`.
 *   spawnApi       override the `spawn` function
 *                  (tests only). The default is
 *                  `node:child_process.spawn`. The
 *                  override must accept
 *                  `(command, args, options)` and
 *                  return a ChildProcess-shaped
 *                  object that emits `error`,
 *                  `close`, `stdout.on('data')`,
 *                  and `stderr.on('data')`.
 */
export function spawnV62Job(scriptRel, env = {}, options = {}) {
  const {
    extraArgs = [],
    timeoutMs,
    cwd = root,
    logger = null,
    execPath,
    spawnApi,
  } = options;
  // Resolve the runtime executable. The default
  // is `process.execPath`. The override must
  // pass `isValidExecPath`. An invalid override
  // is rejected with a sanitized spawnError
  // (no `spawn` call is ever issued).
  let runtimeExecutable = process.execPath;
  let runtimeExecutableLabel = 'process.execPath';
  if (execPath !== undefined && execPath !== null) {
    if (isValidExecPath(execPath)) {
      runtimeExecutable = execPath;
      runtimeExecutableLabel = 'override';
    } else {
      const e = {
        code: 'EINVAL',
        message: 'spawnV62Job: injected execPath is empty or invalid',
      };
      return Promise.resolve({
        code: 1, out: '', err: e.message, truncated: false, timedOut: false,
        spawnError: sanitizeSpawnError(e, scriptRel, 'override'),
      });
    }
  }
  // Resolve the actual spawn function. The
  // default is the Node child_process.spawn
  // import. Tests inject a fake.
  const spawnFn = typeof spawnApi === 'function' ? spawnApi : spawn;
  return new Promise((resolveJob) => {
    let out = '';
    let err = '';
    let truncated = false;
    let timedOut = false;
    let spawnError = null;
    const appendBounded = (target, value) => {
      if (value.length + target.length > MAX_CAPTURE_BYTES) {
        const remaining = Math.max(0, MAX_CAPTURE_BYTES - target.length);
        target += value.slice(0, remaining);
        target += '\n… [truncated]';
        return true;
      }
      target += value;
      return false;
    };
    let proc;
    try {
      proc = spawnFn(runtimeExecutable, [resolve(root, scriptRel), ...extraArgs], {
        cwd, stdio: ['ignore', 'pipe', 'pipe'],
        env: { ...process.env, ...env },
      });
    } catch (e) {
      spawnError = sanitizeSpawnError(e, scriptRel, runtimeExecutableLabel);
      if (logger) logger.error({ msg: 'spawn.error', script: scriptRel, error: spawnError });
      resolveJob({ code: 1, out: '', err: e && e.message ? e.message : String(e), truncated: false, timedOut: false, spawnError });
      return;
    }
    let timer = null;
    if (Number.isFinite(timeoutMs) && timeoutMs > 0) {
      timer = setTimeout(() => {
        timedOut = true;
        try { proc.kill('SIGTERM'); } catch { /* noop */ }
      }, timeoutMs);
      timer.unref();
    }
    if (proc.stdout && typeof proc.stdout.on === 'function') {
      proc.stdout.on('data', (d) => {
        const chunk = d.toString('utf8');
        if (appendBounded(out, chunk)) truncated = true;
      });
    }
    if (proc.stderr && typeof proc.stderr.on === 'function') {
      proc.stderr.on('data', (d) => {
        const chunk = d.toString('utf8');
        if (appendBounded(err, chunk)) truncated = true;
      });
    }
    proc.on('error', (e) => {
      if (timer) clearTimeout(timer);
      spawnError = sanitizeSpawnError(e, scriptRel, runtimeExecutableLabel);
      if (logger) logger.error({ msg: 'spawn.error', script: scriptRel, error: spawnError });
      resolveJob({ code: 1, out, err: err + '\n' + (e && e.message || String(e)), truncated, timedOut, spawnError });
    });
    proc.on('close', (code, signal) => {
      if (timer) clearTimeout(timer);
      const finalCode = timedOut ? (Number.isInteger(code) ? code : 1) : (code == null ? 1 : code);
      if (logger) logger.info({ msg: 'spawn.close', script: scriptRel, code: finalCode, signal: signal || null, outBytes: out.length, errBytes: err.length, truncated, timedOut, runtimeExecutable: runtimeExecutableLabel });
      resolveJob({ code: finalCode, out, err, truncated, timedOut, spawnError });
    });
  });
}

/**
 * Map a V6.2 job exit code to the canonical cron
 * status string used by `runCronJob` and the
 * embedded scheduler. The mapping is the same one
 * each cron entrypoint applied locally before this
 * helper was extracted.
 *
 *   0 → ok
 *   1 → invalid-args (or invalid-executable for
 *                       the embedded scheduler)
 *   2 → lock-held
 *   3 → provider-failure
 *   4 → storage-failure
 *   5 → publication-failure
 *   6 → partial
 *   anything else → error
 */
export function mapV62CodeToStatus(code) {
  if (code === 0) return { status: 'ok' };
  if (code === 1) return { status: 'invalid-args' };
  if (code === 2) return { status: 'lock-held' };
  if (code === 3) return { status: 'provider-failure' };
  if (code === 4) return { status: 'storage-failure' };
  if (code === 5) return { status: 'publication-failure' };
  if (code === 6) return { status: 'partial' };
  return { status: 'error', code };
}

/**
 * Construct a sanitized spawn-failure summary
 * for callers that need to surface the failure
 * outside the spawner's logger. The function
 * returns `{ code, message, runtimeExecutable,
 * jobLabel, phase }` with no absolute path, no
 * secret, and no provider body.
 */
export function describeSpawnFailure(spawnResult, scriptRel) {
  if (!spawnResult || !spawnResult.spawnError) return null;
  return {
    code: spawnResult.spawnError.code,
    message: spawnResult.spawnError.message,
    runtimeExecutable: spawnResult.spawnError.runtimeExecutable,
    jobLabel: scriptRel || spawnResult.spawnError.jobLabel || null,
    phase: spawnResult.spawnError.phase,
  };
}
