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
 * Spawn a V6.2 job (`jobs/<scriptRel>.mjs`) as a
 * child process and capture stdout/stderr into
 * bounded buffers. The function returns a
 * `{ code, out, err, truncated, timedOut }` object.
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
 */
export function spawnV62Job(scriptRel, env = {}, { extraArgs = [], timeoutMs, cwd = root, logger = null } = {}) {
  return new Promise((resolveJob) => {
    let outBytes = 0;
    let errBytes = 0;
    let out = '';
    let err = '';
    let truncated = false;
    let timedOut = false;
    const appendBounded = (target, value, count) => {
      if (count + target.length > MAX_CAPTURE_BYTES) {
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
      proc = spawn('node', [resolve(root, scriptRel), ...extraArgs], {
        cwd, stdio: ['ignore', 'pipe', 'pipe'],
        env: { ...process.env, ...env },
      });
    } catch (e) {
      resolveJob({ code: 1, out: '', err: (e && e.message ? e.message : String(e)), truncated: false, timedOut: false });
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
    proc.stdout.on('data', (d) => {
      const chunk = d.toString('utf8');
      outBytes += chunk.length;
      if (appendBounded(out, chunk, chunk.length)) truncated = true;
    });
    proc.stderr.on('data', (d) => {
      const chunk = d.toString('utf8');
      errBytes += chunk.length;
      if (appendBounded(err, chunk, chunk.length)) truncated = true;
    });
    proc.on('error', (e) => {
      if (timer) clearTimeout(timer);
      if (logger) logger.error({ msg: 'spawn.error', script: scriptRel, error: e && e.message ? e.message : String(e) });
      resolveJob({ code: 1, out, err: err + '\n' + (e && e.message || String(e)), truncated, timedOut });
    });
    proc.on('close', (code, signal) => {
      if (timer) clearTimeout(timer);
      const finalCode = timedOut ? (Number.isInteger(code) ? code : 1) : (code == null ? 1 : code);
      if (logger) logger.info({ msg: 'spawn.close', script: scriptRel, code: finalCode, signal: signal || null, outBytes, errBytes, truncated, timedOut });
      resolveJob({ code: finalCode, out, err, truncated, timedOut });
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
 *   1 → invalid-args
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
