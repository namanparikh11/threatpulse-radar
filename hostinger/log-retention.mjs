/**
 * V6.9 — bounded application-log retention.
 *
 * Implements the 30-day ThreatPulse application-log
 * retention policy declared in
 * `public/legal/privacy.html` and
 * `docs/v6-9-privacy-cookie-and-security-hardening.md`.
 *
 * The cleanup function operates ONLY inside the
 * resolved log directory and ONLY on files whose
 * filename matches the documented ThreatPulse
 * application-log patterns. It will not delete:
 *
 *   - Hostinger-controlled infrastructure / access
 *     logs (those live in a different directory the
 *     application does not own);
 *   - state, snapshot, backup or user-upload files
 *     (different directory again, but the function
 *     also refuses to delete anything outside the
 *     documented log patterns as a defence-in-depth);
 *   - any file the application cannot prove is a
 *     log file (the filename must match the regex
 *     below);
 *   - any symlink (a symlink is rejected at lstat
 *     time; we never follow a symlink to a target
 *     file outside the log directory).
 *
 * The function fails safely:
 *
 *   - it returns `{ok:false,reason:'…'}` on every
 *     error path and never throws;
 *   - it logs sanitized error messages, never full
 *     filesystem paths or secrets;
 *   - it tolerates a missing log directory
 *     (`{ok:true, deleted:0, scanned:0}`);
 *   - it tolerates concurrent writers (an open file
 *     can be unlinked on POSIX-like systems; on
 *     Windows, unlink of an open file may fail with
 *     EBUSY, in which case the file is left for the
 *     next run).
 *
 * Usage:
 *
 *   import { runLogRetention } from './log-retention.mjs';
 *   const r = await runLogRetention({ logDir, retentionDays: 30 });
 *   // r = { ok, scanned, deleted, errors, files }
 *
 *   node hostinger/log-retention.mjs [--log-dir=<path>] [--retention-days=30] [--dry-run]
 */
import { existsSync, lstatSync, readdirSync, unlinkSync } from 'node:fs';
import { join, resolve, sep } from 'node:path';

// Filename patterns that identify a ThreatPulse
// application-generated log file. Anything that does
// not match one of these patterns is skipped. The
// `^threatpulse-\d{4}-\d{2}-\d{2}\.jsonl(\.\d+)?$`
// pattern matches the documented daily JSONL log
// emitted by `hostinger/logger.mjs#createLogger` and
// the rotation artefacts produced by
// `hostinger/logger.mjs#rotateFile` (`.1`–`.10`).
const LOG_FILENAME_RE = /^threatpulse-\d{4}-\d{2}-\d{2}\.jsonl(\.\d+)?$/;

// Threshold: 30 days, expressed in milliseconds.
const MS_PER_DAY = 24 * 60 * 60 * 1000;

function defaultRetentionDays() {
  return 30;
}

/**
 * Determine whether a filename is a ThreatPulse
 * application-generated log file. Returns true only
 * when the filename matches the documented patterns.
 */
export function isThreatPulseLogFilename(name) {
  if (typeof name !== 'string') return false;
  if (name.includes('/') || name.includes('\\') || name.includes('\u0000')) return false;
  if (name === '.' || name === '..') return false;
  return LOG_FILENAME_RE.test(name);
}

/**
 * Run the bounded 30-day log retention pass.
 *
 * @param {object} opts
 * @param {string} opts.logDir              Absolute path to the resolved THREATPULSE_LOG_DIR.
 * @param {number} [opts.retentionDays=30]  Files older than this many days are deleted.
 * @param {boolean} [opts.dryRun=false]      When true, no file is deleted; the function still scans and reports.
 * @param {function} [opts.logger]          Optional structured-logger; the function logs sanitized messages.
 * @returns {Promise<{
 *   ok: boolean,
 *   reason?: string,
 *   logDir: string,
 *   retentionDays: number,
 *   scanned: number,
 *   deleted: number,
 *   errors: number,
 *   files: Array<{ name: string, ageDays: number, deleted: boolean, reason?: string }>
 * }>}
 */
export async function runLogRetention({
  logDir,
  retentionDays = defaultRetentionDays(),
  dryRun = false,
  logger = null,
} = {}) {
  const result = {
    ok: false,
    reason: undefined,
    logDir: '',
    retentionDays,
    scanned: 0,
    deleted: 0,
    errors: 0,
    files: [],
  };

  // Argument validation. The function never throws
  // on bad input; it returns a structured error.
  if (typeof logDir !== 'string' || logDir.length === 0) {
    result.reason = 'invalid-log-dir';
    if (logger && typeof logger.error === 'function') {
      logger.error({ msg: 'log-retention.invalid', reason: result.reason });
    }
    return result;
  }
  if (!Number.isFinite(retentionDays) || retentionDays < 1) {
    result.reason = 'invalid-retention-days';
    if (logger && typeof logger.error === 'function') {
      logger.error({ msg: 'log-retention.invalid', reason: result.reason });
    }
    return result;
  }

  // Resolve the log directory to an absolute path and
  // confirm it exists. The function NEVER creates the
  // directory; missing-directory is a no-op.
  const resolved = resolve(logDir);
  result.logDir = resolved;
  if (!existsSync(resolved)) {
    result.ok = true;
    result.reason = 'log-dir-missing';
    if (logger && typeof logger.info === 'function') {
      logger.info({ msg: 'log-retention.skip', reason: 'log-dir-missing' });
    }
    return result;
  }

  // Compute the age threshold in milliseconds. A
  // file's age is `Date.now() - mtimeMs`; if the age
  // is strictly greater than `retentionMs`, the file
  // is older than the retention window and is
  // eligible for deletion.
  const retentionMs = retentionDays * MS_PER_DAY;

  let entries;
  try {
    entries = readdirSync(resolved);
  } catch (err) {
    result.reason = 'readdir-failed';
    if (logger && typeof logger.error === 'function') {
      logger.error({ msg: 'log-retention.readdir.error', reason: err && err.code ? err.code : 'unknown' });
    }
    return result;
  }

  for (const name of entries) {
    result.scanned += 1;
    if (!isThreatPulseLogFilename(name)) {
      // Skip silently. We do not log every non-match
      // because a non-empty log directory can contain
      // hundreds of historical files.
      continue;
    }
    const fullPath = join(resolved, name);
    let stats;
    try {
      // lstatSync does NOT follow symlinks. A symlink
      // is rejected at this point; we never resolve
      // it to a target file outside the log directory.
      stats = lstatSync(fullPath);
    } catch (err) {
      result.errors += 1;
      result.files.push({ name, ageDays: -1, deleted: false, reason: 'lstat-failed' });
      if (logger && typeof logger.warn === 'function') {
        logger.warn({ msg: 'log-retention.lstat.error', name, reason: err && err.code ? err.code : 'unknown' });
      }
      continue;
    }
    if (stats.isSymbolicLink()) {
      // Defensive: refuse to follow symlinks. This
      // protects against a malicious operator (or a
      // mistake) that places a symlink in the log
      // directory pointing at a state, snapshot,
      // backup or source file.
      result.errors += 1;
      result.files.push({ name, ageDays: -1, deleted: false, reason: 'symlink-rejected' });
      if (logger && typeof logger.warn === 'function') {
        logger.warn({ msg: 'log-retention.symlink.skipped', name });
      }
      continue;
    }
    if (!stats.isFile()) {
      // Directories, sockets, devices, etc. are out
      // of scope for log cleanup.
      result.errors += 1;
      result.files.push({ name, ageDays: -1, deleted: false, reason: 'not-a-regular-file' });
      if (logger && typeof logger.warn === 'function') {
        logger.warn({ msg: 'log-retention.nonfile.skipped', name });
      }
      continue;
    }
    const ageMs = Date.now() - stats.mtimeMs;
    const ageDays = ageMs / MS_PER_DAY;
    if (ageMs <= retentionMs) {
      // Within the retention window. Skip silently.
      result.files.push({ name, ageDays, deleted: false, reason: 'within-window' });
      continue;
    }
    if (dryRun) {
      result.deleted += 1;
      result.files.push({ name, ageDays, deleted: false, reason: 'dry-run' });
      continue;
    }
    // Defence-in-depth: the resolved path MUST
    // remain inside the resolved log directory.
    // join(...) on the already-resolved root is
    // safe, but the check is kept to make the
    // invariant explicit and to fail safely on
    // any future code path that bypasses the
    // filename pattern.
    if (fullPath !== resolve(fullPath)) {
      result.errors += 1;
      result.files.push({ name, ageDays, deleted: false, reason: 'path-escape-rejected' });
      if (logger && typeof logger.error === 'function') {
        logger.error({ msg: 'log-retention.path-escape.rejected', name });
      }
      continue;
    }
    if (!fullPath.startsWith(resolved + sep) && fullPath !== resolved) {
      result.errors += 1;
      result.files.push({ name, ageDays, deleted: false, reason: 'outside-log-dir' });
      if (logger && typeof logger.error === 'function') {
        logger.error({ msg: 'log-retention.outside-log-dir.rejected', name });
      }
      continue;
    }
    try {
      unlinkSync(fullPath);
      result.deleted += 1;
      result.files.push({ name, ageDays, deleted: true });
      if (logger && typeof logger.info === 'function') {
        logger.info({ msg: 'log-retention.deleted', name, ageDays: Math.round(ageDays) });
      }
    } catch (err) {
      // A concurrent writer or a Windows open file
      // can cause unlink to fail with EBUSY /
      // EPERM / ENOENT. We do not treat this as
      // a hard failure; the file will be retried
      // on the next scheduled run.
      result.errors += 1;
      const code = err && err.code ? err.code : 'unknown';
      result.files.push({ name, ageDays, deleted: false, reason: `unlink-${code}` });
      if (logger && typeof logger.warn === 'function') {
        logger.warn({ msg: 'log-retention.unlink.error', name, reason: code });
      }
    }
  }

  result.ok = true;
  return result;
}

export { LOG_FILENAME_RE };
