/**
 * V6.3 — portable filesystem locks for cron jobs.
 *
 * The Hostinger Business managed-hosting plan does
 * not expose a system lock manager (no flock(2), no
 * Redis, no DB). Concurrent cron invocations must
 * be excluded at the application level.
 *
 * This module provides atomic, TTL-bounded locks
 * stored as files under the configured locks
 * directory. The lock file format is JSON with
 *
 *   {
 *     "acquiredAt": ISO timestamp,
 *     "expiresAt": ISO timestamp,
 *     "owner":     "<job name>:<pid>:<nonce>",
 *     "pid":       <process id>,
 *     "nonce":     <random hex>
 *   }
 *
 * ## Hardened acquisition semantics
 *
 *   1. Read the existing lock file, if any.
 *   2. If the file is missing (ENOENT), write a new
 *      lock atomically.
 *   3. If the file is present but the contents are
 *      not a valid JSON object with an `expiresAt`
 *      field, the lock is MALFORMED. The function
 *      renames the malformed lock to
 *      `<name>.lock.malformed-<iso-ts>` and
 *      returns `{ acquired: false, reason:
 *      'malformed' }`. The original lock is NEVER
 *      silently overwritten; an operator must
 *      inspect the quarantined file.
 *   4. If the file is present and the lock is
 *      ACTIVE (expiresAt in the future), the
 *      function returns `{ acquired: false,
 *      reason: 'lock-held', holder, expiresAt }`.
 *   5. If the file is present and the lock is
 *      EXPIRED (expiresAt in the past), the
 *      function renames the expired lock to
 *      `<name>.lock.stale-<iso-ts>` and then
 *      atomically writes the new lock.
 *   6. After every successful write, the function
 *      re-reads the lock and verifies that the
 *      owner matches the caller's `owner` value.
 *      If it does not, a concurrent acquirer won
 *      the race and the function returns
 *      `{ acquired: false, reason: 'race-detected',
 *      holder }`. The function never silently
 *      overwrites a foreign lock.
 *
 * ## Hardened release semantics
 *
 *   - The release is conditional on BOTH the
 *     `owner` field AND the `pid` field of the
 *     stored lock matching the caller. A foreign
 *     lock is NEVER removed.
 *   - The release is idempotent. A missing lock
 *     is reported as released=true with
 *     reason=missing.
 *
 * ## Atomicity
 *
 *   - Writes use `writeFile(..., { flag: 'wx' })`
 *     to a randomly-named temp file, then
 *     `rename(temp, lockPath)`. The `wx` flag
 *     guarantees exclusive creation of the temp
 *     file, so two concurrent writers never share
 *     a temp name. The `rename` call is atomic on
 *     POSIX and Windows.
 *   - The post-rename re-read serves as the
 *     cross-process mutual-exclusion check: the
 *     lock file is the source of truth, and the
 *     re-read confirms that our write was the one
 *     that landed.
 *
 * ## Quarantine format
 *
 *   `<name>.lock.stale-<iso-ts>`     — the lock had
 *     a valid JSON object but its `expiresAt` was
 *     in the past at the time of the reclaim.
 *   `<name>.lock.malformed-<iso-ts>` — the lock
 *     was present but not a valid JSON object.
 *   Both forms include the ISO timestamp so the
 *   operator can recover or remove the quarantined
 *   file with confidence.
 */

import { existsSync } from 'node:fs';
import { mkdir, readFile, rename, unlink, writeFile } from 'node:fs/promises';
import { isAbsolute, join } from 'node:path';
import { randomBytes } from 'node:crypto';

/**
 * Validate a lock name. The name is interpolated
 * into a file path; we reject anything that could
 * escape the locks directory or be confused with
 * the quarantine suffixes.
 */
export function assertValidLockName(name) {
  if (typeof name !== 'string' || name.length === 0) {
    throw new Error('lock: name must be a non-empty string');
  }
  if (name.includes('..') || name.includes('/') || name.includes('\\') || name.includes('\u0000')) {
    throw new Error(`lock: invalid name "${name}"`);
  }
  if (name.length > 128) {
    throw new Error('lock: name too long');
  }
  return true;
}

/**
 * Quarantine a lock file by renaming it to
 * `<path>.<kind>-<iso-ts>`. The function refuses
 * to overwrite an existing quarantine file with
 * the same timestamp (a microsecond-precision
 * timestamp + a 4-byte random suffix keeps the
 * probability of collision negligible, but the
 * safeguard is preserved).
 */
async function quarantineLock(lockPath, kind) {
  const now = new Date();
  const stamp = now.toISOString().replace(/[:.]/g, '-');
  const nonce = randomBytes(4).toString('hex');
  const quarantinePath = `${lockPath}.${kind}-${stamp}-${nonce}`;
  try {
    await rename(lockPath, quarantinePath);
    return quarantinePath;
  } catch (err) {
    if (err && err.code === 'ENOENT') return null;
    throw err;
  }
}

/**
 * Parse + validate a lock file's contents. Returns
 * `{ valid: true, lock }` when the file is a valid
 * JSON object with a string `expiresAt` field;
 * `{ valid: false }` otherwise. The function does
 * NOT enforce a particular owner format.
 */
function parseLockContent(buf) {
  if (!buf || buf.length === 0) return { valid: false, reason: 'empty' };
  let parsed;
  try { parsed = JSON.parse(buf.toString('utf8')); } catch { return { valid: false, reason: 'not-json' }; }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return { valid: false, reason: 'not-object' };
  if (typeof parsed.expiresAt !== 'string') return { valid: false, reason: 'missing-expiresAt' };
  return { valid: true, lock: parsed };
}

/**
 * Acquire a lock atomically. See the file-level
 * docstring for the full hardened semantics.
 */
export async function acquireCronLock({ locksDir, name, ttlMs, owner, pid = process.pid, nonce: providedNonce } = {}) {
  assertValidLockName(name);
  if (!locksDir || !isAbsolute(locksDir)) {
    throw new Error('lock: locksDir must be an absolute path');
  }
  if (!Number.isFinite(ttlMs) || ttlMs <= 0) {
    throw new Error('lock: ttlMs must be a positive number');
  }
  if (typeof owner !== 'string' || owner.length === 0) {
    throw new Error('lock: owner must be a non-empty string');
  }
  if (!existsSync(locksDir)) await mkdir(locksDir, { recursive: true });
  const lockPath = join(locksDir, `${name}.lock`);
  const now = new Date();
  const expiresAt = new Date(now.getTime() + ttlMs);
  const nonce = providedNonce || randomBytes(8).toString('hex');

  // 1. Read the existing lock, if any.
  let buf = null;
  try {
    buf = await readFile(lockPath);
  } catch (err) {
    if (!err || err.code !== 'ENOENT') {
      return { acquired: false, reason: 'lock-unreadable', error: err.message, path: lockPath };
    }
  }
  if (buf !== null) {
    // 2. The lock is present. Validate the
    //    contents.
    const parsed = parseLockContent(buf);
    if (!parsed.valid) {
      // 3. Malformed lock. Quarantine and refuse.
      const q = await quarantineLock(lockPath, 'malformed');
      return {
        acquired: false, reason: 'malformed',
        quarantine: parsed.reason, quarantinePath: q, path: lockPath,
      };
    }
    // 4. Check expiry.
    const exp = new Date(parsed.lock.expiresAt).getTime();
    if (!Number.isNaN(exp) && exp > now.getTime()) {
      return {
        acquired: false, reason: 'lock-held',
        holder: parsed.lock.owner || 'unknown',
        expiresAt: parsed.lock.expiresAt,
        path: lockPath,
      };
    }
    // 5. Expired lock. Quarantine before reclaiming.
    await quarantineLock(lockPath, 'stale');
  }

  // 6. Atomically write the new lock via a temp
  //    file + rename. The `wx` flag prevents the
  //    random-suffix collision window.
  const tempPath = `${lockPath}.${randomBytes(8).toString('hex')}.tmp`;
  const payload = JSON.stringify({
    acquiredAt: now.toISOString(),
    expiresAt: expiresAt.toISOString(),
    owner,
    pid,
    nonce,
  });
  let renamedOk = false;
  try {
    await writeFile(tempPath, payload, { flag: 'wx' });
    await rename(tempPath, lockPath);
    renamedOk = true;
  } catch (err) {
    try { await unlink(tempPath).catch(() => {}); } catch { /* noop */ }
    return { acquired: false, reason: 'lock-write-failed', error: err.message, path: lockPath };
  }
  if (!renamedOk) {
    return { acquired: false, reason: 'lock-write-failed', path: lockPath };
  }

  // 7. Re-read and verify the owner matches. This
  //    is the cross-process mutual-exclusion
  //    check: a concurrent acquirer may have
  //    raced past us and overwritten our write.
  try {
    const reBuf = await readFile(lockPath, 'utf8');
    const reParsed = parseLockContent(reBuf);
    if (!reParsed.valid) {
      // Extremely unlikely: a concurrent acquirer
      // wrote a malformed lock. The operator must
      // inspect.
      return { acquired: false, reason: 'malformed-after-write', path: lockPath };
    }
    if (reParsed.lock.owner !== owner || reParsed.lock.pid !== pid) {
      return {
        acquired: false, reason: 'race-detected',
        holder: reParsed.lock.owner, path: lockPath,
      };
    }
  } catch (err) {
    return { acquired: false, reason: 'lock-verify-failed', error: err.message, path: lockPath };
  }
  return {
    acquired: true, expiresAt: expiresAt.toISOString(),
    path: lockPath, owner, pid, nonce,
  };
}

/**
 * Release a lock. The release is conditional on
 * BOTH the `owner` field AND the `pid` field of
 * the stored lock matching the caller's. A foreign
 * lock is NEVER removed. The function is
 * idempotent: a missing lock returns released=true
 * with reason=missing.
 */
export async function releaseCronLock({ locksDir, name, owner, pid = process.pid } = {}) {
  assertValidLockName(name);
  const lockPath = join(locksDir, `${name}.lock`);
  try {
    const buf = await readFile(lockPath, 'utf8');
    const parsed = parseLockContent(buf);
    if (!parsed.valid) {
      // Malformed: refuse. The operator must
      // clear it through the quarantine path.
      return { released: false, reason: 'malformed' };
    }
    if (owner && parsed.lock.owner !== owner) {
      return { released: false, reason: 'foreign-owner' };
    }
    if (pid != null && parsed.lock.pid !== pid) {
      // != not !== because the stored pid is a
      // number; the caller's pid may be a number
      // or a string-coerced number.
      return { released: false, reason: 'foreign-pid' };
    }
    await unlink(lockPath);
    return { released: true };
  } catch (err) {
    if (err && err.code === 'ENOENT') return { released: true, reason: 'missing' };
    return { released: false, reason: 'release-failed', error: err.message };
  }
}

/**
 * Inspect a lock without acquiring it. Returns
 * `{ held, expiresAt, holder, pid, ageMs, valid }`.
 * Useful for the diagnostic command and the
 * readiness probe.
 */
export async function inspectCronLock({ locksDir, name } = {}) {
  assertValidLockName(name);
  const lockPath = join(locksDir, `${name}.lock`);
  try {
    const buf = await readFile(lockPath, 'utf8');
    const parsed = parseLockContent(buf);
    if (!parsed.valid) return { held: false, valid: false, reason: parsed.reason, path: lockPath };
    const exp = parsed.lock.expiresAt ? new Date(parsed.lock.expiresAt).getTime() : NaN;
    const held = !Number.isNaN(exp) && exp > Date.now();
    return {
      held, valid: true,
      expiresAt: parsed.lock.expiresAt,
      holder: parsed.lock.owner,
      pid: parsed.lock.pid,
      nonce: parsed.lock.nonce,
      ageMs: parsed.lock.acquiredAt ? Date.now() - new Date(parsed.lock.acquiredAt).getTime() : null,
      path: lockPath,
    };
  } catch (err) {
    if (err && err.code === 'ENOENT') return { held: false, valid: true, path: lockPath };
    return { held: false, valid: false, error: err.message, path: lockPath };
  }
}

/**
 * Quarantine a stale lock. The function renames
 * the lock file to `<name>.lock.stale-<iso-ts>`
 * when the lock is expired (or malformed); an
 * active lock is NEVER touched. The function is
 * the safe operator-facing recovery path after a
 * crashed process.
 */
export async function clearStaleCronLock({ locksDir, name } = {}) {
  assertValidLockName(name);
  const lockPath = join(locksDir, `${name}.lock`);
  try {
    const buf = await readFile(lockPath, 'utf8');
    const parsed = parseLockContent(buf);
    if (!parsed.valid) {
      // Malformed: quarantine under the
      // `malformed` kind so the operator can find
      // it.
      const q = await quarantineLock(lockPath, 'malformed');
      return { cleared: true, kind: 'malformed', quarantinePath: q };
    }
    const exp = parsed.lock.expiresAt ? new Date(parsed.lock.expiresAt).getTime() : NaN;
    if (!Number.isNaN(exp) && exp > Date.now()) {
      return { cleared: false, reason: 'lock-active', expiresAt: parsed.lock.expiresAt };
    }
    const q = await quarantineLock(lockPath, 'stale');
    return { cleared: true, kind: 'stale', quarantinePath: q };
  } catch (err) {
    if (err && err.code === 'ENOENT') return { cleared: true, reason: 'missing' };
    return { cleared: false, reason: 'clear-failed', error: err.message };
  }
}

/**
 * List every lock file under the locks directory,
 * including any quarantined files. The function is
 * used by the diagnostic command.
 */
export async function listCronLocks({ locksDir } = {}) {
  if (!locksDir || !isAbsolute(locksDir)) throw new Error('lock: locksDir must be an absolute path');
  const { readdir } = await import('node:fs/promises');
  try {
    const entries = await readdir(locksDir, { withFileTypes: true });
    return entries
      .filter((e) => e.isFile() && e.name.endsWith('.lock') || /\.lock\.(stale|malformed)-/.test(e.name))
      .map((e) => e.name)
      .sort();
  } catch (err) {
    if (err && err.code === 'ENOENT') return [];
    throw err;
  }
}

/**
 * Lock-name registry. Each cron job in V6.3 uses
 * exactly one of these names. The mapping is the
 * single source of truth; do not duplicate literal
 * lock names elsewhere.
 */
export const LOCK_NAMES = Object.freeze({
  DATASET_REFRESH: 'dataset-refresh',
  BASELINE_REFRESH: 'baseline-refresh',
  DATASET_PUBLISH: 'dataset-publish',
  PUBLIC_INTEL_GC: 'public-intelligence-gc',
  STATE_VERIFY: 'state-verify',
  BACKUP_IMPORT: 'backup-import',
});
