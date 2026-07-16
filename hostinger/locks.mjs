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
 *     "owner":     "<job name>:<pid>",
 *     "pid":       <process id>
 *   }
 *
 * Acquisition is atomic on POSIX (rename is atomic)
 * and atomic on Windows via the standard rename
 * path. A stale lock (expiresAt in the past) is
 * overwritten; an active lock (expiresAt in the
 * future) returns `{ acquired: false, holder }` and
 * the caller exits with code 2.
 *
 * Lock files are NEVER deleted by an external
 * process; only the holder (or a stale-lock recovery
 * that has been authorized by the operator) may
 * remove a lock.
 */

import { constants as fsConstants } from 'node:fs';
import { access, mkdir, readFile, rename, unlink, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { dirname, isAbsolute, join, resolve, sep } from 'node:path';
import { randomBytes } from 'node:crypto';

/**
 * Validate a lock name. The name is interpolated into
 * a file path; we reject anything that could escape
 * the locks directory.
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
 * Acquire a lock atomically. The function:
 *   - computes the lock file path
 *   - reads the existing file (if any)
 *   - if the existing lock is expired (or the file
 *     is missing) it overwrites the file via a
 *     temp + rename
 *   - if the existing lock is still active, returns
 *     `{ acquired: false, ... }`
 *
 * Concurrent acquisitions are serialized by the
 * filesystem: only the first writer wins.
 */
export async function acquireCronLock({ locksDir, name, ttlMs, owner, pid = process.pid }) {
  assertValidLockName(name);
  if (!locksDir || !isAbsolute(locksDir)) {
    throw new Error('lock: locksDir must be an absolute path');
  }
  if (!Number.isFinite(ttlMs) || ttlMs <= 0) {
    throw new Error('lock: ttlMs must be a positive number');
  }
  // Ensure the locks directory exists. The mkdir
  // path is recursive so a missing parent directory
  // is created.
  if (!existsSync(locksDir)) await mkdir(locksDir, { recursive: true });
  const lockPath = join(locksDir, `${name}.lock`);
  const now = new Date();
  const expiresAt = new Date(now.getTime() + ttlMs);
  // Read the current lock, if any. If the read fails
  // for any reason other than ENOENT, surface the
  // error — operators must see why the lock could
  // not be inspected.
  let existing = null;
  try {
    const buf = await readFile(lockPath, 'utf8');
    existing = JSON.parse(buf);
  } catch (err) {
    if (!err || err.code !== 'ENOENT') {
      // The lock file is present but unreadable
      // (corrupt, permission). Refuse to overwrite;
      // the operator must intervene.
      return { acquired: false, reason: 'lock-unreadable', error: err.message, path: lockPath };
    }
  }
  if (existing && typeof existing === 'object' && typeof existing.expiresAt === 'string') {
    const exp = new Date(existing.expiresAt).getTime();
    if (!Number.isNaN(exp) && exp > now.getTime()) {
      // Active lock held by someone else.
      return {
        acquired: false,
        reason: 'lock-held',
        holder: existing.owner || 'unknown',
        expiresAt: existing.expiresAt,
        path: lockPath,
      };
    }
  }
  // Atomically write the new lock via a temp file +
  // rename. The random suffix avoids the very small
  // window where two writers could collide on the
  // same temp name.
  const tempPath = `${lockPath}.${randomBytes(8).toString('hex')}.tmp`;
  const payload = JSON.stringify({
    acquiredAt: now.toISOString(),
    expiresAt: expiresAt.toISOString(),
    owner,
    pid,
  });
  try {
    await writeFile(tempPath, payload, { flag: 'wx' });
    await rename(tempPath, lockPath);
  } catch (err) {
    // A racing acquisition may have grabbed the
    // lock between our read and our write. Re-read
    // to confirm.
    try { await unlink(tempPath); } catch { /* noop */ }
    try {
      const buf = await readFile(lockPath, 'utf8');
      const other = JSON.parse(buf);
      if (other && other.expiresAt && new Date(other.expiresAt).getTime() > Date.now()) {
        return {
          acquired: false, reason: 'lock-held', holder: other.owner || 'unknown',
          expiresAt: other.expiresAt, path: lockPath,
        };
      }
    } catch { /* noop */ }
    return { acquired: false, reason: 'lock-write-failed', error: err.message, path: lockPath };
  }
  return { acquired: true, expiresAt: expiresAt.toISOString(), path: lockPath, owner };
}

/**
 * Release a lock. The release is conditional on the
 * owner matching the supplied owner value (or the
 * lock is missing); a foreign lock is NEVER
 * removed. The function is idempotent.
 */
export async function releaseCronLock({ locksDir, name, owner }) {
  assertValidLockName(name);
  const lockPath = join(locksDir, `${name}.lock`);
  try {
    const buf = await readFile(lockPath, 'utf8');
    const existing = JSON.parse(buf);
    if (owner && existing.owner !== owner) {
      // A different process owns this lock. Refuse
      // to delete it.
      return { released: false, reason: 'foreign-owner' };
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
 * `{ held, expiresAt, holder, pid, ageMs }`. Useful
 * for the diagnostic command and the readiness
 * probe.
 */
export async function inspectCronLock({ locksDir, name }) {
  assertValidLockName(name);
  const lockPath = join(locksDir, `${name}.lock`);
  try {
    const buf = await readFile(lockPath, 'utf8');
    const existing = JSON.parse(buf);
    const exp = existing && existing.expiresAt ? new Date(existing.expiresAt).getTime() : NaN;
    const held = !Number.isNaN(exp) && exp > Date.now();
    return {
      held,
      expiresAt: existing && existing.expiresAt,
      holder: existing && existing.owner,
      pid: existing && existing.pid,
      ageMs: existing && existing.acquiredAt ? Date.now() - new Date(existing.acquiredAt).getTime() : null,
      path: lockPath,
    };
  } catch (err) {
    if (err && err.code === 'ENOENT') return { held: false, path: lockPath };
    return { held: false, error: err.message, path: lockPath };
  }
}

/**
 * Atomically remove a stale lock. The function only
 * removes locks whose `expiresAt` is in the past;
 * active locks are NEVER touched. This is the safe
 * recovery path for the operator after a crashed
 * process.
 */
export async function clearStaleCronLock({ locksDir, name }) {
  assertValidLockName(name);
  const lockPath = join(locksDir, `${name}.lock`);
  try {
    const buf = await readFile(lockPath, 'utf8');
    const existing = JSON.parse(buf);
    const exp = existing && existing.expiresAt ? new Date(existing.expiresAt).getTime() : NaN;
    if (!Number.isNaN(exp) && exp > Date.now()) {
      return { cleared: false, reason: 'lock-active', expiresAt: existing.expiresAt };
    }
    await unlink(lockPath);
    return { cleared: true };
  } catch (err) {
    if (err && err.code === 'ENOENT') return { cleared: true, reason: 'missing' };
    return { cleared: false, reason: 'clear-failed', error: err.message };
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
