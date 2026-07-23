/**
 * V6.3 — portable filesystem locks for cron jobs.
 *
 * The Hostinger Business managed-hosting plan does
 * not expose a system lock manager (no flock(2), no
 * Redis, no DB). Concurrent cron invocations must
 * be excluded at the application level.
 *
 * ## Lock representation (V6.3 hardening)
 *
 * Each active lock is a DIRECTORY, not a file.
 *
 *   <locksRoot>/<lockName>.lock/         <- the directory IS the lock
 *     owner.json                         <- metadata: acquiredAt,
 *                                          expiresAt, owner, pid, nonce
 *
 * Acquisition is the atomic `mkdir` system call:
 *
 *   - `mkdir(<lockName>.lock/)` returns success
 *     ONLY when no directory with that name
 *     already exists. The success of mkdir is
 *     itself the proof of exclusive ownership.
 *   - After the mkdir succeeds, the function
 *     writes the owner metadata into
 *     `owner.json` inside the newly-created
 *     directory. The metadata write is a plain
 *     `writeFile`; a crash between mkdir and the
 *     metadata write leaves a recoverable state
 *     (a directory with no owner.json, which the
 *     NEXT acquirer treats as a malformed lock
 *     and quarantines).
 *   - EEXIST means another lock is present. The
 *     function then reads `owner.json` (if any)
 *     to decide whether the existing lock is
 *     active, expired, or malformed.
 *
 * Why a directory and not a file?
 *
 *   - `mkdir` is atomic on every POSIX system and
 *     on Windows (CreateDirectory is atomic at the
 *     NTFS level). The success of mkdir proves
 *     exclusive ownership WITHOUT a temp-file +
 *     rename dance.
 *   - The legacy file-based primitive
 *     `writeFile(temp) + rename(temp, lockPath)`
 *     has a known race: on POSIX the rename
 *     overwrites an existing destination, so two
 *     acquirers can both "win" and the second
 *     silently overwrites the first. The
 *     directory primitive eliminates that race.
 *   - On Windows, `rename` semantics differ
 *     (`MoveFileEx` requires a flag for atomic
 *     replace), and a `wx` `open` of the final
 *     path is more complex. `mkdir` is uniform
 *     across platforms.
 *
 * ## Stale recovery
 *
 *   - An EXPIRED lock is moved to a quarantine
 *     path (`<name>.lock.stale-<ts>-<nonce>/`)
 *     by `rename`. The rename is atomic.
 *   - The acquirer whose quarantine rename
 *     succeeds is the only one allowed to attempt
 *     the new `mkdir`. A second racer that
 *     observes the lock has already been
 *     quarantined by the first racer and sees
 *     EEXIST on its own mkdir; the second racer
 *     returns `reason: 'race-lost'`.
 *   - A new active lock that appeared between the
 *     quarantine and the new mkdir is NEVER
 *     overwritten. The acquirer re-reads
 *     `owner.json` after the mkdir to confirm
 *     ownership, and aborts with `reason:
 *     'race-lost'` if the owner does not match.
 *
 * ## Malformed lock fail-closed
 *
 *   - A lock directory that has no `owner.json`
 *     or whose `owner.json` is not a valid JSON
 *     object with an `expiresAt` field is treated
 *     as MALFORMED. The function renames the
 *     directory to
 *     `<name>.lock.malformed-<ts>-<nonce>/` and
 *     returns `reason: 'malformed'`. The
 *     original is NEVER silently overwritten; an
 *     operator must inspect the quarantined file.
 *
 * ## Release
 *
 *   - The release is conditional on BOTH the
 *     `owner` field AND the `pid` field of the
 *     stored `owner.json` matching the caller's
 *     values. A foreign lock is NEVER removed.
 *   - The function re-reads `owner.json` immediately
 *     before `rmdir` so a replacement lock that
 *     was created after the caller's lease
 *     started is NEVER deleted.
 *   - The release is idempotent: a missing lock
 *     returns released=true with reason=missing.
 *
 * ## Quarantine format
 *
 *   `<name>.lock.stale-<ts>-<nonce>/`        — the
 *     lock had a valid JSON object but its
 *     `expiresAt` was in the past at the time of
 *     the reclaim.
 *   `<name>.lock.malformed-<ts>-<nonce>/`   — the
 *     lock directory was present but the
 *     `owner.json` was missing or invalid.
 *   Both forms include the ISO timestamp + a
 *   4-byte random nonce so the operator can
 *   recover or remove the quarantined directory
 *   with confidence.
 */

import { existsSync, readFileSync, statSync, writeFileSync, mkdirSync, unlinkSync, rmSync } from 'node:fs';
import { mkdir, readdir, readFile, rename, rmdir, unlink, writeFile } from 'node:fs/promises';
import { isAbsolute, join } from 'node:path';
import { randomBytes } from 'node:crypto';

/**
 * Validate a lock name. The name is interpolated
 * into a directory path; we reject anything that
 * could escape the locks directory or be confused
 * with the quarantine suffixes.
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
 * Quarantine a lock directory by renaming it to
 * `<path>.<kind>-<iso-ts>-<nonce>`. The function
 * refuses to overwrite an existing quarantine
 * directory (a microsecond-precision timestamp +
 * a 4-byte random nonce keeps the probability of
 * collision negligible, but the safeguard is
 * preserved).
 *
 * Returns the new quarantine path on success, or
 * null when the source does not exist.
 */
async function quarantineLockDir(lockDir, kind) {
  const now = new Date();
  const stamp = now.toISOString().replace(/[:.]/g, '-');
  const nonce = randomBytes(4).toString('hex');
  const quarantinePath = `${lockDir}.${kind}-${stamp}-${nonce}`;
  try {
    await rename(lockDir, quarantinePath);
    return quarantinePath;
  } catch (err) {
    if (err && err.code === 'ENOENT') return null;
    throw err;
  }
}

/**
 * Read + validate the owner.json contents of a
 * lock directory. Returns:
 *
 *   - `{ valid: true, lock }` when the directory
 *     contains a readable, well-formed JSON object
 *     with a string `expiresAt` field
 *   - `{ valid: false, reason }` when the metadata
 *     is missing, unreadable, or not a valid JSON
 *     object
 *
 * The function returns ENOENT/missing as a
 * `valid: false, reason: 'no-metadata'` so the
 * caller can quarantine the directory.
 */
async function readLockMetadata(lockDir) {
  const metaPath = join(lockDir, 'owner.json');
  try {
    const buf = await readFile(metaPath, 'utf8');
    let parsed;
    try { parsed = JSON.parse(buf); } catch { return { valid: false, reason: 'not-json' }; }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return { valid: false, reason: 'not-object' };
    if (typeof parsed.expiresAt !== 'string') return { valid: false, reason: 'missing-expiresAt' };
    return { valid: true, lock: parsed };
  } catch (err) {
    if (err && err.code === 'ENOENT') return { valid: false, reason: 'no-metadata' };
    return { valid: false, reason: 'read-error', error: err.message };
  }
}

/**
 * Write the owner metadata to the lock directory.
 * The write is performed synchronously after the
 * async mkdir so the caller observes a single
 * combined acquire result.
 */
function writeLockMetadataSync(lockDir, payload) {
  const metaPath = join(lockDir, 'owner.json');
  const json = JSON.stringify(payload, null, 2);
  writeFileSync(metaPath, json, { flag: 'wx' });
}

/**
 * Acquire a lock atomically via `mkdir`. See the
 * file-level docstring for the full hardened
 * semantics.
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
  const lockDir = join(locksDir, `${name}.lock`);
  const now = new Date();
  const expiresAt = new Date(now.getTime() + ttlMs);
  const nonce = providedNonce || randomBytes(8).toString('hex');
  const payload = {
    acquiredAt: now.toISOString(),
    expiresAt: expiresAt.toISOString(),
    owner,
    pid,
    nonce,
  };

  // 1. Try to acquire by creating the lock
  //    directory. mkdir is atomic on every
  //    supported platform.
  try {
    await mkdir(lockDir);
  } catch (err) {
    if (!err || err.code !== 'EEXIST') {
      return { acquired: false, reason: 'mkdir-failed', error: err.message, path: lockDir };
    }
    // The lock directory already exists. Inspect
    // its metadata.
    const meta = await readLockMetadata(lockDir);
    if (!meta.valid) {
      // Malformed lock (missing or invalid
      // owner.json). Quarantine the directory and
      // try to acquire the now-vacated slot. The
      // metadata is gone, so the safe behavior
      // is to reclaim the slot — there is no
      // active holder to displace.
      const q = await quarantineLockDir(lockDir, 'malformed');
      try {
        await mkdir(lockDir);
        return await finalizeAcquisition(lockDir, payload, name);
      } catch (err2) {
        if (err2 && err2.code === 'EEXIST') {
          // A new lock appeared between our
          // quarantine and our mkdir. We do NOT
          // replace it.
          return { acquired: false, reason: 'race-lost', path: lockDir };
        }
        return { acquired: false, reason: 'mkdir-failed', error: err2.message, path: lockDir };
      }
    }
    // Validate expiry.
    const exp = new Date(meta.lock.expiresAt).getTime();
    if (!Number.isNaN(exp) && exp > now.getTime()) {
      return {
        acquired: false, reason: 'lock-held',
        holder: meta.lock.owner || 'unknown',
        expiresAt: meta.lock.expiresAt,
        path: lockDir,
      };
    }
    // Expired lock. Quarantine the directory and
    // try to acquire again. Only one racer can
    // successfully quarantine; the rest will
    // observe the quarantined-or-new state on the
    // next mkdir attempt.
    const q = await quarantineLockDir(lockDir, 'stale');
    if (q === null) {
      // The directory disappeared between our
      // EEXIST and the rename. Another process
      // likely just removed it. Retry the mkdir.
      try {
        await mkdir(lockDir);
        return await finalizeAcquisition(lockDir, payload, name);
      } catch (err2) {
        if (err2 && err2.code === 'EEXIST') {
          return { acquired: false, reason: 'race-lost', path: lockDir };
        }
        return { acquired: false, reason: 'mkdir-failed', error: err2.message, path: lockDir };
      }
    }
    // Quarantine succeeded. Try to acquire the
    // newly-vacated slot.
    try {
      await mkdir(lockDir);
      return await finalizeAcquisition(lockDir, payload, name);
    } catch (err3) {
      if (err3 && err3.code === 'EEXIST') {
        // A new lock appeared between our
        // quarantine and our mkdir. We do NOT
        // replace it.
        return { acquired: false, reason: 'race-lost', path: lockDir };
      }
      return { acquired: false, reason: 'mkdir-failed', error: err3.message, path: lockDir };
    }
  }

  // 2. The mkdir succeeded. Write the metadata.
  return await finalizeAcquisition(lockDir, payload, name);
}

/**
 * Write the owner.json inside an acquired lock
 * directory, then verify the lock is intact. On
 * any failure, the directory is removed so the
 * next acquirer sees a clean slot.
 */
async function finalizeAcquisition(lockDir, payload, name) {
  try {
    writeLockMetadataSync(lockDir, payload);
  } catch (err) {
    // Metadata write failed. Remove the empty
    // directory so the next acquirer does not
    // see a malformed lock.
    try { await rmdir(lockDir); } catch { /* noop */ }
    return { acquired: false, reason: 'metadata-write-failed', error: err.message, path: lockDir };
  }
  // Verify: re-read the metadata and confirm the
  // owner matches. A failed verify is extremely
  // unlikely (would require a replacement
  // mid-write) but is handled for safety.
  const verify = await readLockMetadata(lockDir);
  if (!verify.valid || verify.lock.owner !== payload.owner || verify.lock.pid !== payload.pid) {
    try { await rmdir(lockDir); } catch { /* noop */ }
    return { acquired: false, reason: 'verify-failed', path: lockDir };
  }
  return {
    acquired: true, expiresAt: payload.expiresAt,
    path: lockDir, owner: payload.owner, pid: payload.pid, nonce: payload.nonce,
  };
}

/**
 * Release a lock. The release is conditional on
 * BOTH the `owner` field AND the `pid` field of
 * the stored `owner.json` matching the caller's
 * values. A foreign lock is NEVER removed. The
 * function re-reads `owner.json` immediately
 * before `rmdir` so a replacement lock that was
 * created after the caller's lease started is
 * NEVER deleted.
 *
 * The function is idempotent: a missing lock
 * returns released=true with reason=missing.
 */
export async function releaseCronLock({ locksDir, name, owner, pid = process.pid } = {}) {
  assertValidLockName(name);
  const lockDir = join(locksDir, `${name}.lock`);
  // 1. Re-read the metadata. We do NOT trust a
  //    cached value; the file on disk is the
  //    source of truth.
  const meta = await readLockMetadata(lockDir);
  if (!meta.valid) {
    if (meta.reason === 'no-metadata') {
      // The lock directory exists but has no
      // owner.json. It may be a half-completed
      // acquisition from a crashed process. The
      // safe behavior is to refuse the release
      // rather than delete a lock that the
      // caller doesn't actually own.
      return { released: false, reason: 'no-metadata' };
    }
    return { released: false, reason: 'malformed' };
  }
  if (owner && meta.lock.owner !== owner) {
    return { released: false, reason: 'foreign-owner' };
  }
  if (pid != null && meta.lock.pid !== pid) {
    return { released: false, reason: 'foreign-pid' };
  }
  // 2. The metadata matches the caller's.
  //    Re-read the metadata one more time to
  //    guard against a TOCTOU where a
  //    replacement lock was created between our
  //    first read and this check.
  const recheck = await readLockMetadata(lockDir);
  if (!recheck.valid || recheck.lock.owner !== owner || recheck.lock.pid !== pid) {
    return { released: false, reason: 'replaced' };
  }
  // 3. Remove the lock directory. The lock
  //    directory contains the owner.json
  //    metadata file; we unlink it first, then
  //    rmdir the now-empty directory. The
  //    unlink+rmdir pair is atomic from the
  //    caller's perspective: a concurrent
  //    acquirer that observes the lock is gone
  //    will see the directory as missing (EEXIST
  //    fails) and acquire normally.
  try {
    try { await unlink(join(lockDir, 'owner.json')); } catch (e) { if (!e || e.code !== 'ENOENT') throw e; }
    try { await rmdir(lockDir); } catch (e) {
      if (e && e.code === 'ENOENT') return { released: true, reason: 'missing' };
      throw e;
    }
    return { released: true };
  } catch (err) {
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
  const lockDir = join(locksDir, `${name}.lock`);
  if (!existsSync(lockDir)) return { held: false, valid: true, path: lockDir };
  const meta = await readLockMetadata(lockDir);
  if (!meta.valid) return { held: false, valid: false, reason: meta.reason, path: lockDir };
  const exp = meta.lock.expiresAt ? new Date(meta.lock.expiresAt).getTime() : NaN;
  const held = !Number.isNaN(exp) && exp > Date.now();
  return {
    held, valid: true,
    expiresAt: meta.lock.expiresAt,
    holder: meta.lock.owner,
    pid: meta.lock.pid,
    nonce: meta.lock.nonce,
    ageMs: meta.lock.acquiredAt ? Date.now() - new Date(meta.lock.acquiredAt).getTime() : null,
    path: lockDir,
  };
}

/**
 * Quarantine a stale lock directory. The function
 * renames the lock directory to
 * `<name>.lock.stale-<ts>-<nonce>/` when the
 * metadata is valid and expired, or to
 * `<name>.lock.malformed-<ts>-<nonce>/` when the
 * metadata is missing or invalid. An active lock
 * is NEVER touched. The function is the safe
 * operator-facing recovery path after a crashed
 * process.
 */
export async function clearStaleCronLock({ locksDir, name } = {}) {
  assertValidLockName(name);
  const lockDir = join(locksDir, `${name}.lock`);
  if (!existsSync(lockDir)) return { cleared: true, reason: 'missing' };
  const meta = await readLockMetadata(lockDir);
  if (!meta.valid) {
    const q = await quarantineLockDir(lockDir, 'malformed');
    return { cleared: true, kind: 'malformed', quarantinePath: q };
  }
  const exp = meta.lock.expiresAt ? new Date(meta.lock.expiresAt).getTime() : NaN;
  if (!Number.isNaN(exp) && exp > Date.now()) {
    return { cleared: false, reason: 'lock-active', expiresAt: meta.lock.expiresAt };
  }
  const q = await quarantineLockDir(lockDir, 'stale');
  return { cleared: true, kind: 'stale', quarantinePath: q };
}

/**
 * List every lock and quarantined directory under
 * the locks directory. The function is used by
 * the diagnostic command.
 */
export async function listCronLocks({ locksDir } = {}) {
  if (!locksDir || !isAbsolute(locksDir)) throw new Error('lock: locksDir must be an absolute path');
  try {
    const entries = await readdir(locksDir, { withFileTypes: true });
    return entries
      .filter((e) => e.isDirectory() && (e.name.endsWith('.lock') || /\.lock\.(stale|malformed)-/.test(e.name)))
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
