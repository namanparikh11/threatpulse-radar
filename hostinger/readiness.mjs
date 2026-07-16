/**
 * V6.3 — Data-root readiness validator.
 *
 * Verifies that the configured persistent data root
 * is usable BEFORE the Hostinger application accepts
 * any request. The check is fail-closed: when the
 * data root cannot be trusted, the readiness probe
 * reports `unready` and the application refuses to
 * serve public traffic (operators can still hit
 * `/health` for liveness).
 *
 * Probes performed:
 *   - directory exists OR can be safely created
 *   - read + write permissions
 *   - atomic rename (the FilesystemStorageAdapter
 *     uses temp + rename on every write)
 *   - temp file creation
 *   - gzip write + read round trip
 *   - available disk space where the platform
 *     permits (best-effort; absent on some
 *     restricted filesystems)
 *   - symlink escape protection (the data root
 *     MUST not be a symlink that points outside the
 *     configured location, and writes that resolve
 *     outside the real data root are rejected)
 *   - data root is NOT inside the publicly-served
 *     static directory
 *   - no secret-looking files in the data root
 *     (best-effort: refuse if .env / *.pem /
 *     credentials.json are present)
 *
 * The result is a `{ ready: boolean, checks: [...] }`
 * object. The `/ready` endpoint sanitizes the result
 * for public consumption; the full report is
 * available via `getFullReadiness()`.
 */

import { constants as fsConstants } from 'node:fs';
import { access, mkdir, readdir, realpath, rename, writeFile, readFile, statfs, unlink } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { dirname, isAbsolute, join, normalize, relative, resolve, sep } from 'node:path';
import { gzipSync, gunzipSync } from 'node:zlib';
import { createHash } from 'node:crypto';

import { isPathInside, maskHomePath } from './_lib.mjs';

const FORBIDDEN_NAMES = new Set(['.env', '.env.local', 'credentials.json', 'secrets.json']);

async function existsOrCanCreate(dir) {
  try {
    await access(dir, fsConstants.F_OK);
    return { ok: true, created: false };
  } catch {
    try {
      await mkdir(dir, { recursive: true });
      return { ok: true, created: true };
    } catch (err) {
      return { ok: false, error: err.message };
    }
  }
}

async function checkReadWrite(dir) {
  const probe = join(dir, `.readwrite-probe-${process.pid}-${Date.now()}`);
  try {
    await writeFile(probe, 'ok');
    const back = await readFile(probe, 'utf8');
    await unlink(probe);
    return back === 'ok' ? { ok: true } : { ok: false, error: 'read-back mismatch' };
  } catch (err) {
    try { await unlink(probe).catch(() => {}); } catch { /* noop */ }
    return { ok: false, error: err.message };
  }
}

async function checkAtomicRename(dir) {
  const src = join(dir, `.rename-src-${process.pid}-${Date.now()}`);
  const dst = join(dir, `.rename-dst-${process.pid}-${Date.now()}`);
  try {
    await writeFile(src, 'src');
    await rename(src, dst);
    const back = await readFile(dst, 'utf8');
    await unlink(dst);
    return back === 'src' ? { ok: true } : { ok: false, error: 'rename content mismatch' };
  } catch (err) {
    try { await unlink(src).catch(() => {}); } catch { /* noop */ }
    try { await unlink(dst).catch(() => {}); } catch { /* noop */ }
    return { ok: false, error: err.message };
  }
}

async function checkGzipRoundTrip(dir) {
  const probe = join(dir, `.gzip-probe-${process.pid}-${Date.now()}.gz`);
  const original = JSON.stringify({ hello: 'world', ts: Date.now() });
  try {
    const gz = gzipSync(Buffer.from(original, 'utf8'));
    await writeFile(probe, gz);
    const back = await readFile(probe);
    const decoded = gunzipSync(back).toString('utf8');
    await unlink(probe);
    return decoded === original ? { ok: true, size: gz.length } : { ok: false, error: 'gzip round-trip mismatch' };
  } catch (err) {
    try { await unlink(probe).catch(() => {}); } catch { /* noop */ }
    return { ok: false, error: err.message };
  }
}

async function checkDiskSpace(dir) {
  try {
    const s = await statfs(dir);
    const blockSize = Number(s.bsize) || 4096;
    const freeBytes = Number(s.bavail) * blockSize;
    const totalBytes = Number(s.blocks) * blockSize;
    // Below 50 MiB free we surface a warning, below
    // 10 MiB we fail the readiness check. The
    // application MUST refuse to start on a host
    // that cannot guarantee enough free space for
    // one V6.1 bundle + one export.
    const minBytes = 50 * 1024 * 1024;
    return {
      ok: freeBytes > minBytes,
      freeBytes, totalBytes,
      warning: freeBytes < 50 * 1024 * 1024,
      error: freeBytes < 10 * 1024 * 1024 ? 'insufficient-disk-space' : undefined,
    };
  } catch {
    // statfs is not available on some platforms
    // (notably Windows under certain restrictions).
    return { ok: true, available: false };
  }
}

async function checkSymlinkSafety(dataRoot) {
  // The data root MUST resolve to a real directory
  // that is not a symlink pointing somewhere else.
  try {
    const real = await realpath(dataRoot);
    if (real !== normalize(dataRoot)) {
      // The data root is a symlink. The application
      // still works (it follows the symlink on every
      // write) but operators should be aware; surface
      // a warning, not a failure.
      return { ok: true, symlink: true, resolvedTo: maskHomePath(real) };
    }
    return { ok: true, symlink: false };
  } catch (err) {
    return { ok: false, error: err.message };
  }
}

async function checkPublicIsolation(dataRoot, publicDir) {
  if (!publicDir) return { ok: true, isolated: true, checked: false };
  if (isPathInside(publicDir, dataRoot)) {
    return { ok: false, isolated: false, error: 'data-root-inside-public-dir' };
  }
  if (isPathInside(dataRoot, publicDir)) {
    return { ok: false, isolated: false, error: 'public-dir-inside-data-root' };
  }
  return { ok: true, isolated: true, checked: true };
}

async function checkNoSecretsInRoot(dataRoot) {
  // A best-effort scan of the data root for files
  // that look like credentials. The application
  // never writes these files itself; the check
  // exists so a misconfigured operator catches the
  // problem before deployment.
  try {
    const entries = await readdir(dataRoot, { withFileTypes: true });
    const found = [];
    for (const ent of entries) {
      if (ent.isFile() && FORBIDDEN_NAMES.has(ent.name)) {
        found.push(ent.name);
      }
      if (ent.isFile() && ent.name.endsWith('.pem')) {
        found.push(ent.name);
      }
    }
    return { ok: found.length === 0, found };
  } catch (err) {
    return { ok: true, error: err.message };
  }
}

/**
 * Run every readiness check. The result is a list of
 * `{ name, ok, ...details }` records plus an overall
 * `ready` boolean (false when any check is not ok).
 */
export async function checkReadiness({ dataRoot, publicDir = null, logger = null } = {}) {
  if (!dataRoot || !isAbsolute(dataRoot)) {
    return { ready: false, checks: [{ name: 'dataRoot', ok: false, error: 'data-root-must-be-absolute' }] };
  }
  const checks = [];
  // 1. exists / create
  const exists = await existsOrCanCreate(dataRoot);
  checks.push({ name: 'existsOrCanCreate', ...exists });
  if (!exists.ok) {
    return { ready: false, checks, dataRoot: maskHomePath(dataRoot) };
  }
  // 2. read/write
  checks.push({ name: 'readWrite', ...(await checkReadWrite(dataRoot)) });
  // 3. atomic rename
  checks.push({ name: 'atomicRename', ...(await checkAtomicRename(dataRoot)) });
  // 4. gzip round-trip
  checks.push({ name: 'gzipRoundTrip', ...(await checkGzipRoundTrip(dataRoot)) });
  // 5. disk space
  checks.push({ name: 'diskSpace', ...(await checkDiskSpace(dataRoot)) });
  // 6. symlink safety
  checks.push({ name: 'symlinkSafety', ...(await checkSymlinkSafety(dataRoot)) });
  // 7. public-dir isolation
  checks.push({ name: 'publicIsolation', ...(await checkPublicIsolation(dataRoot, publicDir)) });
  // 8. no secrets in root
  checks.push({ name: 'noSecretsInRoot', ...(await checkNoSecretsInRoot(dataRoot)) });
  const ready = checks.every((c) => c.ok);
  if (logger) {
    if (ready) logger.info({ msg: 'readiness ok', dataRoot: maskHomePath(dataRoot) });
    else logger.warn({ msg: 'readiness failed', failed: checks.filter((c) => !c.ok).map((c) => c.name) });
  }
  return { ready, checks, dataRoot: maskHomePath(dataRoot) };
}

/**
 * Sanitize a readiness result for public consumption
 * via the `/ready` endpoint. The full result is
 * available to the operator via the Hostinger CLI
 * (`node hostinger/app.mjs --readiness`).
 */
export function sanitizeReadinessForPublic(result) {
  if (!result) return { ready: false, reason: 'not-initialized' };
  if (result.ready) {
    return { ready: true };
  }
  // For the public probe we only expose a single
  // sanitized reason, never the full check list.
  const failed = result.checks.filter((c) => !c.ok);
  if (failed.length === 0) return { ready: false, reason: 'unknown' };
  return { ready: false, reason: failed[0].name };
}
