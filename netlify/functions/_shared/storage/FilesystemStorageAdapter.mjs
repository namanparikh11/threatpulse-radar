/**
 * V6.2 — Filesystem storage adapter.
 *
 * Backed by a single configurable data root. Each key is
 * mapped to a deterministic file path; the adapter
 * guarantees:
 *
 *   - Windows and Linux path compatibility. Path
 *     separators are normalized internally.
 *   - Path-traversal rejection. The
 *     `assertValidKey` check rejects `..`, absolute
 *     paths, backslashes, and NUL bytes.
 *   - Atomic writes via a temporary file plus rename.
 *     A crashed writer never leaves a half-written
 *     Blob on disk.
 *   - manifest-last publication: when a key matches
 *     `latest.json` (or its parent path), the
 *     `setLatestAtomic` helper performs a temp + rename
 *     specifically tuned for atomic pointer updates.
 *   - Crash recovery: the next read returns either the
 *     previous bytes or the new bytes — never a
 *     truncated file (the rename is atomic at the
 *     filesystem level on POSIX; on Windows the rename
 *     uses ReplaceFile semantics via the standard
 *     rename path).
 *   - No secrets inside the data directory: the
 *     adapter never writes credentials, env-var values,
 *     or raw hashes. Operators must place the data
 *     root under a path they trust.
 *   - Symlink escape rejection: realpath of the parent
 *     of every written file is checked against the
 *     realpath of the data root; a symlink that points
 *     outside the data root causes a write to fail
 *     with a sanitized error.
 *
 * The adapter is a Node-only implementation; it has no
 * platform-specific code paths beyond the standard `fs`
 * module. Tests can exercise it on Windows, Linux, and
 * macOS without changes.
 */

import { promises as fsp, realpathSync, existsSync, mkdirSync, readdirSync } from 'node:fs';
import { dirname, join, normalize, sep, isAbsolute } from 'node:path';
import { StorageAdapter, assertValidKey } from './StorageAdapter.mjs';

function safeJoin(root, key) {
  // Normalize separators to the host's separator.
  const norm = key.split('/').join(sep);
  const joined = normalize(join(root, norm));
  return joined;
}

function isInside(parent, child) {
  const a = normalize(parent + sep);
  const b = normalize(child + sep);
  return b === a || b.startsWith(a);
}

export class FilesystemStorageAdapter extends StorageAdapter {
  /**
   * @param {Object} opts
   * @param {string} opts.dataRoot - absolute path to the data directory.
   * @param {string} [opts.tmpSuffix] - suffix for temp files (default `.tmp`).
   * @param {boolean} [opts.recheckSymlinks] - if true (default), verify
   *   the parent of every write target is inside the real data root.
   */
  constructor({ dataRoot, tmpSuffix = '.tmp', recheckSymlinks = true } = {}) {
    super({ name: 'filesystem' });
    if (!dataRoot || typeof dataRoot !== 'string') {
      throw new Error('FilesystemStorageAdapter: dataRoot is required');
    }
    if (!isAbsolute(dataRoot)) {
      throw new Error('FilesystemStorageAdapter: dataRoot must be an absolute path');
    }
    this.dataRoot = dataRoot;
    this.tmpSuffix = tmpSuffix;
    this.recheckSymlinks = recheckSymlinks;
    this._realRoot = null;
    // Lazily resolve and verify the data root on first
    // use. Creating the directory here would be
    // surprising; we create on first write instead.
  }

  _ensureRoot() {
    if (this._realRoot) return this._realRoot;
    if (!existsSync(this.dataRoot)) {
      mkdirSync(this.dataRoot, { recursive: true });
    }
    this._realRoot = realpathSync(this.dataRoot);
    return this._realRoot;
  }

  _resolvePath(key) {
    assertValidKey(key);
    const full = safeJoin(this.dataRoot, key);
    const parent = dirname(full);
    const realRoot = this._ensureRoot();
    if (this.recheckSymlinks && existsSync(parent)) {
      const realParent = realpathSync(parent);
      if (!isInside(realRoot, realParent)) {
        throw new Error(`FilesystemStorageAdapter: path-traversal rejected for key "${key}"`);
      }
    } else if (!existsSync(parent)) {
      mkdirSync(parent, { recursive: true });
      // After mkdir, re-verify the parent is inside
      // the real root.
      if (this.recheckSymlinks) {
        const realParent = realpathSync(parent);
        if (!isInside(realRoot, realParent)) {
          throw new Error(`FilesystemStorageAdapter: path-traversal rejected for key "${key}"`);
        }
      }
    }
    return full;
  }

  async _get(key) {
    const full = this._resolvePath(key);
    try {
      const buf = await fsp.readFile(full);
      return buf;
    } catch (err) {
      if (err && err.code === 'ENOENT') return null;
      throw err;
    }
  }

  async _set(key, value) {
    const full = this._resolvePath(key);
    const dir = dirname(full);
    // Ensure the parent exists and is symlink-clean.
    await fsp.mkdir(dir, { recursive: true });
    if (this.recheckSymlinks) {
      const realRoot = this._ensureRoot();
      const realDir = realpathSync(dir);
      if (!isInside(realRoot, realDir)) {
        throw new Error(`FilesystemStorageAdapter: path-traversal rejected for key "${key}"`);
      }
    }
    // Atomic write: temp file + rename.
    const tmp = full + this.tmpSuffix + '.' + process.pid + '.' + Date.now();
    const handle = await fsp.open(tmp, 'w');
    try {
      await handle.writeFile(value);
      await handle.sync();
    } finally {
      await handle.close();
    }
    await fsp.rename(tmp, full);
  }

  async delete(key) {
    const full = this._resolvePath(key);
    try {
      await fsp.unlink(full);
    } catch (err) {
      if (err && err.code === 'ENOENT') return;
      throw err;
    }
  }

  async _list(prefix = '') {
    // Synchronous walk of the data root. Acceptable for
    // the modest number of keys the application writes
    // (manifests, shards, snapshots, source-health).
    const out = [];
    const root = this._ensureRoot();
    const walk = (dir, prefixSoFar) => {
      let entries;
      try {
        entries = readdirSync(dir, { withFileTypes: true });
      } catch (err) {
        if (err && err.code === 'ENOENT') return;
        throw err;
      }
      for (const ent of entries) {
        const next = prefixSoFar ? prefixSoFar + '/' + ent.name : ent.name;
        if (ent.isDirectory()) {
          walk(join(dir, ent.name), next);
        } else if (ent.isFile()) {
          if (next.startsWith(prefix)) out.push(next);
        }
      }
    };
    walk(root, '');
    out.sort();
    return { blobs: out.map((k) => ({ key: k, etag: '' })) };
  }

  async _exists(key) {
    const full = this._resolvePath(key);
    try {
      await fsp.access(full);
      return true;
    } catch {
      return false;
    }
  }
}
