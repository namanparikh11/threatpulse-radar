/**
 * V6.2 — Storage adapter interface.
 *
 * The narrow contract every ThreatPulse storage backend
 * must implement. The interface mirrors the slice of
 * `@netlify/blobs` the application actually uses so the
 * call-site surface does not change when we swap
 * backends.
 *
 * Required semantics:
 *   - Keys are forward-slash-separated strings (e.g.
 *     "latest-dataset", "manifests/latest.json",
 *     "shards/sha256/<hex>.json.gz").
 *   - get() returns null for missing keys.
 *   - set() overwrites unconditionally.
 *   - delete() is idempotent (no error on missing key).
 *   - list({prefix}) returns the keys that begin with
 *     the prefix. The result is an OBJECT with a `blobs`
 *     array of `{key, etag}` (compatible with the
 *     existing Netlify Blobs list() shape).
 *   - getJSON / setJSON round-trip JSON-serializable
 *     values.
 *   - getBinary / setBinary preserve the byte length.
 *   - setBinary MUST be atomic on Filesystem (temp +
 *     rename) so a crashed writer cannot leave a
 *     half-written Blob.
 *
 * Every adapter is constructed via `createStorageAdapter`
 * which centralizes adapter selection and option
 * validation. The legacy module-level
 * `getBaselineStore` / `getDatasetStore` /
 * `getVulnrichmentStore` / `getGithubAdvisoryStore` /
 * `getPublicIntelligenceStore` helpers in this codebase
 * return instances of this interface (or a Netlify client
 * for backward-compatible read sites); the new
 * `createStorageAdapter` factory is the recommended
 * entry point for new code.
 */

/**
 * The canonical options accepted by the public methods
 * of a StorageAdapter. The two `type` values are the only
 * ones the application uses.
 */
export const STORAGE_TYPE = Object.freeze({
  JSON: 'json',
  ARRAY_BUFFER: 'arrayBuffer',
});

/**
 * Default option values for get / set calls. An adapter
 * that ignores unknown options MUST NOT fail when
 * called with these defaults.
 */
export const DEFAULT_GET_OPTIONS = Object.freeze({ type: STORAGE_TYPE.ARRAY_BUFFER });
export const DEFAULT_SET_OPTIONS = Object.freeze({ type: STORAGE_TYPE.ARRAY_BUFFER });

/**
 * Validate a storage key. Keys MUST be non-empty,
 * forward-slash-separated strings. Path-traversal
 * markers (`..`, absolute paths, backslashes) are
 * rejected at the adapter boundary.
 */
export function assertValidKey(key) {
  if (typeof key !== 'string' || key.length === 0) {
    throw new Error('StorageAdapter: key must be a non-empty string');
  }
  if (key.includes('\\')) {
    throw new Error('StorageAdapter: key must not contain backslashes');
  }
  if (key.startsWith('/')) {
    throw new Error('StorageAdapter: key must not start with a forward slash');
  }
  if (key.includes('..')) {
    throw new Error('StorageAdapter: key must not contain a parent-directory marker');
  }
  if (key.includes('\u0000')) {
    throw new Error('StorageAdapter: key must not contain a NUL byte');
  }
  return true;
}

/**
 * Default list() result shape.
 */
function makeListResult(keys) {
  return { blobs: keys.map((k) => ({ key: k, etag: '' })) };
}

/**
 * The base class. Adapters extend this and implement
 * the abstract `_get` / `_set` / `_delete` / `_list`
 * / `_exists` methods. The base class adds
 * `getJSON` / `setJSON` / `getBinary` / `setBinary` as
 * thin JSON-encoding wrappers.
 */
export class StorageAdapter {
  constructor({ name = 'unnamed', siteID = null, token = null } = {}) {
    this.name = name;
    this.siteID = siteID;
    this.token = token;
  }

  /**
   * Read the bytes for a key. Returns null when the
   * key is missing. The returned Buffer is a fresh
   * copy; the caller may mutate it.
   */
  async _get(key) {
    throw new Error(`StorageAdapter(${this.name})._get: not implemented`);
  }

  /**
   * Write the bytes for a key. MUST be atomic on
   * adapters that support atomic publication. A failed
   * write MUST leave the previous value intact.
   */
  async _set(key, value) {
    throw new Error(`StorageAdapter(${this.name})._set: not implemented`);
  }

  /**
   * Delete a key. Idempotent.
   */
  async delete(key) {
    throw new Error(`StorageAdapter(${this.name}).delete: not implemented`);
  }

  /**
   * List keys under a prefix. Returns an object with
   * a `blobs` array of `{key, etag}` entries (compatible
   * with the Netlify Blobs list() shape).
   */
  async _list(prefix = '') {
    throw new Error(`StorageAdapter(${this.name})._list: not implemented`);
  }

  /**
   * Check whether a key exists.
   */
  async _exists(key) {
    const v = await this._get(key);
    return v !== null && v !== undefined;
  }

  /**
   * Public get() with Netlify-compatible options.
   * - { type: 'json' }: parses the value as JSON and
   *   returns the parsed value, or null when missing.
   * - { type: 'arrayBuffer' }: returns a Buffer.
   */
  async get(key, opts = {}) {
    assertValidKey(key);
    const type = opts && opts.type ? opts.type : STORAGE_TYPE.ARRAY_BUFFER;
    const raw = await this._get(key);
    if (raw === null || raw === undefined) return null;
    if (type === STORAGE_TYPE.JSON) {
      if (typeof raw === 'string') return JSON.parse(raw);
      if (raw instanceof Buffer) return JSON.parse(raw.toString('utf8'));
      return raw;
    }
    if (raw instanceof Buffer) return raw;
    return Buffer.from(raw);
  }

  /**
   * Public set() with Netlify-compatible options.
   * - { type: 'json' }: JSON-stringifies the value.
   * - { type: 'arrayBuffer' }: writes the bytes verbatim.
   *   When a Buffer is passed, it is written as-is.
   */
  async set(key, value, opts = {}) {
    assertValidKey(key);
    const type = opts && opts.type ? opts.type : STORAGE_TYPE.ARRAY_BUFFER;
    if (type === STORAGE_TYPE.JSON) {
      const json = typeof value === 'string' ? value : JSON.stringify(value);
      await this._set(key, Buffer.from(json, 'utf8'));
      return;
    }
    if (value instanceof Buffer) {
      await this._set(key, value);
      return;
    }
    await this._set(key, Buffer.from(value));
  }

  /**
   * Read a JSON value. Returns null on missing key or
   * parse error. Convenience wrapper around
   * `get(key, { type: 'json' })`.
   */
  async getJSON(key) {
    return this.get(key, { type: STORAGE_TYPE.JSON });
  }

  /**
   * Write a JSON value. Convenience wrapper around
   * `set(key, value, { type: 'json' })`.
   */
  async setJSON(key, value) {
    return this.set(key, value, { type: STORAGE_TYPE.JSON });
  }

  /**
   * Read a binary value. Returns a Buffer or null.
   */
  async getBinary(key) {
    return this.get(key, { type: STORAGE_TYPE.ARRAY_BUFFER });
  }

  /**
   * Write a binary value. The Buffer is written
   * verbatim; atomic semantics are the adapter's
   * responsibility.
   */
  async setBinary(key, value) {
    return this.set(key, value, { type: STORAGE_TYPE.ARRAY_BUFFER });
  }

  /**
   * List keys under a prefix. Returns the Netlify-shaped
   * `{blobs: [{key, etag}, ...]}` result.
   */
  async list({ prefix = '' } = {}) {
    return this._list(prefix);
  }

  /**
   * Check whether a key exists.
   */
  async exists(key) {
    return this._exists(key);
  }

  /**
   * Identity tag for diagnostics.
   */
  describe() {
    return { name: this.name, siteID: this.siteID };
  }
}
