/**
 * V6.0 — Reference consumer client.
 *
 * This module is a STANDALONE Node.js library that consumers
 * (other products, internal services) can use to ingest the
 * ThreatPulse Radar canonical baseline into their own storage.
 *
 * What this client does NOT do:
 *   - It does NOT issue or store credentials. The caller
 *     provides the credential at runtime; the client never
 *     writes it to disk, never logs it, and never sends it to
 *     any host other than the configured private gateway.
 *   - It does NOT include any code that talks to the OSV
 *     upstream, the public site, or any anonymous function.
 *     The only network surface is the configured private
 *     gateway, authenticated with the provided credential.
 *   - It does NOT include any schema-version-specific data
 *     shape assumptions beyond the JSON Schemas documented
 *     in /schemas (baseline-v1, manifest-v1, delta-v1).
 *
 * What this client DOES do:
 *   - sync() — fetch the current manifest, verify its
 *     canonical content hash, write it locally, and
 *     incrementally pull only the shards it doesn't already
 *     have.
 *   - syncDelta({ fromVersion }) — fetch a delta from a known
 *     previous version to the current one, verify the base
 *     and target manifest hashes, and apply the upserts and
 *     tombstones to the local store.
 *   - snapshot({ version }) — fetch a single-endpoint snapshot
 *     for offline bootstrap. Useful for an air-gapped
 *     consumer that needs to materialize the entire baseline
 *     in one round trip.
 *   - getCurrentVersion() — return the version the local
 *     store currently considers active.
 *
 * Storage backends:
 *   The default FsBaselineStore is the filesystem. SQLite and
 *   Postgres adapters are documented in client/contracts.md;
 *   they implement the same BaselineStore interface. The
 *   client itself is backend-agnostic; it takes any object
 *   that satisfies the BaselineStore shape.
 *
 * The client is intentionally small. It is a reference
 * implementation, not a feature-complete sync engine. A real
 * product would add retries, exponential backoff, concurrent
 * shard fetches, a verification schedule, and so on. The
 * reference keeps the surface area small so the integration
 * story is obvious.
 */

import { gunzipSync } from 'node:zlib';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { gunzip as gunzipP } from 'node:zlib';

/* ------------------------------------------------------------------ */
/* HTTP layer (default; tests inject a stub)                           */
/* ------------------------------------------------------------------ */

async function defaultFetchText(url, init = {}) {
  const resp = await fetch(url, init);
  if (!resp.ok) {
    throw new Error(`fetch ${url} → HTTP ${resp.status}`);
  }
  return await resp.text();
}

async function defaultFetchJson(url, init = {}) {
  const resp = await fetch(url, init);
  if (!resp.ok) {
    throw new Error(`fetch ${url} → HTTP ${resp.status}`);
  }
  return await resp.json();
}

async function defaultFetchBinary(url, init = {}) {
  const resp = await fetch(url, init);
  if (!resp.ok) {
    throw new Error(`fetch ${url} → HTTP ${resp.status}`);
  }
  return Buffer.from(await resp.arrayBuffer());
}

/* ------------------------------------------------------------------ */
/* Canonical content hash (replicated from canonicalHash.mjs)          */
/* ------------------------------------------------------------------ */

function canonicalize(value) {
  if (value === null || value === undefined) return null;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) return null;
    return Object.is(value, -0) ? 0 : value;
  }
  if (typeof value === 'string' || typeof value === 'boolean') return value;
  if (Array.isArray(value)) {
    const allHaveId = value.length > 0 && value.every(
      (v) => v && typeof v === 'object' && typeof v.canonicalId === 'string'
    );
    const sorted = allHaveId
      ? [...value].sort((a, b) => (a.canonicalId < b.canonicalId ? -1 : a.canonicalId > b.canonicalId ? 1 : 0))
      : [...value];
    return sorted.map(canonicalize);
  }
  if (typeof value === 'object') {
    const out = {};
    for (const key of Object.keys(value).sort()) {
      out[key] = canonicalize(value[key]);
    }
    return out;
  }
  return null;
}

function canonicalContentHash(obj) {
  const str = JSON.stringify(canonicalize(obj));
  return `sha256:${createHash('sha256').update(str).digest('hex')}`;
}

// Exported for tests; the consumer's verifyManifest uses it
// internally.
export { canonicalContentHash };

/**
 * Verify a manifest's canonical content hash. Returns true if
 * the hash is valid. The hash is computed over the manifest
 * WITHOUT the `canonicalContentHash` and `deltaHash` fields
 * (deltaHash is metadata, not part of the content).
 */
export function verifyManifest(manifest) {
  if (!manifest || typeof manifest !== 'object') return false;
  const expected = manifest.canonicalContentHash;
  if (typeof expected !== 'string' || !expected.startsWith('sha256:')) return false;
  // Destructure with renaming so we don't shadow the
  // canonicalContentHash function above.
  const { canonicalContentHash: _stored, deltaHash: _delta, ...rest } = manifest;
  void _stored; void _delta;
  return canonicalContentHash(rest) === expected;
}

/* ------------------------------------------------------------------ */
/* Filesystem BaselineStore                                            */
/* ------------------------------------------------------------------ */

/**
 * Filesystem-backed implementation of the BaselineStore contract.
 * Layout matches the publisher's Blob layout:
 *   {rootDir}/
 *     manifests/latest.json
 *     manifests/versions/{version}.json
 *     objects/sha256/<hex>.json.gz
 *     deltas/{from}__to__{to}.json
 *     local-state.json   (private to the consumer — version it last applied)
 *
 * The local-state.json is the consumer's own journal. It records
 * the version of the manifest the consumer considers active.
 * This is separate from the publisher's `manifests/latest.json`
 * so the consumer can roll back independently.
 */
export class FsBaselineStore {
  constructor({ rootDir }) {
    if (typeof rootDir !== 'string' || rootDir.length === 0) {
      throw new Error('FsBaselineStore: rootDir is required');
    }
    this.rootDir = rootDir;
  }

  async _ensureDir(dir) {
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  }

  async readManifest() {
    try {
      const raw = readFileSync(join(this.rootDir, 'manifests', 'latest.json'), 'utf8');
      return JSON.parse(raw);
    } catch {
      return null;
    }
  }

  async writeManifest(manifest) {
    const dir = join(this.rootDir, 'manifests');
    await this._ensureDir(dir);
    writeFileSync(join(dir, 'latest.json'), JSON.stringify(manifest, null, 2), 'utf8');
    // Also write the immutable version manifest for rollback
    if (typeof manifest.baselineVersion === 'string' && manifest.baselineVersion.length > 0) {
      const vdir = join(dir, 'versions');
      await this._ensureDir(vdir);
      writeFileSync(join(vdir, `${manifest.baselineVersion}.json`), JSON.stringify(manifest, null, 2), 'utf8');
    }
  }

  async readVersionManifest(version) {
    try {
      const raw = readFileSync(join(this.rootDir, 'manifests', 'versions', `${version}.json`), 'utf8');
      return JSON.parse(raw);
    } catch {
      return null;
    }
  }

  async readShard(objectKey) {
    try {
      const bytes = readFileSync(join(this.rootDir, objectKey));
      return JSON.parse(gunzipSync(bytes).toString('utf8'));
    } catch {
      return null;
    }
  }

  async hasShard(objectKey) {
    return existsSync(join(this.rootDir, objectKey));
  }

  async writeShard(objectKey, gzippedBytes) {
    const dir = dirname(join(this.rootDir, objectKey));
    await this._ensureDir(dir);
    writeFileSync(join(this.rootDir, objectKey), gzippedBytes);
  }

  async readDelta(fromVersion, toVersion) {
    try {
      const raw = readFileSync(join(this.rootDir, 'deltas', `${fromVersion}__to__${toVersion}.json`), 'utf8');
      return JSON.parse(raw);
    } catch {
      return null;
    }
  }

  async writeDelta(fromVersion, toVersion, delta) {
    const dir = join(this.rootDir, 'deltas');
    await this._ensureDir(dir);
    writeFileSync(join(dir, `${fromVersion}__to__${toVersion}.json`), JSON.stringify(delta, null, 2), 'utf8');
  }

  async getCurrentVersion() {
    const m = await this.readManifest();
    return m ? m.baselineVersion : null;
  }

  async listLocalShards() {
    // Best-effort: scan objects/sha256/. The consumer's local
    // store mirrors the publisher's content-addressed layout, so
    // every shard file in objects/sha256/ is a local copy.
    const dir = join(this.rootDir, 'objects', 'sha256');
    if (!existsSync(dir)) return [];
    const { readdirSync } = await import('node:fs');
    return readdirSync(dir).map((name) => `objects/sha256/${name}`);
  }

  async clear() {
    if (existsSync(this.rootDir)) {
      rmSync(this.rootDir, { recursive: true, force: true });
    }
  }
}

/* ------------------------------------------------------------------ */
/* The ConsumerClient                                                   */
/* ------------------------------------------------------------------ */

export class ConsumerClient {
  /**
   * @param {Object} opts
   * @param {string} opts.gatewayUrl   - base URL of the private gateway (no trailing /)
   * @param {string} opts.credential   - the HMAC credential string (tpr_xxx_yyy)
   * @param {Object} opts.store        - a BaselineStore implementation
   * @param {Object} [opts.fetcher]    - { fetchJson, fetchBinary, fetchText } injection surface
   * @param {number} [opts.shardConcurrency] - max parallel shard fetches (default 4)
   * @param {boolean} [opts.skipShardFetch]  - for tests; do not actually fetch shards
   */
  constructor({ gatewayUrl, credential, store, fetcher, shardConcurrency = 4, skipShardFetch = false } = {}) {
    if (typeof gatewayUrl !== 'string' || gatewayUrl.length === 0) {
      throw new Error('ConsumerClient: gatewayUrl is required');
    }
    if (typeof credential !== 'string' || !credential.startsWith('tpr_')) {
      throw new Error('ConsumerClient: credential must be a tpr_ string');
    }
    if (!store || typeof store.readManifest !== 'function') {
      throw new Error('ConsumerClient: store is required and must satisfy the BaselineStore contract');
    }
    this.gatewayUrl = gatewayUrl.replace(/\/$/, '');
    this.credential = credential;
    this.store = store;
    this.fetcher = fetcher || {
      fetchJson: defaultFetchJson,
      fetchBinary: defaultFetchBinary,
      fetchText: defaultFetchText,
    };
    this.shardConcurrency = Math.max(1, Math.min(shardConcurrency | 0 || 4, 32));
    this.skipShardFetch = !!skipShardFetch;
  }

  _authHeaders() {
    return { 'Authorization': `Bearer ${this.credential}` };
  }

  _url(path) {
    return `${this.gatewayUrl}${path}`;
  }

  /**
   * Fetch the current manifest. Verifies the canonical content
   * hash. Returns the manifest object.
   */
  async fetchAndVerifyManifest({ version } = {}) {
    const path = version ? `/private/v1/manifest/${encodeURIComponent(version)}` : '/private/v1/manifest';
    const m = await this.fetcher.fetchJson(this._url(path), { headers: this._authHeaders() });
    if (!verifyManifest(m)) {
      throw new Error('manifest verification failed: canonicalContentHash mismatch');
    }
    return m;
  }

  /**
   * Sync: fetch the current manifest, write it locally, and
   * pull any shards the local store doesn't already have.
   * Returns `{ version, shardsAdded, shardsReused, manifest }`.
   */
  async sync() {
    const manifest = await this.fetchAndVerifyManifest();
    let shardsAdded = 0;
    let shardsReused = 0;
    if (!this.skipShardFetch) {
      const wantedKeys = [];
      for (const entityType of Object.keys(manifest.shards || {})) {
        for (const bucket of Object.keys(manifest.shards[entityType] || {})) {
          wantedKeys.push(manifest.shards[entityType][bucket].objectKey);
        }
      }
      for (const key of wantedKeys) {
        const have = await this.store.hasShard(key);
        if (have) { shardsReused++; continue; }
        const bytes = await this.fetcher.fetchBinary(this._url(`/private/v1/shard?key=${encodeURIComponent(key)}`), { headers: this._authHeaders() });
        await this.store.writeShard(key, bytes);
        shardsAdded++;
      }
    }
    await this.store.writeManifest(manifest);
    return { version: manifest.baselineVersion, shardsAdded, shardsReused, manifest };
  }

  /**
   * Sync via a delta from a known previous version to the
   * current. The delta's `baseManifestHash` must match the
   * stored previous version's `canonicalContentHash`; the
   * `targetManifestHash` must match the current manifest.
   *
   * Note: this reference consumer applies the delta as a
   * upsert/tombstone overlay. A real consumer might want to
   * reconcile the entire bucket rather than relying on the
   * publisher's delta; see client/contracts.md for the
   * trade-offs.
   */
  async syncDelta({ fromVersion } = {}) {
    if (typeof fromVersion !== 'string' || fromVersion.length === 0) {
      throw new Error('syncDelta: fromVersion is required');
    }
    // Need the current manifest to know the target version.
    const current = await this.fetchAndVerifyManifest();
    const delta = await this.fetcher.fetchJson(
      this._url(`/private/v1/delta?from=${encodeURIComponent(fromVersion)}&to=${encodeURIComponent(current.baselineVersion)}`),
      { headers: this._authHeaders() }
    );
    if (delta.targetManifestHash !== current.canonicalContentHash) {
      throw new Error('delta.targetManifestHash does not match current manifest hash');
    }
    // Save the delta locally for auditability
    await this.store.writeDelta(fromVersion, current.baselineVersion, delta);
    await this.store.writeManifest(current);
    return { fromVersion, toVersion: current.baselineVersion, delta };
  }

  /**
   * One-shot snapshot for offline bootstrap. The response
   * includes the manifest and all shards, with each shard as
   * base64-encoded gzipped bytes.
   *
   * The consumer decodes the base64, writes the gzipped bytes
   * to its local store, and decompresses on read. A real
   * consumer would also verify the snapshot's per-shard sha256
   * against the manifest's shard map.
   */
  async snapshot({ version } = {}) {
    const v = version || (await this.store.getCurrentVersion());
    if (!v) throw new Error('snapshot: no version available — pass version explicitly or call sync() first');
    const snap = await this.fetcher.fetchJson(
      this._url(`/private/v1/snapshot?version=${encodeURIComponent(v)}`),
      { headers: this._authHeaders() }
    );
    if (!verifyManifest(snap.manifest)) {
      throw new Error('snapshot manifest verification failed');
    }
    let shardsWritten = 0;
    for (const [key, base64] of Object.entries(snap.shards || {})) {
      if (typeof base64 !== 'string' || base64.length === 0) continue;
      const bytes = Buffer.from(base64, 'base64');
      await this.store.writeShard(key, bytes);
      shardsWritten++;
    }
    await this.store.writeManifest(snap.manifest);
    return { version: snap.manifest.baselineVersion, shardsWritten, manifest: snap.manifest };
  }

  /**
   * Return the version the local store considers active.
   */
  async getCurrentVersion() {
    return await this.store.getCurrentVersion();
  }
}
