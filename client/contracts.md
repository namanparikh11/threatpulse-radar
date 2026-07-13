# V6.0 — Consumer Storage Adapter Contract

The reference consumer client in
[`client/consumer-client.mjs`](../client/consumer-client.mjs)
ships with a filesystem-backed store (`FsBaselineStore`). SQLite
and Postgres adapters are not implemented in V6.0; this document
is the **contract** they must satisfy to drop in as a
replacement.

The contract is intentionally small. A store is any object that
implements the methods below. The client never inspects a store's
identity, only its methods.

## 1. Method contract

```ts
interface BaselineStore {
  // --- Manifests (the consumer's current view) ---

  /** Read the current manifest, or null if no baseline is
   *  applied yet. */
  readManifest(): Promise<Manifest | null>;

  /** Atomically replace the current manifest and the immutable
   *  version manifest. Must persist both before returning. */
  writeManifest(manifest: Manifest): Promise<void>;

  /** Read an immutable version manifest, or null if unknown. */
  readVersionManifest(version: string): Promise<Manifest | null>;

  // --- Shards (the content-addressed per-bucket content) ---

  /** Read a shard, returning the parsed canonical entity list
   *  (the consumer expects the un-gzipped JSON), or null if
   *  the shard is not local. */
  readShard(objectKey: string): Promise<Entity[] | null>;

  /** Check whether a shard is local, without reading it. */
  hasShard(objectKey: string): Promise<boolean>;

  /** Persist a shard. The input is the GZIPPED bytes as
   *  received from the gateway (or written by the snapshot
   *  endpoint). The store is responsible for any compression
   *  on disk; the consumer does not pre-decompress. */
  writeShard(objectKey: string, gzippedBytes: Uint8Array): Promise<void>;

  // --- Deltas (audit trail) ---

  /** Read a delta, or null if not stored. */
  readDelta(fromVersion: string, toVersion: string): Promise<Delta | null>;

  /** Persist a delta. */
  writeDelta(fromVersion: string, toVersion: string, delta: Delta): Promise<void>;

  // --- Cursor (the consumer's own state) ---

  /** Return the version the consumer considers active. */
  getCurrentVersion(): Promise<string | null>;
}
```

## 2. Object key conventions

The consumer follows the publisher's content-addressed layout
verbatim. Object keys are opaque to the store — the store should
not parse them. The shapes the publisher emits:

| Artifact        | Key shape                                      |
| --------------- | ---------------------------------------------- |
| Shard           | `objects/sha256/<64 hex>.json.gz`              |
| Version manifest| `manifests/versions/<version>.json`            |
| Latest manifest | `manifests/latest.json`                        |
| Delta           | `deltas/<fromVersion>__to__<toVersion>.json`   |

A SQLite store might use a `(kind, key)` table; a Postgres store
might use a `bytea` column or S3-style object storage. The key
shape is the same; the storage is opaque.

## 3. Atomicity requirements

The publisher's atomicity guarantees rely on `manifests/latest.json`
being a single strongly-consistent write. The consumer's
`writeManifest` MUST be atomic at the (manifest, latest pointer)
boundary: a partial write that leaves `manifests/latest.json`
pointing to a not-yet-written version manifest is a violation
of the V6.0 contract.

For a SQLite store this is one transaction:
```sql
BEGIN;
  INSERT OR REPLACE INTO version_manifests (version, body) VALUES (?, ?);
  INSERT OR REPLACE INTO latest_pointer (id, version, body) VALUES (1, ?, ?);
COMMIT;
```

For a Postgres store, the same single transaction. For a Postgres
store with a separate metadata DB and an object store (S3 / GCS),
the consumer should use a two-phase pattern:

1. Upload the new version manifest to object storage.
2. Update the metadata row pointing to it.
3. Update the latest pointer row.

A reader that sees a `latest_pointer` with a missing object
should treat that as a transient state and either retry or
fall back to the previous version.

## 4. Shard key validation

The store SHOULD reject keys that:

- Contain `..`, `/`, or `\` as path components that escape the
  configured root.
- Start with `/` or `\`.
- Contain characters outside `[a-zA-Z0-9_\-./]`.

The reference store does this. A SQLite or Postgres adapter
should validate the key the same way at write time and at read
time.

## 5. Compression and integrity

The store MAY compress shards further (e.g. zstd) on top of the
publisher's gzip, as long as the consumer can decompress them on
read. The publisher's `byteSize` on the shard descriptor is the
gzipped size, not the on-disk size after the adapter's additional
compression.

A consumer that wants to verify shard integrity should compare
the sha256 of the canonical (decompressed) JSON to the
descriptor's `sha256`. The store does not need to do this — the
publisher's sha256 is the content hash and is the same regardless
of how the store compresses the bytes.

## 6. Concurrency

The reference consumer is single-process and does not lock. A
multi-process consumer should:

- Use the store's own locking primitives (SQLite's `BEGIN IMMEDIATE`,
  Postgres's `SELECT ... FOR UPDATE`).
- Serialize concurrent `writeManifest` calls so two processes do
  not race on `latest_pointer`.

The publisher's atomicity is the source of truth. A consumer that
sees a torn write should treat the local state as suspect and
re-sync from the publisher's immutable `manifests/versions/`.

## 7. Failure recovery

The store is the consumer's local state. A failure during
`writeManifest` (process crash, power loss, network blip during
the publisher write that the consumer mirrors) should leave the
store recoverable:

- Re-read `manifests/latest.json` from the publisher. If it
  exists, that is the new active version.
- If the local store has a `manifests/versions/{v}.json` for
  that version, the local copy is consistent; proceed.
- If not, call `snapshot({ version })` to re-pull.

The store does not need to implement crash-safe transactions
beyond the single-write atomicity above. The publisher is the
recovery target.

## 8. Manifest + Delta JSON Schemas

The store's `writeManifest` accepts the manifest as produced by
`buildVersionManifest` in
[`netlify/functions/_shared/baselinePublish.mjs`](../netlify/functions/_shared/baselinePublish.mjs).
The shape is documented in
[`schemas/manifest-v1.schema.json`](../schemas/manifest-v1.schema.json).

The store's `writeDelta` accepts the delta as produced by
`buildDelta` in the same module. The shape is documented in
[`schemas/delta-v1.schema.json`](../schemas/delta-v1.schema.json).

A SQLite or Postgres adapter should validate incoming manifests
and deltas against these JSON Schemas before persisting. The
publisher has already validated them, but a defense-in-depth
check at the consumer catches accidental local corruption and
fence-post errors when the schema evolves.

## 9. SQLite adapter sketch

The reference SQLite store (NOT IMPLEMENTED in V6.0; sketch
only) would have a small schema:

```sql
CREATE TABLE version_manifests (
  version TEXT PRIMARY KEY,
  body BLOB NOT NULL,         -- gzipped JSON
  published_at TEXT NOT NULL,
  canonical_content_hash TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE latest_pointer (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  version TEXT NOT NULL,
  body BLOB NOT NULL,         -- gzipped JSON, same as version_manifests.body
  FOREIGN KEY (version) REFERENCES version_manifests(version)
);

CREATE TABLE shards (
  object_key TEXT PRIMARY KEY,
  body BLOB NOT NULL,         -- gzipped JSON
  sha256 TEXT NOT NULL,
  byte_size INTEGER NOT NULL,
  record_count INTEGER NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE deltas (
  from_version TEXT NOT NULL,
  to_version TEXT NOT NULL,
  body BLOB NOT NULL,         -- gzipped JSON
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (from_version, to_version)
);
```

The `body` columns hold the gzipped JSON. Decompression is
deferred to `readManifest` / `readShard` / `readDelta`.

## 10. Postgres adapter sketch

Same shape as the SQLite adapter with:

- `body BYTEA` instead of `BLOB`.
- `TEXT` for the hash columns (no length limit issues).
- `latest_pointer` keyed by a single-row check constraint or a
  sequence.
- Optionally a `tsvector` index on the manifest's `summary`,
  `description`, and other searchable fields, so consumers can
  build full-text search without a separate indexing pass.

## 11. When to NOT write an adapter

The reference consumer is a deliberate simplification. A real
product usually needs:

- Concurrent shard fetches with bounded concurrency
- Retry with exponential backoff on transient HTTP errors
- A periodic resync schedule
- Schema-version-aware migration
- Verification (a "scrub" pass that re-pulls and re-verifies a
  random sample of shards)
- A observability surface (metrics, structured logs, traces)

The reference client does NONE of these. It is the smallest
useful consumer. Real adapters should add what the product
needs but should NOT add what the baseline does not need —
the V6.0 design is intentionally minimal.
