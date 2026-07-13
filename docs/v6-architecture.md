# V6.0 — Architecture overview

This document is the V6.0 architectural overview. The full
design (with all decisions and trade-offs) is in the V6.0
design report committed alongside the code; this document is
the **read-once** summary for an engineer or operator who
needs to understand how the system fits together.

## What V6.0 is

V6.0 introduces a **canonical baseline** for the ThreatPulse
Radar data: a content-addressed, versioned, atomic-publication
snapshot of all vulnerability / advisory / package /
relationship / tombstone entities, derived from OSV. The
baseline is a private product: only authenticated callers see
it; the public dashboard is unchanged.

The V6.0 system replaces the implicit "each function reads
NVD/CISA/EPSS and builds its own dataset" model with an
explicit "publisher emits a versioned baseline; consumers
ingest it" model. The pipeline is the same shape as a
package manager: a publisher signs and tags versions,
consumers pin or follow.

## Topology

```
                    PUBLIC SITE                          PRIVATE GATEWAY
                    (ThreatPulse Radar)                  (separate Netlify site)
                ┌────────────────────┐                  ┌────────────────────┐
                │                    │                  │                    │
                │  V5.7 dashboard    │                  │  /private/v1/*     │
                │  (UNCHANGED)       │                  │  5 authenticated  │
                │                    │                  │  routes            │
                │  tpr-dataset       │                  │                    │
                │  tpr-vulnrichment  │                  │  THREATPULSE_      │
                │  tpr-github-        │                  │   BASELINE_SITE_ID │
                │   advisory          │                  │  THREATPULSE_      │
                │  tpr-baseline  ◀─── │ ── cross-site ── │   BLOBS_ACCESS_    │
                │   (NEW)            │   read access    │   TOKEN            │
                │                    │   (server-side)  │  THREATPULSE_      │
                │  refresh-          │                  │   CREDENTIAL_PEPPER│
                │   baseline-        │                  │                    │
                │   scheduled  ─┐    │                  │  refresh-baseline- │
                │               │    │                  │   background       │
                │  refresh-     ▼    │                  │   (15-min ceiling) │
                │   baseline-  POST  │  trigger secret  │                    │
                │   background ──────│ ───────────────▶ │                    │
                │   (15-min)          │                  │                    │
                └────────────────────┘                  └────────────────────┘
                          │                                       │
                          │  CRON every hour                      │  runOsvBackground()
                          ▼                                       │  in a loop
                ┌────────────────────┐                            │
                │  Scheduled Func    │  thin: just POSTs          │
                │  (30s ceiling)      │  with X-Trigger-Secret     │
                └────────────────────┘                            │
                                                                   ▼
                                                          ┌──────────────────┐
                                                          │  OSV (upstream)   │
                                                          │  GCS bucket       │
                                                          │  per-ecosystem    │
                                                          │  modified_id.csv  │
                                                          │  + vuln JSON      │
                                                          └──────────────────┘
```

The cron is **public-site** (Netlify Scheduled Function under
30s). It POSTs to the **public-site** Background Function with
`THREATPULSE_REFRESH_TRIGGER_SECRET`. The Background Function
runs the orchestrator which talks to OSV and writes the
canonical baseline to the public-site's `tpr-baseline` Blob
store. The private gateway is a **separate** Netlify site that
**reads** the baseline via cross-site env vars.

## The canonical baseline

Five entity types: `vulnerability`, `advisory`, `package`,
`relationship`, `tombstone`. Each entity has a `canonicalId`
(format: `vuln:{osvId}`, `pkg:{ecosystem}:{nameLower}`,
`rel:{type}:{src}\u2192{dst}`, `tomb:{osvId}`, etc.). The
canonical content hash is `sha256:<hex>` of the canonical
JSON bytes (object keys sorted, entity arrays sorted by
`canonicalId`, non-entity arrays preserved in source order).

Buckets: 256 per entity type (`2 hex chars of
sha256(canonicalId)`). An incremental run only rewrites the
buckets affected by changed canonical IDs.

The publisher's atomicity guarantee: the latest pointer
`manifests/latest.json` is the single strongly-consistent
write. A reader that sees the new pointer can also find
the version manifest and (if any) the delta. A reader that
sees the old pointer still sees a consistent previous
version. Failed publication leaves the pointer unchanged.

## The orchestrator

`runOsvBackground` is the workhorse. It:

1. Reads the bootstrap state (a Blob-backed journal).
2. Reads the previous manifest from `manifests/latest.json`.
3. Captures the per-ecosystem resume cursor BEFORE
   `markRunStarted` resets the state, so a run killed by the
   15-minute ceiling is resumable.
4. For each allowlisted ecosystem, fetches the per-ecosystem
   `modified_id.csv` from OSV's GCS bucket and the individual
   vuln JSON files.
5. Normalizes each vuln to the five canonical entity types.
6. Plans per-bucket upserts.
7. Reads the previous shard for each affected bucket, applies
   the changes, and writes a new content-addressed shard. If
   the bucket's content hash is unchanged, the previous
   objectKey is reused.
8. Builds the new version manifest and (if a previous version
   exists) the delta. The delta's `targetManifestHash` matches
   the new manifest's `canonicalContentHash` exactly.
9. Publishes atomically: writes the version manifest, the
   delta, and finally the latest pointer.
10. Persists the bootstrap state with the new cursor.

The orchestrator returns `done: true` when the slice is
complete (or when there is no work to do) and `done: false`
when the time or record cap is hit; the caller re-invokes to
continue from the cursor.

## The private gateway

Five authenticated routes at `/private/v1/*`:

| Route                                        | Returns                                   |
| -------------------------------------------- | ----------------------------------------- |
| `GET /private/v1/manifest`                   | current manifest                          |
| `GET /private/v1/manifest/{version}`         | specific version manifest                 |
| `GET /private/v1/delta?from={v}&to={v}`      | publisher-signed delta                    |
| `GET /private/v1/shard?key={objectKey}`      | one gzipped shard                         |
| `GET /private/v1/snapshot?version={v}`      | one-shot full snapshot for offline use    |
| `GET /private/v1/sources`                    | source registry                           |

Authentication is HMAC-SHA256 of `keyId + ":" + randomSecret`
keyed by `THREATPULSE_CREDENTIAL_PEPPER`. The stored digest is
the raw HMAC output (no `sha256:` prefix, no extra wrapping).
The credential format is `tpr_<keyId>_<randomSecret>`. The
keyId character set is `A-Za-z0-9-` (deliberately excludes `_`
to keep the credential unambiguously parseable). Comparison
is constant-time. The credential and the pepper are never
logged or echoed in responses.

Rate limit (per amendment #5) is configured on the function's
`config` export, not in `netlify.toml`. Initial rule: 200
requests per 60s, aggregated by IP and domain. Per-client
hard quotas are deferred until an atomic counter store
exists.

## The reference consumer

`client/consumer-client.mjs` is a small Node.js ESM module
that authenticates to the private gateway, fetches the
current manifest, verifies its hash, and pulls only the
shards the local store doesn't already have. The default
`FsBaselineStore` writes to a directory; SQLite and Postgres
adapters satisfy the contract documented in
`client/contracts.md`.

The consumer is intentionally small — a reference
implementation, not a feature-complete sync engine. A real
product adds retries, exponential backoff, concurrent
fetches, a verification schedule, and an observability
surface. The reference keeps the surface area small so the
integration story is obvious.

## What V6.0 explicitly is NOT

- It is NOT a real-time push system. Consumers pull on their
  own schedule.
- It is NOT a multi-product "shared baseline service". The
  baseline is one product's data plane; cross-product use is
  out of scope for V6.0.
- It is NOT a STIX 2.1 interop layer. The manifest schema is
  the V6.0 schema; STIX is a deferred V6.1+ concern.
- It is NOT exposed on the public site. The only public
  surface is the V5.7 dashboard dataset, which is unchanged.
- It is NOT bypassable by anonymous callers. There is no
  anonymous function that reads the canonical baseline. The
  only way to read it is through the private gateway with a
  valid HMAC credential.

## Operational telemetry

- The bootstrap state Blob (`osv-bootstrap-state`) is the
  per-run journal. It records the active config hash, the
  per-ecosystem cursors, the recent-ids ring, and the last
  error per ecosystem.
- The Netlify function logs are the real-time signal. The
  background function logs one line per run with the
  iteration count, total records processed, publish count,
  and elapsed time.
- The version manifests are the audit trail. A consumer that
  wants to "see what was published when" reads the
  `manifests/versions/` directory.

## Further reading

- [`docs/deployment.md`](./deployment.md) — deploying the
  private gateway
- [`docs/credentials.md`](./credentials.md) — issuing,
  rotating, and revoking credentials
- [`docs/ecosystems.md`](./ecosystems.md) — managing the OSV
  ecosystem allowlist
- [`client/contracts.md`](../client/contracts.md) — the
  SQLite/Postgres adapter contract
- [`schemas/`](../schemas/) — the JSON Schemas for
  manifest, delta, baseline, and source-registry
