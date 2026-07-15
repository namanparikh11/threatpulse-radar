# V6.1 — Public Intelligence

This document describes the V6.1 public-intelligence
bundle: a separately versioned, server-side-only dataset
that the public dashboard reads on every request. The
bundle is independent of the V6.0 canonical baseline
(OSV) and the V5.2 public dataset (CISA KEV → NVD →
FIRST EPSS → CISA Vulnrichment → GitHub Advisory). The
public dashboard's surface is unchanged; the V6.1 bundle
is read by the existing public-read code path with a
single small Blob read per request.

## Topology

```
PUBLIC SITE                                  (one Netlify site; no new env vars)
  + netlify/functions/dataset.mjs            (existing function, EXTENDED)
    |- view=osv?version=...&cve=...           (new read mode)
    |- view=changes?version=...&category=...&limit=25
    +- default mode (no view)                  (existing V5.7 surface + V6.1 fields)
  + tpr-dataset/latest-dataset                (existing; carries datasetPublicHash)
  + tpr-vulnrichment/cache                    (existing; carries vulnrichmentPublicHash)
  + tpr-github-advisory/cache                 (existing; carries githubAdvisoryPublicHash)
  + tpr-public-intelligence/                  (NEW store; local-context read only)
      osv/
        versions/{osvProjectionVersion}/manifest.json
        shards/sha256/{bucketContentHash}.json.gz    (content-addressed; shared)
        latest.json
        publication-lock
      dataset/
        versions/{publicIntelligenceVersion}/
          manifest.json
          public-snapshot.json.gz
          source-health.json.gz
          changes.json.gz
        latest.json
        publication-lock
        change-summaries/{YYYY-MM-DD}.json
```

The private gateway subtree (`netlify/gateway/`) is
unchanged. The private gateway never reads
`tpr-public-intelligence`.

## Two-cadence publication

Two independently published artifacts, each with its
own store, lock, and `latest.json` atomic pointer:

1. **OSV public projection** (canonical cadence):
   runs as a sub-step of the V6.0 canonical baseline
   Background Function, after the atomic
   `tpr-baseline/manifests/latest.json` write. Hourly.

2. **Dataset-bound public-intelligence bundle** (dataset
   cadence): runs as a sub-step of the V5.2 dataset
   refresh Background Function, after the
   `latest-dataset` write and after the Vulnrichment and
   GitHub Advisory refresh passes. Every 30 min.

Neither pipeline writes the other's immutable artifacts.

## Version and compatibility

Every public-intelligence artifact is content-addressed.
A bundle is identified by its `publicStateHash` — a
collision-resistant composite hash of the four
currently-served state pieces (the dataset envelope's
public hash, the Vulnrichment cache's public hash, the
GitHub Advisory cache's public hash, and the referenced
OSV projection's version + content hash).

- `publicIntelligenceVersion = "<ISO minute>-<12 hex of publicStateHash>"`
- `osvProjectionVersion = "<canonicalBaselineVersion>-<12 hex of canonicalManifestHash>"`

A new bundle is published only when its `publicStateHash`
differs from the previous successful version (skip-
unchanged). A bundle version is also written when the
referenced OSV projection's `manifestContentHash`
changes. A bundle whose OSV projection version is no
longer the current OSV latest is considered stale and is
NOT attached to the public dataset.

## Skip-unchanged publication

When the new `publicStateHash` equals the previous
successful public-intelligence version's
`publicStateHash`, the publisher exits without writing
the manifest, the snapshot, the changes, or the
`latest.json` pointer. The previous `latest.json`
remains valid. The OSV publisher applies the same
skip-unchanged rule on the OSV manifest hash.

## Skip-unchanged OSV publication

When the new OSV manifest hash equals any retained
OSV version's manifest hash, the OSV publisher exits
without writing the new OSV `latest.json`. The
content-addressed shards are reused across versions
when their content hash is unchanged.

## Per-Blob internal public hash

Three precomputed public hashes are stored inside their
respective Blob envelopes as `INTERNAL_BLOB_FIELDS`-stripped
internal metadata:

- `tpr-dataset/latest-dataset` carries `datasetPublicHash`
- `tpr-vulnrichment/cache` carries `vulnrichmentPublicHash`
- `tpr-github-advisory/cache` carries `githubAdvisoryPublicHash`

The public request path reads both data and hash from the
same Blob read; no re-hashing on the read path. Pre-V6.1
Blobs without the internal hash metadata are treated as
`publicIntelligenceStatus: 'unavailable'`.

## Composite `publicStateHash`

```
publicStateHash = sha256(canonicalize({
  datasetPublicHash,
  vulnrichmentPublicHash,
  githubAdvisoryPublicHash,
  referencedOsvProjectionVersion,
  referencedOsvProjectionContentHash,
  publicProjectionSchemaVersion,
  publicStateSchemaVersion,
}))
```

A cache change (Vulnrichment or GitHub Advisory) →
`publicStateHash` change → new `publicIntelligenceVersion`.
A `fetchedAt`-only change → same `publicStateHash` (the
timestamp is excluded from the hash).

## Source-health observations (not frozen state)

The V6.1 source-health payload persists ONLY observations:

- `lastSuccessfulFetchAt`
- `lastAttemptedFetchAt`
- `lastAttemptOutcome` (success / soft-partial / hard-failure)
- `usableCoverage` / `totalCoverage`
- `thresholdMinutes`
- `sanitizedReason`

The five public states (`unknown`, `fresh`, `partial`,
`stale`, `unavailable`) are derived at request time from
the observations. Time passing alone moves `fresh` to
`stale` without requiring a new bundle publication. A
hard failure after a usable observation matches `partial`
(with a sanitized warning), NOT `unavailable`. The
`unavailable` state is reserved for the case where no
successful observation exists AND a definitive hard
failure has been recorded.

## Change intelligence comparability

A classification axis is computed only when both
snapshots report the corresponding provider as
`comparable`. A hard-failure outcome WITHOUT a recorded
attempt is treated as `unknown` (defensive: the outcome
is inconsistent with the attempt log). The manifest
carries `comparableAxes` and `suppressedAxes` arrays; the
UI surfaces the suppression honestly.

## No-fabrication rule

When no provider axis is comparable in the CURRENT
snapshot (CISA KEV gating failed), the change items
array is empty and `partial: true` is set on the
manifest. The change intelligence step never claims a
change from a failed run.

## Retention

- **Current** (referenced by `latest.json`): always retained.
- **Previous** (one before current): always retained.
- **Rollback** (two before current): always retained.
- **Maximum 3 complete versions** per path (OSV, dataset).
- **Optional 48-hour aggregate change summaries** (small,
  ~1 KB each, no per-CVE data).
- GC is best-effort, never blocks publication, preserves
  last-known-good pointers on failure.

## Mark-and-sweep OSV shard GC

1. Identify the current, previous, and rollback OSV
   projection manifests.
2. Read the complete set of shard content hashes
   referenced by those retained manifests.
3. Mark every referenced hash as retained.
4. Enumerate candidate content-addressed shard objects.
5. Delete only shard objects that are not referenced by
   any retained manifest AND are not part of an
   in-progress publication.
6. Never delete based only on timestamp or age.
7. A GC failure must not fail publication or change
   `latest.json`.
8. `latest.json` must never reference a manifest whose
   shards have been deleted.

## Read-time cost

The default dashboard request reads at most one new small
Blob (`tpr-public-intelligence/dataset/latest.json`,
<32 KiB) plus its manifest (<16 KiB). The OSV drawer
mode reads one OSV shard (<256 KiB compressed) on
drawer open. The changes view mode reads one changes
blob (<256 KiB compressed) on filter activation. No
upstream provider call, no baseline rebuild.

## Five public-state surfaces

The public dataset endpoint exposes five V6.1 envelope
fields on the default response:

- `publicIntelligenceStatus`: `available` | `mismatch` | `unavailable`
- `publicIntelligenceVersion`: `string | null`
- `sources`: 6 source cards with derived state
- `changeSummary`: aggregate counts
- `comparableAxes` / `suppressedAxes`: provider-axis
  comparability metadata

The full `publicStateHash` is internal-only. A short
12-hex `publicStateFingerprint` may be included in the
response as a non-security diagnostic; it MUST NOT be
treated as a verification value.

## Per-CVE data (server-side only)

The per-CVE public comparison snapshot, the per-CVE
change items, the per-CVE source-health observations,
and the per-CVE OSV public projection are stored in
immutable, gzipped, server-side-only Blobs. The browser
NEVER parses them. The browser receives per-CVE data
ONLY through the validated `view=osv` and `view=changes`
query modes on the dataset function.

## Security and privacy

- No env-var name appears in any public response, any
  frontend bundle, or any generated document.
- No upstream provider fetch originates from the
  browser. The browser only reads the public
  dataset function.
- Official-source hyperlinks are rendered as
  `<a target="_blank" rel="noopener noreferrer">` and
  point to validated `https://` URLs only.
- The OSV `osvUrl` is constructed from the validated
  `osvId` (matching `/^[A-Za-z0-9._-]{1,128}$/`),
  not from any upstream-supplied URL.

## Standing rules preserved

- 5 public function entry files (the dataset function
  is extended, not replaced).
- 1 private-gateway function entry file.
- V5.7 CSV remains exactly 21 columns.
- No new table column, header pill, or combined score.
- No browser-originated provider requests.
- No Netlify environment variable changes.
- No private-gateway changes.
- No consumer-client changes.
