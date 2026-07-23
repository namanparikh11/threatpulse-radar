# V6.8 — Controlled deployment runbook

This runbook separates **preparation** (which can be
performed by the operator without further approval)
from **approval-gated actions** (which require explicit
human authorization before they are executed).

The release candidate is the V6.8 commit
`0480a9f414f9dd452191f99e07b94a505e6cb003` on the
`v6-8-release-candidate-consolidation` branch. The
preparation branch is `release/v6-8-deployment-preparation`.

The V6.8 release-candidate is **honest about what it
is and what it is not**. It is a single controlled
release of a defensive cybersecurity intelligence
product. It is NOT enterprise-certified, legally
admissible, complete, or independently audited.

## PHASE 0 — Current preparation (no approval required)

This phase documents what the operator can verify
before the approval-gated phases. None of these
actions trigger a production deployment.

1. **Verify RC commit.** `git rev-parse HEAD` must
   equal `0480a9f414f9dd452191f99e07b94a505e6cb003`.
2. **Verify clean branch.** `git status --short` must
   be empty.
3. **Run every acceptance suite.** `for f in
   scripts/acceptance*.mjs; do node "$f"; done` must
   exit 0 for every suite.
4. **Run the production build.** `npm run build` must
   exit 0 and the `dist/` directory must contain the
   documented chunks.
5. **Run the release preflight.** `node
   scripts/verify-v68-release.mjs` must exit 0 and
   report no defects.
6. **Run the local smoke test.** `node
   scripts/smoke-v68-local.mjs` must exit 0 and
   round-trip a record through the filesystem
   adapter.
7. **Confirm the production smoke dry-run.** `node
   scripts/smoke-v68-production.mjs` must exit 0 and
   list every planned check.
8. **Confirm Netlify credit balance / reset.** Review
   the production site's Netlify credit balance. The
   V6.8 release does NOT change the credit envelope.
9. **Confirm password-manager backup.** Ensure the
   production environment variable values and the
   `THREATPULSE_CREDENTIAL_PEPPER` are backed up in a
   password manager accessible to the operator.
10. **Inspect environment-variable names.** Review
    `docs/v6-8-environment-checklist.md` and confirm
    the documented names match the Netlify UI labels.
11. **Inspect public + gateway project configuration.**
    Review the public and gateway `netlify.toml`
    files and the `package.json` scripts. Confirm the
    scheduled and background functions are wired to
    the right Netlify cron handlers.
12. **Take screenshots with all values masked.** For
    each Netlify UI screen that contains an
    environment variable value, take a screenshot
    and mask the value before sharing.

## PHASE 1 — Explicit user approval required (merge approval)

The following actions require explicit operator
approval. **Do not perform them as part of this
preparation task.**

1. **Create the release PR.** The operator opens a
   PR from `release/v6-8-deployment-preparation` to
   `main` and requests review.
2. **Review the complete diff.** The operator
   confirms the diff is limited to:
   - `deploy/v6-8-release-manifest.json`
   - `scripts/verify-v68-release.mjs`
   - `scripts/smoke-v68-local.mjs`
   - `scripts/smoke-v68-production.mjs`
   - `docs/v6-8-*.md`
   No product, gateway, or client source code is
   modified.
3. **Approve the merge strategy.** The operator
   confirms the merge target is `main`.
4. **Approve the merge into main.** The operator
   merges the PR.

## PHASE 2 — Explicit user approval required (publishing approval)

The following actions require explicit operator
approval AND may require unlocking production
publishing in the Netlify UI. **Do not perform them
as part of this preparation task.**

1. **Configure or confirm production environment
   variables.** Use `docs/v6-8-environment-checklist.md`
   as the canonical name list. Verify every required
   variable is set on the public site and on the
   gateway site. Verify no variable is missing.
2. **Unlock production publishing if required.** The
   public site and the gateway site may require the
   operator to click "Unlock publishing" after a
   long idle period.
3. **Authorize the production deployment.** Once
   PHASE 1 and PHASE 2 are complete, the operator
   clicks "Deploy" in the Netlify UI for both sites.

## PHASE 3 — Deployment sequence (operator-driven)

Once PHASE 2 is complete, the operator runs the
following sequence. The sequence is the recommended
order; deviations must be explicitly justified.

1. **Confirm gateway variables are complete.** The
   `THREATPULSE_BASELINE_SITE_ID`,
   `THREATPULSE_BLOBS_ACCESS_TOKEN`, and
   `THREATPULSE_CREDENTIAL_PEPPER` are set on the
   gateway site.
2. **Deploy / verify the gateway as required by the
   chosen sequence.** If the gateway deploys first,
   confirm the gateway is reachable at the
   `gateway-url` base URL.
3. **Merge / deploy the public release.** The public
   site builds and publishes the Vite dashboard.
4. **Confirm exact function counts.** The public
   site exposes exactly 5 public functions and 0
   background functions out of the cron schedule
   (the schedule triggers the background functions
   in turn). The gateway site exposes exactly 1
   gateway function.
5. **Run production smoke tests.** `node
   scripts/smoke-v68-production.mjs --execute
   --public-url=<base> --gateway-url=<base>`. All
   checks must pass.
6. **Inspect sanitized logs.** Open the Netlify
   function logs for the public and gateway sites.
   Look for any unexpected errors, missing
   environment variables, or credential
   mismatches.
7. **Observe the first scheduled / background
   cycles.** Wait for the first scheduled run (or
   trigger a manual refresh) and confirm the
   background functions complete without errors.
8. **Verify the first OSV projection.** Open the
   `tpr-dataset` Blob store and confirm the first
   OSV projection is published.
9. **Verify the first dataset-bound publication.**
   Open the `tpr-vulnrichment` Blob store and confirm
   the first dataset-bound publication is in place.
10. **Verify the first-run change behavior.** Open
    the dashboard, confirm the "What changed" panel
    reports no fabricated previous-version changes.
11. **Verify the public / private isolation.** From a
    private browser session, attempt to access the
    `private-sync-gateway` function on the public
    site. The public site must return 404 for the
    gateway path. From an anonymous context, attempt
    to call the gateway function on the gateway
    site. The gateway must return 401.

## What is NOT done by this runbook

- This runbook does NOT unlock production
  publishing.
- This runbook does NOT merge any branch into
  `main`.
- This runbook does NOT deploy any code.
- This runbook does NOT change any environment
  variable on any production site.
- This runbook does NOT call Netlify, Hostinger, or
  any provider.
- This runbook does NOT include any actual
  environment-variable value.

## Hostinger Business managed-Node scheduler (optional)

The Hostinger Business managed-Node application
plan does NOT expose Cron Jobs in the operator
dashboard and the ordinary SSH shell does not
expose `node` or `npm`. The standalone
`hostinger/cron-*.mjs` entrypoints therefore cannot
be launched directly on a managed Business-hosting
deployment.

For managed-hosting deployments, the application
ships an opt-in **in-process scheduler** that runs
inside the same Node process as the HTTP server:

- Enable with `THREATPULSE_MANAGED_SCHEDULER=1`.
- Optional bootstrap with
  `THREATPULSE_MANAGED_SCHEDULER_BOOTSTRAP=1`.
- The scheduler reuses the existing
  `hostinger/cron-*.mjs` job implementations and the
  existing `hostinger/locks.mjs` mkdir-based locks.
  No provider, storage, publication or
  canonicalization logic is duplicated.
- Timers are process-local. Cross-process exclusion
  is provided by the existing mkdir-based cron
  locks; multiple managed processes cannot
  concurrently mutate the same job state.
- The scheduler does NOT add a public HTTP trigger
  route. The bootstrap, when enabled, inspects the
  dataset on the local filesystem only.
- A process restart is safe: the scheduler starts
  again from the next calculated UTC occurrence,
  the bootstrap is retried when the dataset is
  missing, and the existing locks prevent duplicate
  active jobs.
- The standalone `hostinger/cron-*.mjs` entrypoints
  remain available for VPS deployments and for
  operator-run ad-hoc schedules. The managed
  scheduler is an additive compatibility layer, not
  a replacement.

### Child-process executable (process.execPath)

Every scheduled child process is spawned with
`process.execPath` as the executable — NOT the bare
string `node`. The Hostinger managed-Node
application dashboard starts `hostinger/app.mjs`
with a known Node executable, but the same PATH is
NOT propagated to subsequent `child_process.spawn`
calls. A bare `spawn("node", ...)` therefore fails
with `ENOENT` because `node` is not on the
child-process PATH.

`process.execPath` is the absolute path of the
currently running Node executable and does not
depend on PATH. It matches the runtime version and
is always present. The `execPath` and `spawnApi`
parameters in `hostinger/cron-spawn.mjs` are
TEST-ONLY injection points; production leaves both
undefined.

Standalone environments (VPS, Docker, dev
workstations) keep working because the bare
`node` is on PATH there; the change to
`process.execPath` is also safe on those
environments because `process.execPath` is the
executable that started the current process.

### Observed deployment blocker

On the production-style Hostinger temporary
deployment the bare-spawn hotfix was required. The
runtime logged both `spawn` and `ENOENT` for every
scheduled dataset-refresh and dataset-publish,
while the HTTP server (`/health`, `/ready`,
`/api/dataset`) continued to respond.

### Future failure mode

A later `EPERM` or `EACCES` spawn failure (instead
of `ENOENT`) would indicate that Hostinger prohibits
child processes entirely. In that case the scheduled
jobs would have to be re-implemented as in-process
job adapters (calling the underlying job functions
directly without spawn). The current hotfix does
NOT cover that scenario.

## Filesystem intelligence-store parity (Hostinger)

On a Hostinger Business managed-Node deployment with
`THREATPULSE_STORAGE_BACKEND=filesystem`, every Blob
namespace the public pipeline depends on must be
reachable through the filesystem storage adapter.
Three observed deployment findings were the result
of a single root cause: the `getDatasetStore`,
`getVulnrichmentStore`, `getGithubAdvisoryStore`, and
`getPublicIntelligenceStore` helpers hardcoded the
`'netlify'` adapter, so every cache write and every
public-intelligence read returned an unusable handle
on a Hostinger runtime that has no Netlify Blobs
context.

The fix routes the four `get*Store` helpers through
`THREATPULSE_STORAGE_BACKEND` exactly the same way
`server/config.mjs` and `jobs/_lib.mjs#resolveStorage`
already do. The Netlify path is preserved unchanged
for backward compatibility. The filesystem path
returns a `FilesystemStorageAdapter` rooted at
`$THREATPULSE_DATA_ROOT/{storeName}` with the same
`get / set / setJSON / getJSON / setBinary /
list / delete` surface the call sites already use.

Filesystem layout (one subdirectory per store, all
under the same `THREATPULSE_DATA_ROOT`):

- `tpr-dataset/` — primary dataset envelope,
  refresh lock, NVD cooldown.
- `tpr-vulnrichment/` — CISA Vulnrichment / SSVC
  cache.
- `tpr-github-advisory/` — GitHub Advisory Database
  cache.
- `tpr-public-intelligence/` — V6.1 public-intelligence
  OSV + dataset versioned artifacts, `latest.json`
  pointers, publication locks, change-summaries.

Atomicity + last-known-good: every filesystem write
uses a temp file + rename; a failed write leaves the
previous valid object intact. The adapter rejects
path-traversal, NUL bytes, backslashes, and symlink
escape at the write boundary. The V6.1 size budgets
(`PUBLIC_SNAPSHOT_HARD_CEILING_UNCOMPRESSED_BYTES`,
`OSV_SHARD_HARD_CEILING_*`, etc.) and the
last-known-good write contract are preserved
unchanged. A dataset that exceeds the public-snapshot
ceiling is a structured skip; the previous
`dataset/latest.json` is preserved.

NVD 429 is preserved as a transient condition: the
refresh orchestrator keeps the previous better
envelope, records an NVD cooldown marker, and the
primary CISA KEV dataset remains serviceable. The
response truthfully reports partial enrichment.

Netlify remains the rollback path until the
observation period ends: an operator can flip
`THREATPULSE_STORAGE_BACKEND` back to `netlify` and
the same code path serves both backends.

## Hostinger dataset-route compatibility alias (frozen frontend)

The frozen V6.8 frontend hardcodes three URLs that
begin with `/.netlify/functions/dataset`:

- the live-data proxy (`fetchVulnerabilities`),
- the per-CVE OSV view (`?view=osv&...`),
- the per-category change panel (`?view=changes&...`).

On a Hostinger Business managed-Node deployment the
canonical route is `/api/dataset`; the alias
`/.netlify/functions/dataset` is a read-only HTTP
compatibility path that forwards to the same
portable `handleDataset` implementation. The alias is
NOT a Netlify Function. On Hostinger it is a plain
HTTP route handled by the portable Node server. No
Netlify runtime is invoked; no credential is required.

The alias is a thin pass-through: it calls the same
`handleDataset(req, { config: portable })` and writes
the same response. POST / PUT / PATCH / DELETE on the
alias return `405` (the upstream method allowlist is
unchanged). Any other `/.netlify/functions/{name}` path
is served an honest `404` so the SPA shell does not
masquerade as a refresh endpoint.

The alias exposes no write, refresh, publication,
backup, GC, or verification action. The managed
Hostinger scheduler
(`THREATPULSE_MANAGED_SCHEDULER=1`) remains the only
Hostinger refresh mechanism. The permanent refresh
cycle, the manual retry path, the per-CVE OSV view,
and the per-category change panel all reach the same
portable `handleDataset` implementation through the
alias without ever touching the filesystem data root
or the lock directory.

Future cleanup: the alias exists only because the
frozen V6.8 frontend still uses the Netlify path. A
follow-up can migrate the frontend to a
provider-neutral endpoint and remove the alias. Until
then, both paths resolve to the same `handleDataset`
implementation and produce identical response bodies.

## Hostinger public-snapshot size boundary (deterministic sharding)

Production data — the full CISA KEV universe, roughly
1,200 CVEs — produces a logical public-comparison
snapshot of ~1.1 MB uncompressed. That is about 74
KiB above the V6.1 `PUBLIC_SNAPSHOT_HARD_CEILING_UNCOMPRESSED_BYTES`
(1 MiB) per-object safety ceiling. The deployment
surfaces this as:

```
lastV61DatasetBoundRefresh:
  { skipped: true,
    reason: 'publish-threw',
    error: 'public-snapshot uncompressed size 1124204 exceeds ceiling 1048576' }
```

…and `publicIntelligenceStatus: 'unavailable'`. The
fix is a bounded storage/publication scalability
correction. The 1 MiB safety ceiling is preserved
unchanged; the logical snapshot is split into
deterministic content-addressed shards.

### What is preserved

- The 1 MiB per-object safety ceiling
  (`PUBLIC_SNAPSHOT_HARD_CEILING_UNCOMPRESSED_BYTES`)
  is unchanged. The ceiling is NOT raised, NOT
  removed, and NOT silently bypassed.
- No field of the per-CVE record is silently
  truncated. The partitioner moves WHOLE records
  between shards; a single CVE's record is never
  split across shards.
- No field of the per-CVE record is silently
  dropped. The reassembled logical snapshot is
  byte-equivalent (canonical-hash-equal) to the
  original logical snapshot. The reader's logical
  content hash check rejects the read on any
  deviation.
- No silent provider switch. The sharding is a pure
  function of the logical snapshot. The same logical
  snapshot always produces the same shard layout and
  the same content hashes. The storage backend
  remains the same (Netlify Blobs or filesystem).

### What changes

- `datasetBoundPublish` partitions the logical
  snapshot into N deterministic shards; each shard
  is gzipped and written under
  `tpr-public-intelligence/dataset/shards/sha256/<hash>.json.gz`
  (the OSV projection uses the same content-addressed
  shape; the dataset snapshot now follows the same
  pattern).
- A per-version shard manifest is written at
  `tpr-public-intelligence/dataset/versions/{v}/snapshot-shards-manifest.json`.
  The manifest is the per-version pointer to the
  shards.
- The atomic `dataset/latest.json` pointer gains
  two new fields: `snapshotShardsManifestContentHash`
  and `snapshotShardsCount`. The existing
  `publicStateHash` is preserved unchanged; the
  publicStateHash is computed from the four
  precomputed per-Blob hashes and is therefore
  independent of shard-boundary changes.
- A new read module
  (`netlify/functions/_shared/publicSnapshotShardRead.mjs`)
  reassembles the logical snapshot from the manifest
  + shards and verifies the logical content hash.
  The reassembled snapshot has the same shape as the
  original; the public response contract is
  unchanged.
- A new GC module
  (`netlify/functions/_shared/publicSnapshotShardGc.mjs`)
  performs mark-and-sweep GC on the shards. The
  current + previous + rollback manifests' shards are
  retained; orphan shards are removed. The currently
  referenced manifest and shards are never collected.

### Per-shard size budgets

- target: 192 KiB (uncompressed)
- per-shard hard ceiling: 768 KiB (uncompressed)
- per-shard compressed ceiling: 192 KiB
- per-object safety ceiling (unchanged): 1 MiB

The 768 KiB per-shard hard ceiling leaves 256 KiB
explicit headroom under the 1 MiB per-object safety
ceiling. Every stored shard is below the per-object
ceiling; the safety invariant is preserved.

### Atomicity and rollback

- Every shard is written atomically (temp file +
  rename on the filesystem adapter; equivalent
  semantics on Netlify Blobs).
- The per-version shard manifest is written AFTER
  every shard and BEFORE `dataset/latest.json`. A
  failed shard write or a failed manifest write
  preserves the previous `dataset/latest.json`
  byte-identical.
- The reader verifies shard existence, order, size
  and hash before reassembling. A missing or corrupt
  shard returns a structured failure
  (`{ ok: false, reason: 'missing-shard' }` or
  `reason: 'corrupt-shard'`) rather than serving a
  partial logical snapshot.
- The composite publicStateHash is stable across
  shard-boundary changes (it is computed from the
  four precomputed per-Blob hashes, not from the
  snapshot bytes). Changing only the shard
  boundaries does not change the logical
  fingerprint.

### NVD partial enrichment

The deployment also reported an NVD timeout /
partial enrichment. The existing V5.4.2 quality
guard classifies the failure as transient, preserves
the previous NVD-enriched envelope, and writes the
NVD cooldown marker. The main CISA KEV dataset is
serviceable without NVD enrichment; the response
truthfully reports partial enrichment. No aggressive
retry loop is added; the partial-enrichment state is
honestly surfaced.

### Operator verification during the next redeploy

1. `git log --oneline -1` on the
   `hostinger/v6-8-public-snapshot-size-boundary`
   branch shows the new sharding commit(s).
2. `git status --short` is empty after the
   redeploy.
3. `curl -fsS https://<hostinger>/api/dataset |
   jq` reports `publicIntelligenceStatus:
   "available"` (was `unavailable` before the
   redeploy), `publicIntelligenceVersion` non-null,
   `publicStateFingerprint` non-null.
4. `lastV61DatasetBoundRefresh.published === true`
   on the dataset envelope.
5. The dataset-bound bundle content is byte-equal
   to the previous valid bundle (no silent field
   drop).
6. The per-version directory contains
   `snapshot-shards-manifest.json` and at least one
   `dataset/shards/sha256/<hash>.json.gz`.
7. `dataset/latest.json` carries
   `snapshotShardsManifestContentHash` and
   `snapshotShardsCount` fields.
8. The full V6.3 Hostinger acceptance suite passes
   (425 tests, including the new section [20]
   public-snapshot size-boundary tests).
9. The full V6.1 dataset-bound snapshot acceptance
   suite passes (73 tests, updated for sharded
   storage).
10. No `logs/` or `state/` artifact is left in the
    repo root.
11. No new public HTTP route is introduced; the
    V6.3 dataset-route compatibility alias
    continues to be read-only.

## Hostinger final provider-neutral data-route label (presentation-only)

A separate
`hostinger/v6-8-final-provider-neutral-label` branch
replaces the user-visible "Proxy: Netlify" badge with a
provider-neutral delivery-route label. The dashboard now
reports the **delivery-route type** rather than the
hosting provider.

| State | Old badge | New badge |
| --- | --- | --- |
| `proxyStatus === 'proxy'` | `Proxy: Netlify` | `Data route: same-origin` |
| `proxyStatus === 'browser-direct'` | (no badge) | `Data route: direct` |
| `proxyStatus === 'unavailable'` | (no badge) | `Data route: unavailable` |

The dataset-store pill's accessibility text drops the
"Netlify Blobs" provider claim and references the
shared public-intelligence store instead. The Source,
NVD, EPSS, dataset-store, cache, and refresh pills are
preserved unchanged.

### What is preserved

- No public HTTP route is added or removed.
- `/.netlify/functions/dataset` continues to be a
  read-only compatibility alias on Hostinger.
- The API response contract (`FetchResult`,
  `proxyStatus`, `dataSource`, `cacheStatus`) is
  unchanged.
- The dataset-route alias behavior, the publication
  and sharding logic, the scheduler behavior, the
  filesystem storage, the public-intelligence
  schemas, the V6.1 size budgets, the 21-column
  public CSV, the 5 public Netlify function
  entries, and the 1 gateway function entry are all
  preserved unchanged.
- `client/**` and `netlify/gateway/**` are not
  modified.
- No Hostinger setting, environment variable,
  credential, DNS record, or deployment is triggered
  by this branch.

### Operator verification during the next redeploy

1. `git log --oneline -1` on the
   `hostinger/v6-8-final-provider-neutral-label`
   branch shows the new label commit.
2. `git status --short` is empty after the
   redeploy.
3. The header on the live dashboard shows
   `Data route: same-origin` (NOT `Proxy: Netlify`).
4. The dataset-store pill's tooltip text mentions
   the shared public-intelligence store, NOT
   `Netlify Blobs`.
5. The `proxy` / `browser-direct` / `unavailable`
   pill accessibility text is meaningful and
   provider-neutral on every state.
6. The full V6.3 Hostinger acceptance suite passes
   (425 tests).
7. The `acceptance-proxy` suite passes
   (121 tests, including the new provider-neutral
   assertions and the absence of "Netlify" /
   "Hostinger" in the user-visible data-route
   pills).
8. The preflight passes (25/25).
9. The build succeeds; the main bundle remains at
   the V6.8 RC size (±1 kB tolerance for the added
   accessibility text).
10. No `logs/` or `state/` artifact is left in the
    repo root.

Schedules (UTC):

- dataset refresh: minute 0 and 30 of every hour
- baseline refresh: minute 10 of every hour
- dataset publish: minute 20 and 50 of every hour
- public-intel GC: minute 25 of every hour
- state verify: 06:30 UTC daily
- backup: 02:40 UTC daily

The exact variable names are listed in
[`docs/v6-8-environment-checklist.md`](./v6-8-environment-checklist.md).
No values are documented in this runbook; only the
variable names.

## Approval matrix

| Action | Required role | Approval step |
| --- | --- | --- |
| PHASE 0 (preparation) | Operator | None (read-only verification) |
| PHASE 1 (merge approval) | Operator | Explicit click in Netlify UI |
| PHASE 2 (publishing approval) | Operator | Explicit click in Netlify UI |
| PHASE 3 (deployment) | Operator | Operator-driven per the sequence above |

## References

- `deploy/v6-8-release-manifest.json` — machine-readable
  release manifest
- `docs/v6-8-environment-checklist.md` — environment
  variable name list
- `docs/v6-8-rollback-plan.md` — rollback triggers
  and actions
- `docs/v6-8-production-observation-plan.md` —
  observation windows
- `docs/v6-8-release-candidate.md` — release
  candidate documentation
