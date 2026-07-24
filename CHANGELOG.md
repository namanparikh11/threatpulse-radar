# Changelog

Public version history for **ThreatPulse Radar**. Newest
entry first. Entries are concise; for design notes and the
audit findings behind each release, see

## V6.9 — Privacy, cookie audit, and security hardening

A documentation + hardening milestone. The audit found
zero cookies, zero non-essential storage, zero
third-party scripts / stylesheets / fonts / iframes and
zero analytics / tracking / pixels / beacons in the V6.8
build. The consent model is **A — no consent banner
required**.

Hardening:

- `Content-Security-Policy` generated from the actual
  build dependency graph. No `unsafe-eval`, no
  `unsafe-inline`, no wildcard origins, no broad
  `https:` fallbacks. `worker-src 'self' blob:` is
  required so Vite's runtime worker bootstrap is not
  blocked. Applied to every public response by
  `hostinger/static.mjs#applySecurityHeaders` and by
  `netlify.toml`.
- `X-Frame-Options: DENY` (was `SAMEORIGIN`) plus the
  equivalent `frame-ancestors 'none'` CSP directive.
- `Referrer-Policy: strict-origin-when-cross-origin`
  (was `same-origin`).
- `Permissions-Policy` denying every browser capability
  the dashboard does not actively use.
- `Strict-Transport-Security: max-age=31536000` with
  no `includeSubDomains` and no `preload`. The
  operator has not yet verified every subdomain is
  HTTPS-only, and HSTS preload is a one-way commitment.
- `Cross-Origin-Resource-Policy: same-origin` for
  every non-dataset public route.
- The CORS policy on `refresh-dataset-background.mjs`
  is tightened from `*` to `same-origin` because the
  route is an internal same-origin trigger; the
  `dataset.mjs` public-data endpoint retains the
  documented wildcard CORS.
- `hostinger/app.mjs` now pins every Node-side timeout
  explicitly: `headersTimeout=10s`, `requestTimeout=
  60s`, `keepAliveTimeout=5s`, `maxRequestsPer
  Connection=100`. The values are chosen to accommodate
  the largest legitimate request while bounding
  slow-loris and similar abuse.
- The `V6.3` hostinger acceptance suite is updated to
  assert the V6.9 header values explicitly.

Documentation:

- `docs/v6-9-privacy-cookie-and-security-hardening.md`
  is the full audit + decision record. It is the
  single source of truth for the V6.9 privacy /
  cookie / security posture.
- `SECURITY.md` is the public security policy,
  responsible-disclosure process, supported versions
  and out-of-scope categories.
- `public/.well-known/security.txt` is the RFC 9116
  contact file. Operator placeholders marked
  `<!-- OPERATOR: -->` must be replaced before the
  site is public-facing.
- `public/legal/index.html`, `public/legal/privacy.html`
  and `public/legal/cookies.html` are the user-facing
  disclosures. Operator placeholders are clearly
  marked.

Verification:

- `scripts/verify-v69-privacy-and-runtime-hardening.mjs`
  is a bounded 29-assertion suite that statically and
  locally audits the cookie / storage / third-party
  inventory, the security headers, the CORS policy,
  the V6.3 hostinger test assertions, the CSV, the
  gateway function entry, the route-handler error
  sanitization and the Node timeout caps. The script
  is read-only, source-and-dist only and does not
  contact the network.
- `scripts/verify-v68-release.mjs` is updated with
  the V6.9 branch's allow-list (hostinger/,
  netlify/functions/, public/legal/,
  public/.well-known/, SECURITY.md, netlify.toml) so
  the V6.9 working tree does not trip the
  release-preparation gate.
- The V6.3 hostinger suite is updated to assert the
  V6.9 header values explicitly (X-Frame-Options:
  DENY, Referrer-Policy: strict-origin-when-cross-
  origin, conservative HSTS, CSP set, Permissions-
  Policy set). 429/429 pass.

No code paths are weakened, no dependencies are
upgraded, no third-party consent-management service is
introduced.
[`README.md`](./README.md),
[`PORTFOLIO_WRITEUP.md`](./PORTFOLIO_WRITEUP.md), and
[`PUBLIC_RELEASE_CHECKLIST.md`](./PUBLIC_RELEASE_CHECKLIST.md).

## Mobile responsiveness — document-level overflow + action-toolbar wrap (additive)

A focused mobile responsiveness correction on the
`hostinger/v6-8-final-provider-neutral-label` branch.
At ~400 px viewport width the page produced a
horizontal scrollbar; the RemediationPanel bottom
toolbar and several table wrappers were not bounded
by `overflow-x-auto`. This patch wraps every wide
table in a bounded scrollable container, makes the
RemediationPanel bottom toolbar stack on mobile, and
fixes the legacy `lg lg:` typo in the Header h1.

- `src/components/Header.tsx` — fix the `lg lg:text-[2.4rem]`
  typo on the brand h1 (the duplicate `lg` was a
  silent no-op that prevented the documented
  `lg:` typography step from applying).
- `src/components/remediation/RemediationPanel.tsx` —
  the bottom toolbar (`flex items-center justify-between`)
  is changed to
  `flex flex-col gap-2 ... sm:flex-row sm:items-center sm:justify-between`
  so the long "All active (default) · local filter
  state is not stored in the URL" paragraph wraps
  below the "Clear all remediation data" button on
  narrow viewports.
- `src/components/workspace/WorkspacePanel.tsx` — the
  queue table wrapper is changed from
  `overflow-hidden` to `overflow-x-auto`; the table
  itself declares `min-w-[640px]` so the inner
  horizontal scroll kicks in below ~640 px.
- `src/components/environment/EnvironmentPanel.tsx`
  — the assets table wrapper is wrapped in
  `overflow-x-auto`; the table declares
  `min-w-[640px]`.
- `src/components/environment/CorrelationQueue.tsx` —
  the correlation table wrapper is wrapped in
  `overflow-x-auto`; the table declares
  `min-w-[640px]`.
- `src/components/reports/ReportHistoryDialog.tsx` —
  the scrollable wrapper combines `overflow-x-auto`
  with the existing `overflow-y-auto`; the table
  declares `min-w-[560px]`.
- `src/components/reports/ReportPreview.tsx` — both
  preview tables (KeyValueRows + Source provenance)
  are wrapped in `overflow-x-auto`; the provenance
  table declares `min-w-[480px]`.
- `src/components/reports/ReportVerifyDialog.tsx` —
  the diff table is wrapped in `overflow-x-auto`.
- `scripts/acceptance-v68-release-candidate.mjs` — new
  "V6.8: mobile responsiveness" test pins the
  document-level invariants: no `w-screen` or
  `100vw` in the product source, every wide
  `min-w-[…px]` is paired with an `overflow-x-auto`
  wrapper, the Header h1 typography scale is
  correct, the RemediationPanel bottom toolbar
  uses `flex-col sm:flex-row`, the Header status
  column uses `flex-wrap lg:flex-col`, the
  BulkActionBar uses `flex-wrap sm:flex-nowrap`,
  the WorkspacePanel uses `flex-wrap sm:flex-nowrap`
  on its header action toolbar, and all five
  bounded tables (Workspace queue, Environment
  assets, Correlation, Report history, Report
  preview / verify) are wrapped in
  `overflow-x-auto` with a `min-w-[…px]` floor.

Preserved invariants:

- Provider-neutral "Data route" label from
  `abb60b8` is intact.
- No "Proxy: Netlify" user-facing label.
- 5 public Netlify function entries, 1 gateway
  function entry, `CSV_COLUMNS` = 21.
- `client/**` and `netlify/gateway/**` are not
  modified.
- The 1 MiB per-object safety ceiling, the
  dataset-bound snapshot sharding, the
  filesystem storage layout, the managed
  scheduler, the dataset-route compatibility
  alias, the public-intelligence schemas, the
  37-suite count, and the V6.7 hash chain +
  atomic plan+ledger commit invariants are
  preserved.
- Desktop and tablet layouts are unchanged.
- The patch is presentation-only. No route,
  API contract, scheduler, storage, schema,
  gateway, credential, DNS, or environment
  variable is modified.

## Hostinger final provider-neutral data-route label (additive)

A separate `hostinger/v6-8-final-provider-neutral-label`
branch is the last hostinger hotfix in the V6.8 line. It
replaces the user-visible "Proxy: Netlify" badge with a
provider-neutral delivery-route label, so the dashboard
reports the route type ("same-origin", "direct",
"unavailable") rather than naming the hosting provider.

This is a presentation-only patch. No route, no API
contract, no scheduler, no storage behavior, no
sharding, no schema, no Netlify/Hostinger setting is
modified.

- `src/components/Header.tsx`: the single
  `proxyStatus === 'proxy'` block is replaced with
  three provider-neutral blocks:
    - `proxy`          → "Data route: same-origin"
    - `browser-direct` → "Data route: direct"
    - `unavailable`    → "Data route: unavailable"
  The dataset-store pill's accessibility text drops the
  "Netlify Blobs" provider claim and references the
  shared public-intelligence store instead. The Source,
  NVD, EPSS, dataset-store, cache, and refresh pills
  are preserved unchanged.
- `scripts/acceptance-proxy.mjs`: the legacy
  "Proxy: Netlify" assertions are replaced with
  provider-neutral assertions covering all three
  states, the absence of "Netlify" / "Hostinger" in
  the user-visible data-route pills, the per-state
  tone (`info` / `warn` / `warn`), the per-state
  accessibility text, and the preservation of the
  source / NVD / EPSS / dataset-store badges.
- `scripts/verify-v68-release.mjs`: the
  branch-aware clean-tree test also accepts the
  `hostinger/v6-8-final-provider-neutral-label`
  branch; `src/components/` is allowed on this
  branch only.

Preserved invariants:

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
  entries, and the 1 gateway function entry are
  all preserved unchanged.
- `client/**` and `netlify/gateway/**` are not
  modified.
- No Hostinger setting, environment variable,
  credential, DNS record, or deployment is
  triggered by this branch.


## Hostinger public-snapshot size-boundary fix (deterministic sharding)

A separate `hostinger/v6-8-public-snapshot-size-boundary`
branch resolves the V6.1 dataset-bound
`public-snapshot uncompressed size 1124204 exceeds
ceiling 1048576` failure on the production Hostinger
managed-Node deployment. The 1 MiB per-object safety
ceiling is preserved unchanged; the logical snapshot is
split into deterministic content-addressed shards.

- `netlify/functions/_shared/publicSnapshotShards.mjs`
  (new): the partitioner (`partitionSnapshotForShards`),
  the per-shard body builder (`buildSnapshotShard`),
  the per-version shard manifest builder
  (`buildSnapshotShardManifest`), the verifier
  (`verifySnapshotShardManifest`), and the reassembler
  (`reassembleSnapshotFromShards`). All functions are
  pure and deterministic.
- `netlify/functions/_shared/publicSnapshotShardRead.mjs`
  (new): the read path. Reads the per-version shard
  manifest, every referenced shard, verifies shard
  hashes, verifies the logical content hash, and
  reassembles the logical snapshot. Returns a
  structured result (never throws on a structured
  failure).
- `netlify/functions/_shared/publicSnapshotShardGc.mjs`
  (new): mark-and-sweep GC. Retains the current +
  previous + rollback shard manifests. Orphan shards
  are removed; the currently-referenced manifest and
  shards are never collected.
- `netlify/functions/_shared/datasetBoundPublish.mjs`:
  the dataset-bound publication now writes the
  logical snapshot as N deterministic shards (one
  gzipped content-addressed object per shard) plus a
  per-version shard manifest. The atomic
  `dataset/latest.json` pointer gains two new fields
  (`snapshotShardsManifestContentHash` and
  `snapshotShardsCount`); the existing
  `publicStateHash` is preserved unchanged. A failed
  shard or manifest write preserves the previous
  `latest.json` byte-identical.
- `netlify/functions/_shared/publicIntelligenceSize.mjs`:
  the public-snapshot size constants are annotated;
  the per-shard target, hard ceiling, and minimum
  CVEs-per-shard are added as documented constants.
- `netlify/functions/_shared/publicIntelligenceStore.mjs`:
  the per-version shard manifest key helper
  (`datasetSnapshotShardManifestKey`) and the
  content-addressed shard key helper
  (`datasetShardKey`) are added. The
  `DATASET_SHARDS_DIR` directory is documented.
- `scripts/verify-v68-release.mjs`: branch-aware
  clean-tree test also accepts the
  `hostinger/v6-8-public-snapshot-size-boundary`
  branch. The branch's `netlify/functions/_shared/`
  files are allowed (the same allowance the
  filesystem-intelligence-stores branch already has).
- `scripts/acceptance-dataset-bound-snapshots.mjs`:
  the section [6] and [11] tests are updated for the
  sharded storage layout. The total test count is
  preserved (the new sharded-shape assertions
  replace the old single-blob assertions).
- `scripts/acceptance-v63-hostinger.mjs`: extended
  with a new section [20] (≈ 50 tests) covering the
  sharded publication, the read/reassemble round
  trip, the GC, the atomic commit, the failed-write
  preservation, the corruption detection, the
  traversal rejection, the no-silent-field-drop
  invariant, the no-silent-provider-switch invariant,
  the logical-fingerprint stability, the HTTP
  regression on both routes, and the filesystem
  round trip. The total V6.3 suite count is now 425
  tests.

Preserved invariants (deliberately):

- The 1 MiB per-object safety ceiling
  (`PUBLIC_SNAPSHOT_HARD_CEILING_UNCOMPRESSED_BYTES`)
  is unchanged. The ceiling is NOT raised, NOT
  removed, and NOT silently bypassed.
- No field of the per-CVE record is silently
  truncated.
- No field of the per-CVE record is silently dropped.
- No silent provider switch. The sharding is a pure
  function of the logical snapshot; the same logical
  snapshot always produces the same shard layout and
  the same content hashes.
- The composite `publicStateHash` is computed from
  the four precomputed per-Blob hashes (dataset,
  Vulnrichment, GitHub Advisory, OSV manifest) — NOT
  from the snapshot bytes. Shard-boundary changes
  therefore CANNOT change the publicStateHash.
- The `client/**` and `netlify/gateway/**`
  byte-equivalence to `32a8a63` is preserved (no
  changes in either directory).
- The 21-column public CSV is preserved unchanged.
- The 5 public Netlify function entries are preserved
  unchanged.
- The 1 gateway function entry is preserved
  unchanged.
- No new public HTTP route is introduced; the
  read-only compatibility alias at
  `/.netlify/functions/dataset` continues to work.
- The V6.3 dataset-route compatibility alias
  continues to be read-only.
- The V6.7 hash chain, atomic plan+ledger commit,
  `validation-pending → failed-locally` transition
  rules, and 1 MiB file-fingerprint worker
  invariants are preserved.
- The V6.8 ErrorBoundary scope (local panels only),
  LocalDataCentre shape (per-dataset cards), and
  lazy-loading of the public dashboard are
  preserved.
- The V6.8 deployment-preparation release manifest
  contract is preserved (no values are added, no
  values are removed; the sharding is documented as
  an additive observation).

## Hostinger dataset-route compatibility alias

A separate `hostinger/v6-8-dataset-route-compatibility`
branch adds a read-only HTTP compatibility alias so the
frozen V6.8 frontend (which hardcodes three URLs
beginning with `/.netlify/functions/dataset`) can reach
the same portable `handleDataset` implementation on a
Hostinger Business managed-Node deployment.

- `hostinger/app.mjs`: the alias
  `/.netlify/functions/dataset` is added as a thin
  pass-through to the same `handleDataset(req, {
  config: portable })` call. POST / PUT / PATCH /
  DELETE on the alias return `405` (the upstream
  method allowlist is unchanged). Any other
  `/.netlify/functions/{name}` path is served an
  honest `404` so the SPA shell does not masquerade
  as a refresh endpoint. The alias is read-only; no
  write, refresh, publication, backup, GC, or
  verification action is reachable through it.
- `scripts/verify-v68-release.mjs`: branch-aware
  clean-tree test also accepts the
  `hostinger/v6-8-dataset-route-compatibility`
  branch.
- `scripts/acceptance-v63-hostinger.mjs`: extended
  with a new section [19] (29 tests) covering the
  alias. The total acceptance suite count remains
  37 — no new suite file is added.

Observed production state preserved:

- The alias exposes no public refresh endpoint; the
  managed Hostinger scheduler
  (`THREATPULSE_MANAGED_SCHEDULER=1`) remains the
  only Hostinger refresh mechanism.
- The SPA fallback does NOT intercept the dataset
  path; the alias is registered before the
  `serveStatic` call.
- Method restrictions are unchanged: GET and HEAD
  only on the alias, 405 for any other method.
- No dataset-building logic is duplicated. No
  Netlify runtime API is invoked. No credential is
  required.
- Future cleanup: the alias exists only because the
  frozen V6.8 frontend still uses the Netlify path.
  A follow-up can migrate the frontend to a
  provider-neutral endpoint and remove the alias.

## Hostinger filesystem intelligence-store parity fix

A separate `hostinger/v6-8-filesystem-intelligence-stores`
branch fixes three observed deployment findings on the
production-style Hostinger Business managed-Node
deployment:

  1. `lastVulnrichmentRefresh.status = failed`
     ("Failed to write Vulnrichment cache blob.")
  2. `lastGitHubAdvisoryRefresh.status = failed`
     ("Failed to write GitHub Advisory cache blob.")
  3. `lastV61DatasetBoundRefresh.status = skipped`
     ("public-intelligence-store-unavailable")

All three had the same root cause: the four
`get*Store` helpers (`getDatasetStore`,
`getVulnrichmentStore`, `getGithubAdvisoryStore`,
`getPublicIntelligenceStore`) hardcoded the
`'netlify'` adapter, so every cache write and every
public-intelligence read returned an unusable handle
on a Hostinger runtime that has no Netlify Blobs
context. The fix routes the four helpers through
`THREATPULSE_STORAGE_BACKEND` exactly the same way
`server/config.mjs` and `jobs/_lib.mjs#resolveStorage`
already do. The Netlify path is preserved unchanged
for backward compatibility.

- `netlify/functions/_shared/store.mjs`: every
  `get*Store` helper now reads
  `THREATPULSE_STORAGE_BACKEND` and routes through
  `createStorageAdapter`. When the backend is
  `'filesystem'`, a `FilesystemStorageAdapter` is
  constructed rooted at
  `$THREATPULSE_DATA_ROOT/{storeName}`. The default
  backend is still `'netlify'`.
- `netlify/functions/_shared/publicIntelligenceStore.mjs`:
  `getPublicIntelligenceStore` now uses
  `createStorageAdapter` (the portable
  `NetlifyBlobsStorageAdapter` on the Netlify path, the
  `FilesystemStorageAdapter` on the filesystem path).
  The direct `getStore` import from `@netlify/blobs`
  is removed.
- `scripts/verify-v68-release.mjs`: branch-aware
  allowlist widened to also accept the
  `hostinger/v6-8-filesystem-intelligence-stores`
  branch; on that branch the `netlify/functions/_shared/`
  prefix is permitted (the storage-adapter parity fix
  lives there).
- `scripts/acceptance-v63-hostinger.mjs`: extended
  with a new section [18] (39 tests) covering the
  filesystem-store parity. The total acceptance suite
  count remains 37 — no new suite file is added.

Observed production state preserved:

- V6.1 size budgets
  (`PUBLIC_SNAPSHOT_HARD_CEILING_UNCOMPRESSED_BYTES`,
  `OSV_SHARD_HARD_CEILING_*`, etc.) are unchanged. A
  dataset that exceeds the public-snapshot ceiling is
  a structured skip; the previous
  `dataset/latest.json` is preserved.
- The atomic temp+rename write contract is
  preserved; a failed write leaves the previous valid
  object intact.
- The NVD 429 partial-enrichment behavior is
  preserved as a transient condition.

NVD 429 is classified as transient and bounded by the
existing NVD cooldown marker. The primary CISA KEV
dataset remains serviceable without NVD enrichment;
the response truthfully reports partial enrichment.
No retry loop is introduced.

## Hostinger managed scheduler ENOENT hotfix

A separate `hostinger/v6-8-managed-scheduler-execpath`
branch fixes a deployment-time ENOENT observed on
the Hostinger Business managed-Node temporary
deployment. Every scheduled child process is now
spawned with `process.execPath` (the absolute path
of the currently running Node executable) instead
of the bare string `node`. The bare string failed
because the managed-Node runtime's PATH is not
propagated to `child_process.spawn`; the absolute
path of the running executable is always present.

- `hostinger/cron-spawn.mjs`: the production
  default for the child executable is
  `process.execPath`. The `execPath` and
  `spawnApi` parameters are TEST-ONLY injection
  points; an empty, missing, or shell-metachar
  injection is rejected with a sanitized
  `spawnError`. ENOENT, EACCES, and EPERM failures
  are now reported in a sanitized
  `spawnError` record on the result object —
  `code`, `spawnable`, `phase`, and
  `runtimeExecutable: "process.execPath"`. The
  absolute executable path is NEVER included.
- `hostinger/managed-scheduler.mjs`: forwards
  `options.execPath` and `options.spawnApi` to
  `spawnV62Job` so the test suite can inject a
  fake spawn. In production both are undefined and
  the spawner uses the managed-Node executable.
  The scheduler logs `managed-scheduler.spawn-failed`
  with the sanitized spawnError when a child
  could not be started.
- `scripts/verify-v68-release.mjs`: branch-aware
  allowlist now also accepts the
  `hostinger/v6-8-managed-scheduler-execpath`
  branch. Other branches still see the strict
  deployment-preparation allowlist.
- `scripts/acceptance-v63-hostinger.mjs`: extended
  with a new section [17] proving the
  `process.execPath` behavior end-to-end. Total
  acceptance suite count remains 37.

Observed deployment blocker: the runtime logged
both `spawn` and `ENOENT` for every scheduled
dataset-refresh and dataset-publish while the HTTP
server (`/health`, `/ready`, `/api/dataset`)
continued to respond.

Future failure mode: a later `EPERM` or `EACCES`
spawn failure would indicate that Hostinger
prohibits child processes entirely. In that case
the scheduled jobs would have to be re-implemented
as in-process job adapters. The current hotfix
does NOT cover that scenario.

## Hostinger Business managed-Node scheduler

A separate `hostinger/v6-8-managed-scheduler` branch
adds an opt-in in-process scheduler for Hostinger
Business managed-Node deployments that do not
expose an OS-level cron. The scheduler is disabled
by default and reuses the existing
`hostinger/cron-*.mjs` job implementations and the
existing `hostinger/locks.mjs` mkdir-based locks.
No provider, storage, publication, or
canonicalization logic is duplicated; the
standalone cron entrypoints remain available for
VPS deployments.

- `hostinger/cron-spawn.mjs` (new): the single
  source of truth for V6.2 job spawning, shared
  by every cron entrypoint and the managed
  scheduler.
- `hostinger/cron-runner.mjs`: extracted a
  `runJob` helper that does NOT install
  SIGINT/SIGTERM handlers by default, so the
  embedded scheduler can call it without taking
  over the application's signal lifecycle. The
  legacy `runCronJob` exit-on-signal contract is
  preserved for the standalone entrypoints.
- `hostinger/managed-scheduler.mjs` (new): the
  embedded scheduler. Accepts an injected clock
  and timer API for tests. Schedules every job by
  computing the next UTC occurrence and arming a
  single bounded `setTimeout`; reschedules
  exactly one timer after each execution. Never
  accumulates duplicate timers. Never calls
  `process.exit`.
- `hostinger/app.mjs`: starts the embedded
  scheduler after the HTTP server is listening
  when `THREATPULSE_MANAGED_SCHEDULER=1`, and
  calls `scheduler.stop()` during graceful
  shutdown with a bounded grace period for any
  in-flight job.
- `scripts/acceptance-v63-hostinger.mjs`:
  extended with 77 new tests covering the
  managed scheduler. The total acceptance suite
  count remains 37 — no new suite file is added.

The exact variable names are
`THREATPULSE_MANAGED_SCHEDULER` and
`THREATPULSE_MANAGED_SCHEDULER_BOOTSTRAP` (the
latter only meaningful when the former is `1`).
No values are documented in this changelog.

## V6.8 controlled deployment preparation

A separate `release/v6-8-deployment-preparation` branch
carries the V6.8 release-preparation tooling without
modifying the V6.8 product. The branch adds:

- `deploy/v6-8-release-manifest.json` — machine-readable
  release manifest (names only, no secret values).
- `scripts/verify-v68-release.mjs` — read-only release
  preflight (exits 0 on success).
- `scripts/smoke-v68-local.mjs` — local smoke test
  (filesystem adapter, worker modules, IndexedDB
  adapters, cron-lock helper, temporary directories).
- `scripts/smoke-v68-production.mjs` — production
  smoke test (dry-run by default; `--execute` is
  required for network access).
- `scripts/acceptance-v68-deployment-preparation.mjs`
  — release-preparation acceptance suite.
- `docs/v6-8-controlled-deployment-runbook.md` —
  phased deployment procedure (PHASE 0 / 1 / 2 / 3).
- `docs/v6-8-rollback-plan.md` — rollback triggers and
  reversible actions.
- `docs/v6-8-production-observation-plan.md` —
  observation windows (30 minutes / 6 hours / 24-48
  hours) and release statuses.
- `docs/v6-8-environment-checklist.md` — every
  environment variable name with classification
  (public / gateway, required / optional, sensitive,
  source, rotation impact, redeploy matrix).
- `docs/v6-8-deployment-cost-controls.md` — operational
  best practices to minimize deployment and runtime
  credit use.

The preparation branch is honest about what it is.
The release is **not** enterprise-certified, legally
admissible, complete, or independently audited. No
claim of production stability is made before the
observation windows complete.

**Preparation-branch commit history (5 commits on top
of the V6.8 RC `0480a9f`):** the three planned
logical commits (`6531ada` manifest + preflight +
smokes, `0698d12` runbooks, `5dda6f7` acceptance
suite + docs) plus two bounded verification
corrections (`43ea1ca` loosen the V6.8
release-candidate suite count to `>= 36` for
forward-compat, `557023f` allow the V6.8
release-candidate acceptance suite in the
deployment-preparation branch's product-source
diff). The V6.8 release-candidate baseline carried
36 acceptance suites; the deployment-preparation
branch carries 37 (the V6.8 deployment-preparation
acceptance suite).

## V6.8 — Release candidate consolidation

V6.8 is a release-candidate consolidation milestone. It
contains the complete V6.1–V6.8 product and focuses on
stabilizing, measuring, lazy-loading, and documenting the
existing surfaces rather than introducing a new major
subsystem.

**This release is honest about what it is and what it
is not. It is a single controlled release of a defensive
cybersecurity intelligence product. It is NOT
enterprise-certified, legally admissible, complete, or
independently audited.**

### What this release adds

- **Release diagnostics.** A sanitized local storage
  diagnostics snapshot that reports storage
  availability, schema versions, record counts, and
  pending-write state. Never includes note, tag,
  owner, plan, task, evidence, or fingerprint
  content.
- **Hardened V6.4 multi-tab upgrade.** The workspace
  IndexedDB adapter now closes on `onversionchange`
  for parity with the V6.6 environment and V6.7
  remediation adapters.
- **Reusable `ErrorBoundary`.** A bounded React
  error boundary that isolates a workspace /
  reports / environment / remediation / data
  centre failure from the public dashboard.
- **Local Data Control Centre.** A single compact
  surface that summarizes every local-only dataset
  (workspace, environment, remediation, report
  history) and exposes per-dataset export and clear
  actions. Every destructive action is gated by an
  accessible confirmation dialog. Datasets are
  independent; clearing one never touches another.
- **First-run guide.** A compact, collapsible
  surface that surfaces the minimal first-use steps
  the operator needs to understand ThreatPulse
  Radar.
- **Lazy-loaded report / environment / remediation
  panels.** The V6.8 main bundle is ~16% smaller
  than the V6.7 main bundle; the report builder,
  report history, report verify/compare, the
  environment panel, and the remediation panel are
  emitted as separate chunks that the dashboard
  only pays for when the operator opens them.
- **End-to-end release-candidate acceptance suite.**
  `scripts/acceptance-v68-release-candidate.mjs`
  exercises the five documented journeys, local
  data separation, migration + recovery, privacy
  instrumentation, structural invariants, and the
  no-Node-hashing / no-`process.exit(0)` invariants.
- **Comprehensive release-candidate documentation.**
  `docs/v6-8-release-candidate.md` documents the
  full product capability map, the public vs
  local-only data boundary, supported providers and
  import formats, the workspace / reporting /
  environment / remediation capabilities and
  limitations, browser persistence limitations,
  backup requirements, Netlify + Hostinger
  deployment architecture, known dependency
  advisories, known deferred work, the release
  verification checklist, and rollback /
  checkpoint information.

### What this release does **not** do

- Add accounts, authentication, cloud sync, active
  scanning, registry calls, or proprietary scoring.
- Introduce a new provider integration.
- Introduce a new major product subsystem.
- Modify `netlify/gateway/`, `client/`, or the
  documented invariants.
- Modify the V6.5 report contract; the public CSV
  columns remain 21.

## V6.7 — Local remediation plans, evidence, and activity ledger

V6.7 adds a local-only remediation workflow layer to ThreatPulse
Radar. The operator can create a remediation plan for a CVE,
correlation, asset, or component; decompose the plan into ordered
tasks; record local owner labels and due dates; attach nine kinds
of evidence; fingerprint a local evidence file with a Web Worker
that never uploads the bytes; walk the plan through a documented
nine-state lifecycle machine; record a local validation result;
reopen a completed or accepted-risk plan; export and re-import
integrity-checked plan bundles; and inspect a per-plan
append-only hash-chained activity ledger.

**All plan, task, evidence, owner-label, due-date, validation,
and ledger data is local browser data. Nothing is uploaded. The
system NEVER claims a locally recorded completion is an external
verification, that a matching fingerprint proves authorship or
authenticity, or that the local ledger has any legal or
identity-significance.**

See [`docs/v6-7-local-remediation-evidence.md`](./docs/v6-7-local-remediation-evidence.md)
for the full design notes.

### What this release adds

- **Remediation schemas (1.0.0).** Plan, task, evidence, and
  ledger event records with strict validation, deterministic
  migrations, field limits, and CVE / tag normalization.
  Nine plan statuses, ten remediation types, five priorities,
  six validation statuses, five task statuses, nine evidence
  types, four evidence validation outcomes, fifteen ledger event
  types.
- **Lifecycle state machine.** `isSupportedTransition`,
  `checkTransition`, `isTerminalStatus`, `isActiveStatus`,
  `allowedTransitionsFrom`, `actionableTransitionsFrom`. The
  `validation-pending → failed-locally` shortcut is intentionally
  not allowed; failure re-enters `in-progress` so the operator
  can update tasks / evidence.
- **Append-only activity ledger.** Web Crypto SHA-256
  `sha256:` + lowercase hex over the canonical JSON of the event
  with `eventHash` stripped. `previousEventHash` is `null` for
  the genesis event and equals the prior event's `eventHash`
  otherwise. Sequences are contiguous. `verifyChain` detects
  modified, missing, reordered, and inserted events.
- **Local file fingerprinting.** Web Worker
  (`fingerprint.worker.mjs`) with chunked 1 MiB progress,
  cancellation, transferable buffer, 25 MiB cap, and Web Crypto
  SHA-256 only. The dispatcher exposes `startFingerprintJob` and
  `startVerifyJob` with a sync fallback when `Worker` is not
  available.
- **IndexedDB remediation adapter.** New database
  `threatpulse-remediation` v1 with five stores (plans, tasks,
  evidence, ledger, meta), `onversionchange` handler,
  BroadcastChannel `threatpulse:remediation:events` for multi-tab
  sync, and atomic plan + ledger commits via
  `transaction.createPlanWithGenesisEvent` /
  `transaction.appendFollowupEvent`.
- **Remediation context** with `flushPendingWrites` and
  `hasPendingWrites` for the report pipeline.
- **Dashboard remediation panel** with count cards (Active,
  Draft, Planned, In progress, Blocked, Overdue, Validation
  pending, Completed, Accepted risk, Archived, Broken-ledger),
  per-plan Export, and a "Clear all remediation data" action.
- **Plan builder, task dialog, evidence dialog, fingerprint
  dialog, plan detail, plan list.** All keyboard-accessible,
  focus-trapping, mobile-safe, reduced-motion aware.
- **Drawer, environment, correlation, and table integration.**
  Local remediation status pill in the vulnerability table.
  Per-CVE "Create plan" and "Open plan" actions in the
  detail drawer. "Create plan" link in the correlation queue
  with auto-populated CVE, asset, component, and correlation
  ids.
- **Export / import format `threatpulse-local-remediation`
  v1.0.0.** SHA-256 integrity-checked JSON bundle. Dry-run,
  merge, and replace modes. Atomic ledger conflict detection
  (same `eventId` with a different `eventHash` is a hard
  failure). Maximum bundle size 25 MiB.
- **Narrow additive report boundary.** Optional
  `localRemediationSummary` field on V6.5 reports; **excluded by
  default**; counts only; never includes owner labels, plan /
  task / evidence content, fingerprints, blocker reasons,
  validation notes, or actor labels. The public CSV (21
  columns) is unchanged.
- **Privacy instrumentation.** Sentinel-based test coverage for
  no fetch, no XHR, no `sendBeacon`, no `history.pushState` /
  `replaceState`, and no console output of plan / task /
  evidence / owner / fingerprint / validation / actor content
  during the workflow.
- **V6.6 lesson preserved.** No `process.exit(0)` in the
  acceptance suite. Unconditional `BroadcastChannel` no-op
  shim before any module import. Web Crypto only — no
  `node:crypto` in any browser-reachable module. No
  `sha256Node` chunk in the Vite build.

### What this release does **not** do

- Add accounts, login, cloud sync, or server-side profiles.
- Touch the public vulnerability corpus.
- Call package or provider APIs from the browser.
- Introduce a proprietary remediation, exposure, or risk score.
- Claim that a recorded completion is an external verification.
- Claim that a fingerprint match proves authorship or legal
  authenticity.
- Use `node:crypto` in any browser-reachable module.
- Modify the V6.5 report contract; the public CSV columns
  remain 21.
- Modify `netlify/gateway/`, `client/`, or the documented
  invariants.

## V6.6 — Local asset, SBOM, and exposure mapping

V6.6 adds a local-only environment relevance layer to ThreatPulse
Radar. The operator can register local assets, import supported
SBOM / software-inventory files (CycloneDX 1.4 / 1.5 / 1.6 JSON,
SPDX 2.3 JSON, ThreatPulse inventory JSON, bounded CSV), identify
components, correlate with public OSV + GitHub Advisory package
data, distinguish reliable affected-range matches from ambiguous
identity-only matches, review / dismiss local correlations, filter
the public vulnerability table by local relevance, and view
potentially affected local assets from the CVE detail drawer.

**All asset / SBOM / package / mapping / user-review data is local
browser data. Nothing is uploaded. The system NEVER claims a
correlation proves exploitability, compromise, or practical
exploitability.**

### What this release adds

- **My Environment panel.** Count cards (Assets, Inventories,
  Components, Correlations, Awaiting review), asset list,
  correlation queue, import / export / clear controls. Mounted
  between the change-intel panel and Defender Views.
- **Local asset + inventory + correlation + review schemas.** All
  fields length-bounded; non-finite numbers rejected;
  prototype-pollution keys (`__proto__` / `prototype` /
  `constructor`) rejected by every validator; future schema
  versions rejected; deep-freeze on success. Six correlation
  states + eight review statuses (documented in
  `docs/v6-6-local-environment.md`).
- **Importers.** CycloneDX 1.4 / 1.5 / 1.6, SPDX 2.3, ThreatPulse
  inventory JSON, bounded CSV (formula-like values rejected).
  Raw SBOM payloads are never retained; only the minimal
  documented component fields are kept.
- **Correlation engine.** Deterministic FNV-1a `correlationId`,
  purl > ecosystem+namespace+name > name-only precedence,
  ecosystem normalization (so `'crates.io'` / `'cargo'` /
  `'crates'` all collapse to `'crates'` for both sides), npm
  semver + crates + packagist evaluators with pre-release
  handling, default exact-only for PyPI / Maven / Go / NuGet.
  `mergeBest` joins OSV + GHSA results with separate
  `providerSources` array.
- **Drawer "Potential local relevance" section.** Per-state count
  chips, matching local assets + components with current review
  status, per-correlation Dismiss action.
- **Table local-relevance filter.** Seven-position filter
  (`any` / `potentially-relevant` / `affected-range` /
  `exact-version` / `identity-only` / `version-not-evaluable` /
  `no-local-data`). Held in `useState` — NEVER serialized to
  URL, NEVER in CSV, NEVER in Defender Views / What Changed.
- **Export / import / restore.** `threatpulse-local-environment`
  v1.0.0 format, SHA-256 over canonical JSON, atomic merge /
  replace with rollback on failure, prototype-pollution +
  future-schema + wrong-format rejected, no credentials / device
  ids in the payload. Public-safe filename
  `threatpulse-environment-{shortId}-{YYYY-MM-DD}.json`.
- **Narrow report integration boundary.** V6.5 reports gain an
  OPTIONAL additive `localEnvironmentSummary` field
  (counts only — no asset names, paths, owner labels, or review
  notes). Default V6.5 reports carry no environment data.
- **Worker dispatch.** `parseInventory.worker-*.js` and
  `correlate.worker-*.js` emitted as separate Vite chunks.
  Main-thread synchronous fallback for older browsers and the
  Node test runner (identical progress / cancellation path).
  Worker has no network access.
- **Three storage adapters.** `IndexedDBEnvironmentAdapter`
  (`persistent`, BroadcastChannel multi-tab sync,
  `onversionchange` handler, atomic inventory promotion);
  `InMemoryEnvironmentAdapter` (`session-only`, test runner);
  `UnavailableEnvironmentAdapter` (no-op with prominent UI
  warning).
- **Acceptance suite.** 47 tests covering schema, normalization,
  parsing, evaluators, correlation, inventory change, adapters,
  export/import integrity, dispatcher, privacy instrumentation,
  hash determinism.

### Preserved invariants

- 5 public Netlify function entries
- 1 gateway function entry (`netlify/gateway/src/private-sync-gateway.mjs`,
  byte-identical to `32a8a63`)
- `netlify/gateway/` + `client/` byte-identical to `32a8a63`
- `CSV_COLUMNS` = 21
- No accounts, no cloud sync, no scanning, no proprietary score
- Vite browser build: no `node:crypto` externalization warning

### V6.5 changes surfaced in the changelog

V6.5 (Local Briefings and Reports) was previously documented in
`docs/v6-5-local-briefings-and-reports.md` and the README but
did not have a top-level changelog entry. V6.5 added:

- **Five report types** (`defender-daily-briefing`,
  `local-triage-queue`, `selected-cve`, `change-briefing`,
  `executive-summary`) + **five redaction modes** (`none`,
  `exclude-private-notes`, `exclude-local-tags`,
  `exclude-all-user-text`, `identifiers-only`).
- **Coherent snapshot model** — public intelligence + selected
  CVE records + flushed workspace writes captured before
  generation; generation runs only from the frozen snapshot.
- **SHA-256 integrity** over canonical report bytes
  (`sha256:` + 64 hex). Browser uses `crypto.subtle.digest`;
  test runner uses Node `crypto` via composed specifier.
- **Verification + comparison** — `verifyJson` + `compareReports`
  refuse corrupt / integrity-failed inputs. Comparison never
  interprets absence as remediation.
- **IndexedDB history** (capped at 100 entries) — summary only,
  no full report body, no private notes, no tags.
- **Export formats** — Markdown, standalone HTML (CSP meta with
  `default-src 'none'`, no scripts, no remote resources),
  print-optimized HTML, strict JSON. Filename convention
  `threatpulse-report-{type}-{shortId}-{YYYY-MM-DD}.{ext}`.
- **26-test acceptance suite** (`scripts/acceptance-v65-briefings.mjs`).

## V6.4 — Local defender workspace and triage

V6.4 turns ThreatPulse Radar from a read-only public
intelligence dashboard into a useful local defender
workspace — without changing any of the public
infrastructure. The V6.3 Hostinger runtime, the V6.2
storage portability layer, the V6.1 source-health and
change-intelligence surfaces, the V6.0 canonical
baseline, the V5.7 21-column CSV, the private gateway,
and the Netlify function entries are all preserved.

### What this release adds

- **Local-only workspace.** A per-device, IndexedDB-backed
  (with a session-memory fallback) triage surface. A
  defender can watch selected CVEs, assign a local triage
  status, assign a local user priority, add local tags,
  add a private note, mark CVEs reviewed, and identify
  watched CVEs that changed since review. Everything
  lives on the user's device; nothing is uploaded.
- **Workspace panel in the dashboard.** A compact
  panel with seven count tiles (Watched, Unreviewed,
  Action required, Changed since review, High / urgent,
  Resolved, Archived), a storage-status badge, an
  Export / Import / Clear-archived / Clear-workspace
  affordance, a single-row queue filter chip group, a
  local search box (CVE id, note, tag), and a
  selectable local queue list. The panel's filters and
  counts affect only the local queue; Defender Views,
  public filters, the public URL, and the CSV export
  are unaffected.
- **Local workspace section in the detail drawer.** A
  compact section between OSV and External references
  that exposes watch / triage / priority / tag / note /
  mark-reviewed / archive controls. Autosave with a
  visible save state (idle / saving / saved / error),
  600 ms debounce on the note textarea, a character
  counter (8,000 max), 20-tag cap, 40-char per tag.
  Mark-reviewed uses the current public-intelligence
  version and change signature.
- **Bulk action bar.** Bounded bulk actions for the
  selected queue rows: add / remove watch, set triage,
  set priority, add tag, archive, restore. Capped at
  200 CVEs per click; destructive actions require a
  confirmation step.
- **Compact watch toggle in the table.** A single
  "Local" column with a Watch / Watched pill. Disabled
  silently when the workspace is unavailable.
- **Multi-tab synchronisation.** `BroadcastChannel
  ('threatpulse-workspace')` posts a `{ type, cveId?,
  ts }` message after every committed write; a
  conflict banner surfaces when a remote tab delivers
  a newer record than the local one.
- **Application-level dialogs.** Export (download JSON),
  Import (file picker → dry-run → merge / replace),
  Clear archived (count-gated confirm), Clear workspace
  (typed `RESET` gate). All dialogs trap and restore
  focus; `Escape` closes them.
- **Change-aware review checkpoints.** The mark-reviewed
  action stamps `lastSeenPublicIntelligenceVersion` and
  `lastSeenChangeSignature` (a deterministic sha256 of
  the public-safe change fields). The "Changed since
  review" classification surfaces only when the current
  public signature differs from the checkpoint at the
  SAME compatible version.
- **Export / import with deterministic checksums.** The
  export is sorted by `cveId`, tags are sorted
  ascending, field order is fixed, and a `sha256:`
  hex digest is baked into the payload. The export
  filename is `threatpulse-workspace.json` (no CVE id,
  no timestamp leak). Merge and replace modes are
  behaviour-tested; failed replace leaves the original
  workspace intact.

### V6.4 invariants (and the test names that verify them)

- All V6.0 / V6.1 / V6.2 / V6.3 invariants preserved
  (31 prior acceptance suites still pass).
- 32 acceptance suites total, 920 assertions, all green.
- V6.4-specific suite: `scripts/acceptance-v64-workspace.mjs`
  — 190 assertions covering schema, migrations, change
  signature, in-memory and unavailable adapters, export
  / import (dry-run, merge, replace, failed-promotion
  preservation), queue filters and ordering, CSV column
  count, Netlify function source sweep, URL privacy,
  export filename hygiene, and per-CVE serialised writes.
- 5 public Netlify function entries; 1 gateway function
  entry (byte-identical to V6.1 baseline `32a8a63`);
  `netlify/gateway/` and `client/` byte-identical to the
  V6.1 baseline.
- `CSV_COLUMNS` = 21.
- No browser workspace data is sent to the backend, the
  private gateway, the public Netlify function entries,
  the Hostinger runtime, the dashboard URL, the CSV
  export, or any analytics endpoint.

## V6.1 — Public intelligence, source transparency, OSV context, and change intelligence

V6.1 makes the public dashboard honest about which data
sources contribute to the current dataset, where each
vulnerability came from, how OSV (the canonical
baseline) describes it, and what has changed since the
previous successful publication. The V5.7 public surface
is preserved; the V6.0 canonical baseline is unchanged;
the private gateway is byte-identical; the V5.7 CSV
remains exactly 21 columns.

### What this release adds

- **Source Health panel.** A compact summary bar with
  six source chips (CISA KEV, NVD, FIRST EPSS, CISA
  Vulnrichment, GitHub Advisory Database, OSV). Each
  chip shows a derived state (`unknown` / `fresh` /
  `partial` / `stale` / `unavailable`) and a coverage
  count. Clicking a chip expands a detail card with
  purpose, limitations, official-source link, refresh
  schedule, and threshold. No env-var names appear in
  any field.
- **"What changed" panel.** A six-category panel
  (Newly tracked, No longer tracked, Fact newly
  available, Fact changed, Fact no longer present,
  Provider status changed) that surfaces a
  deterministic diff between the previous successful
  public-intelligence version and the current one. The
  panel-local filter is isolated from the main
  `VulnerabilityFilters`, the Defender Views presets,
  the main table, and the CSV export.
- **OSV section in the DetailDrawer.** A new third
  context section (between SSVC and External references)
  showing the bounded per-CVE public OSV projection:
  OSV id, ecosystem, aliases, modified timestamp,
  status (Active or Withdrawn), affected packages with
  provider-native range events rendered verbatim, and
  First fixed. The empty-state copy is locked:
  "No OSV record is currently available in this
  ThreatPulse snapshot."
- **Composite publicStateHash.** A precomputed hash
  of the dataset envelope + Vulnrichment cache + GitHub
  Advisory cache + referenced OSV projection. The hash
  is stored internally in each Blob envelope
  (`datasetPublicHash`, `vulnrichmentPublicHash`,
  `githubAdvisoryPublicHash` — all added to
  `INTERNAL_BLOB_FIELDS`). The public request path
  reads data and hash from the same Blob read; no
  re-hashing on the read path.
- **Bounded dataset function read modes.** The
  existing `dataset.mjs` function is extended (no new
  function entry file) with `view=osv` and
  `view=changes` query modes. Both modes enforce the
  current-compatible-version-only rule: the requested
  version MUST equal the currently-attached
  `publicIntelligenceVersion`. Arbitrary
  retained-version browsing is not exposed.
- **Mark-and-sweep OSV shard GC.** Content-addressed
  OSV shards are never deleted based on timestamp or
  age. Only unreferenced shards (not in any retained
  manifest) are eligible for deletion. GC failure
  leaves both latest pointers and all referenced
  shards usable.
- **Skip-unchanged publication.** When the
  `publicStateHash` matches the previous version, the
  publisher exits without writing any artifact. When
  the OSV manifest hash matches, the OSV publisher
  exits. This significantly reduces write operations
  on quiet days.

### What this release explicitly does NOT add

- No new public function entry file. The dataset
  function is extended; the public function entry
  count remains 5.
- No new gateway function entry file. The private
  gateway subtree is byte-identical to V6.0.0.
- No new Netlify environment variable.
- No new cross-site access token.
- No new top-level function entry file on the public
  site or the gateway.
- No new CSV column. The V5.7 CSV remains exactly 21
  columns.
- No new table column, header pill, or combined
  score.
- No browser-originated upstream provider request.
  Official-source hyperlinks are rendered as
  `<a target="_blank" rel="noopener noreferrer">`; the
  browser never calls `fetch` to any provider host.
- No new V6.0 canonical-baseline changes. The
  canonical baseline, the private gateway, the
  consumer client, and the consumer contract are
  byte-identical to V6.0.0.
- No new provider. V6.1 is a transparency + context
  milestone; the next provider is a post-V6.1 concern.
- No new V6.0 baseline write. The public-intelligence
  bundle is independently versioned; the canonical
  baseline manifest is unchanged.
- No production deployment. The Netlify credit
  allowance resets on August 7; production deploy is
  deferred until then.

### Topology

V6.1 adds a single new Blob store (`tpr-public-intelligence`)
on the public site. The store is owned by the public
site's local Netlify Blobs runtime context; no cross-site
access, no new env var, no new token. The store has
two sub-trees:

- `osv/` — content-addressed shards, per-version
  manifest, latest pointer, publication lock. Published
  from the V6.0 canonical pipeline (hourly cadence).
- `dataset/` — per-version manifest, public comparison
  snapshot (gzipped), source-health observations
  (gzipped), changes items (gzipped), latest pointer,
  publication lock, aggregate change summaries. Published
  from the V5.2 dataset pipeline (30-min cadence).

The canonical-baseline pipeline and the dataset
pipeline each call their respective sub-step inside
their existing publication lock windows. The
publication locks are best-effort and never block
publication.

### Operational entries (V6.1)

No new env vars. The V6.0 env-var contract is preserved
in full. The precomputed public hashes are written into
existing Blob envelopes; no new env var carries them.

### V6.1 invariants (and the test names that verify them)

- **The five public states are mutually exclusive and
  exhaustive.** `acceptance-source-health.mjs`
  verifies all 5 states.
- **No env-var name appears in any public response.**
  `acceptance-deployment-hardening.mjs` extends the
  V6.0 check to all new fields.
- **Official-source hyperlinks are `https://` only.**
  `acceptance-source-health-and-changes-ui.mjs` asserts
  the link policy.
- **The browser never fetches upstream providers.**
  `acceptance-source-health-and-changes-ui.mjs` greps
  the bundled output for `fetch` / `XMLHttpRequest` /
  `axios` calls to provider hosts.
- **The OSV section's empty-state copy is locked.**
  `acceptance-source-health-and-changes-ui.mjs` asserts
  the exact copy and forbids "not in OSV" / "no fix".
- **The panel-local filter does not modify the main
  filters.** `acceptance-source-health-and-changes-ui.mjs`
  asserts isolation.
- **The default V6.1 response exposes the 5 documented
  public fields and does NOT expose the full
  publicStateHash.** `acceptance-dataset-read-modes.mjs`
  asserts this.

### Test summary

V6.1 adds 8 new behavior suites across the seven
logical commits: foundations, OSV projections,
dataset-bound snapshots, change intelligence, dataset
read modes, source health and changes UI, release
limits, and production wiring. All 19 existing V5.x
+ V6.0 acceptance scripts pass unchanged. The V5.7
CSV column count remains exactly 21.

### Files added or modified

- **New shared modules**:
  `netlify/functions/_shared/{publicIntelligenceStore,
   publicIntelligenceHash, publicIntelligenceSize,
   publicIntelligenceValidation,
   publicIntelligenceCompression,
   publicIntelligenceBucket,
   osvPublicProjection, osvProjectionPublish,
   osvProjectionGc, publicSnapshot,
   datasetBoundPublish, changeIntelligence,
   datasetPublicIntelligenceRead}.mjs`
- **New schemas**:
  `schemas/{osv-shard-v1, dataset-bundle-manifest-v1,
   public-snapshot-v1, source-health-public-v1,
   change-intelligence-v1}.schema.json`
- **New source-registry 1.1.0** (additive over V6.0):
  `schemas/source-registry-v1.1.schema.json`
- **Modified existing modules**:
  `netlify/functions/_shared/{refresh,
   vulnrichmentRefresh, githubAdvisoryRefresh,
   publicIntelligenceHash, publicIntelligenceStore}.mjs`
  — precomputed public hashes added to the
  respective Blob envelopes; `INTERNAL_BLOB_FIELDS`
  extended with the V6.1 internal fields.
- **Extended dataset function**:
  `netlify/functions/dataset.mjs` — `view=osv` and
  `view=changes` query modes; default mode carries the
  V6.1 aggregate fields.
- **New TypeScript types**:
  `src/types/{osv,change,sourceHealth}.ts`
- **New frontend components**:
  `src/components/{SourceHealthPanel,SourceStatusChip,
   SourceStatusCard,ChangeIntelligencePanel,
   ChangeItemRow}.tsx` and
  `src/components/drawer/OsvContext.tsx`
- **Modified existing frontend files**:
  `src/components/DetailDrawer.tsx` (OSV section),
  `src/pages/DashboardPage.tsx` (panels wiring),
  `src/services/vulnerabilityService.ts`
  (V6.1 fetchers), `src/types/vulnerability.ts`
  (V6.1 fields).
- **New acceptance suites**:
  `scripts/acceptance-{public-intelligence-foundations,
   osv-public-projections, dataset-bound-snapshots,
   change-intelligence, dataset-read-modes,
   source-health-and-changes-ui}.mjs`
- **New docs**:
  `docs/{public-intelligence,source-transparency,
   osv-context,change-intelligence}.md`
- **CHANGELOG.md** — this entry.

### Why this is a substantial release

V6.1 changes the public dashboard's transparency and
context surface without changing the V5.7 dashboard
data plane. The new Source Health, What Changed, and
OSV drawer sections are user-visible additions; the
composite publicStateHash, the per-Blob internal hash
metadata, the two-cadence publication model, the
content-addressed OSV shards, the mark-and-sweep GC,
the skip-unchanged publication, the bounded dataset
function read modes, the deterministic change
classifications, and the per-CVE observation states
together represent a substantial internal-architecture
milestone with a clear user-facing surface. The next
release in this line will be V6.2, focused on
long-term change intelligence (the 30-day rollup view
that the V6.1 retention policy does not yet expose).

## V6.0 — Canonical baseline (private data plane)

V6.0 introduces a **canonical baseline**: a content-addressed,
versioned, atomic-publication snapshot of the full
vulnerability / advisory / package / relationship / tombstone
data plane, derived from OSV. The baseline is **private** —
the V5.7 public dashboard is unchanged.

### What this release adds

- **A new OSV ingestion pipeline.** The public site now
  ships a Scheduled Function (hourly cron) and a Background
  Function (15-minute ceiling) that read OSV's per-ecosystem
  `modified_id.csv` and the per-vuln JSON, normalize to five
  canonical entity types (vulnerability, advisory, package,
  relationship, tombstone), partition into 256 buckets per
  entity type, and publish a new version manifest atomically.
  The pipeline is resumable across Background Function
  invocations via a Blob-backed bootstrap state.
- **A new private sync gateway.** A separate Netlify site
  exposes five authenticated routes at `/private/v1/*`
  (manifest, manifest/{version}, delta, shard, snapshot,
  sources) that authenticated consumers call to read the
  baseline. Authentication is HMAC-SHA256 of the credential
  keyed by a server-side pepper. The credential format is
  `tpr_<keyId>_<randomSecret>`.
- **A reference consumer client.** A small Node.js ESM
  module (`client/consumer-client.mjs`) that authenticates,
  fetches the manifest, verifies its hash, and pulls only
  the shards the local store doesn't already have. The
  default store is a filesystem path; SQLite and Postgres
  adapters are documented in `client/contracts.md`.
- **A new V6.0 documentation set.** `docs/v6-architecture.md`,
  `docs/credentials.md`, `docs/deployment.md`,
  `docs/ecosystems.md`. Plus V6.0 sections in
  `README.md`, `PORTFOLIO_WRITEUP.md`,
  `PUBLIC_RELEASE_CHECKLIST.md`, and this changelog.

### What this release explicitly does NOT add

- No new anonymous function on the public site. The
  baseline is private.
- No real-time push to consumers. Consumers pull.
- No STIX 2.1 interop. The manifest schema is the V6.0
  schema.
- No per-credential hard quotas. Per-IP/per-domain rate
  limits only.
- No change to the V5.7 public dashboard surface.

### Topology

The V6.0 architecture has three Netlify environments:

1. The **public ThreatPulse Radar site** (the V5.7 site
   plus the V6.0 OSV ingestion pipeline). Owns the
   `tpr-baseline` Blob store (canonical baseline data).
   The public site does NOT own the credentials store.
2. The **private sync gateway** (a separate Netlify site,
   built from the `netlify/gateway/` subtree in this
   repo). Reads the public site's `tpr-baseline` store
   via cross-site env vars. Owns its OWN
   `tpr-private-credentials` store, accessed via the
   gateway's local Netlify Blobs runtime context (no
   siteID, no token, no cross-site). Holds the
   credential pepper. The public site does NOT deploy
   the gateway function — the gateway function
   source-of-truth lives in `netlify/gateway/src/`, not
   in `netlify/functions/`.
3. The **consumer** (a third-party product). Authenticates
   to the gateway with the HMAC credential and pulls the
   baseline.

### Operational entries

- `THREATPULSE_REFRESH_TRIGGER_SECRET` (public site,
  Production scope) — shared secret used by the
  scheduled function to invoke the background function.
  Long random string.
- `THREATPULSE_BASELINE_SITE_ID` and
  `THREATPULSE_BLOBS_ACCESS_TOKEN` (private gateway,
  Production scope) — cross-site access to the public
  site's `tpr-baseline` store. The token is scoped to
  `tpr-baseline` only; it does NOT authorize reading the
  gateway-local `tpr-private-credentials` store.
- `THREATPULSE_CREDENTIAL_PEPPER` (private gateway,
  Production scope) — the HMAC pepper. Server-side only.
  Identical to the value used by the operator script
  when issuing credentials. The Production-only scoping
  is critical: a deploy-preview URL with the production
  pepper could forge credentials against the
  gateway-local `tpr-private-credentials` store.
- `THREATPULSE_OSV_ECOSYSTEMS` (public site, optional) —
  JSON override of `config/osv-ecosystems.json`.

The gateway does NOT need an env var to authorize reading
the credentials store. The credentials store is
gateway-local: it lives on the gateway's own Netlify
Blobs runtime context, which is provided automatically
by the Netlify runtime. There is no token, no site ID,
and no cross-site round trip.

### V6.0 invariants (and the test names that verify them)

- **No empty shards.** `applyChangesToBucket` returns an
  empty array for a fully-removed bucket; the orchestrator
  omits that bucket from the new manifest. Tested by
  "empty bucket → null descriptor" in
  `acceptance-canonical-baseline.mjs`.
- **Unchanged shards are reused.** A bucket whose content
  hash matches the previous bucket's hash keeps its
  previous objectKey. Tested by "unchanged content reuses
  previous shard key" in
  `acceptance-canonical-baseline.mjs`.
- **Failed publication leaves `manifests/latest.json`
  unchanged.** A write failure between the version
  manifest write and the latest pointer write does NOT
  cause a torn read. Tested by "failed publication leaves
  latest unchanged" in
  `acceptance-canonical-baseline.mjs`.
- **Old manifests retain valid immutable shard
  references.** A consumer that pins a previous version
  can still fetch its shards indefinitely (the objectKeys
  are content-addressed and never deleted). Tested by
  "manifest/{version} route" in
  `acceptance-private-gateway.mjs`.
- **Equal-timestamp OSV updates are not skipped.** The
  orchestrator re-processes IDs that reappear in
  `modified_id.csv`; the bucket-merge dedup makes the
  re-emit safe. Tested by "equal-timestamp re-emit
  invariant" in `acceptance-osv-ingestion.mjs`.
- **Corrupt shard or delta is rejected.** A consumer
  that receives a bad shard (mismatched sha256) will not
  commit it. The `verifyManifest` function rejects any
  manifest whose computed `canonicalContentHash` does
  not match the embedded value. Tested by "verifyManifest:
  tampered manifest" in
  `acceptance-consumer-client.mjs`.
- **Provider and private API credentials cannot enter
  frontend bundles.** No code path from the public site's
  client code touches the credential pepper, the trigger
  secret, or the cross-site access token. The trigger
  secret, pepper, and access token live in Netlify
  environment variables, not in any code committed to
  this repository.
- **Visitors cannot invoke the background refresh.** The
  background function rejects any request without the
  trigger secret header. Tested by "visitors cannot
  trigger refresh" in `acceptance-scheduler.mjs`.
- **The private sync gateway is NOT deployed on the
  public site.** The public site's `netlify/functions/`
  directory contains only the V5.x and V6.0-publisher
  functions. The gateway function and the
  credentials helper live in `netlify/gateway/src/` and
  are copied to a deployment-only staging directory
  at deploy time by `scripts/copy-gateway-files.mjs`.
  The public-site build does NOT include the gateway
  function. Tested by "public site netlify/functions/
  does NOT contain private-sync-gateway.mjs" in
  `acceptance-deployment-hardening.mjs`.
- **Consumer credential records live in a GATEWAY-LOCAL
  Blob store.** `credentials/<keyId>` is stored in
  `tpr-private-credentials` on the GATEWAY site, NOT on
  the public site. The public site never sees this
  store. The gateway reads it via the local Netlify
  Blobs runtime context — no siteID, no access token,
  no cross-site access. The public site's `tpr-baseline`
  Blob store contains only baseline/intelligence
  artifacts (manifests, version manifests, content-
  addressed shards, deltas, source registry, source
  health, bootstrap state, publication lock). The
  baseline token (`THREATPULSE_BLOBS_ACCESS_TOKEN`,
  scoped to `tpr-baseline`) cannot authorize reading
  the credentials store, because the credentials store
  is in a different Netlify site and uses a different
  access path. Tested by the credential-store-
  separation section in `acceptance-deployment-hardening.mjs`.
- **Route version parameters are validated before
  Blob-key construction.** `version`, `from`, and `to`
  parameters on the gateway's manifest, snapshot, and
  delta routes are matched against
  `/^[A-Za-z0-9._-]{1,128}$/` BEFORE the value is
  interpolated into a Blob key. Path-traversal attempts
  (`..%2F..%2F…`, `/etc/…`, etc.) are rejected with
  HTTP 400 `bad-request` before any store read. Tested
  by the path-traversal section in
  `acceptance-deployment-hardening.mjs`.
- **Safe error responses and sanitized logs.** The
  gateway function does not call `console.log` /
  `console.error` / `console.warn` / `console.info` /
  `console.debug`. 500 / 401 response bodies do not
  contain credential values, keyIds, the pepper env
  var, the token env var, the site-id env var, or the
  Authorization header. The background function's
  `console.log` summary line does not include the
  trigger secret value, the Authorization header, or
  the bearer header. Tested by the safe-error-response
  and sanitized-log sections in
  `acceptance-deployment-hardening.mjs`.
- **Working tree is clean after the final logical
  commit.** Each logical commit's working tree is empty
  before the next one starts. `git status --short` returns
  no output after the V6.0 implementation is complete.

### Test summary

The V6.0 implementation adds 7 new behavior suites with
548 total assertions:

| Suite | Assertions |
| --- | --- |
| `acceptance-canonical-hashing` | 26 |
| `acceptance-osv-ingestion` | 94 |
| `acceptance-canonical-baseline` | 127 |
| `acceptance-scheduler` | 50 |
| `acceptance-private-gateway` | 90 |
| `acceptance-consumer-client` | 54 |
| `acceptance-deployment-hardening` | 107 |
| **Total V6.0** | **548** |

All 11 existing V5.x acceptance scripts pass unchanged.

### Files added or modified

- **New shared modules**:
  `netlify/functions/_shared/{canonicalBaseline,baselinePublish,osvBackground,triggerAuth}.mjs`
- **New public-site functions**:
  `netlify/functions/{refresh-baseline-scheduled,refresh-baseline-background}.mjs`
- **New gateway subtree** (under `netlify/gateway/`):
  - `netlify.toml` — gateway Netlify site config
  - `package.json` — declares `@netlify/blobs` only
  - `site/.gitkeep` — empty publish directory
  - `src/private-sync-gateway.mjs` — gateway function
  - `src/_shared/credentials.mjs` — HMAC credential format + verify
  - `src/_shared/baselineStore.mjs` — gateway-local
    credential store helper (`getCredentialsStore`, no
    siteID, no token) plus the cross-site baseline
    store helper (`getCrossSiteBaselineStore`, requires
    `THREATPULSE_BASELINE_SITE_ID` and
    `THREATPULSE_BLOBS_ACCESS_TOKEN`)
- **New deployment tooling**:
  `scripts/copy-gateway-files.mjs` — copies the gateway
  subtree's source-of-truth into a deployment-only
  staging directory at deploy time.
- **Removed from public site**:
  `netlify/functions/private-sync-gateway.mjs` and
  `netlify/functions/_shared/credentials.mjs` moved
  into the gateway subtree.
- **New client**:
  `client/{consumer-client.mjs,contracts.md}`
- **New docs**: `docs/{v6-architecture,credentials,deployment,ecosystems}.md`
- **New JSON Schemas**: `schemas/{baseline,delta,manifest,source-registry}-v1.schema.json`
- **New config**: `config/osv-ecosystems.json`
- **New acceptance suite**:
  `scripts/acceptance-deployment-hardening.mjs` —
  covers gateway subtree shape, staging script
  behavior, public-site isolation, source-of-truth
  hardening, path-traversal rejection, version
  validation, secret-leak avoidance in error bodies,
  log sanitization, credential-store separation, and
  existing private-gateway regression.
- **Modified**: `netlify.toml` (V6.0 cron + topology
  comment block), `netlify/functions/_shared/baselineStore.mjs`
  (gateway-side cross-site helpers moved to
  `netlify/gateway/src/_shared/baselineStore.mjs`),
  `netlify/functions/refresh-baseline-background.mjs`
  (corrected deployment comment), `README.md`,
  `PORTFOLIO_WRITEUP.md`, `PUBLIC_RELEASE_CHECKLIST.md`,
  `CHANGELOG.md`, `.gitignore` (gateway staging dir
  excluded).

### Why this is a major version

V6.0 changes the data-plane architecture, not the dashboard
surface. The dashboard is unchanged. The internal split
between "the publisher" and "the consumer" is the new
contract. Any downstream product that wants to use the
baseline integrates via the consumer client (or its own
implementation of the same contract). The V5.x public
dashboard continues to work as before — the V6.0 changes
are additive on the public site and entirely new on the
private gateway.

## V5.7 — Transparent remediation views and export

- README, portfolio writeup, public-release checklist, and
  changelog refreshed to describe the v5.7 reviewed
  remediation drawer, the "Affected package" tab, the
  vendor / product facet, the "First patched version"
  rendering, the safe-link behavior, and the export.
- The V5.7 surface is the last major addition before V6.0.
  See the V5.6 entry for the GitHub Advisory capability
  that feeds the v5.7 drawer.

## V5.6.1 — GitHub Advisory release documentation

- README, portfolio writeup, public-release checklist, and
  changelog refreshed to describe the v5.6 reviewed
  GitHub Advisory capability accurately: fifth source
  listed, five-provider architecture diagram, drawer-only
  "Package remediation context" section, neutral
  missing-patch semantics ("First patched version
  unavailable", never "No fix exists"), safe GHSA link
  behavior, server-side-only `GITHUB_TOKEN` contract,
  and explicit no-real-time / no-proprietary-score /
  no-header-pill / no-table-column claims.
- Public-release checklist adds a v5.6 GitHub Advisory
  public-surface audit finding (no token leak, no raw
  rate-limit metadata, no raw provider error bodies, no
  internal cache markers, separate `tpr-github-advisory`
  blob store, drawer-only presentation) and a
  production-verification step for
  `githubAdvisoryStatus` / `githubAdvisoryCoverage` /
  Package remediation context / safe GHSA links.
- Portfolio writeup updates the assertion total from
  701 to **874** and adds a fourth design-choice bullet
  to the v5.x section describing the v5.6 reviewed
  package-remediation enrichment, the optional
  `GITHUB_TOKEN`, the read-time merge without
  `fetchedAt` rewrite, and the null-patched-version
  rendering rule.
- No application, Netlify Function, refresh, UI, or test
  changes.

## V5.6 — GitHub Advisory remediation context

- Fifth defensive-intelligence feed: the public **GitHub
  Advisory Database**, surfaced as reviewed package-
  remediation context (GHSA identifier, advisory severity,
  GitHub-reviewed date, source label, and up to 5
  normalized package entries — ecosystem, name, vulnerable
  range, first patched version) in the vulnerability
  details drawer.
- Server-side incremental enrichment: the endpoint is
  filtered by CVE and by the reviewed advisory type, and
  at most 25 missing / stale CVEs are enriched per
  background run without a token (50 with the optional
  server-side `GITHUB_TOKEN`), running at concurrency 4
  as a separate post-step in the same refresh cycle.
  Only reviewed, non-withdrawn advisories are stored;
  withdrawn and unreviewed entries are dropped at the
  filter.
- Separate Netlify Blobs store
  (`tpr-github-advisory`, key `cache`) holds reviewed
  advisory records and lightweight negative-cache
  markers for empty / 404 ("no reviewed GitHub Advisory")
  responses, so the backfill queue keeps moving instead
  of looping. An empty / 404 result never overwrites an
  existing positive advisory record; provider failures
  (5xx, network errors, rate-limit responses) preserve
  positive cached entries.
- A null patched version on a reviewed advisory is
  rendered as **"First patched version unavailable"** —
  the dashboard never infers a missing patched version
  as **"No fix exists"**.
- Package remediation context is drawer-only: no main-
  table column, no header pill, no combined score. The
  public envelope's `githubAdvisoryStatus` /
  `githubAdvisoryCoverage` reflect the actual cache
  state; the dashboard never claims `available` while
  backfill is still in progress. External GHSA links
  open in a new tab with `rel="noopener noreferrer"`
  and point only to the public
  `https://github.com/advisories/<GHSA-ID>` URL.
- Internal-only fields — negative-cache markers, raw
  rate-limit headers (`x-ratelimit-*`, `Retry-After`),
  raw provider error bodies, cache keys, and stack
  traces — are stripped from the public response. The
  optional `GITHUB_TOKEN` is read from `process.env`
  inside the Netlify Function only, passed to the
  upstream as an `Authorization: Bearer <token>` header,
  and never appears in the function response body, in
  any URL, in any log, or in the frontend bundle. The
  frontend bundle never references the `api.github.com`
  upstream.
- New acceptance suite:
  `scripts/acceptance-github-advisory.mjs`
  (173 assertions).

## V5.5.1 — Vulnrichment launch polish (documentation only)

- README, portfolio writeup, and public-release checklist
  refreshed to describe the v5.5 CISA Vulnrichment /
  SSVC capability accurately: fourth source listed, four-
  provider architecture diagram, honest-partial-coverage
  language, no real-time or proprietary-score claims.
- Public-release checklist adds a Vulnrichment
  public-surface audit finding (no internal metadata, no
  raw provider errors, separate blob store) and a
  production-verification step for `vulnrichmentStatus` /
  `vulnrichmentCoverage`.
- No application, Netlify Function, refresh, UI, or test
  changes.

## V5.5 — CISA Vulnrichment / SSVC

- Fourth defensive-intelligence feed: CISA's public
  **Vulnrichment** repository, surfaced as CISA-ADP **SSVC**
  decision context (Exploitation, Automatable, Technical
  impact) in the vulnerability details drawer.
- Server-side incremental enrichment: at most 50
  missing / stale CVEs enriched per background refresh
  (concurrency 5, KEV-newest first), running as a
  separate post-step in the same refresh cycle.
- Separate Netlify Blobs store (`tpr-vulnrichment`,
  key `cache`) holds SSVC records and lightweight
  negative-cache markers for HTTP 404 ("no CISA
  Vulnrichment assessment available") responses, so the
  backfill queue keeps moving instead of looping.
- A 404 never overwrites an existing positive SSVC record.
  The public envelope's `vulnrichmentStatus` /
  `vulnrichmentCoverage` reflect the actual cache state;
  the dashboard never claims `available` while backfill
  is still in progress.
- Internal-only fields (`lastVulnrichmentRefresh`,
  `lastRefreshFailure`, `lastRefreshAttemptAt`) are
  stripped from the public response. The frontend bundle
  never references the `raw.githubusercontent.com`
  upstream.
- New acceptance suite: `scripts/acceptance-vulnrichment.mjs`
  (125 assertions).

## V5.4.3 — Automatic refresh UI cleanup

- Removed the misleading "Refresh live data" button from
  the dashboard. The button name implied a manual action
  the user could take, but the same path was already run
  on the v5.1 polling tick and the v5.4.2 last-known-good
  guard made manual intervention less meaningful. The
  header "Last refresh" pill and the "New dataset
  available" banner remain as the user-visible signals.
- No code, Netlify Function, or refresh-behavior changes
  — this is a UI-only cleanup.

## V5.4.2 — Last-known-good dataset preservation

- The refresh orchestrator preserves the existing
  prebuilt `latest-dataset` blob when the live build
  fails (CISA unreachable, NVD rate-limited, network
  error). A bad refresh is never allowed to worsen the
  public dataset. The visitor keeps seeing the last
  successful build, the header pill explains the partial
  outage, and the next cron tick retries.
- The existing v5.2.6 NVD cooldown short-circuit is
  preserved on the same path; the new behavior is purely
  additive.
- New acceptance suite: `scripts/acceptance-lastknowngood.mjs`
  (76 assertions).

---

_For the full version-by-version commit history, run
`git log --oneline --graph` from the project root._
