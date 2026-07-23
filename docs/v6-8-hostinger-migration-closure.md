# V6.8 — Hostinger Migration Closure

This document is the final closure record for the V6.8
Hostinger migration. It records the production state,
proves that the Hostinger deployment is independent of
the Netlify public site at the request-path level, and
specifies the exact observation window and rollback
conditions for declaring the Netlify public site
rollback-only.

## Canonical production domains

- **Hostinger (canonical):** `https://threatpulse.namanp.de`
- **Hostinger (temporary, diagnostic-only):** the Hostinger Business Node.js assignment issued by the control panel for the running application port.
- **Netlify public site (rollback-only during observation):** `https://threatpulse-radar.netlify.app`

The Hostinger application is the canonical production
endpoint. The Netlify public site is NOT retired at
this milestone; it is kept online as the rollback
target during the 24–48 hour observation window.

## Public request-path independence from Netlify

The Hostinger application is a single `node:http` server
in `hostinger/app.mjs`. The route table is:

| Path | Owner | Behavior |
| --- | --- | --- |
| `GET /` | `hostinger/app.mjs` (static fallback to `$THREATPULSE_PUBLIC_DIR/index.html`) | SPA |
| `GET /health` | `hostinger/app.mjs` → `server/routes/health.mjs` (`handleHealth`) | Sanitized `{status:'ok'}` |
| `GET /ready` | `hostinger/app.mjs` → `server/routes/ready.mjs` (`handlePortableReady`) | Sanitized `{ready:true}` or `{ready:false, reason:'dataset-missing'}` |
| `GET /api/dataset` (and `?view=osv&...`, `?view=changes&...`) | `hostinger/app.mjs` → `server/routes/dataset.mjs` (`handleDataset`) | Canonical route, served from local filesystem data root |
| `GET /.netlify/functions/dataset` (and `?view=...`) | `hostinger/app.mjs` → same `handleDataset` | **Local compatibility alias** for the frozen V6.8 frontend. NOT a request to `*.netlify.com`. |
| `GET /.netlify/functions/{any other name}` | `hostinger/app.mjs` | Honest `404`. Prevents the SPA shell from masquerading as a refresh endpoint. |
| `POST / PUT / PATCH / DELETE *` | `hostinger/app.mjs` | `405` with `Allow: GET, HEAD` header (the documented method allowlist). |

**Conclusion:** the Hostinger application does not make
any outbound HTTP request to `*.netlify.com` or to any
other host at request time. Every public request is
served entirely from `hostinger/app.mjs` and the local
filesystem data root. The string `/.netlify/functions`
in the alias is a frozen-frontend compatibility path
that the operator-visible URL happens to use; it does
not represent a request to a Netlify Function.

The path `/.netlify/functions/dataset` is the **only**
required public compatibility alias. The remaining
`/.netlify/functions/*` paths (e.g.
`/.netlify/functions/refresh-dataset-background`)
remain closed with honest 404 responses. No write,
refresh, credential, or administrative HTTP endpoint is
publicly exposed on the Hostinger deployment.

## Private-gateway independence

The Hostinger public application has **zero runtime
dependency** on the private Netlify gateway
(`netlify/gateway/src/private-sync-gateway.mjs`).

- `src/`, `hostinger/`, `server/`, `jobs/` contain no
  import from `netlify/gateway/`.
- The public dashboard, the V6.4 local workspace, the
  V6.6 local environment, the V6.7 local remediation,
  and the V6.5 reports are all independent of the
  private gateway. They are purely browser-local
  (IndexedDB) or local-filesystem (Blob storage).
- The only documented consumer of the private gateway
  is the reference offline consumer at
  `client/consumer-client.mjs` (a Node-based sample
  that reads from the gateway's `tpr-baseline` Blob
  store and uses the gateway's HMAC credential).
  The Hostinger production deployment does NOT
  require that consumer to be online.
- The Hostinger runtime does NOT set or read any
  gateway-only environment variable
  (`THREATPULSE_BASELINE_SITE_ID`,
  `THREATPULSE_BLOBS_ACCESS_TOKEN`,
  `THREATPULSE_CREDENTIAL_PEPPER`,
  `THREATPULSE_CREDENTIALS_BLOBS_ACCESS_TOKEN`).

The private gateway can be retired once the reference
consumer (if still in use by the operator) is migrated
to an alternative baseline source. The public Hostinger
deployment does not require this migration to declare
the V6.8 migration closed.

## Active runtime variables (Hostinger)

| Variable | Required? | Default | Notes |
| --- | --- | --- | --- |
| `THREATPULSE_STORAGE_BACKEND` | **Required** | `'filesystem'` | Must be `filesystem` for the Hostinger runtime. |
| `THREATPULSE_DATA_ROOT` | Recommended (safe default) | `$HOME/threatpulse-state` (when `HOME` is set) or `./state` (relative to the working directory) | The Hostinger runtime derives a persistent default. Recommended explicit production setting. |
| `THREATPULSE_HTTP_HOST` | Optional | `'0.0.0.0'` | Bind host. |
| `THREATPULSE_HTTP_PORT` / `PORT` | Optional | `'8787'` | Bind port. Hostinger maps `PORT` from the control panel. |
| `THREATPULSE_PUBLIC_DIR` | Optional | `'./dist'` | Built Vite frontend. |
| `THREATPULSE_LOG_DIR` | Optional | `$HOME/threatpulse-logs` (when `HOME` is set) or `'./logs'` | Optional file logging directory. |
| `THREATPULSE_LOCKS_DIR` | Optional | `$THREATPULSE_DATA_ROOT/locks` | Cron-job lock directory. |
| `THREATPULSE_BACKUP_DIR` | Optional | `$THREATPULSE_DATA_ROOT/../threatpulse-backups` | Daily backup archive directory. |
| `THREATPULSE_DRY_RUN` | Optional | `'0'` | When `'1'` or `'true'`, cron jobs report only without writing. |
| `THREATPULSE_MANAGED_SCHEDULER` | Optional | disabled | Only the literal `'1'` enables the in-process scheduler. |
| `THREATPULSE_MANAGED_SCHEDULER_BOOTSTRAP` | Optional | disabled | Only the literal `'1'` triggers a one-shot dataset-missing bootstrap on startup. |
| `THREATPULSE_LOG_LEVEL` | Optional | default | Log level for the Hostinger logger. |
| `NVD_API_KEY` | Optional | absent | Improves NVD per-cycle throughput. Read only inside the server-side refresh path; never logged; never sent to the browser. |
| `GITHUB_TOKEN` | Optional | absent | Raises the per-cycle GitHub Advisory cap from 25 to 50 CVEs and removes the 60 req/h anonymous cap. Read only inside the server-side GitHub Advisory fetcher; never logged; never sent to the browser. |

**Effective `THREATPULSE_DATA_ROOT` conclusion:** the
variable is **optional** because the Hostinger runtime
in `hostinger/_lib.mjs#resolveHostingerConfig` derives a
persistent default from `$HOME/threatpulse-state`
(when `HOME` is set) or `./state` (when `HOME` is
unset). The `THREATPULSE_DATA_ROOT` override is
recommended in production so the explicit value can be
audited; absence of the variable does NOT cause the
Hostinger runtime to fail.

## Manifest-only variables (declared in release metadata; no active Hostinger runtime consumer)

The following three names appear only in
`deploy/v6-8-release-manifest.json` and / or Netlify-only
function entry points. They are NOT consumed by the
current public Hostinger application.

| Variable | Status | Notes |
| --- | --- | --- |
| `THREATPULSE_REFRESH_TRIGGER_SECRET` | Declared in release metadata; no active runtime consumer in the current public Hostinger application. | Consumed only by `netlify/functions/refresh-baseline-background.mjs` (Netlify Background Function). The Hostinger managed scheduler and the cron job wrappers are the only refresh triggers on Hostinger. The variable may be safely unset. |
| `THREATPULSE_OSV_ECOSYSTEMS` | Declared in release metadata; no active runtime consumer in the current public Hostinger application. | The default OSV ecosystem list is the source-controlled `config/osv-ecosystems.json`. The env var is consumed only by `netlify/functions/_shared/osvEcosystems.mjs` (Netlify path). The Hostinger path reads from the JSON file. The variable may be safely unset. |
| `THREATPULSE_CREDENTIALS_BLOBS_ACCESS_TOKEN` | Declared in release metadata; no active runtime consumer in the public Hostinger application. Gateway-only by design. | Used only by the private gateway for its own `tpr-private-credentials` Blob store. The public side never reads or sets this variable. |

## Filesystem namespace map

All five Blob-store namespaces live under
`$THREATPULSE_DATA_ROOT/` as sibling subdirectories on
the Hostinger filesystem backend:

| Subdirectory | Content |
| --- | --- |
| `tpr-dataset/` | Primary dataset envelope + refresh lock + NVD cooldown. The `latest-dataset` file is the v5.x public dataset. |
| `tpr-baseline/` | Canonical OSV baseline: `manifests/latest.json`, `source-health`, `source-registry`, version manifests, content-addressed shards. |
| `tpr-vulnrichment/` | CISA Vulnrichment / SSVC cache. |
| `tpr-github-advisory/` | GitHub Advisory Database cache. |
| `tpr-public-intelligence/` | V6.1 public intelligence: `osv/shards/sha256/<hash>.json.gz`, `osv/manifests/latest.json`, `dataset/shards/sha256/<hash>.json.gz`, `dataset/versions/{v}/{manifest.json, snapshot-shards-manifest.json, source-health.json.gz}`, `dataset/latest.json`. |

The four-store parity is proven by
`acceptance-v63-hostinger.mjs` section [18]
(`Hostinger filesystem intelligence-store parity`).

## Baseline storage path

`refresh-baseline` on Hostinger is routed through the
existing storage abstraction, not through the
Netlify Blobs runtime. The full trace:

```
managed scheduler
  → hostinger/cron-refresh-baseline.mjs
  → spawnV62Job('jobs/refresh-baseline.mjs', { THREATPULSE_STORAGE_BACKEND: 'filesystem', THREATPULSE_DATA_ROOT: ... })
  → jobs/refresh-baseline.mjs
  → jobs/_lib.mjs#resolveStorage({ dataRoot, storeName: 'tpr-baseline' })
  → netlify/functions/_shared/storage/index.mjs#createStorageAdapter({ name: 'filesystem', storeName: 'tpr-baseline', opts: { dataRoot } })
  → netlify/functions/_shared/storage/FilesystemStorageAdapter({ dataRoot: $THREATPULSE_DATA_ROOT/tpr-baseline })
  → $THREATPULSE_DATA_ROOT/tpr-baseline/{manifests, versions, shards, source-health, source-registry, publication-lock}
```

**The shared baseline-store abstraction is backed by
`FilesystemStorageAdapter` on Hostinger and persists
under the configured filesystem data root.** The
`netlify/functions/_shared/baselineStore.mjs` helper
(which uses `@netlify/blobs#getStore`) is preserved in
the repository for the Netlify deployment but is not
imported by any Hostinger-runtime code path.

## Scheduler schedule table

The Hostinger managed scheduler (`THREATPULSE_MANAGED_SCHEDULER=1`) is the in-process replacement for the OS-level cron. All six logical jobs are present:

| Label | Script | Schedule (UTC) | Lock |
| --- | --- | --- | --- |
| `dataset-refresh` | `jobs/refresh-dataset.mjs` | minute 0 and 30 of every hour | `dataset-refresh` |
| `baseline-refresh` | `jobs/refresh-baseline.mjs` | minute 10 of every hour | `baseline-refresh` |
| `dataset-publish` | `jobs/publish-dataset-intelligence.mjs` | minute 20 and 50 of every hour | `dataset-publish` |
| `public-intel-gc` | `jobs/gc-public-intelligence.mjs` | minute 25 of every hour | `public-intel-gc` |
| `state-verify` | `jobs/verify-state.mjs` | 06:30 UTC daily | `state-verify` |
| `backup` | `hostinger/backup.mjs` (in-process entry) | 02:40 UTC daily | `backup` |

The bootstrap option (`THREATPULSE_MANAGED_SCHEDULER_BOOTSTRAP=1`) schedules a one-shot `dataset-refresh` shortly after startup when `$THREATPULSE_DATA_ROOT/dataset/latest.json` is missing. Bootstrap is opt-in.

The scheduler uses `setTimeout` (never `setInterval`), one timer per label, retried after every execution. The scheduler's `stop()` clears every active timer and waits up to 5s for in-flight jobs during shutdown.

## 24–48 hour observation checklist

The following observation signals must all hold before
declaring the V6.8 migration fully closed and the
Netlify public site eligible for net-only operation.

### First 30 minutes — initial health

| Signal | What to look for | Recovery action |
| --- | --- | --- |
| Hostinger `/health` | HTTP 200 with `{"status":"ok"}` | Check `hostinger/cron-refresh-*.log` and `THREATPULSE_LOG_DIR/*.jsonl`. |
| Hostinger `/ready` | HTTP 200 with `{"ready":true}` | If `ready:false`, check `$THREATPULSE_DATA_ROOT/tpr-dataset/latest-dataset` and the readiness report. |
| Hostinger `/api/dataset` | HTTP 200 with the populated dataset envelope; `publicIntelligenceStatus: "available"`, `publicIntelligenceVersion` non-null, `publicStateFingerprint` non-null. | Inspect the dataset-bound publication chain (`lastV61DatasetBoundRefresh.published === true`). |
| Hostinger `/.netlify/functions/dataset` | HTTP 200 with a body byte-identical (or JSON-equivalent) to `/api/dataset` | The compatibility alias is broken; inspect the route registration. |
| `/.netlify/functions/refresh-dataset-background` | HTTP 404 (closed) | If not 404, the compatibility sink is broken. |
| `POST/PUT/PATCH/DELETE *` | HTTP 405 with `Allow: GET, HEAD` | If a non-405 is returned, the method allowlist is broken. |
| Browser console | No new console errors; "Data route: same-origin" pill visible | None — informational. |
| `lastV61DatasetBoundRefresh` | `published: true`, `error` empty | If `skipped: true`, inspect `reason`. A persistent `reason: 'snapshot-oversize'` is unexpected after the sharding hotfix. |

### First 6 hours — publication chain health

| Signal | What to look for | Recovery action |
| --- | --- | --- |
| `managed-scheduler.activated` log line | The scheduler started after the HTTP server began listening | None — informational. |
| `managed-scheduler.scheduled` log line per entry | All six jobs have a scheduled next occurrence | Investigate when a job is missing. |
| `cron.lock.held` warnings | Another process holds the cron lock | Investigate duplicate processes; do NOT delete the lock. |
| `cron.done` `status: 'lock-held'` | A concurrent run was already in progress | None — the next scheduled occurrence is still armed. |
| `lastV61DatasetBoundRefresh` over multiple cycles | `published: true` repeatedly, `skipped: false` for every cycle | A persistent skip means a structural defect; investigate. |
| `lastNVDRefresh` 429 / 5xx / timeout | NVD transient failure | The V5.4.2 quality guard preserves the previous envelope; the NVD cooldown marker is set; the public status is honestly `partial`. |
| `public-snapshot uncompressed size … exceeds ceiling` | A pre-sharding error path fired | This should not occur after the V6.8 sharding hotfix. If it does, the per-CVE record is unexpectedly large and warrants a per-record field-cap review. |
| `Source-health states` | `fresh` or `unavailable` (never `error`) | Inspect the refresh logs. |
| `Dataset store: latest available` pill | Visible in the header when `dataSource === 'prebuilt-store'` | None — informational. |

### First 24–48 hours — long-term stability

| Signal | What to look for | Recovery action |
| --- | --- | --- |
| Scheduled-run reliability | The managed scheduler completes on every cadence for 24+ hours | Inspect the cron logs. |
| Last-known-good behaviour | The "Last refresh" pill is updated on every refresh | Inspect `$THREATPULSE_DATA_ROOT/tpr-dataset/latest-dataset` mtime. |
| Source recovery and stale transitions | A source that goes `unavailable` recovers automatically | Inspect the source-health state machine. |
| No fabricated changes | The "What changed" panel reports no fabricated previous-version changes | Roll back if fabricated changes are present. |
| Backup archives | A backup archive appears in `$THREATPULSE_BACKUP_DIR` every day at 02:40 UTC | Inspect `hostinger/cron-backup.log` and `$THREATPULSE_LOG_DIR/*.jsonl`. |
| Public CSV | 21 columns, public route returns the same shape | None — informational. |
| `client/**` and `netlify/gateway/**` byte-equivalence to `32a8a63` | Diff is empty | None — informational. |

## Conditions required before disabling the Netlify public site

The following conditions must all hold before the
operator may disable the Netlify public site
(`https://threatpulse-radar.netlify.app`):

1. The Hostinger deployment has completed the 24–48
   hour observation window with no rollback
   recommended / required status.
2. The `scripts/verify-v68-hostinger-migration-closure.mjs`
   suite passes (11 assertions, including the
   no-`netlify/gateway/`-import assertion, the no
   private-gateway-credential-variable assertion, and
   the no public write / refresh / admin route
   assertion).
3. The `scripts/verify-v68-release.mjs` preflight
   suite passes (25 assertions).
4. The Hostinger production smoke
   (`scripts/smoke-v68-production.mjs` with
   `--public-url=https://threatpulse.namanp.de` and
   `--gateway-url=<existing-gateway-if-any>`) passes
   (5 dry-run assertions and the explicit
   `--execute` checks).
5. The V6.3 Hostinger acceptance suite passes
   (425 tests, including the V6.8 sharding section
   and the V6.8 dataset-route compatibility section).
6. The V6.8 release-candidate suite passes (25 tests,
   including the mobile responsiveness test).
7. The Hostinger production domain is documented as
   canonical in the public `README.md`,
   `CHANGELOG.md`, and this closure document.
8. The Netlify public site is explicitly downgraded
   to "rollback-only during observation" in
   `deploy/v6-8-release-manifest.json` and the
   `docs/v6-8-controlled-deployment-runbook.md`.

## Rollback conditions (roll back to the Netlify public site)

The operator SHOULD roll back to the Netlify public site
when ANY of the following occur:

- **Last-known-good is unavailable.** The
  `lastV61DatasetBoundRefresh.published === true`
  signal fails to appear within 4 consecutive
  scheduled cycles, AND the `dataset/latest.json` on
  Hostinger is stale (mtime > 1 hour behind the
  expected publish time).
- **Snapshot sharding is unstable.** A
  `snapshot-shard-write-failed` /
  `snapshot-shard-manifest-write-failed` /
  `snapshot-shard-manifest-invalid` / `snapshot-oversize`
  log line appears in 3 consecutive cycles.
- **Method allowlist is broken.** A non-`GET` /
  non-`HEAD` request returns a non-`405` response
  against any of the public paths.
- **Provider-specific label leaked.** "Proxy: Netlify"
  appears in the user-visible header, or the
  compatibility alias returns a body that is not
  byte-equivalent to `/api/dataset`.
- **Public write / refresh / admin endpoint exposed.**
  A path under `/api/refresh`, `/api/admin`,
  `/api/credential`, or any equivalent returns a
  non-`404` response.
- **Repeated 500 / 503 on `/api/dataset`.** More than 3
  `500 Internal Server Error` responses within 30
  minutes, AND the most recent `cron.done` log line
  reports a status other than `ok` or `lock-held`.

The exact rollback procedure is documented in
`docs/v6-8-rollback-plan.md`. The Hostinger deployment
is preserved across the rollback; only the canonical
production domain is switched back to Netlify.

## Source-control consolidation status

The Hostinger hotfix series is NOT yet merged to
`main`. The `main` branch is at the V5.7 / V6.0
baseline (`32a8a63`); the V6.8 release-candidate
(`v6-8-release-candidate-consolidation` at `0480a9f`)
is the head of the next-line branch. The V6.8
deployment-preparation branch
(`release/v6-8-deployment-preparation` at `d3240dd`)
is the second-line branch. The V6.8 Hostinger hotfix
series (`2afc1aa` → `5df64d5` → `27ce6be` →
`c07c464` → `abb60b8` → `c0a14cc`) is stacked on top of
the V6.8 release-candidate. The
`release/v6-8-hostinger-migration-closure` branch
(this document) is stacked on top of the Hostinger
hotfix series and is the head of the Hostinger
production line.

A future V6.9 (or V8) "post-deployment consolidation"
branch is the natural next step: it would merge the V6.8
release-candidate, the V6.8 deployment-preparation, the
V6.8 Hostinger hotfix series, and this closure branch
into `main` in a single well-tested PR. That PR is NOT
part of this milestone.

## Closure script

`scripts/verify-v68-hostinger-migration-closure.mjs`
is the bounded static verification for this closure
contract. It asserts 11 invariants:

1. Hostinger route ownership
2. Non-dataset `/.netlify/functions/*` paths are closed
3. No public Hostinger runtime import from `netlify/gateway/`
4. No public source references the private gateway credential variables
5. Filesystem storage namespaces are documented
6. Managed scheduler contains all six logical schedules
7. Provider-neutral Header labels and no legacy "Proxy: Netlify"
8. CSV remains exactly 21 columns
9. Exactly 5 public Netlify function entries and 1 gateway function entry
10. `client/**` and `netlify/gateway/**` are unchanged against the documented baseline
11. No public refresh / admin / write HTTP route exists

Run with `node scripts/verify-v68-hostinger-migration-closure.mjs`.
