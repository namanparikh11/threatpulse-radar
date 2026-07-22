# V6.8 — Production observation plan

This document describes the observation windows the
operator runs after the V6.8 production deployment.
**No claim of production stability should occur
before every observation window completes.**

The release is **honest about what it is**. The
release is a single controlled release of a
defensive cybersecurity intelligence product. It is
NOT enterprise-certified, legally admissible,
complete, or independently audited.

## Observation windows

### First 30 minutes — initial health

| Signal | What to look for | Recovery action |
| --- | --- | --- |
| Public site availability | HTTP 200 on `/` and the SPA root | Netlify UI "Publish deploy" rollback |
| Function errors | 0 errors in the public-site logs | Inspect the function log; revert if the error is reproducible |
| Gateway authentication | 401 for anonymous requests | Verify the gateway environment variables |
| Static assets | The main bundle and the worker chunks load with HTTP 200 | Inspect the build output |
| Private / public isolation | The `private-sync-gateway` path on the public site returns 404 | Revert immediately if exposed |
| First dataset response | A sanitized valid envelope is returned | Inspect the function log if the envelope is malformed |

### First 6 hours — publication chain health

| Signal | What to look for | Recovery action |
| --- | --- | --- |
| Dataset refresh | The `tpr-dataset` Blob store updates on schedule | Inspect the `refresh-dataset-background` logs |
| Baseline refresh | The `tpr-baseline` Blob store updates on schedule | Inspect the `refresh-baseline-background` logs |
| Dataset-bound publication | The `tpr-vulnrichment` and `tpr-github-advisory` Blob stores update on schedule | Inspect the scheduled function logs |
| OSV projection | The OSV projection writes successfully | Inspect the `refresh-dataset-background` logs |
| Garbage collection | The `cron-gc` job reports a successful run | Inspect the cron log |
| Blob operation patterns | No unexpected bursts | Inspect the Netlify credit dashboard |
| Source-health states | All public sources report `ok` or `unavailable` (never `error`) | Inspect the `refresh-baseline-background` logs |
| No fabricated changes | The "What changed" panel reports no fabricated previous-version changes | Roll back if fabricated changes are present |

### Hostinger Business managed-Node scheduler (when enabled)

When `THREATPULSE_MANAGED_SCHEDULER=1` is set on a
managed-hosting deployment, the in-process scheduler
runs inside the same Node process as the HTTP
server. Additional observation signals:

| Signal | What to look for | Recovery action |
| --- | --- | --- |
| `managed-scheduler.activated` log line | The scheduler started after the HTTP server began listening | None — informational |
| `managed-scheduler.scheduled` log line per entry | Each of the six jobs has a scheduled next occurrence | Investigate when a job is missing |
| `managed-scheduler.bootstrap.scheduled` / `.skipped` log line | Bootstrap was scheduled when the dataset was missing and skipped when present | None — informational |
| `cron.lock.held` warnings | Another process holds the cron lock | Investigate duplicate processes; do NOT delete the lock |
| `cron.signal` log lines | The application received SIGINT or SIGTERM | Confirm the Hostinger control panel initiated the restart |
| `managed-scheduler.stopped` log line on shutdown | The scheduler cleared every active timer before exit | None — informational |
| `managed-scheduler.error` log line | A job threw an unhandled exception | Inspect the inner job's logs; the lock is released before the next occurrence is scheduled |
| `cron.done` `status: 'lock-held'` | A concurrent run was already in progress | None — the next scheduled occurrence is still armed |
| `spawn.error` log line with `code: 'ENOENT'` and `runtimeExecutable: 'process.execPath'` | The OS rejected the child-process spawn. ENOENT after the `process.execPath` hotfix is unexpected; investigate whether the runtime replaced the Node binary or stripped execute permission | Reapply the hotfix; if EPERM/EACCES appears instead, the runtime forbids child processes and an in-process job adapter is required |
| `spawn.error` log line with `code: 'EPERM'` or `code: 'EACCES'` | The runtime forbids child processes entirely | The current executable-resolution hotfix does NOT cover this case. Plan a follow-up that re-implements the scheduled jobs as in-process job adapters |
| `managed-scheduler.spawn-failed` log line | The scheduler caught a sanitized `spawnError` and will rearm the next occurrence | The job is reported as `invalid-args`; the next scheduled occurrence is still armed |

### Filesystem intelligence-store health (Hostinger)

When `THREATPULSE_STORAGE_BACKEND=filesystem` is set
on a managed-hosting deployment, every Blob store the
public pipeline depends on is rooted at the same
`$THREATPULSE_DATA_ROOT`. Additional observation
signals:

| Signal | What to look for | Recovery action |
| --- | --- | --- |
| Subdirectory `tpr-dataset/latest-dataset` exists | The primary dataset envelope is on disk | None — informational |
| Subdirectory `tpr-vulnrichment/cache` exists | The Vulnrichment cache envelope is on disk | None — informational |
| Subdirectory `tpr-github-advisory/cache` exists | The GitHub Advisory cache envelope is on disk | None — informational |
| Subdirectory `tpr-public-intelligence/dataset/latest.json` exists | The V6.1 dataset-bound publication is on disk | None — informational |
| `dataset/latest.json` mtime stops advancing | A size ceiling or a write error has been hit; the previous envelope is preserved | Inspect the V6.1 publication log; do NOT delete `latest.json`; plan a follow-up if the size ceiling is the cause |
| `Vulnrichment cache write failed` log line | The Vulnrichment write to `tpr-vulnrichment/cache` failed | The previous cache envelope is preserved; the next cycle retries. If the failure persists, check the filesystem write permissions on `$THREATPULSE_DATA_ROOT/tpr-vulnrichment/` |
| `public-intelligence-store-unavailable` log line | The public-intelligence store could not be opened | Confirm `THREATPULSE_DATA_ROOT` is set and the subdirectory is writable |
| `public-snapshot uncompressed size … exceeds ceiling` log line | The V6.1 dataset-bound publication is a structured skip; the previous `latest.json` is preserved | Plan a follow-up; do NOT delete the previous `latest.json`. The hotfix preserves the last-known-good state |
| NVD `status: 'partial'` or `lastNDVRefresh.reason` mentions `429` | NVD HTTP 429 (rate-limit) is in effect | The refresh orchestrator is preserving the previous better envelope and recording an NVD cooldown marker. The CISA KEV primary dataset remains serviceable |

### Dataset route compatibility alias (Hostinger)

When the V6.8 frontend reaches the Hostinger deployment
through the `/.netlify/functions/dataset` alias, the
following signals are expected:

| Signal | What to look for | Recovery action |
| --- | --- | --- |
| `GET /api/dataset` returns 200 with `mode: 'live'` | The canonical Hostinger route serves the populated dataset | None — informational |
| `GET /.netlify/functions/dataset` returns 200 with the same body as `/api/dataset` | The compatibility alias is wired and serves the populated dataset | None — informational |
| `GET /.netlify/functions/dataset?view=osv&...` returns 200 or 400 | The OSV view is forwarded | None — informational |
| `GET /.netlify/functions/dataset?view=changes&...` returns 200 or 400 | The change panel is forwarded | None — informational |
| `POST / PUT / PATCH / DELETE /.netlify/functions/dataset` returns 405 | The method allowlist is enforced; no write is reachable through the alias | None — informational |
| `GET /.netlify/functions/refresh-dataset-background` returns 404 | The refresh path is NOT exposed on the Hostinger deployment | None — informational. The managed Hostinger scheduler is the only refresh mechanism |
| `GET /.netlify/functions/private-sync-gateway` returns 404 | The gateway is NOT exposed on the Hostinger deployment | None — informational |
| `GET /.netlify/functions/` returns 404 | The path prefix is NOT exposed | None — informational |
| `GET /.netlify/functions/dataset` returns a body identical to `GET /api/dataset` | The alias forwards the exact same response | None — informational |
| `GET /api/dataset` returns a body different from `GET /.netlify/functions/dataset` | The alias is out of sync with the canonical route | Inspect `hostinger/app.mjs` and confirm both routes call the same `handleDataset` |

### Public-snapshot size boundary (deterministic sharding)

When the V6.8 public-snapshot size boundary is in
effect (Hostinger managed-Node redeploy of
`hostinger/v6-8-public-snapshot-size-boundary`), the
following signals are expected:

| Signal | What to look for | Recovery action |
| --- | --- | --- |
| `publicIntelligenceStatus: "available"` on `/api/dataset` | The V6.1 dataset-bound publication succeeded | None — informational |
| `publicIntelligenceVersion` is non-null | A new dataset-bound version was written | None — informational |
| `publicStateFingerprint` is non-null (12 hex chars) | The composite logical fingerprint is present | None — informational |
| `lastV61DatasetBoundRefresh.published === true` | The dataset-bound chain published successfully | None — informational |
| `lastV61DatasetBoundRefresh.published !== true` AND `lastV61DatasetBoundRefresh.skipped === true` | The dataset-bound chain skipped this cycle; the previous `latest.json` is preserved | Inspect the `reason` and `error` fields. A persistent skip with `reason: 'snapshot-oversize'` is unexpected after the sharding hotfix; the per-shard ceiling should always be met for the production CISA KEV universe |
| `snapshotShardsManifestContentHash` is present in `dataset/latest.json` | The shard manifest is wired into the latest.json pointer | None — informational |
| `snapshotShardsCount >= 2` on a typical publication | The sharding actually partitioned the logical snapshot into multiple shards | None — informational. A `snapshotShardsCount === 1` is a degenerate single-shard case (very small dataset); the sharding layer is still in effect |
| A per-version `snapshot-shards-manifest.json` exists under `dataset/versions/{v}/` | The per-version shard manifest is on disk | None — informational |
| At least one content-addressed shard exists under `dataset/shards/sha256/<hash>.json.gz` | The shards are on disk | None — informational |
| `shard-write-failed` log line | A shard write failed; the previous `latest.json` is preserved | Investigate disk permissions or adapter error. The atomic commit guarantees the previous pointer remains valid |
| `snapshot-shard-manifest-write-failed` log line | The per-version shard manifest write failed; the previous `latest.json` is preserved | Investigate disk permissions or adapter error |
| `snapshot-shard-manifest-invalid` log line | The shard manifest failed structural verification; the previous `latest.json` is preserved | This should be impossible under normal operation; collect the manifest body for analysis |
| `snapshot-shard-compressed-ceiling-exceeded` log line | A single shard exceeded the per-shard compressed ceiling (192 KiB); the previous `latest.json` is preserved | This should not occur for the production CISA KEV universe; if it does, the per-CVE record is unexpectedly large and warrants an investigation |
| `missing-stard` or `corrupt-shard` from the read path | A reader detected a missing or corrupt shard | The read returns a structured failure with a sanitized reason; the previous `latest.json` (if any) remains the last-known-good |
| NVD `lastNDVRefresh.reason` mentions `429` or `timeout` | NVD is rate-limiting or timing out; the dataset envelope carries a partial-enrichment state | The refresh orchestrator preserves the previous NVD-enriched envelope. The CISA KEV primary dataset remains serviceable |
| `public-snapshot uncompressed size … exceeds ceiling` log line | The legacy (pre-sharding) error path fired; the per-shard ceiling is below the per-object ceiling | This should not occur after the sharding hotfix. If it does, the per-CVE record is unexpectedly large (above 768 KiB uncompressed) and warrants a per-record field-cap review |

### First 24–48 hours — long-term stability

| Signal | What to look for | Recovery action |
| --- | --- | --- |
| Scheduled-run reliability | The scheduled jobs complete on every cadence for 24+ hours | Inspect the cron logs |
| Last-known-good behavior | The "last refresh" pill is updated on every refresh | Inspect the `tpr-baseline` Blob store |
| Source recovery and stale transitions | A source that goes `unavailable` recovers automatically | Inspect the source-health state machine |
| Netlify credit consumption | No abnormal credit consumption | Inspect the Netlify credit dashboard |
| Browser errors | No unexpected console errors in production | Inspect the browser console |
| Local migration complaints | No user reports of migration failures | Open a hotfix branch |
| Report / environment / remediation loading | All three local surfaces load and round-trip a representative record | Inspect the local database adapters |
| No private-data network leakage | No network request carries a private value | Run the V6.8 runtime privacy instrumentation |

## Release statuses

The release is labeled with one of the following
statuses after every observation window. A status
is only as good as the most recent observation.

| Status | Definition |
| --- | --- |
| deployment successful | The deployment completed and the first 30-minute observation window passed |
| stable under observation | The 6-hour and 24-hour windows passed without rollback triggers |
| degraded but usable | One or more non-release-blocking triggers are present but the public dashboard is reachable |
| rollback recommended | A non-release-blocking trigger has persisted for 6+ hours without a fix path |
| rollback required | A release-blocking trigger is present |

## When to claim production stability

Production stability may be claimed only when:

1. The 24–48 hour observation window is complete.
2. Every "First 30 minutes" and "First 6 hours"
   check has passed at least once.
3. No "rollback required" or "rollback recommended"
   status is active.
4. The production smoke test passes
   (`scripts/smoke-v68-production.mjs --execute`).
5. The release preflight passes
   (`scripts/verify-v68-release.mjs`).

Until all five conditions are met, the release is
**candidate stable**, not **stable**. The V6.8
release does NOT ship with a "production stable"
claim.

## What is NOT observed by this plan

- This plan does NOT collect any private value
  (note, tag, owner, plan / task / evidence
  content, fingerprint, blocker reason, validation
  note, actor label).
- This plan does NOT log any environment-variable
  value.
- This plan does NOT store any operator data.
- This plan does NOT make any deployment decision.
  Every rollback decision is the operator's.

## References

- `docs/v6-8-controlled-deployment-runbook.md` —
  phased deployment procedure
- `docs/v6-8-rollback-plan.md` — rollback triggers
  and actions
- `docs/v6-8-environment-checklist.md` — environment
  variable name list
- `scripts/smoke-v68-production.mjs` — production
  smoke test
- `scripts/verify-v68-release.mjs` — release
  preflight
