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
