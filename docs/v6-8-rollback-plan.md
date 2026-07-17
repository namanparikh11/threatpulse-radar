# V6.8 — Rollback plan

This document describes the rollback triggers and the
reversible actions the operator can take if the V6.8
release degrades production. **No action in this
document is executed automatically.** Every action
requires explicit operator authorization.

The V6.8 release is a single controlled release. The
rollback target is the immediately prior known-good
checkpoint. For V6.8, the prior checkpoint is the
V6.7 commit `9912044` on
`v6-7-local-remediation-evidence`.

## Rollback triggers

The following triggers justify a rollback. Each
trigger is independently sufficient. The operator
may combine multiple triggers.

| Trigger | Severity | Action |
| --- | --- | --- |
| Public dashboard unavailable for 5+ minutes | release-blocking | Revert public deployment to the prior known-good |
| Private route exposed publicly | release-blocking | Revert public deployment; audit access logs |
| Gateway accepts anonymous access | release-blocking | Revert gateway deployment; rotate pepper |
| Scheduled jobs fail repeatedly (3+ consecutive) | release-blocking | Disable new publication; revert public deployment if needed |
| Last-known-good pointer corruption | release-blocking | Stop the next publication; rebuild from canonical sources |
| Public-intelligence bundle mismatch | release-blocking | Revert public deployment; investigate the publishing chain |
| OSV projection corruption | release-blocking | Stop OSV projection; revert public deployment |
| Browser build failure (TypeScript or Vite) | release-blocking | Revert to the prior known-good deployment; investigate the source |
| Local migrations cause widespread user-visible failure | non-blocking | Document the defect; assess whether to defer the migration in a follow-up patch |
| Secrets or internal fields exposed in a public surface | release-blocking | Revert immediately; rotate the affected credential |
| Excessive unexpected Netlify consumption | non-blocking | Disable optional scheduled work; investigate the function-log loop |

## Reversible actions

The following actions are reversible and do NOT
delete data or rotate credentials by default.

1. **Stop or lock new production publication.** The
   operator pauses the next scheduled publication
   by either disabling the cron handler in the
   Netlify UI or by toggling the "publishing locked"
   flag in the `tpr-publish-lock` Blob store.
2. **Revert the production deployment to the prior
   known-good deploy.** The operator uses the
   Netlify UI "Publish deploy" action to roll back
   to the immediately prior successful deploy.
   This does NOT modify the source repository.
3. **Preserve Blobs and local artifacts.** The
   `tpr-baseline`, `tpr-dataset`, `tpr-vulnrichment`,
   and `tpr-github-advisory` Blob stores are NOT
   modified during a rollback. The local IndexedDB
   databases on end-user devices are NOT modified
   during a rollback.
4. **Disable only the failing optional derivation
   where supported.** If the OSV projection is
   failing, the operator can disable the
   `refresh-dataset-background` function while
   keeping the rest of the publication chain
   running. This is the minimum-impact rollback.
5. **Keep the V5.7 / V6.0-compatible public dataset
   available.** The `tpr-baseline` store is
   published by a separate code path and is not
   affected by V6.x deployment rollbacks.
6. **Avoid deleting Blob stores.** Deleting a Blob
   store destroys the public dataset and the
   baseline. Deletion is never a rollback action.
7. **Avoid rotating credentials unless compromise is suspected.** Rotating the
   `THREATPULSE_CREDENTIAL_PEPPER` invalidates
   every existing private credential the operator
   has issued. The pepper is rotated only when
   compromise is suspected, never as a routine
   rollback step.
8. **Collect sanitized logs.** The operator
   downloads the Netlify function logs for the
   affected period and the gateway logs for the
   same period. Logs are reviewed for the rollback
   cause before the rollback is finalized.
9. **Open a bounded hotfix branch.** The operator
   creates a hotfix branch from the prior known-good
   checkpoint and applies the minimum patch needed
   to address the rollback cause. The hotfix is
   shipped as a V6.8.x patch.
10. **Verify the rollback with smoke tests.** The
    operator runs the production smoke test
    (`scripts/smoke-v68-production.mjs --execute`)
    against the rolled-back deploy. All checks must
    pass.

## Known-good checkpoints

The following checkpoints are published branches in
the repository. Every checkpoint is a safe rollback
target.

| Checkpoint | Branch | Commit | Role |
| --- | --- | --- | --- |
| V6.0 / V5.7 baseline | `v6-0-canonical-baseline` | `32a8a63` (merge base) | cold baseline |
| V6.1 | `v6-1-public-intelligence` | derived from `32a8a63` | public intelligence |
| V6.2 | `v6-2-portability` | derived from V6.1 | portability |
| V6.3 | `v6-3-hostinger` | derived from V6.2 | Hostinger |
| V6.4 | `v6-4-local-workspace` | derived from V6.3 | local workspace |
| V6.5 | `v6-5-local-briefings-and-reports` | derived from V6.4 | briefings + reports |
| V6.6 | `v6-6-local-environment` | derived from V6.5 | local environment |
| V6.7 | `v6-7-local-remediation-evidence` | `9912044` | local remediation |
| V6.8 RC | `v6-8-release-candidate-consolidation` | `0480a9f` | V6.8 release candidate |

The V6.8 release-candidate is the **forward**
checkpoint. The **rollback** target is the V6.7
commit `9912044`.

## What is NOT done by this plan

- This plan does NOT delete the `tpr-baseline`,
  `tpr-dataset`, `tpr-vulnrichment`,
  `tpr-github-advisory`, or `tpr-private-credentials`
  Blob stores.
- This plan does NOT rotate the
  `THREATPULSE_CREDENTIAL_PEPPER`.
- This plan does NOT force-push to any branch.
- This plan does NOT modify the V6.8 commit
  `0480a9f`.
- This plan does NOT call Netlify, Hostinger, or
  any provider.

## Recovery verification

After a rollback, the operator confirms:

- The public dashboard returns the prior known-good
  dataset.
- The `tpr-baseline` store is intact and matches the
  prior known-good sha256.
- The local IndexedDB databases on end-user devices
  are NOT modified.
- The gateway authentication contract is intact.
- The scheduled jobs resume on the prior known-good
  cadence.
- The "What changed" panel does not show fabricated
  changes.

The operator records the rollback cause, the
rollback duration, and the recovery verification
results in the project issue tracker. The rollback
is closed when the recovery verification passes.
