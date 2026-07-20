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
