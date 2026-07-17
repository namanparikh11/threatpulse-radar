# V6.8 — Deployment cost controls

This document describes how the operator minimizes
deployment and runtime credit use during the V6.8
release. **No claim about specific Netlify pricing
or quota numbers is made.** The controls below are
operational best practices, not architecture facts.

## Pre-deployment controls

### Before PHASE 1 (merge approval)

1. **Configure every required environment variable
   before deploying.** A deployment with missing
   environment variables will run but fail at the
   first function invocation. The operator should
   run `node scripts/verify-v68-release.mjs` to
   confirm every required variable is set.

2. **Avoid repeated production deployments.** Each
   production deployment is a new build + publish
   cycle. The operator should batch all V6.8 changes
   into a single commit and a single deployment.

3. **Avoid merging unrelated changes.** The
   `release/v6-8-deployment-preparation` branch
   carries only release-preparation files. The
   operator should not merge in unrelated changes
   from other branches during the V6.8 release.

4. **Use local builds and local smoke tests first.**
   The operator should run `npm.cmd run build` and
   `node scripts/smoke-v68-local.mjs` before
   triggering a production deployment. A failed
   local build or a failed local smoke test is a
   signal to NOT trigger a production deployment.

5. **Understand that both projects deploy from
   `main`.** The public site and the gateway site
   deploy from the same `main` branch. The gateway
   site uses a different Netlify UI "Base directory"
   (`netlify/gateway/`). A single merge to `main`
   triggers a build for both projects.

6. **Ensure preparation is complete before unlocking
   publishing.** The operator should not unlock
   production publishing until PHASE 0 (preparation)
   is complete. Unlocking publishing without
   preparation can trigger a partial build that
   fails in production.

## Runtime controls

### During the first 24 hours

1. **Avoid manually triggering scheduled or
   background work repeatedly.** Each manual
   trigger counts as a Netlify function invocation.
   The scheduled and background functions are
   designed to run on the documented cadence. The
   operator should let the cadence drive the
   invocations.

2. **Observe actual consumption after release.** The
   operator should open the Netlify credit dashboard
   for both projects and compare the V6.8
   consumption to the V6.7 baseline. The V6.8
   release does NOT add new function invocations on
   top of the V6.7 cadence.

3. **Stop optional jobs if abnormal consumption
   appears.** If the V6.8 release triggers an
   unexpected burst of function invocations, the
   operator can disable the optional
   `refresh-dataset-background` and
   `refresh-baseline-background` functions in the
   Netlify UI. The `refresh-dataset-scheduled` and
   `refresh-baseline-scheduled` functions continue
   to run on their cron cadence.

### During the first 7 days

1. **Compare function log sizes.** The V6.8 release
   should produce function logs of similar size to
   the V6.7 release. A log size increase of more
   than 10% is a signal to investigate.

2. **Compare Blob store sizes.** The V6.8 release
   should produce Blob store updates of similar
   size to the V6.7 release. A Blob store size
   increase of more than 10% is a signal to
   investigate.

3. **Compare scheduled-run counts.** The V6.8
   release does NOT add new scheduled jobs. The
   scheduled-run count should match the V6.7
   baseline.

## What is NOT controlled by this document

- This document does NOT set Netlify credit
  thresholds. The operator configures the credit
  thresholds in the Netlify UI.
- This document does NOT optimize function code. The
  V6.8 function code is identical to the V6.7
  function code.
- This document does NOT add caching. The V6.8
  release does not add or remove caching.
- This document does NOT change the public dataset
  shape. The V6.8 release preserves the V6.7
  public dataset shape.

## What is NEVER acceptable

- Manually triggering a function to test it in
  production. The operator should use the local
  smoke test (`scripts/smoke-v68-local.mjs`) and
  the production smoke test
  (`scripts/smoke-v68-production.mjs --execute`).
- Deploying from a feature branch. The V6.8 release
  deploys only from `main`.
- Manually editing a Blob store. The V6.8 release
  does not provide a manual Blob store editor. The
  operator should let the scheduled jobs manage
  the Blob stores.

## References

- `docs/v6-8-controlled-deployment-runbook.md` —
  phased deployment procedure
- `docs/v6-8-production-observation-plan.md` —
  observation windows
- `scripts/smoke-v68-local.mjs` — local smoke test
- `scripts/smoke-v68-production.mjs` — production
  smoke test
