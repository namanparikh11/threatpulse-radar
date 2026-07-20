# V6.8 — Environment variable checklist

This document lists every environment variable the
V6.8 application reads. The list contains **names
only**. No actual value is included in this
document, in the release manifest, in the runbooks,
or in any commit. The operator is responsible for
maintaining the actual values in the Netlify UI and
in a password manager.

## Classification

Every variable in this checklist is classified as:

- **public / gateway** — the Netlify project that
  must define the variable
- **required / optional** — required variables must
  be defined for the application to function;
  optional variables are only required for a
  specific feature or environment
- **production-only / other context** — the variable
  is required only on the production deploy, or is
  shared across the production, preview, and branch
  deploy contexts
- **runtime scope** — the variable is read at
  function cold-start, per request, or at build time
- **sensitive / non-sensitive** — sensitive variables
  are credentials, tokens, or shared secrets. They
  must NEVER be logged, screenshotted, or pasted
  into chat
- **source of the value** — Netlify UI, password
  manager, or external
- **verification method** — how the operator
  confirms the variable is set correctly
- **rotation implications** — the consequence of
  rotating the value
- **redeploy required** — whether changing the value
  requires a redeploy

## Public site (threatpulse-radar-public)

| Variable | Required | Scope | Sensitive | Source | Verification | Rotation impact | Redeploy |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `THREATPULSE_REFRESH_TRIGGER_SECRET` | required | production-only | yes | password manager | confirm the public-site refresh trigger returns 200 | invalidates the scheduled job handler; rotate via Netlify UI | yes |
| `THREATPULSE_OSV_ECOSYSTEMS` | required | all contexts | no | Netlify UI (JSON string) | confirm the OSV projection writes successfully | no rotation required | yes |
| `THREATPULSE_STORAGE_BACKEND` | required | all contexts | no | Netlify UI | confirm the dataset function returns a valid envelope | no rotation required | yes |
| `THREATPULSE_SITE_ID` | optional | runtime-only | no | auto-populated | n/a | n/a | n/a |
| `THREATPULSE_BLOBS_TOKEN` | optional | runtime-only | yes | auto-populated | n/a | n/a | n/a |
| `THREATPULSE_DATA_ROOT` | optional | runtime-only | no | Netlify UI (filesystem only) | confirm the filesystem adapter can read | no rotation required | yes |

The `THREATPULSE_SITE_ID` and `THREATPULSE_BLOBS_TOKEN`
variables are auto-populated by the Netlify runtime
when `THREATPULSE_STORAGE_BACKEND=netlify`. They are
not required in the Netlify UI.

## Gateway site (threatpulse-radar-gateway)

| Variable | Required | Scope | Sensitive | Source | Verification | Rotation impact | Redeploy |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `THREATPULSE_BASELINE_SITE_ID` | required | production-only | no | Netlify UI | confirm the gateway can read the public `tpr-baseline` store | requires a redeploy; no credential change | yes |
| `THREATPULSE_BLOBS_ACCESS_TOKEN` | required | production-only | yes | password manager | confirm the gateway can read the public `tpr-baseline` store | token rotation requires issuing a new Netlify Blobs access token; no operator impact | yes |
| `THREATPULSE_CREDENTIAL_PEPPER` | required | production-only | yes | password manager | confirm the gateway returns 401 for anonymous requests and 200 for authorized requests | invalidates every existing private credential; emergency rotation only | yes |
| `THREATPULSE_CREDENTIALS_BLOBS_ACCESS_TOKEN` | optional | production-only | yes | Netlify UI | confirm the gateway can write to the `tpr-private-credentials` store | token rotation requires issuing a new Netlify Blobs access token; no operator impact | yes |

## Forbidden patterns

The following patterns are FORBIDDEN. The V6.8 release
preflight (`scripts/verify-v68-release.mjs`) flags
every violation.

- **`VITE_*` secrets.** Any environment variable
  whose name starts with `VITE_` is inlined into the
  client bundle at build time. A `VITE_*` secret
  would leak to every browser. The preflight flags
  any source line that mentions
  `VITE_SECRET`, `VITE_TOKEN`, `VITE_PASSWORD`,
  `VITE_PRIVATE`, or `VITE_CREDENTIAL`.
- **Secrets in Git.** No `.env` file (other than
  `.env.example`, which is documentation only) and no
  `secrets.json` / `secrets.yaml` / `secrets.toml`
  file is committed to the repository. The preflight
  flags every such file.
- **Secrets in screenshots.** When taking
  screenshots of the Netlify UI, mask every
  environment variable value. The preflight does NOT
  enforce this; it is the operator's responsibility.
- **Secrets in command history.** The
  `scripts/smoke-v68-production.mjs` script
  explicitly refuses to read any environment
  variable from the command line. The
  `THREATPULSE_CREDENTIAL_PEPPER` and the
  `THREATPULSE_BLOBS_ACCESS_TOKEN` are read from
  environment variables that the operator must
  export in the shell session that runs the smoke
  test.
- **Secrets in generated manifests.** The
  `deploy/v6-8-release-manifest.json` file contains
  names only. The preflight verifies that no
  high-entropy string is present.
- **Secrets pasted into chat.** This is a human
  policy; no automated check can enforce it.

## Verification sequence

The operator runs the following sequence before
PHASE 1 (merge approval) and again before PHASE 2
(publishing approval).

1. Open the public Netlify site → Environment.
2. Confirm every required public-site variable is
   set. Confirm the value matches the password
   manager. Mask the value in any screenshot.
3. Open the gateway Netlify site → Environment.
4. Confirm every required gateway-site variable is
   set. Confirm the value matches the password
   manager. Mask the value in any screenshot.
5. Run `node scripts/verify-v68-release.mjs`. The
   preflight exits 0 if every check passes.

## Redeploy matrix

| Action | Redeploy required |
| --- | --- |
| Change a `THREATPULSE_REFRESH_TRIGGER_SECRET` value | yes |
| Change a `THREATPULSE_OSV_ECOSYSTEMS` value | yes |
| Change a `THREATPULSE_STORAGE_BACKEND` value | yes |
| Change a `THREATPULSE_BASELINE_SITE_ID` value | yes |
| Change a `THREATPULSE_BLOBS_ACCESS_TOKEN` value | yes |
| Change a `THREATPULSE_CREDENTIAL_PEPPER` value | yes (emergency rotation) |

## Hostinger Business managed-Node scheduler (optional)

For Hostinger Business managed-Node deployments
that do not expose an OS-level cron, the
application ships an opt-in in-process scheduler.
The variable names are listed below; no values are
documented here.

| Variable | Required | Runtime scope | Sensitive | Source | Verification | Rotation impact | Redeploy |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `THREATPULSE_MANAGED_SCHEDULER` | optional | runtime-only | no | Hostinger UI | confirm `/health` reports `{"status":"ok"}` and the log line `managed-scheduler.activated` appears | none (start/stop only) | yes |
| `THREATPULSE_MANAGED_SCHEDULER_BOOTSTRAP` | optional | runtime-only | no | Hostinger UI | confirm the bootstrap log line `managed-scheduler.bootstrap.scheduled` appears when the dataset is missing, or `managed-scheduler.bootstrap.skipped` when it exists | none (start/stop only) | yes |

`THREATPULSE_MANAGED_SCHEDULER` accepts the literal
value `1`. Every other value (unset, empty, `true`,
`yes`, `on`, anything else) keeps the scheduler
disabled.

`THREATPULSE_MANAGED_SCHEDULER_BOOTSTRAP` accepts
the literal value `1`. Every other value disables
the startup bootstrap.

When the scheduler is enabled:

- The application reuses the same
  `hostinger/cron-*.mjs` job implementations and the
  same `hostinger/locks.mjs` mkdir-based locks. No
  provider, storage, publication, or canonicalization
  logic is duplicated.
- Timers are process-local. Cross-process exclusion
  is provided by the existing mkdir-based cron
  locks; multiple managed processes cannot
  concurrently mutate the same job state.
- The scheduler does NOT add a public HTTP trigger
  route. The bootstrap, when enabled, inspects the
  dataset on the local filesystem only.
- A process restart is safe: the scheduler starts
  again from the next calculated UTC occurrence, the
  bootstrap is retried when the dataset is missing,
  and the existing locks prevent duplicate active
  jobs.
- The standalone `hostinger/cron-*.mjs` entrypoints
  remain available for VPS deployments and for
  operator-run ad-hoc schedules. The managed
  scheduler is an additive compatibility layer, not
  a replacement.
| Add a new variable to the public site | yes |
| Add a new variable to the gateway site | yes |
| Remove a variable from the public site | yes |
| Remove a variable from the gateway site | yes |

## References

- `deploy/v6-8-release-manifest.json` — machine-readable
  release manifest
- `docs/v6-8-controlled-deployment-runbook.md` —
  phased deployment procedure
- `scripts/verify-v68-release.mjs` — release
  preflight
