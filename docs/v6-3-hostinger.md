# V6.3 — Hostinger Business Runtime Readiness

ThreatPulse Radar can now run as a production
workload on a Hostinger Business managed-hosting
plan. This document is the operator's guide: it
answers every question in the V6.3 milestone
through executable code and concrete configuration
examples.

The V6.3 milestone does **not** deploy anything.
It produces a runnable, testable package that the
operator can wire to a Hostinger Business Node.js
hosting account when they are ready.

## Product goal

Convert the V6.2 hosting-portability foundation
into a concrete, testable Hostinger Business
runtime. The runtime:

- starts as a Node.js application
- serves the public dashboard and the V6.1 API
  from a single port
- runs every scheduled job through Hostinger cron
- stores all state on the host's local filesystem
- verifies the data root before accepting requests
- never logs secrets
- supports timestamped backups, dry-run
  verification, and an explicit `--apply` restore
- surfaces a deployment manifest that another
  human (or a deployment pipeline) can consume

## How the Node application starts

The application starts with:

```
npm run start:hostinger
```

or directly:

```
node hostinger/app.mjs
```

The process:

1. Resolves the Hostinger configuration from the
   environment (host, port, data root, public dir,
   log dir, locks dir, backend, dry-run flag).
2. Verifies the data root is usable (see
   *Data-root readiness* below). When the check
   fails the process exits 4 before binding to the
   port.
3. Binds to the configured host and port.
4. Accepts `GET` and `HEAD` on `/health`, `/ready`,
   `/api/dataset`, and the static + SPA fallback.
   Every other method returns a sanitized `405`.
5. Handles `SIGINT` and `SIGTERM` gracefully:
   stops accepting new connections, drains
   in-flight requests for up to 5 seconds, then
   exits `0`.

Two diagnostic flags are accepted before the
server starts:

```
node hostinger/app.mjs --config     # print resolved config as JSON, exit 0
node hostinger/app.mjs --readiness  # print readiness report, exit 0 (ready) or 1 (not ready)
```

## How scheduled jobs run through Hostinger cron

Six Hostinger cron entrypoints live under
`hostinger/`. Each:

- acquires a filesystem lock named after the job
  (so a second invocation while the first is
  running exits 2 with no work performed)
- invokes the V6.2 job module under the same
  environment
- releases the lock on completion
- logs a one-line JSON summary to stdout and a
  structured log line to stderr + the daily
  JSONL log file
- exits 0 on success and a meaningful non-zero
  code on failure (see *Lock behavior* below)

| Cron expression | Command | Purpose |
| --- | --- | --- |
| `*/30 * * * *`  | `npm run cron:refresh-dataset`  | public dataset refresh |
| `15,45 * * * *` | `npm run cron:publish-dataset`  | dataset-bound public-intelligence publication |
| `0 * * * *`    | `npm run cron:refresh-baseline` | canonical OSV baseline refresh |
| `5 * * * *`    | `npm run cron:gc`               | public-intelligence garbage collection |
| `30 6 * * *`   | `npm run cron:verify-state`     | state verification (daily) |
| `0 2 * * *`    | `npm run cron:backup`           | backup creation (daily) |

The Hostinger Business cron frequency is once per
minute. The minimum inter-arrival time on the
schedule above is 5 minutes, well within the
host's limit.

## Where persistent files live

```
$threatpulse-radar/        # the application
  dist/                     # the built Vite frontend
  server/, jobs/, tools/    # the application code

$HOME/
  threatpulse-state/        # THREATPULSE_DATA_ROOT
    tpr-dataset/            # the public dataset envelope
    tpr-vulnrichment/       # the SSVC cache
    tpr-github-advisory/    # the GitHub Advisory cache
    tpr-baseline/           # the canonical baseline
    tpr-public-intelligence/# the V6.1 public intelligence
    locks/                  # THREATPULSE_LOCKS_DIR
  threatpulse-logs/         # THREATPULSE_LOG_DIR
    threatpulse-YYYY-MM-DD.jsonl
    threatpulse-YYYY-MM-DD.jsonl.1 (rotated)
  threatpulse-backups/      # THREATPULSE_BACKUP_DIR
    YYYY-MM-DD-HHMMSS-backup/
      threatpulse-export.tar.gz
```

The data root, log dir, locks dir, and backup dir
are all *outside* the public web root. They are
not served by the application; the static-serving
module rejects any request that would resolve
inside any of them.

## Permissions verification

The data-root readiness check
(`hostinger/readiness.mjs`) probes:

- directory exists OR can be created
- read + write
- atomic rename (the FilesystemStorageAdapter
  uses temp + rename on every write)
- gzip write + read round-trip
- available disk space (best-effort; absent on
  restricted filesystems)
- symlink safety
- public-dir isolation
- absence of secret-looking files in the root

The check is **fail-closed**: when any probe
fails the Hostinger application refuses to start
and the readiness endpoint returns `503` with a
sanitized reason.

The `npm run start:hostinger` process exits with
code 4 when the readiness check fails, so the
Hostinger control panel surfaces the failure as
a non-zero process status.

## Concurrency control

The Hostinger Business host does not expose a
system lock manager. Concurrency control is
implemented at the application level via the
`hostinger/locks.mjs` module.

Each lock is a single file under
`THREATPULSE_LOCKS_DIR`. The file content is JSON
with `acquiredAt`, `expiresAt`, `owner`, and
`pid`:

```json
{
  "acquiredAt": "2026-07-16T11:00:00.000Z",
  "expiresAt": "2026-07-16T11:15:00.000Z",
  "owner": "cron:refresh-dataset:12345",
  "pid": 12345
}
```

Acquisition is atomic on POSIX (rename is atomic)
and atomic on Windows via the standard rename
path:

- the existing file is read; if the lock is
  expired or missing, the file is overwritten via
  a temp + rename
- a non-expired foreign lock is NEVER overwritten
- release is conditional on the owner matching
  the caller (a foreign lock is never released)
- `clearStaleCronLock` removes only expired locks
- `inspectCronLock` is read-only

Two simultaneous cron jobs cannot enter the
protected section. The first wins; the second
exits with code 2.

The lock registry (`LOCK_NAMES` in
`hostinger/locks.mjs`) is the single source of
truth:

- `dataset-refresh`
- `baseline-refresh`
- `dataset-publish`
- `public-intelligence-gc`
- `state-verify`
- `backup-import`

Each cron entrypoint uses exactly one of these
names; the runtime never invents a new name
ad-hoc.

## Health and readiness checks

| Endpoint | Status | Purpose |
| --- | --- | --- |
| `GET /health` | `200` | liveness — always 200 when the process is running |
| `GET /ready`  | `200` / `503` | readiness — 200 when the data root is verified AND a dataset envelope is present |

Both endpoints return `Cache-Control: no-store`.

The `/ready` endpoint is sanitized for the public
probe. Operators who want the full readiness
report run:

```
node hostinger/app.mjs --readiness
```

The full report lists every probe's pass/fail
status and is intended for the operator's terminal
or a deployment pipeline.

## Backup and restore

The Hostinger runtime bundles three commands:

| Command | Purpose |
| --- | --- |
| `npm run backup:hostinger`  | create a timestamped tar.gz archive under `THREATPULSE_BACKUP_DIR` |
| `npm run verify:backup -- --archive=<path>` | verify an archive's checksums without touching the live data root |
| `npm run restore:hostinger -- --archive=<path>` | restore (dry-run by default) |
| `npm run restore:hostinger -- --archive=<path> --apply --yes` | restore (destructive; requires explicit confirmation) |

The backup command is also exposed as a cron
entrypoint (`npm run cron:backup`) that runs
under the `backup-import` lock.

### Backup

`npm run backup:hostinger` produces a directory:

```
$THREATPULSE_BACKUP_DIR/YYYY-MM-DD-HHMMSS-backup/
  staging/
    CHECKSUMS.json
    METADATA.json
    dataset/latest-dataset.json
    ...
  threatpulse-export.tar.gz
```

The default retention is 7 archives (overridable
via `--keep=<n>`). Older archives are removed
automatically.

### Verify

`npm run verify:backup` extracts the archive to a
temporary staging area, validates `METADATA.json`,
and recomputes every checksum in
`CHECKSUMS.json` against the extracted files. The
command NEVER touches the live data root. The
output reports the per-archive status, the number
of checksums verified, and the count of present
vs absent entries.

### Restore

The restore command is **dry-run by default**. To
actually write the restored state the operator
must pass both `--apply` and `--yes`:

```
npm run restore:hostinger -- --archive=<path> --apply --yes
```

Without `--yes` the command exits 5 and prints
the target data root and archive path so the
operator can re-check the targets.

The restore command refuses to apply an archive
that lives inside the configured data root
(operator-typo guard).

## Last-known-good preservation

The V6.2 import tool extracts the archive to a
staging area under `<archive>.staging/`, validates
the checksums, and only promotes the staged
contents to the target storage adapter on
success. A failure during the apply phase leaves
the previous state intact.

The Hostinger `restore.mjs` enforces the same
contract through the V6.2 import tool. The
operator can run a dry-run, inspect the result,
and only then pass `--apply --yes`.

## Security hardening

The Hostinger runtime enforces:

- **No writes from the network.** Every endpoint
  is read-only (`GET`/`HEAD`); any other method
  returns `405` with an `Allow` header.
- **Path-traversal rejection.** The static
  serving module rejects any path containing
  `..`, `\\`, NUL bytes, or a percent-encoded
  `..` segment. The check is performed on the
  decoded path, so double-encoded attacks are
  also caught.
- **Public-dir isolation.** The data root, log
  dir, locks dir, and backup dir are NEVER
  served. The static-serving module rejects any
  path that resolves to one of these locations.
- **Forbidden top-level files.** `.env`,
  `.env.local`, `.git`, `node_modules`, and the
  application source directories are not served.
- **Bounded URL length.** Any URI longer than
  2048 characters is rejected with `414`.
- **Malformed percent-encoding.** Any request
  that throws on the `WHATWG URL` parser returns
  `400`.
- **Source maps in production.** Source maps are
  not served in production; the Vite build does
  not emit them by default.
- **Security headers.** Every response includes
  `X-Content-Type-Options: nosniff`,
  `X-Frame-Options: SAMEORIGIN`, and
  `Referrer-Policy: same-origin`. Production
  responses also include
  `Strict-Transport-Security: max-age=15552000;
  includeSubDomains`.
- **No directory listing.** Unknown directories
  return `404` rather than an index page.
- **No secret logging.** The structured logger
  redacts any key whose name matches
  `secret|token|password|api[_-]?key|credential|hmac|pepper|authorization`,
  any value matching a Netlify PAT
  (`nfp_*`) or OpenAI key (`sk-*`) shape, and
  any value matching a SHA-256 internal hash
  (`sha256:<64 hex chars>`) unless debug mode is
  explicitly enabled.
- **No private gateway.** The private gateway
  subtree (`netlify/gateway/`) is not deployed
  on Hostinger; the Hostinger runtime only
  serves the public API.

## When a VPS would be required

The diagnostic command (`npm run diagnose:hostinger`)
measures runtime characteristics and emits one of
three recommendations:

- `compatible` — every probe is within tolerance
- `compatible-with-warnings` — at least one
  warning fired but the workload is still
  expected to run correctly
- `vps-recommended` — at least two warnings, or
  the representative refresh exceeds 60 seconds

The diagnostic NEVER calls a production
provider; it uses the in-memory storage adapter
and synthetic fixtures.

Conditions that would require a VPS:

- The representative dataset refresh exceeds
  60 seconds (the longest-running job in the
  default schedule).
- The filesystem write throughput is below
  20 MiB/s.
- The peak RSS exceeds 70% of the V8 heap
  limit.
- The Hostinger Business cron is too slow
  (more than 5 minutes between the dataset
  refresh and the publication step) to
  guarantee the bundle freshness SLA.
- The operator needs an always-on process
  with sub-second response times (the
  Hostinger Business runtime expects deploy
  restarts on each cron cycle).

## Diagnostic and deployment manifest

### Diagnostic

```
npm run diagnose:hostinger
```

Prints a one-line-per-probe report. With
`--json` it prints the full structured output
suitable for piping to a monitoring pipeline.
The report includes:

- runtime (Node version, platform, arch, cpus,
  load average, total memory, free memory,
  uptime)
- process (pid, rss, heap total, heap limit)
- storage (data root, locks dir, public dir,
  log dir, backend)
- performance (filesystem write throughput,
  atomic rename, representative dataset
  refresh, retained storage)
- warnings (a list of sanitized messages)
- recommendation (compatible / compatible-with-
  warnings / vps-recommended)

### Deployment manifest

```
node hostinger/manifest.mjs --out=<dir>
```

Writes `deployment-manifest.json` (machine-
readable) and `deployment-manifest.md` (human-
readable) to the given directory. The manifest
lists the Node version, the build command, the
start command, the required + optional env
vars, the cron schedule, the health + readiness
URLs, the backup / verify / restore commands,
the rollback procedure, the unsupported
assumptions, and the conditions that would
require a VPS.

The manifest NEVER contains a secret value.

## Migration checklist (Netlify → Hostinger Business)

1. Run `node hostinger/manifest.mjs --out=./deploy`
   and review the JSON + Markdown.
2. On Hostinger Business, create a Node.js
   application. Point it at the repository.
3. Set the required environment variables
   (the manifest lists them; do NOT copy a
   real `.env`).
4. Run `npm ci --omit=dev && npm run build`.
5. Run `node hostinger/app.mjs --readiness` to
   confirm the data root is usable.
6. Start the application with
   `npm run start:hostinger`.
7. Configure the cron schedule in the Hostinger
   control panel using the table above.
8. Run `npm run backup:hostinger` to take the
   first archive; verify it with
   `npm run verify:backup -- --archive=<archive>`.
9. Confirm `/health` returns 200 and
   `/api/dataset` returns the live bundle.
10. (Optional) Migrate the data from a previous
    Netlify deployment by exporting the Netlify
    state and importing on Hostinger (the V6.2
    import tool supports cross-backend import).

The Netlify deployment continues to work in
parallel. The two deployments are independent
and share no state by default.
