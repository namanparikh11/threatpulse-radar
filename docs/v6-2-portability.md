# V6.2 — Hosting Portability Foundation

ThreatPulse Radar can now run through shared application
logic on multiple hosting platforms:

- Netlify (existing V5.x / V6.0 / V6.1 deployment — preserved)
- local Node.js development
- Hostinger Business Node.js hosting
- a future Hostinger VPS
- a future Docker / container platform
- a future S3-compatible object store

This document is the operator's guide for the portable
deployment paths. The Netlify deployment is unchanged.

## What changed in V6.2

- A narrow **storage adapter** interface (`StorageAdapter`)
  with three concrete adapters:
  - `NetlifyBlobsStorageAdapter` — production default
  - `FilesystemStorageAdapter` — Windows/Linux paths, atomic
    temp+rename, symlink escape rejection
  - `InMemoryStorageAdapter` — process-local, for tests
- A `createStorageAdapter({ name, storeName, opts })` factory
  that selects the adapter by name (env or arg).
- Five **portable job entrypoints** in `jobs/` that call the
  same shared orchestration used by Netlify:
  - `refresh-dataset.mjs`
  - `refresh-baseline.mjs`
  - `publish-dataset-intelligence.mjs`
  - `gc-public-intelligence.mjs`
  - `verify-state.mjs`
- A small **portable Node HTTP application** in `server/`
  that serves the public dataset + V6.1 view modes.
- Three **filesystem tools** in `tools/`:
  - `export-threatpulse-state.mjs`
  - `import-threatpulse-state.mjs`
  - `verify-threatpulse-state.mjs`
- Optional **Docker support** (`Dockerfile`,
  `docker-compose.yml`, `.dockerignore`).
- A safe **`.env.example`** with variable names only (no
  secrets).

The V6.1 contract is preserved:

- 5 public Netlify function entry files
- 1 gateway function entry file (untouched)
- 21-column CSV
- V6.1 OSV public projection, change intelligence, and
  source health behaviors

## Quick start — local filesystem

```
# 1. Install
npm ci

# 2. Build the frontend (the same `npm run build` used by Netlify)
npm run build

# 3. Start the portable HTTP server
THREATPULSE_STORAGE_BACKEND=filesystem \
THREATPULSE_DATA_ROOT=$PWD/state \
node server/http.mjs
# -> [v6.2 http] listening on http://127.0.0.1:8787 (storage=filesystem)
```

Verify:

```
curl http://127.0.0.1:8787/health
# -> {"status":"ok"}

curl http://127.0.0.1:8787/ready
# -> {"ready":false,"reason":"no-dataset-envelope"}  (first run)
```

## CLI jobs

All five CLI jobs accept `--data-root=...` and
`--backend=filesystem|netlify|memory`. The default is
Netlify.

```
# Verify the current state
node jobs/verify-state.mjs --data-root=$PWD/state --backend=filesystem

# Run the GC
node jobs/gc-public-intelligence.mjs --data-root=$PWD/state --backend=filesystem

# Run a refresh (dry-run)
node jobs/refresh-dataset.mjs --data-root=$PWD/state --backend=filesystem --dry-run
```

Exit codes are documented in each entrypoint.

## Filesystem adapter safety

- Windows and Linux paths. The adapter normalizes
  separators to the host's separator.
- Deterministic key-to-path mapping.
- Path-traversal rejection. Keys with `..`, absolute
  paths, backslashes, or NUL bytes are rejected at the
  `assertValidKey` boundary.
- Atomic writes via a temp file + rename. A crashed
  writer never leaves a half-written blob on disk.
- Symlink escape rejection. The realpath of the parent
  of every write target is checked against the realpath
  of the data root.
- `manifest-last` publication (the `latest.json` write
  is the last step of a publication).
- Crash recovery: the next read returns either the
  previous bytes or the new bytes — never a truncated
  file.
- No secrets inside the data directory.

## Hostinger Business compatibility

### What runs on Hostinger Business

- The portable HTTP server (`node server/http.mjs`).
- The CLI jobs (invoked via cron).
- The portable storage adapter with the filesystem
  backend.
- The export / import / verify tooling.

### What does NOT run on Hostinger Business

- The Netlify Background Function (Netlify-specific).
- Anything that requires root or systemd.
- A permanent background process. Hostinger Business
  cron jobs run on a schedule but do not provide a
  always-on runtime. The portable server can run as
  a long-lived process, but a deploy restart is
  expected on every cron cycle.

### Cron commands

The Hostinger Business cron schedule is configured in
the Hostinger control panel. The recommended schedule:

```
*/30 * * * *  cd $HOME/threatpulse-radar && THREATPULSE_STORAGE_BACKEND=filesystem THREATPULSE_DATA_ROOT=$HOME/state node jobs/refresh-dataset.mjs >> $HOME/logs/refresh-dataset.log 2>&1
0 * * * *    cd $HOME/threatpulse-radar && THREATPULSE_STORAGE_BACKEND=filesystem THREATPULSE_DATA_ROOT=$HOME/state node jobs/refresh-baseline.mjs >> $HOME/logs/refresh-baseline.log 2>&1
*/30 * * * *  cd $HOME/threatpulse-radar && THREATPULSE_STORAGE_BACKEND=filesystem THREATPULSE_DATA_ROOT=$HOME/state node jobs/publish-dataset-intelligence.mjs >> $HOME/logs/publish-intel.log 2>&1
15 * * * *   cd $HOME/threatpulse-radar && THREATPULSE_STORAGE_BACKEND=filesystem THREATPULSE_DATA_ROOT=$HOME/state node jobs/gc-public-intelligence.mjs >> $HOME/logs/gc.log 2>&1
```

### Expected directories

```
$threatpulse-radar/
  state/                          <- THREATPULSE_DATA_ROOT
    tpr-dataset/                   <- public dataset envelope
    tpr-vulnrichment/              <- SSVC cache
    tpr-github-advisory/           <- GH Advisory cache
    tpr-baseline/                  <- canonical baseline
    tpr-public-intelligence/       <- V6.1 public intelligence
  logs/                            <- per-job log output
    refresh-dataset.log
    refresh-baseline.log
    publish-intel.log
    gc.log
```

### Permissions

The state directory and the application directory must
be readable and writable by the cron user. Recommended
permissions:

```
chmod 700 $HOME/threatpulse-radar
chmod 700 $HOME/state
```

### Health / readiness checks

- `GET /health` — liveness. Returns `{"status":"ok"}` as
  long as the server process is running.
- `GET /ready` — readiness. Returns `{"ready":true,...}`
  when the dataset envelope is present.

Hostinger Business does not provide a built-in health
endpoint integration. The `verify-state.mjs` CLI is the
recommended operator check; it can be invoked from a
cron or a one-off shell.

### Backup procedure

Use the export tool to snapshot the state. The export
is a single `.tar.gz` file containing every Blob-store
namespace, the public-intelligence OSV shards, the
dataset bundle, the schema/version metadata, and the
checksums.

```
node tools/export-threatpulse-state.mjs --out=$HOME/backups/$(date +%Y%m%d)
```

The resulting `backups/<date>/threatpulse-export.tar.gz`
can be transferred to a backup host via the Hostinger
control panel's file manager, or `scp` if SSH is
available.

### Limitations that would require a VPS

- Hostinger Business does not provide an always-on
  process. The HTTP server can be started by a cron
  job, but a deploy restart is expected. Operators who
  need an always-on server with sub-second response
  times should migrate to a Hostinger VPS.
- Hostinger Business cron frequency is limited to once
  per minute. The V6.0 / V6.1 baseline refresh is
  designed for hourly cadence; this is compatible.
- Hostinger Business does not provide log shipping
  integration. Operators rely on local file logs.
- Hostinger Business does not provide distributed
  storage. The filesystem adapter stores all state on
  a single host; a VPS or container platform is
  required for a horizontally-scalable deployment.

## Docker

The optional Dockerfile + docker-compose.yml build a
container image that runs the portable HTTP server on
port 8787 with a persistent data volume at
`/var/lib/threatpulse/state`.

```
docker build -t threatpulse-radar:v6-2 .
docker compose up -d
```

Health check: `GET /health`.

Docker is OPTIONAL. The application runs without Docker
on Netlify, local Node, and Hostinger Business.

## What was NOT changed

- Netlify production deployment is unchanged. The 5
  public Netlify function entries and the 1 gateway
  function entry continue to be the production
  deployment target.
- The 21-column CSV contract is unchanged.
- The V5.x / V6.0 / V6.1 acceptance suites continue to
  pass against the production code path. The portable
  code path is exercised by the V6.2-specific
  acceptance suites.
- The gateway authentication contract is unchanged.
- No secrets or raw hashes are added to any deployment.

## Migration checklist (Netlify → Hostinger Business)

1. Run the export tool against the Netlify deployment
   to capture the current state.
2. Transfer the `threatpulse-export.tar.gz` to the
   Hostinger Business host.
3. Install Node.js 20+ on the Hostinger host.
4. Clone the repository.
5. Run `npm ci --omit=dev`.
6. Run the import tool with `--apply` to populate the
   filesystem-backed state.
7. Configure the cron schedule per the table above.
8. Start the portable HTTP server as a long-lived
   process (optional; only needed for live previews).
9. Verify with `node jobs/verify-state.mjs`.

The Netlify deployment continues to be supported in
parallel. The two deployments are independent and
share no state by default; an operator can run
export-from-Netlify + import-on-Hostinger to migrate
at any time.
