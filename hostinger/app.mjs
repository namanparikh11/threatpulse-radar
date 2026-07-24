#!/usr/bin/env node
/**
 * V6.3 — Hostinger Business application entrypoint.
 *
 * The production HTTP server for the Hostinger
 * Business managed-hosting deployment. Wraps the
 * V6.2 portable HTTP application and adds:
 *
 *   - reads PORT and host from server-only config
 *   - refuses to start when the data-root readiness
 *     check fails (fail-closed)
 *   - structured JSON log output to stderr and an
 *     optional daily-rotated file
 *   - sanitized startup-failure output (no stack
 *     traces by default, no secrets)
 *   - graceful SIGINT / SIGTERM shutdown:
 *     stop accepting new connections → drain in
 *     flight requests → exit
 *   - never reads Netlify runtime globals; the
 *     server is runnable in any Node 20+ environment
 *
 * Usage:
 *   node hostinger/app.mjs [--readiness] [--config]
 *
 * The `--readiness` flag prints the full readiness
 * report and exits 0 (ready) or 1 (not ready).
 * The `--config` flag prints the resolved Hostinger
 * configuration and exits 0.
 *
 * Production invocation (npm run start:hostinger):
 *   THREATPULSE_STORAGE_BACKEND=filesystem \
 *   THREATPULSE_DATA_ROOT=/home/<user>/threatpulse-state \
 *   THREATPULSE_PUBLIC_DIR=/home/<user>/threatpulse-radar/dist \
 *   PORT=<hostinger-assigned> \
 *   node hostinger/app.mjs
 */

import { createServer } from 'node:http';
import { fileURLToPath } from 'node:url';
import { dirname, resolve, join } from 'node:path';
import { existsSync } from 'node:fs';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..');

import { resolveHostingerConfig, sanitizeError, isPathInside } from './_lib.mjs';
import { createLogger, dailyLogPath } from './logger.mjs';
import { checkReadiness, sanitizeReadinessForPublic } from './readiness.mjs';
import { serveStatic, applySecurityHeaders, MAX_PATH_LENGTH } from './static.mjs';
import { createManagedScheduler } from './managed-scheduler.mjs';

// Defense-in-depth cap on the total size of all
// request headers. Node's default
// `--max-http-header-size` is 16 KiB; we cap at the
// same value to bound the attack surface of the
// OpenTelemetry W3C Baggage propagation
// vulnerability that affects @netlify/blobs (see
// docs/v6-3-security-review.md). The cap is applied
// BEFORE the request handler runs, so a request with
// a single oversized header is rejected with 431.
const MAX_TOTAL_HEADER_BYTES = 16 * 1024;

// V6.9 — Bounded Node server timeouts. The defaults
// (5s headersTimeout, no global request timeout, no
// keepAliveTimeout cap) are too permissive for a
// public HTTP surface. We pin every value explicitly
// so a regression that changes Node defaults cannot
// silently relax the surface. Values are chosen to
// accommodate the largest legitimate request in the
// bundle (the SHA-256 fingerprint worker bootstrap)
// while bounding slow-loris and similar abuse.
const HEADERS_TIMEOUT_MS = 10_000;     // 10 s for headers
const REQUEST_TIMEOUT_MS = 60_000;     // 60 s for the full request
const KEEPALIVE_TIMEOUT_MS = 5_000;    // 5 s for keep-alive idle
const MAX_KEEPALIVE_REQUESTS = 100;    // cap per-connection request count

import { resolveConfig as resolvePortableConfig } from '../server/config.mjs';
import { handleHealth } from '../server/routes/health.mjs';
import { handleReady as handlePortableReady } from '../server/routes/ready.mjs';
import { handleDataset } from '../server/routes/dataset.mjs';

function parseArgs(argv) {
  const args = { readiness: false, config: false, help: false };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--readiness') args.readiness = true;
    else if (a === '--config') args.config = true;
    else if (a === '--help' || a === '-h') args.help = true;
  }
  return args;
}

function printHelp() {
  console.log(`ThreatPulse Radar — Hostinger Business runtime

Usage:
  node hostinger/app.mjs [--readiness] [--config] [--help]

Options:
  --readiness   Run the data-root readiness check, print the
                full report as JSON, and exit 0 (ready) or
                1 (not ready). The HTTP server is not started.
  --config      Print the resolved Hostinger configuration
                and exit 0.
  --help        Print this help and exit 0.

Environment:
  PORT, THREATPULSE_HTTP_PORT       bind port (default 8787)
  THREATPULSE_HTTP_HOST             bind host (default 0.0.0.0)
  THREATPULSE_DATA_ROOT             absolute path to the
                                    persistent data root
  THREATPULSE_PUBLIC_DIR            absolute path to the
                                    built frontend (default dist)
  THREATPULSE_LOG_DIR               directory for daily log
                                    files (optional)
  THREATPULSE_LOCKS_DIR             absolute path to the
                                    locks directory (default
                                    $DATA_ROOT/locks)
  THREATPULSE_STORAGE_BACKEND       'filesystem' (default)
  THREATPULSE_DRY_RUN               '1' / 'true' skips writes`);
}

const args = parseArgs(process.argv);
if (args.help) {
  printHelp();
  process.exit(0);
}

const cfg = resolveHostingerConfig();
const logFile = dailyLogPath(cfg.logDir);
const logger = createLogger({ component: 'hostinger.app', filePath: logFile, debug: !cfg.isProduction });

if (args.config) {
  console.log(JSON.stringify({
    host: cfg.host, port: cfg.port, dataRoot: cfg.dataRoot, publicDir: cfg.publicDir,
    logDir: cfg.logDir, locksDir: cfg.locksDir, backend: cfg.backend, dryRun: cfg.dryRun,
    nodeEnv: cfg.nodeEnv, logFile: logFile || null,
  }, null, 2));
  process.exit(0);
}

if (args.readiness) {
  const publicDir = existsSync(cfg.publicDir) ? cfg.publicDir : null;
  const report = await checkReadiness({ dataRoot: cfg.dataRoot, publicDir, logger });
  // For the operator-facing --readiness output we
  // include the full report (no secrets are exposed
  // by the check itself).
  const sanitized = {
    ...report,
    checks: report.checks.map((c) => {
      const { error, ...rest } = c;
      // Truncate long error messages.
      if (typeof error === 'string' && error.length > 200) return { ...rest, error: error.slice(0, 200) + '...' };
      return c;
    }),
  };
  console.log(JSON.stringify(sanitized, null, 2));
  process.exit(report.ready ? 0 : 1);
}

logger.info({ msg: 'startup', host: cfg.host, port: cfg.port, dataRoot: cfg.dataRoot, publicDir: cfg.publicDir, backend: cfg.backend, nodeVersion: process.version, pid: process.pid });

// 1. Verify the data root BEFORE binding to the port.
// The check is fail-closed: a non-usable data root
// causes a clean exit with code 4.
const publicDirForCheck = existsSync(cfg.publicDir) ? cfg.publicDir : null;
const readiness = await checkReadiness({ dataRoot: cfg.dataRoot, publicDir: publicDirForCheck, logger });
if (!readiness.ready) {
  const failed = readiness.checks.filter((c) => !c.ok).map((c) => c.name).join(',');
  logger.error({ msg: 'startup.aborted', reason: 'readiness-failed', failed });
  console.error(JSON.stringify({ error: 'startup-aborted', reason: 'data-root-not-ready', failed: failed.split(',') }));
  process.exit(4);
}
logger.info({ msg: 'readiness.ok' });

// 2. Build the portable config the V6.2 routes need.
const portable = resolvePortableConfig({
  env: {
    THREATPULSE_STORAGE_BACKEND: cfg.backend,
    THREATPULSE_HTTP_HOST: cfg.host,
    THREATPULSE_HTTP_PORT: String(cfg.port),
    THREATPULSE_DATA_ROOT: cfg.dataRoot,
  },
});

// 3. Construct the HTTP server. The handler is a
// single async function that dispatches to the V6.2
// routes. New connections are stopped during shutdown
// via server.close(). V6.9 — every Node-side timeout
// is pinned explicitly so a Node default change
// cannot silently relax the public surface.
let shuttingDown = false;
const server = createServer(async (req, res) => {
  if (shuttingDown) {
    res.statusCode = 503;
    res.setHeader('Connection', 'close');
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.end('server shutting down');
    return;
  }
  try {
    // Reject requests whose URL exceeds the bound.
    // The Hostinger control panel imposes a limit
    // of its own; the application-level bound is a
    // defense in depth.
    if (typeof req.url !== 'string' || req.url.length > MAX_PATH_LENGTH) {
      res.statusCode = 414;
      res.setHeader('Content-Type', 'application/json; charset=utf-8');
      res.end(JSON.stringify({ error: 'uri-too-long' }));
      return;
    }
    // Bound the total header size. Node also
    // enforces a default cap (16 KiB) at the HTTP
    // parser level, but we re-check at the
    // application level to keep the failure mode
    // consistent with the rest of the Hostinger
    // runtime and to defend against the OpenTelemetry
    // W3C Baggage propagation vector that
    // transitively affects @netlify/blobs.
    const totalHeaderBytes = (() => {
      let n = 0;
      for (const k of Object.keys(req.headers || {})) {
        const v = req.headers[k];
        n += k.length;
        if (Array.isArray(v)) for (const x of v) n += x.length;
        else if (typeof v === 'string') n += v.length;
      }
      return n;
    })();
    if (totalHeaderBytes > MAX_TOTAL_HEADER_BYTES) {
      res.statusCode = 431;
      res.setHeader('Content-Type', 'application/json; charset=utf-8');
      res.end(JSON.stringify({ error: 'request-header-fields-too-large' }));
      return;
    }
    // Guard against malformed URLs: bad percent
    // encoding or control characters throw on
    // `new URL()`. Surface a sanitized 400 instead
    // of crashing the request.
    let url;
    try {
      url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    } catch (urlErr) {
      res.statusCode = 400;
      res.setHeader('Content-Type', 'application/json; charset=utf-8');
      res.end(JSON.stringify({ error: 'bad-request', reason: 'malformed-url' }));
      return;
    }
    const path = url.pathname;
    // Method allowlist: only GET and HEAD are
    // supported on every endpoint. Any other method
    // is a sanitized 405. This protects the storage
    // adapter from accidental writes via, e.g.,
    // POST /health or PUT /api/dataset.
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      res.statusCode = 405;
      res.setHeader('Allow', 'GET, HEAD');
      res.setHeader('Content-Type', 'application/json; charset=utf-8');
      res.end(JSON.stringify({ error: 'method-not-allowed' }));
      return;
    }
    if (path === '/health') {
      const r = handleHealth();
      writeResponse(res, r);
      return;
    }
    if (path === '/ready') {
      // The Hostinger /ready probes the data-root
      // readiness plus the portable readiness. The
      // public response is sanitized — only the
      // reason is exposed, never the full check
      // list.
      const r = await handlePortableReady({ config: portable });
      const publicReady = r.status === 200 ? { ready: true } : { ready: false, reason: 'dataset-missing' };
      writeResponse(res, new Response(JSON.stringify(publicReady), {
        status: publicReady.ready ? 200 : 503,
        headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' },
      }));
      return;
    }
    if (path === '/api/dataset') {
      const r = await handleDataset(req, { config: portable });
      writeResponse(res, r);
      return;
    }
    // V6.8 Hostinger dataset-route compatibility alias.
    //
    // The frozen V6.8 frontend hardcodes three URLs that
    // begin with `/.netlify/functions/dataset`:
    // the live-data proxy, the per-CVE OSV view
    // (`?view=osv&...`), and the per-category change
    // panel (`?view=changes&...`). The canonical
    // Hostinger route is `/api/dataset`; this alias
    // exists so the frozen frontend's `fetch` calls
    // resolve to the same portable `handleDataset`
    // implementation.
    //
    // Contract:
    //   - GET and HEAD only (POST/PUT/PATCH/DELETE
    //     remain 405 via the upstream method allowlist)
    //   - the same query string is forwarded
    //   - the response is the exact same JSON body
    //     and the exact same status code as
    //     `/api/dataset`
    //   - the path is NOT a Netlify Function; on
    //     Hostinger it is a plain HTTP route handled
    //     by the portable Node server
    //   - the path is read-only; no write, refresh,
    //     publication, backup, GC or verification
    //     action is reachable through it
    if (path === '/.netlify/functions/dataset') {
      const r = await handleDataset(req, { config: portable });
      writeResponse(res, r);
      return;
    }
    // V6.8 Hostinger Netlify-compatibility sink.
    //
    // Any other `/.netlify/functions/{name}` path is
    // served an honest 404 instead of falling through
    // to the SPA shell. The Hostinger application
    // does NOT implement the Netlify Function
    // surface; only the `dataset` read alias is
    // exposed. This guard prevents the SPA shell
    // from being returned for paths that a Netlify
    // deployment would treat as a function — a user
    // hitting e.g.
    // `/.netlify/functions/refresh-dataset-background`
    // would otherwise see a 200 OK with the SPA HTML,
    // which is misleading. The honest 404 makes it
    // clear that the function does not exist on the
    // Hostinger deployment.
    if (path.startsWith('/.netlify/functions/')) {
      res.statusCode = 404;
      res.setHeader('Content-Type', 'application/json; charset=utf-8');
      res.end(JSON.stringify({ error: 'not-found' }));
      return;
    }
    // Static + SPA fallback. API routes are above
    // this branch so they always win precedence.
    const staticRes = serveStatic({
      path, publicDir: cfg.publicDir, dataDir: cfg.dataRoot,
      isProduction: cfg.isProduction,
    });
    if (staticRes) {
      writeResponse(res, staticRes);
      return;
    }
    // No public dist; serve a sanitized 404.
    res.statusCode = 404;
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.end(JSON.stringify({ error: 'not-found' }));
  } catch (err) {
    logger.error({ msg: 'request.error', error: sanitizeError(err) });
    try {
      res.statusCode = 500;
      res.setHeader('Content-Type', 'application/json; charset=utf-8');
      res.end(JSON.stringify({ error: 'internal' }));
    } catch { /* noop */ }
  }
});

function writeResponse(res, response) {
  try {
    res.statusCode = response.status;
    const headers = new Headers(response.headers);
    applySecurityHeaders(headers, { isProduction: cfg.isProduction });
    for (const [k, v] of headers.entries()) {
      res.setHeader(k, v);
    }
    if (!res.getHeader('Cache-Control')) {
      res.setHeader('Cache-Control', 'no-store');
    }
    // The response body may be a ReadableStream
    // (for static assets) or a string. Handle both.
    if (response.body) {
      // Body is a ReadableStream of bytes.
      const reader = response.body.getReader();
      const pump = () => reader.read().then((r) => {
        if (r.done) { res.end(); return; }
        if (!res.write(r.value)) {
          res.once('drain', pump);
        } else {
          pump();
        }
      }).catch(() => res.end());
      pump();
    } else {
      response.text().then((body) => res.end(body)).catch(() => res.end());
    }
  } catch (err) {
    try { res.statusCode = 500; res.end(); } catch { /* noop */ }
  }
}

// 4. Listen. On EADDRINUSE or other bind errors,
// surface a sanitized message and exit 1.
// V6.9 — Pin every Node server timeout explicitly.
// Node's defaults (5s headersTimeout, no global
// request timeout, no keepAliveTimeout cap) are too
// permissive for a public HTTP surface. The values
// are chosen to accommodate the largest legitimate
// request in the bundle (the SHA-256 fingerprint
// worker bootstrap) while bounding slow-loris
// and similar abuse.
server.headersTimeout = HEADERS_TIMEOUT_MS;
server.requestTimeout = REQUEST_TIMEOUT_MS;
server.keepAliveTimeout = KEEPALIVE_TIMEOUT_MS;
server.maxRequestsPerConnection = MAX_KEEPALIVE_REQUESTS;
server.on('error', (err) => {
  logger.error({ msg: 'listen.error', error: sanitizeError(err) });
  console.error(JSON.stringify({ error: 'listen-failed', code: err.code || null, message: err.message }));
  process.exit(1);
});

// 4a. Managed scheduler. The Hostinger Business
// managed-Node plan does not expose an OS cron.
// When THREATPULSE_MANAGED_SCHEDULER=1, start an
// in-process scheduler after the HTTP server is
// listening. The scheduler is process-local and
// reuses the same locks and V6.2 jobs as the
// standalone cron entrypoints. The application
// keeps the only signal-handler installation;
// the scheduler is stopped via `stop()` during
// shutdown, not via a signal.
let managedScheduler = null;
function startManagedScheduler() {
  managedScheduler = createManagedScheduler(cfg, logger);
  if (!managedScheduler.isEnabled()) {
    logger.info({ msg: 'managed-scheduler.disabled' });
    return;
  }
  try {
    const r = managedScheduler.start();
    logger.info({ msg: 'managed-scheduler.activated', activeTimers: r.activeTimers, bootstrap: r.bootstrap });
  } catch (err) {
    logger.error({ msg: 'managed-scheduler.activation-failed', error: sanitizeError(err) });
  }
}

server.listen(cfg.port, cfg.host, () => {
  logger.info({ msg: 'listening', host: cfg.host, port: cfg.port });
  // eslint-disable-next-line no-console
  console.error(`[v6.3 hostinger] listening on http://${cfg.host}:${cfg.port} (storage=${cfg.backend}, data=${cfg.dataRoot})`);
  // Start the embedded scheduler AFTER the HTTP
  // server is listening so a slow startup or a
  // refresh-failure cannot delay first-byte.
  startManagedScheduler();
});

// 5. Graceful shutdown. The Hostinger control panel
// sends SIGTERM (preferred) or SIGINT (fallback) when
// the application needs to restart. We:
//   a) stop accepting new connections (server.close)
//   b) stop the managed scheduler (clear timers
//      and wait for any in-flight job within a
//      bounded grace period)
//   c) wait up to 5 seconds for in-flight requests
//   d) exit 0
function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  logger.info({ msg: 'shutdown.start', signal });
  const timeout = setTimeout(() => {
    logger.warn({ msg: 'shutdown.timeout', timeoutMs: 5000 });
    process.exit(0);
  }, 5000);
  timeout.unref();
  // Stop the scheduler first so no NEW jobs start
  // after server.close() begins. The scheduler's
  // own grace period (default 5s) caps the wait.
  const stopScheduler = managedScheduler && managedScheduler.isEnabled()
    ? managedScheduler.stop().catch((err) => logger.error({ msg: 'managed-scheduler.stop-error', error: sanitizeError(err) }))
    : Promise.resolve();
  stopScheduler.finally(() => {
    server.close(() => {
      clearTimeout(timeout);
      logger.info({ msg: 'shutdown.done' });
      process.exit(0);
    });
  });
}

for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, () => shutdown(sig));
}

// 6. Uncaught errors. The Hostinger runtime would
// kill the process anyway; we log a sanitized
// message first so the operator sees what happened.
process.on('uncaughtException', (err) => {
  logger.error({ msg: 'uncaughtException', error: sanitizeError(err) });
});
process.on('unhandledRejection', (err) => {
  logger.error({ msg: 'unhandledRejection', error: sanitizeError(err && err.message ? { name: 'Rejection', message: String(err) } : { name: 'Rejection', message: 'unknown' }) });
});
