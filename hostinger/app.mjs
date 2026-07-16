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
// via server.close().
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
    // Method allowlist per path. Anything else is a
    // sanitized 405. This protects the storage
    // adapter from accidental writes via, e.g.,
    // POST /health.
    const allowMethod = (m) => m === 'GET' || m === 'HEAD';
    if (!allowMethod(req.method)) {
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
    // Unknown path.
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
    for (const [k, v] of response.headers.entries()) {
      // Cache-Control is the most important override:
      // we force no-store on every API response.
      if (k.toLowerCase() === 'cache-control' && !v) continue;
      res.setHeader(k, v);
    }
    if (!res.getHeader('Cache-Control')) {
      res.setHeader('Cache-Control', 'no-store');
    }
    response.text().then((body) => res.end(body)).catch(() => res.end());
  } catch (err) {
    try { res.statusCode = 500; res.end(); } catch { /* noop */ }
  }
}

// 4. Listen. On EADDRINUSE or other bind errors,
// surface a sanitized message and exit 1.
server.on('error', (err) => {
  logger.error({ msg: 'listen.error', error: sanitizeError(err) });
  console.error(JSON.stringify({ error: 'listen-failed', code: err.code || null, message: err.message }));
  process.exit(1);
});

server.listen(cfg.port, cfg.host, () => {
  logger.info({ msg: 'listening', host: cfg.host, port: cfg.port });
  // eslint-disable-next-line no-console
  console.error(`[v6.3 hostinger] listening on http://${cfg.host}:${cfg.port} (storage=${cfg.backend}, data=${cfg.dataRoot})`);
});

// 5. Graceful shutdown. The Hostinger control panel
// sends SIGTERM (preferred) or SIGINT (fallback) when
// the application needs to restart. We:
//   a) stop accepting new connections (server.close)
//   b) wait up to 5 seconds for in-flight requests
//   c) exit 0
function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  logger.info({ msg: 'shutdown.start', signal });
  const timeout = setTimeout(() => {
    logger.warn({ msg: 'shutdown.timeout', timeoutMs: 5000 });
    process.exit(0);
  }, 5000);
  timeout.unref();
  server.close(() => {
    clearTimeout(timeout);
    logger.info({ msg: 'shutdown.done' });
    process.exit(0);
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
