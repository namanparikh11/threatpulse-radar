#!/usr/bin/env node
/**
 * V6.2 — portable HTTP application.
 *
 * A small Node HTTP application that serves the
 * public-dataset shape used by the V6.0 / V6.1
 * dashboard. The server uses native Node HTTP — no
 * Express or other large dependency. The route
 * surface is intentionally small.
 *
 * Routes:
 *   GET /health            liveness probe
 *   GET /ready             readiness probe
 *   GET /api/dataset       default dataset + V6.1 additions
 *   GET /api/dataset?view=osv&version=...&cve=...
 *   GET /api/dataset?view=changes&version=...&category=...&limit=25
 *
 * Configuration:
 *   THREATPULSE_HTTP_HOST  (default 127.0.0.1)
 *   THREATPULSE_HTTP_PORT  (default 8787)
 *   THREATPULSE_STORAGE_BACKEND  netlify|filesystem|memory
 *   THREATPULSE_DATA_ROOT  required for filesystem backend
 *
 * No secrets are read from the environment; the server
 * is intended for local development and for non-Netlify
 * deployments. For production use, run behind a reverse
 * proxy that terminates TLS and authenticates the
 * caller.
 */

import { createServer } from 'node:http';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..');

import { resolveConfig } from './config.mjs';
import { handleHealth } from './routes/health.mjs';
import { handleReady } from './routes/ready.mjs';
import { handleDataset } from './routes/dataset.mjs';

const config = resolveConfig();

const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const path = url.pathname;
    if (path === '/health' && req.method === 'GET') {
      const r = handleHealth();
      writeResponse(res, r);
      return;
    }
    if (path === '/ready' && req.method === 'GET') {
      const r = await handleReady({ config });
      writeResponse(res, r);
      return;
    }
    if (path === '/api/dataset' && req.method === 'GET') {
      const r = await handleDataset(req, { config });
      writeResponse(res, r);
      return;
    }
    writeResponse(res, new Response(JSON.stringify({ error: 'not-found' }), {
      status: 404,
      headers: { 'Content-Type': 'application/json; charset=utf-8' },
    }));
  } catch (err) {
    const message = err && err.message ? err.message : String(err);
    writeResponse(res, new Response(JSON.stringify({ error: 'internal', message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json; charset=utf-8' },
    }));
  }
});

function writeResponse(res, response) {
  res.statusCode = response.status;
  for (const [k, v] of response.headers.entries()) {
    res.setHeader(k, v);
  }
  response.text().then((body) => res.end(body)).catch(() => res.end());
}

server.listen(config.port, config.host, () => {
  // eslint-disable-next-line no-console
  console.error(`[v6.2 http] listening on http://${config.host}:${config.port} (storage=${config.backend})`);
});

// Graceful shutdown.
for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, () => {
    // eslint-disable-next-line no-console
    console.error(`[v6.2 http] received ${sig}, closing`);
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 2000).unref();
  });
}
