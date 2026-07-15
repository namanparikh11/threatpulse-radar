#!/usr/bin/env node
// V6.2 — HTTP server + CLI jobs acceptance.
//
//   node scripts/acceptance-v62-http-and-cli.mjs

import { fileURLToPath } from 'node:url';
import { dirname, resolve, join } from 'node:path';
import { spawn } from 'node:child_process';
import { setTimeout as wait } from 'node:timers/promises';
import { mkdtempSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..');

let passed = 0;
let failed = 0;
const failures = [];
function assert(label, cond, extra = '') {
  if (cond) { passed++; console.log(`  PASS  ${label}`); }
  else { failed++; failures.push({ label, extra }); console.log(`  FAIL  ${label}${extra ? `  -- ${extra}` : ''}`); }
}

console.log('V6.2 — HTTP server + CLI jobs acceptance');
console.log('=========================================');
console.log('');

function runNode(args, opts = {}) {
  return new Promise((resolveRun) => {
    const proc = spawn('node', args, {
      cwd: root, stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env, ...(opts.env || {}) },
    });
    let out = '', err = '';
    proc.stdout.on('data', (d) => { out += d.toString(); });
    proc.stderr.on('data', (d) => { err += d.toString(); });
    proc.on('close', (code) => resolveRun({ code, out, err }));
  });
}

/* ---- 1. CLI job exit codes ---- */
console.log('[1] CLI job exit codes');

// verify-state with no data produces a partial exit code
// (the source has no data; some artifacts are missing).
{
  const empty = mkdtempSync(join(tmpdir(), 'tpr-cli-'));
  try {
    // The default backend is 'netlify' which requires
    // the Netlify runtime; an empty tmp directory
    // would trigger STORAGE_FAILURE without producing
    // a report. Set THREATPULSE_STORAGE_BACKEND so
    // verify-state runs against a real (empty)
    // filesystem and reports the missing artifacts.
    const r = await runNode(
      ['jobs/verify-state.mjs', `--data-root=${empty}`, '--json'],
      { env: { THREATPULSE_STORAGE_BACKEND: 'filesystem' } },
    );
    // The verify-state CLI exits 6 (PARTIAL) when some
    // artifacts are missing on a working storage adapter.
    // The test asserts the empty state produces a
    // partial exit (code 6) and a JSON report with
    // the expected structure.
    assert('verify-state exits 6 (PARTIAL) on empty filesystem', r.code === 6, `code=${r.code}`);
    const parsed = JSON.parse(r.out);
    assert('verify-state JSON report is present', parsed && parsed.missing && Array.isArray(parsed.missing));
    assert('verify-state JSON report missing list is non-empty on empty state',
      parsed.missing.length > 0,
      `got: ${parsed.missing.length}`);
  } finally {
    rmSync(empty, { recursive: true, force: true });
  }
}

// --help on every CLI job exits 0 and prints usage.
for (const job of ['refresh-dataset', 'refresh-baseline', 'publish-dataset-intelligence', 'gc-public-intelligence', 'verify-state']) {
  const r = await runNode([`jobs/${job}.mjs`, '--help']);
  assert(`jobs/${job}.mjs --help exits 0`, r.code === 0, `code=${r.code}`);
}

// Invalid arguments produce a non-zero exit code.
{
  const r = await runNode(['jobs/verify-state.mjs', '--unknown-flag']);
  assert('verify-state rejects unknown flags', r.code === 1, `code=${r.code}`);
}

/* ---- 2. HTTP server routes ---- */
console.log('');
console.log('[2] HTTP server routes');

const httpChild = spawn('node', ['server/http.mjs'], {
  cwd: root, stdio: ['ignore', 'pipe', 'pipe'],
  env: { ...process.env, THREATPULSE_STORAGE_BACKEND: 'memory' },
});
let httpStarted = false;
httpChild.stderr.on('data', (d) => {
  const s = d.toString();
  if (s.includes('listening on')) httpStarted = true;
});
for (let i = 0; i < 30 && !httpStarted; i++) await wait(100);
assert('HTTP server started', httpStarted);

try {
  // /health
  const health = await fetch('http://127.0.0.1:8787/health');
  assert('GET /health returns 200', health.status === 200);
  const healthBody = await health.json();
  assert('GET /health body has status=ok', healthBody.status === 'ok');

  // /ready (with empty store)
  const ready = await fetch('http://127.0.0.1:8787/ready');
  // Empty store: ready is false, but the endpoint returns.
  assert('GET /ready returns 200 or 503', ready.status === 200 || ready.status === 503, `status=${ready.status}`);

  // /api/dataset (default mode)
  const dataset = await fetch('http://127.0.0.1:8787/api/dataset');
  assert('GET /api/dataset returns 200', dataset.status === 200);
  const datasetBody = await dataset.json();
  assert('GET /api/dataset has publicIntelligenceStatus', typeof datasetBody.publicIntelligenceStatus === 'string');
  assert('GET /api/dataset has source=portable-server', datasetBody.source === 'portable-server');

  // /api/dataset?view=osv
  const osv = await fetch('http://127.0.0.1:8787/api/dataset?view=osv&version=foo&cve=CVE-2024-1234');
  assert('GET /api/dataset?view=osv returns 400 (invalid version)', osv.status === 400);

  // /api/dataset?view=changes
  const changes = await fetch('http://127.0.0.1:8787/api/dataset?view=changes&version=foo&category=garbage');
  assert('GET /api/dataset?view=changes returns 400 (invalid version)', changes.status === 400);

  // /nope
  const notFound = await fetch('http://127.0.0.1:8787/nope');
  assert('GET /nope returns 404', notFound.status === 404);
} finally {
  httpChild.kill();
  // Give the OS a moment to release the port.
  await wait(200);
}

/* ---- 3. CLI job: gc-public-intelligence dry-run ---- */
console.log('');
console.log('[3] CLI job: gc-public-intelligence --dry-run');

{
  const r = await runNode(['jobs/gc-public-intelligence.mjs', '--dry-run']);
  assert('gc dry-run exits 0', r.code === 0, `code=${r.code} stderr=${r.err.slice(-200)}`);
}

/* ---- 4. CLI job: refresh-dataset --dry-run ---- */
console.log('');
console.log('[4] CLI job: refresh-dataset --dry-run');

{
  const r = await runNode(['jobs/refresh-dataset.mjs', '--dry-run']);
  // refresh-dataset dry-run with no data root may exit
  // non-zero because the lock is acquired then released
  // (it does not actually invoke the refresh). The test
  // accepts either exit code as long as the dry-run
  // path is exercised.
  assert('refresh-dataset dry-run runs without crash', r.code === 0 || r.code === 6, `code=${r.code}`);
}

/* ---- Summary ---- */
console.log('');
console.log('---');
console.log(`PASSED: ${passed}`);
console.log(`FAILED: ${failed}`);
if (failed > 0) {
  for (const f of failures) console.log(`  FAIL: ${f.label}${f.extra ? ` (${f.extra})` : ''}`);
  process.exit(1);
}
process.exit(0);
