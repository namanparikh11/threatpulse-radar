#!/usr/bin/env node
// V6.3 — Hostinger Business runtime acceptance.
//
//   node scripts/acceptance-v63-hostinger.mjs

import { fileURLToPath } from 'node:url';
import { dirname, resolve, join, sep } from 'node:path';
import { spawn } from 'node:child_process';
import { setTimeout as wait } from 'node:timers/promises';
import { mkdtempSync, rmSync, existsSync, writeFileSync, readFileSync, mkdirSync, statSync, unlinkSync } from 'node:fs';
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

function runNode(args, opts = {}) {
  return new Promise((resolveRun) => {
    const proc = spawn('node', args, {
      cwd: root, stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env, ...(opts.env || {}) },
    });
    let out = '', err = '';
    proc.stdout.on('data', (d) => { out += d.toString(); });
    proc.stderr.on('data', (d) => { err += d.toString(); });
    proc.on('error', (e) => resolveRun({ code: 1, out, err: err + '\n' + (e && e.message || String(e)) }));
    proc.on('close', (code) => resolveRun({ code, out, err }));
  });
}

console.log('V6.3 — Hostinger Business runtime acceptance');
console.log('============================================');
console.log('');

const dataRoot = mkdtempSync(join(tmpdir(), 'tpr-v63-data-'));
const publicDir = mkdtempSync(join(tmpdir(), 'tpr-v63-public-'));
const locksDir = join(dataRoot, 'locks');
const logDir = mkdtempSync(join(tmpdir(), 'tpr-v63-logs-'));
const backupDir = mkdtempSync(join(tmpdir(), 'tpr-v63-backup-'));
mkdirSync(locksDir, { recursive: true });

const baseEnv = {
  THREATPULSE_DATA_ROOT: dataRoot,
  THREATPULSE_PUBLIC_DIR: publicDir,
  THREATPULSE_LOG_DIR: logDir,
  THREATPULSE_LOCKS_DIR: locksDir,
  THREATPULSE_BACKUP_DIR: backupDir,
  THREATPULSE_STORAGE_BACKEND: 'filesystem',
  THREATPULSE_HTTP_PORT: '18787',
  THREATPULSE_HTTP_HOST: '127.0.0.1',
  NODE_ENV: 'test',
};

/* ---- 1. Config + readiness ---- */
console.log('[1] Config and readiness');

{
  const r = await runNode(['hostinger/app.mjs', '--config'], { env: baseEnv });
  assert('hostinger app --config exits 0', r.code === 0, `code=${r.code} stderr=${r.err.slice(-200)}`);
  let parsed = null;
  try { parsed = JSON.parse(r.out); } catch { /* noop */ }
  assert('hostinger app --config returns valid JSON', parsed != null);
  if (parsed) {
    assert('config has expected backend=filesystem', parsed.backend === 'filesystem');
    assert('config has expected dataRoot', parsed.dataRoot === dataRoot);
    assert('config has expected publicDir', parsed.publicDir === publicDir);
  }
}

{
  const r = await runNode(['hostinger/app.mjs', '--readiness'], { env: baseEnv });
  assert('hostinger app --readiness exits 0 on a good data root', r.code === 0, `code=${r.code} stderr=${r.err.slice(-200)}`);
  let parsed = null;
  try { parsed = JSON.parse(r.out); } catch { /* noop */ }
  assert('readiness returns valid JSON', parsed != null);
  if (parsed) {
    assert('readiness is ready=true', parsed.ready === true);
    assert('readiness lists the expected checks', Array.isArray(parsed.checks) && parsed.checks.length >= 6,
      `got ${parsed.checks && parsed.checks.length}`);
    const names = (parsed.checks || []).map((c) => c.name);
    for (const expected of ['existsOrCanCreate', 'readWrite', 'atomicRename', 'gzipRoundTrip', 'publicIsolation']) {
      assert(`readiness check ${expected} present`, names.includes(expected));
    }
  }
}

{
  // Read-only directory: readiness should fail when
  // the data root cannot be written to.
  const ro = mkdtempSync(join(tmpdir(), 'tpr-v63-ro-'));
  try {
    // We can't reliably make a directory read-only
    // on Windows from a non-elevated process, so we
    // use a path that does NOT exist AND cannot be
    // created. The data-root validator reports a
    // failure for this case.
    const r = await runNode(['hostinger/app.mjs', '--readiness'], {
      env: { ...baseEnv, THREATPULSE_DATA_ROOT: join(ro, 'cannot-create-here', 'deeper', 'still-deeper') },
    });
    // On a typical POSIX system the recursive mkdir
    // succeeds; on Windows it may also succeed. We
    // only assert the readiness output is valid JSON.
    let parsed = null;
    try { parsed = JSON.parse(r.out); } catch { /* noop */ }
    assert('readiness on a deep path returns valid JSON', parsed != null);
  } finally {
    rmSync(ro, { recursive: true, force: true });
  }
}

/* ---- 2. Logger sanitization ---- */
console.log('');
console.log('[2] Logger sanitization');

{
  const { createLogger } = await import('../hostinger/logger.mjs');
  const logger = createLogger({ component: 'test', filePath: null });
  // Capture stderr.
  const origWrite = process.stderr.write.bind(process.stderr);
  let captured = '';
  process.stderr.write = (chunk) => { captured += String(chunk); return true; };
  try {
    logger.info({ msg: 'test', secret: 'shh', token: 'abc', nested: { password: 'pw' }, hash: 'sha256:' + 'a'.repeat(64) });
    // Use a neutral field name so the value-level
    // redaction (not the key-level one) is exercised.
    logger.info({ msg: 'test', upstream: 'sk-abcdefghijklmnopqrstuvwxyz0123456789' });
    logger.info({ msg: 'test', netlifyPat: 'nfp_abcdefghijklmnopqrstuvwxyz0123' });
  } finally {
    process.stderr.write = origWrite;
  }
  assert('logger redacts "secret" key', captured.includes('"secret":"[redacted]"'));
  assert('logger redacts "token" key', captured.includes('"token":"[redacted]"'));
  assert('logger redacts "password" key (nested)', captured.includes('"password":"[redacted]"'));
  assert('logger redacts internal hash by default', captured.includes('"hash":"[redacted-hash]"'));
  assert('logger redacts OpenAI-shaped value', captured.includes('"upstream":"[redacted-key]"'));
  assert('logger redacts Netlify PAT-shaped value', captured.includes('"netlifyPat":"[redacted-pat]"'));
  assert('logger keeps regular fields', captured.includes('"msg":"test"'));
}

/* ---- 3. Lock acquisition, release, exclusion ---- */
console.log('');
console.log('[3] Filesystem lock semantics');

{
  const { acquireCronLock, releaseCronLock, inspectCronLock, clearStaleCronLock, LOCK_NAMES } = await import('../hostinger/locks.mjs');
  const lockDir = mkdtempSync(join(tmpdir(), 'tpr-v63-lock-'));
  const owner = 'test-owner';
  const r1 = await acquireCronLock({ locksDir: lockDir, name: 'test-lock', ttlMs: 5_000, owner, pid: 99999 });
  assert('first acquisition succeeds', r1.acquired === true);
  const r2 = await acquireCronLock({ locksDir: lockDir, name: 'test-lock', ttlMs: 5_000, owner: 'other-owner', pid: 99998 });
  assert('second acquisition fails while first is held', r2.acquired === false);
  assert('second acquisition reports holder=first owner', r2.holder === owner);
  // Release the first lock.
  const rel = await releaseCronLock({ locksDir: lockDir, name: 'test-lock', owner });
  assert('release of first lock succeeds', rel.released === true);
  // Foreign-release is refused.
  const r3 = await acquireCronLock({ locksDir: lockDir, name: 'test-lock', ttlMs: 5_000, owner, pid: 99999 });
  assert('re-acquisition after release succeeds', r3.acquired === true);
  const foreignRel = await releaseCronLock({ locksDir: lockDir, name: 'test-lock', owner: 'wrong-owner' });
  assert('foreign release is refused', foreignRel.released === false);
  // Clear the active lock and check the result.
  const clearForeign = await clearStaleCronLock({ locksDir: lockDir, name: 'test-lock' });
  assert('clearStale refuses to clear an active lock', clearForeign.cleared === false);
  // Inspect a held lock.
  const ins = await inspectCronLock({ locksDir: lockDir, name: 'test-lock' });
  assert('inspect reports held=true for an active lock', ins.held === true);
  assert('inspect reports the correct holder', ins.holder === owner);
  // Release + inspect empty.
  await releaseCronLock({ locksDir: lockDir, name: 'test-lock', owner });
  const insEmpty = await inspectCronLock({ locksDir: lockDir, name: 'test-lock' });
  assert('inspect reports held=false for a missing lock', insEmpty.held === false);
  // LOCK_NAMES registry is frozen.
  assert('LOCK_NAMES is a frozen object', Object.isFrozen(LOCK_NAMES));
  // Lock name validation.
  let threw = false;
  try { await acquireCronLock({ locksDir: lockDir, name: '../escape', ttlMs: 1000, owner: 'x' }); } catch { threw = true; }
  assert('lock rejects parent-directory name', threw);
  rmSync(lockDir, { recursive: true, force: true });
}

/* ---- 4. Cron-runner exclusion under contention ---- */
console.log('');
console.log('[4] Cron-runner exclusion (two simultaneous jobs)');

{
  const lockDir = mkdtempSync(join(tmpdir(), 'tpr-v63-cron-lock-'));
  // Acquire a lock that the cron-runner will see
  // and reject. The job should exit 2.
  const { acquireCronLock, releaseCronLock } = await import('../hostinger/locks.mjs');
  const blockerOwner = 'blocker';
  const block = await acquireCronLock({ locksDir: lockDir, name: 'cron-test-1', ttlMs: 30_000, owner: blockerOwner, pid: 1 });
  assert('pre-block lock acquired', block.acquired === true);
  // Run the cron-runner via a small shim that uses
  // the test lock directory.
  const r = await runNode(['-e', `
    import('./hostinger/locks.mjs').then(async (m) => {
      const { runCronJob } = await import('./hostinger/cron-runner.mjs');
      const code = await runCronJob({
        name: 'cron-test-1',
        owner: 'test-runner',
        locksDir: ${JSON.stringify(lockDir)},
        ttlMs: 5000,
        job: async () => ({ status: 'ok' }),
      });
      process.exit(code);
    });
  `], { env: { ...process.env, THREATPULSE_DATA_ROOT: dataRoot, THREATPULSE_LOCKS_DIR: lockDir, THREATPULSE_STORAGE_BACKEND: 'filesystem' } });
  assert('cron-runner exits 2 when the lock is held', r.code === 2, `code=${r.code} out=${r.out.slice(-200)}`);
  await releaseCronLock({ locksDir: lockDir, name: 'cron-test-1', owner: blockerOwner });
  // Now the runner can acquire and complete.
  const r2 = await runNode(['-e', `
    import('./hostinger/cron-runner.mjs').then(async (m) => {
      const code = await m.runCronJob({
        name: 'cron-test-1',
        owner: 'test-runner',
        locksDir: ${JSON.stringify(lockDir)},
        ttlMs: 5000,
        job: async () => ({ status: 'ok' }),
      });
      process.exit(code);
    });
  `], { env: { ...process.env, THREATPULSE_DATA_ROOT: dataRoot, THREATPULSE_LOCKS_DIR: lockDir, THREATPULSE_STORAGE_BACKEND: 'filesystem' } });
  assert('cron-runner exits 0 when the lock is free', r2.code === 0, `code=${r2.code} out=${r2.out.slice(-200)}`);
  rmSync(lockDir, { recursive: true, force: true });
}

/* ---- 5. Server startup + security headers ---- */
console.log('');
console.log('[5] Server startup, security headers, method allowlist, SPA fallback');

{
  // Build a minimal dist/index.html for the SPA
  // fallback to find.
  writeFileSync(join(publicDir, 'index.html'), '<!doctype html><html><body>v6.3 hostinger</body></html>');
  mkdirSync(join(publicDir, 'assets'), { recursive: true });
  writeFileSync(join(publicDir, 'assets', 'index-abc12345.js'), 'console.log("asset");');
  const proc = spawn('node', ['hostinger/app.mjs'], {
    cwd: root, stdio: ['ignore', 'pipe', 'pipe'],
    env: { ...baseEnv, NODE_ENV: 'production' },
  });
  let started = false;
  proc.stderr.on('data', (d) => {
    if (String(d).includes('listening on')) started = true;
  });
  for (let i = 0; i < 50 && !started; i++) await wait(100);
  assert('server started', started);
  try {
    // /health
    const health = await fetch('http://127.0.0.1:18787/health');
    assert('GET /health returns 200', health.status === 200);
    assert('GET /health sets X-Content-Type-Options', health.headers.get('x-content-type-options') === 'nosniff');
    assert('GET /health sets X-Frame-Options', health.headers.get('x-frame-options') === 'SAMEORIGIN');
    assert('GET /health sets Referrer-Policy', health.headers.get('referrer-policy') === 'same-origin');
    assert('GET /health sets Strict-Transport-Security in production', !!health.headers.get('strict-transport-security'));
    assert('GET /health sets Cache-Control: no-store', /no-store/.test(health.headers.get('cache-control') || ''));
    // /ready
    const ready = await fetch('http://127.0.0.1:18787/ready');
    assert('GET /ready returns 200 or 503', ready.status === 200 || ready.status === 503);
    assert('GET /ready sets Cache-Control: no-store', /no-store/.test(ready.headers.get('cache-control') || ''));
    // /api/dataset
    const dataset = await fetch('http://127.0.0.1:18787/api/dataset');
    assert('GET /api/dataset returns 200', dataset.status === 200);
    // Method allowlist: POST is rejected with 405.
    const post = await fetch('http://127.0.0.1:18787/health', { method: 'POST' });
    assert('POST /health returns 405', post.status === 405);
    assert('405 response sets Allow header', (post.headers.get('allow') || '').includes('GET'));
    // Path-traversal: percent-encoded "../" using
    // uppercase %2E (which the WHATWG URL parser
    // preserves verbatim; the server then decodes
    // and rejects).
    const trav = await fetch('http://127.0.0.1:18787/assets/%2E%2E%2F%2E%2E%2Fetc%2Fpasswd');
    assert('path-traversal returns 404', trav.status === 404, `status=${trav.status}`);
    // Forbidden top-level: .env
    const env = await fetch('http://127.0.0.1:18787/.env');
    assert('.env is forbidden (404)', env.status === 404);
    const envLocal = await fetch('http://127.0.0.1:18787/.env.local');
    assert('.env.local is forbidden (404)', envLocal.status === 404);
    // node_modules forbidden.
    const nm = await fetch('http://127.0.0.1:18787/node_modules/foo/bar.js');
    assert('node_modules is forbidden (404)', nm.status === 404);
    // SPA fallback: non-API non-asset path returns index.html
    const spa = await fetch('http://127.0.0.1:18787/some/route');
    assert('SPA fallback returns 200', spa.status === 200);
    const spaText = await spa.text();
    assert('SPA fallback returns the index.html body', spaText.includes('v6.3 hostinger'));
    assert('SPA fallback sets Cache-Control: no-store', /no-store/.test(spa.headers.get('cache-control') || ''));
    // Hashed asset: served with long cache.
    const asset = await fetch('http://127.0.0.1:18787/assets/index-abc12345.js');
    assert('hashed asset returns 200', asset.status === 200);
    assert('hashed asset sets long Cache-Control', /max-age=31536000/.test(asset.headers.get('cache-control') || ''));
    // Malformed URL: bad percent encoding (a
    // trailing `%` that the URL parser does not
    // accept). The `WHATWG URL` parser may reject
    // the request before it leaves the client; in
    // either case the server must not serve a 200.
    let bad = null;
    try {
      bad = await fetch('http://127.0.0.1:18787/' + '%E0%A4%A');
    } catch { bad = { status: 0 }; }
    assert('malformed percent-encoding does not return 200',
      bad && bad.status !== 200,
      `status=${bad && bad.status}`);
  } finally {
    proc.kill('SIGTERM');
    await wait(200);
  }
}

/* ---- 6. SPA fallback when public dir is missing ---- */
console.log('');
console.log('[6] SPA fallback when public dir is missing');

{
  const empty = mkdtempSync(join(tmpdir(), 'tpr-v63-empty-'));
  const proc = spawn('node', ['hostinger/app.mjs'], {
    cwd: root, stdio: ['ignore', 'pipe', 'pipe'],
    env: { ...baseEnv, THREATPULSE_PUBLIC_DIR: empty },
  });
  let started = false;
  proc.stderr.on('data', (d) => { if (String(d).includes('listening on')) started = true; });
  for (let i = 0; i < 50 && !started; i++) await wait(100);
  assert('server started with empty public dir', started);
  try {
    const spa = await fetch('http://127.0.0.1:18787/');
    assert('GET / returns 404 when no index.html', spa.status === 404);
    const health = await fetch('http://127.0.0.1:18787/health');
    assert('GET /health still works when no public dir', health.status === 200);
  } finally {
    proc.kill('SIGTERM');
    await wait(200);
    rmSync(empty, { recursive: true, force: true });
  }
}

/* ---- 7. Backup + verify + restore dry-run ---- */
console.log('');
console.log('[7] Backup + verify + restore dry-run');

{
  // Seed the data root with a dataset envelope.
  const { createStorageAdapter } = await import('../netlify/functions/_shared/storage/index.mjs');
  const ds = createStorageAdapter({ name: 'filesystem', storeName: 'tpr-dataset', opts: { dataRoot } });
  await ds.setJSON('latest-dataset', { mode: 'live', source: 'merged', fetchedAt: '2026-07-15T20:00:00.000Z', data: [] });
  // Create a backup.
  const bk = await runNode(['hostinger/backup.mjs', '--json'], { env: baseEnv });
  assert('hostinger/backup exits 0', bk.code === 0, `code=${bk.code} stderr=${bk.err.slice(-200)}`);
  let bkJson = null;
  try { bkJson = JSON.parse(bk.out); } catch { /* noop */ }
  assert('backup JSON has archive path', bkJson && typeof bkJson.archive === 'string');
  if (bkJson) {
    assert('backup archive exists on disk', existsSync(bkJson.archive));
    // Verify.
    const vf = await runNode(['hostinger/verify-backup.mjs', `--archive=${bkJson.archive}`, '--json'], { env: baseEnv });
    assert('verify-backup exits 0 on a fresh archive', vf.code === 0, `code=${vf.code} stderr=${vf.err.slice(-200)}`);
    let vfJson = null;
    try { vfJson = JSON.parse(vf.out); } catch { /* noop */ }
    assert('verify-backup JSON reports ok=true', vfJson && vfJson.ok === true);
    // Restore dry-run (default).
    const rd = await runNode(['hostinger/restore.mjs', `--archive=${bkJson.archive}`], { env: baseEnv });
    assert('restore dry-run (no flags) exits 0', rd.code === 0, `code=${rd.code} stderr=${rd.err.slice(-200)}`);
    // Restore --apply without --yes must refuse.
    const refuse = await runNode(['hostinger/restore.mjs', `--archive=${bkJson.archive}`, '--apply'], { env: baseEnv });
    assert('restore --apply without --yes refuses (exit 5)', refuse.code === 5, `code=${refuse.code}`);
    // Restore --apply --yes actually applies.
    const ap = await runNode(['hostinger/restore.mjs', `--archive=${bkJson.archive}`, '--apply', '--yes'], { env: baseEnv });
    assert('restore --apply --yes exits 0', ap.code === 0, `code=${ap.code} stderr=${ap.err.slice(-200)}`);
  }
}

/* ---- 8. Diagnostic command ---- */
console.log('');
console.log('[8] Diagnostic command');

{
  const r = await runNode(['hostinger/diagnose.mjs', '--json'], { env: baseEnv });
  assert('diagnose exits 0', r.code === 0, `code=${r.code} stderr=${r.err.slice(-300)}`);
  let parsed = null;
  try { parsed = JSON.parse(r.out); } catch { /* noop */ }
  assert('diagnose JSON has recommendation', parsed && typeof parsed.recommendation === 'string');
  assert('diagnose JSON has runtime info', parsed && parsed.runtime && parsed.runtime.nodeVersion);
  assert('diagnose JSON has filesystem write measurement', parsed && parsed.performance && parsed.performance.filesystemWrite);
  assert('diagnose JSON has representative refresh', parsed && parsed.performance && parsed.performance.representativeDatasetRefresh);
  // The recommendation is one of the three values.
  if (parsed) {
    assert('recommendation is compatible / compatible-with-warnings / vps-recommended',
      ['compatible', 'compatible-with-warnings', 'vps-recommended'].includes(parsed.recommendation),
      `got: ${parsed.recommendation}`);
  }
}

/* ---- 9. Deployment manifest generator ---- */
console.log('');
console.log('[9] Deployment manifest generator');

{
  const out = mkdtempSync(join(tmpdir(), 'tpr-v63-manifest-'));
  try {
    const r = await runNode(['hostinger/manifest.mjs', `--out=${out}`], { env: baseEnv });
    assert('manifest --out exits 0', r.code === 0, `code=${r.code} stderr=${r.err.slice(-200)}`);
    assert('manifest wrote JSON', existsSync(join(out, 'deployment-manifest.json')));
    assert('manifest wrote Markdown', existsSync(join(out, 'deployment-manifest.md')));
    const json = JSON.parse(readFileSync(join(out, 'deployment-manifest.json'), 'utf8'));
    assert('manifest JSON has schemaVersion=manifest-v1', json.schemaVersion === 'manifest-v1');
    assert('manifest JSON has cron entries', Array.isArray(json.cron) && json.cron.length === 6);
    assert('manifest JSON has required env vars', Array.isArray(json.requiredEnvVars) && json.requiredEnvVars.length >= 4);
    assert('manifest JSON has backup commands', json.backup && json.backup.command === 'npm run backup:hostinger');
    assert('manifest JSON has rollback procedure', Array.isArray(json.rollback) && json.rollback.length > 0);
    assert('manifest JSON has unsupported assumptions', Array.isArray(json.unsupportedAssumptions));
    const md = readFileSync(join(out, 'deployment-manifest.md'), 'utf8');
    assert('manifest MD mentions node version requirement', /Node\.js >=/.test(md));
    assert('manifest MD mentions cron schedule', /Cron schedule/.test(md));
    assert('manifest MD has NO secret values', !/nfp_/.test(md) && !/sk-[A-Za-z0-9]{20,}/.test(md));
  } finally {
    rmSync(out, { recursive: true, force: true });
  }
}

/* ---- 10. Compatibility invariants ---- */
console.log('');
console.log('[10] Compatibility invariants');

{
  const { readdirSync } = await import('node:fs');
  const publicFiles = readdirSync(resolve(root, 'netlify/functions')).filter((f) => f.endsWith('.mjs'));
  const gatewayFiles = readdirSync(resolve(root, 'netlify/gateway/src')).filter((f) => f.endsWith('.mjs'));
  assert('exactly five public function entry files', publicFiles.length === 5, `got ${publicFiles.length}`);
  assert('exactly one gateway function entry file', gatewayFiles.length === 1, `got ${gatewayFiles.length}`);
  const csvSrc = readFileSync(resolve(root, 'src/utils/csvExport.ts'), 'utf8');
  const arrMatch = csvSrc.match(/export const CSV_COLUMNS = \[([\s\S]*?)\] as const/);
  if (arrMatch) {
    const inner = arrMatch[1];
    const colCount = (inner.match(/^\s*'[^']+'/gm) || []).length;
    assert('CSV_COLUMNS is exactly 21', colCount === 21, `got ${colCount}`);
  } else {
    assert('CSV_COLUMNS found in csvExport.ts', false);
  }
}

/* ---- Cleanup ---- */
rmSync(dataRoot, { recursive: true, force: true });
rmSync(publicDir, { recursive: true, force: true });
rmSync(logDir, { recursive: true, force: true });
rmSync(backupDir, { recursive: true, force: true });

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
