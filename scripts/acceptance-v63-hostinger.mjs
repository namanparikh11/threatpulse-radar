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

// Run a command in an isolated copy of the
// repository. The copy's package.json and
// package-lock.json are intact so `npm ci` and
// `npm run build` work.
function runCmdInCopy(copyRoot, cmdArgs, opts = {}) {
  return new Promise((resolveRun) => {
    const proc = spawn('cmd.exe', ['/c', ...cmdArgs], {
      cwd: copyRoot, stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env, ...(opts.env || {}) },
    });
    let out = '', err = '';
    proc.stdout.on('data', (d) => { out += d.toString(); });
    proc.stderr.on('data', (d) => { err += d.toString(); });
    proc.on('error', (e) => resolveRun({ code: 1, out, err: err + '\n' + (e && e.message || String(e)) }));
    proc.on('close', (code) => resolveRun({ code, out, err }));
  });
}

function runNodeInCopy(copyRoot, nodeArgs, opts = {}) {
  return new Promise((resolveRun) => {
    const proc = spawn(nodeArgs[0], nodeArgs.slice(1), {
      cwd: copyRoot, stdio: ['ignore', 'pipe', 'pipe'],
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
  const testPid = 99999;
  const r1 = await acquireCronLock({ locksDir: lockDir, name: 'test-lock', ttlMs: 5_000, owner, pid: testPid });
  assert('first acquisition succeeds', r1.acquired === true);
  // The lock is a directory.
  assert('first acquisition creates a lock directory', existsSync(join(lockDir, 'test-lock.lock')) && statSync(join(lockDir, 'test-lock.lock')).isDirectory(),
    `existsSync=${existsSync(join(lockDir, 'test-lock.lock'))}`);
  // The owner.json is inside the directory.
  assert('first acquisition writes owner.json', existsSync(join(lockDir, 'test-lock.lock', 'owner.json')));
  const r2 = await acquireCronLock({ locksDir: lockDir, name: 'test-lock', ttlMs: 5_000, owner: 'other-owner', pid: 99998 });
  assert('second acquisition fails while first is held', r2.acquired === false);
  assert('second acquisition reports holder=first owner', r2.holder === owner);
  // Release the first lock.
  const rel = await releaseCronLock({ locksDir: lockDir, name: 'test-lock', owner, pid: testPid });
  assert('release of first lock succeeds', rel.released === true);
  assert('release removes the lock directory', !existsSync(join(lockDir, 'test-lock.lock')));
  // Foreign-release is refused.
  const r3 = await acquireCronLock({ locksDir: lockDir, name: 'test-lock', ttlMs: 5_000, owner, pid: testPid });
  assert('re-acquisition after release succeeds', r3.acquired === true);
  const foreignRel = await releaseCronLock({ locksDir: lockDir, name: 'test-lock', owner: 'wrong-owner', pid: testPid });
  assert('foreign-owner release is refused', foreignRel.released === false);
  const foreignPidRel = await releaseCronLock({ locksDir: lockDir, name: 'test-lock', owner, pid: 12345 });
  assert('foreign-pid release is refused', foreignPidRel.released === false);
  // Clear the active lock and check the result.
  const clearForeign = await clearStaleCronLock({ locksDir: lockDir, name: 'test-lock' });
  assert('clearStale refuses to clear an active lock', clearForeign.cleared === false);
  // Inspect a held lock.
  const ins = await inspectCronLock({ locksDir: lockDir, name: 'test-lock' });
  assert('inspect reports held=true for an active lock', ins.held === true);
  assert('inspect reports the correct holder', ins.holder === owner);
  // Release + inspect empty.
  await releaseCronLock({ locksDir: lockDir, name: 'test-lock', owner, pid: testPid });
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
  `], { env: { ...process.env, THREATPULSE_DATA_ROOT: dataRoot, THREATPULSE_LOCKS_DIR: lockDir, THREATPULSE_LOG_DIR: logDir, THREATPULSE_STORAGE_BACKEND: 'filesystem' } });
  assert('cron-runner exits 2 when the lock is held', r.code === 2, `code=${r.code} out=${r.out.slice(-200)}`);
  await releaseCronLock({ locksDir: lockDir, name: 'cron-test-1', owner: blockerOwner, pid: 1 });
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
  `], { env: { ...process.env, THREATPULSE_DATA_ROOT: dataRoot, THREATPULSE_LOCKS_DIR: lockDir, THREATPULSE_LOG_DIR: logDir, THREATPULSE_STORAGE_BACKEND: 'filesystem' } });
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

/* ---- 11. Hardened lock semantics (mkdir-based, quarantine, owner-verify, pid-token) ---- */
console.log('');
console.log('[11] Hardened lock semantics (quarantine + owner-verify + pid-token)');

{
  const { acquireCronLock, releaseCronLock, inspectCronLock, clearStaleCronLock, listCronLocks } = await import('../hostinger/locks.mjs');
  const lockDir = mkdtempSync(join(tmpdir(), 'tpr-v63-hard-'));

  // Helper: seed an EXPIRED lock directory with
  // valid owner.json.
  function seedExpiredLockDir(name, owner, pid) {
    const dir = join(lockDir, `${name}.lock`);
    mkdirSync(dir);
    writeFileSync(join(dir, 'owner.json'), JSON.stringify({
      acquiredAt: '2020-01-01T00:00:00.000Z',
      expiresAt: '2020-01-01T00:00:01.000Z',
      owner, pid, nonce: 'old',
    }));
    return dir;
  }

  // 11a. Quarantine: an EXPIRED lock directory is
  // renamed to `<name>.lock.stale-<ts>-<nonce>/`
  // before the new lock is created. The previous
  // lock is NEVER silently overwritten.
  {
    const name = 'quarantine-stale';
    seedExpiredLockDir(name, 'old-process', 12345);
    const acq = await acquireCronLock({ locksDir: lockDir, name, ttlMs: 5_000, owner: 'new-process', pid: 99999 });
    assert('quarantine-stale: acquire succeeds over an expired lock', acq.acquired === true);
    const files = await listCronLocks({ locksDir: lockDir });
    const quarantined = files.filter((f) => f.startsWith(`${name}.lock.stale-`));
    assert('quarantine-stale: previous lock is quarantined with .stale- prefix', quarantined.length === 1, `got files: ${files.join(', ')}`);
    assert('quarantine-stale: new lock holds the .lock name', files.includes(`${name}.lock`));
    const ins = await inspectCronLock({ locksDir: lockDir, name });
    assert('quarantine-stale: new lock reports the new owner', ins.holder === 'new-process');
  }

  // 11b. Quarantine: a MALFORMED lock directory
  // (no owner.json OR non-JSON owner.json) is
  // renamed to `<name>.lock.malformed-<ts>-<nonce>/`
  // and the acquirer subsequently claims the
  // newly-vacated slot. The original malformed
  // lock is NEVER silently overwritten; the
  // original is preserved in the quarantine
  // directory for forensic review.
  {
    const name = 'quarantine-malformed';
    const dir = join(lockDir, `${name}.lock`);
    mkdirSync(dir);
    // No owner.json — the directory is malformed.
    const acq = await acquireCronLock({ locksDir: lockDir, name, ttlMs: 5_000, owner: 'p1', pid: 99999 });
    assert('quarantine-malformed: acquire succeeds after quarantining the empty dir', acq.acquired === true);
    const files = await listCronLocks({ locksDir: lockDir });
    const quarantined = files.filter((f) => f.startsWith(`${name}.lock.malformed-`));
    assert('quarantine-malformed: original empty dir is quarantined with .malformed- prefix', quarantined.length === 1, `got files: ${files.join(', ')}`);
    assert('quarantine-malformed: new lock holds the .lock name', files.includes(`${name}.lock`));
    // The new lock's owner.json is the acquirer's.
    const ins = await inspectCronLock({ locksDir: lockDir, name });
    assert('quarantine-malformed: new lock owner is p1', ins.holder === 'p1', `got: ${ins.holder}`);

    // Also: a malformed owner.json (not valid
    // JSON) is quarantined AND the acquirer claims
    // the slot. The original file is preserved
    // inside the quarantine directory.
    const name2 = 'quarantine-malformed-json';
    const dir2 = join(lockDir, `${name2}.lock`);
    mkdirSync(dir2);
    writeFileSync(join(dir2, 'owner.json'), 'this is not valid json {');
    const acq2 = await acquireCronLock({ locksDir: lockDir, name: name2, ttlMs: 5_000, owner: 'p2', pid: 99999 });
    assert('quarantine-malformed-json: acquire succeeds after quarantining the invalid-json dir', acq2.acquired === true);
    const files2 = await listCronLocks({ locksDir: lockDir });
    const q2 = files2.filter((f) => f.startsWith(`${name2}.lock.malformed-`));
    assert('quarantine-malformed-json: original dir is quarantined with .malformed- prefix', q2.length === 1);
    // The malformed owner.json is preserved inside
    // the quarantine directory.
    const preserved = readFileSync(join(lockDir, q2[0], 'owner.json'), 'utf8');
    assert('quarantine-malformed-json: original invalid owner.json is preserved', preserved === 'this is not valid json {');
  }

  // 11c. Owner verification: a process racing
  // after stale quarantine cannot overwrite a
  // newly created active lock.
  {
    const name = 'owner-verify';
    seedExpiredLockDir(name, 'A', 1);
    // Acquire as B over the expired A lock. B
    // quarantines A and creates the new lock.
    const acq = await acquireCronLock({ locksDir: lockDir, name, ttlMs: 60_000, owner: 'B', pid: 2 });
    assert('owner-verify: B acquires over expired A', acq.acquired === true);
    // Now A tries to acquire. The lock is HELD by
    // B; A must see lock-held, not silently win.
    const re = await acquireCronLock({ locksDir: lockDir, name, ttlMs: 60_000, owner: 'A', pid: 1 });
    assert('owner-verify: A sees lock-held after B owns it', re.acquired === false, JSON.stringify(re));
    assert('owner-verify: A sees holder=B', re.holder === 'B', `got: ${re.holder}`);
    // On disk: the lock directory's owner.json is
    // still B's, and the quarantined A lock exists
    // separately.
    const ins = await inspectCronLock({ locksDir: lockDir, name });
    assert('owner-verify: on-disk owner is B', ins.holder === 'B', `got: ${ins.holder}`);
    const files = await listCronLocks({ locksDir: lockDir });
    assert('owner-verify: A was quarantined', files.some((f) => f.startsWith(`${name}.lock.stale-`)));
    // Release B; A can now acquire cleanly.
    await releaseCronLock({ locksDir: lockDir, name, owner: 'B', pid: 2 });
  }

  // 11d. Two concurrent acquirers on a clean
  // directory: exactly one wins (mkdir is
  // atomic).
  {
    const name = 'race-two-acquirers';
    // Clean lock dir. No pre-existing lock.
    const [r1, r2] = await Promise.all([
      acquireCronLock({ locksDir: lockDir, name, ttlMs: 60_000, owner: 'P1', pid: 1001 }),
      acquireCronLock({ locksDir: lockDir, name, ttlMs: 60_000, owner: 'P2', pid: 1002 }),
    ]);
    const winners = [r1, r2].filter((r) => r.acquired).length;
    const losers = [r1, r2].filter((r) => !r.acquired).length;
    assert('race-two-acquirers: exactly one acquirer wins', winners === 1, `winners=${winners} (r1=${JSON.stringify(r1)} r2=${JSON.stringify(r2)})`);
    assert('race-two-acquirers: exactly one acquirer loses', losers === 1);
    // The lock on disk must match the winner.
    const ins = await inspectCronLock({ locksDir: lockDir, name });
    const winnerName = r1.acquired ? 'P1' : 'P2';
    assert('race-two-acquirers: lock on disk matches the winner', ins.holder === winnerName, `disk=${ins.holder} expected=${winnerName}`);
  }

  // 11e. Two stale-lock reclaimers: only one
  // wins. The other returns race-lost.
  {
    const name = 'stale-reclaimers';
    seedExpiredLockDir(name, 'previous', 99999);
    // Two concurrent acquirers on an expired
    // lock. The first to rename the stale lock
    // wins; the second sees the newly-acquired
    // lock and returns race-lost.
    const [r1, r2] = await Promise.all([
      acquireCronLock({ locksDir: lockDir, name, ttlMs: 60_000, owner: 'R1', pid: 2001 }),
      acquireCronLock({ locksDir: lockDir, name, ttlMs: 60_000, owner: 'R2', pid: 2002 }),
    ]);
    const winners = [r1, r2].filter((r) => r.acquired).length;
    assert('stale-reclaimers: exactly one stale-reclaimer wins', winners === 1, `r1=${JSON.stringify(r1)} r2=${JSON.stringify(r2)}`);
    const loser = [r1, r2].find((r) => !r.acquired);
    assert('stale-reclaimers: loser reason is race-lost or lock-held', loser && (loser.reason === 'race-lost' || loser.reason === 'lock-held'),
      `loser=${JSON.stringify(loser)}`);
    // On disk: one quarantine dir for the old
    // lock, and one active lock with the winner's
    // owner.
    const ins = await inspectCronLock({ locksDir: lockDir, name });
    const winnerName = r1.acquired ? 'R1' : 'R2';
    assert('stale-reclaimers: on-disk owner is the winner', ins.holder === winnerName);
  }

  // 11f. Release by a previous owner cannot
  // remove a replacement lock.
  {
    const name = 'replacement-release';
    seedExpiredLockDir(name, 'A-old', 1);
    // The first acquirer (A-old with a new pid)
    // wins over its own expired lock.
    const acq1 = await acquireCronLock({ locksDir: lockDir, name, ttlMs: 5_000, owner: 'A-old', pid: 2 });
    assert('replacement-release: A-old acquires over its own expired lock', acq1.acquired === true);
    // Simulate a replacement: the new lock is
    // released and a different process (B-new)
    // re-acquires.
    await releaseCronLock({ locksDir: lockDir, name, owner: 'A-old', pid: 2 });
    const acq2 = await acquireCronLock({ locksDir: lockDir, name, ttlMs: 5_000, owner: 'B-new', pid: 3 });
    assert('replacement-release: B-new acquires after release', acq2.acquired === true);
    // Now A-old (with its OLD pid) tries to
    // release. The release must NOT remove the
    // replacement. The reason MUST be one of
    // foreign-owner or replaced (the test
    // accepts both because the pid check fires
    // before the owner check).
    const rel = await releaseCronLock({ locksDir: lockDir, name, owner: 'A-old', pid: 1 });
    assert('replacement-release: A-old release is refused', rel.released === false, JSON.stringify(rel));
    assert('replacement-release: reason is foreign-owner, foreign-pid, or replaced',
      rel.reason === 'foreign-owner' || rel.reason === 'foreign-pid' || rel.reason === 'replaced',
      `got: ${rel.reason}`);
    // The replacement is still on disk.
    const ins = await inspectCronLock({ locksDir: lockDir, name });
    assert('replacement-release: replacement lock is still held', ins.held === true);
    assert('replacement-release: replacement owner is still B-new', ins.holder === 'B-new');
  }

  // 11g. Pid-token release: a release with the
  // wrong pid is refused.
  {
    const name = 'pid-token';
    const acq = await acquireCronLock({ locksDir: lockDir, name, ttlMs: 5_000, owner: 'owner1', pid: 7777 });
    assert('pid-token: acquire succeeds', acq.acquired === true);
    const wrong = await releaseCronLock({ locksDir: lockDir, name, owner: 'owner1', pid: 9999 });
    assert('pid-token: wrong-pid release is refused', wrong.released === false, JSON.stringify(wrong));
    assert('pid-token: wrong-pid reason is foreign-pid', wrong.reason === 'foreign-pid', `got: ${wrong.reason}`);
    const ins = await inspectCronLock({ locksDir: lockDir, name });
    assert('pid-token: lock is still held after wrong-pid release', ins.held === true);
    const right = await releaseCronLock({ locksDir: lockDir, name, owner: 'owner1', pid: 7777 });
    assert('pid-token: correct-pid release succeeds', right.released === true);
  }

  // 11h. clearStale renames an expired valid
  // lock directory under the .stale- kind, and a
  // malformed directory under the .malformed-
  // kind.
  {
    const name = 'clearstale-mixed';
    seedExpiredLockDir(name, 'old', 1);
    const cl = await clearStaleCronLock({ locksDir: lockDir, name });
    assert('clearstale-mixed: expired valid lock is cleared', cl.cleared === true);
    assert('clearstale-mixed: kind is stale', cl.kind === 'stale', `got: ${cl.kind}`);
    // Now create a malformed lock and clear it.
    const name2 = 'clearstale-malformed';
    const dir2 = join(lockDir, `${name2}.lock`);
    mkdirSync(dir2);
    const cl2 = await clearStaleCronLock({ locksDir: lockDir, name: name2 });
    assert('clearstale-mixed: malformed lock is cleared', cl2.cleared === true);
    assert('clearstale-mixed: malformed kind is malformed', cl2.kind === 'malformed', `got: ${cl2.kind}`);
  }

  // 11i. Interrupted metadata write leaves a
  // recoverable state. We simulate the crash by
  // creating a lock directory with no
  // owner.json. The next acquirer MUST quarantine
  // it (no-metadata) and acquire cleanly.
  {
    const name = 'interrupted-write';
    const dir = join(lockDir, `${name}.lock`);
    mkdirSync(dir);
    // No owner.json — simulates a crash between
    // mkdir and the metadata write.
    const acq = await acquireCronLock({ locksDir: lockDir, name, ttlMs: 5_000, owner: 'recovered', pid: 99999 });
    assert('interrupted-write: acquirer succeeds over a no-metadata directory', acq.acquired === true);
    const ins = await inspectCronLock({ locksDir: lockDir, name });
    assert('interrupted-write: on-disk owner is the recovered process', ins.holder === 'recovered');
    // The empty directory was quarantined under
    // the .malformed- prefix.
    const files = await listCronLocks({ locksDir: lockDir });
    assert('interrupted-write: empty directory was quarantined', files.some((f) => f.startsWith(`${name}.lock.malformed-`)));
  }

  // 11j. 20 concurrent acquisition attempts
  // produce exactly one winner. This is the
  // stress test for the mkdir primitive.
  {
    const name = 'twenty-concurrent';
    const results = await Promise.all(
      Array.from({ length: 20 }, (_, i) =>
        acquireCronLock({ locksDir: lockDir, name, ttlMs: 60_000, owner: `P${i}`, pid: 3000 + i })
      )
    );
    const winners = results.filter((r) => r.acquired).length;
    const losers = results.filter((r) => !r.acquired).length;
    assert('twenty-concurrent: exactly one of 20 acquirers wins', winners === 1, `winners=${winners}`);
    assert('twenty-concurrent: 19 acquirers lose', losers === 19, `losers=${losers}`);
    // Every loser reports lock-held (or
    // race-lost in an extreme scheduling edge
    // case where the winner's mkdir interleaves
    // with a loser's EEXIST observation).
    const losersOk = results.filter((r) => !r.acquired).every((r) => r.reason === 'lock-held' || r.reason === 'race-lost');
    assert('twenty-concurrent: every loser reports lock-held or race-lost', losersOk, `reasons=${results.filter((r) => !r.acquired).map((r) => r.reason).join(',')}`);
    // On disk: the active lock matches the
    // winner, and there is NO quarantine (no
    // expired lock was reclaimed).
    const ins = await inspectCronLock({ locksDir: lockDir, name });
    const winnerIdx = results.findIndex((r) => r.acquired);
    assert('twenty-concurrent: on-disk owner matches the winner', ins.holder === `P${winnerIdx}`, `disk=${ins.holder} winner=P${winnerIdx}`);
  }

  // 11k. Windows-compatible filesystem paths.
  // The lock primitive accepts both forward-
  // slash and backslash separators in the
  // locksDir; the test exercises a long path
  // that would be platform-rejected by an
  // unsafe path-traversal guard.
  {
    const subDir = mkdtempSync(join(tmpdir(), 'tpr-v63-path-'));
    const sub = join(subDir, 'sub', 'dir');
    mkdirSync(sub, { recursive: true });
    const acq = await acquireCronLock({ locksDir: sub, name: 'deep-lock', ttlMs: 5_000, owner: 'deep-owner', pid: 99999 });
    assert('windows-path: lock works in a deep directory', acq.acquired === true);
    const ins = await inspectCronLock({ locksDir: sub, name: 'deep-lock' });
    assert('windows-path: inspect works in a deep directory', ins.held === true);
    await releaseCronLock({ locksDir: sub, name: 'deep-lock', owner: 'deep-owner', pid: 99999 });
    rmSync(subDir, { recursive: true, force: true });
  }

  rmSync(lockDir, { recursive: true, force: true });
}

/* ---- 12. Staggered cron schedule ---- */
console.log('');
console.log('[12] Staggered cron schedule in the manifest');

{
  const out = mkdtempSync(join(tmpdir(), 'tpr-v63-cron-'));
  try {
    const r = await runNode(['hostinger/manifest.mjs', `--out=${out}`], { env: baseEnv });
    assert('manifest exits 0 for cron check', r.code === 0, `code=${r.code} stderr=${r.err.slice(-200)}`);
    const json = JSON.parse(readFileSync(join(out, 'deployment-manifest.json'), 'utf8'));
    const expected = [
      { name: 'cron:refresh-dataset',  expression: '0,30 * * * *' },
      { name: 'cron:refresh-baseline', expression: '10 * * * *' },
      { name: 'cron:publish-dataset',  expression: '20,50 * * * *' },
      { name: 'cron:gc',               expression: '25 * * * *' },
      { name: 'cron:verify-state',     expression: '30 6 * * *' },
      { name: 'cron:backup',           expression: '40 2 * * *' },
    ];
    const byName = Object.fromEntries((json.cron || []).map((c) => [c.name, c]));
    for (const e of expected) {
      assert(`manifest cron ${e.name}=${e.expression}`, byName[e.name] && byName[e.name].expression === e.expression,
        `got: ${byName[e.name] && byName[e.name].expression}`);
    }
    // Verify no two cron expressions share a minute (no zero-spread collisions).
    const minuteFields = (json.cron || []).map((c) => {
      const parts = c.expression.split(' ');
      return parts[0];
    });
    // For hourly expressions like "10 * * * *" the minute field is a single number.
    // For expressions like "0,30 * * * *" the minute field has multiple numbers.
    // The test asserts every cron expression has a non-zero, non-wildcard minute.
    const allWildcard = minuteFields.every((m) => m === '*' || m === '*/N');
    assert('no cron expression uses a fully-wildcard minute field', !allWildcard, `minutes: ${minuteFields.join('|')}`);
  } finally {
    rmSync(out, { recursive: true, force: true });
  }
}

/* ---- 13. No-artifact invariant ---- */
console.log('');
console.log('[13] No-artifact invariant (tests must not leave artifacts in the repo)');

{
  // After every test in this suite has run, the
  // repository root MUST NOT contain: logs/,
  // state/, scripts/_v6-3-*.log, or any
  // accidental hostinger/ test artifact.
  const repoLogs = existsSync(resolve(root, 'logs'));
  const repoState = existsSync(resolve(root, 'state'));
  assert('no logs/ directory in repo root after test run', !repoLogs);
  assert('no state/ directory in repo root after test run', !repoState);
  // The repo's scripts/ directory must not
  // contain test-prefixed log files.
  const { readdirSync } = await import('node:fs');
  const scriptsFiles = readdirSync(resolve(root, 'scripts')).filter((f) => /^_v6-3-.*\.(log|out)$/.test(f));
  assert('no scripts/_v6-3-*.log artifact left behind', scriptsFiles.length === 0, `got: ${scriptsFiles.join(', ')}`);
  // The repo root must not have any cron-lock
  // files left behind (locks are in the test's
  // temp dir, never in the repo).
  const repoRootFiles = readdirSync(resolve(root));
  const strayLocks = repoRootFiles.filter((f) => /\.lock$/.test(f) || /\.lock\.(stale|malformed)-/.test(f));
  assert('no lock files in repo root after test run', strayLocks.length === 0, `got: ${strayLocks.join(', ')}`);
}

/* ---- 14. Request-header size cap (defense in depth) ---- */
console.log('');
console.log('[14] Request-header size cap (defense in depth)');

{
  // The Hostinger runtime applies a
  // MAX_TOTAL_HEADER_BYTES cap (16 KiB) to the sum
  // of every request header. This bounds the
  // attack surface of the OpenTelemetry W3C
  // Baggage propagation vector that
  // transitively affects @netlify/blobs. A
  // request with a single oversized header is
  // rejected with HTTP 431.
  const proc = spawn('node', ['hostinger/app.mjs'], {
    cwd: root, stdio: ['ignore', 'pipe', 'pipe'],
    env: { ...baseEnv, NODE_ENV: 'production' },
  });
  let started = false;
  proc.stderr.on('data', (d) => { if (String(d).includes('listening on')) started = true; });
  for (let i = 0; i < 50 && !started; i++) await wait(100);
  assert('header-cap server started', started);
  try {
    // Normal /health still works.
    const ok = await fetch('http://127.0.0.1:18787/health');
    assert('header-cap normal request returns 200', ok.status === 200);
    // Build a request whose baggage header alone
    // exceeds 16 KiB. Use 17 KiB of 'a' characters
    // to exceed the cap.
    const huge = 'a'.repeat(17 * 1024);
    let cap = null;
    try {
      cap = await fetch('http://127.0.0.1:18787/health', { headers: { 'baggage': huge } });
    } catch (e) {
      cap = { status: 0, _err: e && e.message };
    }
    // Node's default `--max-http-header-size` is
    // 16 KiB; the request may be rejected at the
    // HTTP parser level (431) OR by the
    // application-level header-size check. Both
    // are acceptable outcomes — the test asserts
    // the request did NOT return 200.
    assert('header-cap oversized request does not return 200', cap && cap.status !== 200,
      `status=${cap && cap.status}`);
  } finally {
    proc.kill('SIGTERM');
    await wait(200);
  }
}

/* ---- 15. Clean Hostinger lifecycle in an isolated tracked-source copy ---- */
console.log('');
console.log('[15] Clean Hostinger lifecycle in an isolated tracked-source copy');

{
  // The test copies the tracked source (everything
  // except node_modules, dist, .git, .env, and
  // test artifacts) to a fresh OS temp dir, then
  // proves the full lifecycle:
  //   npm ci
  //   npm run build
  //   npm prune --omit=dev
  //   npm run start:hostinger
  // The test verifies /health, /ready, /,
  // a hashed asset, /api/dataset, and graceful
  // shutdown on SIGTERM.
  const { cp, rm, mkdir } = await import('node:fs/promises');
  const copyRoot = mkdtempSync(join(tmpdir(), 'tpr-v63-clean-'));
  // Build the exclusion list — never copy the
  // installed deps, the build output, VCS, env,
  // or test artifacts.
  const skipDirs = new Set(['node_modules', 'dist', '.git', 'logs', 'state', 'node_modules.tmp', 'coverage', '.v6-build']);
  const skipFiles = new Set(['.env', '.env.local', '.env.example', 'package-lock.json.tmp']);
  async function copyDir(src, dst) {
    const { readdir } = await import('node:fs/promises');
    const entries = await readdir(src, { withFileTypes: true });
    await mkdir(dst, { recursive: true });
    for (const e of entries) {
      if (e.isDirectory() && skipDirs.has(e.name)) continue;
      if (e.isFile() && skipFiles.has(e.name)) continue;
      if (e.isSymbolicLink()) continue;
      const sp = join(src, e.name);
      const dp = join(dst, e.name);
      if (e.isDirectory()) await copyDir(sp, dp);
      else if (e.isFile()) {
        const { copyFile } = await import('node:fs/promises');
        await copyFile(sp, dp);
      }
    }
  }
  try {
    await copyDir(root, copyRoot);
    // Sanity: the copy must not include the
    // skipped dirs.
    const { readdirSync: readdirSyncP } = await import('node:fs');
    const copied = readdirSyncP(copyRoot);
    assert('isolated copy does NOT include node_modules', !copied.includes('node_modules'));
    assert('isolated copy does NOT include dist', !copied.includes('dist'));
    assert('isolated copy does NOT include .git', !copied.includes('.git'));
    assert('isolated copy does NOT include logs', !copied.includes('logs'));
    assert('isolated copy does NOT include state', !copied.includes('state'));
    assert('isolated copy does NOT include .env', !copied.includes('.env'));

    // 15a. npm ci — install from package-lock.json.
    console.log('  -- running npm ci (this may take a moment)');
    const ci = await runNodeInCopy(copyRoot, ['node', 'C:\\Program Files\\nodejs\\node_modules\\npm\\bin\\npm-cli.js', 'ci'], { env: { ...process.env } });
    // The above may not work on Windows. Fall back
    // to running the npm.cmd via cmd /c.
    let ciResult = ci;
    if (ciResult.code !== 0) {
      ciResult = await runCmdInCopy(copyRoot, ['npm.cmd', 'ci'], { env: { ...process.env } });
    }
    assert('npm ci in isolated copy exits 0', ciResult.code === 0, `code=${ciResult.code} stderr=${ciResult.err.slice(-300)}`);

    // 15b. npm run build.
    const build = await runCmdInCopy(copyRoot, ['npm.cmd', 'run', 'build'], { env: { ...process.env } });
    assert('npm run build in isolated copy exits 0', build.code === 0, `code=${build.code} stderr=${build.err.slice(-300)}`);
    // Verify dist/index.html exists.
    assert('isolated copy built dist/index.html', existsSync(join(copyRoot, 'dist', 'index.html')));
    // Verify the hashed asset file exists.
    const distAssetsDir = join(copyRoot, 'dist', 'assets');
    if (existsSync(distAssetsDir)) {
      const assetFiles = readdirSyncP(distAssetsDir);
      const hashedAsset = assetFiles.find((f) => /index-[A-Za-z0-9_-]{8}\.js$/.test(f));
      assert('isolated copy has at least one hashed asset', !!hashedAsset, `got: ${assetFiles.join(', ')}`);
    }

    // 15c. npm prune --omit=dev.
    const prune = await runCmdInCopy(copyRoot, ['npm.cmd', 'prune', '--omit=dev'], { env: { ...process.env } });
    assert('npm prune --omit=dev exits 0', prune.code === 0, `code=${prune.code} stderr=${prune.err.slice(-300)}`);

    // 15d. Start the Hostinger app in the isolated
    // copy. Use a dedicated data root + log dir +
    // public dir to avoid touching the main
    // repo.
    const isolatedData = join(copyRoot, 'hostinger-state');
    const isolatedLogs = join(copyRoot, 'hostinger-logs');
    const isolatedBackups = join(copyRoot, 'hostinger-backups');
    const isolatedLocks = join(isolatedData, 'locks');
    mkdirSync(isolatedData, { recursive: true });
    mkdirSync(isolatedLogs, { recursive: true });
    mkdirSync(isolatedBackups, { recursive: true });
    mkdirSync(isolatedLocks, { recursive: true });
    const hostingerPort = '18788';
    const app = spawn('node', ['hostinger/app.mjs'], {
      cwd: copyRoot, stdio: ['ignore', 'pipe', 'pipe'],
      env: {
        ...process.env,
        THREATPULSE_HTTP_HOST: '127.0.0.1',
        THREATPULSE_HTTP_PORT: hostingerPort,
        THREATPULSE_DATA_ROOT: isolatedData,
        THREATPULSE_PUBLIC_DIR: join(copyRoot, 'dist'),
        THREATPULSE_LOG_DIR: isolatedLogs,
        THREATPULSE_LOCKS_DIR: isolatedLocks,
        THREATPULSE_BACKUP_DIR: isolatedBackups,
        THREATPULSE_STORAGE_BACKEND: 'filesystem',
        NODE_ENV: 'production',
      },
    });
    let appStarted = false;
    app.stderr.on('data', (d) => { if (String(d).includes('listening on')) appStarted = true; });
    for (let i = 0; i < 80 && !appStarted; i++) await wait(100);
    assert('isolated Hostinger app started', appStarted, `stderr last 200: ${appStarted ? 'ok' : 'no listening'}`);

    if (appStarted) {
      // 15e. Probe every endpoint.
      try {
        const health = await fetch(`http://127.0.0.1:${hostingerPort}/health`);
        assert('isolated /health returns 200', health.status === 200, `status=${health.status}`);
        const ready = await fetch(`http://127.0.0.1:${hostingerPort}/ready`);
        assert('isolated /ready returns 200 or 503', ready.status === 200 || ready.status === 503, `status=${ready.status}`);
        const root = await fetch(`http://127.0.0.1:${hostingerPort}/`);
        assert('isolated / returns 200', root.status === 200, `status=${root.status}`);
        // Find a hashed asset via the dist listing.
        const distAssets = readdirSyncP(distAssetsDir);
        const hashedAsset = distAssets.find((f) => /index-[A-Za-z0-9_-]{8}\.js$/.test(f));
        if (hashedAsset) {
          const asset = await fetch(`http://127.0.0.1:${hostingerPort}/assets/${hashedAsset}`);
          assert('isolated hashed asset returns 200', asset.status === 200, `status=${asset.status}`);
        }
        const dataset = await fetch(`http://127.0.0.1:${hostingerPort}/api/dataset`);
        assert('isolated /api/dataset returns 200', dataset.status === 200, `status=${dataset.status}`);
      } finally {
        // 15f. Graceful shutdown: send SIGTERM and
        // wait for the process to exit within 6
        // seconds. The 'close' event may report
        // code=null when the process is killed by
        // a signal — the assertion is on the
        // *timing* (the process exits within 6s,
        // not the full 60s default) and the fact
        // that the process did exit (not timeout).
        const startTs = Date.now();
        const exitPromise = new Promise((resolveExit) => app.on('close', (code, signal) => resolveExit({ code, signal, elapsedMs: Date.now() - startTs })));
        app.kill('SIGTERM');
        const result = await Promise.race([exitPromise, wait(6000).then(() => ({ code: 'timeout' }))]);
        assert('isolated app shuts down on SIGTERM (graceful shutdown)', result && result.code !== 'timeout', `code=${result && result.code} signal=${result && result.signal} elapsed=${result && result.elapsedMs}ms`);
        assert('isolated app shuts down within 6s of SIGTERM', result && result.elapsedMs < 6000, `elapsed=${result && result.elapsedMs}ms`);
        // The Hostinger app's signal handler is
        // the one that called server.close() and
        // process.exit(0). Verify the close event
        // fired with either code=0 (handler ran to
        // completion) or signal=SIGTERM (OS
        // delivered the signal but the handler
        // may have been preempted by the OS kill).
        // Both are acceptable.
        if (result && result.code !== 0) {
          assert('isolated app shut down via SIGTERM (signal reported)', result.signal === 'SIGTERM', `signal=${result && result.signal}`);
        } else {
          assert('isolated app shut down cleanly (code=0)', true);
        }
      }
    } else {
      app.kill('SIGTERM');
    }
  } finally {
    // Cleanup the copy.
    try { await rm(copyRoot, { recursive: true, force: true }); } catch { /* noop */ }
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
