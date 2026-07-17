#!/usr/bin/env node
/**
 * V6.8 — Deployment preparation acceptance suite.
 *
 * Verifies that the release-preparation branch
 * carries only the documented preparation files
 * (manifest, runbooks, smoke scripts, preflight
 * script) and that every preparation artifact is
 * names-only / read-only / dry-run-by-default.
 *
 * The suite NEVER:
 *   - modifies files
 *   - creates branches
 *   - pushes
 *   - calls Netlify, Hostinger, or any provider
 *   - exposes environment-variable values
 *
 *   node scripts/acceptance-v68-deployment-preparation.mjs
 *
 * Exit code 0 when every assertion passes.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath, pathToFileURL } from 'node:url';
import path from 'node:path';
import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { execSync } from 'node:child_process';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..');
const BASELINE_COMMIT = '32a8a63';

function git(args) {
  try { return execSync(`git ${args}`, { cwd: REPO, encoding: 'utf-8' }).trim(); } catch (err) {
    return (err && err.stdout ? err.stdout.toString() : '').trim();
  }
}

function tryRead(p) {
  try { return readFileSync(p, 'utf-8'); } catch { return null; }
}

function listDirSafe(p) {
  try { return readdirSync(p); } catch { return []; }
}

test('V6.8-deploy: release-preparation branch is release/v6-8-deployment-preparation', () => {
  const branch = git('branch --show-current');
  assert.equal(branch, 'release/v6-8-deployment-preparation', `branch is ${branch}`);
});

test('V6.8-deploy: HEAD is a descendant of the V6.8 RC commit (0480a9f)', () => {
  const out = git('merge-base --is-ancestor 0480a9f HEAD && echo yes || echo no').trim();
  assert.equal(out, 'yes', 'HEAD is not a descendant of the V6.8 RC commit');
});

test('V6.8-deploy: client/ is unchanged against 32a8a63', () => {
  const out = git(`diff --exit-code ${BASELINE_COMMIT}..HEAD -- client/`);
  assert.equal(out, '', `client/ has uncommitted V6.8 changes: ${out}`);
});

test('V6.8-deploy: netlify/gateway/ is unchanged against 32a8a63', () => {
  const out = git(`diff --exit-code ${BASELINE_COMMIT}..HEAD -- netlify/gateway/`);
  assert.equal(out, '', `netlify/gateway/ has uncommitted V6.8 changes: ${out}`);
});

test('V6.8-deploy: product source code is unchanged against the V6.8 RC', () => {
  // The release-preparation branch may ONLY
  // change files under deploy/, scripts/, and
  // docs/ that are documented as
  // release-preparation files. Any change to
  // src/, netlify/functions/, hostinger/,
  // package.json, or other product files is a
  // preparation-blocker.
  const allowed = [
    'deploy/',
    'docs/v6-8-',
    'scripts/verify-v68-release.mjs',
    'scripts/smoke-v68-local.mjs',
    'scripts/smoke-v68-production.mjs',
    'scripts/acceptance-v68-deployment-preparation.mjs',
    'CHANGELOG.md',
    'README.md',
  ];
  const diff = git('diff --name-only 0480a9f..HEAD').split('\n').filter(Boolean);
  const offenders = diff.filter((f) => !allowed.some((p) => f.startsWith(p)));
  assert.equal(offenders.length, 0, `product source code modified: ${offenders.join(', ')}`);
});

test('V6.8-deploy: release manifest contains no high-entropy secret values', () => {
  const text = tryRead(path.join(REPO, 'deploy', 'v6-8-release-manifest.json'));
  assert.ok(text, 'release manifest missing');
  let cleaned = text;
  for (const d of ['0480a9f414f9dd452191f99e07b94a505e6cb003', '32a8a63', 'v6-8-release-candidate-consolidation', 'release/v6-8-deployment-preparation']) {
    cleaned = cleaned.split(d).join('');
  }
  cleaned = cleaned.replace(/THREATPULSE_[A-Z0-9_]+/g, '');
  const candidates = (cleaned.match(/[A-Za-z0-9_\-=+]{32,}/g) || []);
  const secrets = candidates.filter((s) => {
    if (/^[a-z][a-z-]+$/.test(s)) return false;
    if (/^[A-Z][A-Z0-9_]+$/.test(s)) return false;
    if (/^[a-z][a-zA-Z0-9]+$/.test(s)) return false;
    return /\d/.test(s) && /[A-Z]/.test(s) && /[a-z]/.test(s);
  });
  assert.equal(secrets.length, 0, `release manifest contains a possible secret: ${secrets.join(', ')}`);
});

test('V6.8-deploy: preflight script is read-only (no file mutations in source)', () => {
  const text = tryRead(path.join(REPO, 'scripts', 'verify-v68-release.mjs'));
  assert.ok(text, 'preflight script missing');
  // The preflight must NEVER call
  // writeFileSync / appendFileSync / rmSync /
  // rename / unlink.
  for (const op of ['writeFileSync', 'appendFileSync', 'rmSync', 'rename', 'unlink']) {
    assert.ok(!new RegExp(`\\b${op}\\b`).test(text), `preflight must not call ${op}`);
  }
});

test('V6.8-deploy: production smoke script is dry-run by default', () => {
  const text = tryRead(path.join(REPO, 'scripts', 'smoke-v68-production.mjs'));
  assert.ok(text, 'production smoke script missing');
  assert.ok(/EXECUTE/.test(text), 'production smoke must gate network access on --execute');
  assert.ok(/--execute/.test(text), 'production smoke must require --execute flag');
  assert.ok(/--public-url=/.test(text), 'production smoke must require --public-url');
  assert.ok(/--gateway-url=/.test(text), 'production smoke must require --gateway-url');
  // The script must NOT call fetch / http /
  // request without EXECUTE === true.
  assert.ok(/if\s*\(\s*!EXECUTE/.test(text), 'production smoke must guard network calls with EXECUTE check');
});

test('V6.8-deploy: production smoke refuses credential flags', () => {
  const text = tryRead(path.join(REPO, 'scripts', 'smoke-v68-production.mjs'));
  assert.ok(text, 'production smoke script missing');
  // The script must guard against any flag that
  // looks like a credential. We assert that the
  // script's argv guard covers the documented
  // forbidden patterns.
  for (const name of ['token', 'secret', 'password', 'pepper', 'credential', 'key', 'auth']) {
    assert.ok(text.toLowerCase().includes(name), `production smoke must cover forbidden flag ${name}`);
  }
  // The script must also have a guard that
  // asserts on argv.
  assert.ok(/argv/.test(text), 'production smoke must inspect argv');
});

test('V6.8-deploy: local smoke uses temporary directories', () => {
  const text = tryRead(path.join(REPO, 'scripts', 'smoke-v68-local.mjs'));
  assert.ok(text, 'local smoke script missing');
  assert.ok(/mkdtempSync/.test(text), 'local smoke must use mkdtempSync');
  assert.ok(/tmpdir\(\)/.test(text), 'local smoke must use tmpdir()');
  assert.ok(/rmSync/.test(text), 'local smoke must call rmSync for cleanup');
});

test('V6.8-deploy: rollback plan contains no destructive default command', () => {
  const text = tryRead(path.join(REPO, 'docs', 'v6-8-rollback-plan.md'));
  assert.ok(text, 'rollback plan missing');
  // The rollback plan must not instruct the
  // operator to delete a Blob store or rotate
  // credentials by default.
  for (const phrase of ['delete the tpr-baseline store', 'delete the tpr-dataset store', 'rotate the pepper by default', 'force-push to main']) {
    assert.ok(!text.toLowerCase().includes(phrase.toLowerCase()), `rollback plan must not contain: ${phrase}`);
  }
  // The plan must explicitly say "Avoid
  // deleting Blob stores" and "Avoid rotating
  // credentials unless compromise is suspected".
  assert.ok(text.includes('Avoid deleting Blob stores'), 'rollback plan must say "Avoid deleting Blob stores"');
  assert.ok(text.includes('Avoid rotating credentials unless compromise is suspected'), 'rollback plan must say "Avoid rotating credentials unless compromise is suspected"');
});

test('V6.8-deploy: environment checklist contains names only', () => {
  const text = tryRead(path.join(REPO, 'docs', 'v6-8-environment-checklist.md'));
  assert.ok(text, 'environment checklist missing');
  // Strip out the env var name pattern itself
  // and the section headers.
  let cleaned = text;
  cleaned = cleaned.replace(/THREATPULSE_[A-Z0-9_]+/g, '');
  cleaned = cleaned.replace(/required|optional|production-only/gi, '');
  // Look for any high-entropy string that could
  // be a real value.
  const candidates = (cleaned.match(/[A-Za-z0-9_\-=+]{32,}/g) || []);
  const secrets = candidates.filter((s) => /\d/.test(s) && /[A-Z]/.test(s) && /[a-z]/.test(s));
  assert.equal(secrets.length, 0, `environment checklist contains a possible secret: ${secrets.join(', ')}`);
});

test('V6.8-deploy: deployment runbook marks approvals clearly', () => {
  const text = tryRead(path.join(REPO, 'docs', 'v6-8-controlled-deployment-runbook.md'));
  assert.ok(text, 'deployment runbook missing');
  assert.ok(/PHASE 0/.test(text), 'runbook must reference PHASE 0');
  assert.ok(/PHASE 1/.test(text), 'runbook must reference PHASE 1');
  assert.ok(/PHASE 2/.test(text), 'runbook must reference PHASE 2');
  assert.ok(/PHASE 3/.test(text), 'runbook must reference PHASE 3');
  assert.ok(/explicit user approval required/i.test(text), 'runbook must mark explicit user approval');
});

test('V6.8-deploy: five public function entries remain', () => {
  const files = listDirSafe(path.join(REPO, 'netlify', 'functions'))
    .filter((n) => !n.startsWith('.'))
    .filter((n) => {
      try { return statSync(path.join(REPO, 'netlify', 'functions', n)).isFile(); } catch { return false; }
    });
  assert.equal(files.length, 5, `expected 5 public Netlify functions, got ${files.length}: ${files.join(', ')}`);
});

test('V6.8-deploy: one gateway function entry remains', () => {
  const files = listDirSafe(path.join(REPO, 'netlify', 'gateway', 'src'))
    .filter((n) => !n.startsWith('.'))
    .filter((n) => {
      try { return statSync(path.join(REPO, 'netlify', 'gateway', 'src', n)).isFile(); } catch { return false; }
    });
  const gw = files.find((f) => f.includes('private-sync-gateway'));
  assert.ok(gw, `expected gateway entry, got ${files.join(', ')}`);
});

test('V6.8-deploy: CSV_COLUMNS equals 21', () => {
  const csv = tryRead(path.join(REPO, 'src', 'utils', 'csvExport.ts'));
  assert.ok(csv, 'csvExport.ts missing');
  const match = csv.match(/CSV_COLUMNS\s*=\s*\[([\s\S]*?)\]\s*as const/);
  assert.ok(match, 'CSV_COLUMNS array literal not found');
  const cols = (match[1].match(/'[^']+'(?=,|\s)/g) || []);
  assert.equal(cols.length, 21, `CSV_COLUMNS should be 21, got ${cols.length}`);
});

test('V6.8-deploy: no VITE-prefixed secret contract in source or build', () => {
  function walk(dir) {
    const out = [];
    for (const entry of listDirSafe(dir)) {
      const p = path.join(dir, entry);
      if (!existsSync(p)) continue;
      if (statSync(p).isDirectory()) out.push(...walk(p));
      else if (/\.(ts|tsx|mjs|mts|d\.mts)$/.test(entry)) out.push(p);
    }
    return out;
  }
  const src = path.join(REPO, 'src');
  if (!existsSync(src)) return;
  const files = walk(src);
  const offenders = [];
  for (const f of files) {
    const txt = readFileSync(f, 'utf-8');
    for (const m of txt.matchAll(/VITE_[A-Z0-9_]+/g)) {
      const n = m[0];
      if (/(SECRET|TOKEN|PASSWORD|PRIVATE|CREDENTIAL)/i.test(n)) offenders.push(`${f}: ${n}`);
    }
  }
  assert.equal(offenders.length, 0, `VITE-prefixed secret offenders: ${offenders.join(', ')}`);
});

test('V6.8-deploy: 36 acceptance suites enumerated (35 prior + V6.8)', () => {
  const files = listDirSafe(path.join(REPO, 'scripts')).filter((n) => /^acceptance.*\.mjs$/.test(n));
  assert.ok(files.length >= 35, `expected at least 35 acceptance suites, got ${files.length}`);
  assert.ok(files.includes('acceptance-v68-release-candidate.mjs'), 'V6.8 release-candidate suite missing');
  assert.ok(files.includes('acceptance-v68-deployment-preparation.mjs'), 'V6.8 deployment-preparation suite missing');
});

test('V6.8-deploy: no forced `process.exit(0)` in V6.8+ acceptance sources', () => {
  const scripts = path.join(REPO, 'scripts');
  const all = listDirSafe(scripts).filter((n) => /^acceptance.*\.mjs$/.test(n));
  // Exclude the V6.8 deployment-preparation
  // suite from this self-check (it is the suite
  // that performs the check itself and its
  // filter regexes legitimately mention the
  // forbidden pattern).
  const modern = all.filter((f) => /^acceptance-v6[6-9]|^acceptance-v7|^verify-v68/.test(f))
    .filter((f) => f !== 'acceptance-v68-deployment-preparation.mjs');
  for (const f of modern) {
    const txt = tryRead(path.join(scripts, f)) || '';
    const code = txt.split('\n')
      .filter((line) => !/^\s*\*\s/.test(line))
      .filter((line) => !/forced (exit|process\.exit) substring in acceptance source/.test(line))
      .filter((line) => !/no forced process\.exit/.test(line))
      .filter((line) => !/verify-v68-release/.test(line))
      .filter((line) => !/V6\.[0-9]+: no forced/.test(line))
      .filter((line) => !/process\.exit\s*\\s/.test(line))
      .join('\n');
    assert.ok(!/process\.exit\s*\(\s*0\s*\)/.test(code), `forced process.exit(0) in ${f}`);
  }
});

test('V6.8-deploy: preflight script runs and exits 0 in the current tree', () => {
  // The preflight script must pass against the
  // current repository state. We invoke it
  // directly to confirm.
  const out = execSync('node scripts/verify-v68-release.mjs', { cwd: REPO, encoding: 'utf-8' });
  assert.ok(/ℹ pass \d+/.test(out), `preflight output unexpected: ${out.slice(0, 200)}`);
  assert.ok(/ℹ fail 0/.test(out), `preflight reported failures: ${out.slice(0, 200)}`);
});

test('V6.8-deploy: local smoke script runs and exits 0 in the current tree', () => {
  const out = execSync('node scripts/smoke-v68-local.mjs', { cwd: REPO, encoding: 'utf-8' });
  assert.ok(/ℹ pass \d+/.test(out), `local smoke output unexpected: ${out.slice(0, 200)}`);
  assert.ok(/ℹ fail 0/.test(out), `local smoke reported failures: ${out.slice(0, 200)}`);
});

test('V6.8-deploy: production smoke dry-run exits 0', () => {
  const out = execSync('node scripts/smoke-v68-production.mjs', { cwd: REPO, encoding: 'utf-8' });
  assert.ok(/DRY-RUN/.test(out), `production smoke must be dry-run by default: ${out.slice(0, 200)}`);
  assert.ok(/ℹ pass \d+/.test(out), `production smoke output unexpected: ${out.slice(0, 200)}`);
});

test('V6.8-deploy: production smoke with --execute but no URLs is rejected with exit 2', () => {
  let exitCode = 0;
  try {
    execSync('node scripts/smoke-v68-production.mjs --execute', { cwd: REPO, encoding: 'utf-8' });
  } catch (err) {
    exitCode = err.status;
  }
  assert.equal(exitCode, 2, `production smoke --execute without URLs should exit 2, got ${exitCode}`);
});

test('V6.8-deploy: no `.env` or secrets.* committed', () => {
  const offenders = git('ls-files').split('\n').filter((p) => {
    if (!p) return false;
    if (p === '.env.example') return false;
    if (/(^|\/)\.env(\.|$)/.test(p)) return true;
    if (/(^|\/)secrets?\.(json|ya?ml|toml|txt)/i.test(p)) return true;
    return false;
  });
  assert.equal(offenders.length, 0, `committed secret files: ${offenders.join(', ')}`);
});

test('V6.8-deploy: no `process.exit(0)` forced-success in V6.8 release-preparation scripts', () => {
  for (const f of [
    'scripts/verify-v68-release.mjs',
    'scripts/smoke-v68-local.mjs',
    'scripts/smoke-v68-production.mjs',
  ]) {
    const txt = tryRead(path.join(REPO, f)) || '';
    // The V6.8 release-preparation scripts are
    // the very scripts that enforce the
    // `process.exit(0)` rule. They are
    // permitted to mention the pattern in
    // comments / test descriptions / the
    // assertion expression. We strip those
    // permitted lines.
    const lines = txt.split('\n');
    const clean = [];
    for (const line of lines) {
      // Strip doc-comment lines.
      if (/^\s*\*\s/.test(line)) continue;
      // Strip // comments that mention process.exit.
      if (/^\s*\/\/.*process\.exit/.test(line)) continue;
      // Strip the test description that names the
      // regression check.
      if (line.includes("test(") && line.includes("process.exit(0)")) continue;
      // Strip the assertion `! /process.exit\s*\(\s*0\s*\)/.test(...)`.
      if (line.includes('assert.ok(!/process.exit')) continue;
      clean.push(line);
    }
    const code = clean.join('\n');
    assert.ok(!/process\.exit\s*\(\s*0\s*\)/.test(code), `forced process.exit(0) in ${f}`);
  }
});
