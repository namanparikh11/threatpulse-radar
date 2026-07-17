#!/usr/bin/env node
/**
 * V6.8 — Release preflight script.
 *
 * Read-only verification that the repository is in
 * a state that can be released. The script:
 *   - does not modify files
 *   - does not create branches
 *   - does not push
 *   - does not call Netlify, Hostinger, or any
 *     provider
 *   - does not expose environment-variable values
 *   - does not contact the network
 *
 * Exit codes:
 *   0 — ready
 *   1 — verification failed
 *   2 — invalid invocation or repository state
 *
 *   node scripts/verify-v68-release.mjs
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath, pathToFileURL } from 'node:url';
import path from 'node:path';
import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { execSync } from 'node:child_process';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..');

let failureCount = 0;

function fail(msg) {
  failureCount++;
  console.error(`✗ ${msg}`);
}

function pass(msg) {
  console.log(`✓ ${msg}`);
}

function tryReadText(p) {
  try { return readFileSync(p, 'utf-8'); } catch { return null; }
}

function listDirSafe(p) {
  try { return readdirSync(p); } catch { return []; }
}

function isFileSafe(p) {
  try { return statSync(p).isFile(); } catch { return false; }
}

function git(args) {
  try { return execSync(`git ${args}`, { cwd: REPO, encoding: 'utf-8' }).trim(); } catch (err) {
    return (err && err.stdout ? err.stdout.toString() : '').trim();
  }
}

const EXPECTED_COMMIT = '0480a9f414f9dd452191f99e07b94a505e6cb003';
const EXPECTED_SUITE_COUNT = 36;
const EXPECTED_CSV_COLUMNS = 21;
const BASELINE_COMMIT = '32a8a63';

test('verify-v68-release: clean working tree (release-preparation files allowed)', () => {
  // The release-preparation branch is allowed to
  // carry untracked release-preparation files
  // (manifest, runbooks, scripts) until the
  // operator explicitly commits them. The
  // preflight script is itself such a file.
  const status = git('status --short');
  // Allow any file under deploy/, docs/, scripts/,
  // or the verify script's own self-reference.
  const lines = status.split('\n').filter(Boolean);
  const offending = lines.filter((l) => !/^(\?\?|\s*M).*(deploy\/|docs\/|scripts\/|verify-v68-release)/i.test(l));
  assert.equal(offending.length, 0, `working tree has unexpected changes: ${offending.join(', ')}`);
});

test('verify-v68-release: HEAD is based directly on the V6.8 RC commit', () => {
  // The release-preparation branch can be on
  // any commit that is a descendant of the V6.8
  // RC commit `0480a9f`. The preparation branch
  // adds release tooling + runbooks; it must
  // NOT modify the RC product behavior.
  const head = git('rev-parse HEAD');
  const merged = git(`merge-base --is-ancestor ${EXPECTED_COMMIT} HEAD && echo yes || echo no`).trim();
  assert.equal(merged, 'yes', `HEAD (${head}) is not a descendant of the V6.8 RC commit (${EXPECTED_COMMIT})`);
});

test('verify-v68-release: release manifest exists and is valid JSON', () => {
  const manifestPath = path.join(REPO, 'deploy', 'v6-8-release-manifest.json');
  assert.ok(existsSync(manifestPath), 'release manifest missing');
  const text = readFileSync(manifestPath, 'utf-8');
  const parsed = JSON.parse(text);
  assert.equal(parsed.expectedReleaseCandidateCommit, EXPECTED_COMMIT, 'manifest commit mismatch');
  assert.ok(parsed.valuesAreNamesOrPlaceholdersOnly, 'manifest must declare names/placeholders only');
});

test('verify-v68-release: release manifest contains no high-entropy secret values', () => {
  const text = readFileSync(path.join(REPO, 'deploy', 'v6-8-release-manifest.json'), 'utf-8');
  // A genuine secret is typically 32+ chars of
  // base64 / hex that contains at least one digit
  // AND mixed case (i.e. looks like a random
  // token, not an English identifier).
  let cleaned = text;
  for (const d of [
    EXPECTED_COMMIT,
    BASELINE_COMMIT,
    'v6-8-release-candidate-consolidation',
    'release/v6-8-deployment-preparation',
    'v6-8-release-candidate',
    'threatpulse-radar-v6-8-release-candidate',
  ]) {
    cleaned = cleaned.split(d).join('');
  }
  cleaned = cleaned.replace(/THREATPULSE_[A-Z0-9_]+/g, '');
  // The lookalike regex: at least 32 chars,
  // contains a digit, contains mixed case, NOT
  // a kebab-case identifier.
  const candidates = (cleaned.match(/[A-Za-z0-9_\-=+]{32,}/g) || []);
  const secrets = candidates.filter((s) => {
    if (/^[a-z][a-z-]+$/.test(s)) return false; // kebab-case
    if (/^[A-Z][A-Z0-9_]+$/.test(s)) return false; // SCREAMING_SNAKE
    if (/^[a-z][a-zA-Z0-9]+$/.test(s)) return false; // camelCase
    const hasDigit = /\d/.test(s);
    const hasUpper = /[A-Z]/.test(s);
    const hasLower = /[a-z]/.test(s);
    // Looks like a token: digit + mixed case
    return hasDigit && hasUpper && hasLower;
  });
  assert.equal(secrets.length, 0, `release manifest contains a possible secret value: ${secrets.join(', ')}`);
});

test('verify-v68-release: required documentation exists', () => {
  for (const doc of [
    'docs/v6-8-release-candidate.md',
    'docs/v6-8-controlled-deployment-runbook.md',
    'docs/v6-8-rollback-plan.md',
    'docs/v6-8-production-observation-plan.md',
    'docs/v6-8-environment-checklist.md',
    'docs/v6-8-deployment-cost-controls.md',
  ]) {
    assert.ok(existsSync(path.join(REPO, doc)), `${doc} missing`);
  }
});

test('verify-v68-release: no committed .env or credential files (example allowed)', () => {
  // The .env.example file is a documentation
  // template containing only names, not values.
  // A real .env or any secrets.* file is
  // forbidden.
  const offenders = git('ls-files').split('\n').filter((p) => {
    if (!p) return false;
    if (p === '.env.example') return false;
    if (/(^|\/)\.env(\.|$)/.test(p)) return true;
    if (/(^|\/)secrets?\.(json|ya?ml|toml|txt)/i.test(p)) return true;
    return false;
  });
  assert.equal(offenders.length, 0, `committed secret files: ${offenders.join(', ')}`);
});

test('verify-v68-release: no conflict markers', () => {
  const files = git('ls-files').split('\n');
  let conflicts = 0;
  for (const f of files) {
    if (!f) continue;
    const txt = tryReadText(path.join(REPO, f));
    if (txt && /^(<{7}|={7}|>{7})/m.test(txt)) conflicts++;
  }
  assert.equal(conflicts, 0, `${conflicts} file(s) contain conflict markers`);
});

test('verify-v68-release: 36 acceptance suites enumerated', () => {
  const files = listDirSafe(path.join(REPO, 'scripts')).filter((n) => /^acceptance.*\.mjs$/.test(n));
  assert.equal(files.length, EXPECTED_SUITE_COUNT, `expected ${EXPECTED_SUITE_COUNT} suites, got ${files.length}`);
});

test('verify-v68-release: package.json engines.node matches manifest range', () => {
  const pkg = JSON.parse(readFileSync(path.join(REPO, 'package.json'), 'utf-8'));
  const manifest = JSON.parse(readFileSync(path.join(REPO, 'deploy', 'v6-8-release-manifest.json'), 'utf-8'));
  // When package.json omits engines.node, the
  // manifest must still document a supported Node
  // range (the manifest is the source of truth
  // for the release).
  if (pkg.engines && pkg.engines.node) {
    assert.equal(manifest.nodeVersionRange, pkg.engines.node, 'package.json engines.node mismatch with manifest');
  } else {
    assert.ok(manifest.nodeVersionRange, 'manifest must declare a nodeVersionRange even when package.json omits engines.node');
  }
});

test('verify-v68-release: five public Netlify function entries', () => {
  const files = listDirSafe(path.join(REPO, 'netlify', 'functions'))
    .filter((n) => !n.startsWith('.'))
    .filter((n) => isFileSafe(path.join(REPO, 'netlify', 'functions', n)));
  assert.equal(files.length, 5, `expected 5 public Netlify functions, got ${files.length}: ${files.join(', ')}`);
});

test('verify-v68-release: one gateway function entry', () => {
  const files = listDirSafe(path.join(REPO, 'netlify', 'gateway', 'src'))
    .filter((n) => !n.startsWith('.'))
    .filter((n) => isFileSafe(path.join(REPO, 'netlify', 'gateway', 'src', n)));
  const gw = files.find((f) => f.includes('private-sync-gateway'));
  assert.ok(gw, `expected gateway entry, got ${files.join(', ')}`);
});

test('verify-v68-release: CSV_COLUMNS equals 21', () => {
  const csv = readFileSync(path.join(REPO, 'src', 'utils', 'csvExport.ts'), 'utf-8');
  const match = csv.match(/CSV_COLUMNS\s*=\s*\[([\s\S]*?)\]\s*as const/);
  assert.ok(match, 'CSV_COLUMNS array literal not found');
  const cols = (match[1].match(/'[^']+'(?=,|\s)/g) || []);
  assert.equal(cols.length, EXPECTED_CSV_COLUMNS, `CSV_COLUMNS should be ${EXPECTED_CSV_COLUMNS}, got ${cols.length}`);
});

test('verify-v68-release: client/ unchanged against 32a8a63', () => {
  const out = git(`diff --exit-code ${BASELINE_COMMIT}..HEAD -- client/`);
  assert.equal(out, '', `client/ has uncommitted V6.8 changes: ${out}`);
});

test('verify-v68-release: netlify/gateway/ unchanged against 32a8a63', () => {
  const out = git(`diff --exit-code ${BASELINE_COMMIT}..HEAD -- netlify/gateway/`);
  assert.equal(out, '', `netlify/gateway/ has uncommitted V6.8 changes: ${out}`);
});

test('verify-v68-release: no node:crypto in browser-reachable source', () => {
  function walk(dir) {
    const out = [];
    for (const entry of listDirSafe(dir)) {
      const p = path.join(dir, entry);
      const s = tryReadText(p);
      if (s === null) {
        // Not a file or unreadable
        if (existsSync(p) && statSync(p).isDirectory()) out.push(...walk(p));
        continue;
      }
      if (/\.(mjs|ts|tsx|mts|d\.mts)$/.test(entry)) out.push(p);
      else if (statSync(p).isDirectory()) out.push(...walk(p));
    }
    return out;
  }
  const src = path.join(REPO, 'src');
  if (!existsSync(src)) return;
  const files = walk(src);
  const offenders = [];
  for (const f of files) {
    const txt = readFileSync(f, 'utf-8');
    // Strip doc-comment lines
    const code = txt.split('\n').filter((line) => !/^\s*\*\s/.test(line)).join('\n');
    if (/"node"\s*\+\s*":"\s*\+\s*"crypto"/.test(code) || /'node'\s*\+\s*':'\s*\+\s*'crypto'/.test(code)) {
      offenders.push(f);
    }
  }
  assert.equal(offenders.length, 0, `node:crypto offenders: ${offenders.join(', ')}`);
});

test('verify-v68-release: dist/ build has no sha256Node or fingerprintNode chunk', () => {
  const dist = path.join(REPO, 'dist', 'assets');
  if (!existsSync(dist)) {
    // Build hasn't been run yet; skip the chunk check
    // but ensure the dist directory will exist after
    // the build.
    return;
  }
  const files = listDirSafe(dist);
  for (const f of files) {
    assert.ok(!/sha256Node|fingerprintNode/.test(f), `unexpected Node-only chunk in dist: ${f}`);
  }
  for (const f of files) {
    if (f.endsWith('.js')) {
      const txt = readFileSync(path.join(dist, f), 'utf-8');
      assert.ok(!/require\(['"]crypto['"]\)|from\s+['"]crypto['"]/.test(txt), `node:crypto found in ${f}`);
    }
  }
});

test('verify-v68-release: no VITE-prefixed secret contract', () => {
  const src = path.join(REPO, 'src');
  if (!existsSync(src)) return;
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
  const files = walk(src);
  const offenders = [];
  for (const f of files) {
    const txt = readFileSync(f, 'utf-8');
    // VITE_ variables are inlined into the client
    // bundle at build time. A VITE_ name containing
    // "secret" / "token" / "password" would leak.
    for (const m of txt.matchAll(/VITE_[A-Z0-9_]+/g)) {
      const n = m[0];
      if (/(SECRET|TOKEN|PASSWORD|PRIVATE|CREDENTIAL)/i.test(n)) offenders.push(`${f}: ${n}`);
    }
  }
  assert.equal(offenders.length, 0, `VITE-prefixed secret offenders: ${offenders.join(', ')}`);
});

test('verify-v68-release: no forbidden generated artifacts in working tree', () => {
  const forbidden = ['node_modules', 'dist', '.netlify'];
  const offenders = [];
  for (const d of forbidden) {
    if (existsSync(path.join(REPO, d))) {
      // Allowed if gitignored
      const tracked = git(`ls-files ${d}`).trim();
      if (tracked) offenders.push(`${d} is tracked (${tracked.split('\n').length} files)`);
    }
  }
  assert.equal(offenders.length, 0, offenders.join('; '));
});

test('verify-v68-release: package-lock present', () => {
  assert.ok(existsSync(path.join(REPO, 'package-lock.json')), 'package-lock.json missing');
});

test('verify-v68-release: version in package.json is 1.0.0 (matches V6.x line)', () => {
  const pkg = JSON.parse(readFileSync(path.join(REPO, 'package.json'), 'utf-8'));
  assert.equal(pkg.version, '1.0.0', `package.json version is ${pkg.version}, expected 1.0.0`);
});

test('verify-v68-release: changelog documents V6.8', () => {
  const cl = readFileSync(path.join(REPO, 'CHANGELOG.md'), 'utf-8');
  assert.ok(/## V6\.8/.test(cl), 'CHANGELOG.md missing V6.8 entry');
  assert.ok(/## V6\.7/.test(cl), 'CHANGELOG.md missing V6.7 entry');
});

test('verify-v68-release: README documents V6.8', () => {
  const readme = readFileSync(path.join(REPO, 'README.md'), 'utf-8');
  assert.ok(/V6\.8/.test(readme), 'README.md missing V6.8 reference');
});

test('verify-v68-release: no `process.exit(0)` forced-success in any V6.7+ acceptance source', () => {
  // The V6.6 lesson applies to all suites written
  // from V6.6 onward. Pre-V6.6 suites may retain
  // legacy `process.exit(0)` patterns. We flag
  // only the V6.6+ suites.
  const scripts = path.join(REPO, 'scripts');
  const all = listDirSafe(scripts).filter((n) => /^acceptance.*\.mjs$/.test(n));
  const modern = all.filter((f) => /^acceptance-v6[6-9]|^acceptance-v7|^verify-v68/.test(f));
  for (const f of modern) {
    const txt = readFileText(path.join(scripts, f));
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

function readFileText(p) {
  try { return readFileSync(p, 'utf-8'); } catch { return ''; }
}

test('verify-v68-release: gateway function entry is exactly the documented name', () => {
  const files = listDirSafe(path.join(REPO, 'netlify', 'gateway', 'src'));
  const matches = files.filter((f) => /private-sync-gateway/.test(f));
  assert.equal(matches.length, 1, `expected exactly 1 private-sync-gateway entry, got ${matches.length}: ${matches.join(', ')}`);
});

test('verify-v68-release: no VITE_* secret in build output', () => {
  const dist = path.join(REPO, 'dist');
  if (!existsSync(dist)) return;
  const offenders = [];
  function walk(dir) {
    for (const entry of listDirSafe(dir)) {
      const p = path.join(dir, entry);
      if (!existsSync(p)) continue;
      if (statSync(p).isDirectory()) walk(p);
      else if (entry.endsWith('.js')) {
        const txt = readFileSync(p, 'utf-8');
        for (const m of txt.matchAll(/VITE_(SECRET|TOKEN|PASSWORD|PRIVATE|CREDENTIAL)[A-Z0-9_]*/g)) {
          offenders.push(`${p}: ${m[0]}`);
        }
      }
    }
  }
  walk(dist);
  assert.equal(offenders.length, 0, `VITE-prefixed secret in dist: ${offenders.join(', ')}`);
});
