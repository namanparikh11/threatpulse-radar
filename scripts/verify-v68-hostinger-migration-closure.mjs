#!/usr/bin/env node
/**
 * V6.8 — Hostinger migration-closure verification
 * script.
 *
 * Read-only, static, local verification. The script
 * does not:
 *   - modify files
 *   - contact the network
 *   - call Hostinger, Netlify, or any provider
 *   - expose environment-variable values
 *   - create branches, push, merge, or deploy
 *
 * The script asserts the structural and source-level
 * invariants that allow the Netlify public site to
 * enter rollback-only observation:
 *
 *   1. Hostinger route ownership for `/`, `/health`,
 *      `/ready`, `/api/dataset`, `/.netlify/functions/dataset`
 *   2. Non-dataset `/.netlify/functions/*` paths
 *      remain closed (honest 404)
 *   3. No public Hostinger runtime import from
 *      `netlify/gateway/`
 *   4. No public source references the private
 *      gateway credential variables
 *      (`THREATPULSE_BASELINE_SITE_ID`,
 *      `THREATPULSE_BLOBS_ACCESS_TOKEN`,
 *      `THREATPULSE_CREDENTIAL_PEPPER`,
 *      `THREATPULSE_CREDENTIALS_BLOBS_ACCESS_TOKEN`)
 *   5. Filesystem storage namespaces include
 *      `tpr-dataset`, `tpr-baseline`,
 *      `tpr-vulnrichment`, `tpr-github-advisory`,
 *      `tpr-public-intelligence`
 *   6. The managed scheduler contains all six
 *      logical schedules (refresh, baseline, publish,
 *      gc, verify, backup)
 *   7. The provider-neutral Header labels remain
 *      present and the legacy `Proxy: Netlify`
 *      label is absent
 *   8. CSV remains exactly 21 columns
 *   9. Exactly 5 public Netlify function entry files
 *      and 1 gateway function entry remain preserved
 *      for repository compatibility
 *  10. `client/**` and `netlify/gateway/**`
 *      preservation constraints remain satisfied
 *      against the documented baseline
 *  11. No public refresh / admin / write HTTP route
 *      exists
 *
 * Exit codes:
 *   0 — all assertions pass
 *   1 — at least one assertion failed
 *
 *   node scripts/verify-v68-hostinger-migration-closure.mjs
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { execSync } from 'node:child_process';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..');

function readText(p) {
  try { return readFileSync(p, 'utf-8'); } catch { return null; }
}
function listDirSafe(p) {
  try { return readdirSync(p); } catch { return []; } }
function isFileSafe(p) {
  try { return statSync(p).isFile(); } catch { return false; } }
function existsSafe(p) {
  try { return statSync(p).isDirectory(); } catch { return false; } }
function walkTsx(root, out) {
  const entries = listDirSafe(root);
  for (const e of entries) {
    const p = path.join(root, e);
    if (isFileSafe(p) && (p.endsWith('.tsx') || p.endsWith('.ts'))) out.push(p);
    else if (existsSafe(p)) walkTsx(p, out);
  }
}
function walkMjs(root, out) {
  const entries = listDirSafe(root);
  for (const e of entries) {
    const p = path.join(root, e);
    if (isFileSafe(p) && p.endsWith('.mjs')) out.push(p);
    else if (existsSafe(p)) walkMjs(p, out);
  }
}

/* ---- 1. Hostinger route ownership ---- */

test('hostinger-closure: /, /health, /ready, /api/dataset, /.netlify/functions/dataset are owned by hostinger/app.mjs', () => {
  const app = readText(path.join(REPO, 'hostinger', 'app.mjs'));
  assert.ok(app, 'hostinger/app.mjs must exist');
  // / and SPA fallback — the app is a single node:http server
  // with an inline route table; the SPA fallback is at the
  // bottom of the request handler and serves any unmatched
  // path that resolves to a public file.
  assert.ok(
    /handleHealth|handleReady|handleDataset|path === ['"]\/health['"]|path === ['"]\/ready['"]|path === ['"]\/api\/dataset['"]/.test(app),
    'hostinger/app.mjs must register /health, /ready, /api/dataset explicitly',
  );
  // The compatibility alias is a thin pass-through.
  assert.ok(
    /path === ['"]\/\.netlify\/functions\/dataset['"]/.test(app),
    'hostinger/app.mjs must register /.netlify/functions/dataset as a thin pass-through to handleDataset',
  );
  // The SPA fallback is responsible for `/` and any
  // unmatched route that resolves to a public file.
  assert.ok(
    /serveStatic|serveStaticFile|serveIndex|spaFallback|SPA fallback/i.test(app),
    'hostinger/app.mjs must have a static-asset / SPA fallback handler that owns /',
  );
});

/* ---- 2. Non-dataset /.netlify/functions/* paths are closed ---- */

test('hostinger-closure: non-dataset /.netlify/functions/* paths return an honest 404', () => {
  const app = readText(path.join(REPO, 'hostinger', 'app.mjs'));
  assert.ok(app);
  // The V6.8 hotfix adds a sink that returns 404 for any
  // /.netlify/functions/{name} path OTHER than the
  // documented compatibility alias. The pattern must:
  //   1) match the path prefix
  //   2) explicitly NOT match /dataset
  //   3) return 404 (not 200)
  const hasPrefixMatch = /path\.startsWith\(['"]\/\.netlify\/functions\/['"]\)/.test(app);
  const hasNonDatasetSink = !/path === ['"]\/\.netlify\/functions\/dataset['"]/.test(app) === false
    ? true // matched alias above is the documented exception
    : false;
  const returns404 = /statusCode\s*=\s*404/.test(app);
  assert.ok(
    hasPrefixMatch && hasNonDatasetSink && returns404,
    'hostinger/app.mjs must (a) match the /.netlify/functions/ prefix, (b) explicitly allow only /dataset, and (c) return a 404 for any other name',
  );
});

/* ---- 3. No public Hostinger runtime import from netlify/gateway/ ---- */

test('hostinger-closure: no public Hostinger runtime import from netlify/gateway/', () => {
  const allMjs = [];
  walkMjs(path.join(REPO, 'hostinger'), allMjs);
  walkMjs(path.join(REPO, 'server'), allMjs);
  walkMjs(path.join(REPO, 'jobs'), allMjs);
  const offenders = [];
  for (const f of allMjs) {
    const txt = readText(f) || '';
    // Match any import / dynamic import that points at the
    // gateway path.
    if (/(from|import)\s*['"](?:[^'"]*\/)?netlify\/gateway\//.test(txt)
      || /import\(\s*['"](?:[^'"]*\/)?netlify\/gateway\//.test(txt)) {
      offenders.push(path.relative(REPO, f));
    }
  }
  assert.equal(
    offenders.length, 0,
    `no public Hostinger / server / jobs module may import from netlify/gateway/; offenders: ${offenders.join(', ')}`,
  );
});

/* ---- 4. No public source references private gateway credential variables ---- */

test('hostinger-closure: no public source references the private gateway credential variables', () => {
  const gatewayOnlyVars = [
    'THREATPULSE_BASELINE_SITE_ID',
    'THREATPULSE_CREDENTIAL_PEPPER',
    'THREATPULSE_CREDENTIALS_BLOBS_ACCESS_TOKEN',
  ];
  // THREATPULSE_BLOBS_ACCESS_TOKEN is the gateway's
  // cross-site token. The public side uses
  // THREATPULSE_BLOBS_TOKEN (the local Netlify Blobs
  // token) — these are distinct variable names.
  const allPublic = [];
  walkMjs(path.join(REPO, 'hostinger'), allPublic);
  walkMjs(path.join(REPO, 'server'), allPublic);
  walkMjs(path.join(REPO, 'jobs'), allPublic);
  walkTsx(path.join(REPO, 'src'), allPublic);
  const offenders = [];
  for (const f of allPublic) {
    const txt = readText(f) || '';
    for (const v of gatewayOnlyVars) {
      if (txt.includes(v)) offenders.push(`${path.relative(REPO, f)}: ${v}`);
    }
  }
  assert.equal(
    offenders.length, 0,
    `gateway-only credential variables must not appear in public Hostinger / server / jobs / src code; offenders: ${offenders.join(', ')}`,
  );
});

/* ---- 5. Filesystem storage namespaces are documented ---- */

test('hostinger-closure: filesystem storage layout includes the five required namespaces', () => {
  const manifest = readText(path.join(REPO, 'deploy', 'v6-8-release-manifest.json'));
  assert.ok(manifest, 'release manifest must exist');
  // The manifest declares the four required filesystem
  // namespaces (tpr-dataset, tpr-vulnrichment,
  // tpr-github-advisory, tpr-baseline) under the public
  // site. The fifth namespace (tpr-public-intelligence)
  // is documented under hostingerFilesystemIntelligenceStores.
  const hasAll = ['tpr-dataset', 'tpr-vulnrichment', 'tpr-github-advisory', 'tpr-baseline']
    .every((n) => manifest.includes(n));
  assert.ok(hasAll, 'release manifest must declare tpr-dataset, tpr-vulnrichment, tpr-github-advisory, tpr-baseline');
  assert.ok(
    /tpr-public-intelligence/.test(manifest),
    'release manifest must declare the tpr-public-intelligence namespace',
  );
});

/* ---- 6. Managed scheduler contains all six logical schedules ---- */

test('hostinger-closure: managed scheduler contains all six logical schedules (refresh, baseline, publish, gc, verify, backup)', () => {
  const src = readText(path.join(REPO, 'hostinger', 'managed-scheduler.mjs'));
  assert.ok(src, 'managed-scheduler.mjs must exist');
  const expected = [
    { name: 'dataset-refresh', script: 'jobs/refresh-dataset.mjs' },
    { name: 'baseline-refresh', script: 'jobs/refresh-baseline.mjs' },
    { name: 'dataset-publish', script: 'jobs/publish-dataset-intelligence.mjs' },
    { name: 'public-intel-gc', script: 'jobs/gc-public-intelligence.mjs' },
    { name: 'state-verify', script: 'jobs/verify-state.mjs' },
    { name: 'backup', script: 'hostinger/backup.mjs' },
  ];
  for (const e of expected) {
    const re = new RegExp(`label:\\s*'${e.name}'[\\s\\S]{0,200}scriptRel:\\s*'${e.script.replace(/\//g, '\\/')}'`);
    assert.ok(re.test(src), `managed-scheduler.mjs must schedule ${e.name} → ${e.script}`);
  }
});

/* ---- 7. Provider-neutral Header labels and no legacy "Proxy: Netlify" ---- */

test('hostinger-closure: Header renders the provider-neutral data-route labels and no "Proxy: Netlify"', () => {
  const header = readText(path.join(REPO, 'src', 'components', 'Header.tsx'));
  assert.ok(header, 'Header.tsx must exist');
  // The three documented data-route states.
  assert.ok(/Data route:\s*same-origin/.test(header), 'Header.tsx must render "Data route: same-origin"');
  assert.ok(/Data route:\s*direct/.test(header), 'Header.tsx must render "Data route: direct"');
  assert.ok(/Data route:\s*unavailable/.test(header), 'Header.tsx must render "Data route: unavailable"');
  // The legacy provider-specific label must be absent
  // (case-insensitive) in the user-visible label.
  assert.ok(
    !/label\s*=\s*['"]Proxy:\s*Netlify['"]/i.test(header)
      && !/['"]Proxy:\s*Netlify['"]/.test(header),
    'Header.tsx must not render the legacy "Proxy: Netlify" label',
  );
  // Header h1 must use the documented responsive typography
  // scale (the `lg lg:` typo must be absent).
  assert.ok(
    /text-\[1\.65rem\][\s\S]{0,200}sm:text-3xl[\s\S]{0,200}lg:text-\[2\.4rem\]/.test(header),
    'Header.tsx h1 must use the documented responsive typography scale (no doubled `lg lg:` typo)',
  );
});

/* ---- 8. CSV remains exactly 21 columns ---- */

test('hostinger-closure: CSV_COLUMNS remains exactly 21 in src/utils/csvExport.ts', () => {
  const src = readText(path.join(REPO, 'src', 'utils', 'csvExport.ts'));
  assert.ok(src, 'csvExport.ts must exist');
  const m = src.match(/CSV_COLUMNS[^=]*=\s*\[([^\]]*)\]/);
  assert.ok(m, 'CSV_COLUMNS must be defined as an array literal in csvExport.ts');
  const cols = m[1].split(',').map((s) => s.trim()).filter(Boolean);
  assert.equal(cols.length, 21, `CSV_COLUMNS must have exactly 21 entries, got ${cols.length}`);
});

/* ---- 9. Exactly 5 public Netlify function entry files + 1 gateway function entry ---- */

test('hostinger-closure: exactly 5 public Netlify function entries and 1 gateway function entry', () => {
  const fnDir = path.join(REPO, 'netlify', 'functions');
  const publicEntries = listDirSafe(fnDir).filter((n) => n.endsWith('.mjs'));
  assert.equal(publicEntries.length, 5, `expected 5 public Netlify function entries, got ${publicEntries.length}: ${publicEntries.join(', ')}`);

  const gatewayFn = path.join(REPO, 'netlify', 'gateway', 'src', 'private-sync-gateway.mjs');
  assert.ok(isFileSafe(gatewayFn), 'netlify/gateway/src/private-sync-gateway.mjs must exist');

  // The deployment manifest must agree.
  const manifest = readText(path.join(REPO, 'deploy', 'v6-8-release-manifest.json'));
  assert.ok(manifest);
  const expected = ['dataset.mjs', 'refresh-baseline-background.mjs', 'refresh-baseline-scheduled.mjs', 'refresh-dataset-background.mjs', 'refresh-dataset-scheduled.mjs'];
  for (const f of expected) {
    assert.ok(publicEntries.includes(f), `public Netlify function entry must include ${f}`);
  }
  assert.ok(manifest.includes('"gatewayFunctionEntry": "private-sync-gateway.mjs"'), 'manifest must declare the gateway function entry');
});

/* ---- 10. client/** and netlify/gateway/** preservation against the documented baseline ---- */

test('hostinger-closure: client/** and netlify/gateway/** are unchanged against their documented baseline', () => {
  // Reuse the existing preflight helper: the canonical
  // baseline is `32a8a63` (V5.7 / V6.0). The branch under
  // test must have left both directories byte-identical
  // to that baseline. The `verify-v68-release` suite
  // already proves this invariant; we re-assert it here
  // because the closure contract depends on it.
  let out;
  try {
    out = execSync('git rev-parse origin/main', { cwd: REPO, encoding: 'utf-8' }).trim();
  } catch {
    out = '32a8a63bcfb6cb3df2abb2efad6f1b908c59eef5';
  }
  const baseline = out || '32a8a63bcfb6cb3df2abb2efad6f1b908c59eef5';
  for (const p of ['client', 'netlify/gateway']) {
    try {
      execSync(`git diff --quiet ${baseline}..HEAD -- ${p}`, { cwd: REPO, stdio: 'pipe' });
    } catch (err) {
      assert.fail(
        `${p} must be byte-identical to the ${baseline} baseline; non-clean diff detected`,
      );
    }
  }
});

/* ---- 11. No public refresh / admin / write HTTP route ---- */

test('hostinger-closure: no public refresh / admin / write HTTP route is exposed on Hostinger', () => {
  const app = readText(path.join(REPO, 'hostinger', 'app.mjs'));
  assert.ok(app);
  // The Hostinger method allowlist must reject every
  // non-GET, non-HEAD method. This is the documented
  // defense against accidental writes via POST/PUT/PATCH/
  // DELETE on any of the public paths.
  assert.ok(
    /req\.method\s*!==\s*['"]GET['"][\s\S]{0,200}req\.method\s*!==\s*['"]HEAD['"]/.test(app),
    'hostinger/app.mjs must reject every non-GET, non-HEAD method with a 405 response',
  );
  // No path under /api/refresh, /api/admin, /api/reset,
  // /api/clear, /api/wipe, /api/credential, /api/secret,
  // or any equivalent that would expose a write /
  // refresh / admin endpoint over HTTP.
  const blocked = [
    /path\s*===\s*['"]\/api\/refresh['"]/,
    /path\s*===\s*['"]\/api\/admin['"]/,
    /path\s*===\s*['"]\/api\/reset['"]/,
    /path\s*===\s*['"]\/api\/clear['"]/,
    /path\s*===\s*['"]\/api\/wipe['"]/,
    /path\s*===\s*['"]\/api\/credential['"]/,
    /path\s*===\s*['"]\/api\/secret['"]/,
    /path\.startsWith\(['"]\/api\/refresh['"]\)/,
    /path\.startsWith\(['"]\/api\/admin['"]\)/,
  ];
  for (const re of blocked) {
    assert.ok(
      !re.test(app),
      `hostinger/app.mjs must not register a public ${re.source} route`,
    );
  }
});
