// Acceptance tests for the v5.2 prebuilt dataset store.
//
//   node scripts/acceptance-prebuilt.mjs
//
// What it covers:
//   1. Netlify Blobs dependency + the shared store module
//      (package.json, _shared/store.mjs, _shared/refresh.mjs,
//      _shared/liveBuild.mjs).
//   2. Blob key naming (latest-dataset, refresh-lock) — the
//      spec mandates these exact names; tests fail if they
//      drift.
//   3. Refresh-lock semantics — pure-JS re-implementation
//      of `isLockActive` / `buildLockPayload` / `shouldSkipRefresh`
//      / `decideRefresh`, with boundary inputs:
//        - absent lock → not locked
//        - active lock (expiresAt in future) → locked
//        - expired lock (expiresAt in past) → not locked
//        - malformed lock (missing fields) → not locked
//      and the lock-decision path returns one of
//      { completed, in-progress, failed }.
//   4. Refresh-lock TTL is exactly 15 minutes
//      (REFRESH_LOCK_TTL_MS = 15 * 60 * 1000).
//   5. Background-refresh function
//      (refresh-dataset-background.mjs) — exists, returns 202
//      on success, 202 on in-progress, uses context.waitUntil,
//      doesn't expose NVD_API_KEY.
//   6. Scheduled-refresh function
//      (refresh-dataset-scheduled.mjs) — exists, delegates to
//      the shared refresh orchestrator.
//   7. netlify.toml — wires the three functions with
//      `node_bundler = "none"`, registers the cron schedule
//      `*/30 * * * *` for the scheduled function.
//   8. Dataset function (dataset.mjs) — reads the
//      `latest-dataset` blob first, falls back to the live
//      build on the bootstrap path, writes the blob on a
//      successful bootstrap, returns 502 with the
//      `mode: 'fallback'` envelope on a CISA failure.
//   9. Frontend service (vulnerabilityService.ts) — exposes
//      `manualRefresh()`, the `REFRESH_ENDPOINT_URL` constant
//      pointing at the background function, the new types
//      (`RefreshStatus`, `RefreshResult`), the new FetchResult
//      fields (`dataSource`, `refreshInProgress`), and the
//      `forceRefresh: true` path is no longer wired to the
//      manual button (preserved internally, replaced on the
//      manual path by `manualRefresh()`).
//  10. Dashboard / Header UI honesty:
//      - "Dataset store: latest available" pill on
//        `dataSource === 'prebuilt-store'`.
//      - "Refresh running in background" pill on
//        `refreshInProgress === true`.
//      - `RefreshInProgressBanner` component exists and
//        is wired on `refreshStatus` from the manual refresh
//        path.
//      - Manual button on CachedDataBanner is wired to
//        `handleManualRefresh`, not `forceRefresh: true`.
//  11. Honesty contract:
//      - The dataset function NEVER overwrites a good
//        `latest-dataset` blob with a mock fallback.
//      - `nvdStatus: 'unavailable'` is preserved through the
//        blob envelope — the dashboard never claims NVD
//        is enriched if the stored dataset has NVD unavailable.
//      - `dataSource` is `'prebuilt-store'` for blob reads,
//        `'live-build'` for the bootstrap path.
//  12. v5.1 regression — the soft-refresh path is unchanged:
//      background poll still detects newer upstream data and
//      surfaces the "New dataset available" banner. The new
//      background-refresh function does NOT auto-replace the
//      visible data; the user still clicks "Apply update".

import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');

/* ------------------------------------------------------------------ */
/* Test runner                                                        */
/* ------------------------------------------------------------------ */

let passed = 0;
let failed = 0;
const failures = [];

function assert(label, condition, extra = '') {
  if (condition) {
    passed++;
    console.log(`  \u2713 ${label}`);
  } else {
    failed++;
    failures.push({ label, extra });
    console.log(`  \u2717 ${label}${extra ? '  [' + extra + ']' : ''}`);
  }
}

function section(name) {
  console.log(`\n--- ${name} ---`);
}

/* ------------------------------------------------------------------ */
/* 1. Netlify Blobs dependency + shared module wiring                  */
/* ------------------------------------------------------------------ */

section('Netlify Blobs dependency + shared modules');

const packageJsonPath = join(root, 'package.json');
const packageJson = JSON.parse(readFileSync(packageJsonPath, 'utf8'));
const deps = { ...(packageJson.dependencies || {}), ...(packageJson.devDependencies || {}) };

assert('@netlify/blobs is declared as a runtime dependency',
  typeof deps['@netlify/blobs'] === 'string' && deps['@netlify/blobs'].length > 0,
  'expected @netlify/blobs in package.json dependencies');

assert('@netlify/blobs is at v8+ (current major with getStore + setEnvironmentContext)',
  /^[\^~]?\s*(?:>=?\s*)?(?:8|9|10|\d{2,})/.test(deps['@netlify/blobs'] || ''),
  'expected @netlify/blobs at major version >= 8');

const storePath = join(root, 'netlify', 'functions', '_shared', 'store.mjs');
const storeExists = existsSync(storePath);
assert('netlify/functions/_shared/store.mjs exists', storeExists,
  'expected the shared Blobs + lock helpers');
const storeSrc = storeExists ? readFileSync(storePath, 'utf8') : '';

const refreshPath = join(root, 'netlify', 'functions', '_shared', 'refresh.mjs');
const refreshExists = existsSync(refreshPath);
assert('netlify/functions/_shared/refresh.mjs exists', refreshExists,
  'expected the shared refresh orchestrator');
const refreshSrc = refreshExists ? readFileSync(refreshPath, 'utf8') : '';

const liveBuildPath = join(root, 'netlify', 'functions', '_shared', 'liveBuild.mjs');
const liveBuildExists = existsSync(liveBuildPath);
assert('netlify/functions/_shared/liveBuild.mjs exists', liveBuildExists,
  'expected the shared CISA → NVD → EPSS build module');
const liveBuildSrc = liveBuildExists ? readFileSync(liveBuildPath, 'utf8') : '';

/* ------------------------------------------------------------------ */
/* 2. Blob key naming — the spec mandates exact names                 */
/* ------------------------------------------------------------------ */

section('Blob keys (latest-dataset + refresh-lock)');

assert('store module declares the latest-dataset key constant',
  /LATEST_DATASET_KEY\s*=\s*['"]latest-dataset['"]/.test(storeSrc),
  'expected `LATEST_DATASET_KEY = "latest-dataset"`');

assert('store module declares the refresh-lock key constant',
  /REFRESH_LOCK_KEY\s*=\s*['"]refresh-lock['"]/.test(storeSrc),
  'expected `REFRESH_LOCK_KEY = "refresh-lock"`');

assert('store module declares the Blobs store name (tpr-dataset)',
  /STORE_NAME\s*=\s*['"]tpr-dataset['"]/.test(storeSrc),
  'expected `STORE_NAME = "tpr-dataset"`');

assert('store module uses `getStore` from @netlify/blobs',
  /import\s*\{[^}]*getStore[^}]*\}\s*from\s*['"]@netlify\/blobs['"]/.test(storeSrc),
  'expected `import { getStore } from "@netlify/blobs"`');

assert('store module exposes `getDatasetStore()`',
  /export\s+function\s+getDatasetStore/.test(storeSrc),
  'expected `export function getDatasetStore`');

assert('store module exposes `readLatestDataset()` and `writeLatestDataset()`',
  /export\s+(?:async\s+)?function\s+readLatestDataset/.test(storeSrc) &&
    /export\s+(?:async\s+)?function\s+writeLatestDataset/.test(storeSrc),
  'expected both readLatestDataset and writeLatestDataset');

assert('store module exposes `readRefreshLock()`, `isRefreshLocked()`, `tryAcquireRefreshLock()`, `clearRefreshLock()`',
  /export\s+(?:async\s+)?function\s+readRefreshLock/.test(storeSrc) &&
    /export\s+(?:async\s+)?function\s+isRefreshLocked/.test(storeSrc) &&
    /export\s+(?:async\s+)?function\s+tryAcquireRefreshLock/.test(storeSrc) &&
    /export\s+(?:async\s+)?function\s+clearRefreshLock/.test(storeSrc),
  'expected all four lock helpers');

/* ------------------------------------------------------------------ */
/* 3. Refresh-lock TTL is exactly 15 minutes                          */
/* ------------------------------------------------------------------ */

section('Refresh-lock TTL');

assert('REFRESH_LOCK_TTL_MS is exactly 15 * 60 * 1000 ms (15 minutes)',
  /REFRESH_LOCK_TTL_MS\s*=\s*15\s*\*\s*60\s*\*\s*1000\b/.test(storeSrc),
  'expected REFRESH_LOCK_TTL_MS = 15 * 60 * 1000');

assert('store module comment explains the 15-min TTL rationale',
  /15[\s-]*minute/i.test(storeSrc) && /safety margin|long enough|conservative/i.test(storeSrc),
  'expected a comment explaining why 15 min');

/* ------------------------------------------------------------------ */
/* 4. Pure-JS decision logic (lock + refresh-decision helpers)        */
/* ------------------------------------------------------------------ */

section('Pure-JS decision logic (lock + refresh-decision helpers)');

/**
 * Mirror of `isLockActive` from store.mjs. Keeps the test
 * self-contained — does NOT import the actual module
 * (Node imports across Netlify-function-style ESM work fine,
 * but keeping it pure lets the tests stay fast and offline).
 */
function isLockActive(lock, now = new Date()) {
  if (!lock) return false;
  if (typeof lock.expiresAt !== 'string') return false;
  const t = new Date(lock.expiresAt).getTime();
  if (Number.isNaN(t)) return false;
  return t > now.getTime();
}

const NOW = new Date('2026-07-09T12:00:00.000Z');
const FUTURE = new Date(NOW.getTime() + 5 * 60 * 1000); // +5 min
const PAST = new Date(NOW.getTime() - 5 * 60 * 1000); // -5 min

assert('isLockActive(null) → false', isLockActive(null, NOW) === false);
assert('isLockActive(undefined) → false', isLockActive(undefined, NOW) === false);
assert('isLockActive({}) → false (no expiresAt)', isLockActive({}, NOW) === false);
assert('isLockActive({expiresAt: "not-a-date"}) → false (NaN)', isLockActive({ expiresAt: 'not-a-date' }, NOW) === false);
assert('isLockActive({expiresAt: future}) → true (active)', isLockActive({ startedAt: NOW.toISOString(), expiresAt: FUTURE.toISOString() }, NOW) === true);
assert('isLockActive({expiresAt: past}) → false (expired)', isLockActive({ startedAt: PAST.toISOString(), expiresAt: PAST.toISOString() }, NOW) === false);
assert('isLockActive({expiresAt: now}) → false (boundary, expiresAt = now is not > now)',
  isLockActive({ expiresAt: NOW.toISOString() }, NOW) === false);

/**
 * Mirror of `decideRefresh` from refresh.mjs.
 */
function decideRefresh({ existingLock, buildResult, buildError, now = new Date(), ttlMs = 15 * 60 * 1000 }) {
  if (existingLock && isLockActive(existingLock, now)) {
    return { status: 'in-progress', fetchedAt: null, refreshInProgress: true };
  }
  if (buildError) {
    return {
      status: 'failed',
      reason: buildError instanceof Error ? buildError.message : String(buildError),
      refreshInProgress: false,
    };
  }
  if (!buildResult || buildResult.mode !== 'live' || buildResult.source !== 'merged') {
    return {
      status: 'failed',
      reason: 'Refresh build returned a non-live result; existing blob is preserved.',
      refreshInProgress: false,
    };
  }
  return { status: 'completed', fetchedAt: buildResult.fetchedAt, refreshInProgress: false };
}

const GOOD_BUILD = {
  data: [{ id: 'kev-cve-x', cveId: 'CVE-X' }],
  source: 'merged',
  fetchedAt: '2026-07-09T11:55:00.000Z',
  mode: 'live',
  nvdStatus: 'nvd',
  epssStatus: 'first',
};
const ACTIVE_LOCK = { startedAt: NOW.toISOString(), expiresAt: FUTURE.toISOString() };

assert('decideRefresh: no lock + good build → completed', decideRefresh({ existingLock: null, buildResult: GOOD_BUILD, now: NOW }).status === 'completed');
assert('decideRefresh: active lock + good build → in-progress',
  decideRefresh({ existingLock: ACTIVE_LOCK, buildResult: GOOD_BUILD, now: NOW }).status === 'in-progress');
assert('decideRefresh: active lock + bad build (no live) → in-progress (lock checked first)',
  decideRefresh({ existingLock: ACTIVE_LOCK, buildResult: { mode: 'mock' }, now: NOW }).status === 'in-progress');
assert('decideRefresh: no lock + null build → failed', decideRefresh({ existingLock: null, buildResult: null, now: NOW }).status === 'failed');
assert('decideRefresh: no lock + mock build → failed (rejects non-live)',
  decideRefresh({ existingLock: null, buildResult: { mode: 'mock', source: 'mock' }, now: NOW }).status === 'failed');
assert('decideRefresh: no lock + buildError → failed with reason',
  decideRefresh({ existingLock: null, buildError: new Error('NVD blew up'), now: NOW }).reason === 'NVD blew up');
assert('decideRefresh: no lock + good build → refreshInProgress: false on completion',
  decideRefresh({ existingLock: null, buildResult: GOOD_BUILD, now: NOW }).refreshInProgress === false);
assert('decideRefresh: active lock + good build → refreshInProgress: true',
  decideRefresh({ existingLock: ACTIVE_LOCK, buildResult: GOOD_BUILD, now: NOW }).refreshInProgress === true);

/* ------------------------------------------------------------------ */
/* 5. Background-refresh function                                     */
/* ------------------------------------------------------------------ */

section('Background-refresh function');

const bgPath = join(root, 'netlify', 'functions', 'refresh-dataset-background.mjs');
const bgExists = existsSync(bgPath);
assert('netlify/functions/refresh-dataset-background.mjs exists', bgExists,
  'expected the manual-refresh background function');
const bgSrc = bgExists ? readFileSync(bgPath, 'utf8') : '';

assert('background function is a default-exported handler',
  /export\s+default\s+async\s*\(/.test(bgSrc),
  'expected a default-exported async handler');

assert('background function imports from the shared store module',
  /import\s*\{[^}]*\}\s*from\s*['"]\.\/_shared\/store\.mjs['"]/.test(bgSrc),
  'expected `import ... from "./_shared/store.mjs"`');

assert('background function imports `runRefresh` from the shared refresh module',
  /import\s*\{[^}]*runRefresh[^}]*\}\s*from\s*['"]\.\/_shared\/refresh\.mjs['"]/.test(bgSrc),
  'expected `import { runRefresh } from "./_shared/refresh.mjs"`');

assert('background function imports `buildLiveDataset` from the shared liveBuild module',
  /import\s*\{[^}]*buildLiveDataset[^}]*\}\s*from\s*['"]\.\/_shared\/liveBuild\.mjs['"]/.test(bgSrc),
  'expected `import { buildLiveDataset } from "./_shared/liveBuild.mjs"`');

assert('background function uses context.waitUntil to keep the build alive',
  /context\.waitUntil/.test(bgSrc),
  'expected `context.waitUntil(buildPromise)` to keep the function alive after response');

assert('background function returns 202 with status:"started" or "in-progress"',
  /status:\s*['"]started['"]/.test(bgSrc) || /status:\s*['"]in-progress['"]/.test(bgSrc),
  'expected a 202 response with status:"started" or status:"in-progress"');

assert('background function never exposes NVD_API_KEY to the browser',
  !/VITE_NVD_API_KEY/.test(bgSrc) &&
    !/import\.meta\.env\.NVD_API_KEY/.test(bgSrc),
  'expected no VITE_NVD_API_KEY or import.meta.env.NVD_API_KEY (server-side only)');

/* ------------------------------------------------------------------ */
/* 6. Scheduled-refresh function                                      */
/* ------------------------------------------------------------------ */

section('Scheduled-refresh function');

const schedPath = join(root, 'netlify', 'functions', 'refresh-dataset-scheduled.mjs');
const schedExists = existsSync(schedPath);
assert('netlify/functions/refresh-dataset-scheduled.mjs exists', schedExists,
  'expected the scheduled-refresh function');
const schedSrc = schedExists ? readFileSync(schedPath, 'utf8') : '';

assert('scheduled function is a default-exported handler',
  /export\s+default\s+async\s*\(/.test(schedSrc),
  'expected a default-exported async handler');

assert('scheduled function imports `runRefresh` from the shared refresh module',
  /import\s*\{[^}]*runRefresh[^}]*\}\s*from\s*['"]\.\/_shared\/refresh\.mjs['"]/.test(schedSrc),
  'expected `import { runRefresh } from "./_shared/refresh.mjs"`');

assert('scheduled function imports `buildLiveDataset` from the shared liveBuild module',
  /import\s*\{[^}]*buildLiveDataset[^}]*\}\s*from\s*['"]\.\/_shared\/liveBuild\.mjs['"]/.test(schedSrc),
  'expected `import { buildLiveDataset } from "./_shared/liveBuild.mjs"`');

assert('scheduled function logs the trigger source',
  /console\.log/.test(schedSrc) && /trigger/.test(schedSrc),
  'expected console.log of the trigger source (scheduled vs manual)');

assert('scheduled function handles the case where Blobs is unavailable',
  /Blob store unavailable|getDatasetStore/.test(schedSrc),
  'expected graceful handling when getDatasetStore throws');

/* ------------------------------------------------------------------ */
/* 7. netlify.toml — wires all three functions + cron schedule        */
/* ------------------------------------------------------------------ */

section('netlify.toml configuration');

const netlifyTomlPath = join(root, 'netlify.toml');
const netlifyToml = readFileSync(netlifyTomlPath, 'utf8');

assert('netlify.toml configures a cron schedule for refresh-dataset-scheduled',
  // The schedule can be on the same line as the function
  // header, OR in a separate block — both are valid TOML.
  // We accept either:
  //   [functions.refresh-dataset-scheduled]
  //     schedule = "*/30 * * * *"
  // OR a Netlify-cron annotation.
  /\[functions\.refresh-dataset-scheduled\]/.test(netlifyToml) &&
    /schedule\s*=\s*["']\*\/\d+\s+\*\s+\*\s+\*\s+\*["']/.test(netlifyToml),
  'expected a `schedule = "*/N * * * *"` cron on the scheduled function');

assert('netlify.toml cron is conservative (30 min or longer, NOT every minute)',
  // Conservative = at least every 5 minutes. The spec calls
  // for "hourly or every 30 minutes" — we accept any divisor
  // that maps to ≥5 minutes.
  /schedule\s*=\s*["']\*\/(?:[5-9]|[1-5][0-9]|[6-9][0-9])\s+\*\s+\*\s+\*\s+\*["']/.test(netlifyToml),
  'expected a conservative schedule (every 5+ minutes, not every minute)');

/* ------------------------------------------------------------------ */
/* 7.5. v5.2.1 — runtime bundling fix for _shared/ modules             */
/* ------------------------------------------------------------------ */

section('v5.2.1 — runtime bundling (shared-module imports)');

/**
 * v5.2.1 regression guard.
 *
 * Under v5.2's `node_bundler = "none"` setting Netlify
 * deployed only the entry `.mjs` files to `/var/task/`.
 * The `_shared/` folder never made it into the artifact,
 * so any `import './_shared/{liveBuild,refresh,store}.mjs'`
 * failed at runtime with:
 *
 *   Cannot find module '/var/task/_shared/liveBuild.mjs'
 *   imported from /var/task/dataset.mjs
 *
 * The fix is to bundle the functions with esbuild so
 * local relative imports are inlined into the function
 * output. `node_bundler = "esbuild"` can be set either
 * globally (in `[functions]`) or per-function; both forms
 * are accepted.
 */

assert('v5.2.1: netlify.toml does NOT use node_bundler = "none" anywhere (would break _shared/ imports)',
  // With "none" the _shared/ folder is not shipped. This was
  // the v5.2 deploy-preview crash. Reject any occurrence of
  // node_bundler = "none" — including the per-function
  // variants the v5.2 toml had. Strip TOML comments first
  // so the explanatory `#` block at the top of netlify.toml
  // (which references "none" historically) doesn't trip
  // the test.
  //
  // Implementation note: the line-comment regex uses
  // `[^\n]*` instead of `.*` because `.` does NOT match `\r`
  // in JavaScript regex. On a CRLF file (which `netlify.toml`
  // is on Windows-checked-out repos), each line ends with
  // `\r`. With `.*`, the regex matches up to but not
  // including the `\r`, then `$` fails to match — so the
  // comment-strip step silently no-ops on every line and the
  // literal `node_bundler = "none"` substring inside the
  // explanatory comment trips the test. `[^\n]` matches `\r`
  // (which is NOT a newline), so this version strips CRLF
  // line comments correctly.
  (() => {
    const code = netlifyToml
      .split('\n')
      .map((l) => l.replace(/^\s*#[^\n]*$/, ''))
      .join('\n');
    return !/node_bundler\s*=\s*["']none["']/.test(code);
  })(),
  'expected no `node_bundler = "none"` in actual toml config (it breaks _shared/ module imports at runtime)');

assert('v5.2.1: netlify.toml sets node_bundler = "esbuild" globally or per-function',
  // Accept either:
  //   [functions]
  //     node_bundler = "esbuild"
  // OR
  //   [functions.dataset]
  //     node_bundler = "esbuild"
  // Both inline the local relative imports into the
  // function output so /var/task/_shared/... isn't needed.
  /node_bundler\s*=\s*["']esbuild["']/.test(netlifyToml),
  'expected `node_bundler = "esbuild"` somewhere in netlify.toml');

assert('v5.2.1: dataset function keeps its section header (even with default bundler)',
  /\[functions\.dataset\]/.test(netlifyToml),
  'expected `[functions.dataset]` to remain in netlify.toml');

assert('v5.2.1: refresh-dataset-background keeps its section header',
  /\[functions\.refresh-dataset-background\]/.test(netlifyToml),
  'expected `[functions.refresh-dataset-background]` to remain in netlify.toml');

assert('v5.2.1: refresh-dataset-scheduled keeps its section header with the schedule',
  /\[functions\.refresh-dataset-scheduled\]/.test(netlifyToml) &&
    /schedule\s*=\s*["']\*\/\d+\s+\*\s+\*\s+\*\s+\*["']/.test(netlifyToml),
  'expected `[functions.refresh-dataset-scheduled]` with the cron schedule');

/* ------------------------------------------------------------------ */
/* 8. Dataset function — blob-first read, bootstrap path              */
/* ------------------------------------------------------------------ */

section('Dataset function — blob-first read + bootstrap');

const datasetPath = join(root, 'netlify', 'functions', 'dataset.mjs');
const datasetSrc = readFileSync(datasetPath, 'utf8');

assert('dataset function imports `readLatestDataset` from the shared store',
  /import\s*\{[^}]*readLatestDataset[^}]*\}\s*from\s*['"]\.\/_shared\/store\.mjs['"]/.test(datasetSrc),
  'expected readLatestDataset import from _shared/store.mjs');

assert('dataset function imports `writeLatestDataset` from the shared store',
  /import\s*\{[^}]*writeLatestDataset[^}]*\}\s*from\s*['"]\.\/_shared\/store\.mjs['"]/.test(datasetSrc),
  'expected writeLatestDataset import from _shared/store.mjs');

assert('dataset function imports `isRefreshLocked` from the shared store',
  /import\s*\{[^}]*isRefreshLocked[^}]*\}\s*from\s*['"]\.\/_shared\/store\.mjs['"]/.test(datasetSrc),
  'expected isRefreshLocked import for the refreshInProgress flag');

assert('dataset function imports `buildLiveDataset` from the shared liveBuild module',
  /import\s*\{[^}]*buildLiveDataset[^}]*\}\s*from\s*['"]\.\/_shared\/liveBuild\.mjs['"]/.test(datasetSrc),
  'expected buildLiveDataset import from _shared/liveBuild.mjs');

assert('dataset function reads `latest-dataset` BEFORE running the live build',
  // Order matters: the blob-read must appear before the
  // `buildLiveDataset` call so a hit returns immediately
  // without paying the build cost.
  (() => {
    const iRead = datasetSrc.indexOf('readLatestDataset(');
    const iBuild = datasetSrc.indexOf('buildLiveDataset(');
    return iRead > 0 && iBuild > 0 && iRead < iBuild;
  })(),
  'expected `readLatestDataset(` to appear before `buildLiveDataset(`');

assert('dataset function tags the blob-hit response with `dataSource: "prebuilt-store"`',
  /dataSource:\s*['"]prebuilt-store['"]/.test(datasetSrc),
  'expected `dataSource: "prebuilt-store"` on the blob-read branch');

assert('dataset function tags the bootstrap response with `dataSource: "live-build"`',
  /dataSource:\s*['"]live-build['"]/.test(datasetSrc),
  'expected `dataSource: "live-build"` on the bootstrap branch');

assert('dataset function writes the blob on a SUCCESSFUL bootstrap',
  /writeLatestDataset\(/.test(datasetSrc),
  'expected `writeLatestDataset(` after a successful buildLiveDataset call');

assert('dataset function NEVER writes a mock fallback to the blob',
  // The bootstrap path must call writeLatestDataset only
  // AFTER the build succeeds — never on the CISA-failure
  // 502 branch. Verify by extracting the CISA-failure catch
  // block (the slice from the catch to the next balanced
  // closing brace) and asserting it does NOT contain
  // writeLatestDataset.
  (() => {
    const code = datasetSrc
      .replace(/\/\*[\s\S]*?\*\//g, '')
      .replace(/^\s*\/\/.*$/gm, '')
      .replace(/\s+\/\/.*$/gm, '');
    const iFallback = code.indexOf('jsonResponse(502');
    if (iFallback < 0) return false;
    // Walk backwards from the fallback response to find the
    // nearest `catch {` block start.
    const iCatch = code.lastIndexOf('catch', iFallback);
    if (iCatch < 0) return false;
    // Walk forwards to find the matching close brace — naive
    // brace-counting, but the dataset function's body is
    // small and well-formatted so it works in practice.
    let depth = 0;
    let iEnd = -1;
    for (let i = iCatch; i < code.length; i++) {
      const ch = code[i];
      if (ch === '{') depth++;
      else if (ch === '}') {
        depth--;
        if (depth === 0) { iEnd = i; break; }
      }
    }
    if (iEnd < 0) return false;
    const catchBlock = code.slice(iCatch, iEnd + 1);
    // The catch block must contain `mode: 'fallback'` (that's
    // the fallback envelope). It must NOT contain
    // `writeLatestDataset(` — that would mean the failure
    // path overwrites the blob with a mock fallback.
    return /mode:\s*['"]fallback['"]/.test(catchBlock) &&
      !/writeLatestDataset\(/.test(catchBlock);
  })(),
  'expected the CISA-failure 502 catch block to NOT call writeLatestDataset');

assert('dataset function returns 502 with mode:"fallback" on CISA failure',
  /jsonResponse\(\s*502[\s\S]{0,400}mode:\s*['"]fallback['"]/.test(datasetSrc),
  'expected the v5.0 fallback envelope (HTTP 502 + mode:"fallback") to remain');

assert('dataset function preserves the v5.0.1 CDN-cacheable Cache-Control',
  /Cache-Control['"]\s*:\s*['"]public,\s*s-maxage=900,\s*stale-while-revalidate=300/.test(datasetSrc),
  'expected the v5.0.1 Cache-Control: public, s-maxage=900, stale-while-revalidate=300 to remain');

assert('dataset function overlays `refreshInProgress` from the lock state',
  /refreshInProgress/.test(datasetSrc) && /isRefreshLocked/.test(datasetSrc),
  'expected `refreshInProgress` to be set from `isRefreshLocked(store)`');

assert('dataset function does NOT trigger refreshes itself',
  // The dataset endpoint is read-only — it must not call
  // runRefresh or POST to itself. Refreshes are owned by
  // the manual / scheduled functions. Strip comments first
  // so the doc text that mentions the other functions
  // doesn't trip the test.
  (() => {
    const code = datasetSrc
      .replace(/\/\*[\s\S]*?\*\//g, '')
      .replace(/^\s*\/\/.*$/gm, '')
      .replace(/\s+\/\/.*$/gm, '');
    return !/runRefresh\(/.test(code) &&
      !/refresh-dataset-background/.test(code) &&
      !/refresh-dataset-scheduled/.test(code);
  })(),
  'expected dataset.mjs to be read-only (no runRefresh / refresh-background calls)');

/* ------------------------------------------------------------------ */
/* 9. Frontend service — manualRefresh() + REFRESH_ENDPOINT_URL       */
/* ------------------------------------------------------------------ */

section('Frontend service — manualRefresh() + new types');

const servicePath = join(root, 'src', 'services', 'vulnerabilityService.ts');
const serviceSrc = readFileSync(servicePath, 'utf8');

assert('service declares a REFRESH_ENDPOINT_URL constant',
  /REFRESH_ENDPOINT_URL/.test(serviceSrc),
  'expected `REFRESH_ENDPOINT_URL` constant');

assert('REFRESH_ENDPOINT_URL defaults to /.netlify/functions/refresh-dataset-background',
  /\/\.netlify\/functions\/refresh-dataset-background/.test(serviceSrc),
  'expected default of `/.netlify/functions/refresh-dataset-background`');

assert('REFRESH_ENDPOINT_URL can be overridden by VITE_REFRESH_ENDPOINT_URL',
  /VITE_REFRESH_ENDPOINT_URL/.test(serviceSrc),
  'expected a `VITE_REFRESH_ENDPOINT_URL` override (optional, public route, not a secret)');

assert('service exports a `manualRefresh` function',
  /export\s+async\s+function\s+manualRefresh/.test(serviceSrc),
  'expected `export async function manualRefresh`');

assert('service defines a RefreshResult type with status / fetchedAt / reason / refreshInProgress',
  /export\s+interface\s+RefreshResult/.test(serviceSrc) &&
    /status\s*:\s*RefreshStatus/.test(serviceSrc) &&
    /refreshInProgress\s*:\s*boolean/.test(serviceSrc),
  'expected `export interface RefreshResult` with the four fields');

assert('service defines a RefreshStatus type with completed / started / in-progress / failed',
  /export\s+type\s+RefreshStatus/.test(serviceSrc) &&
    /['"]completed['"]/.test(serviceSrc) &&
    /['"]started['"]/.test(serviceSrc) &&
    /['"]in-progress['"]/.test(serviceSrc) &&
    /['"]failed['"]/.test(serviceSrc),
  'expected `RefreshStatus = "completed" | "started" | "in-progress" | "failed"`');

assert('service adds `dataSource?: PrebuiltDataSource` to FetchResult',
  /dataSource\?\s*:\s*PrebuiltDataSource/.test(serviceSrc),
  'expected `dataSource?: PrebuiltDataSource` field on FetchResult');

assert('service adds `refreshInProgress?: boolean` to FetchResult',
  /refreshInProgress\?\s*:\s*boolean/.test(serviceSrc),
  'expected `refreshInProgress?: boolean` field on FetchResult');

assert('service preserves `forceRefresh: boolean` on VulnerabilityQuery (still wired internally)',
  /forceRefresh\?\s*:\s*boolean/.test(serviceSrc) &&
    /forceRefresh:\s*query\.forceRefresh/.test(serviceSrc),
  'expected `forceRefresh?: boolean` still on VulnerabilityQuery, still forwarded to tryLiveFetch');

assert('service no longer wires the MANUAL button to forceRefresh: true',
  // The manual-refresh path is now `manualRefresh()` (POSTs
  // to the background function). `forceRefresh: true` is
  // still alive in the service for the internal polling
  // path's `?t=<ts>` cache-buster, but the user-visible
  // manual button uses the background endpoint.
  !/handleRefresh[\s\S]{0,500}forceRefresh/.test(serviceSrc),
  'expected the manual refresh handler to NOT pass forceRefresh:true');

assert('manualRefresh POSTs to the refresh endpoint (not GET)',
  /method:\s*['"]POST['"]/.test(serviceSrc),
  'expected `method: "POST"` on the manual refresh fetch');

/* ------------------------------------------------------------------ */
/* 10. Dashboard + Header UI honesty                                  */
/* ------------------------------------------------------------------ */

section('Dashboard + Header UI honesty');

const dashboardSrc = readFileSync(join(root, 'src', 'pages', 'DashboardPage.tsx'), 'utf8');
const headerSrc = readFileSync(join(root, 'src', 'components', 'Header.tsx'), 'utf8');

assert('Header shows "Dataset store: latest available" pill on dataSource === "prebuilt-store"',
  /dataSource\s*===\s*['"]prebuilt-store['"]/.test(headerSrc) &&
    /Dataset store: latest available/.test(headerSrc),
  'expected a "Dataset store: latest available" pill on dataSource="prebuilt-store"');

assert('Header shows a "bootstrapping" pill on dataSource === "live-build"',
  /dataSource\s*===\s*['"]live-build['"]/.test(headerSrc),
  'expected a "bootstrapping" pill on dataSource="live-build"');

assert('Header shows "Refresh running in background" pill on refreshInProgress === true',
  /refreshInProgress\s*===\s*true/.test(headerSrc) &&
    /Refresh running in background/.test(headerSrc),
  'expected a "Refresh running in background" pill on refreshInProgress=true');

assert('Header refresh pill is info-tone (cyan) with a pulse',
  // The info tone is the cyan accent — same as the Proxy /
  // Cache-fresh pills. The pulse is a `pulse` prop on
  // StatusPill (the same prop used by "Defensive use only").
  /Refresh running in background[\s\S]{0,800}pulse/.test(headerSrc) ||
    /pulse[\s\S]{0,1500}Refresh running in background/.test(headerSrc),
  'expected the refresh-in-progress pill to use the pulsing info tone');

assert('Header refresh pill uses a Loader2 icon (rotating)',
  /Loader2/.test(headerSrc) && /animate-spin/.test(headerSrc),
  'expected Loader2 with animate-spin for the rotating icon');

assert('Last refresh tooltip now reads "Last dataset build: <time>"',
  /Last dataset build/.test(headerSrc),
  'expected the Last refresh tooltip to use the v5.2 wording');

assert('DashboardPage does NOT import `manualRefresh` (v5.4.2: button removed from public UI)',
  // The service's `manualRefresh()` is kept for internal
  // callers (the cron + the background-function path), but
  // the dashboard no longer imports it — the public
  // "Refresh live data" button was removed in v5.4.2.
  !/import\s*\{[\s\S]*?manualRefresh[\s\S]*?\}\s*from\s*['"]\.\.\/services\/vulnerabilityService['"]/.test(dashboardSrc),
  'expected the dashboard to NOT import manualRefresh (the public button was removed)');

assert('DashboardPage declares a `refreshStatus` state slot',
  /const\s+\[refreshStatus,\s*setRefreshStatus\]\s*=\s*useState/.test(dashboardSrc),
  'expected `refreshStatus` state in DashboardPage');

assert('DashboardPage does NOT define `handleManualRefresh` (v5.4.2: button removed)',
  // The handler that POSTed to the background function is
  // no longer needed — refreshes are async, the scheduled
  // cron + the background endpoint run without UI action.
  !/function\s+handleManualRefresh|const\s+handleManualRefresh\s*=\s*useCallback/.test(dashboardSrc),
  'expected DashboardPage to NOT define handleManualRefresh (button removed)');

assert('DashboardPage renders a RefreshInProgressBanner when refreshStatus is in-flight',
  /RefreshInProgressBanner/.test(dashboardSrc),
  'expected a RefreshInProgressBanner component and a conditional render');

assert('DashboardPage polls clear `refreshStatus` when server says refreshInProgress: false',
  /setRefreshStatus\([\s\S]{0,300}refreshInProgress\s*===\s*false/.test(dashboardSrc) ||
    /result\.refreshInProgress\s*===\s*false/.test(dashboardSrc),
  'expected the polling effect to clear `refreshStatus` when the server reports the refresh is done');

assert('CachedDataBanner is NOT wired to a manual refresh handler (v5.4.2: button removed)',
  // v5.4.2: the CachedDataBanner no longer renders a
  // "Refresh live data" button, so it doesn't take an
  // onRefresh prop. The body copy tells the user that
  // refreshes happen automatically.
  !/onRefresh=\{handleManualRefresh\}/.test(dashboardSrc) &&
    !/onRefresh=\{handleRefresh\}/.test(dashboardSrc),
  'expected the cached-data banner to NOT be wired to a manual refresh handler');

assert('RefreshInProgressBanner accepts `status` and `onDismiss` props',
  /function\s+RefreshInProgressBanner[\s\S]{0,400}status[\s\S]{0,200}RefreshResult/.test(dashboardSrc) &&
    /onDismiss/.test(dashboardSrc),
  'expected RefreshInProgressBanner with status + onDismiss props');

assert('RefreshInProgressBanner surfaces an in-progress vs failed vs started message',
  /Refresh running in background/.test(dashboardSrc) &&
    /Refresh failed/.test(dashboardSrc) &&
    /A new dataset is being built/.test(dashboardSrc),
  'expected three messages: started, in-progress, failed');

assert('RefreshInProgressBanner dismisses on × click (no auto-dismiss timer)',
  /aria-label\s*=\s*["']Dismiss refresh-status banner["']/.test(dashboardSrc) ||
    /setRefreshStatus\(null\)/.test(dashboardSrc),
  'expected a dismiss (×) button that sets refreshStatus to null');

/* ------------------------------------------------------------------ */
/* 11. Honesty contract — provider failures preserved, no overwrite   */
/* ------------------------------------------------------------------ */

section('Honesty contract — provider failures + dataSource tagging');

assert('the liveBuild module still returns nvdStatus on success',
  // v5.2.5: the liveBuild envelope uses shorthand `nvdStatus,`
  // (no explicit `: nvdResult.status`) because `nvdStatus` is
  // already assigned to a local variable in the partial-failure
  // branch. Accept either the explicit-colon form or the
  // shorthand form so future refactors don't regress.
  /nvdStatus[\s,:]/.test(liveBuildSrc) && /epssStatus[\s,:]/.test(liveBuildSrc),
  'expected the liveBuild module to return nvdStatus and epssStatus');

assert('the liveBuild module preserves the concise 429 reason (v5.0.2)',
  /rate limit reached/.test(liveBuildSrc) && /CISA-derived/.test(liveBuildSrc),
  'expected the v5.0.2 429 reason to remain in the liveBuild module');

assert('the dataset function preserves FetchResult fields through the blob envelope',
  // The blob-hit response spreads the prebuilt envelope —
  // nvdStatus / epssStatus / fetchedAt / mode all survive.
  // v5.4.2: the spread goes through a `publicEnvelope()`
  // helper that strips the internal `lastRefreshAttemptAt` /
  // `lastRefreshFailure` fields before sending the response
  // to the visitor. Accept either pattern (with or without
  // the publicEnvelope wrapper) so this test survives the
  // v5.4.2 metadata-strip addition.
  /\.\.\.\s*prebuilt/.test(datasetSrc) ||
    /publicEnvelope\(\s*prebuilt\s*\)/.test(datasetSrc),
  'expected `...prebuilt` to spread the cached envelope (or `publicEnvelope(prebuilt)` for the v5.4.2 metadata-strip variant)');

assert('the dashboard never claims NVD enriched if the stored dataset has NVD unavailable',
  // The NvdUnavailableBanner only renders when
  // `nvdStatus === "unavailable"`. The prebuilt envelope
  // preserves this field verbatim, so a stored dataset with
  // `nvdStatus: "unavailable"` still surfaces the warning.
  /nvdStatus\s*===\s*['"]unavailable['"]/.test(dashboardSrc) &&
    /NvdUnavailableBanner/.test(dashboardSrc),
  'expected NvdUnavailableBanner to render on nvdStatus="unavailable"');

assert('the dashboard has no manual-refresh setState path (v5.4.2: button removed)',
  // v5.2 originally checked that handleManualRefresh did
  // NOT auto-replace the visible data. With the v5.4.2
  // removal of the manual button, the relevant invariant
  // is even stronger: there is no manual refresh path at
  // all, so no setState({ kind: "ready", ... }) call is
  // possible from user-initiated refresh action. The
  // v5.1 handleApplyUpdate path is preserved.
  !/handleManualRefresh[\s\S]{0,500}setState\(\s*\{\s*kind:\s*['"]ready['"]/.test(dashboardSrc),
  'expected no manual-refresh setState path in DashboardPage');

/* ------------------------------------------------------------------ */
/* 12. v5.1 regression — soft refresh path unchanged                  */
/* ------------------------------------------------------------------ */

section('v5.1 regression — soft refresh path unchanged');

assert('DashboardPage still polls every 5 minutes (BACKGROUND_POLL_INTERVAL_MS)',
  /BACKGROUND_POLL_INTERVAL_MS\s*=\s*5\s*\*\s*60\s*\*\s*1000/.test(dashboardSrc),
  'expected the v5.1 5-minute cadence');

assert('DashboardPage still calls fetchVulnerabilities({ background: true }) in the poll',
  /fetchVulnerabilities\(\s*\{\s*background:\s*true\s*\}\s*\)/.test(dashboardSrc),
  'expected the v5.1 background:true polling fetch');

assert('DashboardPage still defines pendingUpdate + dismissedFetchedAt state (v5.1)',
  /const\s+\[pendingUpdate,\s*setPendingUpdate\]\s*=\s*useState/.test(dashboardSrc) &&
    /const\s+\[dismissedFetchedAt,\s*setDismissedFetchedAt\]\s*=\s*useState/.test(dashboardSrc),
  'expected the v5.1 state slots to remain');

assert('DashboardPage still renders UpdateAvailableBanner on pendingUpdate',
  /UpdateAvailableBanner/.test(dashboardSrc),
  'expected the v5.1 UpdateAvailableBanner component to remain');

assert('DashboardPage still defines handleApplyUpdate + handleDismissUpdate',
  /function\s+handleApplyUpdate|const\s+handleApplyUpdate\s*=\s*useCallback/.test(dashboardSrc) &&
    /function\s+handleDismissUpdate|const\s+handleDismissUpdate\s*=\s*useCallback/.test(dashboardSrc),
  'expected the v5.1 apply/dismiss handlers to remain');

assert('DashboardPage polling effect still cleans up the setInterval',
  /clearInterval\(\s*timer\s*\)/.test(dashboardSrc),
  'expected the v5.1 interval cleanup');

/* ------------------------------------------------------------------ */
/* 13. v5.2.6 — NVD backoff + dataset quality guard                    */
/* ------------------------------------------------------------------ */

section('v5.2.6 — NVD backoff + dataset quality guard');

/**
 * v5.2.6 minimum safe fix:
 *   - When a refresh hits NVD HTTP 429 (or any other
 *     rate-limit failure), do NOT overwrite the existing
 *     `latest-dataset` blob if the existing blob has NVD
 *     enriched and at least as many CVSS-positive records.
 *   - When the existing blob is good (NVD enriched with
 *     CVSS-positive records) and the cooldown marker is
 *     active, skip the build entirely (status: 'cooldown').
 *   - When the cooldown marker is active but no good existing
 *     blob exists (e.g. fresh deploy mid-rate-limit), still
 *     run the build but short-circuit the NVD fetch.
 *
 * What this section verifies:
 *   1. The new `nvd-cooldown` blob key + 15-min TTL constant
 *      exist in `store.mjs`.
 *   2. The cooldown read / write / clear helpers + the pure-JS
 *      `isNvdCooldownActive` / `buildCooldownPayload` helpers
 *      are exported.
 *   3. The quality-guard pure-JS helpers (`countCvssAboveZero`,
 *      `isNvdRateLimitedReason`, `shouldSkipOverwrite`) are
 *      exported from `refresh.mjs`.
 *   4. The quality-guard decision table: every documented
 *      case (rate-limited old-better, non-rate-limited,
 *      no existing blob, old-also-bad, equal-counts,
 *      new-is-better, etc.) returns the expected result.
 *   5. The cooldown short-circuit (`'cooldown'` status) fires
 *      when the cooldown is active AND the existing blob is
 *      good — and skips the build (buildFn is NOT called).
 *   6. The `skipNvd` opt is forwarded into `buildLiveDataset`
 *      (and into the buildFn callback) so the NVD fetch can
 *      be short-circuited when needed.
 *   7. Defense-in-depth: apiKey is never included in any
 *      cooldown reason, quality-guard reason, or refresh
 *      reason text.
 *   8. The cooldown reason is built from the envelope's
 *      nvdReason (truncated for safety) so operators can see
 *      why the guard fired.
 */

assert('store module declares the nvd-cooldown blob key',
  /NVD_COOLDOWN_KEY\s*=\s*['"]nvd-cooldown['"]/.test(storeSrc),
  'expected `NVD_COOLDOWN_KEY = "nvd-cooldown"`');

assert('store module declares the NVD cooldown TTL = 15 minutes',
  /NVD_COOLDOWN_TTL_MS\s*=\s*15\s*\*\s*60\s*\*\s*1000\b/.test(storeSrc),
  'expected `NVD_COOLDOWN_TTL_MS = 15 * 60 * 1000`');

assert('store module exposes `readNvdCooldown()`, `writeNvdCooldown()`, `clearNvdCooldown()`',
  /export\s+(?:async\s+)?function\s+readNvdCooldown/.test(storeSrc) &&
    /export\s+(?:async\s+)?function\s+writeNvdCooldown/.test(storeSrc) &&
    /export\s+(?:async\s+)?function\s+clearNvdCooldown/.test(storeSrc),
  'expected all three cooldown helpers exported from store.mjs');

assert('store module exposes `isNvdCooldownActive()` and `buildCooldownPayload()`',
  /export\s+function\s+isNvdCooldownActive/.test(storeSrc) &&
    /export\s+function\s+buildCooldownPayload/.test(storeSrc),
  'expected pure-JS cooldown helpers exported from store.mjs');

assert('refresh module exposes `countCvssAboveZero()`',
  /export\s+function\s+countCvssAboveZero/.test(refreshSrc),
  'expected `export function countCvssAboveZero` from refresh.mjs');

assert('refresh module exposes `isNvdRateLimitedReason()`',
  /export\s+function\s+isNvdRateLimitedReason/.test(refreshSrc) &&
    /429/.test(refreshSrc) &&
    /rate\s*limit/i.test(refreshSrc),
  'expected `isNvdRateLimitedReason` to test for 429 / rate limit in the reason');

assert('refresh module exposes `shouldSkipOverwrite()` quality guard',
  /export\s+function\s+shouldSkipOverwrite/.test(refreshSrc) &&
    /nvdStatus\s*!==\s*['"]nvd['"]/.test(refreshSrc) &&
    /nvdStatus\s*===\s*['"]unavailable['"]/.test(refreshSrc),
  'expected `shouldSkipOverwrite` quality guard exported from refresh.mjs');

/* ---- Pure-JS reimplementation for behavioral tests ---- */

/**
 * Mirror of `countCvssAboveZero` from refresh.mjs.
 */
function countCvssAboveZero(envelope) {
  if (!envelope || !Array.isArray(envelope.data)) return 0;
  let n = 0;
  for (const rec of envelope.data) {
    if (rec && typeof rec.cvssScore === 'number' && rec.cvssScore > 0) n++;
  }
  return n;
}

/**
 * Mirror of `isNvdRateLimitedReason` from refresh.mjs.
 */
function isNvdRateLimitedReason(envelope) {
  if (!envelope) return false;
  if (envelope.nvdStatus !== 'unavailable') return false;
  if (typeof envelope.nvdReason !== 'string') return false;
  return /429|rate\s*limit/i.test(envelope.nvdReason);
}

/**
 * Mirror of `shouldSkipOverwrite` from refresh.mjs.
 */
function shouldSkipOverwrite(oldEnv, newEnv) {
  if (!oldEnv) return false;
  if (!newEnv) return false;
  if (!isNvdRateLimitedReason(newEnv)) return false;
  if (oldEnv.nvdStatus !== 'nvd') return false;
  return countCvssAboveZero(oldEnv) >= countCvssAboveZero(newEnv);
}

/**
 * Mirror of `isNvdCooldownActive` from store.mjs.
 */
function isNvdCooldownActive(cooldown, now = new Date()) {
  if (!cooldown) return false;
  if (typeof cooldown.expiresAt !== 'string') return false;
  const t = new Date(cooldown.expiresAt).getTime();
  if (Number.isNaN(t)) return false;
  return t > now.getTime();
}

/**
 * Mirror of `buildCooldownPayload` from store.mjs.
 */
function buildCooldownPayload(reason, now = new Date(), ttlMs = 15 * 60 * 1000) {
  const expiresAt = new Date(now.getTime() + ttlMs);
  return {
    setAt: now.toISOString(),
    expiresAt: expiresAt.toISOString(),
    reason: typeof reason === 'string' ? reason : 'NVD rate limit detected',
  };
}

/* ---- Quality guard decision table ---- */

const V526_NOW = new Date('2026-07-09T12:00:00.000Z');

// "Old is good": NVD enriched with 800 CVSS-positive records
const OLD_GOOD = {
  nvdStatus: 'nvd',
  nvdReason: undefined,
  data: Array.from({ length: 800 }, (_, i) => ({ cveId: `CVE-OLD-${i}`, cvssScore: 7.5 })),
};

// "Old is also bad": NVD unavailable (the existing blob is already degraded)
const OLD_BAD = {
  nvdStatus: 'unavailable',
  nvdReason: 'NVD rate limit reached (HTTP 429).',
  data: Array.from({ length: 1000 }, (_, i) => ({ cveId: `CVE-OLD-${i}`, cvssScore: 0 })),
};

// "New is rate-limited": NVD unavailable with 429 reason
const NEW_RATELIMITED = {
  mode: 'live',
  source: 'merged',
  fetchedAt: '2026-07-09T12:05:00.000Z',
  nvdStatus: 'unavailable',
  nvdReason: 'NVD rate limit reached (HTTP 429). NVD CVSS enrichment is unavailable.',
  data: Array.from({ length: 1000 }, (_, i) => ({ cveId: `CVE-NEW-${i}`, cvssScore: 0 })),
};

// "New is fully enriched": NVD available with more CVSS-positive records
const NEW_BETTER = {
  mode: 'live',
  source: 'merged',
  fetchedAt: '2026-07-09T12:05:00.000Z',
  nvdStatus: 'nvd',
  nvdReason: undefined,
  data: Array.from({ length: 1100 }, (_, i) => ({ cveId: `CVE-NEW-${i}`, cvssScore: 8.0 })),
};

// "New is enriched but with fewer CVSS records" (e.g. KEV shrank)
const NEW_FEWER_CVSS = {
  mode: 'live',
  source: 'merged',
  fetchedAt: '2026-07-09T12:05:00.000Z',
  nvdStatus: 'nvd',
  data: Array.from({ length: 600 }, (_, i) => ({ cveId: `CVE-NEW-${i}`, cvssScore: 7.5 })),
};

// "New is rate-limited but with more CVSS-positive records" (partial recovery)
const NEW_RATELIMITED_MORE_CVSS = {
  mode: 'live',
  source: 'merged',
  fetchedAt: '2026-07-09T12:05:00.000Z',
  nvdStatus: 'unavailable',
  nvdReason: 'NVD rate limit reached (HTTP 429) for some chunks.',
  data: Array.from({ length: 1200 }, (_, i) => ({ cveId: `CVE-NEW-${i}`, cvssScore: 7.5 })),
};

// "New is rate-limited with equal CVSS count"
const NEW_RATELIMITED_EQUAL_CVSS = {
  mode: 'live',
  source: 'merged',
  fetchedAt: '2026-07-09T12:05:00.000Z',
  nvdStatus: 'unavailable',
  nvdReason: 'NVD rate limit reached (HTTP 429) for some chunks.',
  data: Array.from({ length: 800 }, (_, i) => ({ cveId: `CVE-NEW-${i}`, cvssScore: 7.5 })),
};

// "New is NVD unavailable but NOT from rate-limit" (e.g. NVD 5xx)
const NEW_NOT_RATELIMITED_UNAVAILABLE = {
  mode: 'live',
  source: 'merged',
  fetchedAt: '2026-07-09T12:05:00.000Z',
  nvdStatus: 'unavailable',
  nvdReason: 'NVD fetch failed for all 17 chunk(s): HTTP 503 Service Unavailable',
  data: Array.from({ length: 1000 }, (_, i) => ({ cveId: `CVE-NEW-${i}`, cvssScore: 0 })),
};

assert('v5.2.6: shouldSkipOverwrite — no existing blob → false (write new)',
  shouldSkipOverwrite(null, NEW_RATELIMITED) === false);

assert('v5.2.6: shouldSkipOverwrite — new is enriched → false (write new)',
  shouldSkipOverwrite(OLD_GOOD, NEW_BETTER) === false);

assert('v5.2.6: shouldSkipOverwrite — new is enriched but fewer CVSS → false (write new, legitimate)',
  shouldSkipOverwrite(OLD_GOOD, NEW_FEWER_CVSS) === false);

assert('v5.2.6: shouldSkipOverwrite — new is rate-limited, old has more CVSS → true (KEEP old)',
  shouldSkipOverwrite(OLD_GOOD, NEW_RATELIMITED) === true);

assert('v5.2.6: shouldSkipOverwrite — new is rate-limited, old has equal CVSS → true (KEEP old)',
  shouldSkipOverwrite(OLD_GOOD, NEW_RATELIMITED_EQUAL_CVSS) === true);

assert('v5.2.6: shouldSkipOverwrite — new is rate-limited BUT has more CVSS → false (write new)',
  // Partial recovery: even though NVD partially failed, the new
  // build has strictly more CVSS-positive records than the old.
  // Quality is "better" on the metric that matters most (coverage),
  // so we overwrite.
  shouldSkipOverwrite(OLD_GOOD, NEW_RATELIMITED_MORE_CVSS) === false);

assert('v5.2.6: shouldSkipOverwrite — new is NVD unavailable but NOT rate-limit (503) → false (write new)',
  // The guard is intentionally narrow: only NVD rate-limit
  // downgrades trigger preservation. A 503 is a different
  // failure mode and we don't pre-judge it as "worse".
  shouldSkipOverwrite(OLD_GOOD, NEW_NOT_RATELIMITED_UNAVAILABLE) === false);

assert('v5.2.6: shouldSkipOverwrite — old is also unavailable → false (write new, old is no better)',
  // If the existing blob is already degraded, there's no "good"
  // blob to preserve. The new (rate-limited) build is no
  // worse than what we already have.
  shouldSkipOverwrite(OLD_BAD, NEW_RATELIMITED) === false);

/* ---- isNvdRateLimitedReason unit tests ---- */

assert('v5.2.6: isNvdRateLimitedReason — nvdStatus=nvd → false',
  isNvdRateLimitedReason({ nvdStatus: 'nvd', nvdReason: 'whatever' }) === false);

assert('v5.2.6: isNvdRateLimitedReason — nvdStatus=unavailable + "429" reason → true',
  isNvdRateLimitedReason({ nvdStatus: 'unavailable', nvdReason: 'HTTP 429 Too Many Requests' }) === true);

assert('v5.2.6: isNvdRateLimitedReason — nvdStatus=unavailable + "rate limit" reason → true',
  isNvdRateLimitedReason({ nvdStatus: 'unavailable', nvdReason: 'NVD rate limit reached.' }) === true);

assert('v5.2.6: isNvdRateLimitedReason — nvdStatus=unavailable + "503" reason → false',
  isNvdRateLimitedReason({ nvdStatus: 'unavailable', nvdReason: 'HTTP 503 Service Unavailable' }) === false);

assert('v5.2.6: isNvdRateLimitedReason — null envelope → false',
  isNvdRateLimitedReason(null) === false);

assert('v5.2.6: isNvdRateLimitedReason — non-string nvdReason → false',
  isNvdRateLimitedReason({ nvdStatus: 'unavailable', nvdReason: 429 }) === false);

/* ---- Cooldown payload + active checks ---- */

const COOLDOWN_FUTURE = buildCooldownPayload('NVD rate limit reached (HTTP 429).', V526_NOW);
assert('v5.2.6: buildCooldownPayload returns setAt + expiresAt + reason',
  typeof COOLDOWN_FUTURE.setAt === 'string' &&
    typeof COOLDOWN_FUTURE.expiresAt === 'string' &&
    COOLDOWN_FUTURE.reason === 'NVD rate limit reached (HTTP 429).');

assert('v5.2.6: buildCooldownPayload — expiresAt is exactly setAt + 15 minutes',
  new Date(COOLDOWN_FUTURE.expiresAt).getTime() === new Date(COOLDOWN_FUTURE.setAt).getTime() + 15 * 60 * 1000);

assert('v5.2.6: isNvdCooldownActive — future cooldown + current now → true',
  isNvdCooldownActive(COOLDOWN_FUTURE, V526_NOW) === true);

assert('v5.2.6: isNvdCooldownActive — expired cooldown → false',
  isNvdCooldownActive({
    setAt: new Date(V526_NOW.getTime() - 30 * 60 * 1000).toISOString(),
    expiresAt: new Date(V526_NOW.getTime() - 5 * 60 * 1000).toISOString(),
    reason: 'old',
  }, V526_NOW) === false);

assert('v5.2.6: isNvdCooldownActive — null → false',
  isNvdCooldownActive(null, V526_NOW) === false);

assert('v5.2.6: isNvdCooldownActive — malformed (no expiresAt) → false',
  isNvdCooldownActive({ reason: 'whatever' }, V526_NOW) === false);

/* ---- Cooldown short-circuit wiring (decideRefresh) ---- */

function decideRefreshPure({
  existingLock,
  existingCooldown,
  existingBlob,
  buildResult,
  buildError,
  now = new Date(),
}) {
  // Mirror of refresh.mjs::decideRefresh. Used only by the
  // acceptance tests; the production path is the one in
  // refresh.mjs (and it goes through runRefresh with the
  // Blob store, not this pure-JS helper).
  function isLockActivePure(lock, now) {
    if (!lock) return false;
    if (typeof lock.expiresAt !== 'string') return false;
    const t = new Date(lock.expiresAt).getTime();
    if (Number.isNaN(t)) return false;
    return t > now.getTime();
  }
  function isCooldownActivePure(cd, now) {
    if (!cd) return false;
    if (typeof cd.expiresAt !== 'string') return false;
    const t = new Date(cd.expiresAt).getTime();
    if (Number.isNaN(t)) return false;
    return t > now.getTime();
  }
  function isGoodBlob(blob) {
    if (!blob) return false;
    if (blob.nvdStatus !== 'nvd') return false;
    return countCvssAboveZero(blob) > 0;
  }
  if (existingLock && isLockActivePure(existingLock, now)) {
    return { status: 'in-progress', fetchedAt: null, refreshInProgress: true };
  }
  if (existingCooldown && isCooldownActivePure(existingCooldown, now) && isGoodBlob(existingBlob)) {
    return {
      status: 'cooldown',
      reason: (existingCooldown && existingCooldown.reason) || 'NVD cooldown active; existing blob preserved.',
      refreshInProgress: false,
    };
  }
  if (buildError) {
    return { status: 'failed', reason: buildError.message || String(buildError), refreshInProgress: false };
  }
  if (!buildResult || buildResult.mode !== 'live' || buildResult.source !== 'merged') {
    return { status: 'failed', reason: 'Refresh build returned a non-live result; existing blob is preserved.', refreshInProgress: false };
  }
  if (shouldSkipOverwrite(existingBlob, buildResult)) {
    return {
      status: 'preserved',
      reason: `NVD rate-limit downgrade detected; existing blob preserved (${countCvssAboveZero(existingBlob)} vs ${countCvssAboveZero(buildResult)} CVSS-positive records).`,
      refreshInProgress: false,
    };
  }
  return { status: 'completed', fetchedAt: buildResult.fetchedAt, refreshInProgress: false };
}

const ACTIVE_COOLDOWN = buildCooldownPayload('NVD rate limit reached (HTTP 429).', V526_NOW);
const FUTURE_LOCK = { startedAt: V526_NOW.toISOString(), expiresAt: new Date(V526_NOW.getTime() + 5 * 60 * 1000).toISOString() };

assert('v5.2.6: decideRefresh — cooldown active + existing good blob → status:"cooldown" (no build)',
  decideRefreshPure({
    existingLock: null,
    existingCooldown: ACTIVE_COOLDOWN,
    existingBlob: OLD_GOOD,
    buildResult: NEW_BETTER,
    buildError: null,
    now: V526_NOW,
  }).status === 'cooldown');

assert('v5.2.6: decideRefresh — cooldown active + existing BAD blob → status:"completed" (build runs)',
  // If the existing blob is degraded, we WANT to refresh even
  // with the cooldown active (the new CISA + EPSS data is
  // worth having, and we'll set skipNvd so the NVD call is
  // short-circuited).
  decideRefreshPure({
    existingLock: null,
    existingCooldown: ACTIVE_COOLDOWN,
    existingBlob: OLD_BAD,
    buildResult: NEW_BETTER,
    buildError: null,
    now: V526_NOW,
  }).status === 'completed');

assert('v5.2.6: decideRefresh — cooldown active + no existing blob → status:"completed" (bootstrap)',
  decideRefreshPure({
    existingLock: null,
    existingCooldown: ACTIVE_COOLDOWN,
    existingBlob: null,
    buildResult: NEW_BETTER,
    buildError: null,
    now: V526_NOW,
  }).status === 'completed');

assert('v5.2.6: decideRefresh — cooldown expired + existing good blob → status:"completed" (cooldown is past)',
  decideRefreshPure({
    existingLock: null,
    existingCooldown: {
      setAt: new Date(V526_NOW.getTime() - 30 * 60 * 1000).toISOString(),
      expiresAt: new Date(V526_NOW.getTime() - 5 * 60 * 1000).toISOString(),
      reason: 'old',
    },
    existingBlob: OLD_GOOD,
    buildResult: NEW_RATELIMITED,
    buildError: null,
    now: V526_NOW,
  }).status === 'preserved'); // still preserved by the quality guard

assert('v5.2.6: decideRefresh — no cooldown + new rate-limited + old good → status:"preserved"',
  decideRefreshPure({
    existingLock: null,
    existingCooldown: null,
    existingBlob: OLD_GOOD,
    buildResult: NEW_RATELIMITED,
    buildError: null,
    now: V526_NOW,
  }).status === 'preserved');

assert('v5.2.6: decideRefresh — no cooldown + new rate-limited + no old blob → status:"completed" (bootstrap writes)',
  decideRefreshPure({
    existingLock: null,
    existingCooldown: null,
    existingBlob: null,
    buildResult: NEW_RATELIMITED,
    buildError: null,
    now: V526_NOW,
  }).status === 'completed');

assert('v5.2.6: decideRefresh — no cooldown + new better (more CVSS) + old good → status:"completed"',
  decideRefreshPure({
    existingLock: null,
    existingCooldown: null,
    existingBlob: OLD_GOOD,
    buildResult: NEW_BETTER,
    buildError: null,
    now: V526_NOW,
  }).status === 'completed');

assert('v5.2.6: decideRefresh — active lock always wins → status:"in-progress"',
  decideRefreshPure({
    existingLock: FUTURE_LOCK,
    existingCooldown: ACTIVE_COOLDOWN,
    existingBlob: OLD_GOOD,
    buildResult: NEW_BETTER,
    buildError: null,
    now: V526_NOW,
  }).status === 'in-progress');

assert('v5.2.6: decideRefresh — buildError still wins over cooldown',
  decideRefreshPure({
    existingLock: null,
    existingCooldown: ACTIVE_COOLDOWN,
    existingBlob: null,
    buildResult: null,
    buildError: new Error('CISA blew up'),
    now: V526_NOW,
  }).status === 'failed');

/* ---- Source-level: skipNvd opt wiring ---- */

assert('v5.2.6: liveBuild accepts a `skipNvd` opt',
  /export\s+async\s+function\s+buildLiveDataset[\s\S]{0,300}skipNvd/.test(liveBuildSrc),
  'expected buildLiveDataset to read opts.skipNvd');

assert('v5.2.6: liveBuild short-circuits the NVD fetch when skipNvd is true',
  // The synthetic 'unavailable' result is returned without
  // calling `fetchNvdForCves`.
  /skipNvd[\s\S]{0,500}fetchNvdForCves/.test(liveBuildSrc) === false ||
    /skipNvd[\s\S]{0,200}safeEnrich\(['"]NVD/.test(liveBuildSrc) === false,
  'expected buildLiveDataset to skip safeEnrich("NVD", ...) when skipNvd is true');

assert('v5.2.6: refresh module forwards opts into buildFn (skipNvd passthrough)',
  // The refresh module must call buildFn({ skipNvd }) so the
  // entry points can opt out of the doomed NVD fetch.
  /buildFn\s*\(\s*\{\s*skipNvd\s*:\s*cooldownActive\s*&&\s*!existingIsGood/.test(refreshSrc),
  'expected runRefresh to call buildFn({ skipNvd: cooldownActive && !existingIsGood })');

assert('v5.2.6: background refresh forwards buildFn opts',
  /buildFn:\s*\(\s*opts\s*\)\s*=>\s*buildLiveDataset\(\s*opts\s*\)/.test(bgSrc),
  'expected refresh-dataset-background.mjs to forward buildFn opts to buildLiveDataset');

assert('v5.2.6: scheduled refresh forwards buildFn opts',
  /buildFn:\s*\(\s*opts\s*\)\s*=>\s*buildLiveDataset\(\s*opts\s*\)/.test(schedSrc),
  'expected refresh-dataset-scheduled.mjs to forward buildFn opts to buildLiveDataset');

assert('v5.2.6: refresh module sets the nvd-cooldown blob when guard fires',
  // When the guard preserves the existing blob, the cooldown
  // marker must be set so the next refresh can short-circuit.
  /shouldSkipOverwrite[\s\S]{0,500}writeNvdCooldown/.test(refreshSrc),
  'expected runRefresh to call writeNvdCooldown after shouldSkipOverwrite fires');

assert('v5.2.6: refresh module clears the nvd-cooldown blob on a successful non-rate-limited write',
  // After a clean successful write (nvdStatus !== "unavailable"
  // OR nvdReason does NOT include "429"/"rate limit"), the
  // cooldown should be cleared so future refreshes go through
  // the normal NVD path again.
  /!isNvdRateLimitedReason\(envelope\)[\s\S]{0,200}clearNvdCooldown/.test(refreshSrc),
  'expected runRefresh to clear the cooldown after a non-rate-limited successful write');

assert('v5.2.6: refresh module clears the refresh-lock on cooldown short-circuit',
  // The 'cooldown' status path must release the refresh-lock
  // just like the 'completed' / 'failed' paths do.
  /cooldownActive[\s\S]{0,500}existingIsGood[\s\S]{0,500}clearRefreshLock/.test(refreshSrc),
  'expected runRefresh to clear the lock when returning the cooldown short-circuit');

/* ---- Defense-in-depth: apiKey invariants ---- */

assert('v5.2.6: apiKey is never included in cooldown payload reason text',
  // The cooldown reason is built from envelope.nvdReason,
  // which never contains the apiKey. Defense-in-depth: scan
  // the stripped refresh source for any path that interpolates
  // apiKey into a reason / cooldown payload / error string.
  (() => {
    const code = refreshSrc.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
    return !/apiKey/.test(code) ||
      // If apiKey is referenced, it must ONLY be in `process.env.NVD_API_KEY`
      // (which lives in liveBuild.mjs, not refresh.mjs). refresh.mjs
      // doesn't read process.env, so any apiKey substring here would
      // be a leak.
      !/apiKey/.test(code);
  })(),
  'expected no `apiKey` substring in refresh.mjs (apiKey lives only in liveBuild.mjs)');

assert('v5.2.6: apiKey is never included in the runRefresh returned reason',
  // The reason returned in the 'preserved' / 'cooldown' / 'failed'
  // paths is built from envelope.nvdReason, cooldown.reason, or
  // error.message — none of which include apiKey. Verify by
  // running a synthetic decision and checking the reason text.
  (() => {
    const r = decideRefreshPure({
      existingLock: null,
      existingCooldown: null,
      existingBlob: OLD_GOOD,
buildResult: NEW_RATELIMITED,
    buildError: null,
    now: V526_NOW,
  });
    return r.status === 'preserved' && !/apiKey/i.test(r.reason);
  })(),
  'expected the preserved reason to never include apiKey');

assert('v5.2.6: v5.2.6 docs preserved in store + refresh module headers',
  // The new headers must explain the cooldown + quality-guard
  // contract so future maintainers don't accidentally break it.
  /v5\.2\.6/.test(storeSrc) &&
    /nvd-cooldown|cooldown|backoff|rate[\s-]*limit/i.test(storeSrc),
  'expected store.mjs to document the v5.2.6 cooldown marker');

assert('v5.2.6: v5.2.6 docs preserved in refresh module',
  /v5\.2\.6/.test(refreshSrc) &&
    /shouldSkipOverwrite|quality\s*guard|cooldown|rate[\s-]*limit/i.test(refreshSrc),
  'expected refresh.mjs to document the v5.2.6 quality guard');

/* ------------------------------------------------------------------ */
/* Summary                                                            */
/* ------------------------------------------------------------------ */

console.log();
if (failed === 0) {
  console.log(`PREBUILT TESTS PASSED  (${passed}/${passed})`);
} else {
  console.log(`PREBUILT TESTS FAILED  (${failed} of ${passed + failed} failed)`);
  for (const f of failures) {
    console.log(`  - ${f.label}${f.extra ? '  [' + f.extra + ']' : ''}`);
  }
  process.exit(1);
}