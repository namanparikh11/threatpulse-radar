// V6.0 — Scheduler + background refresh behavior tests.
//
//   node scripts/acceptance-scheduler.mjs
//
// Behavior under test:
//   - triggerAuth.validateTriggerSecret: matching secret accepted
//   - triggerAuth.validateTriggerSecret: mismatched secret rejected
//   - triggerAuth.validateTriggerSecret: empty inputs rejected
//   - triggerAuth.validateTriggerSecret: non-string inputs rejected
//   - triggerAuth.validateTriggerSecret: short secret and long secret
//     produce the same length after SHA-256 (no early-return side
//     channel on the wrong-length path)
//   - triggerAuth.getTriggerSecretFromEnv: returns null when unset
//   - triggerAuth.getTriggerSecretFromEnv: returns the secret when set
//   - triggerAuth: constants are exported and well-formed
//   - refresh-baseline-background: 500 when secret is not configured
//   - refresh-baseline-background: 401 when no header is provided
//   - refresh-baseline-background: 401 when header is wrong
//   - refresh-baseline-background: 500 when store resolution fails
//   - refresh-baseline-background: 202 on success, summary populated
//   - refresh-baseline-background: orchestrator loop continues when
//     done: false
//   - refresh-baseline-background: orchestrator loop exits on done: true
//   - refresh-baseline-background: wall-clock cap is respected
//   - refresh-baseline-background: orchestrator exception → 500
//   - refresh-baseline-background: secret is never included in the
//     response body (no accidental echo)
//   - V6.0 invariant: visitors cannot trigger refresh (any auth
//     failure returns 401, never 200)
//
// The handler file is plain ESM (.mjs) and Node resolves it
// directly. We do NOT compile it via tsc — tsc keeps the .mjs
// extension, and ESM .mjs is what Netlify ships. We import the
// handler with an absolute file:// URL.

import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync, rmSync, readdirSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const buildDir = join(here, '.v6-build-scheduler');

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
    console.log(`  \u2717 ${label}  -- ${extra}`);
  }
}

function section(title) {
  console.log(`\n--- ${title} ---`);
}

/* ------------------------------------------------------------------ */
/* Build the V6.0 _shared sources so we can import triggerAuth         */
/* ------------------------------------------------------------------ */

function buildV6Shared() {
  if (existsSync(buildDir)) {
    try { rmSync(buildDir, { recursive: true, force: true }); } catch (e) { /* fall through */ }
  }
  mkdirSync(buildDir, { recursive: true });
  const tscJs = join(root, 'node_modules', 'typescript', 'lib', 'tsc.js');
  const sources = [
    'netlify/functions/_shared/triggerAuth.mjs',
  ];
  // The .mjs extension is critical here: tsc preserves the input
  // extension when --allowJs is set. We need to import the
  // .mjs file as ESM (not as a CommonJS .js). The file is then
  // importable from the test via its absolute path.
  execFileSync(
    process.execPath,
    [tscJs, ...sources, '--outDir', buildDir.replace(/\\/g, '/'), '--rootDir', '.',
     '--module', 'esnext', '--target', 'es2022', '--moduleResolution', 'node',
     '--skipLibCheck', '--allowJs', '--declaration', 'false'],
    { cwd: root, stdio: 'pipe' }
  );
}

buildV6Shared();

const buildLeaf = buildDir.split(/[\\/]/).pop();
const triggerAuth = await import(`./${buildLeaf}/netlify/functions/_shared/triggerAuth.mjs`);
const {
  TRIGGER_HEADER, REFRESH_BACKGROUND_PATH, TRIGGER_SECRET_ENV_VAR,
  validateTriggerSecret, getTriggerSecretFromEnv,
} = triggerAuth;

// Import the handler directly from source. Netlify's bundler
// inlines all relative imports; for the test we just rely on
// Node's native ESM resolution.
const handlerMod = await import(pathToFileURL(join(root, 'netlify', 'functions', 'refresh-baseline-background.mjs')).href);
const { handleRefreshBaselineBackground } = handlerMod;

/* ------------------------------------------------------------------ */
/* Tests: triggerAuth constants                                        */
/* ------------------------------------------------------------------ */

section('triggerAuth: constants are exported and well-formed');

{
  assert('TRIGGER_HEADER is exported', typeof TRIGGER_HEADER === 'string' && TRIGGER_HEADER.length > 0);
  assert('TRIGGER_HEADER is lowercased (HTTP headers are case-insensitive)',
    TRIGGER_HEADER === TRIGGER_HEADER.toLowerCase());
  assert('REFRESH_BACKGROUND_PATH is exported',
    typeof REFRESH_BACKGROUND_PATH === 'string' && REFRESH_BACKGROUND_PATH.length > 0);
  assert('TRIGGER_SECRET_ENV_VAR is the documented name',
    TRIGGER_SECRET_ENV_VAR === 'THREATPULSE_REFRESH_TRIGGER_SECRET');
}

/* ------------------------------------------------------------------ */
/* Tests: triggerAuth.validateTriggerSecret                            */
/* ------------------------------------------------------------------ */

section('validateTriggerSecret: matching secret accepted');

{
  assert('matching secret returns true', validateTriggerSecret('s3cret', 's3cret'));
  assert('matching long secret returns true', validateTriggerSecret('a'.repeat(100), 'a'.repeat(100)));
}

section('validateTriggerSecret: mismatched secret rejected');

{
  assert('different secrets return false', !validateTriggerSecret('s3cret', 's3cret!'));
  assert('different-case secrets return false', !validateTriggerSecret('S3cret', 's3cret'));
}

section('validateTriggerSecret: empty inputs rejected');

{
  assert('empty provided rejected', !validateTriggerSecret('', 's3cret'));
  assert('empty expected rejected', !validateTriggerSecret('s3cret', ''));
  assert('both empty rejected', !validateTriggerSecret('', ''));
}

section('validateTriggerSecret: non-string inputs rejected');

{
  assert('null provided rejected', !validateTriggerSecret(null, 's3cret'));
  assert('null expected rejected', !validateTriggerSecret('s3cret', null));
  assert('undefined provided rejected', !validateTriggerSecret(undefined, 's3cret'));
  assert('number provided rejected', !validateTriggerSecret(123, 's3cret'));
  assert('object provided rejected', !validateTriggerSecret({}, 's3cret'));
}

section('validateTriggerSecret: short vs long secret — same-length hash path');

{
  assert('short provided, long expected → false (length mismatch)',
    !validateTriggerSecret('x', 'a'.repeat(64)));
  assert('long provided, short expected → false (length mismatch)',
    !validateTriggerSecret('a'.repeat(64), 'x'));
  assert('same-length strings with different content → false',
    !validateTriggerSecret('a'.repeat(32), 'b'.repeat(32)));
}

/* ------------------------------------------------------------------ */
/* Tests: triggerAuth.getTriggerSecretFromEnv                          */
/* ------------------------------------------------------------------ */

section('getTriggerSecretFromEnv: returns null when unset');

{
  const v = getTriggerSecretFromEnv({});
  assert('unset env → null', v === null);
}

section('getTriggerSecretFromEnv: returns the secret when set');

{
  const v = getTriggerSecretFromEnv({ [TRIGGER_SECRET_ENV_VAR]: 'my-secret' });
  assert('set env → secret', v === 'my-secret');
}

section('getTriggerSecretFromEnv: empty string treated as unset');

{
  const v = getTriggerSecretFromEnv({ [TRIGGER_SECRET_ENV_VAR]: '' });
  assert('empty env → null', v === null);
}

/* ------------------------------------------------------------------ */
/* Tests: refresh-baseline-background handler                          */
/* ------------------------------------------------------------------ */

// Stub request factory
function makeRequest(headers) {
  return {
    headers: {
      get: (name) => {
        if (typeof name !== 'string') return null;
        const target = name.toLowerCase();
        for (const k of Object.keys(headers)) {
          if (k.toLowerCase() === target) return headers[k];
        }
        return null;
      },
    },
  };
}

section('Background handler: 500 when secret is not configured');

{
  const resp = await handleRefreshBaselineBackground({
    request: makeRequest({}),
    expectedSecret: null,
    resolveStore: () => null,
    runOrchestrator: async () => ({}),
  });
  assert('returns 500', resp.status === 500);
  const body = await resp.json();
  assert('body mentions trigger secret not configured',
    /not configured/i.test(body.reason || ''));
}

section('Background handler: 401 when no header is provided');

{
  const resp = await handleRefreshBaselineBackground({
    request: makeRequest({}),
    expectedSecret: 's3cret',
    resolveStore: () => null,
    runOrchestrator: async () => ({}),
  });
  assert('returns 401', resp.status === 401);
  const body = await resp.json();
  assert('body status is unauthorized', body.status === 'unauthorized');
  const text = JSON.stringify(body);
  assert('body does not contain the secret', !text.includes('s3cret'));
}

section('Background handler: 401 when header is wrong');

{
  const resp = await handleRefreshBaselineBackground({
    request: makeRequest({ [TRIGGER_HEADER]: 'wrong-secret' }),
    expectedSecret: 's3cret',
    resolveStore: () => null,
    runOrchestrator: async () => ({}),
  });
  assert('returns 401', resp.status === 401);
  const body = await resp.json();
  assert('body status is unauthorized', body.status === 'unauthorized');
}

section('Background handler: 500 when store resolution fails');

{
  const resp = await handleRefreshBaselineBackground({
    request: makeRequest({ [TRIGGER_HEADER]: 's3cret' }),
    expectedSecret: 's3cret',
    resolveStore: () => { throw new Error('blob context missing'); },
    runOrchestrator: async () => ({}),
  });
  assert('returns 500', resp.status === 500);
  const body = await resp.json();
  assert('body mentions store', /store/i.test(body.reason || ''));
}

section('Background handler: 202 on success, summary populated');

{
  const fakeStore = { _marker: 'fake' };
  const resp = await handleRefreshBaselineBackground({
    request: makeRequest({ [TRIGGER_HEADER]: 's3cret' }),
    expectedSecret: 's3cret',
    resolveStore: () => fakeStore,
    runOrchestrator: async () => ({
      status: 'ok',
      done: true,
      published: true,
      recordsProcessed: 5,
      manifest: {
        baselineVersion: '2026-07-12T20-30-00Z-12345678',
        previousVersion: null,
        publishedAt: '2026-07-12T20:30:00.000Z',
        canonicalContentHash: 'sha256:' + 'a'.repeat(64),
        stats: { totalRecords: 5 },
      },
      errors: [],
    }),
    gzipFn: async (b) => b,
  });
  assert('returns 202', resp.status === 202);
  const body = await resp.json();
  assert('body status is ok', body.status === 'ok');
  assert('body iterations is 1', body.iterations === 1);
  assert('body totalProcessed is 5', body.totalProcessed === 5);
  assert('body publishedCount is 1', body.publishedCount === 1);
  assert('body manifest.baselineVersion is set', body.manifest.baselineVersion === '2026-07-12T20-30-00Z-12345678');
  assert('body secret is not echoed', !JSON.stringify(body).includes('s3cret'));
}

section('Background handler: orchestrator loop continues when done: false');

{
  let callCount = 0;
  const fakeStore = { _marker: 'fake' };
  const resp = await handleRefreshBaselineBackground({
    request: makeRequest({ [TRIGGER_HEADER]: 's3cret' }),
    expectedSecret: 's3cret',
    resolveStore: () => fakeStore,
    runOrchestrator: async () => {
      callCount++;
      if (callCount < 3) {
        return { status: 'ok', done: false, published: false, recordsProcessed: 2, errors: [] };
      }
      return { status: 'ok', done: true, published: true, recordsProcessed: 1, manifest: null, errors: [] };
    },
    gzipFn: async (b) => b,
    maxWallMs: 60000,
  });
  assert('orchestrator was called 3 times', callCount === 3);
  const body = await resp.json();
  assert('body iterations is 3', body.iterations === 3);
  assert('body totalProcessed is 5 (2+2+1)', body.totalProcessed === 5);
  assert('body publishedCount is 1', body.publishedCount === 1);
}

section('Background handler: wall-clock cap is respected');

{
  let nowCount = 0;
  const fakeStore = { _marker: 'fake' };
  let callCount = 0;
  const resp = await handleRefreshBaselineBackground({
    request: makeRequest({ [TRIGGER_HEADER]: 's3cret' }),
    expectedSecret: 's3cret',
    resolveStore: () => fakeStore,
    runOrchestrator: async () => {
      callCount++;
      return { status: 'ok', done: false, published: false, recordsProcessed: 0, errors: [] };
    },
    gzipFn: async (b) => b,
    maxWallMs: 3,
    now: () => { nowCount++; return nowCount; },
  });
  assert('wall-clock cap stopped the loop', callCount < 1000, 'called ' + callCount);
  assert('response is 202 (loop exited via cap, not via done)', resp.status === 202);
}

section('Background handler: orchestrator exception → 500');

{
  const fakeStore = { _marker: 'fake' };
  const resp = await handleRefreshBaselineBackground({
    request: makeRequest({ [TRIGGER_HEADER]: 's3cret' }),
    expectedSecret: 's3cret',
    resolveStore: () => fakeStore,
    runOrchestrator: async () => { throw new Error('orchestrator boom'); },
    gzipFn: async (b) => b,
  });
  assert('returns 500 on orchestrator throw', resp.status === 500);
  const body = await resp.json();
  assert('body mentions orchestrator', /orchestrator/i.test(body.reason || ''));
}

section('V6.0 invariant: visitors cannot trigger refresh');

{
  const visitorRequests = [
    makeRequest({}),
    makeRequest({ [TRIGGER_HEADER]: '' }),
    makeRequest({ [TRIGGER_HEADER]: 'guess' }),
    makeRequest({ 'X-Trigger-Secret': 'guess' }),
  ];
  for (const req of visitorRequests) {
    const resp = await handleRefreshBaselineBackground({
      request: req,
      expectedSecret: 's3cret',
      resolveStore: () => { throw new Error('should not reach store'); },
      runOrchestrator: async () => { throw new Error('should not reach orchestrator'); },
    });
    assert(`visitor request returns 401 (status=${resp.status})`, resp.status === 401);
  }
}

console.log();
console.log(`Total: ${passed} passed, ${failed} failed`);

if (failed > 0) {
  console.log('\nFailures:');
  for (const f of failures) {
    console.log(`  - ${f.label}  -- ${f.extra}`);
  }
  process.exit(1);
}
console.log('ALL SCHEDULER TESTS PASSED');
