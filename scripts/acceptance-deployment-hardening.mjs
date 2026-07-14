#!/usr/bin/env node
// V6.0 — Deployment hardening acceptance suite.
//
//   node scripts/acceptance-deployment-hardening.mjs
//
// Behavior under test (regression guards for the B1 / G1 / G2
// / G3 / G4 fixes from the post-merge deployment audit):
//
//   - Gateway subtree exists with the right shape:
//     * netlify/gateway/netlify.toml declares the right build /
//       publish / functions values and does NOT run the Vite
//       build or publish `dist`.
//     * netlify/gateway/package.json declares ONLY @netlify/blobs.
//     * netlify/gateway/site/ exists as the publish placeholder.
//   - The gateway's functions-staging/ directory (recreated by
//     scripts/copy-gateway-files.mjs) contains ONLY the gateway
//     function and the two shared modules it needs. It does NOT
//     contain any of the V5.x / V6.0-publisher functions.
//   - The staging script exits 0 and produces the expected files.
//   - The gateway function still exports the correct `config`:
//     * path = '/private/v1/*'
//     * rateLimit = { windowLimit: 200, windowSize: 60 }
//     * NO `aggregateBy` field (the previous silently-ignored
//       custom field is removed).
//   - Path-traversal attempts in `version`, `from`, `to` are
//     rejected with 400 (`bad-request`), not allowed through to
//     the Blob store read.
//   - The background function's misleading doc comment is gone:
//     the function must NOT claim to live on the private gateway.
//   - The public-site netlify.toml has the V6.0 topology comment
//     block at the top.
//   - No `VITE_*` secret env vars are introduced in any new file.
//   - The root `.gitignore` excludes the gateway staging dir.
//   - scripts/acceptance-private-gateway.mjs still passes (we
//     re-run a smoke test to ensure the new version validation
//     did not break the existing test surface).
//
// Total assertions: a fixed number (printed at end of run).

import { execFileSync, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, rmSync, statSync, writeFileSync, readdirSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join, resolve, relative } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..');
const gatewayDir = join(root, 'netlify', 'gateway');
const stagingDir = join(gatewayDir, 'functions-staging', 'functions');
const publicSrcFn = join(root, 'netlify', 'functions');

let passed = 0;
let failed = 0;
const failures = [];

function assert(label, condition, extra = '') {
  if (condition) {
    passed++;
    console.log(`  PASS  ${label}`);
  } else {
    failed++;
    failures.push({ label, extra });
    console.log(`  FAIL  ${label}${extra ? `  -- ${extra}` : ''}`);
  }
}

function readText(p) {
  return readFileSync(p, 'utf8');
}

/**
 * Strip `# ...` line comments from a TOML file. TOML does not
 * support block comments, so a line-by-line strip is correct.
 * The function returns the comment-stripped contents; blank
 * lines and structure are preserved.
 */
function stripTomlComments(src) {
  return src
    .split(/\r?\n/)
    .map((line) => {
      // Find the first unquoted `#`. Per TOML spec, `#` only
      // starts a comment when it's outside a string. We use a
      // simple heuristic: if the line so far has an odd number
      // of unescaped `"` characters, we're inside a string and
      // should not strip.
      let inString = false;
      let escape = false;
      for (let i = 0; i < line.length; i++) {
        const c = line[i];
        if (escape) { escape = false; continue; }
        if (c === '\\') { escape = true; continue; }
        if (c === '"') { inString = !inString; continue; }
        if (c === '#' && !inString) {
          return line.slice(0, i);
        }
      }
      return line;
    })
    .join('\n');
}

function listFiles(dir) {
  if (!existsSync(dir)) return [];
  const out = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      out.push(...listFiles(full).map((f) => normalizePath(relative(dir, join(full, f)))));
    } else {
      out.push(normalizePath(relative(dir, full)));
    }
  }
  return out.sort();
}

/** Normalize a relative path to forward slashes (so the
 *  acceptance suite is portable across Windows and POSIX). */
function normalizePath(p) {
  return String(p).split(/[\\/]+/).join('/');
}

console.log('V6.0 — deployment hardening acceptance suite');
console.log('============================================');
console.log('');

/* --------------------------------------------------------------- */
/* 1. Gateway subtree shape                                         */
/* --------------------------------------------------------------- */
console.log('[1] Gateway subtree shape');

assert('netlify/gateway/netlify.toml exists',
  existsSync(join(gatewayDir, 'netlify.toml')));

assert('netlify/gateway/package.json exists',
  existsSync(join(gatewayDir, 'package.json')));

assert('netlify/gateway/site/ exists (publish placeholder)',
  existsSync(join(gatewayDir, 'site')));

assert('netlify/gateway/site/.gitkeep exists',
  existsSync(join(gatewayDir, 'site', '.gitkeep')));

assert('gateway subtree does NOT contain functions/ directly (must stage via script)',
  !existsSync(join(gatewayDir, 'functions')));

/* --------------------------------------------------------------- */
/* 2. gateway netlify.toml: correct build/publish/functions values */
/* --------------------------------------------------------------- */
console.log('');
console.log('[2] netlify/gateway/netlify.toml configuration');

if (existsSync(join(gatewayDir, 'netlify.toml'))) {
  const gwToml = stripTomlComments(readText(join(gatewayDir, 'netlify.toml')));

  // command: runs the staging script, not the Vite build.
  assert('gateway netlify.toml runs the staging script as the build command',
    /command\s*=\s*"node \.\.\/\.\.\/scripts\/copy-gateway-files\.mjs"/i.test(gwToml),
    'expected the build command to invoke scripts/copy-gateway-files.mjs');

  // publish: site (the empty placeholder), NOT dist.
  assert('gateway netlify.toml publish = "site" (the empty placeholder)',
    /publish\s*=\s*"site"/.test(gwToml));

  assert('gateway netlify.toml does NOT publish "dist"',
    !/publish\s*=\s*"dist"/.test(gwToml));

  // functions: the staging directory, not the source-of-truth dir.
  assert('gateway netlify.toml functions = "functions-staging/functions"',
    /functions\s*=\s*"functions-staging\/functions"/.test(gwToml));

  // bundler: esbuild, matching the public site.
  assert('gateway netlify.toml sets node_bundler = "esbuild"',
    /node_bundler\s*=\s*"esbuild"/.test(gwToml));

  // No Vite build reference.
  assert('gateway netlify.toml does NOT reference npm run build (no Vite build here)',
    !/npm run build/.test(gwToml));
}

/* --------------------------------------------------------------- */
/* 3. gateway package.json: minimal, correct dep                   */
/* --------------------------------------------------------------- */
console.log('');
console.log('[3] netlify/gateway/package.json');

if (existsSync(join(gatewayDir, 'package.json'))) {
  let gwPkg;
  try { gwPkg = JSON.parse(readText(join(gatewayDir, 'package.json'))); }
  catch (err) { gwPkg = null; assert('gateway package.json is valid JSON', false, err.message); }

  if (gwPkg) {
    assert('gateway package.json declares type: module',
      gwPkg.type === 'module');
    assert('gateway package.json declares @netlify/blobs dependency',
      typeof gwPkg.dependencies === 'object'
      && typeof gwPkg.dependencies['@netlify/blobs'] === 'string');
    const deps = Object.keys(gwPkg.dependencies || {});
    assert('gateway package.json has no extraneous runtime dependencies',
      deps.length === 1 && deps[0] === '@netlify/blobs',
      `found: [${deps.join(', ')}]`);
  }
}

/* --------------------------------------------------------------- */
/* 4. Staging script: runs cleanly and produces the right surface  */
/* --------------------------------------------------------------- */
console.log('');
console.log('[4] scripts/copy-gateway-files.mjs staging behavior');

const scriptPath = join(root, 'scripts', 'copy-gateway-files.mjs');
assert('scripts/copy-gateway-files.mjs exists',
  existsSync(scriptPath));

if (existsSync(scriptPath)) {
  // Run the staging script and capture exit code.
  const runResult = spawnSync(process.execPath, [scriptPath], { encoding: 'utf8' });
  assert('staging script exits 0',
    runResult.status === 0,
    `status=${runResult.status} stderr=${(runResult.stderr || '').split('\n').slice(0, 3).join(' | ')}`);

  assert('staging directory exists after script run',
    existsSync(stagingDir));

  if (existsSync(stagingDir)) {
    const staged = listFiles(stagingDir);
    const expected = [
      '_shared/baselineStore.mjs',
      '_shared/credentials.mjs',
      'private-sync-gateway.mjs',
    ];
    assert('staged surface contains exactly the 3 expected files',
      JSON.stringify(staged) === JSON.stringify(expected),
      `got: [${staged.join(', ')}]`);

    // The staged files must NOT include any of the public-site
    // functions (regression guard for B1).
    const forbidden = [
      'dataset.mjs',
      'refresh-dataset-background.mjs',
      'refresh-dataset-scheduled.mjs',
      'refresh-baseline-scheduled.mjs',
      'refresh-baseline-background.mjs',
    ];
    for (const f of forbidden) {
      assert(`staged surface does NOT contain ${f}`,
        !staged.includes(f));
    }
  }

  // Idempotence: re-run the script and confirm the surface is
  // still exactly the 3 files (no stale leftover from a previous
  // larger run).
  const reRun = spawnSync(process.execPath, [scriptPath], { encoding: 'utf8' });
  assert('staging script is idempotent (re-run still exits 0)',
    reRun.status === 0,
    `status=${reRun.status}`);
  if (existsSync(stagingDir)) {
    const staged = listFiles(stagingDir);
    assert('staging surface is identical after second run',
      JSON.stringify(staged) === JSON.stringify([
        '_shared/baselineStore.mjs',
        '_shared/credentials.mjs',
        'private-sync-gateway.mjs',
      ]),
      `got: [${staged.join(', ')}]`);
  }
}

/* --------------------------------------------------------------- */
/* 5. Source-of-truth gateway function: G2 / G3 / G4 fixes        */
/* --------------------------------------------------------------- */
console.log('');
console.log('[5] netlify/gateway/src/private-sync-gateway.mjs hardening');

const gatewayFnPath = join(gatewayDir, 'src', 'private-sync-gateway.mjs');
assert('source-of-truth gateway function exists at netlify/gateway/src/',
  existsSync(gatewayFnPath));

// V6.0 deployment-hardening topology: the public site's
// netlify/functions/ directory MUST NOT contain the gateway
// function. The gateway function source-of-truth lives in the
// gateway subtree.
const publicSiteGatewayFn = join(publicSrcFn, 'private-sync-gateway.mjs');
assert('public site netlify/functions/ does NOT contain private-sync-gateway.mjs',
  !existsSync(publicSiteGatewayFn),
  'public site should not deploy the gateway function');

// The public site MUST NOT contain the credentials helper either.
const publicSiteCredentialsFn = join(publicSrcFn, '_shared', 'credentials.mjs');
assert('public site netlify/functions/_shared/ does NOT contain credentials.mjs',
  !existsSync(publicSiteCredentialsFn),
  'public site should not deploy the credentials helper');

// The public site must contain EXACTLY 5 function entry
// files. Shared modules in netlify/functions/_shared/ are
// NOT function entry points. The 5 are:
//
//   HTTP:
//     - dataset.mjs
//   Scheduled:
//     - refresh-dataset-scheduled.mjs
//     - refresh-baseline-scheduled.mjs
//   Background:
//     - refresh-dataset-background.mjs
//     - refresh-baseline-background.mjs
const publicEntryFiles = readdirSync(publicSrcFn, { withFileTypes: true })
  .filter((e) => e.isFile() && e.name.endsWith('.mjs'))
  .map((e) => e.name)
  .sort();
const expectedPublicEntries = [
  'dataset.mjs',
  'refresh-baseline-background.mjs',
  'refresh-baseline-scheduled.mjs',
  'refresh-dataset-background.mjs',
  'refresh-dataset-scheduled.mjs',
];
assert('public site has exactly 5 function entry files (1 HTTP + 2 Scheduled + 2 Background)',
  JSON.stringify(publicEntryFiles) === JSON.stringify(expectedPublicEntries),
  `got: [${publicEntryFiles.join(', ')}], expected: [${expectedPublicEntries.join(', ')}]`);

// Gateway staging must contain exactly 1 function entry file.
if (existsSync(stagingDir)) {
  const stagedEntryFiles = readdirSync(stagingDir, { withFileTypes: true })
    .filter((e) => e.isFile() && e.name.endsWith('.mjs'))
    .map((e) => e.name)
    .sort();
  assert('gateway staging has exactly 1 function entry file (private-sync-gateway.mjs)',
    JSON.stringify(stagedEntryFiles) === JSON.stringify(['private-sync-gateway.mjs']),
    `got: [${stagedEntryFiles.join(', ')}]`);
}

if (existsSync(gatewayFnPath)) {
  const src = readText(gatewayFnPath);

  // Strip JS block comments so the G2 check does not match the
  // explanatory comment that mentions the removed
  // `aggregateBy` field.
  const codeOnly = src
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/^\s*\/\/.*$/gm, '');

  // G2: aggregateBy removed from the actual config object.
  assert('G2: aggregateBy field is removed from rateLimit config (code only)',
    !/aggregateBy\s*:/.test(codeOnly));

  assert('G2: rateLimit still has windowLimit = 200 and windowSize = 60',
    /windowLimit\s*:\s*200/.test(codeOnly) && /windowSize\s*:\s*60/.test(codeOnly));

  // G3 + G4: version validation.
  assert('G3/G4: VERSION_PATTERN defined',
    /const\s+VERSION_PATTERN\s*=\s*\/\^\[A-Za-z0-9\._-\]\{1,128\}\$\//.test(codeOnly));

  assert('G3/G4: isValidVersionString helper defined',
    /function\s+isValidVersionString\s*\(/.test(codeOnly));

  assert('G3: handleManifest validates version',
    /async function handleManifest[\s\S]{0,800}isValidVersionString\(version\)/.test(codeOnly));

  assert('G4: handleDelta validates from and to',
    /async function handleDelta[\s\S]{0,800}isValidVersionString\(from\)/.test(codeOnly)
    && /async function handleDelta[\s\S]{0,800}isValidVersionString\(to\)/.test(codeOnly));

  assert('G4: handleSnapshot validates version',
    /async function handleSnapshot[\s\S]{0,800}isValidVersionString\(version\)/.test(codeOnly));

  // The "aggregated by IP and domain" claim must be gone from
  // the user-facing docstrings (not from the explanatory
  // "we removed this" comment that documents the fix).
  assert('docstring no longer claims rate limit is "aggregated by IP and domain"',
    !/aggregated by IP and domain/i.test(src));
}

/* --------------------------------------------------------------- */
/* 6. Path-traversal behavior (G3 + G4 functional check)           */
/* --------------------------------------------------------------- */
console.log('');
console.log('[6] Path-traversal rejection (G3 + G4)');

if (existsSync(gatewayFnPath)) {
  // Use a TS/ESM import via the staging dir (which has the
  // updated source after the staging script ran).
  const stagedGatewayFn = join(stagingDir, 'private-sync-gateway.mjs');
  if (existsSync(stagedGatewayFn)) {
    let mod;
    try {
      mod = await import(pathToFileURL(stagedGatewayFn).href);
    } catch (err) {
      assert('importable staged gateway function', false, err.message);
    }
    if (mod && mod.handlePrivateSyncGateway) {
      // The handler does `new URL(request.url)`, so the fake
      // request must use a full URL — a bare path throws
      // ERR_INVALID_URL.
      const fakeRequest = (path, headers = {}) => ({
        url: new URL(path, 'https://gateway.test').href,
        method: 'GET',
        headers: { get: (h) => headers[h.toLowerCase()] ?? null },
      });

      // No auth header (so the auth check fails first and we
      // can't reach the route handler). For path-traversal
      // behavior we have to provide a valid Authorization
      // header. We don't have a real credential; instead we
      // verify the version validation fires by directly testing
      // the isValidVersionString helper via the module's
      // exported surface if possible, or by inspecting the
      // source for the validation order.

      // The handler runs the auth check BEFORE the route. A
      // missing/invalid Authorization returns 401 regardless of
      // the route or its params. To exercise the version
      // validation we need a valid credential. We use a stub
      // pepper and a pre-computed credential. The simplest
      // approach: inject a valid credential via the test
      // path (handlePrivateSyncGateway accepts `pepper` and
      // `store` as injected deps; we can also inject
      // `readStoreRecord` to return a matching HMAC).

      // For the path-traversal check, we don't need the
      // request to be authenticated — we need the version
      // validation to fire BEFORE the store read. The cleanest
      // way is to construct a credential that parses but whose
      // store record we control, so auth succeeds and the
      // version check runs.

      // We need the credentials helper. Import it from the
      // staged copy.
      const credsPath = join(stagingDir, '_shared', 'credentials.mjs');
      const baselineStorePath = join(stagingDir, '_shared', 'baselineStore.mjs');

      let creds;
      try { creds = await import(pathToFileURL(credsPath).href); }
      catch (err) { assert('importable credentials helper', false, err.message); }

      if (creds && creds.generateCredential) {
        // The imports above are kept around so failures here
        // surface as a clear error.
        void baselineStorePath;

        const testPepper = 'a-test-pepper-do-not-use-in-prod-2026q3';
        const cred = creds.generateCredential({ pepper: testPepper, keyId: 'deployment-hardening' });

        const fakeStore = {
          get: async () => null,  // no data; we expect 404 from the route, not 400
          setJSON: async () => true,
          setBinary: async () => true,
          delete: async () => true,
        };

        const storeRecord = { hmac: cred.hmac };
        const authHeaders = { 'authorization': `Bearer ${cred.credential}` };

        // Path-traversal attempts must be rejected with 400.
        const traversalAttempts = [
          '/private/v1/manifest/..%2F..%2Flatest',
          '/private/v1/manifest/..%2Fcredentials%2Fadmin',
          '/private/v1/manifest/foo%2F..%2F..%2Fbar',
          '/private/v1/manifest/v1%2F..%2F..%2F',
          '/private/v1/snapshot?version=..%2F..%2Fcredentials',
          '/private/v1/snapshot?version=foo%2Fbar',
          '/private/v1/delta?from=v1&to=..%2F..%2Fadmin',
          '/private/v1/delta?from=..%2Fadmin&to=v2',
        ];

        for (const url of traversalAttempts) {
          const req = fakeRequest(url, authHeaders);
          const resp = await mod.handlePrivateSyncGateway({
            request: req,
            pepper: testPepper,
            store: fakeStore,
            readStoreRecord: async () => storeRecord,
          });
          assert(`path-traversal rejected (400): ${url}`,
            resp.status === 400,
            `got status ${resp.status}`);
        }

        // Valid version strings must pass validation and reach
        // the store read (which returns null → 404 not-found,
        // which proves the version validation accepted the
        // value and the handler proceeded past the check).
        const validAttempts = [
          '/private/v1/manifest/v1.2.3',
          '/private/v1/manifest/2026-q3',
          '/private/v1/snapshot?version=v1.0.0',
          '/private/v1/snapshot?version=baseline_2026-07-13',
          '/private/v1/delta?from=v1.0.0&to=v1.0.1',
        ];

        for (const url of validAttempts) {
          const req = fakeRequest(url, authHeaders);
          const resp = await mod.handlePrivateSyncGateway({
            request: req,
            pepper: testPepper,
            store: fakeStore,
            readStoreRecord: async () => storeRecord,
          });
          // The store is empty so the handler returns 404 (not
          // found), not 400 (bad request). The 404 is the
          // positive signal that the version validation
          // accepted the input.
          assert(`valid version accepted (status != 400): ${url}`,
            resp.status !== 400,
            `got status ${resp.status}`);
        }
      }
    } else {
      assert('staged gateway function exports handlePrivateSyncGateway',
        false, 'export not found');
    }
  }
}

/* --------------------------------------------------------------- */
/* 7. G1: background function's misleading comment is fixed        */
/* --------------------------------------------------------------- */
console.log('');
console.log('[7] G1: refresh-baseline-background.mjs comment fix');

const bgFnPath = join(publicSrcFn, 'refresh-baseline-background.mjs');
assert('refresh-baseline-background.mjs exists',
  existsSync(bgFnPath));

if (existsSync(bgFnPath)) {
  const src = readText(bgFnPath);

  // The old comment claimed the background function "lives on
  // the private gateway" and "accesses the public site's
  // tpr-baseline store via cross-site env vars". That was
  // wrong; the function lives on the public site and uses
  // the local Netlify Blobs context.
  assert('G1: comment no longer claims the background function lives on the private gateway',
    !/lives on the private gateway/i.test(src)
    && !/lives\s*\n?\s*on the private gateway/i.test(src));

  assert('G1: comment no longer claims "accesses the public site\'s tpr-baseline store via cross-site env vars"',
    !/accesses the public site['\u2019]s `?tpr-baseline`? store via\s*\n?\s*cross-site env vars/i.test(src));

  // The corrected comment must now mention the public site.
  // Allow whitespace/newlines between "lives" and "on the public".
  assert('G1: comment now says the function lives on the public site',
    /lives[\s\S]{0,40}on the public/i.test(src));
}

/* --------------------------------------------------------------- */
/* 8. Root netlify.toml has the V6.0 topology comment block        */
/* --------------------------------------------------------------- */
console.log('');
console.log('[8] Root netlify.toml topology comment');

const rootToml = join(root, 'netlify.toml');
if (existsSync(rootToml)) {
  const src = readText(rootToml);
  assert('root netlify.toml has a "DEPLOYMENT TOPOLOGY" comment block',
    /V6\.0 DEPLOYMENT TOPOLOGY/i.test(src));
  assert('root netlify.toml comment block references the gateway subtree',
    /netlify\/gateway/i.test(src));
  assert('root netlify.toml comment block references the staging script',
    /copy-gateway-files\.mjs/i.test(src));
  assert('root netlify.toml comment block calls out the 500-on-public-site behavior',
    /500|intentionally absent|no anonymous request can read/i.test(src));
}

/* --------------------------------------------------------------- */
/* 9. .gitignore excludes the gateway staging directory            */
/* --------------------------------------------------------------- */
console.log('');
console.log('[9] .gitignore covers netlify/gateway/functions-staging/');

const gitignore = join(root, '.gitignore');
if (existsSync(gitignore)) {
  const src = readText(gitignore);
  assert('.gitignore excludes netlify/gateway/functions-staging/',
    /netlify\/gateway\/functions-staging\//.test(src));
}

/* --------------------------------------------------------------- */
/* 10. No VITE_* secret env vars in the new code                   */
/* --------------------------------------------------------------- */
console.log('');
console.log('[10] No VITE_* secret env vars in hardened code');

const newFiles = [
  join(gatewayDir, 'netlify.toml'),
  join(gatewayDir, 'package.json'),
  join(root, 'scripts', 'copy-gateway-files.mjs'),
  join(root, 'netlify.toml'),
];
for (const f of newFiles) {
  if (!existsSync(f)) continue;
  const src = readText(f);
  assert(`no VITE_* secret in ${relative(root, f)}`,
    !/VITE_(?:NVD|GITHUB|THREATPULSE|TOKEN|KEY|SECRET|PEPPER)/i.test(src));
}

/* --------------------------------------------------------------- */
/* 11. Credential store: gateway-local, no cross-site env var       */
/* --------------------------------------------------------------- */
console.log('');
console.log('[11] Credential store is gateway-local (no cross-site env var)');

const gwBaselineStorePath = join(gatewayDir, 'src', '_shared', 'baselineStore.mjs');
if (existsSync(gwBaselineStorePath)) {
  const src = readText(gwBaselineStorePath);
  // Strip comments so the explanatory header does not match
  // the negative checks below.
  const codeOnly = src
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/^\s*\/\/.*$/gm, '');

  assert('gateway baselineStore declares CREDENTIALS_STORE_NAME = "tpr-private-credentials"',
    /export const CREDENTIALS_STORE_NAME\s*=\s*['"]tpr-private-credentials['"]/.test(codeOnly));

  assert('gateway baselineStore exports getCredentialsStore() (local runtime context)',
    /export function getCredentialsStore\s*\(/.test(codeOnly));

  assert('gateway baselineStore getCredentialsStore uses local getStore (no siteID, no token)',
    /getCredentialsStore[\s\S]{0,200}?return\s+getStore\s*\(\s*\{[\s\S]{0,300}?name:\s*CREDENTIALS_STORE_NAME[\s\S]{0,300}?consistency:\s*'strong'[\s\S]{0,300}?\}\s*\)/.test(codeOnly)
    && !/getCredentialsStore[\s\S]{0,500}?siteID/.test(codeOnly)
    && !/getCredentialsStore[\s\S]{0,500}?token/.test(codeOnly));

  assert('gateway baselineStore does NOT export getCrossSitePrivateCredentialsStore',
    !/export function getCrossSitePrivateCredentialsStore\s*\(/.test(codeOnly));

  // The credentials store accessor MUST NOT read any env var
  // (the local Netlify Blobs runtime context provides access
  // automatically; no env var, no token, no cross-site).
  assert('gateway baselineStore getCredentialsStore does NOT read any env var',
    /export function getCredentialsStore[\s\S]{0,400}?getStore\s*\(\s*\{[\s\S]{0,300}?\}/.test(codeOnly)
    && !/export function getCredentialsStore[\s\S]{0,400}?process\.env/.test(codeOnly));

  // The baseline accessor MUST still require cross-site env
  // vars (separate from the credentials path).
  assert('gateway baselineStore getCrossSiteBaselineStore still requires siteID and token',
    /export function getCrossSiteBaselineStore[\s\S]{0,800}?process\.env\[BASELINE_SITE_ID_ENV_VAR\][\s\S]{0,200}?process\.env\[BASELINE_BLOBS_ACCESS_TOKEN_ENV_VAR\]/.test(codeOnly));

  // The baseline token MUST be scoped to tpr-baseline only.
  // The cross-site baseline accessor must reference the
  // baseline store name, not the credentials store name.
  // Match the function's `return getStore({...name: BASELINE_STORE_NAME...})`
  // specifically, not the whole module.
  assert('gateway baselineStore getCrossSiteBaselineStore uses BASELINE_STORE_NAME (tpr-baseline), NOT CREDENTIALS_STORE_NAME',
    /function getCrossSiteBaselineStore[\s\S]{0,400}?return\s+getStore\s*\(\s*\{[\s\S]{0,200}?name:\s*BASELINE_STORE_NAME/.test(codeOnly)
    && !/function getCrossSiteBaselineStore[\s\S]{0,400}?name:\s*CREDENTIALS_STORE_NAME/.test(codeOnly));
}

if (existsSync(gatewayFnPath)) {
  const src = readText(gatewayFnPath);
  const codeOnly = src
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/^\s*\/\/.*$/gm, '');

  assert('gateway function imports getCredentialsStore (LOCAL), not getCrossSitePrivateCredentialsStore',
    /import\s*\{[\s\S]{0,300}getCredentialsStore[\s\S]{0,300}\}\s*from\s*['"]\.\/_shared\/baselineStore\.mjs['"]/.test(codeOnly)
    && !/import\s*\{[\s\S]{0,300}getCrossSitePrivateCredentialsStore/.test(codeOnly));

  assert('gateway function production handler wires resolveCredentialsStore to getCredentialsStore (LOCAL)',
    /resolveCredentialsStore:\s*\(\)\s*=>\s*getCredentialsStore\(\)/.test(codeOnly));

  assert('gateway function uses a separate handle for credentials (resolveCredentialsStore, not resolveStore)',
    /resolveCredentialsStore\s*\?/.test(codeOnly) || /resolveCredentialsStore\(\)/.test(codeOnly));
}

// Proof that the baseline token CANNOT be used as a
// credential-store token: the gateway baselineStore.mjs
// does not expose a helper that accepts the baseline token
// and returns a credentials handle.
if (existsSync(gwBaselineStorePath)) {
  const src = readText(gwBaselineStorePath);
  const codeOnly = src
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/^\s*\/\/.*$/gm, '');
  assert('no helper accepts the baseline token and returns a credentials handle (blast-radius isolation)',
    !/getCrossSitePrivateCredentials|getCredentialsStore\s*\([^)]*THREATPULSE_BLOBS_ACCESS_TOKEN/.test(codeOnly)
    && !/getCredentialsStore\s*\([^)]*BASELINE_BLOBS_ACCESS_TOKEN/.test(codeOnly));
}

// No "credentials path" exists in tpr-baseline: the public
// site's baselineStore.mjs (the writer) does NOT write a
// `credentials/` key prefix.
const publicBaselineStorePath = join(root, 'netlify', 'functions', '_shared', 'baselineStore.mjs');
if (existsSync(publicBaselineStorePath)) {
  const src = readText(publicBaselineStorePath);
  const codeOnly = src
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/^\s*\/\/.*$/gm, '');
  assert('public-site baselineStore does NOT write a credentials/ key prefix',
    !/credentials\//.test(codeOnly));
}

// Public-site baselineStore.mjs must NOT carry the cross-site
// helpers (they moved to the gateway subtree).
if (existsSync(publicBaselineStorePath)) {
  const src = readText(publicBaselineStorePath);
  // Strip comments so the explanatory header does not match
  // the negative checks below.
  const codeOnly = src
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/^\s*\/\/.*$/gm, '');
  assert('public-site baselineStore does NOT export getCrossSiteBaselineStore',
    !/export function getCrossSiteBaselineStore\s*\(/.test(codeOnly));
  assert('public-site baselineStore does NOT export getCredentialsStore',
    !/export function getCredentialsStore\s*\(/.test(codeOnly));
  assert('public-site baselineStore does NOT reference tpr-private-credentials (in code, not comments)',
    !/tpr-private-credentials/.test(codeOnly));
}

// Proof: no THREATPULSE_CREDENTIALS_BLOBS_ACCESS_TOKEN (or
// similar credential-token env var) remains anywhere in the
// source tree, the docs, the deployment configs, the
// public-release checklist, or the changelog.
const credentialTokenEnvVars = [
  'THREATPULSE_CREDENTIALS_BLOBS_ACCESS_TOKEN',
  'THREATPULSE_CREDENTIALS_SITE_ID',
];
const scannedForCredentialToken = [
  join(root, 'netlify', 'gateway', 'netlify.toml'),
  join(root, 'netlify.toml'),
  join(root, 'netlify', 'gateway', 'src', 'private-sync-gateway.mjs'),
  join(root, 'netlify', 'gateway', 'src', '_shared', 'baselineStore.mjs'),
  join(root, 'netlify', 'functions', '_shared', 'baselineStore.mjs'),
  join(root, 'docs', 'deployment.md'),
  join(root, 'docs', 'credentials.md'),
  join(root, 'CHANGELOG.md'),
  join(root, 'PUBLIC_RELEASE_CHECKLIST.md'),
];
for (const f of scannedForCredentialToken) {
  if (!existsSync(f)) continue;
  const content = readText(f);
  // Strip the "no such env var exists" documentation
  // comments that explicitly mention the env-var name to
  // warn operators NOT to set it. The "Do NOT set" bullet
  // is followed (possibly across newlines) by the env-var
  // name in backticks and a parenthetical explanation.
  // The longest such block is ~420 chars; use 600 to be
  // safe. Match the trailing punctuation loosely.
  const stripped = content
    .replace(/Do NOT set[\s\S]{0,600}?credentials are gateway-local[)\s.\-]*/g, '')
    .replace(/\(no such env var exists;[^)]*\)/g, '')
    .replace(/\(no such env var\)[\s\S]*?\./g, '');
  for (const envName of credentialTokenEnvVars) {
    assert(`no "${envName}" env-var reference in ${relative(root, f)} (in code, not the "do not set" docs)`,
      !new RegExp(envName.replace(/_/g, '_')).test(stripped));
  }
}

/* --------------------------------------------------------------- */
/* 12. Safe error responses: no secret leak in 4xx/5xx bodies       */
/* --------------------------------------------------------------- */
console.log('');
console.log('[12] Safe error responses (no secret leak in 4xx/5xx bodies)');

const stagedGatewayFn = join(stagingDir, 'private-sync-gateway.mjs');
if (existsSync(stagedGatewayFn)) {
  // Re-import the staged gateway (its module cache may have
  // been cleared by the prior [11] section).
  let safeMod;
  try {
    safeMod = await import(pathToFileURL(stagedGatewayFn).href + '?t=' + Date.now());
  } catch (err) {
    assert('importable staged gateway function (safe-error test)', false, err.message);
  }
  if (safeMod && safeMod.handlePrivateSyncGateway) {
    // Test 1: when the pepper is missing, the 500 body must
    // not contain the env var name with a value, the token,
    // or the site ID.
    const errResp1 = await safeMod.handlePrivateSyncGateway({
      request: { url: 'https://gateway.test/private/v1/manifest', method: 'GET', headers: { get: () => null } },
      pepper: null,
      store: null,
    });
    const errBody1 = await errResp1.json();
    const errBodyStr1 = JSON.stringify(errBody1);
    assert('500 (no pepper) body does not contain pepper env var name',
      !/THREATPULSE_CREDENTIAL_PEPPER/.test(errBodyStr1));
    assert('500 (no pepper) body does not contain "Bearer" header value',
      !/Bearer/.test(errBodyStr1));
    assert('500 (no pepper) body does not contain the token env var',
      !/THREATPULSE_BLOBS_ACCESS_TOKEN/.test(errBodyStr1));
    assert('500 (no pepper) body does not contain the site-id env var',
      !/THREATPULSE_BASELINE_SITE_ID/.test(errBodyStr1));

    // Test 2: when the cross-site store handle throws, the 500
    // body must include only a SANITIZED reason. The raw
    // underlying error message is acceptable to surface (the
    // @netlify/blobs error messages are generic and do not
    // include the token or site ID), but the body must not
    // echo the env var names or values.
    // NOTE: the credential must be a valid `tpr_<keyId>_<secret>`
    // shape (prefix is `tpr_` with an UNDERSCORE; keyId uses
    // the safe alphabet A-Za-z0-9- and the separator before
    // the secret is `_`; secret is >= 16 chars) so the function
    // reaches the store-resolution step where the simulated
    // failure occurs.
    const errResp2 = await safeMod.handlePrivateSyncGateway({
      request: { url: 'https://gateway.test/private/v1/manifest', method: 'GET', headers: { get: () => 'Bearer tpr_leaktest_SECRETLEAKFORTESTING12345' } },
      pepper: 'a-test-pepper',
      store: null,
      resolveStore: () => { throw new Error('simulated store failure: siteID=leakedsite token=leakedtoken'); },
      resolveCredentialsStore: () => { throw new Error('simulated cred store failure'); },
    });
    const errBody2 = await errResp2.json();
    const errBodyStr2 = JSON.stringify(errBody2);
    assert('500 (store failure) body is a JSON object (not a raw stack trace)',
      typeof errBody2 === 'object' && errBody2 !== null && 'status' in errBody2);
    assert('500 (store failure) body has the canonical { status: "failed" } shape',
      errBody2.status === 'failed' && typeof errBody2.reason === 'string');
    assert('500 (store failure) body does NOT contain the credential value',
      !/SECRETLEAKFORTESTING/.test(errBodyStr2));
    assert('500 (store failure) body does NOT contain the credential keyId',
      !/tpr_leaktest_/.test(errBodyStr2));

    // Test 3: a normal 401 (bad credential) response must not
    // echo the credential value.
    const errResp3 = await safeMod.handlePrivateSyncGateway({
      request: { url: 'https://gateway.test/private/v1/manifest', method: 'GET', headers: { get: (h) => h === 'authorization' ? 'Bearer tpr_leaktest2_SECRETLEAKFORTESTING67890' : null } },
      pepper: 'a-test-pepper',
      store: { get: async () => null, setJSON: async () => true, setBinary: async () => true, delete: async () => true },
      resolveCredentialsStore: () => ({ get: async () => null }),
    });
    const errBody3 = await errResp3.json();
    const errBodyStr3 = JSON.stringify(errBody3);
    assert('401 (bad credential) body does NOT contain the credential value',
      !/SECRETLEAKFORTESTING/.test(errBodyStr3));
    assert('401 (bad credential) body does NOT contain the credential keyId',
      !/tpr_leaktest2_/.test(errBodyStr3));
    assert('401 (bad credential) body does NOT contain the keyId',
      !/leaktest2/.test(errBodyStr3));
  }
}

/* --------------------------------------------------------------- */
/* 13. Sanitized function logs: no console.log of secrets           */
/* --------------------------------------------------------------- */
console.log('');
console.log('[13] Sanitized function logs (no console.log of secrets)');

if (existsSync(gatewayFnPath)) {
  const src = readText(gatewayFnPath);
  assert('gateway function does NOT call console.log()',
    !/console\.log\s*\(/.test(src));
  assert('gateway function does NOT call console.error()',
    !/console\.error\s*\(/.test(src));
  assert('gateway function does NOT call console.warn()',
    !/console\.warn\s*\(/.test(src));
  assert('gateway function does NOT call console.info()',
    !/console\.info\s*\(/.test(src));
  assert('gateway function does NOT call console.debug()',
    !/console\.debug\s*\(/.test(src));
}

if (existsSync(join(root, 'netlify', 'functions', 'refresh-baseline-background.mjs'))) {
  const src = readText(join(root, 'netlify', 'functions', 'refresh-baseline-background.mjs'));
  // The background function's console.log of the trigger secret
  // would be a critical leak. We assert the secret value is
  // never passed to console.log. The function does log a
  // summary line; we check that line does not contain the
  // secret value.
  assert('background function does not log the trigger secret value',
    !/console\.log\s*\([^)]*secret[^)]*\.value/.test(src)
    && !/console\.log\s*\([^)]*provided\s*[,)]/.test(src));
  assert('background function does not log the Authorization header',
    !/console\.log\s*\([^)]*[Aa]uthorization/.test(src));
  assert('background function does not log the bearer header',
    !/console\.log\s*\([^)]*[Bb]earer/.test(src));
}

/* --------------------------------------------------------------- */
/* 14. Existing private-gateway acceptance suite still passes       */
/* --------------------------------------------------------------- */
console.log('');
console.log('[14] Existing acceptance-private-gateway.mjs smoke test');

const privateGwScript = join(here, 'acceptance-private-gateway.mjs');
if (existsSync(privateGwScript)) {
  const r = spawnSync(process.execPath, [privateGwScript], { encoding: 'utf8' });
  assert('scripts/acceptance-private-gateway.mjs exits 0',
    r.status === 0,
    `status=${r.status} ${(r.stderr || '').split('\n').slice(0, 2).join(' | ')}`);
} else {
  assert('scripts/acceptance-private-gateway.mjs exists', false);
}

/* --------------------------------------------------------------- */
/* 15. Documentation reflects the new architecture                  */
/* --------------------------------------------------------------- */
console.log('');
console.log('[15] Documentation reflects the new architecture');

const deploymentDoc = join(root, 'docs', 'deployment.md');
if (existsSync(deploymentDoc)) {
  const src = readText(deploymentDoc);
  assert('docs/deployment.md describes tpr-private-credentials store',
    /tpr-private-credentials/.test(src));
  assert('docs/deployment.md describes deploy-preview secret scoping (Production scope)',
    /Production.+scope|scope.+Production|scoping/.test(src));
  assert('docs/deployment.md describes the netlify/gateway/ topology',
    /netlify\/gateway/.test(src));
  assert('docs/deployment.md describes the copy-gateway-files.mjs staging script',
    /copy-gateway-files\.mjs/.test(src));
  assert('docs/deployment.md describes the gateway-local credentials store (no cross-site env var)',
    /gateway-local|local Netlify Blobs runtime context/.test(src));
}

const credentialsDoc = join(root, 'docs', 'credentials.md');
if (existsSync(credentialsDoc)) {
  const src = readText(credentialsDoc);
  assert('docs/credentials.md describes tpr-private-credentials (NOT tpr-baseline)',
    /tpr-private-credentials/.test(src) && !/credentials.+in `?tpr-baseline`?/.test(src));
  assert('docs/credentials.md explains the separate-store rationale',
    /separate/i.test(src) && /(decouple|decoupling|isolation|blast radius|gateway-local)/i.test(src));
}

const changelog = join(root, 'CHANGELOG.md');
if (existsSync(changelog)) {
  const src = readText(changelog);
  // The deployment-hardening content is folded INTO the V6.0
  // entry (no V6.0.1 micro-version). The test must NOT look
  // for a "V6.0.1" header.
  assert('CHANGELOG.md has NO V6.0.1 micro-version (V6.0 not yet released)',
    !/^##\s+V6\.0\.1\b/im.test(src));
  assert('CHANGELOG.md has a single V6.0 entry',
    (src.match(/^##\s+V6\.0\b/gm) || []).length === 1);
  assert('CHANGELOG.md V6.0 entry documents the credential-store separation',
    /tpr-private-credentials/.test(src) || /credential.+separation/i.test(src));
  assert('CHANGELOG.md V6.0 entry documents the gateway function move',
    /netlify\/gateway\/src/.test(src) || /moved out of.+netlify\/functions/.test(src));
  assert('CHANGELOG.md V6.0 entry documents the route-version validation invariant',
    /Route version parameters are validated/i.test(src));
  assert('CHANGELOG.md V6.0 entry documents the safe error / sanitized log invariant',
    /Safe error responses and sanitized logs/i.test(src));
  assert('CHANGELOG.md V6.0 entry documents the deploy-preview secret scoping',
    /Production scope|Production.+scope/i.test(src));
}

const publicReleaseChecklist = join(root, 'PUBLIC_RELEASE_CHECKLIST.md');
if (existsSync(publicReleaseChecklist)) {
  const src = readText(publicReleaseChecklist);
  assert('PUBLIC_RELEASE_CHECKLIST.md documents the new gateway location',
    /netlify\/gateway\/src\/private-sync-gateway\.mjs/.test(src));
  assert('PUBLIC_RELEASE_CHECKLIST.md documents tpr-private-credentials (NOT tpr-baseline)',
    /tpr-private-credentials/.test(src));
}

/* --------------------------------------------------------------- */
/* 16. No fake credentials in non-test files                        */
/* --------------------------------------------------------------- */
console.log('');
console.log('[16] No fake credentials leaked outside the test suite');

// The fake test credentials used by the safe-error-response
// tests (above) MUST NOT appear in any other source file,
// documentation, or fixture. The fixture file paths below
// are the EXCLUSION list (the test file itself + the staging
// output that the test loads).
const fakeCredentialNeedles = [
  'SECRETLEAKFORTESTING',
  'tpr_leaktest_',
  'tpr_leaktest2_',
  'tpr-leaktest_SECRETLEAK',
  'leakedsite',
  'leakedtoken',
];
const allowedFilesForFakeNeedles = new Set([
  // The test file itself; it constructs the fake credentials
  // deliberately.
  join(root, 'scripts', 'acceptance-deployment-hardening.mjs'),
  // The deployment-hardening test imports the staged copy
  // of the gateway function. The staging copy is built by
  // the staging script, which copies the gateway source.
  // The fake credentials DO NOT appear in the gateway source;
  // the test injects them at request-build time. We include
  // the staging file in the allowlist defensively.
  join(root, 'netlify', 'gateway', 'functions-staging', 'functions', 'private-sync-gateway.mjs'),
]);
const scannedExtensions = new Set(['.mjs', '.js', '.ts', '.json', '.md', '.toml']);

function walkForFakeCreds(dir, found) {
  if (!existsSync(dir)) return;
  const entries = readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.name.startsWith('.')) continue;        // skip .git, .v6-build, etc.
    if (entry.name === 'node_modules') continue;
    if (entry.name === 'dist') continue;
    if (entry.name === 'functions-staging') continue; // gitignored staging output
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      walkForFakeCreds(full, found);
    } else {
      const ext = entry.name.slice(entry.name.lastIndexOf('.'));
      if (!scannedExtensions.has(ext)) continue;
      try {
        const content = readFileSync(full, 'utf8');
        for (const needle of fakeCredentialNeedles) {
          if (content.includes(needle)) {
            found.push({ file: full, needle });
          }
        }
      } catch {
        // skip unreadable
      }
    }
  }
}

const found = [];
walkForFakeCreds(root, found);
const disallowed = found.filter((f) => !allowedFilesForFakeNeedles.has(f.file));
if (disallowed.length === 0) {
  assert('no fake test credentials in non-test files (and no fixtures, docs, or production code)', true);
} else {
  for (const d of disallowed) {
    failed++;
    failures.push({ label: `fake credential "${d.needle}" leaked to ${d.file}`, extra: '' });
    console.log(`  FAIL  fake credential "${d.needle}" leaked to ${relative(root, d.file)}`);
  }
}

/* --------------------------------------------------------------- */
/* Summary                                                          */
/* --------------------------------------------------------------- */
console.log('');
console.log('============================================');
console.log(`Total: ${passed} passed, ${failed} failed`);
if (failed > 0) {
  console.log('');
  console.log('Failures:');
  for (const f of failures) {
    console.log(`  - ${f.label}${f.extra ? `  (${f.extra})` : ''}`);
  }
  process.exit(1);
}
process.exit(0);
