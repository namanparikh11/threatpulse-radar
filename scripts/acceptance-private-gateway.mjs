// V6.0 — Private sync gateway + credentials behavior tests.
//
//   node scripts/acceptance-private-gateway.mjs
//
// Behavior under test:
//   - credentials.parseCredential: valid format
//   - credentials.parseCredential: invalid format (wrong prefix, bad
//     keyId, short secret, etc.)
//   - credentials.computeHmac: matches an independent Node HMAC
//   - credentials.constantTimeHexEqual: same / different / wrong length
//   - credentials.generateCredential: produces a valid credential
//     whose stored HMAC verifies with the matching pepper
//   - credentials.verifyCredential: valid, malformed, unknown-key,
//     hmac-mismatch
//   - credentials.getPepperFromEnv: returns null when unset
//   - private-sync-gateway: 401 when no Authorization header
//   - private-sync-gateway: 401 when Bearer prefix is missing
//   - private-sync-gateway: 401 when credential is malformed
//   - private-sync-gateway: 401 when keyId is unknown
//   - private-sync-gateway: 401 when HMAC does not match
//   - private-sync-gateway: 500 when pepper is not configured
//   - private-sync-gateway: 500 when store is unavailable
//   - private-sync-gateway: 200 /private/v1/manifest route
//   - private-sync-gateway: 200 /private/v1/manifest/{version} route
//   - private-sync-gateway: 200 /private/v1/delta route
//   - private-sync-gateway: 200 /private/v1/shard route (gzip body)
//   - private-sync-gateway: 200 /private/v1/snapshot route
//   - private-sync-gateway: 200 /private/v1/sources route
//   - private-sync-gateway: 404 on unknown route
//   - private-sync-gateway: 405 on POST
//   - private-sync-gateway: rejects shard-key traversal attempts
//   - private-sync-gateway: secret is never echoed in the response
//   - V6.0 invariant: anonymous requests can never read the canonical
//     baseline (any auth failure returns 401, not 200 with empty body)

import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync, rmSync, readdirSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';
import { createHmac, randomBytes } from 'node:crypto';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const buildDir = join(here, '.v6-build-gateway');

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
/* Build the credentials module to .mjs for import                     */
/* ------------------------------------------------------------------ */

function buildCredentials() {
  if (existsSync(buildDir)) {
    try { rmSync(buildDir, { recursive: true, force: true }); } catch (e) { /* fall through */ }
  }
  mkdirSync(buildDir, { recursive: true });
  const tscJs = join(root, 'node_modules', 'typescript', 'lib', 'tsc.js');
  execFileSync(
    process.execPath,
    [tscJs, 'netlify/gateway/src/_shared/credentials.mjs',
     '--outDir', buildDir.replace(/\\/g, '/'), '--rootDir', '.',
     '--module', 'esnext', '--target', 'es2022', '--moduleResolution', 'node',
     '--skipLibCheck', '--allowJs', '--declaration', 'false'],
    { cwd: root, stdio: 'pipe' }
  );
}

buildCredentials();
const buildLeaf = buildDir.split(/[\\/]/).pop();
const credentials = await import(`./${buildLeaf}/netlify/gateway/src/_shared/credentials.mjs`);
const {
  CREDENTIAL_PREFIX, KEY_ID_MAX_LENGTH, KEY_ID_PATTERN, RANDOM_SECRET_BYTES,
  PEPPER_ENV_VAR, credentialBlobKey,
  parseCredential, computeHmac, constantTimeHexEqual,
  generateCredential, verifyCredential, getPepperFromEnv,
} = credentials;

// Import the gateway directly (it's pure ESM). The gateway
// function lives at netlify/gateway/src/private-sync-gateway.mjs
// — the public site's netlify/functions/ directory no longer
// contains it (per the V6.0 deployment-hardening topology).
const gatewayMod = await import(pathToFileURL(join(root, 'netlify', 'gateway', 'src', 'private-sync-gateway.mjs')).href);
const { handlePrivateSyncGateway, config } = gatewayMod;

const PEPPER = 'a-test-pepper-do-not-use-in-prod';

function makeRequest({ method = 'GET', url = 'https://gateway.test/private/v1/manifest', headers = {} } = {}) {
  return { method, url, headers: { get: (n) => headers[n] || headers[n.toLowerCase()] || null } };
}

function bearer(cred) {
  return { authorization: `Bearer ${cred}` };
}

/* ------------------------------------------------------------------ */
/* Tests: credentials.parseCredential                                  */
/* ------------------------------------------------------------------ */

section('parseCredential: valid format');

{
  const c = `${CREDENTIAL_PREFIX}mykeyid_${'A'.repeat(43)}`;
  const parsed = parseCredential(c);
  assert('parsed is non-null', parsed !== null);
  assert('parsed.keyId is correct', parsed.keyId === 'mykeyid');
  assert('parsed.randomSecret is correct', parsed.randomSecret === 'A'.repeat(43));
}

section('parseCredential: invalid format');

{
  assert('null input rejected', parseCredential(null) === null);
  assert('undefined input rejected', parseCredential(undefined) === null);
  assert('non-string input rejected', parseCredential(123) === null);
  assert('empty string rejected', parseCredential('') === null);
  assert('wrong prefix rejected', parseCredential('xxx_abc_def') === null);
  assert('missing separator rejected', parseCredential(`${CREDENTIAL_PREFIX}abc`) === null);
  assert('empty randomSecret rejected', parseCredential(`${CREDENTIAL_PREFIX}abc_`) === null);
  assert('illegal characters in keyId rejected',
    parseCredential(`${CREDENTIAL_PREFIX}has space_${'A'.repeat(43)}`) === null);
  assert('keyId too long rejected',
    parseCredential(`${CREDENTIAL_PREFIX}${'a'.repeat(65)}_${'A'.repeat(43)}`) === null);
  assert('short secret rejected',
    parseCredential(`${CREDENTIAL_PREFIX}mykey_short`) === null);
}

/* ------------------------------------------------------------------ */
/* Tests: credentials.computeHmac                                      */
/* ------------------------------------------------------------------ */

section('computeHmac: matches independent HMAC');

{
  const pepper = 'test-pepper';
  const keyId = 'mykey01';
  const randomSecret = 'abcdefghij1234567890';
  const ours = computeHmac({ pepper, keyId, randomSecret });
  // Independent computation
  const h = createHmac('sha256', pepper);
  h.update(`${keyId}:${randomSecret}`);
  const expected = h.digest('hex');
  assert('matches independent HMAC', ours === expected);
  assert('hex digest is 64 chars', ours.length === 64);
  assert('hex digest is lowercase', ours === ours.toLowerCase());
}

section('computeHmac: validates inputs');

{
  let threw = null;
  try { computeHmac({ pepper: '', keyId: 'k', randomSecret: 's' }); } catch (e) { threw = e; }
  assert('empty pepper throws', threw !== null);
  threw = null;
  try { computeHmac({ pepper: 'p', keyId: 'has space', randomSecret: 's' }); } catch (e) { threw = e; }
  assert('invalid keyId throws', threw !== null);
  threw = null;
  try { computeHmac({ pepper: 'p', keyId: 'k', randomSecret: '' }); } catch (e) { threw = e; }
  assert('empty randomSecret throws', threw !== null);
}

/* ------------------------------------------------------------------ */
/* Tests: credentials.constantTimeHexEqual                             */
/* ------------------------------------------------------------------ */

section('constantTimeHexEqual');

{
  const a = 'a'.repeat(64);
  const b = 'a'.repeat(64);
  const c = 'b'.repeat(64);
  assert('same hex → true', constantTimeHexEqual(a, b));
  assert('different hex → false', !constantTimeHexEqual(a, c));
  assert('different length → false', !constantTimeHexEqual('aa', 'aaaa'));
  assert('non-string → false', !constantTimeHexEqual(null, a));
  assert('empty → false', !constantTimeHexEqual('', ''));
  assert('non-hex chars → false', !constantTimeHexEqual('z'.repeat(64), 'a'.repeat(64)));
  // Case-insensitive
  const upperA = 'A'.repeat(64);
  assert('uppercase A equals lowercase a', constantTimeHexEqual(upperA, a));
}

/* ------------------------------------------------------------------ */
/* Tests: credentials.generateCredential + verifyCredential            */
/* ------------------------------------------------------------------ */

section('generateCredential: roundtrip with verifyCredential');

{
  const c = generateCredential({ pepper: PEPPER });
  assert('credential has the right shape',
    typeof c.credential === 'string' && c.credential.startsWith(CREDENTIAL_PREFIX));
  assert('keyId is from the safe character set', KEY_ID_PATTERN.test(c.keyId));
  assert('randomSecret is base64url (no padding)', /^[A-Za-z0-9_-]+$/.test(c.randomSecret));
  assert('hmac is 64 hex chars', /^[0-9a-f]{64}$/.test(c.hmac));

  // Store the HMAC and verify
  const storeRecord = { hmac: c.hmac, createdAt: '2026-07-12T20:00:00.000Z', label: 'test' };
  const v = verifyCredential({ credential: c.credential, pepper: PEPPER, storeRecord });
  assert('valid credential verifies', v.valid === true);
  assert('verification returns the keyId', v.keyId === c.keyId);
}

section('generateCredential: explicit keyId is honored');

{
  const c = generateCredential({ pepper: PEPPER, keyId: 'my-explicit-key' });
  assert('explicit keyId is used', c.keyId === 'my-explicit-key');
  assert('credential starts with tpr_my-explicit-key_',
    c.credential.startsWith(`${CREDENTIAL_PREFIX}my-explicit-key_`));
}

section('generateCredential: explicit keyId is validated');

{
  let threw = null;
  try { generateCredential({ pepper: PEPPER, keyId: 'has space' }); } catch (e) { threw = e; }
  assert('illegal keyId throws', threw !== null);
}

section('verifyCredential: failure modes');

{
  // Malformed credential
  const r1 = verifyCredential({ credential: 'not-a-credential', pepper: PEPPER, storeRecord: { hmac: 'a'.repeat(64) } });
  assert('malformed credential → valid:false', r1.valid === false && r1.reason === 'malformed');

  // Unknown key (storeRecord null) — credential must parse OK
  const r2 = verifyCredential({ credential: `${CREDENTIAL_PREFIX}keyid_${'A'.repeat(43)}`, pepper: PEPPER, storeRecord: null });
  assert('null storeRecord → unknown-key', r2.valid === false && r2.reason === 'unknown-key');

  // Malformed store record (no hmac)
  const r3 = verifyCredential({ credential: `${CREDENTIAL_PREFIX}keyid_${'A'.repeat(43)}`, pepper: PEPPER, storeRecord: {} });
  assert('storeRecord without hmac → malformed-store-record', r3.valid === false && r3.reason === 'malformed-store-record');

  // HMAC mismatch
  const c = generateCredential({ pepper: PEPPER, keyId: 'real-key' });
  const wrongRecord = { hmac: 'a'.repeat(64) };
  const r4 = verifyCredential({ credential: c.credential, pepper: PEPPER, storeRecord: wrongRecord });
  assert('wrong HMAC → hmac-mismatch', r4.valid === false && r4.reason === 'hmac-mismatch');

  // Different pepper produces a different HMAC
  const r5 = verifyCredential({ credential: c.credential, pepper: 'other-pepper', storeRecord: { hmac: c.hmac } });
  assert('different pepper → hmac-mismatch', r5.valid === false && r5.reason === 'hmac-mismatch');
}

section('getPepperFromEnv');

{
  assert('unset env → null', getPepperFromEnv({}) === null);
  assert('set env → pepper', getPepperFromEnv({ [PEPPER_ENV_VAR]: 'p' }) === 'p');
  assert('empty env → null', getPepperFromEnv({ [PEPPER_ENV_VAR]: '' }) === null);
}

/* ------------------------------------------------------------------ */
/* Tests: private-sync-gateway handler with stubbed store              */
/* ------------------------------------------------------------------ */

/* In-memory store stub matching the Netlify Blobs surface we use. */
function makeMemoryStore({ shards = {}, manifests = {}, deltas = {}, sourceRegistry = null, credentials = {} } = {}) {
  const blobs = new Map();
  // Shards
  for (const [k, bytes] of Object.entries(shards)) blobs.set(k, bytes);
  // Manifests (stored as JSON strings)
  for (const [v, m] of Object.entries(manifests)) blobs.set(`manifests/versions/${v}.json`, JSON.stringify(m));
  if (manifests.latest) blobs.set('manifests/latest.json', JSON.stringify(manifests.latest));
  // Deltas
  for (const [k, d] of Object.entries(deltas)) blobs.set(k, JSON.stringify(d));
  // Source registry
  if (sourceRegistry) blobs.set('source-registry', JSON.stringify(sourceRegistry));
  // Credentials
  for (const [k, v] of Object.entries(credentials)) blobs.set(k, JSON.stringify(v));

  return {
    async get(key, opts = {}) {
      if (!blobs.has(key)) return null;
      const v = blobs.get(key);
      if (opts.type === 'json') {
        try { return JSON.parse(v); } catch { return null; }
      }
      if (opts.type === 'arrayBuffer') {
        return Buffer.from(v);
      }
      return v;
    },
    async set(key, value) { blobs.set(key, value); },
    _blobs: blobs,
  };
}

const validManifest = {
  schemaVersion: '1.0.0',
  baselineVersion: 'v1',
  previousVersion: null,
  publishedAt: '2026-07-12T20:30:00.000Z',
  configHash: 'sha256:' + 'a'.repeat(64),
  sourceStatus: {},
  shards: {
    vulnerability: { ab: { objectKey: 'objects/sha256/aaa.json.gz', sha256: 'sha256:' + 'a'.repeat(64), byteSize: 100, recordCount: 5 } },
  },
  stats: { totalRecords: 5, totalCompressedBytes: 100, totalBuckets: 1, perType: {} },
  canonicalContentHash: 'sha256:' + 'a'.repeat(64),
  deltaHash: null,
};

function setup() {
  const c = generateCredential({ pepper: PEPPER, keyId: 'test-key' });
  const store = makeMemoryStore({
    manifests: { latest: validManifest, v1: validManifest },
    shards: { 'objects/sha256/aaa.json.gz': Buffer.from('gzipped-content') },
    deltas: {},
    sourceRegistry: { sources: [{ id: 'osv' }] },
    credentials: { 'credentials/test-key': { hmac: c.hmac, createdAt: '2026-07-12T20:00:00.000Z' } },
  });
  return { credential: c.credential, store, keyId: c.keyId };
}

section('Private gateway: 500 when pepper is not configured');

{
  const { store, credential } = setup();
  const resp = await handlePrivateSyncGateway({
    request: makeRequest({ headers: bearer(credential) }),
    pepper: null,
    store,
  });
  assert('returns 500', resp.status === 500);
  const body = await resp.json();
  assert('body mentions pepper', /pepper/i.test(body.reason || ''));
}

section('Private gateway: 401 when no Authorization header');

{
  const { store } = setup();
  const resp = await handlePrivateSyncGateway({
    request: makeRequest({ headers: {} }),
    pepper: PEPPER,
    store,
  });
  assert('returns 401', resp.status === 401);
}

section('Private gateway: 401 when Bearer prefix is missing');

{
  const { store, credential } = setup();
  const resp = await handlePrivateSyncGateway({
    request: makeRequest({ headers: { authorization: credential } }), // no "Bearer " prefix
    pepper: PEPPER,
    store,
  });
  assert('returns 401', resp.status === 401);
}

section('Private gateway: 401 when credential is malformed');

{
  const { store } = setup();
  const resp = await handlePrivateSyncGateway({
    request: makeRequest({ headers: bearer('garbage') }),
    pepper: PEPPER,
    store,
  });
  assert('returns 401', resp.status === 401);
}

section('Private gateway: 401 when keyId is unknown');

{
  const { store, credential } = setup();
  // Credential parses but the store has no record for the keyId.
  // We need a different keyId. Use the parser to construct one.
  const fakeCred = `${CREDENTIAL_PREFIX}unknown-keyid_${'A'.repeat(43)}`;
  const resp = await handlePrivateSyncGateway({
    request: makeRequest({ headers: bearer(fakeCred) }),
    pepper: PEPPER,
    store,
  });
  assert('returns 401', resp.status === 401);
}

section('Private gateway: 401 when HMAC does not match');

{
  const { store, keyId } = setup();
  // A credential with the right keyId but wrong secret.
  const wrong = `${CREDENTIAL_PREFIX}${keyId}_${'B'.repeat(43)}`;
  const resp = await handlePrivateSyncGateway({
    request: makeRequest({ headers: bearer(wrong) }),
    pepper: PEPPER,
    store,
  });
  assert('returns 401', resp.status === 401);
}

section('Private gateway: 500 when store is unavailable');

{
  const { credential } = setup();
  const resp = await handlePrivateSyncGateway({
    request: makeRequest({ headers: bearer(credential) }),
    pepper: PEPPER,
    resolveStore: () => { throw new Error('blob context missing'); },
  });
  assert('returns 500', resp.status === 500);
  const body = await resp.json();
  assert('body mentions store', /store/i.test(body.reason || ''));
}

section('Private gateway: 200 manifest route');

{
  const { credential, store } = setup();
  const resp = await handlePrivateSyncGateway({
    request: makeRequest({ url: 'https://gateway.test/private/v1/manifest', headers: bearer(credential) }),
    pepper: PEPPER, store,
  });
  assert('returns 200', resp.status === 200);
  const body = await resp.json();
  assert('body.baselineVersion is v1', body.baselineVersion === 'v1');
  assert('body has shards', body.shards && body.shards.vulnerability);
}

section('Private gateway: 200 manifest/{version} route');

{
  const { credential, store } = setup();
  const resp = await handlePrivateSyncGateway({
    request: makeRequest({ url: 'https://gateway.test/private/v1/manifest/v1', headers: bearer(credential) }),
    pepper: PEPPER, store,
  });
  assert('returns 200', resp.status === 200);
  const body = await resp.json();
  assert('body.baselineVersion is v1', body.baselineVersion === 'v1');
}

section('Private gateway: 200 delta route');

{
  const c = generateCredential({ pepper: PEPPER, keyId: 'test-key' });
  const store = makeMemoryStore({
    manifests: { v0: { ...validManifest, baselineVersion: 'v0' }, latest: validManifest },
    deltas: { 'deltas/v0__to__v1.json': { schemaVersion: '1.0.0', baseVersion: 'v0', targetVersion: 'v1', upserts: [], tombstones: [], deltaSha256: 'a'.repeat(64) } },
    credentials: { 'credentials/test-key': { hmac: c.hmac } },
  });
  const resp = await handlePrivateSyncGateway({
    request: makeRequest({ url: 'https://gateway.test/private/v1/delta?from=v0&to=v1', headers: bearer(c.credential) }),
    pepper: PEPPER, store,
  });
  assert('returns 200', resp.status === 200);
  const body = await resp.json();
  assert('body.baseVersion is v0', body.baseVersion === 'v0');
  assert('body.targetVersion is v1', body.targetVersion === 'v1');
}

section('Private gateway: 200 shard route returns gzipped content');

{
  const { credential, store } = setup();
  const resp = await handlePrivateSyncGateway({
    request: makeRequest({ url: 'https://gateway.test/private/v1/shard?key=objects/sha256/aaa.json.gz', headers: bearer(credential) }),
    pepper: PEPPER, store,
  });
  assert('returns 200', resp.status === 200);
  assert('content-type is octet-stream', resp.headers.get('content-type') === 'application/octet-stream');
  assert('content-encoding is gzip', resp.headers.get('content-encoding') === 'gzip');
  const text = await resp.text();
  assert('body matches the stored bytes', text === 'gzipped-content');
}

section('Private gateway: 200 snapshot route includes all shards');

{
  const { credential, store } = setup();
  const resp = await handlePrivateSyncGateway({
    request: makeRequest({ url: 'https://gateway.test/private/v1/snapshot?version=v1', headers: bearer(credential) }),
    pepper: PEPPER, store,
  });
  assert('returns 200', resp.status === 200);
  const body = await resp.json();
  assert('body has manifest', body.manifest && body.manifest.baselineVersion === 'v1');
  assert('body has shards', body.shards && typeof body.shards === 'object');
  assert('body.shards has the documented shard key',
    body.shards['objects/sha256/aaa.json.gz'] !== undefined);
  // base64 of 'gzipped-content'
  const expected = Buffer.from('gzipped-content').toString('base64');
  assert('body.shards[key] is the base64-encoded gzip', body.shards['objects/sha256/aaa.json.gz'] === expected);
  assert('body.encoding.shards is documented', body.encoding && body.encoding.shards === 'base64-gzip');
}

section('Private gateway: 200 sources route');

{
  const { credential, store } = setup();
  const resp = await handlePrivateSyncGateway({
    request: makeRequest({ url: 'https://gateway.test/private/v1/sources', headers: bearer(credential) }),
    pepper: PEPPER, store,
  });
  assert('returns 200', resp.status === 200);
  const body = await resp.json();
  assert('body.sources is the documented array', Array.isArray(body.sources) && body.sources[0].id === 'osv');
}

section('Private gateway: 404 on unknown route');

{
  const { credential, store } = setup();
  const resp = await handlePrivateSyncGateway({
    request: makeRequest({ url: 'https://gateway.test/private/v1/unknown', headers: bearer(credential) }),
    pepper: PEPPER, store,
  });
  assert('returns 404', resp.status === 404);
}

section('Private gateway: 405 on POST');

{
  const { credential, store } = setup();
  const resp = await handlePrivateSyncGateway({
    request: makeRequest({ method: 'POST', url: 'https://gateway.test/private/v1/manifest', headers: bearer(credential) }),
    pepper: PEPPER, store,
  });
  assert('returns 405', resp.status === 405);
}

section('Private gateway: rejects shard-key traversal attempts');

{
  const { credential, store } = setup();
  for (const badKey of ['../etc/passwd', '../../secret', '/etc/passwd', 'keys/../bad']) {
    const resp = await handlePrivateSyncGateway({
      request: makeRequest({ url: `https://gateway.test/private/v1/shard?key=${encodeURIComponent(badKey)}`, headers: bearer(credential) }),
      pepper: PEPPER, store,
    });
    assert(`bad key '${badKey}' rejected`, resp.status === 400);
  }
}

section('Private gateway: secret is never echoed in the response');

{
  const { credential, store } = setup();
  const resp = await handlePrivateSyncGateway({
    request: makeRequest({ url: 'https://gateway.test/private/v1/manifest', headers: bearer(credential) }),
    pepper: PEPPER, store,
  });
  const text = await resp.text();
  // The credential string is in the Authorization header but
  // should never appear in the response body.
  assert('response body does not contain the credential', !text.includes(credential));
  // The random secret half (any base64url chunk) is not echoed
  // either. We test the exact credential string.
  const parsed = parseCredential(credential);
  assert('response body does not contain the random secret', !text.includes(parsed.randomSecret));
}

section('V6.0 invariant: anonymous requests can never read the canonical baseline');

{
  // Try every flavor of "visitor request" — all must 401.
  const { store } = setup();
  const visitorAttempts = [
    makeRequest({ url: 'https://gateway.test/private/v1/manifest', headers: {} }),
    makeRequest({ url: 'https://gateway.test/private/v1/manifest', headers: { authorization: '' } }),
    makeRequest({ url: 'https://gateway.test/private/v1/manifest', headers: { authorization: 'Bearer ' } }),
    makeRequest({ url: 'https://gateway.test/private/v1/snapshot?version=v1', headers: {} }),
    makeRequest({ url: 'https://gateway.test/private/v1/shard?key=objects/sha256/aaa.json.gz', headers: {} }),
  ];
  for (const req of visitorAttempts) {
    const resp = await handlePrivateSyncGateway({ request: req, pepper: PEPPER, store });
    assert(`anonymous request to ${req.url} returns 401`, resp.status === 401);
  }
}

section('Gateway config: rate limit and path are exported');

{
  assert('config.path is set', typeof config.path === 'string' && config.path === '/private/v1/*');
  assert('config.rateLimit is set', config.rateLimit && typeof config.rateLimit === 'object');
  assert('rateLimit.windowLimit is a number', typeof config.rateLimit.windowLimit === 'number');
  assert('rateLimit.windowSize is a number', typeof config.rateLimit.windowSize === 'number');
  assert('rateLimit.aggregateBy is an array',
    Array.isArray(config.rateLimit.aggregateBy) && config.rateLimit.aggregateBy.includes('ip'));
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
console.log('ALL PRIVATE-GATEWAY TESTS PASSED');
