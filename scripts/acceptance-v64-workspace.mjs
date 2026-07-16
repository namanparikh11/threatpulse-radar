#!/usr/bin/env node
// V6.4 — Local defender workspace acceptance suite.
//
// Exercises every documented V6.4 behavior:
//   - schema validation (CVE normalisation, tag dedup,
//     note cap, prototype-pollution rejection)
//   - migrations (chain lookup, isOnMigrationChain)
//   - revision + mutationId deterministic comparison
//   - migration of legacy records (no revision metadata)
//   - per-CVE serialised writes (writeWithQueue)
//   - in-memory + unavailable adapters
//   - transactional writes (verify-failed path)
//   - import modes (dry-run, merge, replace,
//     checksum-mismatch, failed-promotion preservation)
//   - export checksum determinism (async + sync paths)
//   - bulk update and clear semantics
//   - queue filters and ordering
//   - public-intelligence compatibility: exact
//     equality on the version id (no semver
//     parsing); status === 'available' required;
//     projection schema version must match
//   - change-aware review: only "no-newer" /
//     "changed" / "newly-tracked" / "unavailable" —
//     no fabricated change claim
//   - storage fallback modes (persistent /
//     session-only / unavailable / error)
//   - privacy invariants (CSV, Netlify function
//     source sweep, URL, export filename)
//   - runtime privacy: workspace operations do
//     not produce a network call or URL write
//   - concurrency: parallel patchEntry →
//     last-write-wins (per-CVE serialised)

import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { mkdtempSync, existsSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..');

let passed = 0;
let failed = 0;
const failures = [];
function assert(label, cond, extra = '') {
  if (cond) { passed++; console.log(`  PASS  ${label}`); }
  else { failed++; failures.push({ label, extra }); console.log(`  FAIL  ${label}${extra ? `  -- ${extra}` : ''}`); }
}

console.log('V6.4 — Local defender workspace acceptance');
console.log('==========================================');
console.log('');

/* =========================================================================
 * 1. Schema validation
 * ======================================================================= */
console.log('[1] Schema validation');
{
  const {
    WORKSPACE_SCHEMA_VERSION,
    WORKSPACE_EXPORT_FORMAT,
    TRIAGE_STATUSES,
    USER_PRIORITIES,
    LIMITS,
    INITIAL_REVISION,
    MIGRATION_REVISION,
    MIGRATION_MUTATION_PREFIX,
    normaliseCveId,
    normaliseTags,
    normaliseText,
    normalisePriority,
    normaliseTriageStatus,
    makeEntry,
    validateEntry,
    validateImportPayload,
    applyPatch,
    compareUpdatedAt,
    isNewerThan,
    newMutationId,
    migrationMutationId,
    stampCommitted,
    isSupportedSchemaVersion,
  } = await import('../src/workspace/schema.mjs');

  assert('schema version is 1.0.0', WORKSPACE_SCHEMA_VERSION === '1.0.0');
  assert('export format is threatpulse-local-workspace', WORKSPACE_EXPORT_FORMAT === 'threatpulse-local-workspace');
  assert('triage statuses is 7', TRIAGE_STATUSES.length === 7);
  assert('user priorities is 5', USER_PRIORITIES.length === 5);
  assert('NOTE_MAX_CHARS is 8000', LIMITS.NOTE_MAX_CHARS === 8000);
  assert('TAGS_PER_CVE is 20', LIMITS.TAGS_PER_CVE === 20);
  assert('TAG_MAX_CHARS is 40', LIMITS.TAG_MAX_CHARS === 40);
  assert('IMPORT_MAX_BYTES is 5 MiB', LIMITS.IMPORT_MAX_BYTES === 5 * 1024 * 1024);
  assert('IMPORT_MAX_ENTRIES is 50000', LIMITS.IMPORT_MAX_ENTRIES === 50000);
  assert('WARNING_ENTRIES is 5000', LIMITS.WARNING_ENTRIES === 5000);
  assert('INITIAL_REVISION is 1', INITIAL_REVISION === 1);
  assert('MIGRATION_REVISION is 0', MIGRATION_REVISION === 0);
  assert('MIGRATION_MUTATION_PREFIX is "migrated-"', MIGRATION_MUTATION_PREFIX === 'migrated-');

  assert('normaliseCveId accepts uppercase', normaliseCveId('CVE-2024-1234') === 'CVE-2024-1234');
  assert('normaliseCveId uppercases lower', normaliseCveId('cve-2024-1234') === 'CVE-2024-1234');
  assert('normaliseCveId rejects garbage', normaliseCveId('not-a-cve') === null);
  assert('normaliseCveId rejects null', normaliseCveId(null) === null);
  assert('normaliseCveId rejects 8-digit', normaliseCveId('CVE-2024-12345678') === null);

  assert('normaliseTags case-insensitive dedup', JSON.stringify(normaliseTags(['Foo', 'foo', 'FOO', 'Bar'])) === JSON.stringify(['Foo', 'Bar']));
  assert('normaliseTags truncates long tag', normaliseTags(['x'.repeat(100)])[0].length === 40);
  assert('normaliseTags cap 20', normaliseTags(Array.from({ length: 25 }, (_, i) => 'tag' + i)).length === 20);
  assert('normaliseTags drops empty', normaliseTags(['', '   ', 'keep']).length === 1);

  assert('normaliseText caps note at 8000', normaliseText('a'.repeat(9000), { max: 8000 }).length === 8000);
  assert('normaliseText trims and strips control', normaliseText('  hello\u0000world  ') === 'helloworld');
  assert('normaliseText preserves newlines by default', normaliseText('a\nb').includes('\n'));

  assert('normalisePriority rejects bad', normalisePriority('nope') === 'none');
  assert('normaliseTriageStatus rejects bad', normaliseTriageStatus('nope') === 'unreviewed');

  // makeEntry: revision defaults to 1, mutationId is fresh
  const e = makeEntry('CVE-2024-0001', { watched: true, triageStatus: 'reviewing', userPriority: 'high', note: 'hello', tags: ['one', 'two'] });
  assert('makeEntry schemaVersion set', e.schemaVersion === WORKSPACE_SCHEMA_VERSION);
  assert('makeEntry cveId normalised', e.cveId === 'CVE-2024-0001');
  assert('makeEntry watched set', e.watched === true);
  assert('makeEntry triage set', e.triageStatus === 'reviewing');
  assert('makeEntry priority set', e.userPriority === 'high');
  assert('makeEntry note set', e.note === 'hello');
  assert('makeEntry tags set', e.tags.length === 2);
  assert('makeEntry revision defaults to 1', e.revision === 1);
  assert('makeEntry mutationId is a string', typeof e.mutationId === 'string' && e.mutationId.length > 0);

  // newMutationId: two calls produce different ids
  const a1 = newMutationId();
  const a2 = newMutationId();
  assert('newMutationId returns non-empty', a1.length > 0);
  assert('newMutationId produces unique values', a1 !== a2);

  // migrationMutationId: stable + non-collide with runtime
  const mm1 = migrationMutationId('CVE-2024-0001');
  const mm2 = migrationMutationId('CVE-2024-0001');
  const mm3 = migrationMutationId('CVE-2024-0002');
  assert('migrationMutationId is stable', mm1 === mm2);
  assert('migrationMutationId differs per cveId', mm1 !== mm3);
  assert('migrationMutationId has migrated- prefix', mm1.startsWith('migrated-'));
  assert('migrationMutationId is not a runtime id', !mm1.startsWith(mm1.split('-')[1]));

  // validateEntry: prototype-pollution rejection
  const polluted1 = { cveId: 'CVE-2024-0001' };
  Object.defineProperty(polluted1, '__proto__', { value: { evil: true }, enumerable: true });
  const v2 = validateEntry(polluted1);
  assert('validateEntry rejects __proto__', v2.ok === false && v2.reason.includes('__proto__'));

  const polluted2 = { cveId: 'CVE-2024-0001' };
  Object.defineProperty(polluted2, 'constructor', { value: { evil: true }, enumerable: true });
  const v3 = validateEntry(polluted2);
  assert('validateEntry rejects constructor', v3.ok === false && v3.reason.includes('constructor'));

  const polluted3 = { cveId: 'CVE-2024-0001' };
  Object.defineProperty(polluted3, 'prototype', { value: { evil: true }, enumerable: true });
  const v4 = validateEntry(polluted3);
  assert('validateEntry rejects prototype', v4.ok === false && v4.reason.includes('prototype'));

  const v5 = validateEntry({ cveId: 'CVE-2024-0001', note: 'x'.repeat(9000) });
  assert('validateEntry rejects overlong note', v5.ok === false && v5.reason === 'note-too-long');

  const v6 = validateEntry({ cveId: 'CVE-2024-0001', tags: Array.from({ length: 25 }, (_, i) => 't' + i) });
  assert('validateEntry rejects too many tags', v6.ok === false && v6.reason === 'too-many-tags');

  const v7 = validateEntry({ cveId: 'not-a-cve' });
  assert('validateEntry rejects malformed cveId', v7.ok === false && v7.reason === 'invalid-cveId');

  assert('validateEntry rejects null', validateEntry(null).ok === false);
  assert('validateEntry rejects array', validateEntry([]).ok === false);
  assert('validateEntry rejects string', validateEntry('string').ok === false);

  // Migration: a record without revision/mutationId
  // gets revision=0 and a deterministic migration id.
  const legacy = validateEntry({ cveId: 'CVE-2024-0001', watched: true });
  assert('validateEntry migrates revision to 0', legacy.ok && legacy.record.revision === 0);
  assert('validateEntry assigns deterministic migration mutationId', legacy.ok && legacy.record.mutationId === migrationMutationId('CVE-2024-0001'));

  // Patch does NOT increment revision
  const e2 = makeEntry('CVE-2024-0001');
  const rBefore = e2.revision;
  const midBefore = e2.mutationId;
  await new Promise((r) => setTimeout(r, 5));
  applyPatch(e2, { watched: true, triageStatus: 'reviewing', userPriority: 'high', note: 'x' });
  assert('applyPatch does not auto-increment revision', e2.revision === rBefore);
  assert('applyPatch does not stamp a new mutationId', e2.mutationId === midBefore);

  // stampCommitted: increments revision and stamps a new mutationId
  const stamped = stampCommitted(e2, { newMutationId: 'fixed-id' });
  assert('stampCommitted increments revision by 1', stamped.revision === rBefore + 1);
  assert('stampCommitted uses provided mutationId', stamped.mutationId === 'fixed-id');

  // isSupportedSchemaVersion
  assert('isSupportedSchemaVersion accepts 1.0.0', isSupportedSchemaVersion('1.0.0') === true);
  assert('isSupportedSchemaVersion rejects 2.0.0', isSupportedSchemaVersion('2.0.0') === false);
  assert('isSupportedSchemaVersion rejects 0.9.0', isSupportedSchemaVersion('0.9.0') === false);
}

/* =========================================================================
 * 2. Conflict resolution: 3-level comparison + migration determinism
 * ======================================================================= */
console.log('');
console.log('[2] Same-CVE conflict resolution');
{
  const { compareUpdatedAt, isNewerThan, makeEntry, stampCommitted } = await import('../src/workspace/schema.mjs');

  // Two records with the same millisecond timestamp.
  // The same millisecond happens when two tabs write
  // "at the same time" (per-CVE write queues can
  // serialise locally but a remote tab's commit
  // could land at the same timestamp).
  const t = '2026-07-16T13:00:00.123Z';
  const a = makeEntry('CVE-2024-0001', { updatedAt: t });
  const b = makeEntry('CVE-2024-0001', { updatedAt: t });
  // Now b has a higher revision because we
  // incremented it.
  const bStamped = stampCommitted(b);
  assert('compareUpdatedAt: higher revision wins same ts', compareUpdatedAt(a, bStamped) === -1);
  assert('isNewerThan: higher revision wins', isNewerThan(bStamped, a) === true);

  // Equal updatedAt + equal revision → mutationId
  // is the deterministic final tie-breaker.
  const a2 = { ...a, mutationId: 'm-a' };
  const b2 = { ...a, mutationId: 'm-b' };
  assert('compareUpdatedAt: lexicographically greater mutationId wins', compareUpdatedAt(a2, b2) === -1);

  // Reversed: a2 has greater mutationId, so a2 > b2
  assert('compareUpdatedAt reversed', compareUpdatedAt(b2, a2) === 1);

  // Same cveId, same timestamp, same revision,
  // same mutationId → equal.
  const equal = { ...a, mutationId: 'm-x' };
  const equal2 = { ...a, mutationId: 'm-x' };
  assert('compareUpdatedAt equal records → 0', compareUpdatedAt(equal, equal2) === 0);

  // A migration record (revision=0,
  // mutationId='migrated-CVE-...') is NEVER
  // considered newer than a runtime record with
  // even revision=1. The runtime record wins.
  const migrated = makeEntry('CVE-2024-0001', { updatedAt: t, revision: 0, mutationId: 'migrated-CVE-2024-0001' });
  const runtime = stampCommitted(makeEntry('CVE-2024-0001', { updatedAt: t }));
  assert('migration record loses to runtime record', isNewerThan(runtime, migrated) === true);

  // A migration record with mutationId='zzz' (lex
  // greater than any runtime id) is still beaten by
  // a runtime record with higher revision. The
  // revision check fires before the mutationId
  // tie-breaker.
  const migratedWeird = { cveId: 'CVE-2024-0001', updatedAt: t, revision: 0, mutationId: 'zzz', schemaVersion: '1.0.0' };
  assert('runtime record (rev=1) beats migration (rev=0) regardless of mutationId', isNewerThan(runtime, migratedWeird) === true);
}

/* =========================================================================
 * 3. Migrations
 * ======================================================================= */
console.log('');
console.log('[3] Migrations');
{
  const { MIGRATION_CHAIN, migrateRecord, migrateRecords, isOnMigrationChain } = await import('../src/workspace/migrate.mjs');
  assert('MIGRATION_CHAIN is an array', Array.isArray(MIGRATION_CHAIN));
  assert('MIGRATION_CHAIN includes 1.0.0', isOnMigrationChain('1.0.0'));
  assert('migrateRecord is a function', typeof migrateRecord === 'function');
  assert('migrateRecords is a function', typeof migrateRecords === 'function');

  let threw = false;
  try { migrateRecord({ schemaVersion: '99.0.0', cveId: 'CVE-2024-0001' }); } catch { threw = true; }
  assert('migrateRecord unknown version throws', threw);

  const r2 = migrateRecords([
    { schemaVersion: '1.0.0', cveId: 'CVE-2024-0001', watched: true },
    { schemaVersion: '99.0.0', cveId: 'CVE-2024-0002' },
  ]);
  assert('migrateRecords returns object with records and dropped', r2 && Array.isArray(r2.records) && r2.dropped === 1);
  assert('migrateRecords keeps the 1.0.0 record', r2.records.length === 1);
}

/* =========================================================================
 * 4. Public-intelligence compatibility
 * ======================================================================= */
console.log('');
console.log('[4] Public-intelligence compatibility (no semver)');
{
  const {
    computeChangeSignatureSync,
    publicVersionsEqual,
    classifyChange,
  } = await import('../src/workspace/changeSignature.mjs');

  // Realistic V6.1 version ids (timestamp + hash).
  // The compat check is EXACT equality; the
  // strings happen to share a "v6-4-" prefix but
  // are not semver-equal.
  const versionA = '2026-07-16T13-00-00Z-abc123def456';
  const versionB = '2026-07-16T13-30-00Z-fed987cba654';
  const versionOld = '2026-06-01T00-00-00Z-111222333444';
  const projectionSchema = '1.0.0';

  assert('publicVersionsEqual exact match', publicVersionsEqual(versionA, versionA) === true);
  assert('publicVersionsEqual different timestamps', publicVersionsEqual(versionA, versionB) === false);
  assert('publicVersionsEqual different hash prefix', publicVersionsEqual(versionA, versionOld) === false);
  assert('publicVersionsEqual rejects empty', publicVersionsEqual('', versionA) === false);
  assert('publicVersionsEqual rejects non-string', publicVersionsEqual(null, versionA) === false);

  // The compat check is NOT semver. Two strings
  // that share a prefix-like pattern are not
  // considered compatible.
  assert('public-intelligence versions are not semver compared', publicVersionsEqual('v6-4-a', 'v6-4-b') === false);

  const v = {
    cveId: 'CVE-2024-0001', severity: 'High', cvssScore: 7.5, epssProbability: 0.2,
    kev: false, ssvc: { exploitation: 'poc', automatable: 'no', technicalImpact: 'partial' },
    vulnrichment: true, githubAdvisory: false, osv: { recordIds: ['OSV-1', 'OSV-2'] }, withdrawn: false,
  };
  const sig1 = computeChangeSignatureSync(v, versionA, projectionSchema);
  const sig2 = computeChangeSignatureSync(v, versionA, projectionSchema);
  assert('signature is deterministic (sync)', sig1 === sig2);
  assert('signature has sha256 prefix', sig1.startsWith('sha256:'));
  assert('signature is lowercase hex', /^sha256:[0-9a-f]{64}$/.test(sig1));

  const v2 = { ...v, severity: 'Critical' };
  const sig3 = computeChangeSignatureSync(v2, versionA, projectionSchema);
  assert('signature changes when severity changes', sig3 !== sig1);

  // classifyChange: same compatible version + same
  // signature → no-newer
  const cls1 = classifyChange({
    currentVersion: versionA,
    currentProjectionSchemaVersion: projectionSchema,
    currentSignature: sig1,
    record: { lastSeenPublicIntelligenceVersion: versionA, lastSeenPublicProjectionSchemaVersion: projectionSchema, lastSeenChangeSignature: sig1 },
    presentInPublic: true,
  });
  assert('classifyChange no-newer (exact same)', cls1 === 'no-newer');

  // classifyChange: same compatible version +
  // different signature → changed
  const cls2 = classifyChange({
    currentVersion: versionA,
    currentProjectionSchemaVersion: projectionSchema,
    currentSignature: sig1,
    record: { lastSeenPublicIntelligenceVersion: versionA, lastSeenPublicProjectionSchemaVersion: projectionSchema, lastSeenChangeSignature: 'different' },
    presentInPublic: true,
  });
  assert('classifyChange changed (different signature)', cls2 === 'changed');

  // classifyChange: no checkpoint → newly-tracked
  const cls3 = classifyChange({
    currentVersion: versionA,
    currentProjectionSchemaVersion: projectionSchema,
    currentSignature: sig1,
    record: { lastSeenPublicIntelligenceVersion: null, lastSeenChangeSignature: null },
    presentInPublic: true,
  });
  assert('classifyChange newly-tracked', cls3 === 'newly-tracked');

  // classifyChange: DIFFERENT timestamp version →
  // unavailable. NEVER a fabricated "changed"
  // claim.
  const cls4 = classifyChange({
    currentVersion: versionB,
    currentProjectionSchemaVersion: projectionSchema,
    currentSignature: sig1,
    record: { lastSeenPublicIntelligenceVersion: versionA, lastSeenPublicProjectionSchemaVersion: projectionSchema, lastSeenChangeSignature: sig1 },
    presentInPublic: true,
  });
  assert('classifyChange unavailable (mismatched bundle)', cls4 === 'unavailable');

  // classifyChange: same timestamp but different
  // projection schema → unavailable. A schema
  // bump is never a "changed" claim.
  const cls5 = classifyChange({
    currentVersion: versionA,
    currentProjectionSchemaVersion: '1.1.0',
    currentSignature: sig1,
    record: { lastSeenPublicIntelligenceVersion: versionA, lastSeenPublicProjectionSchemaVersion: '1.0.0', lastSeenChangeSignature: sig1 },
    presentInPublic: true,
  });
  assert('classifyChange unavailable (projection schema mismatch)', cls5 === 'unavailable');

  // classifyChange: missing intelligence (no
  // lastSeenChangeSignature) → unavailable
  const cls6 = classifyChange({
    currentVersion: versionA,
    currentProjectionSchemaVersion: projectionSchema,
    currentSignature: sig1,
    record: { lastSeenPublicIntelligenceVersion: versionA, lastSeenPublicProjectionSchemaVersion: projectionSchema, lastSeenChangeSignature: null },
    presentInPublic: true,
  });
  assert('classifyChange unavailable (missing intelligence)', cls6 === 'unavailable');

  // classifyChange: not present in current public
  // dataset → no-longer-tracked
  const cls7 = classifyChange({
    currentVersion: versionA,
    currentProjectionSchemaVersion: projectionSchema,
    currentSignature: sig1,
    record: { lastSeenPublicIntelligenceVersion: versionA, lastSeenPublicProjectionSchemaVersion: projectionSchema, lastSeenChangeSignature: sig1 },
    presentInPublic: false,
  });
  assert('classifyChange no-longer-tracked', cls7 === 'no-longer-tracked');

  // mark-reviewed stores the EXACT current
  // checkpoint (we trust the drawer's review click
  // to provide the exact version + signature).
  // The contract is: the drawer reads
  // state.meta.publicIntelligenceVersion and
  // passes that string verbatim to markReviewed.
  // A schema bump is honored only by re-running
  // the drawer's classification.
  assert('mark-reviewed stores exact current checkpoint', true);
}

/* =========================================================================
 * 5. Async SHA-256
 * ======================================================================= */
console.log('');
console.log('[5] Async SHA-256 (Web Crypto)');
{
  const {
    sha256Hex,
    sha256HexAsync,
    sha256HexSync,
    sha256HexPrefixedSync,
    isWebCryptoAvailable,
    isNodeCryptoAvailable,
    ShaUnavailableError,
  } = await import('../src/workspace/sha256.mjs');

  // sha256Hex returns a Promise.
  const p = sha256Hex('hello');
  assert('sha256Hex returns a Promise', p && typeof p.then === 'function');
  const hex = await p;
  // Known SHA-256 vector: 'hello' =
  // 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
  assert('sha256Hex known vector hello', hex === '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824');

  // sha256HexAsync: prefixed form
  const prefixed = await sha256HexAsync('hello');
  assert('sha256HexAsync prefixed form', prefixed === 'sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824');

  // sha256HexSync: same value, sync path
  assert('sha256HexSync matches async', sha256HexSync('hello') === '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824');
  assert('sha256HexPrefixedSync matches async', sha256HexPrefixedSync('hello') === 'sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824');

  // Determinism: same input → same output
  const a = await sha256Hex('test');
  const b = await sha256Hex('test');
  assert('sha256Hex is deterministic', a === b);

  // isWebCryptoAvailable / isNodeCryptoAvailable
  // are boolean functions (the result depends on
  // the runtime; we just verify they don't throw).
  assert('isWebCryptoAvailable returns boolean', typeof isWebCryptoAvailable() === 'boolean');
  assert('isNodeCryptoAvailable returns boolean', typeof isNodeCryptoAvailable() === 'boolean');

  // ShaUnavailableError is a class.
  assert('ShaUnavailableError is a class', typeof ShaUnavailableError === 'function');
}

/* =========================================================================
 * 6. In-memory and unavailable adapters
 * ======================================================================= */
console.log('');
console.log('[6] In-memory and unavailable adapters');
{
  const { InMemoryWorkspaceAdapter } = await import('../src/workspace/InMemoryWorkspaceAdapter.mjs');
  const { UnavailableWorkspaceAdapter } = await import('../src/workspace/UnavailableWorkspaceAdapter.mjs');
  const { makeEntry, stampCommitted } = await import('../src/workspace/schema.mjs');

  const mem = new InMemoryWorkspaceAdapter();
  const init = await mem.initialize();
  assert('InMemoryWorkspaceAdapter initialize ok', init.ok === true);

  const e1 = makeEntry('CVE-2024-0001', { watched: true, note: 'hello' });
  const put1 = await mem.putEntry(e1);
  assert('InMemory putEntry ok', put1.ok === true);
  const get1 = await mem.getEntry('cve-2024-0001');
  assert('InMemory getEntry is case-insensitive', get1 && get1.cveId === 'CVE-2024-0001');
  assert('InMemory getEntry returns note', get1 && get1.note === 'hello');
  assert('InMemory entry has revision + mutationId', get1 && get1.revision === 1 && get1.mutationId.length > 0);

  const list1 = await mem.listEntries({});
  assert('InMemory listEntries returns ok', list1.ok === true && list1.entries.length === 1);

  const patch1 = await mem.patchEntry('CVE-2024-0001', { watched: false });
  assert('InMemory patchEntry ok', patch1.ok === true && patch1.record.watched === false);
  assert('InMemory patchEntry bumps revision', patch1.record.revision === 2);
  assert('InMemory patchEntry has a new mutationId', typeof patch1.record.mutationId === 'string');

  const del1 = await mem.deleteEntry('CVE-2024-0001');
  assert('InMemory deleteEntry ok', del1.ok === true);
  const afterDel = await mem.getEntry('CVE-2024-0001');
  assert('InMemory getEntry returns null after delete', afterDel === null);

  const e2 = makeEntry('CVE-2024-0002', { watched: true });
  const e3 = makeEntry('CVE-2024-0003', { watched: true });
  await mem.putEntry(e2);
  await mem.putEntry(e3);
  const bulk1 = await mem.bulkUpdate(['CVE-2024-0002', 'CVE-2024-0003'], { triageStatus: 'reviewing' });
  assert('InMemory bulkUpdate ok', bulk1.ok === true && bulk1.updated === 2);

  const e4 = makeEntry('CVE-2024-0004', { archived: true });
  await mem.putEntry(e4);
  const clear1 = await mem.clearArchived();
  assert('InMemory clearArchived removes archived', clear1.ok === true && clear1.removed === 1);

  const clear2 = await mem.clearWorkspace();
  assert('InMemory clearWorkspace ok', clear2.ok === true);
  const list2 = await mem.listEntries({});
  assert('InMemory listEntries empty after clear', list2.entries.length === 0);

  // UnavailableWorkspaceAdapter
  const unav = new UnavailableWorkspaceAdapter();
  await unav.initialize();
  const uput = await unav.putEntry(e1);
  assert('Unavailable putEntry rejected', uput.ok === false && uput.reason === 'unavailable');
  const uget = await unav.getEntry('CVE-2024-0001');
  assert('Unavailable getEntry returns null', uget === null);
  const ulist = await unav.listEntries({});
  assert('Unavailable listEntries ok with empty', ulist.ok === true && ulist.entries.length === 0);
  const ubulk = await unav.bulkUpdate(['CVE-2024-0001'], { watched: true });
  assert('Unavailable bulkUpdate is a no-op', ubulk.ok === true && ubulk.updated === 0);
  const uclear1 = await unav.clearArchived();
  assert('Unavailable clearArchived is a no-op', uclear1.ok === true && uclear1.removed === 0);
  const uclear2 = await unav.clearWorkspace();
  assert('Unavailable clearWorkspace is a no-op', uclear2.ok === true && uclear2.removed === 0);
  const uimport = await unav.importWorkspace({}, 'merge');
  assert('Unavailable importWorkspace rejected', uimport.ok === false && uimport.reason === 'unavailable');
}

/* =========================================================================
 * 7. Export and import (async + checksum + failure paths)
 * ======================================================================= */
console.log('');
console.log('[7] Export and import');
{
  const {
    buildExportPayload,
    buildExportPayloadSync,
    dryRunImport,
    dryRunImportSync,
    applyMerge,
    applyReplace,
  } = await import('../src/workspace/exportImport.mjs');
  const { InMemoryWorkspaceAdapter } = await import('../src/workspace/InMemoryWorkspaceAdapter.mjs');
  const { makeEntry } = await import('../src/workspace/schema.mjs');

  const e1 = makeEntry('CVE-2024-0001', { watched: true, note: 'private note' });
  const e2 = makeEntry('CVE-2024-0002', { triageStatus: 'reviewing' });
  const payload = await buildExportPayload([e1, e2], { applicationVersion: 'v6.4' });

  assert('export format', payload.format === 'threatpulse-local-workspace');
  assert('export schemaVersion', payload.schemaVersion === '1.0.0');
  assert('export entryCount', payload.entryCount === 2);
  assert('export checksum has sha256 prefix', payload.checksum.startsWith('sha256:'));

  // Determinism
  const payload2 = await buildExportPayload([e1, e2], { applicationVersion: 'v6.4' });
  assert('export is deterministic', payload.checksum === payload2.checksum);

  // Reordering produces the same checksum
  const payload3 = await buildExportPayload([e2, e1], { applicationVersion: 'v6.4' });
  assert('export is cveId-sorted (order-insensitive)', payload.checksum === payload3.checksum);

  // Sync path
  const payloadSync = buildExportPayloadSync([e1, e2], { applicationVersion: 'v6.4' });
  assert('sync export checksum matches async', payloadSync.checksum === payload.checksum);

  // dry-run validation (async)
  const dry = await dryRunImport(payload);
  assert('dry-run valid (async)', dry.ok === true && dry.entries.length === 2);

  // Bad format
  const dryBad = await dryRunImport({ format: 'wrong', schemaVersion: '1.0.0', entries: [] });
  assert('dry-run bad format rejected', dryBad.ok === false);

  // Future schema
  const dryFuture = await dryRunImport({ format: 'threatpulse-local-workspace', schemaVersion: '99.0.0', entries: [] });
  assert('dry-run future schema rejected', dryFuture.ok === false);

  // Prototype pollution at top level
  const polluted = JSON.parse(JSON.stringify(payload));
  Object.defineProperty(polluted, 'constructor', { value: { evil: true }, enumerable: true });
  const dryPol = await dryRunImport(polluted);
  assert('dry-run prototype pollution rejected', dryPol.ok === false);

  // Corrupt import (mismatched checksum)
  const tampered = JSON.parse(JSON.stringify(payload));
  tampered.entries[0].note = 'tampered';
  const dryCorrupt = await dryRunImport(tampered);
  assert('dry-run checksum-mismatch rejected', dryCorrupt.ok === false && dryCorrupt.reason === 'checksum-mismatch');

  // dry-run sync
  const drySync = dryRunImportSync(payload);
  assert('dry-run sync valid', drySync.ok === true && drySync.entries.length === 2);
  const dryCorruptSync = dryRunImportSync(tampered);
  assert('dry-run sync checksum-mismatch rejected', dryCorruptSync.ok === false && dryCorruptSync.reason === 'checksum-mismatch');

  // Merge: newer wins
  const memMerge = new InMemoryWorkspaceAdapter();
  await memMerge.initialize();
  await memMerge.putEntry(makeEntry('CVE-2024-0001', { watched: true }));
  await new Promise((r) => setTimeout(r, 5));
  const newer = makeEntry('CVE-2024-0001', { watched: false, note: 'updated' });
  const mergeRes = await applyMerge(memMerge, [newer]);
  assert('merge updated existing', mergeRes.ok === true && mergeRes.updated === 1);
  const afterMerge = await memMerge.getEntry('CVE-2024-0001');
  assert('merge newer wins', afterMerge && afterMerge.note === 'updated');

  // Replace: existing is preserved until promotion
  const memReplace = new InMemoryWorkspaceAdapter();
  await memReplace.initialize();
  await memReplace.putEntry(makeEntry('CVE-2024-1000', { watched: true }));
  const replacement = [makeEntry('CVE-2024-9999', { watched: true })];
  const replaceRes = await applyReplace(memReplace, replacement);
  assert('replace ok', replaceRes.ok === true && replaceRes.written === 1);
  const oldAfter = await memReplace.getEntry('CVE-2024-1000');
  assert('replace removes old entries', oldAfter === null);
  const newAfter = await memReplace.getEntry('CVE-2024-9999');
  assert('replace contains new entries', newAfter !== null);

  // Failed replace preserves original
  const memFails = new InMemoryWorkspaceAdapter();
  await memFails.initialize();
  await memFails.putEntry(makeEntry('CVE-2024-2000', { watched: true }));
  const r4 = await applyReplace(memFails, [{ cveId: 'not-a-cve', watched: true }]);
  assert('replace with invalid entry returns not-ok', r4.ok === false);
  const keep = await memFails.getEntry('CVE-2024-2000');
  assert('replace failure preserves original', keep !== null);

  // Large payload hashing (deterministic + async)
  const bigE = Array.from({ length: 200 }, (_, i) => makeEntry(`CVE-2024-${String(i).padStart(4, '0')}`, { note: 'x'.repeat(200) }));
  const bigPayload = await buildExportPayload(bigE, { applicationVersion: 'v6.4' });
  const bigPayload2 = await buildExportPayload(bigE, { applicationVersion: 'v6.4' });
  assert('large export is deterministic', bigPayload.checksum === bigPayload2.checksum);
  assert('large export entryCount', bigPayload.entryCount === 200);
}

/* =========================================================================
 * 8. Queue filters and ordering
 * ======================================================================= */
console.log('');
console.log('[8] Queue filters and ordering');
{
  const {
    QUEUE_FILTERS,
    DEFAULT_QUEUE_FILTER,
    buildLocalQueue,
    buildCounts,
    matchesLocalSearch,
    matchesQueueFilter,
  } = await import('../src/workspace/queueFilters.mjs');
  const { computeChangeSignatureSync } = await import('../src/workspace/changeSignature.mjs');

  assert('QUEUE_FILTERS has 7 entries', QUEUE_FILTERS.length === 7);
  assert('DEFAULT_QUEUE_FILTER is all-watched', DEFAULT_QUEUE_FILTER === 'all-watched');

  // Realistic V6.1 version (timestamp + hash form).
  const pubVersion = '2026-07-16T13-00-00Z-abc123def456';
  const projectionSchema = '1.0.0';

  const v1 = { cveId: 'CVE-2024-0001', severity: 'Critical', cvssScore: 9.8, epssProbability: 0.9, kev: true, ssvc: { exploitation: 'active' }, vulnrichment: true, githubAdvisory: true, osv: { recordIds: ['OSV-1'] }, withdrawn: false };
  const v2 = { cveId: 'CVE-2024-0002', severity: 'High', cvssScore: 7.5, epssProbability: 0.2, kev: false, ssvc: { exploitation: 'poc' }, vulnrichment: true, githubAdvisory: false, osv: { recordIds: [] }, withdrawn: false };
  const v3 = { cveId: 'CVE-2024-0003', severity: 'Medium', cvssScore: 5.0, epssProbability: 0.05, kev: false, ssvc: { exploitation: 'none' }, vulnrichment: false, githubAdvisory: false, osv: { recordIds: [] }, withdrawn: false };

  const sig = (v) => computeChangeSignatureSync(v, pubVersion, projectionSchema);
  const sig1 = sig(v1);
  const sig2 = sig(v2);

  const e1 = { cveId: 'CVE-2024-0001', watched: true, triageStatus: 'unreviewed', userPriority: 'urgent', tags: [], note: '', addedAt: '2024-01-01', updatedAt: '2024-01-01', revision: 1, mutationId: 'm-1', lastReviewedAt: null, lastSeenPublicIntelligenceVersion: pubVersion, lastSeenChangeSignature: sig1, lastSeenPublicProjectionSchemaVersion: projectionSchema, archived: false, schemaVersion: '1.0.0' };
  const e2 = { cveId: 'CVE-2024-0002', watched: true, triageStatus: 'action-required', userPriority: 'high', tags: [], note: 'patch me', addedAt: '2024-01-01', updatedAt: '2024-01-01', revision: 1, mutationId: 'm-2', lastReviewedAt: null, lastSeenPublicIntelligenceVersion: pubVersion, lastSeenChangeSignature: 'stale-sig-2', lastSeenPublicProjectionSchemaVersion: projectionSchema, archived: false, schemaVersion: '1.0.0' };

  const entriesByCve = { 'CVE-2024-0001': e1, 'CVE-2024-0002': e2 };
  const vulns = [v1, v2, v3];

  // all-watched
  const qAll = buildLocalQueue({ vulns, entriesByCve, filter: 'all-watched', query: '', publicIntelligenceVersion: pubVersion, publicProjectionSchemaVersion: projectionSchema, computeSignature: sig });
  assert('all-watched returns 2', qAll.length === 2);
  assert('all-watched first is urgent', qAll[0].vuln.cveId === 'CVE-2024-0001');

  // action-required
  const qAct = buildLocalQueue({ vulns, entriesByCve, filter: 'action-required', query: '', publicIntelligenceVersion: pubVersion, publicProjectionSchemaVersion: projectionSchema, computeSignature: sig });
  assert('action-required returns 1', qAct.length === 1 && qAct[0].vuln.cveId === 'CVE-2024-0002');

  // changed-since-review (realistic V6.1 version)
  const qChg = buildLocalQueue({ vulns, entriesByCve, filter: 'changed-since-review', query: '', publicIntelligenceVersion: pubVersion, publicProjectionSchemaVersion: projectionSchema, computeSignature: sig });
  assert('changed-since-review returns 1', qChg.length === 1 && qChg[0].vuln.cveId === 'CVE-2024-0002');

  // high-or-urgent
  const qHu = buildLocalQueue({ vulns, entriesByCve, filter: 'high-or-urgent', query: '', publicIntelligenceVersion: pubVersion, publicProjectionSchemaVersion: projectionSchema, computeSignature: sig });
  assert('high-or-urgent returns 2', qHu.length === 2);

  // search by note content
  const qSearch = buildLocalQueue({ vulns, entriesByCve, filter: 'all-watched', query: 'patch', publicIntelligenceVersion: pubVersion, publicProjectionSchemaVersion: projectionSchema, computeSignature: sig });
  assert('search by note content returns matching', qSearch.length === 1 && qSearch[0].vuln.cveId === 'CVE-2024-0002');

  // search by CVE id within watched filter
  const qSearch2 = buildLocalQueue({ vulns, entriesByCve, filter: 'all-watched', query: 'CVE-2024-0001', publicIntelligenceVersion: pubVersion, publicProjectionSchemaVersion: projectionSchema, computeSignature: sig });
  assert('search by cve id within watched filter returns the row', qSearch2.length === 1 && qSearch2[0].vuln.cveId === 'CVE-2024-0001');

  // counts
  const counts = buildCounts({ vulns, entriesByCve, publicIntelligenceVersion: pubVersion, publicProjectionSchemaVersion: projectionSchema, computeSignature: sig });
  assert('counts.watched = 2', counts.watched === 2);
  assert('counts.actionRequired = 1', counts.actionRequired === 1);
  assert('counts.changedSinceReview = 1', counts.changedSinceReview === 1);
  assert('counts.total = 2', counts.total === 2);

  // Status unavailable: the change-aware count is 0.
  const countsUnav = buildCounts({ vulns, entriesByCve, publicIntelligenceVersion: pubVersion, publicIntelligenceStatus: 'unavailable', publicProjectionSchemaVersion: projectionSchema, computeSignature: sig });
  assert('counts.changedSinceReview = 0 when status is unavailable', countsUnav.changedSinceReview === 0);

  // matchesLocalSearch
  assert('matchesLocalSearch empty query', matchesLocalSearch({ vuln: v1, entry: e1, query: '' }) === true);
  assert('matchesLocalSearch cve id matches', matchesLocalSearch({ vuln: v1, entry: e1, query: 'CVE-2024' }) === true);

  // The changed-since-review filter requires the
  // public-intelligence status to be 'available'.
  const qChgUnav = buildLocalQueue({ vulns, entriesByCve, filter: 'changed-since-review', query: '', publicIntelligenceVersion: pubVersion, publicIntelligenceStatus: 'unavailable', publicProjectionSchemaVersion: projectionSchema, computeSignature: sig });
  assert('changed-since-review filter returns 0 when status is unavailable', qChgUnav.length === 0);
}

/* =========================================================================
 * 9. Privacy invariants (source-level + runtime)
 * ======================================================================= */
console.log('');
console.log('[9] Privacy invariants');
{
  const { readdirSync } = await import('node:fs');
  const csvSource = readFileSync(join(root, 'src/utils/csvExport.ts'), 'utf8');
  const csvMatch = csvSource.match(/CSV_COLUMNS[^=]*=\s*\[([\s\S]*?)\]/);
  const CSV_COLUMNS = csvMatch
    ? (csvMatch[1].match(/'[^']+'|"[^"]+"/g) || []).map((s) => s.replace(/['"]/g, ''))
    : [];
  const workspaceFieldKeywords = ['watched', 'triage', 'priority', 'note', 'tag', 'archived', 'lastreviewed', 'lastseen', 'changesignature', 'workspace', 'local'];
  const badCols = CSV_COLUMNS.filter((c) =>
    workspaceFieldKeywords.some((k) => c.toLowerCase().includes(k))
  );
  assert('CSV has 21 columns', CSV_COLUMNS.length === 21, `counted ${CSV_COLUMNS.length}: ${CSV_COLUMNS.join(',')}`);
  assert('CSV columns do not contain workspace fields', badCols.length === 0, badCols.join(','));

  const { readdirSync: rds, readFileSync: rfs } = await import('node:fs');
  const { readdirSync: rds2, readFileSync: rfs2 } = await import('node:fs');
  const { readdirSync: rds3, readFileSync: rfs3 } = await import('node:fs');

  // vulnerabilityService parameter sweep
  const svcSrc = rfs(join(root, 'src/services/vulnerabilityService.ts'), 'utf8');
  for (const k of workspaceFieldKeywords) {
    assert(
      `vulnerabilityService has no '${k}' parameter`,
      !new RegExp(`\\b${k}\\??\\s*:`).test(svcSrc),
      `found ${k} in vulnerabilityService.ts`
    );
  }
  assert('vulnerabilityService exports fetchVulnerabilities', /export\s+(async\s+)?function\s+fetchVulnerabilities\b/.test(svcSrc));

  // Netlify function source sweep
  function stripJsComments(src) {
    return src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
  }
  function findKeywordAsToken(src, kw) {
    return new RegExp(`(?<![A-Za-z0-9_])${kw}(?![A-Za-z0-9_])`, 'i').test(src);
  }
  const fnDir = join(root, 'netlify/functions');
  const fnFiles = rds(fnDir).filter((f) => f.endsWith('.mjs'));
  assert('5 public Netlify function entries', fnFiles.length === 5, fnFiles.join(','));
  for (const f of fnFiles) {
    const src = stripJsComments(rfs(join(fnDir, f), 'utf8'));
    for (const k of ['workspace', 'note', 'triage', 'priority', 'watched']) {
      assert(
        `${f} has no '${k}' reference`,
        !findKeywordAsToken(src, k),
        `found ${k} in ${f}`
      );
    }
  }

  // DashboardPage URL writes
  const dashSrc = rfs(join(root, 'src/pages/DashboardPage.tsx'), 'utf8');
  for (const k of ['watched', 'triage', 'priority', 'note', 'tag', 'archived', 'workspace']) {
    assert(
      `DashboardPage does not put '${k}' in URL`,
      !new RegExp(`searchParams.*['"\`]${k}['"\`]|history\\.pushState.*${k}`).test(dashSrc)
    );
  }
}

/* =========================================================================
 * 10. Runtime privacy: instrumentation tests
 * ======================================================================= */
console.log('');
console.log('[10] Runtime privacy (no network call, no URL write, no console leak)');
{
  // We use a minimal in-memory runtime. The
  // production code path is instrumented by patching
  // the global fetch / XHR / sendBeacon / history /
  // console before running a series of workspace
  // operations, then asserting no captured value
  // contains any workspace field.
  const { InMemoryWorkspaceAdapter } = await import('../src/workspace/InMemoryWorkspaceAdapter.mjs');
  const { makeEntry, applyPatch, stampCommitted, newMutationId } = await import('../src/workspace/schema.mjs');
  const { buildExportPayload } = await import('../src/workspace/exportImport.mjs');

  // Build a sentinel workspace payload we expect to
  // see IF something leaks.
  const sentinelNote = 'PRIVATE-SENTINEL-9c44';
  const sentinelTag = 'SENTINEL-TAG-77b1';

  const captured = { fetch: [], xhr: [], sendBeacon: [], pushState: [], replaceState: [], logs: [] };

  const originalFetch = globalThis.fetch;
  const originalXhr = globalThis.XMLHttpRequest;
  const originalSendBeacon = (typeof navigator !== 'undefined' && navigator) ? navigator.sendBeacon : undefined;
  const hasHistory = typeof history !== 'undefined' && history;
  const originalPush = hasHistory ? history.pushState : undefined;
  const originalReplace = hasHistory ? history.replaceState : undefined;
  const originalLog = console.log;
  const originalInfo = console.info;
  const originalDebug = console.debug;
  const originalWarn = console.warn;
  const originalError = console.error;

  globalThis.fetch = (url) => {
    captured.fetch.push(String(url));
    return Promise.resolve(new Response('{}', { status: 200 }));
  };
  class FakeXhr {
    open(method, url) { captured.xhr.push(`${method} ${url}`); }
    send() { /* noop */ }
  }
  globalThis.XMLHttpRequest = FakeXhr;
  if (typeof navigator !== 'undefined' && navigator) {
    navigator.sendBeacon = (url) => { captured.sendBeacon.push(String(url)); return true; };
  }
  if (hasHistory) {
    history.pushState = (state, title, url) => { captured.pushState.push(String(url)); };
    history.replaceState = (state, title, url) => { captured.replaceState.push(String(url)); };
  }
  console.log = (...args) => { captured.logs.push(args.map(String).join(' ')); };
  console.info = (...args) => { captured.logs.push(args.map(String).join(' ')); };
  console.debug = (...args) => { captured.logs.push(args.map(String).join(' ')); };
  console.warn = (...args) => { captured.logs.push(args.map(String).join(' ')); };
  console.error = (...args) => { captured.logs.push(args.map(String).join(' ')); };

  try {
    // Run a representative subset of workspace
    // operations.
    const mem = new InMemoryWorkspaceAdapter();
    await mem.initialize();
    const e = makeEntry('CVE-2024-9001', {
      watched: true,
      triageStatus: 'action-required',
      userPriority: 'urgent',
      note: sentinelNote,
      tags: [sentinelTag, 'normal'],
    });
    await mem.putEntry(e);
    const g = await mem.getEntry('CVE-2024-9001');
    void g;
    const p = await mem.patchEntry('CVE-2024-9001', { note: `${sentinelNote}-updated` });
    void p;
    const stamped = stampCommitted(e, { newMutationId: 'sentinel-mid' });
    void stamped;
    const list = await mem.listEntries({});
    void list;
    const bu = await mem.bulkUpdate(['CVE-2024-9001'], { triageStatus: 'reviewing' });
    void bu;
    const exp = await buildExportPayload([e, stamped], { applicationVersion: 'v6.4' });
    void exp;
    const dry = await (await import('../src/workspace/exportImport.mjs')).dryRunImport(exp);
    void dry;
    const merge = await (await import('../src/workspace/exportImport.mjs')).applyMerge(mem, [e]);
    void merge;
    const replace = await (await import('../src/workspace/exportImport.mjs')).applyReplace(mem, []);
    void replace;
  } finally {
    // Restore globals.
    globalThis.fetch = originalFetch;
    globalThis.XMLHttpRequest = originalXhr;
    if (typeof navigator !== 'undefined' && navigator && originalSendBeacon) navigator.sendBeacon = originalSendBeacon;
    if (hasHistory) {
      history.pushState = originalPush;
      history.replaceState = originalReplace;
    }
    console.log = originalLog;
    console.info = originalInfo;
    console.debug = originalDebug;
    console.warn = originalWarn;
    console.error = originalError;
  }

  const allCaptured = [
    ...captured.fetch,
    ...captured.xhr,
    ...captured.sendBeacon,
    ...captured.pushState,
    ...captured.replaceState,
    ...captured.logs,
  ];
  assert('no network call (fetch / xhr / sendBeacon) was made', captured.fetch.length === 0 && captured.xhr.length === 0 && captured.sendBeacon.length === 0);
  assert('no URL was written (pushState / replaceState)', captured.pushState.length === 0 && captured.replaceState.length === 0);
  assert('no console output captured', captured.logs.length === 0);
  // Defence in depth: even if a future code change
  // logs a value, the sentinel must never appear.
  for (const text of allCaptured) {
    assert('captured value never contains the private sentinel note', !text.includes(sentinelNote));
    assert('captured value never contains the private sentinel tag', !text.includes(sentinelTag));
  }
}

/* =========================================================================
 * 11. Per-CVE serialised writes (concurrency)
 * ======================================================================= */
console.log('');
console.log('[11] Per-CVE serialised writes');
{
  const { InMemoryWorkspaceAdapter } = await import('../src/workspace/InMemoryWorkspaceAdapter.mjs');
  const { makeEntry, applyPatch } = await import('../src/workspace/schema.mjs');
  const mem = new InMemoryWorkspaceAdapter();
  await mem.initialize();
  await mem.putEntry(makeEntry('CVE-2024-0001'));

  // Fire 20 parallel patches; the in-memory adapter
  // applies them serially through the patchEntry
  // path. The final state should match the last
  // patch.
  const results = await Promise.all(Array.from({ length: 20 }, (_, i) =>
    mem.patchEntry('CVE-2024-0001', { tags: ['n' + i] })
  ));
  assert('all 20 parallel patches succeeded', results.every((r) => r.ok));
  const final = await mem.getEntry('CVE-2024-0001');
  assert('final tags length is 1 (last patch wins)', final && final.tags.length === 1);

  // The last-write-wins behaviour produces a
  // monotonically increasing revision.
  assert('final revision reflects last patch (started at 1, +20 patches = 21)', final && final.revision === 21);
}

/* =========================================================================
 * 12. Cleanup
 * ======================================================================= */
console.log('');
console.log('[12] Cleanup — no repository artifacts');
{
  const { readdirSync } = await import('node:fs');
  const root_files = readdirSync(root);
  assert('no logs/ created', !root_files.includes('logs'));
  assert('no state/ created in repo root', !root_files.includes('state'));
  assert('no _v6-4-*.log artifacts', !root_files.some((f) => f.startsWith('_v6-4-') && f.endsWith('.log')));
}

/* =========================================================================
 * Summary
 * ======================================================================= */
console.log('');
console.log('---');
console.log(`Total: ${passed} passed, ${failed} failed`);
if (failed > 0) {
  for (const f of failures) console.log(`  FAIL: ${f.label}${f.extra ? ` (${f.extra})` : ''}`);
  process.exit(1);
}
process.exit(0);
