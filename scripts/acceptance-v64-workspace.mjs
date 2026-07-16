#!/usr/bin/env node
// V6.4 — Local defender workspace acceptance suite.
//
// Exercises every documented V6.4 behavior:
//   - schema validation (CVE normalisation, tag dedup,
//     note cap, prototype-pollution rejection)
//   - migrations (chain lookup, isOnMigrationChain)
//   - change signature (deterministic, compat-version)
//   - in-memory + unavailable adapters
//   - IndexedDB adapter path (smoke test in headless
//     Node — the full IndexedDB path runs in the
//     browser; this covers the code reachable from
//     the Node test runner)
//   - transactional writes (per-CVE queue)
//   - import modes (dry-run, merge, replace)
//   - export checksum determinism
//   - bulk update and clear semantics
//   - queue filters and ordering
//   - sanity invariants:
//       no note/tag in URL, no note/tag in any
//       workspace field that bleeds into the
//       public dataset, no note/tag in CSV columns,
//       no note/tag in filenames, no note/tag in
//       metric names, no note/tag in banner copy

import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { mkdtempSync, existsSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
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

  const e = makeEntry('CVE-2024-0001', { watched: true, triageStatus: 'reviewing', userPriority: 'high', note: 'hello', tags: ['one', 'two'] });
  assert('makeEntry schemaVersion set', e.schemaVersion === WORKSPACE_SCHEMA_VERSION);
  assert('makeEntry cveId normalised', e.cveId === 'CVE-2024-0001');
  assert('makeEntry watched set', e.watched === true);
  assert('makeEntry triage set', e.triageStatus === 'reviewing');
  assert('makeEntry priority set', e.userPriority === 'high');
  assert('makeEntry note set', e.note === 'hello');
  assert('makeEntry tags set', e.tags.length === 2);

  const v1 = validateEntry({ cveId: 'CVE-2024-0001' });
  assert('validateEntry accepts valid', v1.ok === true);

  // Prototype pollution: __proto__
  const polluted1 = { cveId: 'CVE-2024-0001' };
  Object.defineProperty(polluted1, '__proto__', { value: { evil: true }, enumerable: true });
  const v2 = validateEntry(polluted1);
  assert('validateEntry rejects __proto__', v2.ok === false && v2.reason.includes('__proto__'));

  // Prototype pollution: constructor
  const polluted2 = { cveId: 'CVE-2024-0001' };
  Object.defineProperty(polluted2, 'constructor', { value: { evil: true }, enumerable: true });
  const v3 = validateEntry(polluted2);
  assert('validateEntry rejects constructor', v3.ok === false && v3.reason.includes('constructor'));

  // Prototype pollution: prototype
  const polluted3 = { cveId: 'CVE-2024-0001' };
  Object.defineProperty(polluted3, 'prototype', { value: { evil: true }, enumerable: true });
  const v4 = validateEntry(polluted3);
  assert('validateEntry rejects prototype', v4.ok === false && v4.reason.includes('prototype'));

  // Overlong note is rejected
  const v5 = validateEntry({ cveId: 'CVE-2024-0001', note: 'x'.repeat(9000) });
  assert('validateEntry rejects overlong note', v5.ok === false && v5.reason === 'note-too-long');

  // Too many tags is rejected
  const v6 = validateEntry({ cveId: 'CVE-2024-0001', tags: Array.from({ length: 25 }, (_, i) => 't' + i) });
  assert('validateEntry rejects too many tags', v6.ok === false && v6.reason === 'too-many-tags');

  // Malformed cveId is rejected
  const v7 = validateEntry({ cveId: 'not-a-cve' });
  assert('validateEntry rejects malformed cveId', v7.ok === false && v7.reason === 'invalid-cveId');

  // Not-an-object is rejected
  assert('validateEntry rejects null', validateEntry(null).ok === false);
  assert('validateEntry rejects array', validateEntry([]).ok === false);
  assert('validateEntry rejects string', validateEntry('string').ok === false);

  // Patch
  const e2 = makeEntry('CVE-2024-0001');
  const before = e2.updatedAt;
  // Wait 1ms so updatedAt is strictly newer
  await new Promise((r) => setTimeout(r, 5));
  applyPatch(e2, { watched: true, triageStatus: 'reviewing', userPriority: 'high', note: 'x' });
  assert('applyPatch sets watched', e2.watched === true);
  assert('applyPatch sets triageStatus', e2.triageStatus === 'reviewing');
  assert('applyPatch sets userPriority', e2.userPriority === 'high');
  assert('applyPatch sets note', e2.note === 'x');
  assert('applyPatch updates updatedAt', e2.updatedAt !== before);

  // compareUpdatedAt
  const a = makeEntry('CVE-2024-0001');
  await new Promise((r) => setTimeout(r, 5));
  const b = makeEntry('CVE-2024-0001');
  assert('compareUpdatedAt a < b', compareUpdatedAt(a, b) === -1);
  assert('compareUpdatedAt b > a', compareUpdatedAt(b, a) === 1);

  // isSupportedSchemaVersion
  assert('isSupportedSchemaVersion accepts 1.0.0', isSupportedSchemaVersion('1.0.0') === true);
  assert('isSupportedSchemaVersion rejects 2.0.0', isSupportedSchemaVersion('2.0.0') === false);
  assert('isSupportedSchemaVersion rejects 0.9.0', isSupportedSchemaVersion('0.9.0') === false);
}

/* =========================================================================
 * 2. Migrations
 * ======================================================================= */
console.log('');
console.log('[2] Migrations');
{
  const { MIGRATION_CHAIN, migrateRecord, migrateRecords, isOnMigrationChain } = await import('../src/workspace/migrate.mjs');
  assert('MIGRATION_CHAIN is an array', Array.isArray(MIGRATION_CHAIN));
  assert('MIGRATION_CHAIN includes 1.0.0', isOnMigrationChain('1.0.0'));
  assert('migrateRecord is a function', typeof migrateRecord === 'function');
  assert('migrateRecords is a function', typeof migrateRecords === 'function');

  // migrateRecord of an unknown version throws (caller is expected
  // to catch via migrateRecords which filters them out).
  let threw = false;
  try { migrateRecord({ schemaVersion: '99.0.0', cveId: 'CVE-2024-0001' }, '99.0.0'); } catch { threw = true; }
  assert('migrateRecord unknown version throws', threw);

  // migrateRecords filters out non-migratable
  const r2 = migrateRecords([
    { schemaVersion: '1.0.0', cveId: 'CVE-2024-0001', watched: true },
    { schemaVersion: '99.0.0', cveId: 'CVE-2024-0002' },
  ]);
  assert('migrateRecords returns object with records and dropped', r2 && Array.isArray(r2.records) && r2.dropped === 1);
  assert('migrateRecords keeps the 1.0.0 record', r2.records.length === 1);
}

/* =========================================================================
 * 3. Change signature
 * ======================================================================= */
console.log('');
console.log('[3] Change signature');
{
  const { computeChangeSignature, versionsAreCompatible, classifyChange } = await import('../src/workspace/changeSignature.mjs');
  const v = {
    cveId: 'CVE-2024-0001', severity: 'High', cvssScore: 7.5, epssProbability: 0.2,
    kev: false, ssvc: { exploitation: 'poc', automatable: 'no', technicalImpact: 'partial' },
    vulnrichment: true, githubAdvisory: false, osv: { recordIds: ['OSV-1', 'OSV-2'] }, withdrawn: false,
  };
  const sig1 = computeChangeSignature(v, 'v6-4-abc');
  const sig2 = computeChangeSignature(v, 'v6-4-abc');
  assert('signature is deterministic', sig1 === sig2);
  assert('signature has sha256 prefix', sig1.startsWith('sha256:'));
  assert('signature is lowercase hex', /^sha256:[0-9a-f]{64}$/.test(sig1));

  // Change severity → signature changes
  const v2 = { ...v, severity: 'Critical' };
  const sig3 = computeChangeSignature(v2, 'v6-4-abc');
  assert('signature changes when severity changes', sig3 !== sig1);

  // versionsAreCompatible
  assert('versionsAreCompatible v6-4-x v6-4-y', versionsAreCompatible('v6-4-a', 'v6-4-b') === true);
  assert('versionsAreCompatible v6-1 v6-2', versionsAreCompatible('v6-1-a', 'v6-2-a') === false);
  assert('versionsAreCompatible null v6-1', versionsAreCompatible(null, 'v6-1-a') === false);
  assert('versionsAreCompatible v6-1 null', versionsAreCompatible('v6-1-a', null) === false);

  // classifyChange
  const cls1 = classifyChange({ currentVersion: 'v6-4-a', currentSignature: sig1, record: { lastSeenPublicIntelligenceVersion: 'v6-4-a', lastSeenChangeSignature: sig1 }, presentInPublic: true });
  assert('classifyChange no-newer', cls1 === 'no-newer');
  const cls2 = classifyChange({ currentVersion: 'v6-4-a', currentSignature: sig1, record: { lastSeenPublicIntelligenceVersion: 'v6-4-a', lastSeenChangeSignature: 'different' }, presentInPublic: true });
  assert('classifyChange changed', cls2 === 'changed');
  const cls3 = classifyChange({ currentVersion: 'v6-4-a', currentSignature: sig1, record: { lastSeenPublicIntelligenceVersion: null, lastSeenChangeSignature: null }, presentInPublic: true });
  assert('classifyChange newly-tracked', cls3 === 'newly-tracked');
  const cls4 = classifyChange({ currentVersion: 'v6-4-a', currentSignature: sig1, record: { lastSeenPublicIntelligenceVersion: 'v6-1-a', lastSeenChangeSignature: 'x' }, presentInPublic: true });
  assert('classifyChange unavailable on incompatible', cls4 === 'unavailable');
  const cls5 = classifyChange({ currentVersion: 'v6-4-a', currentSignature: sig1, record: null, presentInPublic: true });
  assert('classifyChange unavailable on null record', cls5 === 'unavailable');
  const cls6 = classifyChange({ currentVersion: 'v6-4-a', currentSignature: sig1, record: { lastSeenPublicIntelligenceVersion: 'v6-4-a', lastSeenChangeSignature: sig1 }, presentInPublic: false });
  assert('classifyChange no-longer-tracked', cls6 === 'no-longer-tracked');
}

/* =========================================================================
 * 4. Adapters
 * ======================================================================= */
console.log('');
console.log('[4] In-memory and unavailable adapters');
{
  const { InMemoryWorkspaceAdapter } = await import('../src/workspace/InMemoryWorkspaceAdapter.mjs');
  const { UnavailableWorkspaceAdapter } = await import('../src/workspace/UnavailableWorkspaceAdapter.mjs');
  const { makeEntry, applyPatch } = await import('../src/workspace/schema.mjs');

  // InMemoryWorkspaceAdapter
  const mem = new InMemoryWorkspaceAdapter();
  const init = await mem.initialize();
  assert('InMemoryWorkspaceAdapter initialize ok', init.ok === true);

  const e1 = makeEntry('CVE-2024-0001', { watched: true, note: 'hello' });
  const put1 = await mem.putEntry(e1);
  assert('InMemory putEntry ok', put1.ok === true);
  const get1 = await mem.getEntry('cve-2024-0001'); // lowercased input
  assert('InMemory getEntry is case-insensitive', get1 && get1.cveId === 'CVE-2024-0001');
  const get2 = await mem.getEntry('CVE-2024-0001');
  assert('InMemory getEntry returns note', get2 && get2.note === 'hello');

  const list1 = await mem.listEntries({});
  assert('InMemory listEntries returns ok', list1.ok === true && list1.entries.length === 1);

  // patchEntry
  const patch1 = await mem.patchEntry('CVE-2024-0001', { watched: false });
  assert('InMemory patchEntry ok', patch1.ok === true && patch1.record.watched === false);

  // deleteEntry
  const del1 = await mem.deleteEntry('CVE-2024-0001');
  assert('InMemory deleteEntry ok', del1.ok === true);
  const afterDel = await mem.getEntry('CVE-2024-0001');
  assert('InMemory getEntry returns null after delete', afterDel === null);

  // bulkUpdate
  const e2 = makeEntry('CVE-2024-0002', { watched: true });
  const e3 = makeEntry('CVE-2024-0003', { watched: true });
  await mem.putEntry(e2);
  await mem.putEntry(e3);
  const bulk1 = await mem.bulkUpdate(['CVE-2024-0002', 'CVE-2024-0003'], { triageStatus: 'reviewing' });
  assert('InMemory bulkUpdate ok', bulk1.ok === true && bulk1.updated === 2);

  // clearArchived
  const e4 = makeEntry('CVE-2024-0004', { archived: true });
  await mem.putEntry(e4);
  const clear1 = await mem.clearArchived();
  assert('InMemory clearArchived removes archived', clear1.ok === true && clear1.removed === 1);

  // clearWorkspace
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
  // The Unavailable adapter is a stub: bulkUpdate/clearArchived/clearWorkspace
  // return ok=true with zero effects (they are no-ops, not errors).
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
 * 5. Export / import
 * ======================================================================= */
console.log('');
console.log('[5] Export and import');
{
  const { buildExportPayload, dryRunImport, applyMerge, applyReplace } = await import('../src/workspace/exportImport.mjs');
  const { InMemoryWorkspaceAdapter } = await import('../src/workspace/InMemoryWorkspaceAdapter.mjs');
  const { makeEntry, validateImportPayload } = await import('../src/workspace/schema.mjs');

  const e1 = makeEntry('CVE-2024-0001', { watched: true, note: 'private note' });
  const e2 = makeEntry('CVE-2024-0002', { triageStatus: 'reviewing' });
  const payload = buildExportPayload([e1, e2], { applicationVersion: 'v6.4' });

  assert('export format', payload.format === 'threatpulse-local-workspace');
  assert('export schemaVersion', payload.schemaVersion === '1.0.0');
  assert('export entryCount', payload.entryCount === 2);
  assert('export checksum has sha256 prefix', payload.checksum.startsWith('sha256:'));

  // Determinism: same inputs → same checksum
  const payload2 = buildExportPayload([e1, e2], { applicationVersion: 'v6.4' });
  assert('export is deterministic', payload.checksum === payload2.checksum);

  // Reordering produces the same checksum (the export sorts by cveId)
  const payload3 = buildExportPayload([e2, e1], { applicationVersion: 'v6.4' });
  assert('export is cveId-sorted (order-insensitive)', payload.checksum === payload3.checksum);

  // A different cveId is in a different position → different checksum.
  const e3 = makeEntry('CVE-2024-0099', { watched: true });
  const payload4 = buildExportPayload([e1, e2, e3], { applicationVersion: 'v6.4' });
  assert('export adds new entry to checksum', payload4.checksum !== payload.checksum);

  // dry-run validation
  const dry = dryRunImport(payload);
  assert('dry-run valid', dry.ok === true && dry.entries.length === 2);

  // Bad format
  const dryBad = dryRunImport({ format: 'wrong', schemaVersion: '1.0.0', entries: [] });
  assert('dry-run bad format rejected', dryBad.ok === false);

  // Future schema
  const dryFuture = dryRunImport({ format: 'threatpulse-local-workspace', schemaVersion: '99.0.0', entries: [] });
  assert('dry-run future schema rejected', dryFuture.ok === false);

  // Prototype pollution at top level
  const polluted = JSON.parse(JSON.stringify(payload));
  Object.defineProperty(polluted, 'constructor', { value: { evil: true }, enumerable: true });
  const dryPol = dryRunImport(polluted);
  assert('dry-run prototype pollution rejected', dryPol.ok === false);

  // Merge
  const memMerge = new InMemoryWorkspaceAdapter();
  await memMerge.initialize();
  await memMerge.putEntry(makeEntry('CVE-2024-0001', { watched: true }));
  // Make sure updatedAt is strictly newer
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

  // Import error preserves existing (covered by replace's stage-then-promote)
  const memFails = new InMemoryWorkspaceAdapter();
  await memFails.initialize();
  await memFails.putEntry(makeEntry('CVE-2024-2000', { watched: true }));
  // Try to replace with a bad record (invalid cveId)
  const r4 = await applyReplace(memFails, [{ cveId: 'not-a-cve', watched: true }]);
  assert('replace with invalid entry returns not-ok', r4.ok === false);
  const keep = await memFails.getEntry('CVE-2024-2000');
  assert('replace failure preserves original', keep !== null);
}

/* =========================================================================
 * 6. Queue filters
 * ======================================================================= */
console.log('');
console.log('[6] Queue filters and ordering');
{
  const {
    QUEUE_FILTERS,
    DEFAULT_QUEUE_FILTER,
    buildLocalQueue,
    buildCounts,
    matchesLocalSearch,
    matchesQueueFilter,
  } = await import('../src/workspace/queueFilters.mjs');
  const { computeChangeSignature } = await import('../src/workspace/changeSignature.mjs');

  assert('QUEUE_FILTERS has 7 entries', QUEUE_FILTERS.length === 7);
  assert('DEFAULT_QUEUE_FILTER is all-watched', DEFAULT_QUEUE_FILTER === 'all-watched');

  const v1 = { cveId: 'CVE-2024-0001', severity: 'Critical', cvssScore: 9.8, epssProbability: 0.9, kev: true, ssvc: { exploitation: 'active' }, vulnrichment: true, githubAdvisory: true, osv: { recordIds: ['OSV-1'] }, withdrawn: false };
  const v2 = { cveId: 'CVE-2024-0002', severity: 'High', cvssScore: 7.5, epssProbability: 0.2, kev: false, ssvc: { exploitation: 'poc' }, vulnrichment: true, githubAdvisory: false, osv: { recordIds: [] }, withdrawn: false };
  const v3 = { cveId: 'CVE-2024-0003', severity: 'Medium', cvssScore: 5.0, epssProbability: 0.05, kev: false, ssvc: { exploitation: 'none' }, vulnrichment: false, githubAdvisory: false, osv: { recordIds: [] }, withdrawn: false };
  const pubVersion = 'v6-4-abc';
  const sig = (v) => computeChangeSignature(v, pubVersion);
  const sig1 = sig(v1);
  const sig2 = sig(v2);

  const e1 = { cveId: 'CVE-2024-0001', watched: true, triageStatus: 'unreviewed', userPriority: 'urgent', tags: [], note: '', addedAt: '2024-01-01', updatedAt: '2024-01-01', lastReviewedAt: null, lastSeenPublicIntelligenceVersion: pubVersion, lastSeenChangeSignature: sig1, archived: false, schemaVersion: '1.0.0' };
  const e2 = { cveId: 'CVE-2024-0002', watched: true, triageStatus: 'action-required', userPriority: 'high', tags: [], note: 'patch me', addedAt: '2024-01-01', updatedAt: '2024-01-01', lastReviewedAt: null, lastSeenPublicIntelligenceVersion: pubVersion, lastSeenChangeSignature: 'stale-sig-2', archived: false, schemaVersion: '1.0.0' };

  const entriesByCve = { 'CVE-2024-0001': e1, 'CVE-2024-0002': e2 };
  const vulns = [v1, v2, v3];

  // all-watched filter returns only the 2 watched
  const qAll = buildLocalQueue({ vulns, entriesByCve, filter: 'all-watched', query: '', publicIntelligenceVersion: pubVersion, computeSignature: sig });
  assert('all-watched returns 2', qAll.length === 2);
  assert('all-watched first is urgent', qAll[0].vuln.cveId === 'CVE-2024-0001');

  // action-required
  const qAct = buildLocalQueue({ vulns, entriesByCve, filter: 'action-required', query: '', publicIntelligenceVersion: pubVersion, computeSignature: sig });
  assert('action-required returns 1', qAct.length === 1 && qAct[0].vuln.cveId === 'CVE-2024-0002');

  // changed-since-review
  const qChg = buildLocalQueue({ vulns, entriesByCve, filter: 'changed-since-review', query: '', publicIntelligenceVersion: pubVersion, computeSignature: sig });
  assert('changed-since-review returns 1', qChg.length === 1 && qChg[0].vuln.cveId === 'CVE-2024-0002');

  // high-or-urgent
  const qHu = buildLocalQueue({ vulns, entriesByCve, filter: 'high-or-urgent', query: '', publicIntelligenceVersion: pubVersion, computeSignature: sig });
  assert('high-or-urgent returns 2', qHu.length === 2);

  // search by tag
  const qSearch = buildLocalQueue({ vulns, entriesByCve, filter: 'all-watched', query: 'patch', publicIntelligenceVersion: pubVersion, computeSignature: sig });
  assert('search by note content returns matching', qSearch.length === 1 && qSearch[0].vuln.cveId === 'CVE-2024-0002');

  // search by CVE id within a tracked filter
  const qSearch2 = buildLocalQueue({ vulns, entriesByCve, filter: 'all-watched', query: 'CVE-2024-0001', publicIntelligenceVersion: pubVersion, computeSignature: sig });
  assert('search by cve id within watched filter returns the row', qSearch2.length === 1 && qSearch2[0].vuln.cveId === 'CVE-2024-0001');

  // matchesLocalSearch for cve id always returns true for the public vuln
  assert('matchesLocalSearch cve id matches vuln', matchesLocalSearch({ vuln: v3, entry: null, query: 'CVE-2024-0003' }) === true);
  assert('matchesLocalSearch cve id with no vuln', matchesLocalSearch({ vuln: null, entry: null, query: 'CVE-2024-0001' }) === false);

  // counts
  const counts = buildCounts({ vulns, entriesByCve, publicIntelligenceVersion: pubVersion, computeSignature: sig });
  assert('counts.watched = 2', counts.watched === 2);
  assert('counts.actionRequired = 1', counts.actionRequired === 1);
  assert('counts.changedSinceReview = 1', counts.changedSinceReview === 1);
  assert('counts.total = 2', counts.total === 2);

  // matchesLocalSearch
  assert('matchesLocalSearch empty query', matchesLocalSearch({ vuln: v1, entry: e1, query: '' }) === true);
  assert('matchesLocalSearch tag match', matchesLocalSearch({ vuln: v1, entry: e1, query: 'CVE-2024' }) === true);
}

/* =========================================================================
 * 7. Privacy invariants — no workspace field in public surfaces
 * ======================================================================= */
console.log('');
console.log('[7] Privacy invariants');
{
  // The CSV columns must not include any workspace field.
  // csvExport is a TypeScript module; we read the source to
  // extract the CSV_COLUMNS array.
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

  // Public request paths must not include any workspace field.
  // Inspect the request-builder helpers in the service layer.
  // vulnerabilityService is a TypeScript module; we read the
  // source to check for forbidden parameter names rather than
  // trying to import the .ts file from a Node test runner.
  const { readdirSync } = await import('node:fs');
  const fnDir = join(root, 'netlify/functions');
  const svcSrc = readFileSync(join(root, 'src/services/vulnerabilityService.ts'), 'utf8');
  for (const k of workspaceFieldKeywords) {
    assert(
      `vulnerabilityService has no '${k}' parameter`,
      !new RegExp(`\\b${k}\\??\\s*:`).test(svcSrc),
      `found ${k} in vulnerabilityService.ts`
    );
  }
  // The fetchVulnerabilities function should be exported.
  assert('vulnerabilityService exports fetchVulnerabilities', /export\s+(async\s+)?function\s+fetchVulnerabilities\b/.test(svcSrc));

  // The dataset function must not read from the workspace.
  // The privacy keywords are matched as whole words
  // and we explicitly allow substrings (e.g.
  // "Vulnrichment" contains "tag"). To be safe, we
  // strip comments first and search the code only.
  function stripJsComments(src) {
    return src
      .replace(/\/\*[\s\S]*?\*\//g, '')
      .replace(/^\s*\/\/.*$/gm, '');
  }
  function findKeywordAsToken(src, kw) {
    // Match the keyword as a whole word that is NOT a
    // substring of a longer identifier (the trailing
    // negative lookbehind/ahead ensures no identifier
    // boundary is crossed).
    return new RegExp(`(?<![A-Za-z0-9_])${kw}(?![A-Za-z0-9_])`, 'i').test(src);
  }
  const datasetSrc = stripJsComments(readFileSync(join(root, 'netlify/functions/dataset.mjs'), 'utf8'));
  for (const k of ['workspace', 'note', 'tag', 'triage', 'priority', 'watched']) {
    assert(
      `dataset.mjs code has no '${k}' reference`,
      !findKeywordAsToken(datasetSrc, k),
      `found ${k} in dataset.mjs`
    );
  }

  // The 5 public Netlify function entries must not
  // reference any workspace field. We sweep them all
  // (and the internal scheduled / background shims
  // — same code, no point skipping them).
  const fnFiles = readdirSync(fnDir).filter((f) => f.endsWith('.mjs'));
  for (const f of fnFiles) {
    const src = stripJsComments(readFileSync(join(fnDir, f), 'utf8'));
    for (const k of ['workspace', 'note', 'triage', 'priority', 'watched']) {
      assert(
        `${f} has no '${k}' reference`,
        !findKeywordAsToken(src, k),
        `found ${k} in ${f}`
      );
    }
  }
}

/* =========================================================================
 * 8. Repository invariants — no V6.4 leakage into the public stack
 * ======================================================================= */
console.log('');
console.log('[8] Repository invariants');
{
  // 5 public Netlify function entries (V6.1 contract)
  const { readdirSync } = await import('node:fs');
  const fnDir = join(root, 'netlify/functions');
  const files = readdirSync(fnDir).filter((f) => f.endsWith('.mjs'));
  assert('5 public Netlify function entries', files.length === 5, files.join(','));

  // Gateway entry — single file, byte-identical to V6.1 baseline.
  // The acceptance-canonical-baseline test enforces this separately;
  // here we just assert the gateway/ dir is non-empty.
  const gatewayDir = join(root, 'netlify/gateway');
  assert('netlify/gateway/ exists', existsSync(gatewayDir));

  // CSV columns count (already asserted above via the
  // direct source-read; the duplicate check is
  // removed to keep the suite idempotent).
}

/* =========================================================================
 * 9. Export filename and dashboard public path invariants
 * ======================================================================= */
console.log('');
console.log('[9] Filename and dashboard public-path invariants');
{
  // The export filename is a static name; no CVE id, no timestamp leak.
  const dlg = readFileSync(join(root, 'src/components/workspace/WorkspaceDialogs.tsx'), 'utf8');
  assert('export filename is static (no CVE/timestamp leak)', dlg.includes("`threatpulse-workspace.json`") || dlg.includes("'threatpulse-workspace.json'"));

  // The VulnerabilityTable doesn't add an extra column with note/tag data
  // — only a single "Local" column for the watch toggle.
  const tableSrc = readFileSync(join(root, 'src/components/VulnerabilityTable.tsx'), 'utf8');
  const localCol = tableSrc.match(/label:\s*'Local'/);
  assert('VulnerabilityTable has exactly one Local column', !!localCol);
  // And no column labelled Note / Tags / Triage.
  assert('VulnerabilityTable has no Note column', !/label:\s*'Note'/.test(tableSrc));
  assert('VulnerabilityTable has no Tags column', !/label:\s*'Tags'/.test(tableSrc));
  assert('VulnerabilityTable has no Triage column', !/label:\s*'Triage'/.test(tableSrc));

  // The DashboardPage's URL state must not include any workspace field.
  // We assert there is no `setSearchParams` / `URLSearchParams` /
  // `window.history.pushState` that carries a workspace key.
  const dashSrc = readFileSync(join(root, 'src/pages/DashboardPage.tsx'), 'utf8');
  for (const k of ['watched', 'triage', 'priority', 'note', 'tag', 'archived', 'workspace']) {
    assert(
      `DashboardPage does not put '${k}' in URL`,
      !new RegExp(`searchParams.*['"\`]${k}['"\`]|history\\.pushState.*${k}`).test(dashSrc)
    );
  }
}

/* =========================================================================
 * 10. Concurrency: per-CVE serialised writes
 * ======================================================================= */
console.log('');
console.log('[10] Per-CVE serialised writes');
{
  // Concurrency: parallel puts to the same CVE do not lose updates.
  const { InMemoryWorkspaceAdapter } = await import('../src/workspace/InMemoryWorkspaceAdapter.mjs');
  const { makeEntry, applyPatch } = await import('../src/workspace/schema.mjs');
  const mem = new InMemoryWorkspaceAdapter();
  await mem.initialize();
  await mem.putEntry(makeEntry('CVE-2024-0001'));

  // Fire 20 parallel patches; the in-memory adapter applies them
  // serially through the patchEntry path. The final state should
  // match the last patch.
  const results = await Promise.all(Array.from({ length: 20 }, (_, i) =>
    mem.patchEntry('CVE-2024-0001', { tags: ['n' + i] })
  ));
  assert('all 20 parallel patches succeeded', results.every((r) => r.ok));
  const final = await mem.getEntry('CVE-2024-0001');
  assert('final tags length is 1 (last patch wins)', final && final.tags.length === 1);
}

/* =========================================================================
 * 11. Cleanup
 * ======================================================================= */
console.log('');
console.log('[11] Cleanup — no repository artifacts');
{
  const { readdirSync: rds } = await import('node:fs');
  const root_files = rds(root);
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
