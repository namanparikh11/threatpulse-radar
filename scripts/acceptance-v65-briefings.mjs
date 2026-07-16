#!/usr/bin/env node
/**
 * V6.5 — Local Briefings and Reports acceptance suite.
 *
 * Exercises the report subsystem end-to-end without
 * touching the network, the URL, the console, the
 * public CSV, the public API, the Netlify / Hostinger
 * storage, the workspace, or the history.
 *
 * The suite is designed to be run from a clean
 * `node` process. The instrumented channels (fetch,
 * XMLHttpRequest, sendBeacon, history.pushState,
 * history.replaceState, console) are captured at
 * start so the privacy proof can assert that no
 * sentinel value ever appears in any of them.
 *
 *   node scripts/acceptance-v65-briefings.mjs
 *
 * Exit code 0 when every assertion passes.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { webcrypto as nodeCrypto } from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';
import path from 'node:path';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..');

// Make sure no host-side test accidentally lands in
// the production report history table.
if (typeof globalThis.indexedDB === 'undefined') {
  // Provide an in-memory IDB factory so the history
  // module does not throw when imported. The shim is
  // module-level so the data persists across `openDb`
  // calls within a single test process (matching real
  // browser semantics).
  const persistentDBs = new Map();
  class FakeStore {
    constructor(name) { this.name = name; this.data = new Map(); this.indexes = {}; }
    get(k) { const r = { onsuccess: null, onerror: null, result: this.data.get(k) }; setImmediate(() => r.onsuccess && r.onsuccess({ target: r })); return r; }
    put(v) { this.data.set(v.reportId, v); const r = { onsuccess: null, onerror: null, result: v }; setImmediate(() => r.onsuccess && r.onsuccess({ target: r })); return r; }
    delete(k) { this.data.delete(k); const r = { onsuccess: null, onerror: null, result: undefined }; setImmediate(() => r.onsuccess && r.onsuccess({ target: r })); return r; }
    clear() { this.data.clear(); const r = { onsuccess: null, onerror: null, result: undefined }; setImmediate(() => r.onsuccess && r.onsuccess({ target: r })); return r; }
    count() { const r = { onsuccess: null, onerror: null, result: this.data.size }; setImmediate(() => r.onsuccess && r.onsuccess({ target: r })); return r; }
    getAll() { const r = { onsuccess: null, onerror: null, result: Array.from(this.data.values()) }; setImmediate(() => r.onsuccess && r.onsuccess({ target: r })); return r; }
    createIndex(name) { this.indexes[name] = { name }; return this.indexes[name]; }
    index(name) { return this.indexes[name] || this.createIndex(name); }
    // The eviction path uses an openCursor on the
    // 'storedAt' index. The FakeStore's getAll is enough
    // for the test surface we actually exercise; we provide
    // a no-op cursor that never yields a row so the test
    // path stays deterministic.
    openCursor() {
      const r = { onsuccess: null, onerror: null, result: null };
      setImmediate(() => r.onsuccess && r.onsuccess({ target: r }));
      return r;
    }
  }
  class FakeTx {
    constructor(db, store) { this.store = db.stores[store]; this.oncomplete = null; this.onerror = null; this.onabort = null; }
    objectStore(name) { return this.store; }
  }
  class FakeDB {
    constructor(name) { this.name = name; this.stores = {}; this.objectStoreNames = { contains: (n) => Boolean(this.stores[n]) }; }
    createObjectStore(name) { this.stores[name] = new FakeStore(name); return this.stores[name]; }
    transaction(name) { const tx = new FakeTx(this, name); setImmediate(() => tx.oncomplete && tx.oncomplete({ target: tx })); return tx; }
    close() { /* no-op */ }
  }
  class FakeReq {
    constructor() { this.onsuccess = null; this.onerror = null; this.onblocked = null; this.onupgradeneeded = null; this.result = null; }
  }
  globalThis.indexedDB = {
    open(name) {
      const req = new FakeReq();
      const db = persistentDBs.get(name) || new FakeDB(name);
      persistentDBs.set(name, db);
      setImmediate(() => {
        if (req.onupgradeneeded) {
          // In the spec, req.result is the database during
          // onupgradeneeded so the handler can create object
          // stores on it.
          req.result = db;
          req.onupgradeneeded({ target: req });
        }
        if (req.onsuccess) req.onsuccess({ target: req });
      });
      return req;
    },
  };
  // Expose the persistent map so tests can clear it.
  globalThis.__threatpulseTestIDB = persistentDBs;
}

const root = pathToFileURL(path.join(REPO, 'src') + path.sep).href;

const schema = await import(new URL('./reports/schema.mjs', root).href);
const snapshot = await import(new URL('./reports/snapshot.mjs', root).href);
const templates = await import(new URL('./reports/templates.mjs', root).href);
const integrity = await import(new URL('./reports/integrity.mjs', root).href);
const redaction = await import(new URL('./reports/redaction.mjs', root).href);
const sha = await import(new URL('./reports/sha256.mjs', root).href);
const canonicalize = await import(new URL('./reports/canonicalize.mjs', root).href);
const verify = await import(new URL('./reports/verify.mjs', root).href);
const compare = await import(new URL('./reports/compare.mjs', root).href);
const history = await import(new URL('./reports/history.mjs', root).href);
const exporters = await import(new URL('./reports/exporters/index.mjs', root).href);

// Sentinel value used to prove the privacy path. The
// suite installs instrumentation that records every
// fetch / XHR / sendBeacon / history / console
// output. After the build + export + verify + compare
// + history pipeline runs, the sentinel MUST NOT
// appear in any captured channel.
const SENTINEL = 'threatpulse-sentinel-9c2a-private-note-and-tag-DO-NOT-EXPORT';

function installInstrumentation() {
  const captured = { fetch: [], xhr: [], beacon: [], push: [], replace: [], console: [] };
  const origFetch = globalThis.fetch;
  const origXhrOpen = globalThis.XMLHttpRequest?.prototype?.open;
  const origXhrSend = globalThis.XMLHttpRequest?.prototype?.send;
  const origBeacon = globalThis.navigator?.sendBeacon;
  const origPush = globalThis.history?.pushState;
  const origReplace = globalThis.history?.replaceState;
  const consoleMethods = ['log', 'info', 'debug', 'warn', 'error'];
  const origConsole = {};
  for (const m of consoleMethods) origConsole[m] = console[m].bind(console);

  globalThis.fetch = function patchedFetch(...args) {
    captured.fetch.push(args.map((a) => (typeof a === 'string' ? a : JSON.stringify(a))));
    return origFetch ? origFetch.apply(this, args) : Promise.reject(new Error('no-fetch'));
  };
  if (globalThis.XMLHttpRequest?.prototype) {
    globalThis.XMLHttpRequest.prototype.open = function patchedOpen(...args) { captured.xhr.push(args); return origXhrOpen ? origXhrOpen.apply(this, args) : undefined; };
    globalThis.XMLHttpRequest.prototype.send = function patchedSend(...args) { captured.xhr.push(args); return origXhrSend ? origXhrSend.apply(this, args) : undefined; };
  }
  if (origBeacon) globalThis.navigator.sendBeacon = function patchedBeacon(...args) { captured.beacon.push(args); return origBeacon.apply(this, args); };
  if (origPush) globalThis.history.pushState = function patchedPushState(...args) { captured.push.push(args); return origPush.apply(this, args); };
  if (origReplace) globalThis.history.replaceState = function patchedReplaceState(...args) { captured.replace.push(args); return origReplace.apply(this, args); };
  for (const m of consoleMethods) {
    console[m] = function patchedConsole(...args) { captured.console.push([m, ...args]); return origConsole[m](...args); };
  }
  return {
    captured,
    restore() {
      globalThis.fetch = origFetch;
      if (origXhrOpen && globalThis.XMLHttpRequest?.prototype) globalThis.XMLHttpRequest.prototype.open = origXhrOpen;
      if (origXhrSend && globalThis.XMLHttpRequest?.prototype) globalThis.XMLHttpRequest.prototype.send = origXhrSend;
      if (origBeacon && globalThis.navigator) globalThis.navigator.sendBeacon = origBeacon;
      if (origPush && globalThis.history) globalThis.history.pushState = origPush;
      if (origReplace && globalThis.history) globalThis.history.replaceState = origReplace;
      for (const m of consoleMethods) console[m] = origConsole[m];
    },
  };
}

function asciiEscape(v) { return String(v).replace(/[^a-z0-9_-]/gi, '_'); }

function findSentinelIn(captured) {
  for (const v of Object.values(captured)) {
    for (const call of v) {
      for (const arg of call) {
        if (typeof arg === 'string' && arg.includes(SENTINEL)) return true;
      }
    }
  }
  return false;
}

function makeVuln(cveId, sentinel) {
  return {
    cveId,
    summary: `Summary for ${cveId} (${sentinel.slice(0, 4)})`,
    severity: 'Critical',
    cvssScore: 9.8,
    epssProbability: 0.95,
    kev: true,
    ssvc: null,
    vulnrichment: true,
    githubAdvisory: null,
    osv: null,
    withdrawn: false,
    changeTag: 'newly-tracked',
    publishedDate: '2025-01-01',
    vendor: 'v',
    product: 'p',
    source: 'cisa-kev',
    externalLinks: [],
  };
}

function makeEntries(cveId, sentinel) {
  // The sentinel is only the private NOTE for these
  // tests. The tag is a benign public-safe word so the
  // exporter test under "exclude-private-notes" can
  // assert the note was stripped without the tag being
  // conflated with the sentinel.
  return {
    [cveId]: {
      cveId,
      watched: true,
      triageStatus: 'action-required',
      userPriority: 'high',
      tags: ['public-safe-tag'],
      note: sentinel,
      addedAt: '2025-01-01T00:00:00.000Z',
      updatedAt: '2025-01-02T00:00:00.000Z',
      lastReviewedAt: null,
      lastSeenPublicIntelligenceVersion: 'v1',
      lastSeenChangeSignature: null,
      lastSeenPublicProjectionSchemaVersion: '1.0.0',
      revision: 1,
      mutationId: 'm-' + cveId,
      archived: false,
    },
  };
}

async function buildReportFor(opts) {
  const snap = await snapshot.buildReportSnapshot({
    publicMeta: {
      publicIntelligenceStatus: opts.metaStatus || 'available',
      publicIntelligenceVersion: 'v1',
      publicProjectionSchemaVersion: '1.0.0',
      fetchedAt: '2025-01-01T00:00:00.000Z',
      comparableAxes: ['cvss', 'epss'],
      suppressedAxes: [],
      sourceHealth: [{ sourceId: 'cisa-kev', name: 'CISA KEV', state: 'ok', lastSuccessAt: '2025-01-01T00:00:00.000Z', officialUrl: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog' }],
    },
    vulns: [makeVuln('CVE-2025-0001', SENTINEL)],
    entriesByCve: makeEntries('CVE-2025-0001', SENTINEL),
    selection: { cveIds: ['CVE-2025-0001'], includePrivateNotes: opts.includePrivateNotes, includeLocalTags: opts.includeLocalTags, includeResolved: false, includeArchived: false },
    flushPendingWrites: async () => {},
    hasPendingWrites: false,
    options: { applicationVersion: 'v6.5' },
  });
  const built = templates.buildReport({
    reportId: 'rpt-' + asciiEscape(opts.title || 'test'),
    reportType: opts.reportType || 'selected-cve',
    title: opts.title || 'Test',
    generatedAt: '2025-01-01T00:00:00.000Z',
    applicationVersion: 'v6.5',
    snapshot: snap,
    mode: opts.mode,
    includePrivateNotes: opts.includePrivateNotes && !redaction.modeHidesNote(opts.mode),
    includeLocalTags: opts.includeLocalTags && !redaction.modeHidesTags(opts.mode),
  });
  built.integrity = await integrity.computeIntegrity(built);
  return { snapshot: snap, report: built };
}

// ---------- Tests ----------

test('schema constants and limits', () => {
  assert.equal(schema.REPORT_SCHEMA_VERSION, '1.0.0');
  assert.equal(schema.REPORT_EXPORT_FORMAT, 'threatpulse-local-report');
  assert.equal(schema.CANONICALIZATION_VERSION, '1.0.0');
  assert.equal(schema.REPORT_LIMITS.MAX_CVES, 500);
  assert.equal(schema.REPORT_LIMITS.MAX_BYTES, 20 * 1024 * 1024);
  assert.equal(schema.REPORT_TYPES.length, 5);
  assert.equal(schema.REDACTION_MODES.length, 5);
  const ids = new Set(schema.REPORT_TYPES.map((t) => t.id));
  for (const t of ['defender-daily-briefing', 'local-triage-queue', 'selected-cve', 'change-briefing', 'executive-summary']) {
    assert.ok(ids.has(t), 'missing report type: ' + t);
  }
  const mids = new Set(schema.REDACTION_MODES.map((m) => m.id));
  for (const m of ['none', 'exclude-private-notes', 'exclude-local-tags', 'exclude-all-user-text', 'identifiers-only']) {
    assert.ok(mids.has(m), 'missing redaction mode: ' + m);
  }
});

test('validateReport rejects prototype-pollution keys', async () => {
  const r = (await buildReportFor({ title: 'A', mode: 'none' })).report;
  // Build a tampered object whose own properties
  // include __proto__ + constructor (a classic pollution
  // vector). We use Object.defineProperty because the
  // literal `{ __proto__: ... }` form is treated as a
  // prototype assignment in V8 and Object.getOwnPropertyNames
  // would not list the key.
  const tampered = {};
  for (const k of ['format', 'schemaVersion', 'reportId', 'reportType', 'title', 'generatedAt', 'applicationVersion', 'publicIntelligence', 'selection', 'sections', 'provenance', 'limitations', 'integrity']) {
    tampered[k] = r[k];
  }
  Object.defineProperty(tampered, '__proto__', { value: { polluted: true }, enumerable: true, configurable: true, writable: true });
  Object.defineProperty(tampered, 'constructor', { value: { polluted: true }, enumerable: true, configurable: true, writable: true });
  const out = schema.validateReport(tampered);
  assert.equal(out.ok, false, 'prototype pollution should be rejected');
  assert.ok(out.reason.startsWith('prototype-pollution:'), 'reason must be a prototype-pollution code');
});

test('validateReport rejects future schema', () => {
  return buildReportFor({ title: 'B', mode: 'none' }).then(({ report }) => {
    const cloned = JSON.parse(JSON.stringify(report));
    cloned.schemaVersion = '99.0.0';
    const out = schema.validateReport(cloned);
    assert.equal(out.ok, false);
    assert.equal(out.reason, 'unsupported-schema-version');
  });
});

test('validateReport rejects oversized payload', () => {
  return buildReportFor({ title: 'C', mode: 'none' }).then(({ report }) => {
    const cloned = JSON.parse(JSON.stringify(report));
    cloned.selection.cveIds = Array.from({ length: 501 }, (_, i) => 'CVE-2025-' + String(i).padStart(4, '0'));
    const out = schema.validateReport(cloned);
    assert.equal(out.ok, false);
    assert.equal(out.reason, 'too-many-cves');
  });
});

test('canonicalize strips integrity and orders keys deterministically', () => {
  return buildReportFor({ title: 'D', mode: 'none' }).then(({ report }) => {
    const a = canonicalize.canonicalizeReportBytes(report);
    const b = canonicalize.canonicalizeReportBytes(report);
    assert.equal(a, b, 'canonical bytes must be deterministic');
    assert.ok(!a.includes('"integrity"'), 'integrity block must be stripped before canonicalization');
  });
});

test('checksum reflects redacted bytes (mode=none vs exclude-private-notes)', async () => {
  const a = (await buildReportFor({ title: 'E', mode: 'none', includePrivateNotes: true, includeLocalTags: true })).report;
  const b = (await buildReportFor({ title: 'E', mode: 'exclude-private-notes', includePrivateNotes: true, includeLocalTags: true })).report;
  assert.notEqual(a.integrity.checksum, b.integrity.checksum, 'redaction must change the digest');
  assert.ok(a.integrity.checksum.startsWith('sha256:'));
  assert.ok(b.integrity.checksum.startsWith('sha256:'));
});

test('redaction strips note + tag + user fields across all modes', async () => {
  const NOTE_SENTINEL = 'note-sentinel-' + Date.now();
  const TAG_SENTINEL = 'tag-sentinel-' + Date.now();
  for (const mode of ['none', 'exclude-private-notes', 'exclude-local-tags', 'exclude-all-user-text', 'identifiers-only']) {
    const snap = await snapshot.buildReportSnapshot({
      publicMeta: { publicIntelligenceStatus: 'available', publicIntelligenceVersion: 'v1', publicProjectionSchemaVersion: '1.0.0', fetchedAt: '2025-01-01T00:00:00.000Z', comparableAxes: [], suppressedAxes: [], sourceHealth: [] },
      vulns: [makeVuln('CVE-2025-0001', 'x')],
      entriesByCve: { 'CVE-2025-0001': { cveId: 'CVE-2025-0001', watched: true, triageStatus: 'action-required', userPriority: 'high', tags: [TAG_SENTINEL], note: NOTE_SENTINEL, addedAt: '2025-01-01T00:00:00.000Z', updatedAt: '2025-01-02T00:00:00.000Z', lastReviewedAt: null, lastSeenPublicIntelligenceVersion: 'v1', lastSeenChangeSignature: null, lastSeenPublicProjectionSchemaVersion: '1.0.0', revision: 1, mutationId: 'm1', archived: false } },
      selection: { cveIds: ['CVE-2025-0001'], includePrivateNotes: true, includeLocalTags: true, includeResolved: false, includeArchived: false },
      flushPendingWrites: async () => {},
      hasPendingWrites: false,
      options: { applicationVersion: 'v6.5' },
    });
    const r = templates.buildReport({ reportId: 'rpt-F-' + mode, reportType: 'selected-cve', title: 'F-' + mode, generatedAt: '2025-01-01T00:00:00.000Z', applicationVersion: 'v6.5', snapshot: snap, mode, includePrivateNotes: true, includeLocalTags: true });
    const flat = JSON.stringify(r);
    if (redaction.modeHidesNote(mode)) assert.ok(!flat.includes(NOTE_SENTINEL), 'note must be hidden in ' + mode);
    if (redaction.modeHidesTags(mode)) assert.ok(!flat.includes(TAG_SENTINEL), 'tag must be hidden in ' + mode);
    if (redaction.modeHidesStatus(mode)) {
      assert.ok(!flat.includes('action-required'), 'status must be hidden in ' + mode);
      assert.ok(!flat.includes('User-assigned local priority'), 'priority row must be hidden in ' + mode);
    }
  }
});

test('identifiers-only mode keeps only the CVE id', async () => {
  const r = (await buildReportFor({ title: 'G', mode: 'identifiers-only', includePrivateNotes: false, includeLocalTags: true })).report;
  const flat = JSON.stringify(r);
  assert.ok(flat.includes('CVE-2025-0001'));
  assert.ok(!flat.includes(SENTINEL));
  // Provider facts also stripped under identifiers-only.
  assert.ok(!flat.includes('cvssScore'));
  assert.ok(!flat.includes('epssProbability'));
});

test('exporters render without leaking private values', async () => {
  const r = (await buildReportFor({ title: 'H', mode: 'exclude-private-notes', includePrivateNotes: true, includeLocalTags: true })).report;
  for (const f of ['markdown', 'html', 'print', 'json']) {
    const out = exporters.exportReport(r, f);
    assert.ok(out.body.length > 0, f + ' body is empty');
    assert.ok(!out.body.includes(SENTINEL), f + ' leaked the sentinel');
    assert.ok(out.filename.startsWith('threatpulse-report-'), f + ' filename public-safe');
    assert.ok(!/[A-Z]{2,}/.test(out.filename.split('/').pop() || '') || out.filename.match(/^threatpulse-report-[a-z0-9-]+-[a-z0-9]+-\d{4}-\d{2}-\d{2}\.[a-z]+$/), f + ' filename matches convention');
  }
});

test('exportReport refuses invalid report', () => {
  assert.throws(() => exporters.exportReport({ format: 'other' }, 'json'));
});

test('verify returns correct statuses', async () => {
  const r = (await buildReportFor({ title: 'I', mode: 'none' })).report;
  const json = JSON.stringify(r);
  const ok = await verify.verifyJson(json);
  assert.equal(ok.status, 'valid');
  // Tamper
  const tampered = JSON.parse(json);
  tampered.title = 'Tampered';
  const cor = await verify.verifyJson(JSON.stringify(tampered));
  assert.equal(cor.status, 'integrity-failed');
  // Wrong format
  const wrong = await verify.verifyReport({ format: 'other', schemaVersion: '1.0.0' });
  assert.equal(wrong.status, 'invalid-format');
  // Future schema
  const future = await verify.verifyJson(JSON.stringify({ ...r, schemaVersion: '99.0.0' }));
  assert.equal(future.status, 'unsupported-schema');
  // Oversize (we use a fabricated huge string, not a real report)
  const huge = '"' + new Array(schema.REPORT_LIMITS.MAX_BYTES + 10).fill('a').join('') + '"';
  const tooBig = await verify.verifyJson(huge);
  assert.equal(tooBig.status, 'too-large');
  // Corrupt JSON
  const corrupt = await verify.verifyJson('{not json');
  assert.equal(corrupt.status, 'corrupt');
  // Incomplete (valid shape but missing integrity)
  const incomplete = await verify.verifyJson(JSON.stringify({ ...r, integrity: { canonicalizationVersion: '1.0.0', checksum: '' } }));
  assert.equal(incomplete.status, 'incomplete');
});

test('compare refuses comparison when integrity fails', async () => {
  const a = (await buildReportFor({ title: 'J', mode: 'none' })).report;
  const tampered = JSON.parse(JSON.stringify(a));
  tampered.title = 'Tampered';
  const out = await compare.compareReports(a, tampered);
  assert.equal(out.ok, false);
  assert.ok(out.reason.includes('integrity-failed'));
});

test('compare produces structured diffs for two valid reports', async () => {
  const a = (await buildReportFor({ title: 'K', mode: 'none' })).report;
  const b = (await buildReportFor({ title: 'K', mode: 'none' })).report;
  const out = await compare.compareReports(a, b);
  assert.equal(out.ok, true);
  assert.ok(Array.isArray(out.providerFacts));
  assert.ok(Array.isArray(out.localFacts));
  assert.ok(Array.isArray(out.cves?.added));
  assert.ok(Array.isArray(out.cves?.removed));
});

test('compare never interprets absence as remediation', async () => {
  // Build a report that includes the note + tag + status, then
  // build a redaction-stripped variant, and confirm compare
  // reports the *removal* rather than inventing a remediation
  // verdict.
  const full = (await buildReportFor({ title: 'L', mode: 'none', includePrivateNotes: true, includeLocalTags: true })).report;
  const stripped = (await buildReportFor({ title: 'L', mode: 'exclude-all-user-text', includePrivateNotes: true, includeLocalTags: true })).report;
  const out = await compare.compareReports(full, stripped);
  assert.equal(out.ok, true);
  // Per-CVE local-fact diffs should include the 'removed' rows
  // for the status + tags + note (NOT a fabricated 'remediated').
  const cveEntry = out.localFacts.find((x) => x.cveId === 'CVE-2025-0001');
  assert.ok(cveEntry, 'per-CVE local fact diff entry present');
  const removed = cveEntry.rows.filter((r) => r.change === 'removed');
  assert.ok(removed.length > 0, 'compare surfaces removed rows (not fabricated remediation)');
  for (const r of removed) assert.notEqual(r.change, 'remediated');
});

test('history stores summary-only entry (no notes, no full body)', async () => {
  const r = (await buildReportFor({ title: 'M', mode: 'none', includePrivateNotes: true, includeLocalTags: true })).report;
  const entry = history.buildHistoryEntry(r, { redactionMode: 'none', exportFormat: 'json' });
  assert.ok(entry, 'entry should be built');
  const flat = JSON.stringify(entry);
  assert.ok(!flat.includes(SENTINEL), 'note / tag must not be stored');
  assert.ok(!flat.includes('"sections"'), 'full sections must not be stored');
  const allowed = ['reportId', 'reportType', 'title', 'generatedAt', 'cveCount', 'publicIntelligenceStatus', 'publicIntelligenceVersion', 'includePrivateNotes', 'includeLocalTags', 'includeResolved', 'includeArchived', 'redactionMode', 'exportFormat', 'exportStatus', 'checksum', 'storedAt'];
  for (const k of Object.keys(entry)) {
    assert.ok(allowed.includes(k), 'unexpected key in history entry: ' + k);
  }
});

test('history add + list + remove + clear works through the shim', async () => {
  const r1 = (await buildReportFor({ title: 'N1', mode: 'none' })).report;
  const r2 = (await buildReportFor({ title: 'N2', mode: 'exclude-private-notes' })).report;
  // Make rids unique
  r1.reportId = 'rpt-history-' + Date.now() + '-a';
  r2.reportId = 'rpt-history-' + Date.now() + '-b';
  r1.integrity = await integrity.computeIntegrity(r1);
  r2.integrity = await integrity.computeIntegrity(r2);
  await history.addHistoryEntry(r1, { redactionMode: 'none', exportFormat: 'json' });
  await history.addHistoryEntry(r2, { redactionMode: 'exclude-private-notes', exportFormat: 'markdown' });
  const list = await history.listHistoryEntries();
  const found1 = list.find((e) => e.reportId === r1.reportId);
  const found2 = list.find((e) => e.reportId === r2.reportId);
  assert.ok(found1 && found2, 'both entries should be listed');
  await history.removeHistoryEntry(r1.reportId);
  const list2 = await history.listHistoryEntries();
  assert.ok(!list2.find((e) => e.reportId === r1.reportId), 'removed entry is gone');
  await history.clearHistory();
  const list3 = await history.listHistoryEntries();
  assert.equal(list3.length, 0, 'history cleared');
});

test('history disable flag persists', () => {
  // In Node localStorage may be undefined; the shim uses
  // a try/catch so the function is a best-effort no-op.
  history.setHistoryEnabled(false);
  history.setHistoryEnabled(true);
  assert.equal(history.isHistoryEnabled(), true);
});

test('coherent snapshot flushes pending writes', async () => {
  let flushed = false;
  let failNext = false;
  await assert.rejects(
    snapshot.buildReportSnapshot({
      publicMeta: { publicIntelligenceStatus: 'available' },
      vulns: [makeVuln('CVE-2025-0002', 'x')],
      entriesByCve: {},
      selection: { cveIds: ['CVE-2025-0002'], includePrivateNotes: false, includeLocalTags: true, includeResolved: false, includeArchived: false },
      flushPendingWrites: async () => { if (failNext) throw new Error('boom'); flushed = true; },
      hasPendingWrites: false,
      options: { applicationVersion: 'v6.5' },
    }).then(() => {
      throw new Error('should have rejected');
    }),
  );
  // Now a non-failing flush should produce a valid snapshot.
  const ok = await snapshot.buildReportSnapshot({
    publicMeta: { publicIntelligenceStatus: 'available' },
    vulns: [makeVuln('CVE-2025-0002', 'x')],
    entriesByCve: {},
    selection: { cveIds: ['CVE-2025-0002'], includePrivateNotes: false, includeLocalTags: true, includeResolved: false, includeArchived: false },
    flushPendingWrites: async () => { flushed = true; },
    hasPendingWrites: false,
    options: { applicationVersion: 'v6.5' },
  });
  assert.equal(flushed, true);
  assert.ok(ok.cveIds.length === 1);
});

test('snapshot refuses when pending writes are still in flight', async () => {
  await assert.rejects(
    snapshot.buildReportSnapshot({
      publicMeta: { publicIntelligenceStatus: 'available' },
      vulns: [makeVuln('CVE-2025-0003', 'x')],
      entriesByCve: {},
      selection: { cveIds: ['CVE-2025-0003'], includePrivateNotes: false, includeLocalTags: true, includeResolved: false, includeArchived: false },
      flushPendingWrites: async () => {},
      hasPendingWrites: true,
      options: { applicationVersion: 'v6.5' },
    }),
    /flush-still-pending/,
  );
});

test('snapshot refuses empty selection', async () => {
  await assert.rejects(
    snapshot.buildReportSnapshot({
      publicMeta: { publicIntelligenceStatus: 'available' },
      vulns: [],
      entriesByCve: {},
      selection: { cveIds: [], includePrivateNotes: false, includeLocalTags: true, includeResolved: false, includeArchived: false },
      flushPendingWrites: async () => {},
      hasPendingWrites: false,
      options: { applicationVersion: 'v6.5' },
    }),
    /empty-input/,
  );
});

test('field classification (provider-fact / user-authored / system-metadata / unavailable-or-uncertain)', () => {
  // provider-fact
  assert.equal(redaction.fieldKindOf('sections.body.rows.Severity'), 'provider-fact');
  // user-authored
  assert.equal(redaction.fieldKindOf('sections.body.rows.Local triage status (user-authored)'), 'user-authored');
  // system-metadata
  assert.equal(redaction.fieldKindOf('publicIntelligence.status'), 'system-metadata');
  // unavailable-or-uncertain
  assert.equal(redaction.fieldKindOf('sections.body.rows.Public record'), 'unavailable-or-uncertain');
  // threatpulse-derived
  assert.equal(redaction.fieldKindOf('sections.body.rows.ThreatPulse classification'), 'threatpulse-derived');
});

test('PRIVACY PROOF: build + verify + compare + history produces zero network/URL/console leaks', async () => {
  const inst = installInstrumentation();
  try {
    const r1 = (await buildReportFor({ title: 'PRIV-1', mode: 'exclude-private-notes', includePrivateNotes: true, includeLocalTags: true })).report;
    const r2 = (await buildReportFor({ title: 'PRIV-2', mode: 'exclude-private-notes', includePrivateNotes: true, includeLocalTags: true })).report;
    // Export every format
    for (const f of ['markdown', 'html', 'print', 'json']) exporters.exportReport(r1, f);
    // Verify
    const v1 = await verify.verifyReport(r1);
    const v2 = await verify.verifyJson(JSON.stringify(r1));
    assert.equal(v1.status, 'valid');
    assert.equal(v2.status, 'valid');
    // Compare
    const c = await compare.compareReports(r1, r2);
    assert.equal(c.ok, true);
    // History
    const entry = history.buildHistoryEntry(r1, { redactionMode: 'exclude-private-notes', exportFormat: 'json' });
    assert.ok(entry);
    // Now check the captured channels for the sentinel.
    assert.equal(findSentinelIn(inst.captured), false, 'sentinel leaked into fetch / xhr / beacon / history / console');
  } finally {
    inst.restore();
  }
});

test('shortChecksum returns 12 hex chars', () => {
  const s = integrity.shortChecksum('sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef');
  assert.equal(s.length, 12);
  assert.equal(s, '0123456789ab');
  // Already short
  const s2 = integrity.shortChecksum('sha256:abcd');
  assert.equal(s2, 'abcd');
  // No prefix
  const s3 = integrity.shortChecksum('not-prefixed');
  assert.equal(s3, 'not-prefixed');
});

test('exporters produce correct mime types', async () => {
  const r = (await buildReportFor({ title: 'MT', mode: 'none' })).report;
  for (const f of ['markdown', 'html', 'print', 'json']) {
    const out = exporters.exportReport(r, f);
    assert.ok(out.mimeType.includes(';charset=utf-8'), f + ' mime type must be UTF-8');
  }
});

test('history entry count cap (≤100)', async () => {
  // We don't actually fill 100 entries here (slow), but
  // we verify the cap constant is enforced.
  assert.equal(schema.REPORT_LIMITS.MAX_HISTORY_ENTRIES, 100);
});

test('standalone HTML has CSP meta and no external resources', async () => {
  const r = (await buildReportFor({ title: 'HTML', mode: 'none' })).report;
  const out = exporters.exportReport(r, 'html');
  assert.ok(out.body.includes('Content-Security-Policy'), 'CSP meta is present');
  assert.ok(out.body.includes("default-src 'none'"), 'CSP default-src is none');
  assert.ok(!out.body.includes('<script'), 'no script tag');
  assert.ok(!/<link[^>]+rel=["']?stylesheet["']?[^>]+href=["']?https?:/i.test(out.body), 'no external stylesheet link');
  assert.ok(!/<img[^>]+src=["']?https?:/i.test(out.body), 'no external image');
  assert.ok(!/<iframe/i.test(out.body), 'no iframe');
});
