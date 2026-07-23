/**
 * V6.7 — Remediation bundle export/import.
 *
 * `threatpulse-local-remediation` v1.0.0 bundle format.
 *
 * The bundle is a self-contained, deterministic JSON
 * envelope containing the recorded plan + tasks +
 * evidence + ledger chain. The integrity is
 * established by a SHA-256 checksum over the canonical
 * JSON of the body (everything except `checksum`),
 * computed with Web Crypto. The bundle never includes
 * device identifiers, credentials, or the public
 * vulnerability corpus.
 *
 * Import lifecycle:
 *   1. validateImportPayload(json) — synchronous, runs
 *      prototype-pollution rejection, schema + version
 *      checks, size cap, and per-record limit checks.
 *   2. dry-run import — verify the bundle would
 *      succeed (no writes). Confirms every ledger
 *      chain is intact and the import would not
 *      collide with existing data.
 *   3. promote import — apply the records to the
 *      adapter, preserving the per-record revision
 *      ordering and the ledger dedup-by-eventId.
 *
 * The module is browser-reachable. It uses
 * `crypto.subtle` only. The Node test runner is
 * covered by the same Web Crypto API.
 */
import { sha256HexPrefixed } from './hash.mjs';
import { canonicalizeToString } from './canonicalize.mjs';
import { verifyChain } from './ledger.mjs';
import { REMEDIATION_LIMITS, validatePlan, validateTask, validateEvidence, validateLedgerEvent } from './schema.mjs';

export const REMEDIATION_BUNDLE_FORMAT = 'threatpulse-local-remediation';
export const REMEDIATION_BUNDLE_VERSION = '1.0.0';
export const REMEDIATION_BUNDLE_MAX_BYTES = 25 * 1024 * 1024;
export const REMEDIATION_BUNDLE_KIND_PLAN = 'plan';
export const REMEDIATION_BUNDLE_KIND_FULL = 'full';

const PROTO_POLLUTION_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

function safeParse(json) {
  if (typeof json !== 'string' || json.length === 0) return { ok: false, reason: 'empty' };
  if (json.length > REMEDIATION_BUNDLE_MAX_BYTES) return { ok: false, reason: 'too-large' };
  try {
    return { ok: true, value: JSON.parse(json) };
  } catch (err) {
    return { ok: false, reason: 'parse-failed' };
  }
}

function isPlainObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

function rejectProtoKeys(value, path = '') {
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) {
      const r = rejectProtoKeys(value[i], `${path}[${i}]`);
      if (r) return r;
    }
    return null;
  }
  if (isPlainObject(value)) {
    for (const k of Object.keys(value)) {
      if (PROTO_POLLUTION_KEYS.has(k)) return `${path || 'root'}.${k}`;
      const r = rejectProtoKeys(value[k], path ? `${path}.${k}` : k);
      if (r) return r;
    }
  }
  return null;
}

function isIsoTimestamp(s) {
  return typeof s === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})$/.test(s);
}

/**
 * Validate a parsed JSON payload as a remediation
 * bundle. Returns { ok, value } on success or
 * { ok: false, reason } on rejection. Async because
 * `verifyChain` uses Web Crypto SHA-256.
 */
export async function validateImportPayload(json) {
  const parsed = safeParse(json);
  if (!parsed.ok) return parsed;
  const root = parsed.value;
  if (!isPlainObject(root)) return { ok: false, reason: 'not-object' };
  const polluted = rejectProtoKeys(root);
  if (polluted) return { ok: false, reason: `prototype-pollution:${polluted}` };
  if (root.format !== REMEDIATION_BUNDLE_FORMAT) return { ok: false, reason: 'wrong-format' };
  if (root.schemaVersion !== REMEDIATION_BUNDLE_VERSION) return { ok: false, reason: 'unsupported-schema' };
  if (typeof root.exportedAt !== 'string' || !isIsoTimestamp(root.exportedAt)) return { ok: false, reason: 'bad-exported-at' };
  if (typeof root.applicationVersion !== 'string' || root.applicationVersion.length === 0) return { ok: false, reason: 'bad-application-version' };
  if (typeof root.checksum !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(root.checksum)) return { ok: false, reason: 'bad-checksum' };
  if (!isPlainObject(root.plans) || Array.isArray(root.plans)) return { ok: false, reason: 'bad-plans' };
  if (!isPlainObject(root.tasks) || Array.isArray(root.tasks)) return { ok: false, reason: 'bad-tasks' };
  if (!isPlainObject(root.evidence) || Array.isArray(root.evidence)) return { ok: false, reason: 'bad-evidence' };
  if (!isPlainObject(root.ledgerEvents) || Array.isArray(root.ledgerEvents)) return { ok: false, reason: 'bad-ledger' };
  if (root.kind !== REMEDIATION_BUNDLE_KIND_PLAN && root.kind !== REMEDIATION_BUNDLE_KIND_FULL) {
    return { ok: false, reason: 'bad-kind' };
  }
  if (root.kind === REMEDIATION_BUNDLE_KIND_PLAN) {
    if (typeof root.planId !== 'string' || root.planId.length === 0) return { ok: false, reason: 'bad-plan-id' };
  }
  // Per-record validation
  for (const id of Object.keys(root.plans)) {
    const v = validatePlan(root.plans[id]);
    if (!v.ok) return { ok: false, reason: `plan:${id}:${v.reason}` };
  }
  for (const id of Object.keys(root.tasks)) {
    const v = validateTask(root.tasks[id]);
    if (!v.ok) return { ok: false, reason: `task:${id}:${v.reason}` };
  }
  for (const id of Object.keys(root.evidence)) {
    const v = validateEvidence(root.evidence[id]);
    if (!v.ok) return { ok: false, reason: `evidence:${id}:${v.reason}` };
  }
  for (const planId of Object.keys(root.ledgerEvents)) {
    const list = root.ledgerEvents[planId];
    if (!Array.isArray(list)) return { ok: false, reason: 'bad-ledger-list' };
    if (list.length > REMEDIATION_LIMITS.MAX_LEDGER_EVENTS_PER_PLAN) return { ok: false, reason: 'ledger-too-long' };
    for (const ev of list) {
      const v = validateLedgerEvent(ev);
      if (!v.ok) return { ok: false, reason: `ledger:${v.reason}` };
    }
    const chain = await verifyChain(list);
    if (!chain.ok) return { ok: false, reason: `ledger:${planId}:${chain.reason}` };
  }
  return { ok: true, value: root };
}

/**
 * Build a deterministic, integrity-checked bundle
 * from a plan + its tasks + evidence + ledger events.
 * The checksum is computed over the canonical JSON
 * of the body (everything except `checksum`).
 */
export async function buildBundle(plan, tasks, evidence, events, options) {
  if (!isPlainObject(plan)) throw new Error('buildBundle: plan required');
  const planId = String(plan.planId || '');
  if (!planId) throw new Error('buildBundle: plan.planId required');
  const plans = { [planId]: plan };
  const tasksByPlan = {};
  for (const t of (Array.isArray(tasks) ? tasks : [])) {
    if (t && t.planId === planId) tasksByPlan[t.taskId] = t;
  }
  const evidenceByPlan = {};
  for (const e of (Array.isArray(evidence) ? evidence : [])) {
    if (e && e.planId === planId) evidenceByPlan[e.evidenceId] = e;
  }
  const ledgerEvents = { [planId]: Array.isArray(events) ? events.slice().sort((a, b) => a.sequence - b.sequence) : [] };
  return await _buildBody(plans, tasksByPlan, evidenceByPlan, ledgerEvents, REMEDIATION_BUNDLE_KIND_PLAN, { planId, applicationVersion: (options && options.applicationVersion) || 'unknown' });
}

/**
 * Build a full-database bundle. Use only when
 * explicitly requested — the file can be large.
 */
export async function buildFullBundle(plans, tasks, evidence, ledger, options) {
  const plansById = {};
  for (const p of (Array.isArray(plans) ? plans : [])) plansById[p.planId] = p;
  const tasksByPlan = {};
  for (const t of (Array.isArray(tasks) ? tasks : [])) {
    if (!tasksByPlan[t.planId]) tasksByPlan[t.planId] = {};
    tasksByPlan[t.planId][t.taskId] = t;
  }
  const evidenceByPlan = {};
  for (const e of (Array.isArray(evidence) ? evidence : [])) {
    if (!evidenceByPlan[e.planId]) evidenceByPlan[e.planId] = {};
    evidenceByPlan[e.planId][e.evidenceId] = e;
  }
  const ledgerEvents = {};
  for (const ev of (Array.isArray(ledger) ? ledger : [])) {
    if (!ledgerEvents[ev.planId]) ledgerEvents[ev.planId] = [];
    ledgerEvents[ev.planId].push(ev);
  }
  for (const k of Object.keys(ledgerEvents)) ledgerEvents[k].sort((a, b) => a.sequence - b.sequence);
  return await _buildBody(plansById, tasksByPlan, evidenceByPlan, ledgerEvents, REMEDIATION_BUNDLE_KIND_FULL, { applicationVersion: (options && options.applicationVersion) || 'unknown' });
}

async function _buildBody(plans, tasks, evidence, ledgerEvents, kind, options) {
  const body = {
    format: REMEDIATION_BUNDLE_FORMAT,
    schemaVersion: REMEDIATION_BUNDLE_VERSION,
    kind,
    exportedAt: nowIso(),
    applicationVersion: options.applicationVersion,
    plans,
    tasks,
    evidence,
    ledgerEvents,
  };
  if (kind === REMEDIATION_BUNDLE_KIND_PLAN && options.planId) body.planId = options.planId;
  const canonical = canonicalizeToString(body);
  const checksum = await sha256HexPrefixed(canonical);
  return { ...body, checksum };
}

function nowIso() { return new Date().toISOString(); }

/**
 * Verify a parsed bundle's checksum. Returns
 * { ok, reason }. The bundle must be re-canonicalized
 * the same way `_buildBody` does.
 */
export async function verifyBundleChecksum(parsed) {
  if (!isPlainObject(parsed)) return { ok: false, reason: 'not-object' };
  const { checksum, ...rest } = parsed;
  if (typeof checksum !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(checksum)) return { ok: false, reason: 'bad-checksum' };
  const canonical = canonicalizeToString(rest);
  const expected = await sha256HexPrefixed(canonical);
  if (expected !== checksum) return { ok: false, reason: 'checksum-mismatch' };
  return { ok: true };
}

/**
 * Plan a merge or replace import against the
 * existing adapter. Returns a per-record decision
 * list. Does NOT mutate the adapter.
 */
export async function dryRunImport(parsed, adapter) {
  if (!isPlainObject(parsed)) return { ok: false, reason: 'not-object' };
  const decisions = { plans: [], tasks: [], evidence: [], ledger: [], conflictLedger: [] };
  if (typeof adapter.getPlan !== 'function') return { ok: false, reason: 'adapter-readonly' };
  for (const id of Object.keys(parsed.plans)) {
    const existing = await adapter.getPlan(id);
    decisions.plans.push({ planId: id, action: existing && existing.ok && existing.value ? 'overwrite' : 'insert' });
  }
  // Ledger dedup: same eventId + same hash = duplicate (skip). Same eventId + different hash = hard conflict.
  for (const planId of Object.keys(parsed.ledgerEvents)) {
    const list = parsed.ledgerEvents[planId] || [];
    const existing = await adapter.listLedgerEvents(planId);
    const existingById = new Map();
    if (existing.ok) for (const ev of existing.value) existingById.set(ev.eventId, ev);
    for (const ev of list) {
      const ex = existingById.get(ev.eventId);
      if (!ex) {
        decisions.ledger.push({ planId, eventId: ev.eventId, action: 'append' });
      } else if (ex.eventHash === ev.eventHash) {
        decisions.ledger.push({ planId, eventId: ev.eventId, action: 'skip-duplicate' });
      } else {
        decisions.conflictLedger.push({ planId, eventId: ev.eventId, action: 'conflict' });
      }
    }
  }
  if (decisions.conflictLedger.length > 0) {
    return { ok: false, reason: 'ledger-conflict', decisions };
  }
  return { ok: true, decisions };
}

/**
 * Apply a parsed bundle to the adapter in the
 * given mode. Returns the same decisions structure
 * as `dryRunImport`.
 */
export async function applyImport(parsed, adapter, mode) {
  const dry = await dryRunImport(parsed, adapter);
  if (!dry.ok) return dry;
  if (typeof adapter.putPlan !== 'function' || typeof adapter.putTask !== 'function' || typeof adapter.putEvidence !== 'function' || typeof adapter.appendLedgerEvent !== 'function') {
    return { ok: false, reason: 'adapter-readonly' };
  }
  // Plans
  for (const d of dry.decisions.plans) {
    if (mode === 'merge' && d.action === 'overwrite') {
      // In merge mode, the per-record revision wins; we still
      // overwrite if the imported plan has a strictly higher
      // revision. For now we honor the higher-revision rule.
      const cur = await adapter.getPlan(d.planId);
      const curRev = cur && cur.ok && cur.value ? (cur.value.revision || 0) : 0;
      const incRev = parsed.plans[d.planId] && parsed.plans[d.planId].revision || 0;
      if (incRev <= curRev) continue;
    }
    const r = await adapter.putPlan(parsed.plans[d.planId]);
    if (!r.ok) return { ok: false, reason: `put-plan:${d.planId}:${r.reason}` };
  }
  // Tasks
  for (const planId of Object.keys(parsed.tasks)) {
    for (const taskId of Object.keys(parsed.tasks[planId])) {
      const t = parsed.tasks[planId][taskId];
      const r = await adapter.putTask(t);
      if (!r.ok) return { ok: false, reason: `put-task:${taskId}:${r.reason}` };
    }
  }
  // Evidence
  for (const planId of Object.keys(parsed.evidence)) {
    for (const eId of Object.keys(parsed.evidence[planId])) {
      const e = parsed.evidence[planId][eId];
      const r = await adapter.putEvidence(e);
      if (!r.ok) return { ok: false, reason: `put-evidence:${eId}:${r.reason}` };
    }
  }
  // Ledger
  for (const d of dry.decisions.ledger) {
    if (d.action === 'skip-duplicate') continue;
    const planId = d.planId;
    const ev = (parsed.ledgerEvents[planId] || []).find((x) => x.eventId === d.eventId);
    if (!ev) continue;
    const r = await adapter.appendLedgerEvent(ev);
    if (!r.ok) return { ok: false, reason: `append-ledger:${d.eventId}:${r.reason}` };
  }
  return { ok: true, decisions: dry.decisions };
}
