/**
 * V6.7 — Remediation schema.
 *
 * Strict versioned local schema for remediation
 * plans, tasks, evidence records, and ledger
 * events. The schema is the single source of truth
 * for the on-disk format; the IndexedDB, in-memory,
 * and unavailable adapters all read and write
 * through the same validation pipeline.
 *
 * Strict rules (all enforced by `validate*`):
 *   - payload is a plain object
 *   - prototype-pollution keys are rejected
 *     (`__proto__`, `prototype`, `constructor`)
 *   - non-finite numbers are rejected
 *   - string identifiers match their regexes
 *   - CVE ids match CVE-\d{4}-\d{4,7}
 *   - list sizes do not exceed the documented
 *     limits
 *   - timestamps are ISO-8601 strings
 *   - supported enums are closed
 *   - future schemaVersion is rejected
 *
 * The module NEVER mutates the input. Returns
 * a deep-cloned + frozen value when validation
 * succeeds so the adapter can safely store it.
 */

export const REMEDIATION_PLAN_SCHEMA_VERSION = '1.0.0';
export const REMEDIATION_TASK_SCHEMA_VERSION = '1.0.0';
export const REMEDIATION_EVIDENCE_SCHEMA_VERSION = '1.0.0';
export const REMEDIATION_LEDGER_SCHEMA_VERSION = '1.0.0';

export const PLAN_STATUSES = Object.freeze([
  'draft',
  'planned',
  'in-progress',
  'blocked',
  'validation-pending',
  'completed',
  'accepted-risk',
  'deferred',
  'cancelled',
]);

export const REMEDIATION_TYPES = Object.freeze([
  'patch',
  'upgrade',
  'configuration-change',
  'mitigation',
  'compensating-control',
  'remove-component',
  'replace-component',
  'isolate-asset',
  'validate-not-applicable',
  'other',
]);

export const LOCAL_PRIORITIES = Object.freeze([
  'none',
  'low',
  'medium',
  'high',
  'urgent',
]);

export const VALIDATION_STATUSES = Object.freeze([
  'not-started',
  'pending',
  'passed-locally',
  'failed-locally',
  'inconclusive',
  'not-applicable',
]);

export const TASK_STATUSES = Object.freeze([
  'todo',
  'in-progress',
  'blocked',
  'done',
  'skipped',
]);

export const EVIDENCE_TYPES = Object.freeze([
  'local-note',
  'local-file-fingerprint',
  'inventory-snapshot-reference',
  'correlation-snapshot-reference',
  'report-reference',
  'validation-result',
  'change-ticket-reference',
  'external-reference',
  'other',
]);

export const EVIDENCE_VALIDATION_OUTCOMES = Object.freeze([
  'not-applicable',
  'passed-locally',
  'failed-locally',
  'inconclusive',
]);

export const LEDGER_EVENT_TYPES = Object.freeze([
  'plan-created',
  'plan-updated',
  'status-changed',
  'task-created',
  'task-updated',
  'task-completed',
  'task-reopened',
  'evidence-added',
  'evidence-superseded',
  'validation-recorded',
  'plan-completed',
  'plan-reopened',
  'risk-accepted',
  'plan-archived',
  'plan-restored',
]);

export const REMEDIATION_LIMITS = Object.freeze({
  MAX_PLANS: 50000,
  WARNING_PLAN_COUNT: 5000,
  MAX_TASKS_PER_PLAN: 500,
  MAX_EVIDENCE_PER_PLAN: 2000,
  MAX_LEDGER_EVENTS_PER_PLAN: 50000,
  MAX_LEDGER_GAP: 1,                       // sequence must be contiguous
  MAX_PLAN_TITLE_CHARS: 200,
  MAX_PLAN_DESCRIPTION_CHARS: 8000,
  MAX_TASK_TITLE_CHARS: 200,
  MAX_TASK_DESCRIPTION_CHARS: 4000,
  MAX_BLOCKER_REASON_CHARS: 2000,
  MAX_EVIDENCE_TITLE_CHARS: 200,
  MAX_EVIDENCE_DESCRIPTION_CHARS: 8000,
  MAX_SOURCE_LABEL_CHARS: 120,
  MAX_OWNER_LABEL_CHARS: 120,
  MAX_TAG_CHARS: 40,
  MAX_TAGS: 20,
  MAX_LINKED_CVES: 500,
  MAX_LINKED_ASSETS: 500,
  MAX_LINKED_COMPONENTS: 5000,
  MAX_LINKED_CORRELATIONS: 5000,
  MAX_LINKED_INVENTORIES: 500,
  MAX_LINKED_REPORTS: 200,
  MAX_ACTOR_LABEL_CHARS: 120,
  MAX_SUMMARY_CHARS: 240,
  MAX_RATIONALE_CHARS: 4000,
  MAX_EXTERNAL_URL_CHARS: 2000,
  MAX_FILE_FINGERPRINT_BYTES: 25 * 1024 * 1024,
  MAX_FILE_NAME_CHARS: 250,
  MAX_REVISION: 1_000_000_000,
});

const ID_RE = /^[a-zA-Z0-9_-]{1,64}$/;
const CVE_RE = /^CVE-\d{4}-\d{4,7}$/;
const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/;
const SHA256_RE = /^sha256:[0-9a-f]{64}$/;
const PROTOTYPE_POLLUTION_KEYS = new Set(['__proto__', 'prototype', 'constructor']);

function isPlainObject(v) {
  if (!v || typeof v !== 'object' || Array.isArray(v)) return false;
  const p = Object.getPrototypeOf(v);
  return p === Object.prototype || p === null;
}

function hasProtoPollution(input) {
  if (!isPlainObject(input)) return false;
  for (const k of Object.getOwnPropertyNames(input)) {
    if (PROTOTYPE_POLLUTION_KEYS.has(k)) return true;
  }
  return false;
}

function isFiniteNumber(n) {
  return typeof n === 'number' && Number.isFinite(n);
}

function isIso(s) {
  return typeof s === 'string' && ISO_RE.test(s);
}

function isNonEmptyString(s, max) {
  if (typeof s !== 'string') return false;
  if (s.length === 0) return false;
  if (typeof max === 'number' && s.length > max) return false;
  return true;
}

function isBoundedString(s, max) {
  return typeof s === 'string' && s.length <= max;
}

function isStringArray(arr, maxLen, maxItem) {
  if (!Array.isArray(arr)) return false;
  if (arr.length > maxLen) return false;
  for (const s of arr) {
    if (typeof s !== 'string') return false;
    if (typeof maxItem === 'number' && s.length > maxItem) return false;
  }
  return true;
}

function isIdArray(arr, maxLen) {
  if (!Array.isArray(arr)) return false;
  if (arr.length > maxLen) return false;
  for (const s of arr) {
    if (typeof s !== 'string' || !ID_RE.test(s)) return false;
  }
  return true;
}

function isCveArray(arr, maxLen) {
  if (!Array.isArray(arr)) return false;
  if (arr.length > maxLen) return false;
  for (const s of arr) {
    if (typeof s !== 'string' || !CVE_RE.test(s)) return false;
  }
  return true;
}

function deepClone(v, seen = new WeakSet()) {
  if (v === null || typeof v !== 'object') return v;
  if (seen.has(v)) throw new Error('canonicalize: circular reference');
  seen.add(v);
  if (Array.isArray(v)) return v.map((x) => deepClone(x, seen));
  if (isPlainObject(v)) {
    const out = {};
    for (const k of Object.keys(v)) {
      if (PROTOTYPE_POLLUTION_KEYS.has(k)) continue;
      out[k] = deepClone(v[k], seen);
    }
    return out;
  }
  return v;
}

function deepFreeze(v) {
  if (v === null || typeof v !== 'object') return v;
  if (Object.isFrozen(v)) return v;
  Object.freeze(v);
  for (const k of Object.keys(v)) deepFreeze(v[k]);
  return v;
}

/** Normalize a free-form tag list: trim, dedup
 *  (case-insensitive), cap to MAX_TAGS items, cap
 *  each tag to MAX_TAG_CHARS characters. */
export function normalizeTags(input) {
  if (!Array.isArray(input)) return [];
  const seen = new Set();
  const out = [];
  for (const raw of input) {
    if (typeof raw !== 'string') continue;
    const trimmed = raw.trim();
    if (trimmed.length === 0) continue;
    if (trimmed.length > REMEDIATION_LIMITS.MAX_TAG_CHARS) continue;
    const key = trimmed.toLowerCase();
    if (seen.has(key)) continue;
    if (out.length >= REMEDIATION_LIMITS.MAX_TAGS) break;
    seen.add(key);
    out.push(trimmed);
  }
  return out;
}

/** Normalize a CVE id list: uppercase, dedup,
 *  validate, cap to MAX_LINKED_CVES. */
export function normalizeCveIds(input) {
  if (!Array.isArray(input)) return [];
  const seen = new Set();
  const out = [];
  for (const raw of input) {
    if (typeof raw !== 'string') continue;
    const upper = raw.toUpperCase().trim();
    if (!CVE_RE.test(upper)) continue;
    if (seen.has(upper)) continue;
    if (out.length >= REMEDIATION_LIMITS.MAX_LINKED_CVES) break;
    seen.add(upper);
    out.push(upper);
  }
  return out;
}

/** Normalize a local id list: dedup, validate, cap. */
function normalizeIdList(input, maxLen) {
  if (!Array.isArray(input)) return [];
  const seen = new Set();
  const out = [];
  for (const raw of input) {
    if (typeof raw !== 'string' || !ID_RE.test(raw)) continue;
    if (seen.has(raw)) continue;
    if (out.length >= maxLen) break;
    seen.add(raw);
    out.push(raw);
  }
  return out;
}

/** Validate a remediation plan object. */
export function validatePlan(input) {
  if (!isPlainObject(input)) return { ok: false, reason: 'invalid-plan-shape' };
  if (hasProtoPollution(input)) return { ok: false, reason: 'prototype-pollution' };
  if (input.schemaVersion !== REMEDIATION_PLAN_SCHEMA_VERSION) return { ok: false, reason: 'unsupported-schema-version' };
  if (!isNonEmptyString(input.planId, 64)) return { ok: false, reason: 'invalid-plan-id' };
  if (!ID_RE.test(input.planId)) return { ok: false, reason: 'invalid-plan-id' };
  if (!isNonEmptyString(input.title, REMEDIATION_LIMITS.MAX_PLAN_TITLE_CHARS)) return { ok: false, reason: 'invalid-title' };
  if (typeof input.description !== 'string' || input.description.length > REMEDIATION_LIMITS.MAX_PLAN_DESCRIPTION_CHARS) {
    return { ok: false, reason: 'invalid-description' };
  }
  if (!PLAN_STATUSES.includes(input.status)) return { ok: false, reason: 'invalid-status' };
  if (!REMEDIATION_TYPES.includes(input.remediationType)) return { ok: false, reason: 'invalid-remediation-type' };
  if (!LOCAL_PRIORITIES.includes(input.localPriority)) return { ok: false, reason: 'invalid-local-priority' };
  if (typeof input.ownerLabel !== 'string' || input.ownerLabel.length > REMEDIATION_LIMITS.MAX_OWNER_LABEL_CHARS) {
    return { ok: false, reason: 'invalid-owner-label' };
  }
  if (input.dueAt !== null && !isIso(input.dueAt)) return { ok: false, reason: 'invalid-due-at' };
  if (input.startedAt !== null && !isIso(input.startedAt)) return { ok: false, reason: 'invalid-started-at' };
  if (input.completedAt !== null && !isIso(input.completedAt)) return { ok: false, reason: 'invalid-completed-at' };
  if (!VALIDATION_STATUSES.includes(input.validationStatus)) return { ok: false, reason: 'invalid-validation-status' };
  if (!isCveArray(input.linkedCveIds, REMEDIATION_LIMITS.MAX_LINKED_CVES)) return { ok: false, reason: 'invalid-linked-cves' };
  if (!isIdArray(input.linkedAssetIds, REMEDIATION_LIMITS.MAX_LINKED_ASSETS)) return { ok: false, reason: 'invalid-linked-assets' };
  if (!isIdArray(input.linkedComponentIds, REMEDIATION_LIMITS.MAX_LINKED_COMPONENTS)) return { ok: false, reason: 'invalid-linked-components' };
  if (!isIdArray(input.linkedCorrelationIds, REMEDIATION_LIMITS.MAX_LINKED_CORRELATIONS)) return { ok: false, reason: 'invalid-linked-correlations' };
  if (!isIdArray(input.linkedInventoryIds, REMEDIATION_LIMITS.MAX_LINKED_INVENTORIES)) return { ok: false, reason: 'invalid-linked-inventories' };
  if (!isStringArray(input.tags, REMEDIATION_LIMITS.MAX_TAGS, REMEDIATION_LIMITS.MAX_TAG_CHARS)) {
    return { ok: false, reason: 'invalid-tags' };
  }
  if (typeof input.acceptedRiskRationale !== 'string' || input.acceptedRiskRationale.length > REMEDIATION_LIMITS.MAX_RATIONALE_CHARS) {
    return { ok: false, reason: 'invalid-accepted-risk-rationale' };
  }
  if (typeof input.notes !== 'string' || input.notes.length > REMEDIATION_LIMITS.MAX_PLAN_DESCRIPTION_CHARS) {
    return { ok: false, reason: 'invalid-notes' };
  }
  if (!isIso(input.createdAt)) return { ok: false, reason: 'invalid-created-at' };
  if (!isIso(input.updatedAt)) return { ok: false, reason: 'invalid-updated-at' };
  if (!isFiniteNumber(input.revision) || input.revision < 0 || input.revision > REMEDIATION_LIMITS.MAX_REVISION) {
    return { ok: false, reason: 'invalid-revision' };
  }
  if (typeof input.mutationId !== 'string' || !ID_RE.test(input.mutationId)) {
    return { ok: false, reason: 'invalid-mutation-id' };
  }
  if (typeof input.archived !== 'boolean') return { ok: false, reason: 'invalid-archived' };
  return { ok: true, value: deepFreeze(deepClone(input)) };
}

/** Validate a remediation task object. */
export function validateTask(input) {
  if (!isPlainObject(input)) return { ok: false, reason: 'invalid-task-shape' };
  if (hasProtoPollution(input)) return { ok: false, reason: 'prototype-pollution' };
  if (input.schemaVersion !== REMEDIATION_TASK_SCHEMA_VERSION) return { ok: false, reason: 'unsupported-schema-version' };
  if (!isNonEmptyString(input.taskId, 64)) return { ok: false, reason: 'invalid-task-id' };
  if (!ID_RE.test(input.taskId)) return { ok: false, reason: 'invalid-task-id' };
  if (!isNonEmptyString(input.planId, 64)) return { ok: false, reason: 'invalid-plan-id' };
  if (!ID_RE.test(input.planId)) return { ok: false, reason: 'invalid-plan-id' };
  if (!isNonEmptyString(input.title, REMEDIATION_LIMITS.MAX_TASK_TITLE_CHARS)) return { ok: false, reason: 'invalid-title' };
  if (typeof input.description !== 'string' || input.description.length > REMEDIATION_LIMITS.MAX_TASK_DESCRIPTION_CHARS) {
    return { ok: false, reason: 'invalid-description' };
  }
  if (!TASK_STATUSES.includes(input.status)) return { ok: false, reason: 'invalid-status' };
  if (typeof input.ownerLabel !== 'string' || input.ownerLabel.length > REMEDIATION_LIMITS.MAX_OWNER_LABEL_CHARS) {
    return { ok: false, reason: 'invalid-owner-label' };
  }
  if (input.dueAt !== null && !isIso(input.dueAt)) return { ok: false, reason: 'invalid-due-at' };
  if (input.completedAt !== null && !isIso(input.completedAt)) return { ok: false, reason: 'invalid-completed-at' };
  if (!isFiniteNumber(input.order) || input.order < 0) return { ok: false, reason: 'invalid-order' };
  if (typeof input.blockerReason !== 'string' || input.blockerReason.length > REMEDIATION_LIMITS.MAX_BLOCKER_REASON_CHARS) {
    return { ok: false, reason: 'invalid-blocker-reason' };
  }
  if (!isIso(input.createdAt)) return { ok: false, reason: 'invalid-created-at' };
  if (!isIso(input.updatedAt)) return { ok: false, reason: 'invalid-updated-at' };
  if (!isFiniteNumber(input.revision) || input.revision < 0 || input.revision > REMEDIATION_LIMITS.MAX_REVISION) {
    return { ok: false, reason: 'invalid-revision' };
  }
  if (typeof input.mutationId !== 'string' || !ID_RE.test(input.mutationId)) {
    return { ok: false, reason: 'invalid-mutation-id' };
  }
  return { ok: true, value: deepFreeze(deepClone(input)) };
}

/** Validate a remediation evidence record. */
export function validateEvidence(input) {
  if (!isPlainObject(input)) return { ok: false, reason: 'invalid-evidence-shape' };
  if (hasProtoPollution(input)) return { ok: false, reason: 'prototype-pollution' };
  if (input.schemaVersion !== REMEDIATION_EVIDENCE_SCHEMA_VERSION) return { ok: false, reason: 'unsupported-schema-version' };
  if (!isNonEmptyString(input.evidenceId, 64)) return { ok: false, reason: 'invalid-evidence-id' };
  if (!ID_RE.test(input.evidenceId)) return { ok: false, reason: 'invalid-evidence-id' };
  if (!isNonEmptyString(input.planId, 64)) return { ok: false, reason: 'invalid-plan-id' };
  if (!ID_RE.test(input.planId)) return { ok: false, reason: 'invalid-plan-id' };
  if (input.taskId !== null && (typeof input.taskId !== 'string' || !ID_RE.test(input.taskId))) {
    return { ok: false, reason: 'invalid-task-id' };
  }
  if (!EVIDENCE_TYPES.includes(input.evidenceType)) return { ok: false, reason: 'invalid-evidence-type' };
  if (!isNonEmptyString(input.title, REMEDIATION_LIMITS.MAX_EVIDENCE_TITLE_CHARS)) return { ok: false, reason: 'invalid-title' };
  if (typeof input.description !== 'string' || input.description.length > REMEDIATION_LIMITS.MAX_EVIDENCE_DESCRIPTION_CHARS) {
    return { ok: false, reason: 'invalid-description' };
  }
  if (!isIso(input.capturedAt)) return { ok: false, reason: 'invalid-captured-at' };
  if (typeof input.sourceLabel !== 'string' || input.sourceLabel.length > REMEDIATION_LIMITS.MAX_SOURCE_LABEL_CHARS) {
    return { ok: false, reason: 'invalid-source-label' };
  }
  if (input.externalUrl !== null) {
    if (typeof input.externalUrl !== 'string' || input.externalUrl.length === 0 || input.externalUrl.length > REMEDIATION_LIMITS.MAX_EXTERNAL_URL_CHARS) {
      return { ok: false, reason: 'invalid-external-url' };
    }
    // http(s) only; no javascript:, data:, file: schemes
    if (!/^https?:\/\//i.test(input.externalUrl)) return { ok: false, reason: 'invalid-external-url' };
  }
  if (input.linkedInventoryId !== null && (typeof input.linkedInventoryId !== 'string' || !ID_RE.test(input.linkedInventoryId))) {
    return { ok: false, reason: 'invalid-linked-inventory-id' };
  }
  if (input.linkedCorrelationId !== null && (typeof input.linkedCorrelationId !== 'string' || !ID_RE.test(input.linkedCorrelationId))) {
    return { ok: false, reason: 'invalid-linked-correlation-id' };
  }
  if (input.linkedReportId !== null && (typeof input.linkedReportId !== 'string' || input.linkedReportId.length > 200)) {
    return { ok: false, reason: 'invalid-linked-report-id' };
  }
  if (input.fileFingerprint !== null) {
    const f = input.fileFingerprint;
    if (!isPlainObject(f)) return { ok: false, reason: 'invalid-file-fingerprint' };
    if (hasProtoPollution(f)) return { ok: false, reason: 'prototype-pollution' };
    if (typeof f.fileName !== 'string' || f.fileName.length === 0 || f.fileName.length > REMEDIATION_LIMITS.MAX_FILE_NAME_CHARS) {
      return { ok: false, reason: 'invalid-file-name' };
    }
    if (typeof f.sizeBytes !== 'number' || !isFiniteNumber(f.sizeBytes) || f.sizeBytes < 0 || f.sizeBytes > REMEDIATION_LIMITS.MAX_FILE_FINGERPRINT_BYTES) {
      return { ok: false, reason: 'invalid-size-bytes' };
    }
    if (typeof f.mimeType !== 'string' || f.mimeType.length > 200) return { ok: false, reason: 'invalid-mime-type' };
    if (f.lastModified !== null && (typeof f.lastModified !== 'number' || !isFiniteNumber(f.lastModified) || f.lastModified < 0)) {
      return { ok: false, reason: 'invalid-last-modified' };
    }
    if (typeof f.checksum !== 'string' || !SHA256_RE.test(f.checksum)) {
      return { ok: false, reason: 'invalid-checksum' };
    }
  }
  if (input.validationOutcome !== null && !EVIDENCE_VALIDATION_OUTCOMES.includes(input.validationOutcome)) {
    return { ok: false, reason: 'invalid-validation-outcome' };
  }
  if (input.supersedesEvidenceId !== null && (typeof input.supersedesEvidenceId !== 'string' || !ID_RE.test(input.supersedesEvidenceId))) {
    return { ok: false, reason: 'invalid-supersedes-evidence-id' };
  }
  if (!isIso(input.createdAt)) return { ok: false, reason: 'invalid-created-at' };
  if (!isFiniteNumber(input.revision) || input.revision < 0 || input.revision > REMEDIATION_LIMITS.MAX_REVISION) {
    return { ok: false, reason: 'invalid-revision' };
  }
  if (typeof input.mutationId !== 'string' || !ID_RE.test(input.mutationId)) {
    return { ok: false, reason: 'invalid-mutation-id' };
  }
  return { ok: true, value: deepFreeze(deepClone(input)) };
}

/** Validate a ledger event. */
export function validateLedgerEvent(input) {
  if (!isPlainObject(input)) return { ok: false, reason: 'invalid-event-shape' };
  if (hasProtoPollution(input)) return { ok: false, reason: 'prototype-pollution' };
  if (input.ledgerSchemaVersion !== REMEDIATION_LEDGER_SCHEMA_VERSION) return { ok: false, reason: 'unsupported-schema-version' };
  if (!isNonEmptyString(input.eventId, 64)) return { ok: false, reason: 'invalid-event-id' };
  if (!ID_RE.test(input.eventId)) return { ok: false, reason: 'invalid-event-id' };
  if (!isNonEmptyString(input.planId, 64)) return { ok: false, reason: 'invalid-plan-id' };
  if (!ID_RE.test(input.planId)) return { ok: false, reason: 'invalid-plan-id' };
  if (!isFiniteNumber(input.sequence) || input.sequence < 0) return { ok: false, reason: 'invalid-sequence' };
  if (!LEDGER_EVENT_TYPES.includes(input.eventType)) return { ok: false, reason: 'invalid-event-type' };
  if (!isIso(input.occurredAt)) return { ok: false, reason: 'invalid-occurred-at' };
  if (typeof input.actorLabel !== 'string' || input.actorLabel.length > REMEDIATION_LIMITS.MAX_ACTOR_LABEL_CHARS) {
    return { ok: false, reason: 'invalid-actor-label' };
  }
  if (typeof input.summary !== 'string' || input.summary.length === 0 || input.summary.length > REMEDIATION_LIMITS.MAX_SUMMARY_CHARS) {
    return { ok: false, reason: 'invalid-summary' };
  }
  if (!isPlainObject(input.targetIds)) return { ok: false, reason: 'invalid-target-ids' };
  if (hasProtoPollution(input.targetIds)) return { ok: false, reason: 'prototype-pollution' };
  if (input.previousEventHash !== null && (typeof input.previousEventHash !== 'string' || !SHA256_RE.test(input.previousEventHash))) {
    return { ok: false, reason: 'invalid-previous-event-hash' };
  }
  if (typeof input.eventHash !== 'string' || !SHA256_RE.test(input.eventHash)) {
    return { ok: false, reason: 'invalid-event-hash' };
  }
  return { ok: true, value: deepFreeze(deepClone(input)) };
}

/** Normalize a plan input by applying the documented
 *  ordering and formatting rules. Used by both the
 *  adapter (before write) and the export pipeline
 *  (before hash). */
export function normalizePlan(input) {
  if (!isPlainObject(input)) throw new Error('normalizePlan: invalid input');
  return {
    schemaVersion: REMEDIATION_PLAN_SCHEMA_VERSION,
    planId: input.planId,
    title: input.title,
    description: input.description,
    status: input.status,
    remediationType: input.remediationType,
    localPriority: input.localPriority,
    ownerLabel: input.ownerLabel,
    dueAt: input.dueAt,
    startedAt: input.startedAt,
    completedAt: input.completedAt,
    validationStatus: input.validationStatus,
    linkedCveIds: normalizeCveIds(input.linkedCveIds),
    linkedAssetIds: normalizeIdList(input.linkedAssetIds, REMEDIATION_LIMITS.MAX_LINKED_ASSETS),
    linkedComponentIds: normalizeIdList(input.linkedComponentIds, REMEDIATION_LIMITS.MAX_LINKED_COMPONENTS),
    linkedCorrelationIds: normalizeIdList(input.linkedCorrelationIds, REMEDIATION_LIMITS.MAX_LINKED_CORRELATIONS),
    linkedInventoryIds: normalizeIdList(input.linkedInventoryIds, REMEDIATION_LIMITS.MAX_LINKED_INVENTORIES),
    tags: normalizeTags(input.tags),
    acceptedRiskRationale: input.acceptedRiskRationale || '',
    notes: input.notes || '',
    createdAt: input.createdAt,
    updatedAt: input.updatedAt,
    revision: input.revision,
    mutationId: input.mutationId,
    archived: Boolean(input.archived),
  };
}
