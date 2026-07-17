/**
 * V6.7 — Remediation migrations.
 *
 * The remediation storage records carry
 * `schemaVersion` (plan / task / evidence) or
 * `ledgerSchemaVersion` (ledger event). Migrations
 * are deterministic and run on read in the adapter.
 *
 * The V6.7 launch only recognises the initial V1.0.0
 * schema for every record type. Future schema bumps
 * add a migration step and call it from `migrate*`
 * below. Records with a future `schemaVersion` are
 * rejected by the validator before migration runs, so
 * `migrate*` only sees a known set of source versions.
 */

import { REMEDIATION_PLAN_SCHEMA_VERSION, REMEDIATION_TASK_SCHEMA_VERSION, REMEDIATION_EVIDENCE_SCHEMA_VERSION, REMEDIATION_LEDGER_SCHEMA_VERSION } from './schema.mjs';

const SUPPORTED_PLAN_VERSIONS = Object.freeze(['1.0.0']);
const SUPPORTED_TASK_VERSIONS = Object.freeze(['1.0.0']);
const SUPPORTED_EVIDENCE_VERSIONS = Object.freeze(['1.0.0']);
const SUPPORTED_LEDGER_VERSIONS = Object.freeze(['1.0.0']);

export function supportedPlanVersions() { return SUPPORTED_PLAN_VERSIONS.slice(); }
export function supportedTaskVersions() { return SUPPORTED_TASK_VERSIONS.slice(); }
export function supportedEvidenceVersions() { return SUPPORTED_EVIDENCE_VERSIONS.slice(); }
export function supportedLedgerVersions() { return SUPPORTED_LEDGER_VERSIONS.slice(); }

function unsupported(from, target) {
  return { ok: false, reason: 'unsupported-target-version', from, target };
}

function identity(record, schemaVersion) {
  return { ok: true, value: Object.assign({}, record, { schemaVersion }), changed: false };
}

/** Migrate a plan record. Source version is
 *  guaranteed to be in SUPPORTED_PLAN_VERSIONS by
 *  the time this runs. Returns `{ ok, value }` on
 *  success, `{ ok: false, reason }` otherwise. */
export function migratePlan(record, fromVersion, targetVersion) {
  if (!SUPPORTED_PLAN_VERSIONS.includes(targetVersion)) {
    return unsupported(fromVersion, targetVersion);
  }
  if (!SUPPORTED_PLAN_VERSIONS.includes(fromVersion)) {
    return unsupported(fromVersion, targetVersion);
  }
  if (targetVersion !== REMEDIATION_PLAN_SCHEMA_VERSION) {
    return unsupported(fromVersion, targetVersion);
  }
  // No migration steps between 1.0.0 and 1.0.0.
  return identity(record, REMEDIATION_PLAN_SCHEMA_VERSION);
}

export function migrateTask(record, fromVersion, targetVersion) {
  if (!SUPPORTED_TASK_VERSIONS.includes(targetVersion)) {
    return unsupported(fromVersion, targetVersion);
  }
  if (!SUPPORTED_TASK_VERSIONS.includes(fromVersion)) {
    return unsupported(fromVersion, targetVersion);
  }
  if (targetVersion !== REMEDIATION_TASK_SCHEMA_VERSION) {
    return unsupported(fromVersion, targetVersion);
  }
  return identity(record, REMEDIATION_TASK_SCHEMA_VERSION);
}

export function migrateEvidence(record, fromVersion, targetVersion) {
  if (!SUPPORTED_EVIDENCE_VERSIONS.includes(targetVersion)) {
    return unsupported(fromVersion, targetVersion);
  }
  if (!SUPPORTED_EVIDENCE_VERSIONS.includes(fromVersion)) {
    return unsupported(fromVersion, targetVersion);
  }
  if (targetVersion !== REMEDIATION_EVIDENCE_SCHEMA_VERSION) {
    return unsupported(fromVersion, targetVersion);
  }
  return identity(record, REMEDIATION_EVIDENCE_SCHEMA_VERSION);
}

export function migrateLedgerEvent(record, fromVersion, targetVersion) {
  if (!SUPPORTED_LEDGER_VERSIONS.includes(targetVersion)) {
    return unsupported(fromVersion, targetVersion);
  }
  if (!SUPPORTED_LEDGER_VERSIONS.includes(fromVersion)) {
    return unsupported(fromVersion, targetVersion);
  }
  if (targetVersion !== REMEDIATION_LEDGER_SCHEMA_VERSION) {
    return unsupported(fromVersion, targetVersion);
  }
  return identity(record, REMEDIATION_LEDGER_SCHEMA_VERSION);
}
