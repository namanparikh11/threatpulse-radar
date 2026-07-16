/**
 * V6.5 — Local report schema, canonicalization, and
 * strict validation.
 *
 * A report is a JSON document describing a local
 * defender briefing or a defensible export. Reports
 * are:
 *   - generated entirely in the browser
 *   - strictly versioned
 *   - canonicalized deterministically (sorted keys,
 *     cveId-sorted entries, no timestamps with
 *     non-deterministic components)
 *   - integrity-checked via an async Web Crypto
 *     SHA-256 over the canonical bytes
 *   - redacted BEFORE the checksum is computed so
 *     excluded values never enter the digest input
 *
 * Reports are NOT:
 *   - certified
 *   - complete
 *   - legally admissible
 *   - digitally signed
 *   - independently verified
 *   - a replacement for professional judgment or
 *     asset validation
 *
 * The format is intentionally different from the V6.4
 * workspace export so the two never collide.
 */

export const REPORT_SCHEMA_VERSION = '1.0.0';
export const REPORT_EXPORT_FORMAT = 'threatpulse-local-report';
export const CANONICALIZATION_VERSION = '1.0.0';

/**
 * Bounded limits for a single report.
 * Exceeding either limit surfaces a sanitized
 * `too-many-cves` / `payload-too-large` error and
 * generation is aborted.
 */
export const REPORT_LIMITS = Object.freeze({
  MAX_CVES: 500,
  MAX_BYTES: 20 * 1024 * 1024, // 20 MiB
  MAX_NOTE_CHARS: 8000,
  MAX_TAGS_PER_CVE: 20,
  MAX_TAG_CHARS: 40,
  MAX_TITLE_CHARS: 200,
  MAX_HISTORY_ENTRIES: 100,
});

/** Field classification used by the UI to render
 *  inline metadata. The values are stable strings so
 *  the redaction and comparison logic can branch on
 *  them. */
export const FIELD_KIND = Object.freeze({
  PROVIDER_FACT: 'provider-fact',
  THREATPULSE_DERIVED: 'threatpulse-derived',
  USER_AUTHORED: 'user-authored',
  SYSTEM_METADATA: 'system-metadata',
  UNAVAILABLE: 'unavailable-or-uncertain',
});

/** The 5 documented report types. The `id` is the
 *  stable identifier stored in the JSON; the
 *  `label` is the human-readable copy. */
export const REPORT_TYPES = Object.freeze([
  { id: 'defender-daily-briefing', label: 'Defender Daily Briefing' },
  { id: 'local-triage-queue',       label: 'Local Triage Queue Report' },
  { id: 'selected-cve',             label: 'Selected CVE Report' },
  { id: 'change-briefing',          label: 'Change Briefing' },
  { id: 'executive-summary',        label: 'Executive Summary' },
]);

/** Redaction modes. */
export const REDACTION_MODES = Object.freeze([
  { id: 'none', label: 'No redaction (all selected local fields included)' },
  { id: 'exclude-private-notes', label: 'Exclude private notes' },
  { id: 'exclude-local-tags', label: 'Exclude local tags' },
  { id: 'exclude-all-user-text', label: 'Exclude all user-authored text' },
  { id: 'identifiers-only', label: 'Identifiers only' },
]);

const CVE_RE = /^CVE-\d{4}-\d{4,7}$/;
const PROTOTYPE_POLLUTION_KEYS = new Set(['__proto__', 'prototype', 'constructor']);

/** True iff the given string is a valid CVE id. */
export function normaliseCveId(input) {
  if (typeof input !== 'string') return null;
  const trimmed = input.trim().toUpperCase();
  if (!CVE_RE.test(trimmed)) return null;
  return trimmed;
}

function checkProto(input) {
  for (const k of Object.getOwnPropertyNames(input)) {
    if (PROTOTYPE_POLLUTION_KEYS.has(k)) {
      return `prototype-pollution:${k}`;
    }
  }
  return null;
}

function isPlainObject(v) {
  if (!v || typeof v !== 'object' || Array.isArray(v)) return false;
  const proto = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}

/**
 * Strictly validate a report payload. The function
 * returns `{ ok: true, report }` with the normalised
 * (sanitised) report, or `{ ok: false, reason }` on
 * the first violation it finds. The function never
 * throws. Future unsupported schemas are rejected
 * outright.
 *
 * Validation rules:
 *   - payload is a plain object
 *   - prototype-pollution keys are rejected
 *   - format + schemaVersion match the current
 *     values
 *   - reportType is one of the documented five
 *   - title is a non-empty string
 *   - publicIntelligence is an object with the
 *     documented fields
 *   - selection.cveIds is an array of valid CVE ids
 *   - selection flags are booleans
 *   - sections is an array
 *   - provenance is an object
 *   - limitations is an array of strings
 *   - integrity is an object with a `checksum` field
 *     starting with `sha256:`
 *   - total CVEs in the report do not exceed
 *     REPORT_LIMITS.MAX_CVES
 */
export function validateReport(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    return { ok: false, reason: 'payload-not-object' };
  }
  const p = checkProto(input);
  if (p) return { ok: false, reason: p };
  if (input.format !== REPORT_EXPORT_FORMAT) {
    return { ok: false, reason: 'invalid-format' };
  }
  if (input.schemaVersion !== REPORT_SCHEMA_VERSION) {
    return { ok: false, reason: 'unsupported-schema-version' };
  }
  if (typeof input.reportId !== 'string' || !input.reportId) {
    return { ok: false, reason: 'invalid-report-id' };
  }
  if (typeof input.title !== 'string' || input.title.length === 0) {
    return { ok: false, reason: 'invalid-title' };
  }
  if (input.title.length > REPORT_LIMITS.MAX_TITLE_CHARS) {
    return { ok: false, reason: 'title-too-long' };
  }
  if (!REPORT_TYPES.find((t) => t.id === input.reportType)) {
    return { ok: false, reason: 'invalid-report-type' };
  }
  if (typeof input.generatedAt !== 'string' || !input.generatedAt) {
    return { ok: false, reason: 'invalid-generated-at' };
  }
  if (!isPlainObject(input.publicIntelligence)) {
    return { ok: false, reason: 'invalid-public-intelligence' };
  }
  if (!isPlainObject(input.selection)) {
    return { ok: false, reason: 'invalid-selection' };
  }
  if (!Array.isArray(input.selection.cveIds)) {
    return { ok: false, reason: 'invalid-selection-cveids' };
  }
  if (input.selection.cveIds.length > REPORT_LIMITS.MAX_CVES) {
    return { ok: false, reason: 'too-many-cves' };
  }
  for (const id of input.selection.cveIds) {
    if (normaliseCveId(id) === null) {
      return { ok: false, reason: 'invalid-cve-id' };
    }
  }
  for (const k of ['includePrivateNotes', 'includeLocalTags', 'includeResolved', 'includeArchived']) {
    if (typeof input.selection[k] !== 'boolean') {
      return { ok: false, reason: `invalid-selection-${k}` };
    }
  }
  if (!Array.isArray(input.sections)) {
    return { ok: false, reason: 'invalid-sections' };
  }
  if (!Array.isArray(input.provenance)) {
    return { ok: false, reason: 'invalid-provenance' };
  }
  for (const p of input.provenance) {
    if (!isPlainObject(p)) return { ok: false, reason: 'invalid-provenance-item' };
  }
  if (!Array.isArray(input.limitations) || !input.limitations.every((l) => typeof l === 'string')) {
    return { ok: false, reason: 'invalid-limitations' };
  }
  if (!isPlainObject(input.integrity)) {
    return { ok: false, reason: 'invalid-integrity' };
  }
  if (typeof input.integrity.checksum !== 'string' || !input.integrity.checksum.startsWith('sha256:')) {
    return { ok: false, reason: 'invalid-checksum' };
  }
  return { ok: true, report: input };
}

/**
 * Coarse-grained payload size check. The exact byte
 * count is computed by `serializeReport`; this is a
 * pre-flight guard for very large inputs.
 */
export function checkSize(serialized) {
  if (typeof serialized !== 'string') return 'invalid-serialized';
  if (serialized.length > REPORT_LIMITS.MAX_BYTES) {
    return 'payload-too-large';
  }
  return null;
}

/**
 * Coarse-grained CVE count check.
 */
export function checkCveCount(input) {
  if (!input || !Array.isArray(input.selection?.cveIds)) return 'invalid-selection';
  if (input.selection.cveIds.length > REPORT_LIMITS.MAX_CVES) return 'too-many-cves';
  return null;
}
