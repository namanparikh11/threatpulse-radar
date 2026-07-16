/**
 * V6.4 — Local defender workspace schema.
 *
 * The workspace is the user's local-only triage surface
 * for ThreatPulse Radar. The schema is the single source
 * of truth for the shape of every record stored in the
 * browser. Records are kept in IndexedDB; the schema is
 * never sent to the server.
 *
 * Properties of every record:
 *   - schemaVersion is always present and matches a
 *     supported version (or the migration layer
 *     upgrades an older record before it is read).
 *   - cveId is a strict, normalised CVE identifier.
 *   - All string fields are trimmed and length-bounded.
 *   - Tags are normalised, deduplicated, and length-bounded.
 *   - Timestamps are local and ISO-8601.
 *   - No provider intelligence is copied into the
 *     record. lastSeenPublicIntelligenceVersion and
 *     lastSeenChangeSignature are stored as opaque
 *     references only.
 *
 * The schema is NOT a public contract; future
 * incompatible changes bump the major version. Old
 * records are either migrated or rejected.
 */

export const WORKSPACE_SCHEMA_VERSION = '1.0.0';
export const WORKSPACE_EXPORT_FORMAT = 'threatpulse-local-workspace';

export const TRIAGE_STATUSES = Object.freeze([
  'unreviewed',
  'reviewing',
  'action-required',
  'mitigating',
  'resolved',
  'accepted-risk',
  'not-applicable',
]);

export const USER_PRIORITIES = Object.freeze([
  'none',
  'low',
  'medium',
  'high',
  'urgent',
]);

/** Documented limits. Adjust with care. */
export const LIMITS = Object.freeze({
  NOTE_MAX_CHARS: 8000,
  TAGS_PER_CVE: 20,
  TAG_MAX_CHARS: 40,
  IMPORT_MAX_BYTES: 5 * 1024 * 1024,
  IMPORT_MAX_ENTRIES: 50_000,
  /** Soft warning threshold for the total entry count. */
  WARNING_ENTRIES: 5_000,
});

const CVE_RE = /^CVE-\d{4}-\d{4,7}$/;
const PROTOTYPE_POLLUTION_KEYS = new Set(['__proto__', 'prototype', 'constructor']);
const CONTROL_CHAR_RE = /[\u0000-\u001f\u007f-\u009f]/;

/**
 * Validate + normalise a CVE identifier. The result
 * is always uppercase. Returns null for any value
 * that does not match the CVE pattern.
 */
export function normaliseCveId(input) {
  if (typeof input !== 'string') return null;
  const trimmed = input.trim().toUpperCase();
  if (!CVE_RE.test(trimmed)) return null;
  return trimmed;
}

/**
 * Strip control characters from a string. Preserves
 * newlines and tabs so multi-line notes still work.
 */
export function stripControlChars(s) {
  if (typeof s !== 'string') return '';
  return s.replace(CONTROL_CHAR_RE, '');
}

export function normaliseText(input, { max = Infinity, allowNewlines = true } = {}) {
  if (typeof input !== 'string') return '';
  let s = input.replace(/\r\n?/g, '\n');
  if (!allowNewlines) s = s.replace(/\n/g, ' ');
  s = stripControlChars(s).trim();
  if (s.length > max) s = s.slice(0, max);
  return s;
}

export function normalisePriority(input) {
  if (typeof input !== 'string') return 'none';
  return USER_PRIORITIES.includes(input) ? input : 'none';
}

export function normaliseTriageStatus(input) {
  if (typeof input !== 'string') return 'unreviewed';
  return TRIAGE_STATUSES.includes(input) ? input : 'unreviewed';
}

export function normaliseTags(input) {
  if (!Array.isArray(input)) return [];
  const out = [];
  const seen = new Set();
  for (const raw of input) {
    if (typeof raw !== 'string') continue;
    const t = stripControlChars(raw).trim().slice(0, LIMITS.TAG_MAX_CHARS);
    if (!t) continue;
    const key = t.toLocaleLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(t);
    if (out.length >= LIMITS.TAGS_PER_CVE) break;
  }
  return out;
}

export function nowIso() {
  return new Date().toISOString();
}

/**
 * Build a fresh workspace record for a CVE. The
 * caller may override any field. The result is a
 * validated record: invalid overrides fall back to
 * defaults. Pure (no side effects).
 */
export function makeEntry(cveId, overrides = {}) {
  const id = normaliseCveId(cveId);
  if (id === null) {
    throw new Error(`makeEntry: invalid CVE id ${JSON.stringify(cveId)}`);
  }
  const now = nowIso();
  const out = {
    schemaVersion: WORKSPACE_SCHEMA_VERSION,
    cveId: id,
    watched: false,
    triageStatus: normaliseTriageStatus(overrides.triageStatus),
    userPriority: normalisePriority(overrides.userPriority),
    tags: normaliseTags(overrides.tags),
    note: normaliseText(overrides.note, { max: LIMITS.NOTE_MAX_CHARS }),
    addedAt: typeof overrides.addedAt === 'string' ? overrides.addedAt : now,
    updatedAt: typeof overrides.updatedAt === 'string' ? overrides.updatedAt : now,
    lastReviewedAt:
      typeof overrides.lastReviewedAt === 'string' ? overrides.lastReviewedAt : null,
    lastSeenPublicIntelligenceVersion:
      typeof overrides.lastSeenPublicIntelligenceVersion === 'string'
        ? overrides.lastSeenPublicIntelligenceVersion
        : null,
    lastSeenChangeSignature:
      typeof overrides.lastSeenChangeSignature === 'string'
        ? overrides.lastSeenChangeSignature
        : null,
    archived: !!overrides.archived,
  };
  return out;
}

/**
 * Validate an existing record (or imported object)
 * against the current schema. Returns `{ ok: true,
 * record }` with the normalised record on success, or
 * `{ ok: false, reason }` on any violation. Unknown
 * fields are stripped silently; prototype-pollution
 * keys are rejected.
 */
export function validateEntry(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    return { ok: false, reason: 'not-an-object' };
  }
  for (const k of Object.keys(input)) {
    if (PROTOTYPE_POLLUTION_KEYS.has(k)) {
      return { ok: false, reason: `prototype-pollution:${k}` };
    }
  }
  const cveId = normaliseCveId(input.cveId);
  if (cveId === null) return { ok: false, reason: 'invalid-cveId' };
  const note = normaliseText(input.note, { max: LIMITS.NOTE_MAX_CHARS });
  if (typeof input.note === 'string' && input.note.length > LIMITS.NOTE_MAX_CHARS) {
    return { ok: false, reason: 'note-too-long' };
  }
  const tags = normaliseTags(input.tags);
  if (Array.isArray(input.tags) && input.tags.length > LIMITS.TAGS_PER_CVE) {
    return { ok: false, reason: 'too-many-tags' };
  }
  return {
    ok: true,
    record: {
      schemaVersion: WORKSPACE_SCHEMA_VERSION,
      cveId,
      watched: !!input.watched,
      triageStatus: normaliseTriageStatus(input.triageStatus),
      userPriority: normalisePriority(input.userPriority),
      tags,
      note,
      addedAt: typeof input.addedAt === 'string' ? input.addedAt : nowIso(),
      updatedAt: typeof input.updatedAt === 'string' ? input.updatedAt : nowIso(),
      lastReviewedAt: typeof input.lastReviewedAt === 'string' ? input.lastReviewedAt : null,
      lastSeenPublicIntelligenceVersion:
        typeof input.lastSeenPublicIntelligenceVersion === 'string'
          ? input.lastSeenPublicIntelligenceVersion
          : null,
      lastSeenChangeSignature:
        typeof input.lastSeenChangeSignature === 'string'
          ? input.lastSeenChangeSignature
          : null,
      archived: !!input.archived,
    },
  };
}

/**
 * Validate an entire import payload. Returns
 * `{ ok: true, entries, dropped }` on success, or
 * `{ ok: false, reason, ... }` on any violation. The
 * `dropped` array lists CVEs that were discarded for
 * a non-fatal reason (e.g. invalid triage status that
 * fell back to 'unreviewed' is NOT dropped; an invalid
 * CVE id IS dropped).
 */
export function validateImportPayload(payload, { maxBytes = LIMITS.IMPORT_MAX_BYTES, maxEntries = LIMITS.IMPORT_MAX_ENTRIES } = {}) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    return { ok: false, reason: 'payload-not-object' };
  }
  for (const k of Object.keys(payload)) {
    if (PROTOTYPE_POLLUTION_KEYS.has(k)) {
      return { ok: false, reason: `prototype-pollution:${k}` };
    }
  }
  if (payload.format !== WORKSPACE_EXPORT_FORMAT) {
    return { ok: false, reason: 'invalid-format' };
  }
  if (typeof payload.schemaVersion !== 'string') {
    return { ok: false, reason: 'missing-schema-version' };
  }
  // Future versions are rejected outright. A past
  // version is migrated by the migration layer before
  // the entries are validated.
  if (!isSupportedSchemaVersion(payload.schemaVersion)) {
    return { ok: false, reason: 'unsupported-schema-version', schemaVersion: payload.schemaVersion };
  }
  if (!Array.isArray(payload.entries)) {
    return { ok: false, reason: 'entries-not-array' };
  }
  // The byte-size check is approximate but bounded.
  try {
    const json = JSON.stringify(payload);
    if (json.length > maxBytes * 2) {
      return { ok: false, reason: 'payload-too-large' };
    }
  } catch { /* best-effort */ }
  if (payload.entries.length > maxEntries) {
    return { ok: false, reason: 'too-many-entries' };
  }
  const entries = [];
  const dropped = [];
  for (const raw of payload.entries) {
    const v = validateEntry(raw);
    if (v.ok) entries.push(v.record);
    else dropped.push({ cveId: raw && raw.cveId, reason: v.reason });
  }
  return { ok: true, entries, dropped };
}

/** Supported schema versions (current only; future additions bump the list). */
const SUPPORTED_SCHEMA_VERSIONS = new Set([WORKSPACE_SCHEMA_VERSION]);
export function isSupportedSchemaVersion(v) {
  return typeof v === 'string' && SUPPORTED_SCHEMA_VERSIONS.has(v);
}

/**
 * Deterministic comparison for newer-vs-older. Used
 * by the multi-tab conflict detector. Returns -1 if a
 * is older, +1 if a is newer, 0 if equal.
 */
export function compareUpdatedAt(a, b) {
  if (a.updatedAt < b.updatedAt) return -1;
  if (a.updatedAt > b.updatedAt) return 1;
  // Deterministic tie-breaker: cveId ascending.
  if (a.cveId < b.cveId) return -1;
  if (a.cveId > b.cveId) return 1;
  return 0;
}

/**
 * Merge a patch into an existing entry. The patch
 * must contain only recognised fields. Tags are
 * REPLACED (not appended); use `addTags` / `removeTags`
 * helpers for tag deltas.
 */
const PATCH_FIELDS = new Set([
  'watched',
  'triageStatus',
  'userPriority',
  'tags',
  'note',
  'archived',
  'lastReviewedAt',
  'lastSeenPublicIntelligenceVersion',
  'lastSeenChangeSignature',
]);

export function applyPatch(entry, patch) {
  if (!entry || typeof entry !== 'object') return entry;
  if (!patch || typeof patch !== 'object') return entry;
  for (const k of Object.keys(patch)) {
    if (PROTOTYPE_POLLUTION_KEYS.has(k)) continue;
    if (!PATCH_FIELDS.has(k)) continue;
    if (k === 'tags') {
      entry.tags = normaliseTags(patch.tags);
    } else if (k === 'note') {
      entry.note = normaliseText(patch.note, { max: LIMITS.NOTE_MAX_CHARS });
    } else if (k === 'triageStatus') {
      entry.triageStatus = normaliseTriageStatus(patch.triageStatus);
    } else if (k === 'userPriority') {
      entry.userPriority = normalisePriority(patch.userPriority);
    } else if (k === 'watched' || k === 'archived') {
      entry[k] = !!patch[k];
    } else {
      entry[k] = patch[k] === null || typeof patch[k] === 'string' ? patch[k] : null;
    }
  }
  entry.updatedAt = nowIso();
  return entry;
}
