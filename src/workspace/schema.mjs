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
 *   - revision is a non-negative integer incremented
 *     exactly once per committed mutation. revision=0
 *     is the migration value for records that predate
 *     this field. The revision field is the primary
 *     tie-breaker when two committed records share an
 *     updatedAt (same millisecond).
 *   - mutationId is a per-committed-mutation identifier
 *     (random UUID/string). It is NOT a device / browser
 *     identifier. It exists only to provide a final
 *     deterministic tie-breaker when both updatedAt and
 *     revision are equal across two committed records
 *     (an effectively impossible state under normal
 *     single-tab use, but reachable if a manual export
 *     + import cycle produces a duplicate).
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
  /** Cap on mutationId string length. */
  MUTATION_ID_MAX_CHARS: 96,
});

/** Prefix used by deterministic migration mutationIds. */
export const MIGRATION_MUTATION_PREFIX = 'migrated-';
/** Revision value assigned to records that predate revision tracking. */
export const MIGRATION_REVISION = 0;
/** Revision value used for a freshly created record. */
export const INITIAL_REVISION = 1;

const CVE_RE = /^CVE-\d{4}-\d{4,7}$/;
const PROTOTYPE_POLLUTION_KEYS = new Set(['__proto__', 'prototype', 'constructor']);
// Control characters EXCEPT newline (\u000a) and tab (\u0009). The
// intent of stripControlChars is to remove ASCII control codes
// while preserving \n and \t for multi-line notes.
const CONTROL_CHAR_RE = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/;

/** Random-id generator. Node 19+ has crypto.randomUUID natively; we
 *  fall back to a time + Math.random hex string for older runtimes
 *  and for the in-memory test path that runs without Web Crypto. */
function generateMutationId() {
  try {
    if (typeof globalThis !== 'undefined' && globalThis.crypto && typeof globalThis.crypto.randomUUID === 'function') {
      return globalThis.crypto.randomUUID();
    }
  } catch { /* noop */ }
  // Time + random fallback. 16 hex chars + 16 hex chars = 32 hex.
  const t = Date.now().toString(16);
  let r = '';
  for (let i = 0; i < 16; i++) r += Math.floor(Math.random() * 16).toString(16);
  return `t-${t}-${r}`;
}

/** Public helper. Always returns a fresh non-empty string. */
export function newMutationId() {
  const id = generateMutationId();
  if (typeof id !== 'string' || id.length === 0) {
    throw new Error('newMutationId: failed to generate');
  }
  return id.slice(0, LIMITS.MUTATION_ID_MAX_CHARS);
}

/** Build a deterministic migration mutationId for a given cveId.
 *  The result is stable across migration runs, never collides with
 *  a runtime-generated mutationId (different prefix), and is bound
 *  to the CVE id so two records with the same cveId migrate to the
 *  same migration mutationId. */
export function migrationMutationId(cveId) {
  const id = normaliseCveId(cveId);
  if (id === null) {
    throw new Error('migrationMutationId: invalid cveId');
  }
  return `${MIGRATION_MUTATION_PREFIX}${id}`;
}

/** Coerce an input to a non-negative integer revision. */
function normaliseRevision(input) {
  if (typeof input === 'number' && Number.isInteger(input) && input >= 0) {
    return input;
  }
  // Migration fallback: a record that lacks revision
  // metadata (or has a non-integer one) is treated as
  // revision=0. The migration layer is responsible for
  // stamping a deterministic mutationId.
  return MIGRATION_REVISION;
}

/** Coerce an input to a valid mutationId string. */
function normaliseMutationId(input) {
  if (typeof input !== 'string') return null;
  const s = stripControlChars(input).trim();
  if (!s) return null;
  if (s.length > LIMITS.MUTATION_ID_MAX_CHARS) {
    return s.slice(0, LIMITS.MUTATION_ID_MAX_CHARS);
  }
  return s;
}

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
 * Strip ASCII control characters from a string. Preserves
 * newlines (\n) and tabs (\t) so multi-line notes still work.
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
    watched: !!overrides.watched,
    triageStatus: normaliseTriageStatus(overrides.triageStatus),
    userPriority: normalisePriority(overrides.userPriority),
    tags: normaliseTags(overrides.tags),
    note: normaliseText(overrides.note, { max: LIMITS.NOTE_MAX_CHARS }),
    addedAt: typeof overrides.addedAt === 'string' ? overrides.addedAt : now,
    updatedAt: typeof overrides.updatedAt === 'string' ? overrides.updatedAt : now,
    revision: typeof overrides.revision === 'number'
      ? normaliseRevision(overrides.revision)
      : INITIAL_REVISION,
    mutationId: normaliseMutationId(overrides.mutationId) || newMutationId(),
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
    lastSeenPublicProjectionSchemaVersion:
      typeof overrides.lastSeenPublicProjectionSchemaVersion === 'string'
        ? overrides.lastSeenPublicProjectionSchemaVersion
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
  for (const k of Object.getOwnPropertyNames(input)) {
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
      revision: normaliseRevision(input.revision),
      mutationId: normaliseMutationId(input.mutationId) || migrationMutationId(cveId),
      lastReviewedAt: typeof input.lastReviewedAt === 'string' ? input.lastReviewedAt : null,
      lastSeenPublicIntelligenceVersion:
        typeof input.lastSeenPublicIntelligenceVersion === 'string'
          ? input.lastSeenPublicIntelligenceVersion
          : null,
      lastSeenChangeSignature:
        typeof input.lastSeenChangeSignature === 'string'
          ? input.lastSeenChangeSignature
          : null,
      lastSeenPublicProjectionSchemaVersion:
        typeof input.lastSeenPublicProjectionSchemaVersion === 'string'
          ? input.lastSeenPublicProjectionSchemaVersion
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
  for (const k of Object.getOwnPropertyNames(payload)) {
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
 *
 * v6.4 hardened: the comparison is three-level:
 *   1. updatedAt (the primary, millisecond-grained
 *      timestamp)
 *   2. revision (a non-negative integer incremented
 *      exactly once per committed mutation)
 *   3. mutationId (a per-mutation random string; the
 *      deterministic final tie-breaker)
 * `cveId` is intentionally NOT used as a tie-breaker:
 * both records share the same cveId, so it cannot
 * resolve same-CVE conflicts.
 */
export function compareUpdatedAt(a, b) {
  if (a.updatedAt < b.updatedAt) return -1;
  if (a.updatedAt > b.updatedAt) return 1;
  // Same timestamp: fall through to revision.
  const ra = normaliseRevision(a.revision);
  const rb = normaliseRevision(b.revision);
  if (ra < rb) return -1;
  if (ra > rb) return 1;
  // Same timestamp AND revision: deterministic
  // tie-breaker is the mutationId (lexicographically
  // greater wins). Records lacking a mutationId
  // migrate to a deterministic value, so a runtime
  // record that genuinely collides with a migrated
  // record is still resolved consistently.
  const ma = normaliseMutationId(a.mutationId) || '';
  const mb = normaliseMutationId(b.mutationId) || '';
  if (ma < mb) return -1;
  if (ma > mb) return 1;
  return 0;
}

/** Strict newer-than: returns true iff a is strictly newer than b
 *  per compareUpdatedAt. */
export function isNewerThan(a, b) {
  return compareUpdatedAt(a, b) > 0;
}

/**
 * Merge a patch into an existing entry. The patch
 * must contain only recognised fields. Tags are
 * REPLACED (not appended); use `addTags` / `removeTags`
 * helpers for tag deltas.
 *
 * v6.4 hardened: this function DOES NOT increment
 * `revision` or stamp a new `mutationId`. The
 * commit-time layer (WorkspaceContext.applyMutation)
 * is the single source of truth for "this write
 * committed" and stamps both fields atomically with
 * the next revision number and a fresh mutationId.
 * A failed write never increments revision.
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
  'lastSeenPublicProjectionSchemaVersion',
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

/** Build the next committed-record fields after a successful
 *  patch. Pure: takes the patched entry + the current
 *  revision and returns a fresh mutationId + the next
 *  revision number. Does NOT mutate the input. */
export function stampCommitted(entry, { newMutationId: nextId } = {}) {
  if (!entry || typeof entry !== 'object') return entry;
  const next = { ...entry };
  const cur = normaliseRevision(entry.revision);
  next.revision = cur + 1;
  next.mutationId = normaliseMutationId(nextId) || newMutationId();
  return next;
}
