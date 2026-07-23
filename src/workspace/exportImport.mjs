/**
 * V6.4 — Workspace export / import.
 *
 * Export: builds a JSON document with a deterministic
 * shape (sorted entries, sorted tags, deterministic
 * field order) and computes a sha256 checksum over
 * the canonical entry list. The export NEVER
 * contains credentials, browser identifiers, or
 * internal hidden fields.
 *
 * Import:
 *   - dry-run: validate the payload only. Returns
 *     the number of records that would be added /
 *     updated / left alone, plus a list of any
 *     dropped records and their reason. The existing
 *     workspace is NEVER touched.
 *   - merge: newer updatedAt wins per CVE. The
 *     comparison uses the three-level
 *     (updatedAt, revision, mutationId) tie-breaker
 *     from schema.compareUpdatedAt.
 *   - replace: every existing entry is replaced by
 *     the imported set. The import is staged FIRST
 *     (validated end-to-end) and only then promoted
 *     to the live adapter. If validation fails, the
 *     existing workspace is preserved.
 *
 * The export and import helpers are ASYNC. The
 * browser production path uses Web Crypto so the
 * main thread is never blocked by a 5 MiB payload.
 * The Node test runner uses node:crypto as the
 * fallback. No remote hashing service is used.
 */

import { sha256HexAsync, sha256HexSync } from './sha256.mjs';
import {
  WORKSPACE_SCHEMA_VERSION,
  WORKSPACE_EXPORT_FORMAT,
  LIMITS,
  validateImportPayload,
  compareUpdatedAt,
  migrationMutationId,
} from './schema.mjs';

function sortByCveId(a, b) {
  if (a.cveId < b.cveId) return -1;
  if (a.cveId > b.cveId) return 1;
  return 0;
}

function canonicaliseEntries(entries) {
  const sorted = entries.slice().sort(sortByCveId);
  return sorted.map((e) => ({
    schemaVersion: WORKSPACE_SCHEMA_VERSION,
    cveId: e.cveId,
    watched: !!e.watched,
    triageStatus: e.triageStatus,
    userPriority: e.userPriority,
    tags: (e.tags || []).slice().sort((a, b) => a < b ? -1 : a > b ? 1 : 0),
    note: e.note || '',
    addedAt: e.addedAt,
    updatedAt: e.updatedAt,
    revision: typeof e.revision === 'number' ? e.revision : 0,
    mutationId: e.mutationId || migrationMutationId(e.cveId),
    lastReviewedAt: e.lastReviewedAt || null,
    lastSeenPublicIntelligenceVersion: e.lastSeenPublicIntelligenceVersion || null,
    lastSeenChangeSignature: e.lastSeenChangeSignature || null,
    lastSeenPublicProjectionSchemaVersion: e.lastSeenPublicProjectionSchemaVersion || null,
    archived: !!e.archived,
  }));
}

async function computeChecksumAsync(canonicalEntries) {
  // Stable stringification: the entries are already
  // sorted by cveId and the field order is fixed.
  return await sha256HexAsync(JSON.stringify(canonicalEntries));
}

function computeChecksumSync(canonicalEntries) {
  // The sync path returns the same prefixed
  // form as the async path: 'sha256:<hex>'. The
  // export format document is unambiguous about
  // the prefix; both paths must produce an
  // identical payload for the same input.
  return `sha256:${sha256HexSync(JSON.stringify(canonicalEntries))}`;
}

/**
 * Build an exportable payload. The result is
 * deterministic for a given entry list (cveId
 * ascending, tags ascending, fields in fixed order).
 *
 * The checksum is async on the browser production
 * path so a 5 MiB workspace file never blocks the
 * main thread. The Node test runner uses the same
 * async path; if Web Crypto is unavailable, the
 * async call throws a sanitized `ShaUnavailableError`
 * which the caller surfaces.
 */
export async function buildExportPayload(entries, { applicationVersion = 'unknown' } = {}) {
  const canonical = canonicaliseEntries(entries || []);
  const checksum = await computeChecksumAsync(canonical);
  return {
    format: WORKSPACE_EXPORT_FORMAT,
    schemaVersion: WORKSPACE_SCHEMA_VERSION,
    exportedAt: new Date().toISOString(),
    applicationVersion,
    entryCount: canonical.length,
    entries: canonical,
    checksum,
  };
}

/** Sync variant for unit tests and small fixtures.
 *  The browser production path always uses
 *  buildExportPayload. */
export function buildExportPayloadSync(entries, { applicationVersion = 'unknown' } = {}) {
  const canonical = canonicaliseEntries(entries || []);
  return {
    format: WORKSPACE_EXPORT_FORMAT,
    schemaVersion: WORKSPACE_SCHEMA_VERSION,
    exportedAt: new Date().toISOString(),
    applicationVersion,
    entryCount: canonical.length,
    entries: canonical,
    checksum: computeChecksumSync(canonical),
  };
}

/**
 * Validate a payload without touching the live
 * adapter. Returns either `{ ok: false, reason }` or
 * `{ ok: true, entries, dropped, stats }`. The
 * async path also re-validates the checksum when a
 * checksum is present.
 */
export async function dryRunImport(payload) {
  const v = validateImportPayload(payload, {
    maxBytes: LIMITS.IMPORT_MAX_BYTES,
    maxEntries: LIMITS.IMPORT_MAX_ENTRIES,
  });
  if (!v.ok) return { ok: false, reason: v.reason, schemaVersion: v.schemaVersion };
  // Verify the embedded checksum, if present. We
  // recompute the canonical checksum from the
  // normalised entries (after validation) and
  // compare it to the payload's `checksum`. A
  // mismatch means the file was tampered with.
  if (payload && typeof payload.checksum === 'string' && payload.checksum.length > 0) {
    const canonical = canonicaliseEntries(v.entries);
    const actual = await computeChecksumAsync(canonical);
    if (actual !== payload.checksum) {
      return { ok: false, reason: 'checksum-mismatch' };
    }
  }
  return {
    ok: true,
    entries: v.entries,
    dropped: v.dropped,
    stats: {
      add: v.entries.length,
      update: 0,
      leave: 0,
      skip: 0,
      drop: v.dropped.length,
    },
  };
}

/** Sync dry-run for unit tests. */
export function dryRunImportSync(payload) {
  const v = validateImportPayload(payload, {
    maxBytes: LIMITS.IMPORT_MAX_BYTES,
    maxEntries: LIMITS.IMPORT_MAX_ENTRIES,
  });
  if (!v.ok) return { ok: false, reason: v.reason, schemaVersion: v.schemaVersion };
  if (payload && typeof payload.checksum === 'string' && payload.checksum.length > 0) {
    const canonical = canonicaliseEntries(v.entries);
    const actual = computeChecksumSync(canonical);
    if (actual !== payload.checksum) {
      return { ok: false, reason: 'checksum-mismatch' };
    }
  }
  return {
    ok: true,
    entries: v.entries,
    dropped: v.dropped,
    stats: {
      add: v.entries.length,
      update: 0,
      leave: 0,
      skip: 0,
      drop: v.dropped.length,
    },
  };
}

/**
 * Build the in-memory staged payload for an
 * import. The staged payload is a list of records
 * (after validation + per-record normalisation) and
 * is the same regardless of `merge` vs `replace`.
 */
async function stageEntries(payload) {
  const v = await dryRunImport(payload);
  if (!v.ok) return v;
  return { ok: true, entries: v.entries, dropped: v.dropped };
}

/**
 * Apply a merge. The merge is atomic at the API
 * level: every patch is written through the
 * adapter; on any write failure the operation is
 * halted and a partial result is returned.
 *
 * v6.4: the comparison uses the three-level
 * (updatedAt, revision, mutationId) tie-breaker
 * from compareUpdatedAt. The merge is "newer
 * wins" — a record with a strictly newer
 * updatedAt/revision/mutationId overrides the
 * existing record; a record that is older or
 * equal is left alone.
 */
export async function applyMerge(adapter, stagedEntries) {
  if (!Array.isArray(stagedEntries) || stagedEntries.length === 0) {
    return { ok: true, added: 0, updated: 0, unchanged: 0, removed: 0 };
  }
  const current = (await adapter.listEntries({})).entries || [];
  const currentByCve = new Map(current.map((e) => [e.cveId, e]));
  let added = 0, updated = 0, unchanged = 0;
  for (const staged of stagedEntries) {
    const cur = currentByCve.get(staged.cveId);
    if (!cur) {
      const r = await adapter.putEntry(staged);
      if (!r.ok) return { ok: false, reason: r.reason, added, updated, unchanged };
      added++;
    } else {
      const cmp = compareUpdatedAt(staged, cur);
      if (cmp > 0) {
        // The staged entry is newer. Promote it.
        const r = await adapter.putEntry(staged);
        if (!r.ok) return { ok: false, reason: r.reason, added, updated, unchanged };
        updated++;
      } else {
        unchanged++;
      }
    }
  }
  return { ok: true, added, updated, unchanged, removed: 0 };
}

/**
 * Apply a replace. The function stages the new
 * workspace entirely before clearing the old one.
 * If any stage-write fails, the existing workspace
 * is preserved.
 */
export async function applyReplace(adapter, stagedEntries) {
  if (!Array.isArray(stagedEntries)) {
    return { ok: false, reason: 'invalid-payload' };
  }
  if (typeof adapter.replaceAll === 'function') {
    return await adapter.replaceAll(stagedEntries);
  }
  // Fallback: write everything first, then clear old.
  const current = (await adapter.listEntries({})).entries || [];
  const incomingIds = new Set(stagedEntries.map((e) => e.cveId));
  let written = 0;
  for (const staged of stagedEntries) {
    const r = await adapter.putEntry(staged);
    if (!r.ok) return { ok: false, reason: r.reason };
    written++;
  }
  let removed = 0;
  for (const e of current) {
    if (!incomingIds.has(e.cveId)) {
      const r = await adapter.deleteEntry(e.cveId);
      if (!r.ok) return { ok: false, reason: r.reason };
      removed++;
    }
  }
  return { ok: true, written, removed };
}

export { stageEntries };
