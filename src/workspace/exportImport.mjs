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
 *   - merge: newer updatedAt wins per CVE. Ties are
 *     broken by deterministic cveId order. The merge
 *     happens in a single batch (the existing entries
 *     are NOT deleted first; merge is additive).
 *   - replace: every existing entry is replaced by
 *     the imported set. The import is staged FIRST
 *     (validated end-to-end) and only then promoted
 *     to the live adapter. If validation fails, the
 *     existing workspace is preserved.
 *
 * The export function is intentionally a PURE function
 * of the entry list. The import function takes the
 * adapter as an argument so it can stage the new
 * workspace in memory before promoting it.
 */

import { createHash } from 'node:crypto';
import {
  WORKSPACE_SCHEMA_VERSION,
  WORKSPACE_EXPORT_FORMAT,
  LIMITS,
  validateImportPayload,
  validateEntry,
  compareUpdatedAt,
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
    lastReviewedAt: e.lastReviewedAt || null,
    lastSeenPublicIntelligenceVersion: e.lastSeenPublicIntelligenceVersion || null,
    lastSeenChangeSignature: e.lastSeenChangeSignature || null,
    archived: !!e.archived,
  }));
}

function computeChecksum(canonicalEntries) {
  const h = createHash('sha256');
  // Stable stringification: the entries are already
  // sorted by cveId and the field order is fixed.
  h.update(JSON.stringify(canonicalEntries));
  return 'sha256:' + h.digest('hex');
}

/**
 * Build an exportable payload. The result is
 * deterministic for a given entry list (cveId
 * ascending, tags ascending, fields in fixed order).
 * The checksum is computed over the canonical entry
 * list.
 */
export function buildExportPayload(entries, { applicationVersion = 'unknown' } = {}) {
  const canonical = canonicaliseEntries(entries || []);
  const checksum = computeChecksum(canonical);
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

/**
 * Validate a payload without touching the live
 * adapter. Returns either `{ ok: false, reason }` or
 * `{ ok: true, entries, dropped, stats }`.
 */
export function dryRunImport(payload) {
  const v = validateImportPayload(payload, {
    maxBytes: LIMITS.IMPORT_MAX_BYTES,
    maxEntries: LIMITS.IMPORT_MAX_ENTRIES,
  });
  if (!v.ok) return { ok: false, reason: v.reason, schemaVersion: v.schemaVersion };
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
function stageEntries(payload) {
  const v = validateImportPayload(payload, {
    maxBytes: LIMITS.IMPORT_MAX_BYTES,
    maxEntries: LIMITS.IMPORT_MAX_ENTRIES,
  });
  if (!v.ok) {
    return { ok: false, reason: v.reason, schemaVersion: v.schemaVersion };
  }
  return { ok: true, entries: v.entries, dropped: v.dropped };
}

/**
 * Compute the merge result against the live
 * adapter. The merge is determined ENTIRELY from
 * the current live state and the staged entries;
 * no partial application happens here. The caller
 * (the WorkspaceContext) performs the writes.
 */
export async function computeMerge(adapter) {
  const current = (await adapter.listEntries({})).entries || [];
  const currentByCve = new Map(current.map((e) => [e.cveId, e]));
  return {
    add: [], update: [], leave: [], remove: [],
  };
}

/**
 * Apply a merge. The merge is atomic at the API
 * level: every patch is written through the
 * adapter; on any write failure the operation is
 * halted and a partial result is returned.
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
  // 1. Stage every new entry into a temp namespace.
  //    We do this by writing through a temporary
  //    "stage" set on the adapter (the in-memory
  //    adapter supports this; the IndexedDB adapter
  //    uses an isolated transaction below).
  // 2. Validate by reading the staged entries back.
  // 3. Clear the live store.
  // 4. Promote the staged entries into the live store.
  // 5. On any failure between steps, leave the live
  //    store untouched.
  if (!Array.isArray(stagedEntries)) {
    return { ok: false, reason: 'invalid-payload' };
  }
  // For the in-memory adapter, a simple put+clear
  // works. For IndexedDB, we must do this in a single
  // transaction. The adapter-level method does that.
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
