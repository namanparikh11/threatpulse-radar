/**
 * V6.0 — OSV bootstrap state.
 *
 * The bootstrap state is a small, Blob-backed document that records
 * where the OSV incremental ingestion is in its run. The state is
 * not the authoritative configuration — `config/osv-ecosystems.json`
 * is. The state is a journal of progress: it lets the Background
 * Function resume mid-run after a 15-minute ceiling, and it lets
 * operators see at a glance what happened in the last run.
 *
 * Schema (see `schemas/osv-bootstrap-state-v1.schema.json`):
 *   {
 *     schemaVersion: "1.0.0",
 *     status:        "idle" | "running" | "failed" | "paused",
 *     phase:         "preparation" | "ingestion" | "publication" | "complete",
 *     startedAt:     ISO string | null,
 *     lastSuccessfulAt: ISO string | null,
 *     configHash:    "sha256:<64 hex>" | null,
 *     overlapWindowMs: number,
 *     recordsPersistInterval: number,
 *     perEcosystem:  { [ecosystem]: {
 *       cursor: number,                   // next index into the CSV to fetch
 *       processedCount: number,           // running total this run
 *       totalSeenCount: number,           // running total processed in last completed run
 *       lastId: string | null,           // last OSV id successfully processed
 *       lastError: { message, at } | null,
 *       recentIds: [string, ...],         // bounded ring of recently-processed ids
 *     } },
 *     errors:        { [ecosystem]: { message, at } },
 *     lastPublishedBaselineVersion: string | null,
 *     lastPublishedAt: ISO string | null,
 *   }
 *
 * The `recentIds` ring is bounded (default 2000 per ecosystem) and is
 * the deduplication surface for "equal-timestamp OSV updates cannot
 * be skipped": when the same OSV id appears in two consecutive
 * `modified_id.csv` reads, we know to re-emit the canonical record
 * (which is the correct behavior — content may have changed even if
 * the timestamp didn't).
 *
 * The full processed-id history is NOT retained. The state is a
 * journal, not a log.
 */

import { readJson, writeJson } from './baselineStore.mjs';

export const OSV_BOOTSTRAP_STATE_KEY = 'osv-bootstrap-state';
export const OSV_BOOTSTRAP_STATE_SCHEMA = '1.0.0';

export const STATUS = Object.freeze({
  IDLE: 'idle',
  RUNNING: 'running',
  FAILED: 'failed',
  PAUSED: 'paused',
});

export const PHASE = Object.freeze({
  PREPARATION: 'preparation',
  INGESTION: 'ingestion',
  PUBLICATION: 'publication',
  COMPLETE: 'complete',
});

/** Default overlap window in ms. 15 minutes matches the V6.0 spec. */
export const DEFAULT_OVERLAP_WINDOW_MS = 15 * 60 * 1000;

/** Default per-run records-persist interval. The spec's default is 200. */
export const DEFAULT_RECORDS_PERSIST_INTERVAL = 200;

/** Bounded size of the per-ecosystem recent-ids ring. */
export const RECENT_IDS_RING_SIZE = 2000;

/**
 * Build a fresh, empty bootstrap state. Used by the read helper when
 * the Blob key is missing (first run ever) and by tests.
 */
export function initialBootstrapState({
  overlapWindowMs = DEFAULT_OVERLAP_WINDOW_MS,
  recordsPersistInterval = DEFAULT_RECORDS_PERSIST_INTERVAL,
} = {}) {
  return {
    schemaVersion: OSV_BOOTSTRAP_STATE_SCHEMA,
    status: STATUS.IDLE,
    phase: PHASE.PREPARATION,
    startedAt: null,
    lastSuccessfulAt: null,
    configHash: null,
    overlapWindowMs,
    recordsPersistInterval,
    perEcosystem: {},
    errors: {},
    lastPublishedBaselineVersion: null,
    lastPublishedAt: null,
  };
}

/**
 * Read the bootstrap state from the Blob store. Returns a fresh
 * initial state when the key is missing.
 */
export async function readBootstrapState(store) {
  const existing = await readJson(store, OSV_BOOTSTRAP_STATE_KEY);
  if (!existing || typeof existing !== 'object') return initialBootstrapState();
  // Forward-compat: if the schemaVersion is missing or unknown, we
  // treat the state as empty rather than guessing. The 1.0 schema
  // has a fixed shape; a future 1.1 may add fields, and the read
  // helper can still handle 1.0 records.
  if (existing.schemaVersion !== OSV_BOOTSTRAP_STATE_SCHEMA) {
    return initialBootstrapState({
      overlapWindowMs: typeof existing.overlapWindowMs === 'number'
        ? existing.overlapWindowMs
        : DEFAULT_OVERLAP_WINDOW_MS,
      recordsPersistInterval: typeof existing.recordsPersistInterval === 'number'
        ? existing.recordsPersistInterval
        : DEFAULT_RECORDS_PERSIST_INTERVAL,
    });
  }
  return existing;
}

/**
 * Persist the bootstrap state. Best-effort; returns false on failure.
 */
export async function writeBootstrapState(store, state) {
  return writeJson(store, OSV_BOOTSTRAP_STATE_KEY, state);
}

/**
 * Mark a new run as started. Mutates and returns a fresh state
 * object. The caller is expected to write the state to the store
 * after this call.
 */
export function markRunStarted(state, { configHash, now = new Date(), overlapWindowMs, recordsPersistInterval } = {}) {
  if (typeof configHash !== 'string' || !configHash.startsWith('sha256:')) {
    throw new Error('markRunStarted: configHash (sha256:<hex>) is required');
  }
  return {
    ...state,
    status: STATUS.RUNNING,
    phase: PHASE.PREPARATION,
    startedAt: now.toISOString(),
    configHash,
    overlapWindowMs: typeof overlapWindowMs === 'number' ? overlapWindowMs : state.overlapWindowMs,
    recordsPersistInterval: typeof recordsPersistInterval === 'number' ? recordsPersistInterval : state.recordsPersistInterval,
    // Per-ecosystem cursors are reset at the start of a run.
    perEcosystem: {},
    errors: {},
  };
}

/**
 * Mark the run as complete (idle / complete phase). Preserves the
 * per-ecosystem cursors so the next run can read them as the
 * starting point.
 */
export function markRunComplete(state, { now = new Date(), publishedBaselineVersion = null, publishedAt = null } = {}) {
  return {
    ...state,
    status: STATUS.IDLE,
    phase: PHASE.COMPLETE,
    lastSuccessfulAt: now.toISOString(),
    lastPublishedBaselineVersion: publishedBaselineVersion || state.lastPublishedBaselineVersion,
    lastPublishedAt: publishedAt || (publishedBaselineVersion ? now.toISOString() : state.lastPublishedAt),
  };
}

/**
 * Mark the run as failed for a specific ecosystem. The overall
 * status becomes 'failed' but the run can be retried; the cursor
 * for the failing ecosystem is rolled back to its pre-run value so
 * the next run re-fetches the same range.
 */
export function markEcosystemFailed(state, ecosystem, errorMessage, { now = new Date() } = {}) {
  const errors = { ...state.errors };
  errors[ecosystem] = { message: String(errorMessage), at: now.toISOString() };
  const perEcosystem = { ...state.perEcosystem };
  if (perEcosystem[ecosystem]) {
    perEcosystem[ecosystem] = {
      ...perEcosystem[ecosystem],
      lastError: { message: String(errorMessage), at: now.toISOString() },
    };
  } else {
    perEcosystem[ecosystem] = {
      cursor: 0,
      processedCount: 0,
      totalSeenCount: 0,
      lastId: null,
      lastError: { message: String(errorMessage), at: now.toISOString() },
      recentIds: [],
    };
  }
  return {
    ...state,
    status: STATUS.FAILED,
    errors,
    perEcosystem,
  };
}

/**
 * Update the per-ecosystem cursor and append to the recent-ids ring.
 * Returns a NEW state object (immutable update). When the
 * `processedCount` crosses the records-persist interval, the caller
 * is expected to persist the new state. (The helper does NOT
 * auto-persist; that keeps the I/O policy in one place.)
 */
export function recordEcosystemProgress(state, ecosystem, { id, newCursor, totalSeen } = {}) {
  if (typeof ecosystem !== 'string' || ecosystem.length === 0) {
    throw new Error('recordEcosystemProgress: ecosystem is required');
  }
  const prev = state.perEcosystem[ecosystem] || {
    cursor: 0,
    processedCount: 0,
    totalSeenCount: 0,
    lastId: null,
    lastError: null,
    recentIds: [],
  };
  const recentIds = prev.recentIds.slice();
  if (typeof id === 'string' && id.length > 0) {
    recentIds.push(id);
    if (recentIds.length > RECENT_IDS_RING_SIZE) {
      recentIds.splice(0, recentIds.length - RECENT_IDS_RING_SIZE);
    }
  }
  const next = {
    ...prev,
    cursor: typeof newCursor === 'number' ? newCursor : prev.cursor,
    processedCount: id ? prev.processedCount + 1 : prev.processedCount,
    totalSeenCount: typeof totalSeen === 'number' ? totalSeen : prev.totalSeenCount,
    lastId: id || prev.lastId,
    recentIds,
  };
  return {
    ...state,
    perEcosystem: { ...state.perEcosystem, [ecosystem]: next },
  };
}

/**
 * Mark the run as entering the ingestion phase.
 */
export function markPhase(state, phase) {
  return { ...state, phase };
}

/**
 * Lookup helper. Returns the recent-ids ring for an ecosystem, or
 * an empty array when the ecosystem has not been seen this run.
 */
export function recentIdsFor(state, ecosystem) {
  const slot = state.perEcosystem[ecosystem];
  if (!slot) return [];
  return Array.isArray(slot.recentIds) ? slot.recentIds : [];
}

/**
 * Membership test against the recent-ids ring. Used to dedupe
 * equal-timestamp OSV updates within the same run.
 */
export function isRecentlyProcessed(state, ecosystem, id) {
  if (typeof id !== 'string') return false;
  return recentIdsFor(state, ecosystem).includes(id);
}
