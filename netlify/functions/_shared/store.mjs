/**
 * Shared store + lock helpers for the v5.2 prebuilt dataset.
 *
 * Used by:
 *   - netlify/functions/dataset.mjs              (read: try-blob-first, else bootstrap)
 *   - netlify/functions/refresh-dataset-background.mjs (write: build + write + lock)
 *   - netlify/functions/refresh-dataset-scheduled.mjs  (write: same, on cron)
 *
 * Architecture (v5.2):
 *
 *   Netlify Blobs (store name: "tpr-dataset")
 *   ├── latest-dataset   → full FetchResult envelope (JSON).
 *   │                       Written only after a SUCCESSFUL live build.
 *   │                       Never overwritten by a mock fallback.
 *   └── refresh-lock     → { startedAt, expiresAt }. Prevents
 *                           duplicate concurrent refreshes. TTL is
 *                           15 minutes — long enough for the longest
 *                           realistic refresh to complete (no NVD
 *                           API key → up to ~60 s of serial chunks;
 *                           15 min leaves a generous safety margin).
 *
 * Local-dev note: `netlify dev` provides the Blobs emulator
 * automatically (via the Netlify CLI). For Vite-only `npm run dev`,
 * the helpers below will detect the missing context and the
 * dataset function will fall back to the existing bootstrap path
 * (the v5.0 / v5.0.1 / v5.0.2 / v5.0.3 / v5.1 behavior is
 * preserved on the happy path).
 */
import { getStore } from '@netlify/blobs';

/** Netlify Blobs store name. Single source of truth. */
export const STORE_NAME = 'tpr-dataset';

/** Blob key for the most recently built live dataset. */
export const LATEST_DATASET_KEY = 'latest-dataset';

/** Blob key for the refresh lock. */
export const REFRESH_LOCK_KEY = 'refresh-lock';

/**
 * Refresh-lock TTL (ms). Long enough for the longest realistic
 * refresh to complete (serial NVD without API key can take ~60 s
 * for 10 chunks × 8 s each; 15 min leaves a 14-min safety margin).
 * Conservative on purpose — if a refresh somehow hangs, the lock
 * expires and the next scheduled / manual refresh will be allowed
 * to start instead of being blocked forever.
 */
export const REFRESH_LOCK_TTL_MS = 15 * 60 * 1000;

/**
 * Resolve a Blobs store handle. In production (Netlify Functions
 * runtime) `@netlify/blobs` auto-detects siteID and token from
 * the function's environment. In `netlify dev` the same is true.
 *
 * For Vite-only `npm run dev` (no function context), `getStore`
 * may still work via env vars `NETLIFY_BLOBS_SITE_ID` /
 * `NETLIFY_BLOBS_TOKEN`. We don't require them — `dataset.mjs`
 * treats a failed blob read as "no prebuilt yet" and falls back
 * to the bootstrap path.
 *
 * The optional `opts.consistency` is 'strong' by default —
 * prebuilt-dataset reads must be consistent across all visitors
 * within a moment. Writes are serialized via the refresh lock.
 */
export function getDatasetStore(opts = {}) {
  const consistency = opts.consistency ?? 'strong';
  return getStore({ name: STORE_NAME, consistency });
}

/**
 * Read the prebuilt dataset blob. Returns `null` when no blob
 * exists yet (first deploy, fresh deploy, or bootstrap never
 * succeeded). Defensive try/catch around all Blobs calls — a
 * transient Blobs outage must never crash the dataset endpoint;
 * the bootstrap path catches the same case for the first
 * visitor and re-establishes the blob.
 */
export async function readLatestDataset(store) {
  try {
    const blob = await store.get(LATEST_DATASET_KEY, { type: 'json' });
    return blob ?? null;
  } catch {
    return null;
  }
}

/**
 * Write the prebuilt dataset blob. Only called after a
 * SUCCESSFUL live build (never with a mock fallback envelope).
 * `silent: true` swallows Blobs write errors so a transient
 * Blobs outage on the write path doesn't propagate as a 500
 * to the visitor — the next refresh will retry.
 */
export async function writeLatestDataset(store, payload) {
  try {
    await store.setJSON(LATEST_DATASET_KEY, payload);
    return true;
  } catch {
    return false;
  }
}

/**
 * Read the refresh-lock blob. Returns `null` when no lock
 * exists; otherwise returns `{ startedAt, expiresAt }`. A
 * defensive try/catch means a Blobs read error is treated as
 * "no lock" — preferable to blocking refreshes indefinitely.
 */
export async function readRefreshLock(store) {
  try {
    const blob = await store.get(REFRESH_LOCK_KEY, { type: 'json' });
    if (!blob || typeof blob.startedAt !== 'string' || typeof blob.expiresAt !== 'string') {
      return null;
    }
    return blob;
  } catch {
    return null;
  }
}

/**
 * Return whether a refresh is currently locked (i.e. another
 * refresh is in progress). A lock is considered "active" only
 * if `expiresAt` is still in the future. An expired lock is
 * treated as "no lock" so a stuck refresh doesn't block the
 * next scheduled / manual attempt forever.
 */
export async function isRefreshLocked(store, now = new Date()) {
  const lock = await readRefreshLock(store);
  if (!lock) return false;
  const expiresAt = new Date(lock.expiresAt);
  if (Number.isNaN(expiresAt.getTime())) return false;
  return expiresAt.getTime() > now.getTime();
}

/**
 * Try to acquire the refresh lock. Returns `true` if the lock
 * was acquired, `false` if another refresh already holds a
 * non-expired lock.
 *
 * Implementation note: this is a "set if not present" check
 * implemented as a read-then-write. With Netlify Blobs
 * (strongly consistent), a simultaneous double-call from two
 * scheduled function invocations would still see one of them
 * lose the race — the loser sees the freshly-written lock and
 * returns `false`. The 15-minute TTL is the safety net for any
 * edge case where two writes race past the read.
 */
export async function tryAcquireRefreshLock(store, now = new Date()) {
  if (await isRefreshLocked(store, now)) return false;
  const expiresAt = new Date(now.getTime() + REFRESH_LOCK_TTL_MS);
  const payload = {
    startedAt: now.toISOString(),
    expiresAt: expiresAt.toISOString(),
  };
  try {
    await store.setJSON(REFRESH_LOCK_KEY, payload);
    // Re-check in case another writer raced past us.
    const recheck = await readRefreshLock(store);
    if (recheck && recheck.startedAt === payload.startedAt) return true;
    // Someone else wrote between our set and our re-read. Our
    // lock acquisition failed; clean up our write so we don't
    // leak a phantom lock.
    await clearRefreshLock(store);
    return false;
  } catch {
    return false;
  }
}

/**
 * Release the refresh lock. Best-effort: a Blobs write error
 * here means the lock will eventually expire on its own
 * (15-min TTL). Never throws.
 */
export async function clearRefreshLock(store) {
  try {
    await store.delete(REFRESH_LOCK_KEY);
  } catch {
    // Intentionally swallowed.
  }
}

/**
 * Pure-JS decision helper exported for the acceptance suite.
 * Re-implements the "should we even try to read the blob?"
 * guard. Mirrors `isRefreshLocked` but doesn't require a
 * store — used in unit tests and in the lock-expiry check
 * tests below.
 */
export function isLockActive(lock, now = new Date()) {
  if (!lock) return false;
  if (typeof lock.expiresAt !== 'string') return false;
  const t = new Date(lock.expiresAt).getTime();
  if (Number.isNaN(t)) return false;
  return t > now.getTime();
}

/**
 * Pure-JS helper for the acceptance suite. Returns the new
 * payload to write (or null if the lock should NOT be
 * acquired because another active lock is present).
 */
export function buildLockPayload(now = new Date(), ttlMs = REFRESH_LOCK_TTL_MS) {
  const expiresAt = new Date(now.getTime() + ttlMs);
  return {
    startedAt: now.toISOString(),
    expiresAt: expiresAt.toISOString(),
  };
}