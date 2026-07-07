/**
 * localStorage-backed cache for the vulnerability dataset.
 *
 * Purpose: a portfolio visitor who comes back to the page within
 * an hour sees their previously-fetched data instantly, with a
 * background re-fetch filling in the freshest values. This
 * avoids the 30–60 s NVD first-load on every visit.
 *
 * Honesty contract (per the portfolio rules):
 *   - Only *successful live* fetches are cached. The fallback
 *     (mock) dataset is never cached — mock is already instant.
 *   - The cached FetchResult carries its own `nvdStatus`,
 *     `epssStatus`, `fallbackReason`, and source label, so the
 *     existing failure banners keep showing correctly on cached
 *     data. The cache never hides provider failures.
 *   - Cache age is shown prominently (header pill + freshness
 *     banner). The user can always force a re-fetch with the
 *     manual "Refresh live data" button.
 *   - All localStorage access is wrapped in try/catch. Private
 *     mode, quota exceeded, disabled storage, SSR — none of
 *     these crash the app. The cache is an optimization, not
 *     a requirement.
 *
 * Storage shape:
 *   key:  "tpr:dataset:v1"          (versioned so we can
 *                                    invalidate the schema later)
 *   val:  { fetchResult: FetchResult, cachedAt: epochMs }
 *
 * `fetchResult.data` is the full Vulnerability[] payload —
 * the in-memory cost is small (~1000 records × ~500 bytes
 * JSON each ≈ 500 KB, well under the 5 MB localStorage quota).
 */
import type { FetchResult } from './vulnerabilityService';
import type { Vulnerability } from '../types/vulnerability';

const CACHE_KEY = 'tpr:dataset:v1';

/** 1 hour. Short enough to keep data fresh, long enough to skip
 *  the slow NVD fetch on a returning visitor. */
export const CACHE_TTL_MS = 60 * 60 * 1000;

export interface CachedDataset {
  fetchResult: FetchResult<Vulnerability[]>;
  /** Epoch ms when this was written to localStorage. */
  cachedAt: number;
}

/** Read the cached dataset, or `null` if missing / malformed / disabled. */
export function readCache(): CachedDataset | null {
  if (typeof localStorage === 'undefined') return null;
  try {
    const raw = localStorage.getItem(CACHE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Partial<CachedDataset>;
    if (
      typeof parsed.cachedAt !== 'number' ||
      !parsed.fetchResult ||
      !Array.isArray(parsed.fetchResult.data)
    ) {
      return null;
    }
    return parsed as CachedDataset;
  } catch {
    // localStorage may throw on disabled storage, quota errors,
    // JSON parse failures, etc. Treat as a cache miss.
    return null;
  }
}

/** Persist a fresh fetch result. Silently no-ops on storage errors. */
export function writeCache(fetchResult: FetchResult<Vulnerability[]>): void {
  if (typeof localStorage === 'undefined') return;
  try {
    const dataset: CachedDataset = {
      fetchResult,
      cachedAt: Date.now(),
    };
    localStorage.setItem(CACHE_KEY, JSON.stringify(dataset));
  } catch {
    // localStorage quota exceeded, private mode, etc. The cache
    // is an optimization — failing to write is fine.
  }
}

/** Remove the cached dataset. Silently no-ops on storage errors. */
export function clearCache(): void {
  if (typeof localStorage === 'undefined') return;
  try {
    localStorage.removeItem(CACHE_KEY);
  } catch {
    // ignore
  }
}

/** Is this cache entry still within its TTL? */
export function isCacheFresh(cachedAt: number): boolean {
  return getCacheAgeMs(cachedAt) < CACHE_TTL_MS;
}

/** Milliseconds since the cache entry was written. Always >= 0. */
export function getCacheAgeMs(cachedAt: number): number {
  return Math.max(0, Date.now() - cachedAt);
}

/**
 * Compact human label for an age in ms. Used by the header
 * freshness pill. Examples: "just now" (< 60 s), "5m ago",
 * "2h ago", "3d ago".
 */
export function formatAgeShort(ms: number): string {
  if (ms < 60_000) return 'just now';
  const minutes = Math.floor(ms / 60_000);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}
