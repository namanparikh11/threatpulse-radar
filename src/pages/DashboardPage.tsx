import { useCallback, useEffect, useMemo, useState } from 'react';
import { CircleAlert, HardDrive, RefreshCw } from 'lucide-react';
import Header from '../components/Header';
import StatsCards from '../components/StatsCards';
import FiltersPanel from '../components/FiltersPanel';
import VulnerabilityTable from '../components/VulnerabilityTable';
import DetailDrawer from '../components/DetailDrawer';
import EmptyState from '../components/EmptyState';
import LoadingState from '../components/LoadingState';
import ErrorState from '../components/ErrorState';
import SeverityChart, { EpssChart } from '../components/charts/SeverityChart';
import TrendChart from '../components/charts/TrendChart';
import KevChart from '../components/charts/KevChart';
import { useVulnerabilityFilter } from '../hooks/useVulnerabilityFilter';
import { fetchVulnerabilities, type FetchResult } from '../services/vulnerabilityService';
import type {
  SortState,
  Vulnerability,
  VulnerabilityFilters,
} from '../types/vulnerability';
import { DEFAULT_FILTERS, DEFAULT_SORT } from '../types/vulnerability';
import {
  computeStats,
  countByDay,
  countByEpssBucket,
  countBySeverity,
} from '../utils/analytics';
import { formatAbsolute, formatRelative } from '../utils/format';

type LoadState =
  | { kind: 'loading' }
  | { kind: 'ready'; meta: FetchResult<Vulnerability[]> }
  | { kind: 'error'; message: string };

export default function DashboardPage() {
  const [state, setState] = useState<LoadState>({ kind: 'loading' });
  const [filters, setFilters] = useState<VulnerabilityFilters>(DEFAULT_FILTERS);
  const [sort, setSort] = useState<SortState>(DEFAULT_SORT);
  const [selected, setSelected] = useState<Vulnerability | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetchVulnerabilities()
      .then((meta) => {
        if (cancelled) return;
        setState({ kind: 'ready', meta });
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        setState({
          kind: 'error',
          message:
            err instanceof Error
              ? err.message
              : 'Failed to load vulnerability data.',
        });
      });
    return () => {
      cancelled = true;
    };
  }, []);

  /* ----------------------------- derived data ----------------------------- */
  // All charts are computed off the *raw* dataset so they don't change as the
  // user fiddles with the search box.
  const all = state.kind === 'ready' ? state.meta.data : [];

  const charts = useMemo(() => {
    if (all.length === 0) return null;
    return {
      stats: computeStats(all),
      severityCounts: countBySeverity(all),
      epssBuckets: countByEpssBucket(all),
      trend: countByDay(all, 14),
      kevCount: all.filter((v) => v.kev).length,
      nonKevCount: all.filter((v) => !v.kev).length,
    };
  }, [all]);

  // Filter + sort pipeline (delegates to the custom hook).
  const { sorted, isAnyFilterActive, isSearchActive, isSearching } =
    useVulnerabilityFilter(all, filters, sort);

  const handleReset = useCallback(() => {
    setFilters(DEFAULT_FILTERS);
    setSort(DEFAULT_SORT);
  }, []);

  async function handleRetry() {
    setState({ kind: 'loading' });
    try {
      const meta = await fetchVulnerabilities();
      setState({ kind: 'ready', meta });
    } catch (err) {
      setState({
        kind: 'error',
        message: err instanceof Error ? err.message : 'Failed to load vulnerability data.',
      });
    }
  }

  /**
   * v4: Force a fresh upstream fetch, bypassing the localStorage
   * cache. Wired to the "Refresh live data" button in the cached-
   * data banner. Goes through the same error path as handleRetry
   * so a forced refresh that fails is treated like any other
   * fetch failure (falls back to mock, never silently hides
   * failures).
   */
  async function handleRefresh() {
    setState({ kind: 'loading' });
    try {
      const meta = await fetchVulnerabilities({ forceRefresh: true });
      setState({ kind: 'ready', meta });
    } catch (err) {
      setState({
        kind: 'error',
        message:
          err instanceof Error
            ? err.message
            : 'Failed to refresh vulnerability data.',
      });
    }
  }

  return (
    <div className="min-h-screen text-radar-text">
      <Header meta={state.kind === 'ready' ? state.meta : null} />

      <main className="mx-auto max-w-[1400px] space-y-5 px-4 py-5 lg:px-8 lg:py-7">
        {state.kind === 'loading' && (
          <LoadingState message="Loading CISA KEV · NVD CVSS · FIRST EPSS — may take up to a minute on first load…" />
        )}

        {state.kind === 'error' && (
          <ErrorState message={state.message} onRetry={handleRetry} />
        )}

        {state.kind === 'ready' && charts && (
          <>
            {/* v4: cache banner sits above all provider banners. It
                is the most fundamental "where did this data come
                from on this load" question; the provider banners
                are layered on top of that. */}
            {(state.meta.cacheStatus === 'fresh' ||
              state.meta.cacheStatus === 'stale') && (
              <CachedDataBanner
                cacheStatus={state.meta.cacheStatus}
                fetchedAt={state.meta.fetchedAt}
                onRefresh={handleRefresh}
              />
            )}

            {state.meta.mode === 'fallback' && (
              <FallbackBanner
                reason={state.meta.fallbackReason}
                onRetry={handleRetry}
              />
            )}

            {state.meta.mode === 'live' &&
              state.meta.nvdStatus === 'unavailable' && (
                <NvdUnavailableBanner reason={state.meta.nvdReason} />
              )}

            {state.meta.mode === 'live' &&
              state.meta.epssStatus === 'unavailable' && (
                <EpssUnavailableBanner reason={state.meta.epssReason} />
              )}

            <StatsCards stats={charts.stats} />

            <section className="grid grid-cols-1 gap-3 lg:grid-cols-3">
              <SeverityChart counts={charts.severityCounts} />
              <EpssChart data={charts.epssBuckets} />
              <KevChart kev={charts.kevCount} nonKev={charts.nonKevCount} />
            </section>

            <TrendChart data={charts.trend} />

            <FiltersPanel
              filters={filters}
              sort={sort}
              onChange={setFilters}
              onSortChange={setSort}
              totalCount={all.length}
              matchCount={sorted.length}
              isSearching={isSearching}
              isSearchActive={isSearchActive}
              onReset={handleReset}
            />

            {sorted.length === 0 ? (
              <EmptyState
                title="No vulnerabilities match your filters."
                description="Try clearing the search, lowering the EPSS threshold, or removing the KEV / severity restriction."
                action={
                  <button
                    type="button"
                    onClick={handleReset}
                    className="focus-ring rounded-md border border-radar-border bg-radar-panel2 px-3 py-1.5 text-xs text-radar-text hover:border-radar-accent/40"
                  >
                    Reset all filters
                  </button>
                }
              />
            ) : (
              <VulnerabilityTable
                vulns={sorted}
                sort={sort}
                onSortChange={setSort}
                onSelect={setSelected}
              />
            )}

            {isAnyFilterActive && (
              <p className="text-center text-[11px] text-radar-dim">
                Filters are active. Results reflect your current search, severity,
                KEV and EPSS selection.
              </p>
            )}

            <Footer />
          </>
        )}
      </main>

      <DetailDrawer vuln={selected} onClose={() => setSelected(null)} />
    </div>
  );
}

function Footer() {
  return (
    <footer className="pt-2 text-center text-[11px] text-radar-dim">
      <p>
        ThreatPulse Radar · defensive vulnerability intelligence · CISA KEV +
        NVD + FIRST EPSS live data with mock-data fallback.
      </p>
    </footer>
  );
}

/**
 * Small banner shown above the stats when the live CISA KEV feed
 * was unreachable and the dashboard is showing the mock dataset.
 * Non-dismissible: refreshes on next page load or via the button.
 */
function FallbackBanner({
  reason,
  onRetry,
}: {
  reason: string | undefined;
  onRetry: () => void;
}) {
  return (
    <div
      role="status"
      className="panel flex flex-col gap-2 border-radar-warn/40 bg-radar-warn/5 px-4 py-3 text-sm sm:flex-row sm:items-center sm:justify-between"
    >
      <div className="flex items-start gap-2">
        <CircleAlert className="mt-0.5 h-4 w-4 shrink-0 text-radar-warn" />
        <div>
          <p className="font-medium text-radar-text">
            Live CISA KEV feed unavailable — showing mock data.
          </p>
          <p className="mt-0.5 text-xs text-radar-muted">
            Reason: {reason ?? 'Unknown error.'} The dashboard still works
            against the curated mock dataset; filters and search behave
            identically.
          </p>
        </div>
      </div>
      <button
        type="button"
        onClick={onRetry}
        className="focus-ring inline-flex items-center gap-1.5 self-start rounded-md border border-radar-warn/40 bg-radar-panel2 px-2.5 py-1.5 text-xs text-radar-text transition hover:border-radar-warn"
      >
        <RefreshCw className="h-3 w-3" />
        Retry live fetch
      </button>
    </div>
  );
}

/**
 * Softer banner shown when the CISA KEV feed is live but the FIRST
 * EPSS enrichment fetch failed. The CISA data is still being shown
 * (and is current); only the EPSS probability column is unavailable.
 * No retry button — the next page load will retry automatically.
 */
function EpssUnavailableBanner({
  reason,
}: {
  reason: string | undefined;
}) {
  return (
    <div
      role="status"
      className="panel flex items-start gap-2 border-radar-warn/30 bg-radar-warn/5 px-4 py-2.5 text-xs"
    >
      <CircleAlert className="mt-0.5 h-3.5 w-3.5 shrink-0 text-radar-warn" />
      <div>
        <p className="font-medium text-radar-text">
          EPSS enrichment unavailable — exploitation probabilities
          default to 0.
        </p>
        <p className="mt-0.5 text-radar-muted">
          CISA KEV data is current. FIRST EPSS could not be reached:
          {reason ?? 'unknown error.'} The EPSS filter still works
          (it will simply show no rows above the 0% threshold for
          affected CVEs).
        </p>
      </div>
    </div>
  );
}

/**
 * Banner shown when the CISA KEV feed is live but the NVD CVSS
 * enrichment fetch failed. The CISA data is still being shown (and
 * is current); only the CVSS column is unavailable. No retry
 * button — the next page load will retry automatically.
 */
function NvdUnavailableBanner({
  reason,
}: {
  reason: string | undefined;
}) {
  return (
    <div
      role="status"
      className="panel flex items-start gap-2 border-radar-warn/30 bg-radar-warn/5 px-4 py-2.5 text-xs"
    >
      <CircleAlert className="mt-0.5 h-3.5 w-3.5 shrink-0 text-radar-warn" />
      <div>
        <p className="font-medium text-radar-text">
          NVD CVSS enrichment unavailable — scores default to 0.
        </p>
        <p className="mt-0.5 text-radar-muted">
          CISA KEV data is current. NVD could not be reached:
          {reason ?? 'unknown error.'} Severity and CVSS sorting
          will fall back to the CISA-derived values (KEV records
          default to "High"; ransomware-known records to "Critical").
        </p>
      </div>
    </div>
  );
}

/**
 * v4: Banner shown when the dashboard is rendering data served
 * from the localStorage cache instead of a fresh live fetch.
 *
 * Two visual treatments:
 *   - 'fresh': in-TTL cache hit (data is < 1 h old). Cyan info
 *     tone. The user knows the data is real and recent.
 *   - 'stale': expired cache hit, used because the live fetch
 *     just failed. Amber warn tone. The data is real and the
 *     user can still use it, but it's older than the TTL.
 *
 * The banner always carries the original upstream `fetchedAt`
 * so the user can see the age of the data they're looking at,
 * and exposes a manual "Refresh live data" button that forces
 * a bypass-cache re-fetch.
 *
 * Critically, the cached FetchResult's provider-status fields
 * (nvdStatus / epssStatus / fallbackReason) are preserved, so
 * if the original live fetch had NVD or EPSS unavailable, those
 * banners are still rendered alongside this one. The cache
 * never hides provider failures.
 */
function CachedDataBanner({
  cacheStatus,
  fetchedAt,
  onRefresh,
}: {
  cacheStatus: 'fresh' | 'stale';
  fetchedAt: string;
  onRefresh: () => void;
}) {
  const isStale = cacheStatus === 'stale';
  const relative = formatRelative(fetchedAt);
  const absolute = formatAbsolute(fetchedAt);
  return (
    <div
      role="status"
      className={[
        'panel flex flex-col gap-2 px-4 py-3 text-sm sm:flex-row sm:items-center sm:justify-between',
        isStale
          ? 'border-radar-warn/40 bg-radar-warn/5'
          : 'border-radar-accent/30 bg-radar-accent/5',
      ].join(' ')}
    >
      <div className="flex items-start gap-2">
        <HardDrive
          className={[
            'mt-0.5 h-4 w-4 shrink-0',
            isStale ? 'text-radar-warn' : 'text-radar-accent',
          ].join(' ')}
        />
        <div>
          <p className="font-medium text-radar-text">
            {isStale
              ? 'Cached data (stale) — live fetch failed'
              : 'Cached data — refreshed ' + relative}
          </p>
          <p className="mt-0.5 text-xs text-radar-muted">
            {isStale
              ? 'The 1-hour cache TTL has expired and the live fetch just failed. Showing last-known real data from '
              : 'Showing data from local cache (within the 1-hour TTL). Data was last fetched at '}
            <span className="text-radar-text">{absolute}</span>.
            {isStale
              ? ' Provider-status banners above reflect the original fetch.'
              : ' Click refresh to fetch the latest upstream data.'}
          </p>
        </div>
      </div>
      <button
        type="button"
        onClick={onRefresh}
        className={[
          'focus-ring inline-flex items-center gap-1.5 self-start rounded-md border px-2.5 py-1.5 text-xs text-radar-text transition',
          isStale
            ? 'border-radar-warn/40 bg-radar-panel2 hover:border-radar-warn'
            : 'border-radar-accent/40 bg-radar-panel2 hover:border-radar-accent',
        ].join(' ')}
      >
        <RefreshCw className="h-3 w-3" />
        Refresh live data
      </button>
    </div>
  );
}
