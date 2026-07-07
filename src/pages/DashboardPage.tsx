import { useCallback, useEffect, useMemo, useState } from 'react';
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

  return (
    <div className="min-h-screen text-radar-text">
      <Header meta={state.kind === 'ready' ? state.meta : null} />

      <main className="mx-auto max-w-[1400px] space-y-5 px-4 py-5 lg:px-8 lg:py-7">
        {state.kind === 'loading' && (
          <LoadingState message="Loading threat intelligence…" />
        )}

        {state.kind === 'error' && (
          <ErrorState message={state.message} onRetry={handleRetry} />
        )}

        {state.kind === 'ready' && charts && (
          <>
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
        ThreatPulse Radar · defensive vulnerability intelligence · v1 uses curated mock
        data. Real NVD / CISA KEV / FIRST EPSS integrations coming in v2.
      </p>
    </footer>
  );
}
