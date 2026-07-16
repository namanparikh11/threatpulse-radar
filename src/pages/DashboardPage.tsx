import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { CircleAlert, HardDrive, Loader2, RefreshCw, Sparkles, X } from 'lucide-react';
import Header from '../components/Header';
import StatsCards from '../components/StatsCards';
import FiltersPanel from '../components/FiltersPanel';
import DefenderViewsPanel from '../components/DefenderViewsPanel';
import VulnerabilityTable from '../components/VulnerabilityTable';
import DetailDrawer from '../components/DetailDrawer';
import EmptyState from '../components/EmptyState';
import LoadingState from '../components/LoadingState';
import ErrorState from '../components/ErrorState';
import SeverityChart, { EpssChart } from '../components/charts/SeverityChart';
import TrendChart from '../components/charts/TrendChart';
import KevChart from '../components/charts/KevChart';
import SourceHealthPanel from '../components/SourceHealthPanel';
import ChangeIntelligencePanel from '../components/ChangeIntelligencePanel';
import ConflictBanner from '../components/workspace/ConflictBanner';
import WorkspacePanel from '../components/workspace/WorkspacePanel';
import BulkActionBar from '../components/workspace/BulkActionBar';
import WorkspaceDialogs, { type DialogKind } from '../components/workspace/WorkspaceDialogs';
import ReportBuilder from '../components/reports/ReportBuilder';
import { exportReport } from '../reports/exporters/index.mjs';
import { downloadFile, openHtmlInNewTab } from '../reports/download.mjs';
import { useVulnerabilityFilter } from '../hooks/useVulnerabilityFilter';
import { useWorkspace } from '../state/WorkspaceContext';
import { buildCounts } from '../workspace/queueFilters.mjs';
import { computeChangeSignatureSync as computeChangeSignature } from '../workspace/changeSignature.mjs';
import {
  fetchVulnerabilities,
  type FetchResult,
  type RefreshResult,
} from '../services/vulnerabilityService';
import type {
  SortState,
  Vulnerability,
  VulnerabilityFilters,
} from '../types/vulnerability';
import type { SourceStatus } from '../types/sourceHealth';
import { DEFAULT_FILTERS, DEFAULT_SORT } from '../types/vulnerability';
import {
  computeStats,
  countByDay,
  countByEpssBucket,
  countBySeverity,
} from '../utils/analytics';
import { formatAbsolute, formatRelative } from '../utils/format';
import { formatAgeShort } from '../services/datasetCache';

type LoadState =
  | { kind: 'loading' }
  | { kind: 'ready'; meta: FetchResult<Vulnerability[]> }
  | { kind: 'error'; message: string };

/**
 * v5.1: Background poll cadence for the soft-refresh path.
 * Every 5 minutes the dashboard silently checks the proxy
 * for a newer upstream dataset. If newer data is found AND
 * the user hasn't dismissed that exact update already, a
 * small banner appears with an explicit "Apply update"
 * button. The poll only fires while the document is visible
 * (browsers throttle hidden-tab timers anyway, but we also
 * skip explicitly so we don't hit the proxy while the user
 * is away).
 *
 * 5 min chosen to balance latency (worst-case ~20 min from
 * upstream change → banner, given the CDN's s-maxage=900)
 * against proxy load (288 polls/day/visitor vs. ~2880/day
 * at 1-min cadence for no UX benefit).
 */
const BACKGROUND_POLL_INTERVAL_MS = 5 * 60 * 1000;

export default function DashboardPage() {
  const [state, setState] = useState<LoadState>({ kind: 'loading' });
  const [filters, setFilters] = useState<VulnerabilityFilters>(DEFAULT_FILTERS);
  const [sort, setSort] = useState<SortState>(DEFAULT_SORT);
  const [selected, setSelected] = useState<Vulnerability | null>(null);
  /**
   * v5.1: A newer FetchResult detected by the background
   * poll but not yet applied by the user. When non-null, the
   * UpdateAvailableBanner is rendered. The polling logic
   * only sets this when:
   *   - the poll succeeded (`mode === 'live'`), AND
   *   - the result's `fetchedAt` is strictly newer than the
   *     currently displayed `state.meta.fetchedAt`, AND
   *   - the user hasn't already dismissed that exact
   *     `fetchedAt` (see `dismissedFetchedAt`).
   * Null otherwise.
   */
  const [pendingUpdate, setPendingUpdate] = useState<FetchResult<Vulnerability[]> | null>(null);
  /**
   * v5.1: The `fetchedAt` of the most recently dismissed
   * pending update. Used so a background poll that returns
   * the same `fetchedAt` (e.g. a stale-while-revalidate
   * re-serve with no actual upstream change) does NOT
   * re-show the banner. Cleared on Apply so a future poll
   * for the same `fetchedAt` won't be suppressed either.
   */
  const [dismissedFetchedAt, setDismissedFetchedAt] = useState<string | null>(null);
  /**
   * v5.2: Refresh-in-progress state. When non-null, the small
   * "Refresh running in background" banner is rendered. The
   * state is set by the polling effect when the server reports
   * `refreshInProgress: true` (a scheduled or manual refresh
   * is currently rebuilding the shared dataset) and cleared
   * when the next poll returns `refreshInProgress: false`.
   */
  const [refreshStatus, setRefreshStatus] = useState<RefreshResult | null>(null);
  /**
   * v6.1: which source card to highlight in the Source
   * Health panel (e.g. when the user clicks the "Provider
   * status changed" chip in the What Changed panel).
   */
  const [highlightSourceId, setHighlightSourceId] = useState<string | null>(null);
  /**
   * v6.4: local workspace UI state. The CVE ids the
   * operator has selected in the workspace queue drive
   * the BulkActionBar. The active dialog is one of
   * 'export' | 'import' | 'clear-archived' |
   * 'clear-workspace' | null.
   */
  const [selectedCveIds, setSelectedCveIds] = useState<string[]>([]);
  const [activeDialog, setActiveDialog] = useState<DialogKind>(null);
  // V6.5: report-builder dialog state. The dialog is
  // pre-seeded by entry points (workspace panel, detail
  // drawer, "what changed" panel, local queue).
  const [reportBuilderSeed, setReportBuilderSeed] = useState<{ cveIds: string[]; reportType?: string; title?: string } | null>(null);
  const [activeReportDialog, setActiveReportDialog] = useState(false);
  const workspace = useWorkspace();
  /**
   * v6.4: keep the workspace's `changedSinceReview` count
   * in sync with the actual public-intelligence view. The
   * workspace's internal count is approximate; we replace
   * it with the exact value derived from
   * `buildCounts(...)` so the count tile and the
   * `Changed since review` queue filter agree.
   */
  useEffect(() => {
    if (state.kind !== 'ready') {
      workspace.clearChangedSinceReview();
      return;
    }
    const counts = buildCounts({
      vulns: state.meta.data,
      entriesByCve: workspace.state.entriesByCve,
      publicIntelligenceVersion: state.meta.publicIntelligenceVersion ?? null,
      publicIntelligenceStatus: state.meta.publicIntelligenceStatus ?? 'unavailable',
      publicProjectionSchemaVersion: state.meta.publicProjectionSchemaVersion ?? null,
      computeSignature: computeChangeSignature,
    });
    workspace.incrementChangedSinceReview(counts.changedSinceReview);
  }, [
    state.kind === 'ready' ? state.meta : null,
    workspace.state.entriesByCve,
    workspace.incrementChangedSinceReview,
    workspace.clearChangedSinceReview,
  ]);
  /**
   * v5.1: Refs that mirror the latest `state.meta.fetchedAt`
   * and `dismissedFetchedAt` so the polling closure (started
   * once on first 'ready') can read the current values
   * without restarting the interval on every state change.
   */
  const stateRef = useRef(state);
  const dismissedRef = useRef(dismissedFetchedAt);
  useEffect(() => {
    stateRef.current = state;
  }, [state]);
  useEffect(() => {
    dismissedRef.current = dismissedFetchedAt;
  }, [dismissedFetchedAt]);

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
  // v5.7: `activePreset` is surfaced so the "Filters are
  // active" footer can name the active preset. The hook
  // also returns `filtered` (pre-sort) for callers that
  // need the un-ordered matching set; the table and the
  // export use the sorted view.
  const {
    sorted,
    isAnyFilterActive,
    isSearchActive,
    isSearching,
    activePreset,
  } = useVulnerabilityFilter(all, filters, sort);

  const handleReset = useCallback(() => {
    // DEFAULT_FILTERS already carries `presetId: null` and
    // the v5.7 enrichment filters at their "any" defaults,
    // so resetting the filter state via the constants also
    // clears the active defender-view preset.
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
   * v5.1: Background poll effect. Starts a setInterval when the
   * initial load reaches 'ready'. Each tick calls
   * `fetchVulnerabilities({ background: true })` — which bypasses
   * the localStorage cache read but leaves the CDN alone — and
   * compares the result's `fetchedAt` against the currently
   * displayed one. If newer (and the user hasn't already
   * dismissed that exact update), stores the result as
   * `pendingUpdate` so the UpdateAvailableBanner can render.
   *
   * v5.2: also clears `refreshStatus` when the polled result
   * says `refreshInProgress: false` — that signals the
   * server-side build has finished. The banner auto-clears.
   *
   * The closure reads the latest state / dismissedFetchedAt
   * via refs (stateRef / dismissedRef) so we don't restart the
   * interval on every render. The interval is torn down on
   * unmount and re-created if the page leaves 'ready' and
   * returns (e.g. a navigation causes a fresh initial load).
   */
  useEffect(() => {
    if (state.kind !== 'ready') return;
    let cancelled = false;
    let timer: ReturnType<typeof setInterval> | null = null;

    async function pollOnce() {
      // Don't bother the proxy while the tab is hidden. Browsers
      // already throttle hidden-tab timers, but we also skip
      // explicitly so the next visible-tab tick is the first
      // one to run after the user comes back.
      if (
        typeof document !== 'undefined' &&
        document.visibilityState !== 'visible'
      ) {
        return;
      }
      try {
        const result = await fetchVulnerabilities({ background: true });
        if (cancelled) return;
        // v5.2: server-side refresh complete → clear the local
        // "Refresh running in background" banner. Only applies
        // when we previously set it via handleManualRefresh.
        if (result.refreshInProgress === false) {
          setRefreshStatus((prev) => (prev && prev.refreshInProgress ? null : prev));
        }
        // Only a real live fetch is a "new dataset." A mock
        // fallback or stale-cache re-serve is the same data the
        // user is already looking at — not worth notifying.
        if (result.mode !== 'live') return;
        // Read the *current* (not stale-closure) state.
        const current = stateRef.current;
        if (current.kind !== 'ready') return;
        if (result.fetchedAt <= current.meta.fetchedAt) return;
        // The user already dismissed this exact update. Skip
        // so the same banner doesn't re-appear on every poll
        // tick (e.g. a stale-while-revalidate re-serve).
        if (result.fetchedAt === dismissedRef.current) return;
        setPendingUpdate(result);
      } catch {
        // Background poll failures are silent. The user is
        // already looking at a working dataset; a transient
        // proxy error shouldn't surface as a banner.
      }
    }

    timer = setInterval(pollOnce, BACKGROUND_POLL_INTERVAL_MS);
    return () => {
      cancelled = true;
      if (timer) clearInterval(timer);
    };
  }, [state.kind === 'ready']);

  /**
   * v5.1: User clicked "Apply update" on the
   * UpdateAvailableBanner. Replace the displayed FetchResult
   * with the pending one. Filters / search / sort are NOT
   * touched — they live in separate useState slots that
   * survive this state transition. The DetailDrawer is
   * updated to reflect the new dataset: if the selected CVE
   * still exists, swap the selected reference so any
   * updated CVSS / EPSS scores show through; if it no longer
   * exists in the new dataset, close the drawer (showing a
   * phantom record would be worse than closing).
   */
  const handleApplyUpdate = useCallback(() => {
    setPendingUpdate((current) => {
      if (!current) return null;
      setState({ kind: 'ready', meta: current });
      setDismissedFetchedAt(null);
      setRefreshStatus(null);
      setSelected((prev) => {
        if (!prev) return prev;
        const stillExists = current.data.find((v) => v.cveId === prev.cveId);
        if (!stillExists) return null;
        return stillExists;
      });
      return null;
    });
  }, []);

  /**
   * v5.1: User clicked the dismiss (×) button. Hide the
   * banner. Remember the dismissed `fetchedAt` so a
   * background poll returning the same fetchedAt (e.g. a
   * stale-while-revalidate re-serve) doesn't re-show the
   * banner. Cleared automatically on Apply.
   */
  const handleDismissUpdate = useCallback(() => {
    setPendingUpdate((current) => {
      if (current) {
        setDismissedFetchedAt(current.fetchedAt);
      }
      return null;
    });
  }, []);

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
            {/* v5.1: soft-refresh banner is the most actionable
                thing on screen ("there's a newer dataset waiting
                for you"), so it sits above all informational
                banners. Renders only when the background poll
                has detected a newer FetchResult that the user
                hasn't dismissed yet. */}
            {pendingUpdate && (
              <UpdateAvailableBanner
                pendingFetchedAt={pendingUpdate.fetchedAt}
                onApply={handleApplyUpdate}
                onDismiss={handleDismissUpdate}
              />
            )}

            {/* v5.2: refresh-in-progress banner. Surfaces
                immediately when the user clicks "Refresh live
                data" (the response from the background function
                is 202 "started" / "in-progress"). Auto-clears on
                the next poll that returns `refreshInProgress:
                false` — i.e. when the server-side build
                completes. Sits below the v5.1 banner so a
                detected update takes priority over a manual
                refresh in flight. */}
            {refreshStatus && refreshStatus.refreshInProgress && (
              <RefreshInProgressBanner
                status={refreshStatus}
                onDismiss={() => setRefreshStatus(null)}
              />
            )}

            {/* v4: cache banner sits above all provider banners. It
                is the most fundamental "where did this data come
                from on this load" question; the provider banners
                are layered on top of that. */}
            {(state.meta.cacheStatus === 'fresh' ||
              state.meta.cacheStatus === 'stale') && (
              <CachedDataBanner
                cacheStatus={state.meta.cacheStatus}
                fetchedAt={state.meta.fetchedAt}
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

            <ConflictBanner />

            <BulkActionBar
              selectedCveIds={selectedCveIds}
              onClearSelection={() => setSelectedCveIds([])}
            />

            <WorkspacePanel
              vulns={all}
              publicIntelligenceVersion={state.meta.publicIntelligenceVersion ?? null}
              publicIntelligenceStatus={state.meta.publicIntelligenceStatus ?? 'unavailable'}
              publicProjectionSchemaVersion={state.meta.publicProjectionSchemaVersion ?? null}
              selectedCveIds={selectedCveIds}
              onSelectedCveIdsChange={setSelectedCveIds}
              onOpenVuln={setSelected}
              onExport={() => setActiveDialog('export')}
              onImport={() => setActiveDialog('import')}
              onClearArchived={() => setActiveDialog('clear-archived')}
              onClearWorkspace={() => setActiveDialog('clear-workspace')}
              onOpenReportBuilder={(cveIds) => {
                setReportBuilderSeed({ cveIds, reportType: 'defender-daily-briefing', title: 'Defender Daily Briefing' });
                setActiveReportDialog(true);
              }}
            />

            <StatsCards stats={charts.stats} />

            <section className="grid grid-cols-1 gap-3 lg:grid-cols-3">
              <SeverityChart counts={charts.severityCounts} />
              <EpssChart data={charts.epssBuckets} />
              <KevChart kev={charts.kevCount} nonKev={charts.nonKevCount} />
            </section>

            <TrendChart data={charts.trend} />

            {state.meta.sources && state.meta.sources.length > 0 ? (
              <SourceHealthPanel
                sources={state.meta.sources as unknown as SourceStatus[]}
                highlightId={highlightSourceId}
              />
            ) : null}

            {state.meta.changeSummary ? (
              <ChangeIntelligencePanel
                changeSummary={state.meta.changeSummary as unknown as import('../types/change').ChangeSummary}
                comparableAxes={state.meta.comparableAxes || []}
                suppressedAxes={state.meta.suppressedAxes || []}
                publicIntelligenceVersion={state.meta.publicIntelligenceVersion ?? null}
                sources={state.meta.sources as unknown as SourceStatus[]}
                onOpen={(cveId) => {
                  const hit = all.find((v) => v.cveId === cveId);
                  if (hit) setSelected(hit);
                }}
                onHighlightSource={(sourceId) => setHighlightSourceId(sourceId)}
                onOpenReportBuilder={() => {
                  setReportBuilderSeed({ cveIds: [], reportType: 'change-briefing', title: 'Change Briefing' });
                  setActiveReportDialog(true);
                }}
              />
            ) : null}

            <DefenderViewsPanel
              rows={sorted}
              totalCount={all.length}
              filters={filters}
              onChange={setFilters}
            />

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
              allVulnerabilities={all}
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
                {activePreset
                  ? `Filters and the “${activePreset.label}” preset are active. Reset clears the preset too.`
                  : 'Filters are active. Results reflect your current search, severity, KEV, EPSS, GitHub Advisory, patch context, and SSVC exploitation selection.'}
              </p>
            )}

            <Footer />
          </>
        )}
      </main>

      <DetailDrawer
        vuln={selected}
        onClose={() => setSelected(null)}
        publicIntelligenceVersion={
          state.kind === 'ready' ? state.meta.publicIntelligenceVersion ?? null : null
        }
        publicIntelligenceStatus={
          state.kind === 'ready' ? state.meta.publicIntelligenceStatus ?? 'unavailable' : 'unavailable'
        }
        publicProjectionSchemaVersion={
          state.kind === 'ready' ? state.meta.publicProjectionSchemaVersion ?? null : null
        }
        onOpenReportBuilder={(cveIds, reportType, title) => {
          setReportBuilderSeed({ cveIds, reportType: reportType || 'selected-cve', title: title || `Selected CVE Report: ${cveIds.join(', ')}` });
          setActiveReportDialog(true);
        }}
      />

      <WorkspaceDialogs
        active={activeDialog}
        onClose={() => setActiveDialog(null)}
      />

      {activeReportDialog && reportBuilderSeed && (
        <ReportBuilder
          initialCveIds={reportBuilderSeed.cveIds}
          initialReportType={reportBuilderSeed.reportType}
          initialTitle={reportBuilderSeed.title}
          publicMeta={state.kind === 'ready' ? state.meta : null}
          publicVulns={all}
          onClose={() => { setActiveReportDialog(false); setReportBuilderSeed(null); }}
          onExport={(report, format) => {
            // V6.5: render the chosen format and trigger
            // a local download (or open the print HTML in
            // a new tab so the operator can use the
            // browser's "Save as PDF" command).
            try {
              const out = exportReport(report, format);
              if (format === 'print') {
                const win = openHtmlInNewTab(out.body, '_blank');
                if (!win) {
                  // Pop-up blocked; fall back to a download.
                  downloadFile(out.filename, out.body, out.mimeType);
                }
              } else {
                downloadFile(out.filename, out.body, out.mimeType);
              }
            } catch (err) {
              // Surface a minimal sanitized error in the
              // console without leaking private content.
              const msg = err instanceof Error ? err.message : 'export-failed';
              // eslint-disable-next-line no-console
              console.warn('[threatpulse] report export failed:', msg);
            }
          }}
        />
      )}
    </div>
  );
}

function Footer() {
  return (
    <footer className="pt-2 text-center text-[11px] text-radar-dim">
      <p>
        Built by Naman Parikh · Defensive cybersecurity portfolio project ·
        Data sources: CISA KEV, NVD, FIRST EPSS where available
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
 * so the user can see the age of the data they're looking at.
 * The cached FetchResult's provider-status fields
 * (nvdStatus / epssStatus / fallbackReason) are preserved, so
 * if the original live fetch had NVD or EPSS unavailable, those
 * banners are still rendered alongside this one. The cache
 * never hides provider failures.
 *
 * v5.4.2: The public manual-refresh control was removed
 * from the cached-data banner because refreshes are
 * asynchronous and automatically scheduled. The button
 * no longer exists in the public UI; the body copy tells
 * the user that data refreshes automatically in the
 * background and the latest successfully enriched dataset
 * remains available during provider delays.
 */
function CachedDataBanner({
  cacheStatus,
  fetchedAt,
}: {
  cacheStatus: 'fresh' | 'stale';
  fetchedAt: string;
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
            {' '}Data refreshes automatically in the background. The
            latest successfully enriched dataset remains available
            during provider delays.
          </p>
        </div>
      </div>
    </div>
  );
}

/**
 * v5.1: Banner shown when the background poll has detected a
 * newer upstream dataset that the user hasn't dismissed. Two
 * buttons:
 *   - "Apply update" — promotes the newer FetchResult to the
 *     displayed state. Filters / search / sort / drawer policy
 *     are handled by `handleApplyUpdate` upstream.
 *   - "×" — dismiss. Sets `dismissedFetchedAt` so the same
 *     exact update won't re-appear on every poll tick. Cleared
 *     automatically on Apply.
 *
 * Tone is info (cyan) — the situation is "good news, newer
 * data is available" rather than a warning or an error. The
 * banner is intentionally smaller and quieter than the cache
 * banner because it's a routine, expected event after the
 * dashboard has been open for a while.
 */
function UpdateAvailableBanner({
  pendingFetchedAt,
  onApply,
  onDismiss,
}: {
  pendingFetchedAt: string;
  onApply: () => void;
  onDismiss: () => void;
}) {
  const ageMs = Math.max(0, Date.now() - new Date(pendingFetchedAt).getTime());
  const ageLabel = formatAgeShort(ageMs);
  const absolute = formatAbsolute(pendingFetchedAt);
  return (
    <div
      role="status"
      aria-live="polite"
      className="panel flex flex-col gap-2 border-radar-accent/30 bg-radar-accent/5 px-4 py-3 text-sm sm:flex-row sm:items-center sm:justify-between"
    >
      <div className="flex items-start gap-2">
        <Sparkles className="mt-0.5 h-4 w-4 shrink-0 text-radar-accent" />
        <div>
          <p className="font-medium text-radar-text">
            New dataset available. Updated {ageLabel}.
          </p>
          <p className="mt-0.5 text-xs text-radar-muted">
            A newer upstream dataset was detected on{' '}
            <span className="text-radar-text">{absolute}</span>. Click
            Apply update to load it — your filters, search, sort,
            and open detail view will be preserved.
          </p>
        </div>
      </div>
      <div className="flex items-center gap-2 self-start">
        <button
          type="button"
          onClick={onApply}
          className="focus-ring inline-flex items-center gap-1.5 rounded-md border border-radar-accent/40 bg-radar-panel2 px-2.5 py-1.5 text-xs text-radar-text transition hover:border-radar-accent"
        >
          <Sparkles className="h-3 w-3" />
          Apply update
        </button>
        <button
          type="button"
          onClick={onDismiss}
          aria-label="Dismiss update notification"
          title="Dismiss — hide until the next newer dataset"
          className="focus-ring inline-flex h-7 w-7 items-center justify-center rounded-md border border-radar-border bg-radar-panel2 text-radar-muted transition hover:border-radar-accent/40 hover:text-radar-text"
        >
          <X className="h-3.5 w-3.5" />
        </button>
      </div>
    </div>
  );
}

/**
 * v5.2: Banner shown when the user has triggered a manual
 * refresh (or a scheduled refresh is already running). The
 * banner is intentionally smaller and quieter than the
 * UpdateAvailableBanner — it's a "the rebuild is in flight,
 * your data is unchanged" notice rather than an actionable
 * update. The user can dismiss it (it'll re-appear on the
 * next poll if the build is still running), or wait for the
 * v5.1 polling to detect the new blob and surface the
 * "New dataset available" banner.
 *
 * Status copy:
 *   - 'started'   → "Refresh started. A new dataset is being built…"
 *   - 'in-progress' → "A refresh is already running."
 *   - 'completed'  → would clear via the next poll; should not render.
 *   - 'failed'    → "Refresh failed: <reason>." Surfaces only briefly
 *                    before the next poll clears it.
 */
function RefreshInProgressBanner({
  status,
  onDismiss,
}: {
  status: RefreshResult;
  onDismiss: () => void;
}) {
  const message =
    status.status === 'in-progress'
      ? 'A refresh is already running on the server. Your current view is unchanged.'
      : status.status === 'failed'
        ? `Refresh failed: ${status.reason ?? 'unknown error'}.`
        : 'A new dataset is being built in the background. Your current view is unchanged; the new dataset will appear via the next “Apply update” banner.';
  return (
    <div
      role="status"
      aria-live="polite"
      className="panel flex flex-col gap-2 border-radar-accent/30 bg-radar-accent/5 px-4 py-2.5 text-xs sm:flex-row sm:items-center sm:justify-between"
    >
      <div className="flex items-start gap-2">
        {status.status === 'failed' ? (
          <CircleAlert className="mt-0.5 h-3.5 w-3.5 shrink-0 text-radar-warn" />
        ) : (
          <Loader2 className="mt-0.5 h-3.5 w-3.5 shrink-0 animate-spin text-radar-accent" />
        )}
        <div>
          <p className="font-medium text-radar-text">
            {status.status === 'in-progress'
              ? 'Refresh running in background'
              : status.status === 'failed'
                ? 'Refresh failed'
                : 'Refresh running in background'}
          </p>
          <p className="mt-0.5 text-radar-muted">{message}</p>
        </div>
      </div>
      <button
        type="button"
        onClick={onDismiss}
        aria-label="Dismiss refresh-status banner"
        title="Dismiss"
        className="focus-ring inline-flex h-7 w-7 items-center justify-center self-start rounded-md border border-radar-border bg-radar-panel2 text-radar-muted transition hover:border-radar-accent/40 hover:text-radar-text"
      >
        <X className="h-3.5 w-3.5" />
      </button>
    </div>
  );
}