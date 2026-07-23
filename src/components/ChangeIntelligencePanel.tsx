/**
 * V6.1 — "What changed" panel.
 *
 * Renders the aggregate change summary, the panel-local
 * category chip row, and the filtered per-CVE change rows
 * (bounded to 25). The panel-local filter is isolated to
 * this component; it does NOT modify the main
 * VulnerabilityFilters, the Defender Views presets, the
 * main table, or the CSV export.
 *
 * The chip-local filter is documented in the panel as
 * "Filters here affect only this panel."
 *
 * Categories:
 *   - newly-tracked
 *   - no-longer-tracked
 *   - fact-newly-available
 *   - fact-changed
 *   - fact-no-longer-present
 *   - provider-status-changed (summary-level; opens the
 *     Source Health card on click)
 */

import { useState, useEffect, useMemo, useCallback } from 'react';
import { History } from 'lucide-react';
import type { ChangeSummary, ChangePanelCategory, ChangeItem } from '../types/change';
import type { SourceStatus } from '../types/sourceHealth';
import { fetchChangesForCategory } from '../services/vulnerabilityService';
import ChangeItemRow from './ChangeItemRow';

interface ChangeIntelligencePanelProps {
  /** Aggregate change summary (from the public envelope). */
  changeSummary: ChangeSummary | null;
  /** Comparable axes (for the suppression disclosure). */
  comparableAxes: string[];
  /** Suppressed axes (with sanitized reasons). */
  suppressedAxes: { axis: string; reason: string }[];
  /** Currently-attached public-intelligence version. */
  publicIntelligenceVersion: string | null;
  /** Sources (for the provider-status-changed chip). */
  sources: SourceStatus[];
  /** Callback to open the drawer for a CVE. */
  onOpen: (cveId: string) => void;
  /** Callback to highlight a Source Health card. */
  onHighlightSource: (sourceId: string) => void;
  /** V6.5: open the report builder pre-seeded with the
   *  currently loaded change items. Optional. */
  onOpenReportBuilder?: (cveIds: string[], reportType?: string, title?: string) => void;
}

interface CategoryChip {
  id: ChangePanelCategory;
  label: string;
  count: number;
  description: string;
}

function classifyProviderStatusChanged(prev: SourceStatus[], current: SourceStatus[]): { changed: boolean; sourceIds: string[] } {
  if (prev.length !== current.length) return { changed: true, sourceIds: [] };
  const sourceIds: string[] = [];
  for (let i = 0; i < current.length; i++) {
    const a = prev[i];
    const b = current[i];
    if (a.id !== b.id) return { changed: true, sourceIds: [] };
    if (a.freshness.state !== b.freshness.state) sourceIds.push(b.id);
  }
  return { changed: sourceIds.length > 0, sourceIds };
}

const CHANGE_LIMIT = 25;

export default function ChangeIntelligencePanel({
  changeSummary,
  comparableAxes: _comparableAxes,
  suppressedAxes,
  publicIntelligenceVersion,
  sources,
  onOpen,
  onHighlightSource,
  onOpenReportBuilder,
}: ChangeIntelligencePanelProps) {
  const [activeCategory, setActiveCategory] = useState<ChangePanelCategory | null>(null);
  const [categoryItems, setCategoryItems] = useState<ChangeItem[]>([]);
  const [totalMatching, setTotalMatching] = useState<number>(0);
  const [loading, setLoading] = useState<boolean>(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [previousSources, setPreviousSources] = useState<SourceStatus[] | null>(null);

  // Compute provider-status-changed count from a previous
  // snapshot of sources (kept in component state for the
  // session). This is the only summary-level classifier.
  const providerStatusChangedInfo = useMemo(() => {
    if (!previousSources) return { changed: false, sourceIds: [] };
    return classifyProviderStatusChanged(previousSources, sources);
  }, [previousSources, sources]);

  // Track previous sources for the provider-status-changed
  // detector. Updated whenever `sources` changes.
  useEffect(() => {
    setPreviousSources((prev) => {
      if (!prev) return sources;
      return prev;
    });
  }, [sources]);

  const chips: CategoryChip[] = useMemo(() => {
    if (!changeSummary) return [];
    return [
      { id: 'newly-tracked',            label: 'Newly tracked',            count: changeSummary.newlyTracked,         description: 'CVEs that are new in the current snapshot' },
      { id: 'no-longer-tracked',        label: 'No longer tracked',        count: changeSummary.noLongerTracked,     description: 'CVEs that left the public tracked universe' },
      { id: 'fact-newly-available',     label: 'Fact newly available',     count: changeSummary.factNewlyAvailable,   description: 'A provider fact became available for a CVE' },
      { id: 'fact-changed',             label: 'Fact changed',             count: changeSummary.factChanged,          description: 'A provider fact changed value' },
      { id: 'fact-no-longer-present',   label: 'Fact no longer present',   count: changeSummary.factNoLongerPresent,  description: 'A previously-known provider fact is no longer present' },
      { id: 'provider-status-changed',  label: 'Provider status changed',  count: providerStatusChangedInfo.changed ? providerStatusChangedInfo.sourceIds.length : 0, description: 'A source health state changed' },
    ];
  }, [changeSummary, providerStatusChangedInfo]);

  // Fetch category items when activeCategory changes.
  useEffect(() => {
    if (!activeCategory) {
      setCategoryItems([]);
      setTotalMatching(0);
      return;
    }
    if (activeCategory === 'provider-status-changed') {
      // No CVE list for this category; the click action
      // navigates to the Source Health panel.
      setCategoryItems([]);
      setTotalMatching(0);
      return;
    }
    if (!publicIntelligenceVersion) {
      setLoadError('No public-intelligence version is attached.');
      return;
    }
    let cancelled = false;
    setLoading(true);
    setLoadError(null);
    fetchChangesForCategory(activeCategory, publicIntelligenceVersion, CHANGE_LIMIT)
      .then((body) => {
        if (cancelled) return;
        if (!body) {
          setLoadError('Failed to load change items.');
          setCategoryItems([]);
          setTotalMatching(0);
          return;
        }
        setCategoryItems(Array.isArray(body.items) ? body.items : []);
        setTotalMatching(typeof body.totalMatching === 'number' ? body.totalMatching : 0);
      })
      .catch(() => {
        if (cancelled) return;
        setLoadError('Failed to load change items.');
        setCategoryItems([]);
        setTotalMatching(0);
      })
      .finally(() => {
        if (cancelled) return;
        setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [activeCategory, publicIntelligenceVersion]);

  const handleChipClick = useCallback((id: ChangePanelCategory) => {
    if (id === 'provider-status-changed' && providerStatusChangedInfo.sourceIds.length > 0) {
      onHighlightSource(providerStatusChangedInfo.sourceIds[0]);
      return;
    }
    setActiveCategory((cur) => (cur === id ? null : id));
  }, [onHighlightSource, providerStatusChangedInfo]);

  if (!changeSummary) {
    return (
      <section className="panel p-4" aria-label="What changed">
        <div className="flex items-center gap-2 text-radar-muted">
          <History className="h-4 w-4" />
          <h2 className="text-sm font-semibold">What changed unavailable.</h2>
        </div>
        <p className="mt-1 text-[11px] text-radar-dim">
          The change intelligence bundle is not yet published. The panel
          will populate once a second dataset-bound bundle is available.
        </p>
      </section>
    );
  }

  const totalChanges = (changeSummary.newlyTracked || 0)
    + (changeSummary.noLongerTracked || 0)
    + (changeSummary.factNewlyAvailable || 0)
    + (changeSummary.factChanged || 0)
    + (changeSummary.factNoLongerPresent || 0);

  return (
    <section
      className="panel p-4"
      aria-label="What changed"
      data-testid="change-intelligence-panel"
    >
      <div className="flex flex-wrap items-center gap-3">
        <History className="h-4 w-4 text-radar-accent" aria-hidden="true" />
        <h2 className="text-sm font-semibold text-radar-text">What changed</h2>
        <span className="text-xs text-radar-dim">
          {totalChanges} {totalChanges === 1 ? 'change' : 'changes'} in the current snapshot
        </span>
      </div>
      <p className="mt-1 text-[11px] text-radar-dim">
        A centrally generated diff between the previous successful dataset
        and the current one. Click a category to see the matching CVEs.
        Filters here affect only this panel.
      </p>

      {onOpenReportBuilder && totalChanges > 0 && (
        <div className="mt-2">
          <button
            type="button"
            onClick={() => onOpenReportBuilder([], 'change-briefing', 'Change Briefing')}
            className="focus-ring inline-flex items-center gap-1.5 rounded-md border border-radar-accent/40 bg-radar-accent/10 px-2.5 py-1.5 text-xs text-radar-accent transition hover:border-radar-accent"
            data-testid="change-intel-report"
          >
            Build a Change Briefing report
          </button>
        </div>
      )}

      {suppressedAxes && suppressedAxes.length > 0 ? (
        <p className="mt-2 text-[11px] text-amber-300/90">
          Suppressed axes:{' '}
          {suppressedAxes.map((s) => `${s.axis} (${s.reason})`).join('; ')}
        </p>
      ) : null}

      <div
        className="mt-3 flex flex-wrap gap-2"
        role="group"
        aria-label="Change categories"
      >
        {chips.map((c) => {
          const isActive = activeCategory === c.id;
          return (
            <button
              key={c.id}
              type="button"
              onClick={() => handleChipClick(c.id)}
              aria-pressed={isActive}
              aria-label={`Category: ${c.label}. ${c.description}`}
              title={`${c.label} — ${c.description}`}
              data-testid={`change-chip-${c.id}`}
              className={[
                'focus-ring inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1.5 text-xs transition',
                isActive
                  ? 'border-radar-accent/60 bg-radar-accent/15 text-radar-text'
                  : 'border-radar-border bg-radar-panel2 text-radar-muted hover:border-radar-accent/40 hover:text-radar-text',
              ].join(' ')}
            >
              <span>{c.label}</span>
              <span className="text-[10px] text-radar-dim">{c.count}</span>
            </button>
          );
        })}
      </div>

      {activeCategory === 'provider-status-changed' ? (
        <p className="mt-3 text-[11px] text-radar-dim">
          A source's health state changed since the previous snapshot.{' '}
          {providerStatusChangedInfo.sourceIds.length > 0
            ? `The first changed source (${providerStatusChangedInfo.sourceIds[0]}) is highlighted in the Source Health panel above.`
            : 'No specific source has changed yet — the chip will populate once sources are tracked across snapshots.'}
        </p>
      ) : null}

      {activeCategory && activeCategory !== 'provider-status-changed' ? (
        <>
          {loading ? (
            <p className="mt-3 text-[11px] text-radar-dim">Loading change items…</p>
          ) : loadError ? (
            <p className="mt-3 text-[11px] text-rose-300/90">{loadError}</p>
          ) : categoryItems.length === 0 ? (
            <p className="mt-3 rounded-md border border-radar-border bg-radar-panel2/60 p-3 text-xs text-radar-muted">
              No changes match the “{activeCategory}” category in this snapshot.
            </p>
          ) : (
            <>
              <p className="mt-3 text-[11px] text-radar-dim">
                {totalMatching} matching change{totalMatching === 1 ? '' : 's'} in this category.
                Showing the most recent {Math.min(categoryItems.length, CHANGE_LIMIT)}
                {totalMatching > CHANGE_LIMIT ? ` of ${totalMatching}` : ''}.
              </p>
              <ul className="mt-2 divide-y divide-radar-border rounded-md border border-radar-border bg-radar-panel2/40">
                {categoryItems.map((item) => (
                  <ChangeItemRow key={item.cveId} item={item} onOpen={onOpen} />
                ))}
              </ul>
            </>
          )}
        </>
      ) : null}
    </section>
  );
}
