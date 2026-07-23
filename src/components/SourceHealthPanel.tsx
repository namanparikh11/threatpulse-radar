/**
 * V6.1 — Source Health panel.
 *
 * Compact summary bar with a chip per source. Clicking a
 * chip expands a detail card beneath. The expanded card
 * shows purpose, limitations, official-source link,
 * refresh schedule, coverage, and (for incremental
 * sources) backfill metadata.
 *
 * No env-var names appear in any field. The state per
 * source is derived at request time from the persisted
 * observations; the persisted payload contains only
 * observations.
 */

import { useState, useEffect, useRef } from 'react';
import { Activity } from 'lucide-react';
import type { SourceStatus, SourceState } from '../types/sourceHealth';
import SourceStatusChip from './SourceStatusChip';
import SourceStatusCard from './SourceStatusCard';

interface SourceHealthPanelProps {
  sources: SourceStatus[];
  /**
   * Optional id of a source card to highlight (e.g. when
   * the user clicks the "Provider status changed" chip in
   * the What Changed panel). The card is briefly
   * highlighted with a focus ring.
   */
  highlightId?: string | null;
}

const STATE_LABELS: Record<SourceState, string> = {
  unknown: 'unknown',
  fresh: 'healthy',
  partial: 'partial',
  stale: 'stale',
  unavailable: 'unavailable',
};

export default function SourceHealthPanel({ sources, highlightId }: SourceHealthPanelProps) {
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const cardRef = useRef<HTMLDivElement | null>(null);

  // Keyboard: ESC closes the expanded card.
  useEffect(() => {
    if (!expandedId) return;
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') setExpandedId(null);
    }
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [expandedId]);

  // When the parent requests a highlight, expand + scroll
  // to the matching card.
  useEffect(() => {
    if (!highlightId) return;
    setExpandedId(highlightId);
    // Defer scroll until after the card mounts.
    const id = highlightId;
    setTimeout(() => {
      const el = document.querySelector(`[data-testid="source-chip-${id}"]`);
      if (el && typeof (el as HTMLElement).scrollIntoView === 'function') {
        (el as HTMLElement).scrollIntoView({ behavior: 'smooth', block: 'center' });
      }
    }, 50);
  }, [highlightId]);

  if (!sources || sources.length === 0) {
    return (
      <section className="panel p-4" aria-label="Source health">
        <div className="flex items-center gap-2 text-radar-muted">
          <Activity className="h-4 w-4" />
          <h2 className="text-sm font-semibold">Source health unavailable.</h2>
        </div>
        <p className="mt-1 text-[11px] text-radar-dim">
          The V6.1 public intelligence bundle is not yet published. Source
          health will appear here once the first dataset-bound bundle is
          available.
        </p>
      </section>
    );
  }

  // Aggregate counts for the summary line.
  const counts = sources.reduce<Record<SourceState, number>>(
    (acc, s) => {
      acc[s.freshness.state] = (acc[s.freshness.state] || 0) + 1;
      return acc;
    },
    { unknown: 0, fresh: 0, partial: 0, stale: 0, unavailable: 0 },
  );

  const expandedSource = expandedId ? sources.find((s) => s.id === expandedId) || null : null;

  return (
    <section
      className="panel p-4"
      aria-label="Source health"
      data-testid="source-health-panel"
    >
      <div className="flex flex-wrap items-center gap-3">
        <Activity className="h-4 w-4 text-radar-accent" aria-hidden="true" />
        <h2 className="text-sm font-semibold text-radar-text">Source health</h2>
        <span className="text-xs text-radar-dim">
          {counts.fresh} {STATE_LABELS.fresh} ·{' '}
          {counts.partial} {STATE_LABELS.partial} ·{' '}
          {counts.stale} {STATE_LABELS.stale} ·{' '}
          {counts.unavailable} {STATE_LABELS.unavailable} ·{' '}
          {counts.unknown} {STATE_LABELS.unknown}
        </span>
      </div>
      <p className="mt-1 text-[11px] text-radar-dim">
        Click a chip to see the full status, limitations, refresh schedule,
        and official source link. Six sources, one gating, two best-effort,
        two incremental, one canonical.
      </p>
      <div
        className="mt-3 flex flex-wrap gap-2"
        role="group"
        aria-label="Source chips"
      >
        {sources.map((s) => (
          <SourceStatusChip
            key={s.id}
            source={s}
            expanded={expandedId === s.id}
            highlight={highlightId === s.id}
            onToggle={(id) => setExpandedId((cur) => (cur === id ? null : id))}
          />
        ))}
      </div>
      {expandedSource ? (
        <div ref={cardRef}>
          <SourceStatusCard
            source={expandedSource}
            onClose={() => setExpandedId(null)}
          />
        </div>
      ) : null}
    </section>
  );
}
