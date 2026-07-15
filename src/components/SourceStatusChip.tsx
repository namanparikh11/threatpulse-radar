/**
 * V6.1 — One chip per source for the Source Health panel.
 *
 * Renders the state indicator, the source display name,
 * the state chip, and the coverage count. Clicking the
 * chip expands the per-source card; clicking again (or
 * pressing ESC) collapses it. The expanded card is rendered
 * by the parent SourceHealthPanel.
 */

import type { SourceStatus } from '../types/sourceHealth';

interface SourceStatusChipProps {
  source: SourceStatus;
  expanded: boolean;
  highlight: boolean;
  onToggle: (id: string) => void;
}

function stateToneClass(state: string): string {
  switch (state) {
    case 'fresh':       return 'text-emerald-400';
    case 'partial':     return 'text-cyan-400';
    case 'stale':       return 'text-amber-400';
    case 'unavailable': return 'text-rose-400';
    case 'unknown':
    default:            return 'text-radar-dim';
  }
}

function stateChipLabel(state: string): { label: string; tone: string } | null {
  switch (state) {
    case 'fresh':       return { label: 'OK',         tone: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-300' };
    case 'partial':     return { label: 'Partial',    tone: 'border-cyan-500/40 bg-cyan-500/10 text-cyan-300' };
    case 'stale':       return { label: 'Stale',      tone: 'border-amber-500/40 bg-amber-500/10 text-amber-300' };
    case 'unavailable': return { label: 'Unavailable',tone: 'border-rose-500/40 bg-rose-500/10 text-rose-300' };
    case 'unknown':     return { label: 'Unknown',    tone: 'border-radar-border bg-radar-panel2 text-radar-muted' };
    default:            return null;
  }
}

export default function SourceStatusChip({ source, expanded, highlight, onToggle }: SourceStatusChipProps) {
  const chip = stateChipLabel(source.freshness.state);
  return (
    <button
      type="button"
      onClick={() => onToggle(source.id)}
      aria-expanded={expanded}
      aria-controls={`source-detail-${source.id}`}
      data-highlight={highlight || undefined}
      data-testid={`source-chip-${source.id}`}
      className={[
        'focus-ring group inline-flex items-center gap-2 rounded-md border px-2.5 py-1.5 text-xs transition',
        expanded
          ? 'border-radar-accent/60 bg-radar-accent/15 text-radar-text'
          : 'border-radar-border bg-radar-panel2 text-radar-muted hover:border-radar-accent/40 hover:text-radar-text',
        highlight ? 'ring-2 ring-radar-accent/60' : '',
      ].join(' ')}
    >
      <span
        className={`inline-block h-2 w-2 rounded-full ${stateToneClass(source.freshness.state)}`}
        aria-hidden="true"
      />
      <span className="font-medium">{source.displayName}</span>
      {chip ? (
        <span className={`chip ${chip.tone}`}>{chip.label}</span>
      ) : null}
      <span className="text-[10px] text-radar-dim">
        {source.coverage.enriched.toLocaleString('en-US')} /{' '}
        {source.coverage.total.toLocaleString('en-US')}
      </span>
    </button>
  );
}
