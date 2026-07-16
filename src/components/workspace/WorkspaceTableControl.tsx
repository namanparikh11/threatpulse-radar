/**
 * V6.4 — Compact watch toggle rendered inside the
 * existing vulnerability table action surface.
 *
 * A standalone cell that:
 *   - shows a "Watch" pill / "Watched" pill
 *   - toggles on click, prevents the row-level click
 *     from also opening the drawer
 *   - is keyboard accessible (Enter / Space)
 *   - has an aria-label that includes the full CVE id
 *     so a screen-reader user knows exactly which row
 *     they are about to mutate
 *   - renders a thin "WS" indicator when the row is
 *     archived (visual feedback; the row-level state
 *     is the source of truth, not the URL)
 *   - is silent when the workspace is unavailable
 *     (the toggle stays visible but disabled, so the
 *     operator can see the workspace status without
 *     the dashboard breaking)
 *
 * The component NEVER reads from the URL. The URL
 * does not change as the operator watches / unwatches
 * a CVE. A shared public URL therefore does not
 * reveal whether a CVE is watched on the current
 * device.
 */

import { useCallback, useMemo } from 'react';
import { Bookmark, BookmarkMinus, EyeOff } from 'lucide-react';
import { useWorkspace, type WorkspaceEntry } from '../../state/WorkspaceContext';

interface WatchCellProps {
  cveId: string;
}

export default function WorkspaceTableControl({ cveId }: WatchCellProps) {
  const { state, getEntry, toggleWatch } = useWorkspace();
  const entry: WorkspaceEntry | null = getEntry(cveId);
  const watched = !!entry?.watched;
  const archived = !!entry?.archived;
  const disabled = state.status === 'unavailable' || state.status === 'error';

  const onClick = useCallback((e: React.MouseEvent | React.KeyboardEvent) => {
    e.stopPropagation();
    if (disabled) return;
    void toggleWatch(cveId, !watched);
  }, [cveId, watched, disabled, toggleWatch]);

  const label = useMemo(() => watched
    ? `Remove ${cveId} from local watchlist`
    : `Add ${cveId} to local watchlist`,
  [cveId, watched]);

  return (
    <div className="inline-flex items-center gap-1">
      <button
        type="button"
        onClick={onClick}
        disabled={disabled}
        aria-label={label}
        title={label}
        className={[
          'focus-ring inline-flex items-center gap-1 rounded-md border px-2 py-1 text-[11px] transition',
          watched
            ? 'border-radar-accent/40 bg-radar-accent/10 text-radar-accent hover:border-radar-accent'
            : 'border-radar-border bg-radar-panel2 text-radar-muted hover:border-radar-accent/40 hover:text-radar-text',
          disabled ? 'opacity-50 cursor-not-allowed' : '',
        ].join(' ')}
      >
        {watched ? <BookmarkMinus className="h-3 w-3" /> : <Bookmark className="h-3 w-3" />}
        {watched ? 'Watched' : 'Watch'}
      </button>
      {archived && (
        <span
          className="inline-flex items-center gap-0.5 rounded-full border border-radar-muted/40 bg-radar-panel2 px-1.5 py-0.5 text-[10px] text-radar-muted"
          aria-label={`${cveId} is archived in the local workspace`}
          title="Archived locally"
        >
          <EyeOff className="h-2.5 w-2.5" />
          Archived
        </span>
      )}
    </div>
  );
}
