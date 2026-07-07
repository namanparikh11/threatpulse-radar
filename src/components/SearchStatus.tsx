import { Loader2 } from 'lucide-react';

interface SearchStatusProps {
  /** True when the search text is debouncing (filter hasn't applied yet). */
  isSearching: boolean;
  /** True when there's an active search (debounced or not). */
  isSearchActive: boolean;
  /** How many rows match the current (debounced) filter. */
  matchCount: number;
  /** Total rows in the dataset (pre-filter). */
  totalCount: number;
}

/**
 * Tiny inline status line rendered under the search input.
 * - "Searching current dataset…" while debouncing
 * - "X of Y results" once the filter has settled
 * - "Y results" when no search is active
 */
export default function SearchStatus({
  isSearching,
  isSearchActive,
  matchCount,
  totalCount,
}: SearchStatusProps) {
  let label: string;
  let tone: 'busy' | 'done' | 'idle' = 'idle';

  if (isSearching) {
    label = 'Searching current dataset…';
    tone = 'busy';
  } else if (isSearchActive) {
    label = `${matchCount.toLocaleString('en-US')} of ${totalCount.toLocaleString('en-US')} results`;
    tone = 'done';
  } else {
    label = `${totalCount.toLocaleString('en-US')} records in dataset`;
    tone = 'idle';
  }

  return (
    <div
      role="status"
      aria-live="polite"
      className="mt-1 flex items-center gap-1.5 text-[11px]"
    >
      {tone === 'busy' && (
        <Loader2 className="h-3 w-3 animate-spin text-radar-accent" />
      )}
      {tone === 'done' && (
        <span className="h-1.5 w-1.5 rounded-full bg-radar-accent2" />
      )}
      {tone === 'idle' && (
        <span className="h-1.5 w-1.5 rounded-full bg-radar-dim" />
      )}
      <span
        className={
          tone === 'busy'
            ? 'text-radar-accent'
            : tone === 'done'
            ? 'text-radar-text'
            : 'text-radar-dim'
        }
      >
        {label}
      </span>
    </div>
  );
}
