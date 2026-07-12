import {
  ArrowDownAZ,
  Filter,
  RotateCcw,
  Search,
  ShieldOff,
  X,
} from 'lucide-react';
import type {
  SeverityFilterValue,
  SsvcExploitation,
  SortDirection,
  SortField,
  SortState,
  Vulnerability,
  VulnerabilityFilters,
} from '../types/vulnerability';
import { DEFAULT_FILTERS, DEFAULT_SORT } from '../types/vulnerability';
import { SEVERITY_ORDER } from '../utils/severity';
import SearchStatus from './SearchStatus';

interface FiltersPanelProps {
  filters: VulnerabilityFilters;
  sort: SortState;
  onChange: (next: VulnerabilityFilters) => void;
  onSortChange: (next: SortState) => void;
  totalCount: number;
  matchCount: number;
  isSearching: boolean;
  isSearchActive: boolean;
  onReset: () => void;
  /**
   * v5.7: full vulnerability set (un-filtered) — used to
   * compute the dynamic SSVC exploitation values the
   * dropdown offers. Without this prop, the dropdown would
   * have to hardcode a value list, which the v5.7 spec
   * explicitly forbids.
   */
  allVulnerabilities?: Vulnerability[];
}

const SEVERITY_OPTIONS: SeverityFilterValue[] = ['All', ...SEVERITY_ORDER];

/**
 * Friendly labels for every (field, direction) pair the dashboard supports.
 * Drives the <select> dropdown. The displayed label tells the user exactly
 * what will happen when they pick it.
 */
const SORT_OPTIONS: { value: SortState; label: string }[] = [
  { value: { field: 'newest',        direction: 'desc' }, label: 'Newest first' },
  { value: { field: 'publishedDate', direction: 'asc'  }, label: 'Oldest first' },
  { value: { field: 'cvss',          direction: 'desc' }, label: 'CVSS: high to low' },
  { value: { field: 'cvss',          direction: 'asc'  }, label: 'CVSS: low to high' },
  { value: { field: 'epss',          direction: 'desc' }, label: 'EPSS: high to low' },
  { value: { field: 'epss',          direction: 'asc'  }, label: 'EPSS: low to high' },
  { value: { field: 'severity',      direction: 'desc' }, label: 'Severity: high to low' },
  { value: { field: 'severity',      direction: 'asc'  }, label: 'Severity: low to high' },
  { value: { field: 'kev',           direction: 'desc' }, label: 'KEV first' },
  { value: { field: 'kev',           direction: 'asc'  }, label: 'Non-KEV first' },
  { value: { field: 'vendor',        direction: 'asc'  }, label: 'Vendor A–Z' },
  { value: { field: 'vendor',        direction: 'desc' }, label: 'Vendor Z–A' },
];

function sortKey(s: SortState): string {
  return `${s.field}:${s.direction}`;
}

export default function FiltersPanel({
  filters,
  sort,
  onChange,
  onSortChange,
  totalCount,
  matchCount,
  isSearching,
  isSearchActive,
  onReset,
  allVulnerabilities = [],
}: FiltersPanelProps) {
  const update = <K extends keyof VulnerabilityFilters>(
    key: K,
    value: VulnerabilityFilters[K]
  ) => onChange({ ...filters, [key]: value });

  const clearSearch = () => update('search', '');

  /**
   * v5.7: "Reset all filters" must also clear the active
   * defender-view preset. The reset always returns the
   * filter state to `DEFAULT_FILTERS` (presetId: null,
   * githubAdvisory: 'any', patchContext: 'any',
   * ssvcExploitation: 'any') and the sort to
   * `DEFAULT_SORT`. The `onReset` callback is fired so
   * the dashboard can clear any other state.
   */
  const handleReset = () => {
    onChange(DEFAULT_FILTERS);
    onSortChange(DEFAULT_SORT);
    onReset();
  };

  const epssPct = Math.round(filters.minEpss * 100);

  /**
   * v5.7: Dynamically enumerate the SSVC exploitation
   * values that actually appear in the current dataset so
   * the dropdown never offers a value the data cannot
   * satisfy. The order is the documented SSVC order
   * (`none` → `poc` → `active`), not the order of first
   * appearance, so the dropdown is stable across renders.
   */
  const SSVC_EXPLOITATION_ORDER: SsvcExploitation[] = [
    'none',
    'poc',
    'active',
  ];
  const ssvcValuesPresent = new Set<SsvcExploitation>();
  for (const v of allVulnerabilities) {
    if (v.ssvcExploitation) ssvcValuesPresent.add(v.ssvcExploitation);
  }
  const ssvcExploitationOptions: SsvcExploitation[] = SSVC_EXPLOITATION_ORDER.filter(
    (v) => ssvcValuesPresent.has(v)
  );
  // If the current filter is set to a value that no
  // longer appears in the dataset (e.g. after a refresh
  // the value fell out), keep the option visible so the
  // user can still see the active filter and reset it.
  const currentSsvc = filters.ssvcExploitation ?? 'any';
  if (
    currentSsvc !== 'any' &&
    !ssvcExploitationOptions.includes(currentSsvc as SsvcExploitation)
  ) {
    ssvcExploitationOptions.push(currentSsvc as SsvcExploitation);
  }

  return (
    <section className="panel p-4" aria-label="Filters">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2 text-radar-text">
          <Filter className="h-4 w-4 text-radar-accent" />
          <h2 className="text-sm font-semibold">Filters</h2>
          <span className="text-xs text-radar-dim">
            Showing {matchCount.toLocaleString('en-US')} of {totalCount.toLocaleString('en-US')}
          </span>
        </div>
        <button
          type="button"
          onClick={handleReset}
          className="focus-ring inline-flex items-center gap-1 rounded-md border border-radar-border px-2 py-1 text-xs text-radar-muted transition hover:text-radar-text"
        >
          <RotateCcw className="h-3 w-3" />
          Reset all filters
        </button>
      </div>

      <div className="grid grid-cols-1 gap-4 md:grid-cols-12">
        {/* Search */}
        <div className="md:col-span-5">
          <label className="stat-label mb-1 block" htmlFor="search">
            Search
          </label>
          <div className="relative">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-radar-dim" />
            <input
              id="search"
              type="search"
              value={filters.search}
              onChange={(e) => update('search', e.target.value)}
              placeholder="CVE id, vendor, product, severity, source…"
              className="focus-ring w-full rounded-md border border-radar-border bg-radar-panel2 py-2 pl-8 pr-9 text-sm text-radar-text placeholder:text-radar-dim"
              aria-describedby="search-status"
              autoComplete="off"
              spellCheck={false}
            />
            {filters.search.length > 0 && (
              <button
                type="button"
                onClick={clearSearch}
                aria-label="Clear search"
                className="focus-ring absolute right-1.5 top-1/2 grid h-6 w-6 -translate-y-1/2 place-items-center rounded-md text-radar-dim transition hover:bg-radar-border/50 hover:text-radar-text"
              >
                <X className="h-3.5 w-3.5" />
              </button>
            )}
          </div>
          <div id="search-status">
            <SearchStatus
              isSearching={isSearching}
              isSearchActive={isSearchActive}
              matchCount={matchCount}
              totalCount={totalCount}
            />
          </div>
        </div>

        {/* Severity */}
        <div className="md:col-span-3">
          <label className="stat-label mb-1 block">Severity</label>
          <div className="flex flex-wrap gap-1" role="group" aria-label="Severity filter">
            {SEVERITY_OPTIONS.map((s) => {
              const active = filters.severity === s;
              return (
                <button
                  key={s}
                  type="button"
                  onClick={() => update('severity', s)}
                  className={[
                    'focus-ring rounded-md border px-2.5 py-1.5 text-xs transition',
                    active
                      ? 'border-radar-accent/50 bg-radar-accent/10 text-radar-text'
                      : 'border-radar-border bg-radar-panel2 text-radar-muted hover:text-radar-text',
                  ].join(' ')}
                  aria-pressed={active}
                >
                  {s}
                </button>
              );
            })}
          </div>
        </div>

        {/* Sort */}
        <div className="md:col-span-2">
          <label className="stat-label mb-1 block" htmlFor="sort-by">
            Sort by
          </label>
          <div className="relative">
            <ArrowDownAZ className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-radar-dim" />
            <select
              id="sort-by"
              value={sortKey(sort)}
              onChange={(e) => {
                const next = SORT_OPTIONS.find(
                  (o) => sortKey(o.value) === e.target.value
                );
                if (next) onSortChange(next.value);
              }}
              className="focus-ring w-full appearance-none rounded-md border border-radar-border bg-radar-panel2 py-2 pl-8 pr-3 text-sm text-radar-text"
            >
              {SORT_OPTIONS.map((o) => (
                <option key={sortKey(o.value)} value={sortKey(o.value)} className="bg-radar-panel2">
                  {o.label}
                </option>
              ))}
            </select>
          </div>
        </div>

        {/* KEV */}
        <div className="md:col-span-2">
          <label className="stat-label mb-1 block">KEV only</label>
          <button
            type="button"
            onClick={() => update('kevOnly', !filters.kevOnly)}
            className={[
              'focus-ring flex w-full items-center justify-between gap-2 rounded-md border px-2.5 py-2 text-xs transition',
              filters.kevOnly
                ? 'border-radar-warn/50 bg-radar-warn/10 text-radar-text'
                : 'border-radar-border bg-radar-panel2 text-radar-muted hover:text-radar-text',
            ].join(' ')}
            aria-pressed={filters.kevOnly}
          >
            <span className="flex items-center gap-1.5">
              <ShieldOff className="h-3.5 w-3.5" />
              {filters.kevOnly ? 'Yes' : 'Off'}
            </span>
            <span
              className={[
                'h-2 w-2 rounded-full',
                filters.kevOnly ? 'bg-radar-warn' : 'bg-radar-dim',
              ].join(' ')}
            />
          </button>
        </div>

        {/* EPSS Slider */}
        <div className="md:col-span-12">
          <div className="flex items-center justify-between">
            <label className="stat-label" htmlFor="epss">
              Minimum EPSS probability
            </label>
            <span className="font-mono text-xs text-radar-accent">
              ≥ {epssPct}%
            </span>
          </div>
          <input
            id="epss"
            type="range"
            min={0}
            max={100}
            step={1}
            value={epssPct}
            onChange={(e) => update('minEpss', Number(e.target.value) / 100)}
            aria-valuemin={0}
            aria-valuemax={100}
            aria-valuenow={epssPct}
            className="focus-ring mt-2 h-1.5 w-full cursor-pointer appearance-none rounded-full bg-radar-border accent-radar-accent"
          />
          <div className="mt-1 flex justify-between text-[10px] text-radar-dim">
            <span>0%</span>
            <span>25%</span>
            <span>50%</span>
            <span>75%</span>
            <span>100%</span>
          </div>
        </div>

        {/* v5.7 enrichment filters: GitHub Advisory, Patch
            context, and SSVC exploitation. Each is a compact
            <select> with the documented "Any" wildcard plus
            the values the data actually carries. Absence of
            enrichment is treated as "unknown", never as a
            negative signal. */}
        <div className="md:col-span-4">
          <label
            className="stat-label mb-1 block"
            htmlFor="github-advisory"
          >
            GitHub Advisory
          </label>
          <select
            id="github-advisory"
            value={filters.githubAdvisory ?? 'any'}
            onChange={(e) =>
              update(
                'githubAdvisory',
                e.target.value as 'any' | 'available'
              )
            }
            className="focus-ring w-full appearance-none rounded-md border border-radar-border bg-radar-panel2 py-2 px-2.5 text-xs text-radar-text"
            aria-label="Filter by GitHub Advisory availability"
          >
            <option value="any">Any</option>
            <option value="available">Available</option>
          </select>
          <p className="mt-1 text-[10px] text-radar-dim">
            Available = a reviewed GitHub Advisory exists. Absence
            is <span className="text-radar-text">unknown</span>,
            not &quot;no patch&quot;.
          </p>
        </div>

        <div className="md:col-span-4">
          <label
            className="stat-label mb-1 block"
            htmlFor="patch-context"
          >
            Patch context
          </label>
          <select
            id="patch-context"
            value={filters.patchContext ?? 'any'}
            onChange={(e) =>
              update(
                'patchContext',
                e.target.value as 'any' | 'available' | 'unavailable'
              )
            }
            className="focus-ring w-full appearance-none rounded-md border border-radar-border bg-radar-panel2 py-2 px-2.5 text-xs text-radar-text"
            aria-label="Filter by patch context"
          >
            <option value="any">Any</option>
            <option value="available">First patched version available</option>
            <option value="unavailable">Patched version unavailable</option>
          </select>
          <p className="mt-1 text-[10px] text-radar-dim">
            Unavailable = reviewed advisory exists but no patched
            version is listed. Rendered as &quot;First patched
            version unavailable&quot;, never &quot;No fix exists&quot;.
          </p>
        </div>

        <div className="md:col-span-4">
          <label
            className="stat-label mb-1 block"
            htmlFor="ssvc-exploitation"
          >
            SSVC exploitation
          </label>
          <select
            id="ssvc-exploitation"
            value={currentSsvc}
            onChange={(e) =>
              update(
                'ssvcExploitation',
                e.target.value as 'any' | SsvcExploitation
              )
            }
            className="focus-ring w-full appearance-none rounded-md border border-radar-border bg-radar-panel2 py-2 px-2.5 text-xs text-radar-text"
            aria-label="Filter by CISA Vulnrichment SSVC exploitation value"
          >
            <option value="any">Any</option>
            {ssvcExploitationOptions.map((v) => (
              <option key={v} value={v}>
                {v === 'active'
                  ? 'Active'
                  : v === 'poc'
                    ? 'Proof of concept'
                    : 'None'}
              </option>
            ))}
          </select>
          <p className="mt-1 text-[10px] text-radar-dim">
            Options come from the current dataset only — no
            hardcoded values. Absence of SSVC is{' '}
            <span className="text-radar-text">unknown</span>, not a
            negative assessment.
          </p>
        </div>
      </div>
    </section>
  );
}

// Re-export for convenience; some callers want the field/direction types.
export type { SortField, SortDirection };
