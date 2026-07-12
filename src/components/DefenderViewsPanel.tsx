import { useCallback } from 'react';
import { Crosshair, Download, ShieldCheck, ShieldX, X } from 'lucide-react';
import type { Vulnerability, VulnerabilityFilters } from '../types/vulnerability';
import {
  PRESETS,
  type DefenderPreset,
  type PresetId,
} from '../utils/presets';
import {
  CSV_COLUMNS,
  defaultExportFilename,
  downloadCsv,
  toCsv,
} from '../utils/csvExport';

interface DefenderViewsPanelProps {
  /**
   * The currently-displayed rows (post-filter, post-sort).
   * This is the exact set the table shows the user, so the
   * CSV export mirrors the on-screen order row-for-row.
   */
  rows: Vulnerability[];
  /** Total count, for the "X of Y" header. */
  totalCount: number;
  /** Current filter state. */
  filters: VulnerabilityFilters;
  /** Setter for the full filter state. */
  onChange: (next: VulnerabilityFilters) => void;
}

/**
 * v5.7 — Compact "Defender views" control.
 *
 * Sits next to the existing filters. Renders the five
 * documented defender-view presets as toggle chips, surfaces
 * the active preset's selection rules so a defender can read
 * the rule without inferring it, and exposes the filtered CSV
 * export control. Designed to be usable on desktop and
 * mobile — the chip row wraps, the active-state and rules
 * copy collapse below the row, and the export control sits
 * in the panel header (right side on desktop, full-width on
 * mobile).
 *
 * No combined score is ever shown. Each preset is just a
 * different filter against the same fields the table
 * already exposes.
 */
export default function DefenderViewsPanel({
  rows,
  totalCount,
  filters,
  onChange,
}: DefenderViewsPanelProps) {
  const activePresetId: PresetId | null = filters.presetId ?? null;
  const activePreset: DefenderPreset | null =
    activePresetId === null
      ? null
      : PRESETS.find((p) => p.id === activePresetId) ?? null;

  /**
   * Click a preset chip. If the chip is already active,
   * clicking it again clears the preset (back to the
   * "no preset" baseline) — symmetric with the
   * documented "be removable" requirement. The other
   * filters are intentionally NOT touched; a defender
   * might intentionally combine, say, "Exploited and
   * patchable" with a vendor search.
   */
  const handlePresetClick = useCallback(
    (id: PresetId) => {
      const next: VulnerabilityFilters = {
        ...filters,
        presetId: filters.presetId === id ? null : id,
      };
      onChange(next);
    },
    [filters, onChange]
  );

  /**
   * Explicit "clear preset" button. Mirrors the chip-toggle
   * behavior but is also exposed as a clickable target for
   * keyboard / screen-reader users who can't easily target
   * an individual chip.
   */
  const handleClearPreset = useCallback(() => {
    onChange({ ...filters, presetId: null });
  }, [filters, onChange]);

  /**
   * Build the CSV body from the currently-displayed rows and
   * hand it to the browser's download path. The function is
   * a no-op when the row set is empty — the button is also
   * disabled in that state, so the guard is a second line of
   * defense.
   *
   * The export NEVER touches the network. The CSV body is
   * generated in the browser from the in-memory data and
   * written to a Blob; the user downloads the result.
   */
  const handleExport = useCallback(() => {
    if (rows.length === 0) return;
    const body = toCsv(rows);
    if (body.length === 0) return;
    downloadCsv(defaultExportFilename(), body);
  }, [rows]);

  const exportDisabled = rows.length === 0;

  return (
    <section
      className="panel p-4"
      aria-label="Defender views and export"
    >
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2 text-radar-text">
            <Crosshair className="h-4 w-4 text-radar-accent" />
            <h2 className="text-sm font-semibold">Defender views</h2>
            <span className="text-xs text-radar-dim">
              Showing {rows.length.toLocaleString('en-US')} of{' '}
              {totalCount.toLocaleString('en-US')}
            </span>
            {activePreset && (
              <span
                data-testid="preset-active-badge"
                className="chip border-radar-accent/40 bg-radar-accent/10 text-radar-accent"
                title={`Active preset: ${activePreset.label}`}
              >
                <ShieldCheck className="mr-1 inline h-3 w-3 -translate-y-px" />
                Preset active: {activePreset.label}
              </span>
            )}
          </div>
          <p className="mt-1 text-[11px] text-radar-dim">
            Each preset is a transparent filter — its selection
            rules are shown below the chip, and the underlying
            field values appear in the table. No proprietary
            combined score is computed.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2 sm:flex-nowrap">
          <button
            type="button"
            onClick={handleExport}
            disabled={exportDisabled}
            title={
              exportDisabled
                ? 'No rows match the current filters — export is disabled.'
                : `Download the currently-filtered rows (${rows.length}) as a CSV file. The export runs entirely in your browser; no data is sent to a server.`
            }
            aria-label="Export filtered vulnerabilities as CSV"
            className={[
              'focus-ring inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1.5 text-xs transition',
              exportDisabled
                ? 'cursor-not-allowed border-radar-border bg-radar-panel2/40 text-radar-dim'
                : 'border-radar-accent/40 bg-radar-accent/10 text-radar-text hover:border-radar-accent',
            ].join(' ')}
          >
            <Download className="h-3.5 w-3.5" />
            Export CSV
          </button>
        </div>
      </div>

      {/* Preset chips. Each chip is a real <button> with an
          aria-pressed state so screen readers can announce
          the active preset. The title / aria-label exposes
          the explicit selection rules. */}
      <div
        className="mt-3 flex flex-wrap gap-2"
        role="group"
        aria-label="Defender-view presets"
      >
        {PRESETS.map((p) => {
          const isActive = p.id === activePresetId;
          return (
            <button
              key={p.id}
              type="button"
              onClick={() => handlePresetClick(p.id)}
              aria-pressed={isActive}
              aria-label={`Preset: ${p.label}. ${p.summary}`}
              title={`${p.label} — ${p.summary}`}
              data-testid={`preset-chip-${p.id}`}
              className={[
                'focus-ring inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1.5 text-xs transition',
                isActive
                  ? 'border-radar-accent/60 bg-radar-accent/15 text-radar-text'
                  : 'border-radar-border bg-radar-panel2 text-radar-muted hover:border-radar-accent/40 hover:text-radar-text',
              ].join(' ')}
            >
              <Crosshair className="h-3 w-3" />
              {p.label}
            </button>
          );
        })}
        {activePreset && (
          <button
            type="button"
            onClick={handleClearPreset}
            aria-label="Clear active defender-view preset"
            title="Clear active defender-view preset"
            className="focus-ring inline-flex items-center gap-1 rounded-md border border-radar-border bg-radar-panel2 px-2 py-1.5 text-[11px] text-radar-muted transition hover:text-radar-text"
          >
            <X className="h-3 w-3" />
            Clear preset
          </button>
        )}
      </div>

      {/* Selection rules for the active preset. Rendered only
          when a preset is active so the panel doesn't always
          show five rule blocks. The rules are an unordered
          list of explicit, deterministic field checks. */}
      {activePreset && (
        <div className="mt-3 rounded-md border border-radar-accent/30 bg-radar-accent/5 p-3">
          <div className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-radar-accent">
            <ShieldCheck className="h-3 w-3" />
            Selection rules for &quot;{activePreset.label}&quot;
          </div>
          <ul className="mt-1.5 list-disc space-y-0.5 pl-5 text-[11px] text-radar-text/90">
            {activePreset.criteria.map((line) => (
              <li key={line}>
                <code className="font-mono text-[11px] text-radar-text">{line}</code>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* "Unknown, not negative" reassurance. Rendered only
          when the user has activated a filter that interacts
          with partial coverage (GitHub Advisory / Patch
          context / SSVC exploitation). Keeps the dashboard
          honest about what absence of enrichment means. */}
      {((filters.githubAdvisory && filters.githubAdvisory !== 'any') ||
        (filters.patchContext && filters.patchContext !== 'any') ||
        (filters.ssvcExploitation && filters.ssvcExploitation !== 'any')) && (
        <div className="mt-3 flex items-start gap-1.5 rounded-md border border-radar-border bg-radar-panel2/60 p-2.5 text-[11px] text-radar-muted">
          <ShieldX className="mt-0.5 h-3 w-3 shrink-0 text-radar-dim" />
          <p>
            Records without the corresponding enrichment are
            treated as <span className="text-radar-text">unknown</span>,
            not as a negative assessment. A missing GitHub
            Advisory is not &quot;no patch&quot;; a missing SSVC
            record is not &quot;no exploitation&quot;.
          </p>
        </div>
      )}

      {/* Column count and "no internal metadata" reassurance
          for the export control. The text is small on
          purpose — it's a reminder, not a banner. */}
      <p className="mt-3 text-[10px] text-radar-dim">
        CSV export uses {CSV_COLUMNS.length} columns:
        public source fields, recommended action, SSVC
        decision context, and reviewed GitHub Advisory
        package remediation context. No internal metadata,
        raw provider errors, cache markers, blob keys, or
        tokens are exported.
      </p>
    </section>
  );
}
