/**
 * V6.4 — Local workspace dashboard panel.
 *
 * Compact, self-contained panel that:
 *   - shows local workspace counts (watched, unreviewed,
 *     action-required, changed-since-review, resolved,
 *     archived) plus the current storage status
 *   - renders a single-row of queue filter chips
 *   - renders a search box (matches CVE id / note / tag
 *     contents, never sent remotely)
 *   - renders a compact list of the current local queue
 *     rows when a filter is active, with a checkbox per
 *     row to power the BulkActionBar
 *   - exposes a "Manage" affordance: "Export",
 *     "Import", "Clear archived", "Clear workspace" —
 *     the parent DashboardPage owns the dialogs.
 *
 * The component NEVER:
 *   - writes to the URL
 *   - touches the public vulnerability list
 *   - sends note/tag content to any network target
 *   - logs note/tag content
 *
 * The component is keyboard accessible, respects the
 * "Stored only on this device" trust signal, and falls
 * back to a clear unavailable state when IndexedDB is
 * blocked.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  AlertCircle,
  Archive,
  CheckCircle2,
  CircleDot,
  Database,
  EyeOff,
  Filter,
  HardDrive,
  ListChecks,
  Search,
  ShieldAlert,
  Sparkles,
  Tag,
  TriangleAlert,
  X,
} from 'lucide-react';
import { useWorkspace } from '../../state/WorkspaceContext';
import {
  QUEUE_FILTERS,
  DEFAULT_QUEUE_FILTER,
  buildCounts,
  buildLocalQueue,
  type QueueFilterId,
} from '../../workspace/queueFilters.mjs';
import { SEVERITY_BADGE } from '../../utils/severity';
import { computeChangeSignatureSync as computeChangeSignature } from '../../workspace/changeSignature.mjs';
import type { Vulnerability } from '../../types/vulnerability';

interface WorkspacePanelProps {
  /** The current public vulnerability list. The panel
   *  uses it to compute "changed since review" against
   *  the latest public intelligence version. */
  vulns: Vulnerability[];
  /** The current public intelligence version (from
   *  FetchResult.publicIntelligenceVersion). */
  publicIntelligenceVersion: string | null;
  /** The current public intelligence status. The
   *  panel never fabricates a change claim: when the
   *  status is not 'available' the change-aware tile
   *  shows 0 and the queue's "changed since review"
   *  filter is unavailable. */
  publicIntelligenceStatus: 'available' | 'mismatch' | 'unavailable';
  /** The public-projection schema version, when
   *  available. The change signature is bound to
   *  this version; the queue never treats the
   *  dataset version as semver. */
  publicProjectionSchemaVersion: string | null;
  /** Selected CVE ids, owned by the parent so the
   *  bulk-action bar can act on them. */
  selectedCveIds: string[];
  onSelectedCveIdsChange: (next: string[]) => void;
  /** Open the drawer for a given vuln. */
  onOpenVuln: (vuln: Vulnerability) => void;
  /** Open the export dialog. */
  onExport: () => void;
  /** Open the import dialog. */
  onImport: () => void;
  /** Open the clear-archived confirmation dialog. */
  onClearArchived: () => void;
  /** Open the clear-workspace confirmation dialog. */
  onClearWorkspace: () => void;
}

const QUEUE_FILTER_LABELS: Record<QueueFilterId, string> = {
  'all-watched': 'All watched',
  'needs-review': 'Needs review',
  'action-required': 'Action required',
  'changed-since-review': 'Changed since review',
  'high-or-urgent': 'High / urgent',
  'resolved': 'Resolved',
  'archived': 'Archived',
};

export default function WorkspacePanel({
  vulns,
  publicIntelligenceVersion,
  publicIntelligenceStatus,
  publicProjectionSchemaVersion,
  selectedCveIds,
  onSelectedCveIdsChange,
  onOpenVuln,
  onExport,
  onImport,
  onClearArchived,
  onClearWorkspace,
}: WorkspacePanelProps) {
  const { state } = useWorkspace();
  const [filter, setFilter] = useState<QueueFilterId>(DEFAULT_QUEUE_FILTER);
  const [query, setQuery] = useState('');

  // Compute counts using the current public dataset +
  // workspace entries. Pure derivation; safe to call on
  // every render. The status and projection schema
  // version are passed in so the change-aware count
  // never fabricates a claim.
  const counts = useMemo(
    () =>
      buildCounts({
        vulns,
        entriesByCve: state.entriesByCve,
        publicIntelligenceVersion,
        publicIntelligenceStatus,
        publicProjectionSchemaVersion,
        computeSignature: computeChangeSignature,
      }),
    [vulns, state.entriesByCve, publicIntelligenceVersion, publicIntelligenceStatus, publicProjectionSchemaVersion]
  );

  // Compute the queue rows for the active filter. We
  // re-compute when the underlying entries or the filter
  // changes; the queue is otherwise stable.
  const queue = useMemo(
    () =>
      buildLocalQueue({
        vulns,
        entriesByCve: state.entriesByCve,
        filter,
        query,
        publicIntelligenceVersion,
        publicIntelligenceStatus,
        publicProjectionSchemaVersion,
        computeSignature: computeChangeSignature,
      }),
    [vulns, state.entriesByCve, filter, query, publicIntelligenceVersion, publicIntelligenceStatus, publicProjectionSchemaVersion]
  );

  const handleFilter = useCallback(
    (id: QueueFilterId) => {
      setFilter(id);
      // Clear selection when the filter changes so the
      // bulk action bar doesn't act on a stale set.
      onSelectedCveIdsChange([]);
    },
    [onSelectedCveIdsChange]
  );

  const handleToggleRow = useCallback(
    (cveId: string, on: boolean) => {
      if (on) {
        if (selectedCveIds.includes(cveId)) return;
        onSelectedCveIdsChange([...selectedCveIds, cveId]);
      } else {
        onSelectedCveIdsChange(selectedCveIds.filter((c) => c !== cveId));
      }
    },
    [selectedCveIds, onSelectedCveIdsChange]
  );

  const handleToggleAll = useCallback(
    (on: boolean) => {
      if (on) {
        onSelectedCveIdsChange(queue.map((q) => q.vuln.cveId));
      } else {
        onSelectedCveIdsChange([]);
      }
    },
    [queue, onSelectedCveIdsChange]
  );

  const isUnavailable = state.status === 'unavailable' || state.status === 'error';
  const isSessionOnly = state.status === 'session-only';
  const isInitializing = state.status === 'initializing';
  const backendLabel = state.backend === 'indexeddb'
    ? 'IndexedDB on this device'
    : state.backend === 'memory'
      ? 'Session memory only'
      : state.backend === 'unavailable'
        ? 'Storage unavailable'
        : 'Initializing…';

  // Reduce motion preference: hide the pulse animation.
  const [prefersReducedMotion, setPrefersReducedMotion] = useState(false);
  useEffect(() => {
    if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return;
    const mq = window.matchMedia('(prefers-reduced-motion: reduce)');
    setPrefersReducedMotion(mq.matches);
    const onChange = () => setPrefersReducedMotion(mq.matches);
    mq.addEventListener?.('change', onChange);
    return () => mq.removeEventListener?.('change', onChange);
  }, []);

  return (
    <section
      className="panel p-4"
      aria-label="Local workspace panel"
      data-testid="workspace-panel"
    >
      {/* Header */}
      <header className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2 text-radar-text">
            <Database className="h-4 w-4 text-radar-accent" />
            <h2 className="text-sm font-semibold">Local workspace</h2>
            <span className="chip border-radar-accent/40 bg-radar-accent/10 text-radar-accent">
              <ShieldAlert className="mr-1 inline h-3 w-3 -translate-y-px" />
              Stored only on this device
            </span>
            <StorageBadge
              status={state.status}
              backendLabel={backendLabel}
            />
          </div>
          <p className="mt-1 text-[11px] text-radar-dim">
            Watchlists, statuses, tags and notes are stored only in this
            browser. Export a backup before clearing browser data or
            switching devices.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2 sm:flex-nowrap">
          <button
            type="button"
            onClick={onExport}
            disabled={isUnavailable || isInitializing}
            className="focus-ring inline-flex items-center gap-1.5 rounded-md border border-radar-border bg-radar-panel2 px-2.5 py-1.5 text-xs text-radar-text transition hover:border-radar-accent/40 disabled:opacity-50 disabled:cursor-not-allowed"
            title="Download a local JSON backup. The file may contain your private notes."
          >
            <HardDrive className="h-3.5 w-3.5" />
            Export
          </button>
          <button
            type="button"
            onClick={onImport}
            disabled={isUnavailable || isInitializing}
            className="focus-ring inline-flex items-center gap-1.5 rounded-md border border-radar-border bg-radar-panel2 px-2.5 py-1.5 text-xs text-radar-text transition hover:border-radar-accent/40 disabled:opacity-50 disabled:cursor-not-allowed"
            title="Import a local JSON backup. You can dry-run, merge, or replace."
          >
            <Archive className="h-3.5 w-3.5" />
            Import
          </button>
          <button
            type="button"
            onClick={onClearArchived}
            disabled={counts.archived === 0}
            className="focus-ring inline-flex items-center gap-1.5 rounded-md border border-radar-border bg-radar-panel2 px-2.5 py-1.5 text-xs text-radar-text transition hover:border-radar-warn/40 disabled:opacity-50 disabled:cursor-not-allowed"
            title="Remove all locally archived entries. Destructive — confirmation required."
          >
            <EyeOff className="h-3.5 w-3.5" />
            Clear archived
          </button>
          <button
            type="button"
            onClick={onClearWorkspace}
            disabled={isUnavailable || counts.total === 0}
            className="focus-ring inline-flex items-center gap-1.5 rounded-md border border-radar-warn/40 bg-radar-warn/5 px-2.5 py-1.5 text-xs text-radar-warn transition hover:border-radar-warn disabled:opacity-50 disabled:cursor-not-allowed"
            title="Remove every entry in the local workspace. Destructive — confirmation required."
          >
            <X className="h-3.5 w-3.5" />
            Clear workspace
          </button>
        </div>
      </header>

      {/* Status banner when the workspace is degraded. */}
      {(isUnavailable || isSessionOnly) && (
        <div
          role="status"
          aria-live="polite"
          className="mt-3 flex items-start gap-2 rounded-md border border-radar-warn/40 bg-radar-warn/5 px-3 py-2 text-xs text-radar-muted"
        >
          <TriangleAlert className="mt-0.5 h-3.5 w-3.5 shrink-0 text-radar-warn" />
          <p>
            {isUnavailable
              ? 'Local workspace is unavailable in this browser session. Watchlists, statuses, tags, and notes cannot be saved. Reload the page or use a normal (non-private) window to re-enable storage.'
              : 'Session-only mode. Data is stored in this tab only and will be lost on tab close or reload. Export a backup now to preserve your work.'}
          </p>
        </div>
      )}

      {/* Warning banner when the entry count exceeds the soft threshold. */}
      {state.warning && (
        <div
          role="status"
          className="mt-3 flex items-start gap-2 rounded-md border border-radar-warn/30 bg-radar-warn/5 px-3 py-2 text-xs text-radar-muted"
        >
          <AlertCircle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-radar-warn" />
          <p>
            The local workspace contains more than{' '}
            {state.counts.total.toLocaleString('en-US')} entries. Consider
            archiving old records to keep the dashboard responsive.
          </p>
        </div>
      )}

      {/* Counts grid */}
      <dl
        className="mt-4 grid grid-cols-2 gap-2 sm:grid-cols-4 lg:grid-cols-7"
        aria-label="Local workspace counts"
      >
        <CountTile
          label="Watched"
          value={counts.watched}
          icon={<ListChecks className="h-3.5 w-3.5" />}
          tone="accent"
          active={filter === 'all-watched'}
          onClick={() => handleFilter('all-watched')}
        />
        <CountTile
          label="Unreviewed"
          value={counts.unreviewed}
          icon={<CircleDot className="h-3.5 w-3.5" />}
          tone="muted"
          active={filter === 'needs-review'}
          onClick={() => handleFilter('needs-review')}
        />
        <CountTile
          label="Action required"
          value={counts.actionRequired}
          icon={<TriangleAlert className="h-3.5 w-3.5" />}
          tone="warn"
          active={filter === 'action-required'}
          onClick={() => handleFilter('action-required')}
        />
        <CountTile
          label="Changed since review"
          value={counts.changedSinceReview}
          icon={<Sparkles className="h-3.5 w-3.5" />}
          tone="accent"
          active={filter === 'changed-since-review'}
          onClick={() => handleFilter('changed-since-review')}
        />
        <CountTile
          label="High / urgent"
          value={
            // Derived from entries: count entries with priority high|urgent
            // (not in the queue subset).
            Object.values(state.entriesByCve).filter(
              (e) => !e.archived && (e.userPriority === 'high' || e.userPriority === 'urgent')
            ).length
          }
          icon={<Tag className="h-3.5 w-3.5" />}
          tone="muted"
          active={filter === 'high-or-urgent'}
          onClick={() => handleFilter('high-or-urgent')}
        />
        <CountTile
          label="Resolved"
          value={counts.resolved}
          icon={<CheckCircle2 className="h-3.5 w-3.5" />}
          tone="muted"
          active={filter === 'resolved'}
          onClick={() => handleFilter('resolved')}
        />
        <CountTile
          label="Archived"
          value={counts.archived}
          icon={<Archive className="h-3.5 w-3.5" />}
          tone="muted"
          active={filter === 'archived'}
          onClick={() => handleFilter('archived')}
        />
      </dl>

      <p className="mt-3 text-[11px] text-radar-dim">
        Filters here affect only your local workspace queue. They do not
        change Defender Views, public filters, the public URL, or the
        What Changed panel.
      </p>

      {/* Filter + search row */}
      <div className="mt-3 flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
        <div
          className="flex flex-wrap items-center gap-1.5"
          role="group"
          aria-label="Local queue filters"
        >
          <span className="inline-flex items-center gap-1 text-[11px] uppercase tracking-wider text-radar-dim">
            <Filter className="h-3 w-3" />
            Queue
          </span>
          {QUEUE_FILTERS.map((f) => {
            const active = filter === f.id;
            return (
              <button
                key={f.id}
                type="button"
                onClick={() => handleFilter(f.id)}
                aria-pressed={active}
                className={[
                  'focus-ring inline-flex items-center rounded-md border px-2 py-1 text-[11px] transition',
                  active
                    ? 'border-radar-accent/60 bg-radar-accent/15 text-radar-accent'
                    : 'border-radar-border bg-radar-panel2 text-radar-muted hover:border-radar-accent/40 hover:text-radar-text',
                ].join(' ')}
              >
                {QUEUE_FILTER_LABELS[f.id] || f.label}
              </button>
            );
          })}
        </div>
        <label className="flex w-full items-center gap-2 sm:w-auto">
          <span className="sr-only">Search local workspace (CVE id, note, tag)</span>
          <span className="inline-flex items-center gap-1 text-[11px] text-radar-dim">
            <Search className="h-3 w-3" />
            Search
          </span>
          <input
            type="search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="CVE id, note, tag…"
            className="focus-ring w-full rounded-md border border-radar-border bg-radar-panel2 px-2.5 py-1 text-xs text-radar-text sm:w-64"
            aria-label="Search local workspace by CVE id, note content, or tag"
          />
          {query && (
            <button
              type="button"
              onClick={() => setQuery('')}
              className="focus-ring inline-flex h-6 w-6 items-center justify-center rounded-md border border-radar-border bg-radar-panel2 text-radar-muted hover:border-radar-accent/40"
              aria-label="Clear search"
            >
              <X className="h-3 w-3" />
            </button>
          )}
        </label>
      </div>

      {/* Queue list */}
      {queue.length > 0 ? (
        <QueueList
          queue={queue}
          selectedCveIds={selectedCveIds}
          onToggleRow={handleToggleRow}
          onToggleAll={handleToggleAll}
          onOpenVuln={onOpenVuln}
          pulse={!prefersReducedMotion}
        />
      ) : (
        <p className="mt-3 rounded-md border border-dashed border-radar-border bg-radar-panel2/40 px-3 py-3 text-[11px] text-radar-dim">
          No local workspace entries match this filter{query ? ' or search' : ''}.
          Open a vulnerability and add it to the watchlist to start.
        </p>
      )}
    </section>
  );
}

/* ----------------------------- sub-components ----------------------------- */

function CountTile({
  label,
  value,
  icon,
  tone,
  active,
  onClick,
}: {
  label: string;
  value: number;
  icon?: React.ReactNode;
  tone: 'accent' | 'warn' | 'muted';
  active?: boolean;
  onClick?: () => void;
}) {
  const toneClass =
    tone === 'accent'
      ? 'text-radar-accent'
      : tone === 'warn'
        ? 'text-radar-warn'
        : 'text-radar-text';
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={!!active}
      className={[
        'focus-ring flex flex-col items-start gap-1 rounded-md border px-3 py-2 text-left transition',
        active
          ? 'border-radar-accent/60 bg-radar-accent/10'
          : 'border-radar-border bg-radar-panel2 hover:border-radar-accent/40',
      ].join(' ')}
      title={onClick ? `Filter by ${label.toLowerCase()}` : undefined}
    >
      <span className="flex items-center gap-1 text-[10px] uppercase tracking-wider text-radar-dim">
        {icon}
        {label}
      </span>
      <span className={['text-lg font-semibold tabular-nums', toneClass].join(' ')}>
        {value.toLocaleString('en-US')}
      </span>
    </button>
  );
}

function StorageBadge({
  status,
  backendLabel,
}: {
  status: string;
  backendLabel: string;
}) {
  const tone =
    status === 'persistent'
      ? 'border-radar-accent/40 bg-radar-accent/5 text-radar-accent'
      : status === 'session-only'
        ? 'border-radar-warn/40 bg-radar-warn/5 text-radar-warn'
        : status === 'unavailable' || status === 'error'
          ? 'border-radar-warn/40 bg-radar-warn/10 text-radar-warn'
          : 'border-radar-border bg-radar-panel2 text-radar-muted';
  return (
    <span
      className={['inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 text-[10px]', tone].join(' ')}
      title={`Backend: ${backendLabel}`}
      data-testid="workspace-storage-badge"
    >
      <Database className="h-3 w-3" />
      {status === 'persistent' && 'Persistent'}
      {status === 'session-only' && 'Session only'}
      {status === 'initializing' && 'Initializing…'}
      {status === 'unavailable' && 'Unavailable'}
      {status === 'error' && 'Error'}
    </span>
  );
}

function QueueList({
  queue,
  selectedCveIds,
  onToggleRow,
  onToggleAll,
  onOpenVuln,
  pulse,
}: {
  queue: Array<{ vuln: Vulnerability; entry: any; changeClass: string }>;
  selectedCveIds: string[];
  onToggleRow: (cveId: string, on: boolean) => void;
  onToggleAll: (on: boolean) => void;
  onOpenVuln: (vuln: Vulnerability) => void;
  pulse: boolean;
}) {
  const allSelected = selectedCveIds.length === queue.length && queue.length > 0;
  const someSelected = selectedCveIds.length > 0 && !allSelected;
  const selectAllRef = useRef<HTMLInputElement | null>(null);
  useEffect(() => {
    if (selectAllRef.current) {
      selectAllRef.current.indeterminate = someSelected;
    }
  }, [someSelected]);

  return (
    <div className="mt-3 overflow-hidden rounded-md border border-radar-border">
      <table className="w-full text-sm">
        <thead className="bg-radar-panel2/60 text-[10px] uppercase tracking-wider text-radar-dim">
          <tr>
            <th scope="col" className="w-8 px-2 py-1.5">
              <input
                ref={selectAllRef}
                type="checkbox"
                aria-label={
                  allSelected
                    ? 'Deselect all queue rows'
                    : 'Select all queue rows'
                }
                checked={allSelected}
                onChange={(e) => onToggleAll(e.target.checked)}
                className="focus-ring h-3.5 w-3.5"
              />
            </th>
            <th scope="col" className="px-2 py-1.5 text-left">CVE</th>
            <th scope="col" className="px-2 py-1.5 text-left">Severity</th>
            <th scope="col" className="px-2 py-1.5 text-left">Local status</th>
            <th scope="col" className="px-2 py-1.5 text-left">Local priority</th>
            <th scope="col" className="px-2 py-1.5 text-left">Tags</th>
            <th scope="col" className="px-2 py-1.5 text-left">Changed</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-radar-border/60">
          {queue.map((q) => {
            const v = q.vuln;
            const e = q.entry;
            const selected = selectedCveIds.includes(v.cveId);
            return (
              <tr
                key={v.cveId}
                className={[
                  'group transition',
                  selected ? 'bg-radar-accent/5' : 'hover:bg-radar-panel2/40',
                ].join(' ')}
              >
                <td className="px-2 py-1.5">
                  <input
                    type="checkbox"
                    aria-label={`Select ${v.cveId} for bulk action`}
                    checked={selected}
                    onChange={(ev) => onToggleRow(v.cveId, ev.target.checked)}
                    className="focus-ring h-3.5 w-3.5"
                  />
                </td>
                <td className="px-2 py-1.5 font-mono text-xs text-radar-accent">
                  <button
                    type="button"
                    onClick={() => onOpenVuln(v)}
                    className="focus-ring rounded-sm hover:underline"
                    aria-label={`Open ${v.cveId} in detail drawer`}
                  >
                    {v.cveId}
                  </button>
                </td>
                <td className="px-2 py-1.5">
                  <span className={['chip', SEVERITY_BADGE[v.severity] || ''].join(' ')}>
                    {v.severity}
                  </span>
                </td>
                <td className="px-2 py-1.5 text-xs text-radar-text">
                  {e ? (
                    <span className="inline-flex items-center gap-1">
                      <StatusDot status={e.triageStatus} />
                      {labelForStatus(e.triageStatus)}
                    </span>
                  ) : (
                    <span className="text-radar-dim">—</span>
                  )}
                </td>
                <td className="px-2 py-1.5 text-xs text-radar-text">
                  {e && e.userPriority !== 'none' ? (
                    <span
                      className={[
                        'inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 text-[10px]',
                        e.userPriority === 'urgent'
                          ? 'border-radar-critical/40 bg-radar-critical/10 text-radar-critical'
                          : e.userPriority === 'high'
                            ? 'border-radar-high/40 bg-radar-high/10 text-radar-high'
                            : 'border-radar-border bg-radar-panel2 text-radar-muted',
                      ].join(' ')}
                      title="Local user-assigned workflow value — not a vulnerability risk ranking."
                    >
                      {labelForPriority(e.userPriority)}
                    </span>
                  ) : (
                    <span className="text-radar-dim">No local priority</span>
                  )}
                </td>
                <td className="px-2 py-1.5 text-xs text-radar-muted">
                  {e && e.tags && e.tags.length > 0 ? (
                    <span className="line-clamp-1">{e.tags.join(', ')}</span>
                  ) : (
                    <span className="text-radar-dim">—</span>
                  )}
                </td>
                <td className="px-2 py-1.5 text-xs">
                  <ChangedPill cls={q.changeClass} pulse={pulse} />
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function StatusDot({ status }: { status: string }) {
  const cls =
    status === 'action-required'
      ? 'text-radar-warn'
      : status === 'reviewing'
        ? 'text-radar-accent'
        : status === 'resolved'
          ? 'text-radar-low'
          : status === 'mitigating'
            ? 'text-radar-medium'
            : status === 'accepted-risk' || status === 'not-applicable'
              ? 'text-radar-muted'
              : 'text-radar-dim';
  return <CircleDot className={['h-3 w-3', cls].join(' ')} />;
}

function labelForStatus(s: string): string {
  switch (s) {
    case 'unreviewed': return 'Unreviewed';
    case 'reviewing': return 'Reviewing';
    case 'action-required': return 'Action required';
    case 'mitigating': return 'Mitigating';
    case 'resolved': return 'Resolved';
    case 'accepted-risk': return 'Accepted risk';
    case 'not-applicable': return 'Not applicable';
    default: return s;
  }
}

function labelForPriority(p: string): string {
  switch (p) {
    case 'low': return 'Low';
    case 'medium': return 'Medium';
    case 'high': return 'High';
    case 'urgent': return 'Urgent';
    default: return 'None';
  }
}

function ChangedPill({ cls, pulse }: { cls: string; pulse: boolean }) {
  if (cls === 'changed') {
    return (
      <span
        className={[
          'inline-flex items-center gap-1 rounded-md border border-radar-accent/40 bg-radar-accent/10 px-1.5 py-0.5 text-[10px] text-radar-accent',
          pulse ? 'animate-pulse' : '',
        ].join(' ')}
        title="The public intelligence for this CVE changed since the last review."
      >
        <Sparkles className="h-3 w-3" />
        Changed since review
      </span>
    );
  }
  if (cls === 'newly-tracked') {
    return (
      <span
        className="inline-flex items-center gap-1 rounded-md border border-radar-warn/40 bg-radar-warn/10 px-1.5 py-0.5 text-[10px] text-radar-warn"
        title="This CVE has been added to the local workspace without a prior review checkpoint."
      >
        <CircleDot className="h-3 w-3" />
        Newly tracked
      </span>
    );
  }
  if (cls === 'no-longer-tracked') {
    return (
      <span
        className="inline-flex items-center gap-1 rounded-md border border-radar-muted/40 bg-radar-panel2 px-1.5 py-0.5 text-[10px] text-radar-muted"
        title="This CVE is no longer in the current public dataset."
      >
        <EyeOff className="h-3 w-3" />
        No longer tracked
      </span>
    );
  }
  if (cls === 'no-newer') {
    return (
      <span
        className="inline-flex items-center gap-1 rounded-md border border-radar-border bg-radar-panel2 px-1.5 py-0.5 text-[10px] text-radar-muted"
        title="No newer compatible change recorded since the last review."
      >
        No newer
      </span>
    );
  }
  return (
    <span
      className="inline-flex items-center gap-1 rounded-md border border-radar-border bg-radar-panel2 px-1.5 py-0.5 text-[10px] text-radar-dim"
      title="Change status is unavailable: missing or incompatible public-intelligence version."
    >
      Change unavailable
    </span>
  );
}
